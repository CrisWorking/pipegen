// v0.2 Plan G G11 (ruling S24, carry B-T1c; G10-R1): a new cosign key pair for `finish --rotate-key` (or when deliver stored none). The
// pinned cosign binary is resolved by the caller's resolver RIGHT BEFORE the exec (ensurePinnedBinary re-hashes it on every call) and the
// path is never kept. cosign runs with an absolute path, no shell, in a fresh 0700 folder, its password from a random value in its
// environment only; both key texts are read back, held to cosign's exact forms (src/util/cosign-pem.ts), and the folder is removed whatever
// happens. Nothing of the key, the password or cosign's output is ever in a message.
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { cosignKeyProblem, cosignPubProblem, MAX_COSIGN_KEY_BYTES, MAX_COSIGN_PUB_BYTES } from '../util/cosign-pem.js';
import { DeliverError } from './git-data.js';

/** Runs `bin args` (absolute path, no shell) in `cwd` with exactly `env`; rejects when it fails. */
export type CosignExec = (bin: string, args: readonly string[], opts: { cwd: string; env: Record<string, string> }) => Promise<void>;
/** The cosign binary's absolute path, resolved (downloaded and re-hashed) on every call: `() => ensurePinnedBinary('cosign')`. */
export type CosignResolver = () => Promise<string>;

/** The real exec: execFile, no shell, a time limit, output never kept. */
export const execCosign: CosignExec = (bin, args, opts) => new Promise((resolve, reject) => {
  execFile(bin, [...args], { cwd: opts.cwd, env: opts.env, timeout: 120_000, maxBuffer: 1024 * 1024, windowsHide: true, shell: false }, (e) => (e === null ? resolve() : reject(e)));
});

export interface CosignKeyPair { key: string; password: string; pub: string }

const readCapped = (path: string, cap: number): string => {
  const buf = readFileSync(path);
  if (buf.length > cap) throw new DeliverError('cosign wrote a key file larger than a cosign key, so pipegen stores no key.');
  return buf.toString('utf8');
};

/**
 * A new encrypted key pair from the pinned cosign: `generate-key-pair --output-key-prefix <tmp>/pipegen` with COSIGN_PASSWORD set to 32
 * random bytes (base64url). `resolve` is called right before the exec, once per exec.
 */
export async function makeCosignKeyPair(resolve: CosignResolver, exec: CosignExec = execCosign, base: string = tmpdir()): Promise<CosignKeyPair> {
  const dir = mkdtempSync(join(base, 'pipegen-cosign-'));
  try {
    const password = randomBytes(32).toString('base64url');
    const prefix = join(dir, 'pipegen');
    const bin = await resolve();
    if (typeof bin !== 'string' || !isAbsolute(bin)) throw new DeliverError('The cosign path pipegen was given is not an absolute path, so it makes no key.');
    try {
      await exec(bin, ['generate-key-pair', '--output-key-prefix', prefix], { cwd: dir, env: { COSIGN_PASSWORD: password, HOME: dir, PATH: '/usr/bin:/bin' } });
    } catch (e) {
      const code = (e as { code?: unknown } | null)?.code;
      throw new DeliverError(`cosign couldn't make the key pair${typeof code === 'number' ? ` (exit ${code})` : ''}, so pipegen stores no key.`);
    }
    let key: string;
    let pub: string;
    try {
      key = readCapped(`${prefix}.key`, MAX_COSIGN_KEY_BYTES);
      pub = readCapped(`${prefix}.pub`, MAX_COSIGN_PUB_BYTES);
    } catch (e) {
      if (e instanceof DeliverError) throw e;
      throw new DeliverError('cosign didn\'t write the key pair where pipegen asked, so pipegen stores no key.');
    }
    const bad = cosignKeyProblem(key) ?? (cosignPubProblem(pub) === null ? null : 'has a public key that is not in the form cosign writes');
    if (bad !== null) throw new DeliverError(`The key pair cosign made ${bad}, so pipegen stores no key.`);
    return { key, password, pub };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
