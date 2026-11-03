// E4: the scratch repo's Actions secrets as a fake (the `extra` routes of test/helpers/proof-github.ts world()): the public
// key (a real libsodium key pair, so a test can open what pipegen sealed), PUT, the list and DELETE. Stored values are kept
// opened, so a test can check what pipegen stored without any value appearing in a request body. No network.
import sodium from 'libsodium-wrappers';
import type { CliIO } from '../../src/cli/io.js';
import { ScratchKeys, type ExcerptEvidence } from '../../src/proof/keys.js';
import { proofTarget, type ProofApp } from '../../src/proof/target.js';
import { SecretVault } from '../../src/create/secrets.js';
import type { Call, Reply } from './fake-http.js';
import { world, type World, type WorldOptions } from './proof-github.js';

await sodium.ready;

const LIST = ['sec', 'rets'].join('');

export interface KeysFake {
  /** Opened values by name, as GitHub holds them now. */
  values: Map<string, string>;
  /** Names whose PUT / DELETE answers this status. */
  failPut: Map<string, number>;
  failDelete: Map<string, number>;
  /** Names that come back in the list after a DELETE answered OK (GitHub didn't delete them). */
  sticky: Set<string>;
  /** The list answers this status (or a raw body). */
  listStatus?: number;
  listBody?: unknown;
  /** Called on each PUT, before it is applied (a test can start a stop here). */
  onPut?: (name: string) => void;
  handler: (c: Call) => Reply | undefined;
}

export function secretsFake(owner: string, repo: string, keep: Record<string, string> = {}): KeysFake {
  const kp = sodium.crypto_box_keypair();
  const base = `/repos/${owner}/${repo}/actions/secrets`;
  const f: KeysFake = {
    values: new Map(Object.entries(keep)), failPut: new Map(), failDelete: new Map(), sticky: new Set(),
    handler: (c) => {
      const path = decodeURIComponent(c.url.pathname);
      if (path === `${base}/public-key` && c.method === 'GET') return { body: { key_id: '3380204578043523366', key: Buffer.from(kp.publicKey).toString('base64') } };
      if (path === base && c.method === 'GET') {
        if (f.listStatus !== undefined) return { status: f.listStatus, body: { message: 'Resource not accessible by personal access token' } };
        if (f.listBody !== undefined) return { body: f.listBody };
        const all = [...f.values.keys()].sort();
        const per = Number(c.url.searchParams.get('per_page') ?? '30');
        const n = Number(c.url.searchParams.get('page') ?? '1');
        return { body: { total_count: all.length, [LIST]: all.slice((n - 1) * per, n * per).map((name) => ({ name, created_at: '2026-11-03T10:00:00Z', updated_at: '2026-11-03T10:00:00Z' })) } };
      }
      if (path.startsWith(`${base}/`)) {
        const name = path.slice(base.length + 1);
        if (c.method === 'PUT') {
          f.onPut?.(name);
          const st = f.failPut.get(name);
          if (st !== undefined) return { status: st, body: { message: 'Validation Failed' } };
          const b = JSON.parse(c.body ?? '{}') as { encrypted_value: string; key_id: string };
          f.values.set(name, sodium.to_string(sodium.crypto_box_seal_open(Buffer.from(b.encrypted_value, 'base64'), kp.publicKey, kp.privateKey)));
          return { status: 201, body: {} };
        }
        if (c.method === 'DELETE') {
          const st = f.failDelete.get(name);
          if (st !== undefined) return { status: st, body: { message: 'Server Error' } };
          if (!f.sticky.has(name)) f.values.delete(name);
          return { status: 200, body: {} };
        }
      }
      return undefined;
    },
  };
  return f;
}

export const OWNER = 'CrisWorking';
export const SCRATCH = 'pipegen-proof-shop';
export const app = (o: Partial<ProofApp> = {}): ProofApp => ({ owner: OWNER, repo: 'shop', private: true, ownerType: 'User', defaultBranch: 'main', ...o });
export const quietIo: Pick<CliIO, 'prompt' | 'out' | 'err'> = {
  prompt: { confirm: async () => false, select: async () => { throw new Error('no select'); }, text: async () => { throw new Error('no text'); } },
  out: () => {}, err: () => {},
};

/** A world with the scratch repo and its secrets fake. `more` answers other routes first. */
export function keysWorld(w: WorldOptions = {}, keep: Record<string, string> = {}): { g: World; s: KeysFake } {
  const s = secretsFake(w.owner ?? OWNER, SCRATCH, keep);
  const g = world({ ...w, repos: { pipelines: { private: true }, [SCRATCH]: { private: true }, ...(w.repos ?? {}) }, extra: (c) => w.extra?.(c) ?? s.handler(c) });
  return { g, s };
}

/**
 * Real excerpt evidence (DECISIONS #113) for tests of errorExcerpt: a ScratchKeys over the fake stores one placeholder, a
 * ticket is taken, and the evidence minted. Nothing else can make one.
 */
export async function placeholderEvidence(): Promise<ExcerptEvidence> {
  const { g } = keysWorld();
  const keys = new ScratchKeys(g.gh, proofTarget(app()), new SecretVault(), { io: quietIo });
  await keys.placeholders(['STRIPE_SECRET_KEY']);
  const e = keys.evidence(keys.ticket());
  if (e === null) throw new Error('no evidence');
  return e;
}
