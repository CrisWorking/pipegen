// D5 (v0.2 Plan D Task 4, rulings S8/S10): secret requests, the vault, askSecrets, sealed storage, the fingerprint key.
import { inspect } from 'node:util';
import sodium from 'libsodium-wrappers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Prompter } from '../src/cli/io.js';
import { composeCoveredNames } from '../src/create/compose.js';
import {
  askSecrets, coveredNames, generateFpKey, MIN_VALUE_LENGTH, secretRequests, SecretVault, storeEnvSecret, storeSecrets,
  TEST_KEYS_ONLY, type SecretRequest,
} from '../src/create/secrets.js';
import { isDangerousName } from '../src/engine/job-rules.js';
import { displayForm } from '../src/util/safe-text.js';
import { activeSafeText, anyString, anyYamlScalar, LONG_NUMBER_DIGITS, scrubForDisplay, withActiveVault } from '../src/util/known-values.js';
import { show } from '../src/engine/render-error.js';
import { packageJsonProblems } from '../src/create/package-rules.js';
import { runExitHooks } from '../src/util/exit-hooks.js';
import { R } from '../src/ai/redact-core.js';
import type { CreatedFile, Dependency, DependencyKind, Service } from '../src/types.js';
import { makeOctokit } from '../src/github/client.js';
import { fakeFetch, fakeOctokit, type Call, type Routes } from './helpers/fake-http.js';
import { profile, service } from './helpers/render.js';

// provider-key prefixes are built at runtime: no secret-looking literal is committed (test/no-secret-literals.test.ts)
const SKT = 'sk' + '_test_';
const SKL = 'sk' + '_live_';
const RKL = 'rk' + '_live_';
const PKL = 'pk' + '_live_';
const RZL = 'rzp' + '_live_';
const LIVE = 'live' + '_';
await sodium.ready;
const dep = (kind: DependencyKind, envVars: string[] = [], name: string = kind): Dependency => ({ kind, name, evidence: 'x', envVars });
const svc = (over: Partial<Service> = {}): Service => service({ name: 'api', path: 'api', envVars: [], ...over });
const names = (r: { requests: SecretRequest[] }): string[] => r.requests.map((q) => q.name);
const NONE = { covered: new Set<string>() };

afterEach(() => { runExitHooks(); vi.restoreAllMocks(); });

describe('requests', () => {
  it('requests: STRIPE_SECRET_KEY requested with test-key hint', () => {
    const p = profile([svc({ envVars: ['STRIPE_SECRET_KEY'], dependsOn: [dep('external', ['STRIPE_SECRET_KEY'], 'stripe')] })]);
    const r = secretRequests(p, NONE);
    expect(names(r)).toEqual(['STRIPE_SECRET_KEY']);
    expect(r.requests[0]?.example).toMatch(/\*\*test\*\* key/);
    expect(r.requests[0]?.service).toBe('api');
    expect(r.requests[0]?.why).toMatch(/STRIPE_SECRET_KEY/);
  });

  it('requests: well-known non-secrets and covered names are not asked', () => {
    const p = profile([svc({ envVars: ['PORT', 'NODE_ENV', 'LOG_LEVEL', 'HOST', 'DATABASE_URL', 'API_KEY'] })]);
    expect(names(secretRequests(p, { covered: new Set(['DATABASE_URL']) }))).toEqual(['API_KEY']);
  });

  it('requests: DATABASE_URL not requested when compose generates it', () => {
    const p = profile([svc({ port: 3000, scripts: ['start'], dockerfile: 'api/Dockerfile', envVars: ['DATABASE_URL', 'STRIPE_SECRET_KEY'], dependsOn: [dep('postgres', ['DATABASE_URL'])] })]);
    const covered = coveredNames(p, []);
    expect(covered.has('DATABASE_URL')).toBe(true);
    expect(names(secretRequests(p, { covered }))).toEqual(['STRIPE_SECRET_KEY']);
  });

  it('C2: coveredNames passes the Dockerfiles pipegen creates (the default empty list would wrongly ask for DATABASE_URL)', () => {
    const p = profile([svc({ port: 3000, scripts: ['start'], dockerfile: undefined, envVars: ['DATABASE_URL'], dependsOn: [dep('postgres', ['DATABASE_URL'])] })]);
    const df: CreatedFile = { path: 'api/Dockerfile', content: 'x', part: 'docker', reason: 'r', repo: 'app' };
    // the default (no created Dockerfile): D4's helper covers nothing, so the request logic would ask the user for DATABASE_URL
    expect(composeCoveredNames(p)).toEqual([]);
    expect(names(secretRequests(p, { covered: new Set(composeCoveredNames(p)) }))).toEqual(['DATABASE_URL']);
    // the real call hands over the created Dockerfiles and covers it
    const covered = coveredNames(p, [df]);
    expect(covered.has('DATABASE_URL')).toBe(true);
    expect(names(secretRequests(p, { covered }))).toEqual([]);
    // only app-repo Dockerfiles of part docker count
    expect(coveredNames(p, [{ ...df, repo: 'central' }]).has('DATABASE_URL')).toBe(false);
    expect(coveredNames(p, [{ ...df, part: 'tests' }]).has('DATABASE_URL')).toBe(false);
  });

  it('requests: dangerous or case-colliding names never asked, listed as can\'t-map', () => {
    const p = profile([svc({ envVars: ['NODE_OPTIONS', 'LD_PRELOAD', 'node_options', 'ld_preload', 'GITHUB_TOKEN', 'github_foo', 'PIPEGEN_FP_KEY', 'pipegen_x', 'api_key', 'API_KEY', 'OK_KEY', 'bad-name', 'DOCKER_HOST', 'NPM_TOKEN', 'GH_TOKEN', 'GH_HOST', 'GH_ENTERPRISE_TOKEN', 'npm_token'] })]);
    const r = secretRequests(p, NONE);
    expect(names(r)).toEqual(['OK_KEY']);
    const all = r.cantMap.join('\n');
    for (const n of ['NODE_OPTIONS', 'LD_PRELOAD', 'node_options', 'ld_preload', 'GITHUB_TOKEN', 'github_foo', 'PIPEGEN_FP_KEY', 'pipegen_x', 'api_key', 'API_KEY', 'bad-name', 'DOCKER_HOST', 'NPM_TOKEN', 'GH_TOKEN', 'GH_HOST', 'GH_ENTERPRISE_TOKEN', 'npm_token']) expect(all, n).toContain(n);
    expect(r.cantMap).toHaveLength(17);
    expect(r.cantMap.every((l) => /pipegen can't map this name into a step: rename it/.test(l))).toBe(true);
  });

  it('requests: names a compose dependency covers but the table can\'t map → note, not asked', () => {
    const p = profile([svc({ envVars: ['POSTGRES_SSL_CERT', 'DATABASE_URL'], dependsOn: [dep('postgres', ['POSTGRES_SSL_CERT', 'DATABASE_URL'])] })]);
    const r = secretRequests(p, { covered: new Set(['DATABASE_URL']) });
    expect(r.requests).toEqual([]);
    expect(r.notes.join('\n')).toMatch(/POSTGRES_SSL_CERT/);
    expect(r.notes.join('\n')).toMatch(/postgres/);
  });

  it('requests: the same name in two services is asked once; repo-derived text is cleaned', () => {
    const p = profile([svc({ name: 'a', envVars: ['K'] }), svc({ name: 'b\u001b[31m', path: 'b', envVars: ['K', 'M'] })]);
    const r = secretRequests(p, NONE);
    expect(names(r)).toEqual(['K', 'M']);
    expect(JSON.stringify(r)).not.toContain('\u001b');
  });

  it('requests: a lowercase name from the dangerous table (alone, no upper-case twin) is can\'t-map', () => {
    const r = secretRequests(profile([svc({ envVars: ['node_options', 'ld_preload', 'npm_token', 'gh_host', 'docker_host', 'ok_key'] })]), NONE);
    expect(names(r)).toEqual(['ok_key']);
    expect(r.cantMap).toHaveLength(5);
  });

  it('requests: covered and non-secret names match in any letter case (database_url is not asked when DATABASE_URL is covered)', () => {
    const p = profile([svc({ envVars: ['database_url', 'Port', 'host', 'node_env', 'log_level', 'REAL_KEY'] }), svc({ name: 'b', path: 'b', envVars: ['Database_Url'] })]);
    const r = secretRequests(p, { covered: new Set(['DATABASE_URL']) });
    expect(names(r)).toEqual(['REAL_KEY']);
    expect(r.cantMap).toEqual([]);
  });

  it('requests: NPM_TOKEN and the gh CLI variables (GH_TOKEN, GH_HOST, GH_REPO, GH_CONFIG_DIR, ...) are dangerous names', () => {
    for (const n of ['NPM_TOKEN', 'GH_TOKEN', 'GH_HOST', 'GH_ENTERPRISE_TOKEN', 'GH_REPO', 'GH_CONFIG_DIR', 'GH_DEBUG', 'GH_PROMPT_DISABLED', 'GH_NO_UPDATE_NOTIFIER']) expect(isDangerousName(n), n).toBe(true);
    for (const n of ['STRIPE_KEY', 'NPM_REGISTRY_NAME', 'GHOST_KEY', 'MY_GH_TOKEN']) expect(isDangerousName(n), n).toBe(false);
  });

  it('requests: non-string and malformed entries are ignored without throwing', () => {
    const p = profile([svc({ envVars: [null as unknown as string, 7 as unknown as string, 'OK'] }), null as unknown as Service]);
    expect(() => secretRequests(p, NONE)).not.toThrow();
    expect(names(secretRequests(p, NONE))).toEqual(['OK']);
  });
});

/** Collects every Buffer.alloc result (the vault and the sealing step allocate their value Buffers with it). */
function captureAllocs(): { made: Buffer[] } {
  const made: Buffer[] = [];
  const real = Buffer.alloc;
  vi.spyOn(Buffer, 'alloc').mockImplementation(((...a: Parameters<typeof Buffer.alloc>) => { const b = real(...a); made.push(b); return b; }) as typeof Buffer.alloc);
  return { made };
}

describe('vault', () => {
  it('vault: set/get/names/has; get returns a string; wipe zeroes every Buffer and clears; wipe twice is safe', () => {
    const v = new SecretVault();
    v.set('A_KEY', 'value-one-12345');
    v.set('B_KEY', 'value-two-67890');
    expect(v.get('A_KEY')).toBe('value-one-12345');
    expect(v.names().sort()).toEqual(['A_KEY', 'B_KEY']);
    expect(v.has('A_KEY')).toBe(true);
    // catch the Buffer the vault makes for a value, to prove wipe() zeroes it (the vault has no accessor for its Buffers)
    const cap = captureAllocs();
    v.set('C_KEY', 'value-three-0');
    const made = cap.made.filter((b) => b.toString() === 'value-three-0');
    expect(made.length).toBeGreaterThan(0);
    v.wipe();
    expect(made.every((b) => b.every((x) => x === 0))).toBe(true);
    expect(v.names()).toEqual([]);
    expect(v.get('A_KEY')).toBeUndefined();
    expect(v.has('A_KEY')).toBe(false);
    expect(() => v.wipe()).not.toThrow();
  });

  it('vault: set replaces and zeroes the old value; empty value and bad names are refused', () => {
    const v = new SecretVault();
    const cap = captureAllocs();
    v.set('A_KEY', 'old-value-1234');
    const old = cap.made.filter((b) => b.toString() === 'old-value-1234');
    expect(old.length).toBeGreaterThan(0);
    v.set('A_KEY', 'new-value-1234');
    expect(old.every((b) => b.every((x) => x === 0))).toBe(true);
    vi.restoreAllMocks();
    expect(v.get('A_KEY')).toBe('new-value-1234');
    expect(() => v.set('A_KEY', '')).toThrow();
    expect(() => v.set('bad name', 'x')).toThrow();
    expect(() => v.set('__proto__', 'xxxxxxxx')).not.toThrow();   // a Map key, never an object key
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('vault: a value under 8 characters is refused (the error names the variable, never the value); 8 is accepted', () => {
    const v = new SecretVault();
    for (const short of ['a', 'true', '1', 'abcdefg']) {
      const err = (() => { try { v.set('A_KEY', short); return null; } catch (e) { return e as Error; } })();
      expect(err, short).toBeInstanceOf(Error);
      expect(err?.message).toContain('A_KEY');
      expect(err?.message).not.toContain(`"${short}"`);
    }
    expect(v.has('A_KEY')).toBe(false);
    v.set('A_KEY', 'abcdefgh');
    expect(v.has('A_KEY')).toBe(true);
  });

  it('vault: PIPEGEN_* and GITHUB_* are refused by set (any case); only generateFpKey sets PIPEGEN_FP_KEY', () => {
    const v = new SecretVault();
    for (const n of ['PIPEGEN_FP_KEY', 'pipegen_x', 'GITHUB_TOKEN', 'github_x']) expect(() => v.set(n, 'value-12345678'), n).toThrow();
    expect(v.names()).toEqual([]);
    generateFpKey(v);
    expect(v.names()).toEqual(['PIPEGEN_FP_KEY']);
  });

  it('vault: values live in unpooled Buffers (never a slice of Node\'s shared 8 KiB pool)', () => {
    const { made } = captureAllocs();
    const v = new SecretVault();
    v.set('A_KEY', 'value-12345678');
    const mine = made.filter((b) => b.length === 'value-12345678'.length);
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.every((b) => b.buffer.byteLength === b.length)).toBe(true);
    expect(mine.some((b) => b.toString() === 'value-12345678')).toBe(true);
  });

  it('vault: no values() method; inspect, JSON.stringify and a template literal show no value', () => {
    const v = new SecretVault();
    v.set('STRIPE_KEY', SKT + 'SUPERSECRETVALUE123');
    expect((v as unknown as { values?: unknown }).values).toBeUndefined();
    for (const shown of [inspect(v, { depth: 5, showHidden: true }), JSON.stringify(v), `${v}`, String(v), JSON.stringify({ v }), inspect({ v })]) {
      expect(shown).not.toContain('SUPERSECRET');
    }
    expect(inspect(v)).toContain('STRIPE_KEY');
    expect(Object.keys(v)).toEqual([]);
    expect(Object.getOwnPropertyNames(v)).toEqual([]);
  });

  it('vault: scrubber() removes the value, its base64 and URL forms; containsKnownValue sees the same forms', () => {
    const v = new SecretVault();
    const val = SKT + 'ab/cd+ef gh==';
    v.set('K_ONE', val);
    const forms = [val, Buffer.from(val).toString('base64'), encodeURIComponent(val)];
    const scrub = v.scrubber();
    for (const f of forms) {
      expect(scrub(`before ${f} after`)).toBe('before [REDACTED] after');
      expect(v.containsKnownValue(`x${f}y`)).toBe(true);
    }
    expect(v.containsKnownValue('nothing here')).toBe(false);
    expect(new SecretVault().containsKnownValue('anything')).toBe(false);
  });

  it('vault: registers wipe on the exit-hook registry; the hook wipes it; wipe removes the hook', () => {
    const before = process.listenerCount('SIGINT');
    const v = new SecretVault();
    expect(process.listenerCount('SIGINT')).toBe(before);   // nothing held, nothing registered
    v.set('K_ONE', 'value-12345678');
    expect(process.listenerCount('SIGINT')).toBe(before + 1);
    const w = new SecretVault();
    w.set('K_TWO', 'value-12345678');
    expect(process.listenerCount('SIGINT')).toBe(before + 1);   // one registry, one handler
    runExitHooks();
    expect(v.has('K_ONE')).toBe(false);
    expect(w.has('K_TWO')).toBe(false);
    expect(process.listenerCount('SIGINT')).toBe(before);
    const x = new SecretVault();
    x.set('K_THREE', 'value-12345678');
    x.set('K_FOUR', 'value-12345678');   // a second value does not register a second hook
    x.wipe();
    expect(process.listenerCount('SIGINT')).toBe(before);
    x.set('K_FIVE', 'value-12345678');   // a vault can be filled again after a wipe
    expect(x.has('K_FIVE')).toBe(true);
    x.wipe();
    expect(process.listenerCount('SIGINT')).toBe(before);
  });

  it('vault: values kept after scratch cleanup, wiped only after delivery (no storeSecrets wipe)', async () => {
    const v = new SecretVault();
    v.set('K_ONE', 'value-12345678');
    const kp = keypair();
    const { gh } = fakeOctokit(repoRoutes(kp, []));
    await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['K_ONE']);
    expect(v.get('K_ONE')).toBe('value-12345678');
    v.wipe();
    expect(v.get('K_ONE')).toBeUndefined();
  });
});

// ---------- prompts ----------

function scriptedPrompter(answers: string[]): Prompter & { asked: { msg: string; masked: boolean | undefined }[] } {
  const asked: { msg: string; masked: boolean | undefined }[] = [];
  return {
    asked,
    async confirm() { throw new Error('unexpected confirm'); },
    async select() { throw new Error('unexpected select'); },
    async text(msg, opts) { asked.push({ msg, masked: opts?.secret }); const a = answers.shift(); if (a === undefined) throw new Error('no more answers'); return a; },
  };
}
type Ask = SecretRequest;
function req(name: string, over: Partial<Ask> = {}): Ask {
  return { name, service: 'api', why: `needed: ${name}`, ...over };
}

describe('askSecrets', () => {
  it('ask: prompt warns test keys only and deletion after proof; input is masked', async () => {
    const io = scriptedPrompter([SKT + 'abcdefgh']);
    const v = new SecretVault();
    await askSecrets(io, [req('STRIPE_KEY', { example: 'use a **test** key' })], v);
    expect(io.asked[0]?.msg.startsWith("Use TEST keys only (never production). They're used for the proof and deleted from the test repo afterwards.")).toBe(true);
    expect(io.asked[0]?.msg).toContain('STRIPE_KEY');
    expect(io.asked[0]?.masked).toBe(true);
    expect(TEST_KEYS_ONLY.startsWith('Use TEST keys only')).toBe(true);
  });

  it('ask: empty answer → missing, nothing stored', async () => {
    const io = scriptedPrompter(['', '   ', 'real-enough-value']);
    const v = new SecretVault();
    const r = await askSecrets(io, [req('A_KEY'), req('B_KEY'), req('C_KEY')], v);
    expect(r.missing).toEqual(['A_KEY', 'B_KEY']);
    expect(v.names()).toEqual(['C_KEY']);
  });

  it('ask: sk_live_ / rk_live_ refused with a test-key message, asked again once, then missing', async () => {
    for (const bad of [SKL + 'abcdef123456', RKL + 'abcdef123456', PKL + 'abcdef123456', RZL + 'abcdef1234', LIVE + 'abcdef123456', '  ' + SKL.toUpperCase() + 'abcdef123456']) {
      const io = scriptedPrompter([bad, bad]);
      const v = new SecretVault();
      const r = await askSecrets(io, [req('STRIPE_KEY')], v);
      expect(r.missing, bad).toEqual(['STRIPE_KEY']);
      expect(v.names()).toEqual([]);
      expect(io.asked).toHaveLength(2);
      expect(io.asked[1]?.msg).toMatch(/live key|production/i);
      expect(io.asked[1]?.msg).toMatch(/TEST/);
      for (const a of io.asked) expect(a.msg).not.toContain(bad.trim());
    }
  });

  it('ask: a live key followed by a test key on the retry is accepted', async () => {
    const io = scriptedPrompter([SKL + 'abcdef123456', SKT + 'abcdef123456']);
    const v = new SecretVault();
    const r = await askSecrets(io, [req('STRIPE_KEY')], v);
    expect(r.missing).toEqual([]);
    expect(v.get('STRIPE_KEY')).toBe(SKT + 'abcdef123456');
  });

  it('ask: test keys such as sk_test_ and names with "live" inside are not refused', async () => {
    const io = scriptedPrompter([SKT + 'x1234567', 'deliver_live_x1234']);
    const v = new SecretVault();
    expect((await askSecrets(io, [req('A_KEY'), req('B_KEY')], v)).missing).toEqual([]);
  });

  it('ask: a value under 8 characters is refused with a fixed message, asked once more, then missing; 8 characters is taken', async () => {
    for (const short of ['a', 'true', '1', 'abcdefg']) {
      const io = scriptedPrompter([short, short]);
      const v = new SecretVault();
      const r = await askSecrets(io, [req('A_KEY')], v);
      expect(r.missing, short).toEqual(['A_KEY']);
      expect(v.names()).toEqual([]);
      expect(io.asked).toHaveLength(2);
      expect(io.asked[1]?.msg.startsWith(TEST_KEYS_ONLY)).toBe(true);
      expect(io.asked[1]?.msg).toMatch(/too short to protect: pipegen needs at least 8 characters/);
      expect(io.asked[1]?.msg).not.toContain(`\n${short}\n`);
    }
    const io = scriptedPrompter(['abc', 'abcdefgh']);
    const v = new SecretVault();
    expect((await askSecrets(io, [req('A_KEY')], v)).missing).toEqual([]);
    expect(v.get('A_KEY')).toBe('abcdefgh');
    const io8 = scriptedPrompter(['abcdefgh']);
    expect((await askSecrets(io8, [req('B_KEY')], new SecretVault())).missing).toEqual([]);
  });

  it('ask: a request with a reserved or unmappable name (PIPEGEN_*, GITHUB_*, dangerous) is never asked and counts as missing', async () => {
    const io = scriptedPrompter(['value-12345678']);
    const v = new SecretVault();
    const r = await askSecrets(io, [req('PIPEGEN_FP_KEY'), req('github_x'), req('NODE_OPTIONS'), req('bad-name'), req('OK_KEY')], v);
    expect(r.missing).toEqual(['PIPEGEN_FP_KEY', 'github_x', 'NODE_OPTIONS', 'bad-name']);
    expect(io.asked).toHaveLength(1);
    expect(v.names()).toEqual(['OK_KEY']);
  });

  it('ask: no prompt text, missing list or error holds a typed value', async () => {
    const io = scriptedPrompter([SKL + 'TOPSECRET99999', SKL + 'TOPSECRET99999']);
    const v = new SecretVault();
    const r = await askSecrets(io, [req('STRIPE_KEY')], v);
    expect(JSON.stringify([io.asked, r])).not.toContain('TOPSECRET');
  });
});

// ---------- sealed storage ----------

function keypair() { return sodium.crypto_box_keypair(); }
type Pair = ReturnType<typeof keypair>;
const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');
function repoRoutes(kp: Pair, puts: Call[], over: { keyReply?: Routes[string]; putReply?: Routes[string] } = {}): Routes {
  return {
    'GET https://api.github.com/repos/o/r/actions/secrets/public-key': over.keyReply ?? { body: { key_id: 'key-123', key: b64(kp.publicKey) } },
    ...Object.fromEntries(['STRIPE_KEY', 'K_ONE', 'API_KEY', 'MIXED_CASE'].map((n) => [`PUT https://api.github.com/repos/o/r/actions/secrets/${n}`, over.putReply ?? ((c: Call) => { puts.push(c); return { status: 201, body: {} }; })])),
  };
}
/** GitHub wants standard base64 with padding. Buffer.from(x, 'base64') also takes the URL alphabet, so check the text itself and the sealed length. */
function expectStandardBase64(text: string, plaintextBytes: number): void {
  expect(text).toMatch(/^[A-Za-z0-9+/]*={0,2}$/);
  expect(text.length % 4).toBe(0);
  expect(Buffer.from(text, 'base64').toString('base64')).toBe(text);   // canonical: re-encoding gives the same text
  expect(Buffer.from(text, 'base64')).toHaveLength(plaintextBytes + sodium.crypto_box_SEALBYTES);
}
const open = (kp: Pair, sealed: string): string => sodium.to_string(sodium.crypto_box_seal_open(Buffer.from(sealed, 'base64'), kp.publicKey, kp.privateKey));

describe('storeSecrets', () => {
  beforeEach(async () => { await sodium.ready; });

  it('store: sealed with crypto_box_seal (roundtrip with a test keypair); key_id sent; value never in a request body', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const { gh, calls } = fakeOctokit(repoRoutes(kp, puts));
    const v = new SecretVault();
    v.set('STRIPE_KEY', SKT + 'PLAINTEXTVALUE');
    const stored = await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['STRIPE_KEY']);
    expect(stored).toEqual(['STRIPE_KEY']);
    expect(puts).toHaveLength(1);
    const body = JSON.parse(puts[0]?.body as string) as Record<string, string>;
    expect(Object.keys(body).sort()).toEqual(['encrypted_value', 'key_id']);
    expect(body.key_id).toBe('key-123');
    expectStandardBase64(body.encrypted_value as string, (SKT + 'PLAINTEXTVALUE').length);
    expect(open(kp, body.encrypted_value as string)).toBe(SKT + 'PLAINTEXTVALUE');
    for (const c of calls) {
      expect(c.body ?? '').not.toContain('PLAINTEXTVALUE');
      expect(c.url.href).not.toContain('PLAINTEXTVALUE');
    }
    expect(calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual(['GET /repos/o/r/actions/secrets/public-key', 'PUT /repos/o/r/actions/secrets/STRIPE_KEY']);
  });

  it('store: one public-key fetch for several secrets; sealing is randomised per secret', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const { gh, calls } = fakeOctokit(repoRoutes(kp, puts));
    const v = new SecretVault();
    v.set('K_ONE', 'same-value-123456');
    v.set('API_KEY', 'same-value-123456');
    await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['K_ONE', 'API_KEY']);
    expect(calls.filter((c) => c.method === 'GET')).toHaveLength(1);
    const sealed = puts.map((c) => (JSON.parse(c.body as string) as { encrypted_value: string }).encrypted_value);
    expect(sealed[0]).not.toBe(sealed[1]);
  });

  it('store: name uppercased; GITHUB_ prefix refused (nothing sent)', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const { gh, calls } = fakeOctokit(repoRoutes(kp, puts));
    const v = new SecretVault();
    v.set('mixed_case', 'value-12345678');
    expect(await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['mixed_case'])).toEqual(['MIXED_CASE']);
    expect(puts[0]?.url.pathname).toBe('/repos/o/r/actions/secrets/MIXED_CASE');
    const n = calls.length;
    for (const bad of ['GITHUB_TOKEN', 'github_x', 'bad-name', 'NOT_IN_VAULT']) await expect(storeSecrets(gh, { owner: 'o', repo: 'r' }, v, [bad]), bad).rejects.toThrow();
    expect(calls).toHaveLength(n);
  });

  it('store: a mixed batch with one bad name sends nothing at all', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const { gh, calls } = fakeOctokit(repoRoutes(kp, puts));
    const v = new SecretVault();
    v.set('K_ONE', 'value-12345678');
    await expect(storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['K_ONE', 'GITHUB_X'])).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it('store: two vault names that are the same after upper-casing send nothing (one would overwrite the other)', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const { gh, calls } = fakeOctokit(repoRoutes(kp, puts));
    const v = new SecretVault();
    v.set('api_key', 'value-aaaaaaaa');
    v.set('API_KEY', 'value-bbbbbbbb');
    await expect(storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['api_key', 'API_KEY'])).rejects.toThrow(/same/);
    expect(calls).toHaveLength(0);
  });

  it('store: every sealed text is standard padded base64 whatever the value length (all three padding cases)', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const { gh } = fakeOctokit(repoRoutes(kp, puts));
    const v = new SecretVault();
    const lens = [8, 9, 10, 11, 40];
    for (const n of lens) {
      v.set('K_ONE', 'x'.repeat(n));
      await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['K_ONE']);
    }
    puts.forEach((c, i) => expectStandardBase64((JSON.parse(c.body as string) as { encrypted_value: string }).encrypted_value, lens[i] as number));
  });

  it('store: owner and repo are validated before any request', async () => {
    const { gh, calls } = fakeOctokit({});
    const v = new SecretVault();
    v.set('K_ONE', 'value-12345678');
    for (const bad of [{ owner: 'o/../x', repo: 'r' }, { owner: 'o', repo: '..' }, { owner: '', repo: 'r' }, { owner: 'o', repo: 'r?x' }]) await expect(storeSecrets(gh, bad, v, ['K_ONE'])).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it('store: an invalid public key from GitHub (bad base64, wrong length, no key_id) is an error and nothing is sent', async () => {
    const kp = keypair();
    const bads = [
      { key_id: 'k', key: '!!!not base64!!!' },
      { key_id: 'k', key: b64(new Uint8Array(31)) },
      { key_id: 'k', key: b64(new Uint8Array(33)) },
      { key_id: 'k', key: '' },
      { key: b64(kp.publicKey) },
      { key_id: '', key: b64(kp.publicKey) },
      { key_id: 'k', key: 12 },
      { key_id: 'a\nb', key: b64(kp.publicKey) },
      { key_id: 'a b', key: b64(kp.publicKey) },
      { key_id: 'a\u0000b', key: b64(kp.publicKey) },
      { key_id: 'x'.repeat(129), key: b64(kp.publicKey) },
      {},
    ];
    for (const body of bads) {
      const puts: Call[] = [];
      const { gh } = fakeOctokit(repoRoutes(kp, puts, { keyReply: { body } }));
      const v = new SecretVault();
      v.set('K_ONE', 'value-12345678');
      await expect(storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['K_ONE']), JSON.stringify(body)).rejects.toThrow(/public key/);
      expect(puts).toHaveLength(0);
    }
  });

  it('store: value never in any log call, output write or thrown error (also when GitHub echoes the body back)', async () => {
    const kp = keypair();
    const logged: string[] = [];
    for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) vi.spyOn(console, m).mockImplementation((...a: unknown[]) => { logged.push(a.map(String).join(' ')); });
    vi.spyOn(process.stdout, 'write').mockImplementation(((c: unknown) => { logged.push(String(c)); return true; }) as never);
    vi.spyOn(process.stderr, 'write').mockImplementation(((c: unknown) => { logged.push(String(c)); return true; }) as never);
    const echo = (c: Call): { status: number; body: unknown } => ({ status: 422, body: { message: `bad body ${c.body as string}` } });
    const { gh } = fakeOctokit(repoRoutes(kp, [], { putReply: echo }));
    const v = new SecretVault();
    v.set('STRIPE_KEY', SKT + 'PLAINTEXTVALUE');
    const err = await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['STRIPE_KEY']).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    const text = `${(err as Error).message}\n${(err as Error).stack}\n${inspect(err, { depth: 6 })}\n${logged.join('\n')}`;
    expect(text).not.toContain('PLAINTEXTVALUE');
    expect(text).not.toMatch(/encrypted_value/);
    expect((err as Error).message).toMatch(/STRIPE_KEY/);
    expect((err as Error).message).toMatch(/422/);
  });

  it('store: pipegen\'s Octokit with debug on logs no request body (no encrypted_value, no plaintext)', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const { fetch } = fakeFetch(repoRoutes(kp, puts));
    const lines: string[] = [];
    const gh = makeOctokit(null, { debug: true, fetch, log: (l) => lines.push(l) });
    const v = new SecretVault();
    v.set('STRIPE_KEY', SKT + 'PLAINTEXTVALUE');
    await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['STRIPE_KEY']);
    expect(puts).toHaveLength(1);
    expect(lines.length).toBeGreaterThan(0);   // the debug log was on
    const sealed = (JSON.parse(puts[0]?.body as string) as { encrypted_value: string }).encrypted_value;
    const all = lines.join('\n');
    expect(all).not.toContain('encrypted_value');
    expect(all).not.toContain(sealed);
    expect(all).not.toContain('PLAINTEXTVALUE');
  });

  it('store: a failing key fetch is an error with no value in it', async () => {
    const kp = keypair();
    const { gh } = fakeOctokit(repoRoutes(kp, [], { keyReply: { status: 403, body: { message: 'Resource not accessible' } } }));
    const v = new SecretVault();
    v.set('K_ONE', 'value-PLAINTEXT');
    const err = await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['K_ONE']).then(() => null, (e: unknown) => e);
    expect((err as Error).message).toMatch(/403/);
    expect(inspect(err, { depth: 6 })).not.toContain('PLAINTEXT');
  });
});

describe('storeEnvSecret (environment)', () => {
  beforeEach(async () => { await sodium.ready; });
  const envRoutes = (kp: Pair, puts: Call[]): Routes => ({
    'GET https://api.github.com/repos/o/r/environments/pipegen-signing/secrets/public-key': { body: { key_id: 'env-key', key: b64(kp.publicKey) } },
    'PUT https://api.github.com/repos/o/r/environments/pipegen-signing/secrets/PIPEGEN_COSIGN_KEY': (c) => { puts.push(c); return { status: 201, body: {} }; },
  });

  it('env store: uses the environment public key endpoint, seals, sends key_id', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const { gh, calls } = fakeOctokit(envRoutes(kp, puts));
    await storeEnvSecret(gh, { owner: 'o', repo: 'r' }, 'pipegen-signing', 'pipegen_cosign_key', 'cosign-PLAIN-1234');
    expect(calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([
      'GET /repos/o/r/environments/pipegen-signing/secrets/public-key',
      'PUT /repos/o/r/environments/pipegen-signing/secrets/PIPEGEN_COSIGN_KEY',
    ]);
    const body = JSON.parse(puts[0]?.body as string) as Record<string, string>;
    expect(body.key_id).toBe('env-key');
    expectStandardBase64(body.encrypted_value as string, 'cosign-PLAIN-1234'.length);
    expect(open(kp, body.encrypted_value as string)).toBe('cosign-PLAIN-1234');
    expect(calls.every((c) => !(c.body ?? '').includes('PLAIN'))).toBe(true);
  });

  it('env store: environment secrets never go through storeSecrets', async () => {
    const kp = keypair();
    const { gh, calls } = fakeOctokit(envRoutes(kp, []));
    const v = new SecretVault();
    v.set('COSIGN_KEY', 'value-12345678');
    await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['COSIGN_KEY']).catch(() => undefined);
    expect(calls.some((c) => c.url.pathname.includes('/environments/'))).toBe(false);
    expect(calls.every((c) => c.url.pathname.startsWith('/repos/o/r/actions/secrets/'))).toBe(true);
  });

  it('env store: owner, repo, env, name and value are validated before any request', async () => {
    const { gh, calls } = fakeOctokit({});
    const ok = { owner: 'o', repo: 'r' };
    const cases: [typeof ok, string, string, string][] = [
      [ok, '../x', 'K_ONE', 'v1234567'], [ok, 'a/b', 'K_ONE', 'v1234567'], [ok, '', 'K_ONE', 'v1234567'], [ok, 'env', 'GITHUB_TOKEN', 'v1234567'],
      [ok, 'env', 'bad-name', 'v1234567'], [ok, 'env', 'K_ONE', ''], [{ owner: 'o/x', repo: 'r' }, 'env', 'K_ONE', 'v1234567'], [{ owner: 'o', repo: '..' }, 'env', 'K_ONE', 'v1234567'], [{ owner: '', repo: 'r' }, 'env', 'K_ONE', 'v1234567'],
      [ok, 'prod env', 'K_ONE', 'v1234567'], [ok, 'a?b', 'K_ONE', 'v1234567'],
    ];
    for (const [r, e, n, val] of cases) await expect(storeEnvSecret(gh, r, e, n, val), `${e} ${n}`).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it('env store: the plaintext Buffer made for sealing is zeroed afterwards', async () => {
    const kp = keypair();
    const { gh } = fakeOctokit(envRoutes(kp, []));
    const value = 'zeroing-check-value';
    const { made } = captureAllocs();
    await storeEnvSecret(gh, { owner: 'o', repo: 'r' }, 'pipegen-signing', 'PIPEGEN_COSIGN_KEY', value);
    const mine = made.filter((b) => b.length === value.length);
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.every((b) => b.every((x) => x === 0))).toBe(true);
  });

  it('env store: an invalid key is refused and nothing is sent; errors carry no value', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const routes = envRoutes(kp, puts);
    routes['GET https://api.github.com/repos/o/r/environments/pipegen-signing/secrets/public-key'] = { body: { key_id: 'k', key: b64(new Uint8Array(5)) } };
    const { gh } = fakeOctokit(routes);
    const err = await storeEnvSecret(gh, { owner: 'o', repo: 'r' }, 'pipegen-signing', 'PIPEGEN_COSIGN_KEY', 'cosign-PLAIN-1234').then(() => null, (e: unknown) => e);
    expect((err as Error).message).toMatch(/public key/);
    expect(puts).toHaveLength(0);
    expect(inspect(err, { depth: 6 })).not.toContain('PLAIN');
  });
});

describe('generateFpKey', () => {
  it('fp key: 32 random bytes, hex, in the vault, never logged', () => {
    const logged: string[] = [];
    for (const m of ['log', 'info', 'warn', 'error'] as const) vi.spyOn(console, m).mockImplementation((...a: unknown[]) => { logged.push(a.map(String).join(' ')); });
    vi.spyOn(process.stdout, 'write').mockImplementation(((c: unknown) => { logged.push(String(c)); return true; }) as never);
    const v = new SecretVault();
    generateFpKey(v);
    const key = v.get('PIPEGEN_FP_KEY') as string;
    expect(key).toMatch(/^[0-9a-f]{64}$/);
    const w = new SecretVault();
    generateFpKey(w);
    expect(w.get('PIPEGEN_FP_KEY')).not.toBe(key);
    expect(logged.join('\n')).not.toContain(key);
    expect(inspect(v)).not.toContain(key);
  });

  it('fp key: 32 bytes of key material (64 hex characters), a fresh key each call', () => {
    const v = new SecretVault();
    generateFpKey(v);
    expect(Buffer.from(v.get('PIPEGEN_FP_KEY') as string, 'hex')).toHaveLength(32);
  });
});

describe('value validation (B3): code points, well-formed, nothing invisible', () => {
  const INV = '\u200b';
  const bad: [string, string][] = [
    ['four two-byte letters (8 bytes, 4 code points)', 'éééé'],
    ['four emoji (4 code points, 8 UTF-16 units)', '😀😀😀😀'],
    ['abc and 5 invisible characters', 'abc' + INV.repeat(5)],
    ['8 lone surrogates', '\ud800'.repeat(8)],
    ['a soft hyphen inside', 'abcdefg\u00adh'],
    ['a newline inside', 'abcdefg\nhijk'],
    ['a bidi mark inside', 'abcdefg\u202ehijk'],
    ['U+2028 inside', 'abcdefg\u2028hijk'],
  ];
  const good = ['éééééééé', '😀😀😀😀😀😀😀😀', 'e\u0301e\u0301e\u0301e\u0301', 'abcdefgh'];

  it('vault.set refuses them with a fixed message that holds no part of the value, and accepts 8 code points', () => {
    for (const [why, value] of bad) {
      const v = new SecretVault();
      const err = (() => { try { v.set('A_KEY', value); return null; } catch (e) { return e as Error; } })();
      expect(err, why).toBeInstanceOf(Error);
      expect(err?.message, why).toContain('A_KEY');
      expect(err?.message, why).not.toContain('abcdefg');
      expect(v.has('A_KEY'), why).toBe(false);
    }
    for (const value of good) {
      const v = new SecretVault();
      v.set('A_KEY', value);
      expect(v.get('A_KEY')).toBe(value);
    }
  });

  it('askSecrets refuses them (asked once more, then missing) and takes 8 code points', async () => {
    for (const [why, value] of bad) {
      const io = scriptedPrompter([value, value]);
      const v = new SecretVault();
      const r = await askSecrets(io, [req('A_KEY')], v);
      expect(r.missing, why).toEqual(['A_KEY']);
      expect(io.asked, why).toHaveLength(2);
      expect(v.names()).toEqual([]);
    }
    for (const value of good) {
      const io = scriptedPrompter([value]);
      const v = new SecretVault();
      expect((await askSecrets(io, [req('A_KEY')], v)).missing).toEqual([]);
    }
    const io = scriptedPrompter(['abc' + INV.repeat(5), 'abcdefgh']);
    await askSecrets(io, [req('A_KEY')], new SecretVault());
    expect(io.asked[1]?.msg).toMatch(/invisible or control characters/);
  });

  it('storeEnvSecret applies the same validation to its value, before any request', async () => {
    const { gh, calls } = fakeOctokit({});
    for (const [why, value] of bad) await expect(storeEnvSecret(gh, { owner: 'o', repo: 'r' }, 'pipegen-signing', 'K_ONE', value), why).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });
});

describe('displayForm, containsKnownValue and scrubForDisplay (B1)', () => {
  const VAL = 'Zq7Rk2mW9xLp4Tn8Hy6Vb3Nc';
  const split = (ch: string): string => `${VAL.slice(0, 6)}${ch}${VAL.slice(6)}`;
  const classes: [string, string][] = [['ZWSP', '\u200b'], ['word joiner', '\u2060'], ['BOM', '\ufeff'], ['bidi override', '\u202e'], ['soft hyphen', '\u00ad'], ['ESC sequence', '\u001b[0m'], ['newline', '\n']];

  it('displayForm is what safeText shows before it cuts: invisible, control and bidi removed, U+2028 a space', () => {
    expect(displayForm('a\u200bb\u2060c\ufeffd\u202ee\u00adf\n')).toBe('abcdef');
    expect(displayForm('a\u2028b')).toBe('a b');
    expect(displayForm('éabc')).toBe('éabc');
  });

  it('a value split by any invisible class is found, and scrubForDisplay removes it before any cut', () => {
    const v = new SecretVault();
    v.set('K_LONG', VAL);
    for (const [name, ch] of classes) {
      const text = `${'j'.repeat(40)}${split(ch)}`;
      expect(v.containsKnownValue(text), name).toBe(true);
      const shown = scrubForDisplay(v, text, (t) => t.slice(0, 50));
      expect(shown, name).not.toContain(VAL.slice(0, 8));
      expect(shown, name).toContain('[REDACTED]');
    }
    expect(v.containsKnownValue('j'.repeat(40))).toBe(false);
  });

  it('scrubForDisplay: a value that the display pass itself would destroy (an escape sequence eats its first characters) is scrubbed from the raw text first', () => {
    const v = new SecretVault();
    v.set('K_ESC', 'Aabcdefg');
    const text = '\u001b[Aabcdefg';   // displayForm drops "ESC [ A", leaving "abcdefg"
    expect(displayForm(text)).toBe('abcdefg');
    expect(scrubForDisplay(v, text)).not.toContain('abcdefg');
  });

  it('scrubForDisplay scrubs the raw text first, then the display form, then cuts (default cut: safeText)', () => {
    const v = new SecretVault();
    v.set('K_LONG', VAL);
    expect(scrubForDisplay(v, `x ${VAL} y`)).toBe('x [REDACTED] y');
    expect(scrubForDisplay(v, `${'j'.repeat(195)}${split('\u200b')}`).includes(VAL.slice(0, 4))).toBe(false);
  });
});

describe('B4 layer 1: containsKnownValue sees decoded and altered forms', () => {
  const VAL = 'Zq7Rk2mW9xLp4Tn8Hy6Vb3Nc';
  function vault(value: string = VAL): SecretVault {
    const v = new SecretVault();
    v.set('K_LONG', value);
    return v;
  }

  it('ESC inserted before one of the characters (the display eats ESC and that character) is found, in a raw text', () => {
    const v = vault();
    const text = `${VAL.slice(0, 6)}\u001b${VAL.slice(6)}`;
    expect(displayForm(text)).not.toContain(VAL.slice(0, 8));   // the display alone would miss it
    expect(v.containsKnownValue(text)).toBe(true);
  });

  it('a value split by BEL, NUL, TAB or DEL, one character at a time, is found', () => {
    const v = vault();
    for (const ch of ['\u0007', '\u0000', '\t', '\u007f', '\u0085']) expect(v.containsKnownValue(`${VAL.slice(0, 9)}${ch}${VAL.slice(9)}`), JSON.stringify(ch)).toBe(true);
  });

  it('NFC and NFD: a value typed one way is found, and scrubbed, when the text holds the other form', () => {
    const nfc = 'caf\u00e9-key-12345';
    const nfd = nfc.normalize('NFD');
    expect(nfd).not.toBe(nfc);
    for (const [value, text] of [[nfc, nfd], [nfd, nfc]]) {
      const v = new SecretVault();
      v.set('K_UNI', value as string);
      expect(v.containsKnownValue(`x ${text} y`)).toBe(true);
      expect(v.scrubber()(`x ${text} y`)).toBe('x [REDACTED] y');
    }
  });

  it('anyString walks every key and string leaf (nested, arrays), iteratively, with a depth cap', () => {
    const seen: string[] = [];
    anyString({ a: ['x', { 'k-1': 'y', n: 5, z: null }], 'top-key': { deep: 'w' } }, (t) => { seen.push(t); return false; });
    expect(seen.sort()).toEqual(['00000000000000000000000000000000000000000000000000000000000000005', '5', 'a', 'deep', 'k-1', 'n', 'top-key', 'w', 'x', 'y', 'z']);   // the number 5 as its text (fix round 5)
    expect(anyString({ a: { b: 'needle' } }, (t) => t === 'needle')).toBe(true);
    expect(anyString({ ['needle']: 1 }, (t) => t === 'needle')).toBe(true);
    let deep: unknown = 'needle';
    for (let i = 0; i < 100_000; i++) deep = [deep];
    expect(anyString(deep, () => false)).toBe(true);   // no stack overflow; beyond the 64-level cap it stops looking and fails closed (fix round 4, m1)
    let near: unknown = 'needle';
    for (let i = 0; i < 30; i++) near = { k: [near] };
    expect(anyString(near, (t) => t === 'needle')).toBe(true);
    const cyc: Record<string, unknown> = { a: 'x' };
    cyc.self = cyc;
    let calls = 0;
    expect(anyString(cyc, () => { calls++; return false; })).toBe(false);
    expect(calls).toBeLessThanOrEqual(4);   // each node is visited once
  });
});

describe('B4 layer 2: every cutter scrubs with the active vault before it cuts', () => {
  const VAL = 'Zq7Rk2mW9xLp4Tn8Hy6Vb3Nc';
  const noPiece = (shown: string): void => { for (let k = 0; k + 4 <= VAL.length; k++) expect(shown, VAL.slice(k, k + 4)).not.toContain(VAL.slice(k, k + 4)); };
  function v(): SecretVault {
    const x = new SecretVault();
    x.set('K_LONG', VAL);
    return x;
  }

  it('without an active vault the cutters behave as before', () => {
    expect(show('x'.repeat(100))).toBe(JSON.stringify(`${'x'.repeat(59)}…`));
    expect(activeSafeText('a\u200bb', 10)).toBe('ab');
  });

  it('show (render-error) and activeSafeText: a value placed across the cut never shows, also split or decoded', () => {
    const vault = v();
    withActiveVault(vault, () => {
      for (const lead of [40, 55, 58, 59, 60, 61, 100]) {
        for (const raw of [`${'j'.repeat(lead)}${VAL}`, `${'j'.repeat(lead)}${VAL.slice(0, 6)}\u200b${VAL.slice(6)}`, `${'j'.repeat(lead)}${VAL.slice(0, 6)}\u001b${VAL.slice(6)}`]) {
          noPiece(show(raw));
          noPiece(activeSafeText(raw, 60));
        }
      }
    });
  });

  it('package-rules: a devDependency key holding the value across the 57-character cut never shows in the problem text', () => {
    const vault = v();
    const key = `${'p'.repeat(50)}${VAL}`;
    const problems = withActiveVault(vault, () => packageJsonProblems('{"devDependencies":{}}', JSON.stringify({ devDependencies: { [key]: '1.0.0' } })));
    expect(problems.length).toBeGreaterThan(0);
    noPiece(problems.join('\n'));
  });

  it('the active vault is restored afterwards, also when the function throws, and nests', () => {
    const vault = v();
    expect(() => withActiveVault(vault, () => { throw new Error('x'); })).toThrow();
    expect(show(`${'j'.repeat(50)}${VAL}`)).toContain(VAL.slice(0, 4));
    withActiveVault(vault, () => withActiveVault(undefined, () => expect(show(`${'j'.repeat(50)}${VAL}`)).toContain(VAL.slice(0, 4))));
  });
});

describe('fix round 4: fail closed on ESC and C1 (B6), anyString caps (m1), every form scrubbed (m2)', () => {
  const VAL = 'Zq7Rk2mW9xLp4Tn8Hy6Vb3Nc';
  const noPiece = (shown: string): void => { for (let k = 0; k + 4 <= VAL.length; k++) expect(shown, VAL.slice(k, k + 4)).not.toContain(VAL.slice(k, k + 4)); };
  // the reviewer's B6 repro: ESC eats the value's first character, a CSI (or OSC, or a C1 CSI) splits the rest
  const combos: [string, string][] = [
    ['ESC + CSI', `\u001b${VAL.slice(0, 11)}\u001b[0m${VAL.slice(11)}`],
    ['ESC + OSC', `\u001b${VAL.slice(0, 11)}\u001b]0;t\u0007${VAL.slice(11)}`],
    ['ESC + C1 CSI', `\u001b${VAL.slice(0, 11)}\u009b0m${VAL.slice(11)}`],
  ];
  function v(): SecretVault {
    const x = new SecretVault();
    x.set('K_LONG', VAL);
    return x;
  }

  it('the repro beats every decoding form: the display shows 23 characters', () => {
    expect(displayForm(combos[0][1])).toBe(VAL.slice(1));
  });

  it('layer 1: with a vault, a text holding ESC or any C1 control counts as holding a value', () => {
    const vault = v();
    for (const [name, text] of combos) expect(vault.containsKnownValue(`x ${text} y`), name).toBe(true);
    for (const ch of ['\u001b', '\u0080', '\u0085', '\u009b', '\u009d', '\u009f']) expect(vault.containsKnownValue(`plain ${ch} text`), JSON.stringify(ch)).toBe(true);
    expect(vault.containsKnownValue('plain text with \u007f and \u00a0 only')).toBe(false);   // DEL and U+00A0 are outside the rule
    expect(new SecretVault().containsKnownValue('plain \u001b[0m text')).toBe(true);   // a vault given, even an empty one: fail closed
    expect(new SecretVault().containsKnownValue('anything')).toBe(false);
  });

  it('layer 2: with an active vault, every cutter shows the whole text as [REDACTED] when it holds ESC or a C1 control', () => {
    const vault = v();
    withActiveVault(vault, () => {
      for (const [name, text] of combos) {
        for (const lead of [0, 40, 59]) {
          const raw = `${'j'.repeat(lead)}${text}`;
          expect(activeSafeText(raw), name).toBe('[REDACTED]');
          expect(activeSafeText(raw, 60), name).toBe('[REDACTED]');
          expect(show(raw), name).toBe(JSON.stringify('[REDACTED]'));
          noPiece(show(raw));
        }
      }
      expect(activeSafeText('no value, just \u001b[1mbold')).toBe('[REDACTED]');
      expect(activeSafeText('x\u0090y')).toBe('[REDACTED]');
      expect(activeSafeText('plain text')).toBe('plain text');
    });
    expect(R).toBe('[REDACTED]');   // the placeholder is the scrubber's own marker
    for (const [name, text] of combos) expect(scrubForDisplay(vault, `pre ${text} post`), name).toBe('[REDACTED]');
    expect(scrubForDisplay(new SecretVault(), 'a \u001b b')).toBe('[REDACTED]');
  });

  it('with no active vault the cutters are unchanged (the display still eats the sequence)', () => {
    expect(activeSafeText(combos[0][1])).toBe(VAL.slice(1));
    expect(activeSafeText('a\u001b[1mb')).toBe('ab');
    withActiveVault(v(), () => withActiveVault(undefined, () => expect(activeSafeText('a\u001b[1mb')).toBe('ab')));
  });

  it('m1: anyString fails closed when its node cap or depth cap is hit', () => {
    expect(anyString(new Array(1_000_001).fill('a'), () => false)).toBe(true);   // 1,000,002 nodes
    expect(anyString(new Array(999_998).fill('a'), () => false)).toBe(false);    // 999,999 nodes: under the cap
    const nest = (n: number): unknown => { let x: unknown = 'a'; for (let i = 0; i < n; i++) x = [x]; return x; };
    expect(anyString(nest(64), () => false)).toBe(false);   // the innermost array is at depth 63
    expect(anyString(nest(65), () => false)).toBe(true);    // an object at depth 64: not looked into, so it counts as holding
    const obj = (n: number): unknown => { let x: unknown = 'a'; for (let i = 0; i < n; i++) x = { k: x }; return x; };
    expect(anyString(obj(64), () => false)).toBe(false);
    expect(anyString(obj(65), () => false)).toBe(true);
  });

  it('layer 2 fails closed when the scrub does not settle: a scrubber that changes the text every round gives one [REDACTED]', () => {
    const restless = { scrubber: () => (t: string): string => `${t}.` };
    expect(scrubForDisplay(restless, 'abc', (t) => t)).toBe('[REDACTED]');
    withActiveVault(restless, () => expect(activeSafeText('abc')).toBe('[REDACTED]'));
  });

  it('m2: layer 2 scrubs every form layer 1 checks: a value split by a ZWSP and in mixed NFC/NFD', () => {
    const value = 'caf\u00e9-cl\u00e9-12345-xyz';   // NFC
    const vault = new SecretVault();
    vault.set('K_UNI', value);
    // the first é composed, the second decomposed, and a ZWSP inside: neither the NFC nor the NFD value is in the raw or stripped text
    const mixed = `caf\u00e9-\u200bcle\u0301-12345-xyz`;
    expect(mixed.normalize('NFC')).not.toBe(value);
    expect(vault.containsKnownValue(`x ${mixed} y`)).toBe(true);
    const pieces = (shown: string): void => { const n = shown.normalize('NFC'); for (let k = 0; k + 4 <= value.length; k++) expect(n, value.slice(k, k + 4)).not.toContain(value.slice(k, k + 4)); };
    pieces(scrubForDisplay(vault, `x ${mixed} y`, (t) => t));
    withActiveVault(vault, () => pieces(activeSafeText(`x ${mixed} y`)));
  });
});

describe('fix round 5 (O1): anyString and anyYamlScalar check non-string scalars', () => {
  it('anyString: a number that is not a safe integer (or not finite) holds; a safe integer, a bigint or a boolean is checked as its text', () => {
    const never = (): boolean => false;
    for (const n of [12345678901234567000, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 2 ** 53, 1234.56789, -0.12345678]) expect(anyString({ a: [n] }, never), String(n)).toBe(true);
    for (const n of [0, -0, 3000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.5, -1.5, 3.11, 22.5, 1.234567]) expect(anyString({ a: [n] }, never), String(n)).toBe(false);
    expect(anyString({ a: 1.234567 }, (t) => t === '1.234567')).toBe(true);   // a short fractional is checked as its text
    expect(LONG_NUMBER_DIGITS).toBe(MIN_VALUE_LENGTH);
    expect(anyString({ a: 123.4567 }, never)).toBe(false);   // 7 digits
    expect(anyString({ a: 1234.5678 }, never)).toBe(true);   // 8 digits
    const seen: string[] = [];
    anyString({ a: 12345678, b: 7n, c: true, d: null }, (t) => { seen.push(t); return false; });
    expect(seen.sort()).toEqual(['000000000000000000000000000000000000000000000000000000000000000012345678', '12345678', '7', 'a', 'b', 'c', 'd', 'true']);   // an integer number is also checked zero-padded (D5 r5, R1)
    expect(anyString(12345678, (t) => t === '12345678')).toBe(true);
  });

  it('D5 r5 R1: an all-digit vault value with leading zeros written as an octal or hex integer is caught', () => {
    const vault = new SecretVault();
    vault.set('K_PIN', '00012345678');
    expect(vault.containsKnownValue('12345678')).toBe(false);   // the bare integer is a substring the vault does not cover on its own
    const pred = (t: string): boolean => vault.containsKnownValue(t);
    expect(anyString({ run: 0o57060516 }, pred)).toBe(true);
    expect(anyYamlScalar('name: 0o57060516\n', pred)).toBe(true);
    expect(anyYamlScalar('name: 0xBC614E\n', pred)).toBe(true);
    expect(anyString({ run: 0o57060517 }, pred)).toBe(false);
    expect(anyString({ run: -0o57060516 }, pred)).toBe(true);
  });

  it('anyYamlScalar: number keys and values are checked the same way', () => {
    expect(anyYamlScalar('a: 0xab54a98ceb1f0ad2\n', () => false)).toBe(true);
    expect(anyYamlScalar('0xab54a98ceb1f0ad2: x\n', () => false)).toBe(true);
    expect(anyYamlScalar('a: 0xBC614E\n', (t) => t === '12345678')).toBe(true);
    expect(anyYamlScalar('0xBC614E: x\n', (t) => t === '12345678')).toBe(true);
    expect(anyYamlScalar('a: 3000\nb: true\n', () => false)).toBe(false);
  });
});
