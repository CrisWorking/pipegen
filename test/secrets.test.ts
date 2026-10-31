// D5 (v0.2 Plan D Task 4, rulings S8/S10): secret requests, the vault, askSecrets, sealed storage, the fingerprint key.
import { inspect } from 'node:util';
import sodium from 'libsodium-wrappers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Prompter } from '../src/cli/io.js';
import { composeCoveredNames } from '../src/create/compose.js';
import {
  askSecrets, coveredNames, generateFpKey, secretRequests, SecretVault, storeEnvSecret, storeSecrets,
  TEST_KEYS_ONLY, type SecretRequest,
} from '../src/create/secrets.js';
import { runExitHooks } from '../src/util/exit-hooks.js';
import type { CreatedFile, Dependency, DependencyKind, Service } from '../src/types.js';
import { fakeOctokit, type Call, type Routes } from './helpers/fake-http.js';
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
    const p = profile([svc({ envVars: ['NODE_OPTIONS', 'LD_PRELOAD', 'GITHUB_TOKEN', 'github_foo', 'PIPEGEN_FP_KEY', 'pipegen_x', 'api_key', 'API_KEY', 'OK_KEY', 'bad-name', 'DOCKER_HOST'] })]);
    const r = secretRequests(p, NONE);
    expect(names(r)).toEqual(['OK_KEY']);
    const all = r.cantMap.join('\n');
    for (const n of ['NODE_OPTIONS', 'LD_PRELOAD', 'GITHUB_TOKEN', 'github_foo', 'PIPEGEN_FP_KEY', 'pipegen_x', 'api_key', 'API_KEY', 'bad-name', 'DOCKER_HOST']) expect(all, n).toContain(n);
    expect(r.cantMap).toHaveLength(10);
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

  it('requests: non-string and malformed entries are ignored without throwing', () => {
    const p = profile([svc({ envVars: [null as unknown as string, 7 as unknown as string, 'OK'] }), null as unknown as Service]);
    expect(() => secretRequests(p, NONE)).not.toThrow();
    expect(names(secretRequests(p, NONE))).toEqual(['OK']);
  });
});

describe('vault', () => {
  it('vault: set/get/names/has; get returns a string; wipe zeroes every Buffer and clears; wipe twice is safe', () => {
    const v = new SecretVault();
    v.set('A_KEY', 'value-one-12345');
    v.set('B_KEY', 'value-two-67890');
    expect(v.get('A_KEY')).toBe('value-one-12345');
    expect(v.names().sort()).toEqual(['A_KEY', 'B_KEY']);
    expect(v.has('A_KEY')).toBe(true);
    // catch the Buffer the vault makes for a value, to prove wipe() zeroes it (the vault has no accessor for its Buffers)
    const spy = vi.spyOn(Buffer, 'from');
    v.set('C_KEY', 'value-three-0');
    const made = spy.mock.results.map((x) => x.value as Buffer).filter((b) => Buffer.isBuffer(b) && b.toString() === 'value-three-0');
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
    const spy = vi.spyOn(Buffer, 'from');
    v.set('A_KEY', 'old-value-1234');
    const old = spy.mock.results.map((x) => x.value as Buffer).filter((b) => Buffer.isBuffer(b) && b.toString() === 'old-value-1234');
    expect(old.length).toBeGreaterThan(0);
    v.set('A_KEY', 'new-value-1234');
    expect(old.every((b) => b.every((x) => x === 0))).toBe(true);
    spy.mockRestore();
    expect(v.get('A_KEY')).toBe('new-value-1234');
    expect(() => v.set('A_KEY', '')).toThrow();
    expect(() => v.set('bad name', 'x')).toThrow();
    expect(() => v.set('__proto__', 'x')).not.toThrow();   // a Map key, never an object key
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
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
    v.set('GITHUB_TOKEN', 'value-12345678');
    v.set('github_x', 'value-12345678');
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
    v.set('GITHUB_X', 'value-12345678');
    await expect(storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['K_ONE', 'GITHUB_X'])).rejects.toThrow();
    expect(calls).toHaveLength(0);
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
    'GET https://api.github.com/repositories/42/environments/pipegen-signing/secrets/public-key': { body: { key_id: 'env-key', key: b64(kp.publicKey) } },
    'PUT https://api.github.com/repositories/42/environments/pipegen-signing/secrets/PIPEGEN_COSIGN_KEY': (c) => { puts.push(c); return { status: 201, body: {} }; },
  });

  it('env store: uses the environment public key endpoint, seals, sends key_id', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const { gh, calls } = fakeOctokit(envRoutes(kp, puts));
    await storeEnvSecret(gh, { owner: 'o', repo: 'r', id: 42 }, 'pipegen-signing', 'pipegen_cosign_key', 'cosign-PLAIN-1234');
    expect(calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([
      'GET /repositories/42/environments/pipegen-signing/secrets/public-key',
      'PUT /repositories/42/environments/pipegen-signing/secrets/PIPEGEN_COSIGN_KEY',
    ]);
    const body = JSON.parse(puts[0]?.body as string) as Record<string, string>;
    expect(body.key_id).toBe('env-key');
    expect(open(kp, body.encrypted_value as string)).toBe('cosign-PLAIN-1234');
    expect(calls.every((c) => !(c.body ?? '').includes('PLAIN'))).toBe(true);
  });

  it('env store: environment secrets never go through storeSecrets', async () => {
    const kp = keypair();
    const { gh, calls } = fakeOctokit(envRoutes(kp, []));
    const v = new SecretVault();
    v.set('PIPEGEN_COSIGN_KEY', 'value-12345678');
    await storeSecrets(gh, { owner: 'o', repo: 'r' }, v, ['PIPEGEN_COSIGN_KEY']).catch(() => undefined);
    expect(calls.some((c) => c.url.pathname.includes('/environments/'))).toBe(false);
    expect(calls.every((c) => c.url.pathname.startsWith('/repos/o/r/actions/secrets/'))).toBe(true);
  });

  it('env store: env, name, id and value are validated before any request', async () => {
    const { gh, calls } = fakeOctokit({});
    const ok = { owner: 'o', repo: 'r', id: 42 };
    const cases: [typeof ok, string, string, string][] = [
      [ok, '../x', 'K_ONE', 'v1234567'], [ok, 'a/b', 'K_ONE', 'v1234567'], [ok, '', 'K_ONE', 'v1234567'], [ok, 'env', 'GITHUB_TOKEN', 'v1234567'],
      [ok, 'env', 'bad-name', 'v1234567'], [ok, 'env', 'K_ONE', ''], [{ ...ok, id: 0 }, 'env', 'K_ONE', 'v1234567'], [{ ...ok, id: 1.5 }, 'env', 'K_ONE', 'v1234567'],
      [{ ...ok, id: Number.NaN }, 'env', 'K_ONE', 'v1234567'],
    ];
    for (const [r, e, n, val] of cases) await expect(storeEnvSecret(gh, r, e, n, val), `${e} ${n}`).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it('env store: an invalid key is refused and nothing is sent; errors carry no value', async () => {
    const kp = keypair();
    const puts: Call[] = [];
    const routes = envRoutes(kp, puts);
    routes['GET https://api.github.com/repositories/42/environments/pipegen-signing/secrets/public-key'] = { body: { key_id: 'k', key: b64(new Uint8Array(5)) } };
    const { gh } = fakeOctokit(routes);
    const err = await storeEnvSecret(gh, { owner: 'o', repo: 'r', id: 42 }, 'pipegen-signing', 'PIPEGEN_COSIGN_KEY', 'cosign-PLAIN-1234').then(() => null, (e: unknown) => e);
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
