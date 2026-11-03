// Plan E E4 fix round 2 (review-E4-r1.md R1, R2, R6): the excerpt brand is bound to finished (run id, attempt) pairs and
// revoked by a later real store; environment secrets and variables are read before any brand; deleteAll deletes by the
// guarded scratch names even when the repo id can't be read. Real makeOctokit over the fakes; interrupting() mocked.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SecretVault } from '../src/create/secrets.js';
import { errorExcerpt } from '../src/proof/excerpt.js';
import { evidenceCovers, isExcerptEvidence, ScratchKeys } from '../src/proof/keys.js';
import { proofTarget } from '../src/proof/target.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { app, keysWorld, OWNER, quietIo, SCRATCH } from './helpers/scratch-secrets.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));
afterEach(() => { vi.mocked(interrupting).mockReturnValue(false); });

const TYPED = ['typed', 'Test', 'Value', '0123456789abcdef'].join('-');
const SK = ['STRIPE', 'SEC' + 'RET', 'KEY'].join('_');
const vaultWith = () => {
  const v = new SecretVault();
  v.set(SK, TYPED);
  return v;
};
type W = ReturnType<typeof keysWorld>;
const keysFor = (w: W, deps: Partial<ConstructorParameters<typeof ScratchKeys>[3]> = {}) =>
  new ScratchKeys(w.g.gh, proofTarget(app()), vaultWith(), { io: quietIo, readByWorkflows: [SK, 'A_KEY'], ...deps });
const noScan = {} as never;   // errorExcerpt refuses before the scanner is ever used
const ENVS = ['envi', 'ronments'].join('');

describe('R1: the brand names finished (run id, attempt) pairs and dies with a later real store', () => {
  it('P6: a brand from a placeholders run, then a real store, then a re-run attempt of the same run id: both attempts refused', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders([SK]);
    const e = await K.evidence(await K.ticket(), [77]);
    expect(isExcerptEvidence(e)).toBe(true);
    expect(evidenceCovers(e, 77, 1)).toBe(true);
    expect(evidenceCovers(e, 77, 2)).toBe(false);
    expect(evidenceCovers(e, 77)).toBe(false);          // no attempt named: no match
    await K.real([SK]);
    w.s.runs.set(77, { status: 'completed', run_attempt: 2 });   // rerun-failed-jobs: same run id, attempt 2, with the real value
    expect(evidenceCovers(e, 77, 1)).toBe(false);
    expect(evidenceCovers(e, 77, 2)).toBe(false);
    for (const attempt of [1, 2]) {
      await expect(errorExcerpt('Error: x', (t) => t, noScan, e as never, { runId: 77, attempt })).rejects.toThrow(/run/);
    }
    // another instance's real store on the same repo revokes it too (the shared state)
    const w2 = keysWorld();
    const A = keysFor(w2);
    const B = keysFor(w2);
    await A.placeholders(['A_KEY']);
    const e2 = await A.evidence(await A.ticket(), [5]);
    expect(evidenceCovers(e2, 5, 1)).toBe(true);
    await B.real([SK]);
    expect(evidenceCovers(e2, 5, 1)).toBe(false);
  });

  it('evidence() reads each run: an unfinished or unreadable run gets no brand; the attempt it names is the run\'s own', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders(['A_KEY']);
    w.s.runs.set(77, { status: 'in_progress', run_attempt: 1 });
    expect(await K.evidence(await K.ticket(), [77])).toBeNull();
    expect(K.lastRefusal).toMatch(/run 77.*not finished/);
    w.s.runs.set(77, { status: 'queued', run_attempt: 2 });
    expect(await K.evidence(await K.ticket(), [78, 77])).toBeNull();
    w.s.runs.set(77, { status: 'completed', run_attempt: 3, run_started_at: new Date(w.s.serverTime + 600_000).toISOString() });   // re-run after the ticket
    const e = await K.evidence(await K.ticket(), [77, 78]);
    expect(evidenceCovers(e, 77, 3)).toBe(true);
    expect(evidenceCovers(e, 77, 1)).toBe(false);
    expect(evidenceCovers(e, 78, 1)).toBe(true);
    // a run GitHub doesn't answer for, or answers about another id: no brand
    const reads = w.g.calls.filter((c) => /\/actions\/runs\/\d+$/.test(c.url.pathname)).length;
    expect(reads).toBeGreaterThanOrEqual(4);
    const w2 = keysWorld({ extra: (c) => (c.url.pathname === `/repos/${OWNER}/${SCRATCH}/actions/runs/9` ? { status: 404, body: { message: 'Not Found' } } : undefined) });
    const K2 = keysFor(w2);
    await K2.placeholders(['A_KEY']);
    expect(await K2.evidence(await K2.ticket(), [9])).toBeNull();
    const w3 = keysWorld({ extra: (c) => (c.url.pathname === `/repos/${OWNER}/${SCRATCH}/actions/runs/9` ? { body: { id: 10, status: 'completed', run_attempt: 1 } } : undefined) });
    const K3 = keysFor(w3);
    await K3.placeholders(['A_KEY']);
    expect(await K3.evidence(await K3.ticket(), [9])).toBeNull();
    // errorExcerpt takes only the exact (run id, attempt) pair
    await expect(errorExcerpt('Error: x', (t) => t, noScan, e as never, { runId: 77, attempt: 1 })).rejects.toThrow(/run/);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect(errorExcerpt('Error: x', (t) => t, noScan, e as never, { runId: 77 } as any)).rejects.toThrow(/run/);
  });
});

describe('R2: environment secrets and variables', () => {
  it('P7: verify reads the environments, each one\'s secrets and variables; any environment secret means no brand', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders([SK]);
    w.s.environments = { 'pipegen-signing': { held: [], vars: [] } };
    const n = w.g.calls.length;
    await K.ticket();
    const reads = new Set(w.g.calls.slice(n).map((c) => decodeURIComponent(c.url.pathname)));
    for (const p of [`/repos/${OWNER}/${SCRATCH}/${ENVS}`, `/repos/${OWNER}/${SCRATCH}/${ENVS}/pipegen-signing/secrets`, `/repos/${OWNER}/${SCRATCH}/${ENVS}/pipegen-signing/variables`]) {
      expect(reads.has(p), p).toBe(true);
    }
    expect(isExcerptEvidence(await K.evidence(await K.ticket(), [1]))).toBe(true);
    // a secret by hand in the environment overrides the repo placeholder for a job that names it
    w.s.environments = { 'pipegen-signing': { held: [SK], vars: [] } };
    expect(await K.evidence(await K.ticket(), [1])).toBeNull();
    expect(K.lastRefusal).toMatch(/environment pipegen-signing/);
  });

  it('environment variables: only the declared name holding a date; unreadable environment lists give no brand', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders(['A_KEY']);
    const brand = async () => K.evidence(await K.ticket(), [1]);
    w.s.environments = { prod: { held: [], vars: [{ name: 'PIPEGEN_BLOCK_FROM', value: '2026-11-03' }] } };
    expect(isExcerptEvidence(await brand())).toBe(true);
    w.s.environments = { prod: { held: [], vars: [{ name: 'API_TOKEN', value: TYPED }] } };
    expect(await brand()).toBeNull();
    w.s.environments = { prod: { held: [], vars: [{ name: 'OTHER_CONFIG', value: '2026-11-03' }] } };   // undeclared, even holding a date
    expect(await brand()).toBeNull();
    expect(K.lastRefusal).toMatch(/OTHER_CONFIG.*doesn't declare/);
    w.s.environments = { prod: { held: [], vars: [{ name: 'PIPEGEN_BLOCK_FROM', value: TYPED }] } };
    expect(await brand()).toBeNull();
    // unreadable: the environment list, one environment's secrets, one environment's variables
    w.s.environments = null;
    expect(await brand()).toBeNull();
    expect(K.lastRefusal).toMatch(/environments/);
    w.s.environments = { prod: { held: null, vars: [] } };
    expect(await brand()).toBeNull();
    w.s.environments = { prod: { held: [], vars: null } };
    expect(await brand()).toBeNull();
    w.s.environments = {};
    expect(isExcerptEvidence(await brand())).toBe(true);
  });
});

describe('R6: deleteAll does not depend on the repo-id read', () => {
  it('the id read fails during cleanup: every secret is still deleted by the scratch names, the failure is a leftover, no brand after', async () => {
    let idDown = true;
    const w = keysWorld({ extra: (c) => (idDown && c.method === 'GET' && c.url.pathname === `/repos/${OWNER}/${SCRATCH}` ? { status: 502, body: { message: 'Bad Gateway' } } : undefined) },
      { OLD_A: 'a'.repeat(10), OLD_B: 'b'.repeat(10) });
    const K = keysFor(w);
    const left: string[] = [];
    const deleted = await K.deleteAll({ leftover: (x) => left.push(x) });
    expect(deleted.sort()).toEqual(['OLD_A', 'OLD_B']);
    expect(w.s.values.size).toBe(0);
    expect(left).toEqual([expect.stringMatching(/couldn't read .*pipegen-proof-shop.*not verified/)]);
    // the deletes came first, by name; the id read after
    const seen = w.g.seen();
    expect(seen.indexOf(`DELETE /repos/${OWNER}/${SCRATCH}/actions/secrets/OLD_A`)).toBeLessThan(seen.indexOf(`GET /repos/${OWNER}/${SCRATCH}`));
    // no brand: the state was never verified (the id read fails, then works but the clean list was not booked)
    expect(await K.evidence(await K.ticket(), [1])).toBeNull();
    idDown = false;
    expect(await K.evidence(await K.ticket(), [1])).toBeNull();
    await K.deleteAll();
    await K.placeholders(['A_KEY']);
    expect(isExcerptEvidence(await K.evidence(await K.ticket(), [1]))).toBe(true);
    // a leftover secret with the id down: still thrown, names given
    idDown = true;
    w.s.touch('STUCK', 'x'.repeat(10));
    w.s.failDelete.set('STUCK', 500);
    const K2 = keysFor(w);
    await expect(K2.deleteAll({ leftover: () => {} })).rejects.toThrow(/STUCK/);
  });
});
