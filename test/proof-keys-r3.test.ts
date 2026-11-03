// Plan E E4 fix round 3, exception (review-E4-r2.md N1, N6, N7; DECISIONS #108): the brand covers only runs that STARTED
// after the ticket (GitHub's server time from the `date` header of the ticket's secrets list, against each attempt's
// run_started_at); the environment names `.` and `..` are refused; the unscanned excerpt is reachable from excerpt.ts and
// tests only. Real makeOctokit over the fakes; interrupting() mocked. No network.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SecretVault } from '../src/create/secrets.js';
import { evidenceCovers, isExcerptEvidence, ScratchKeys } from '../src/proof/keys.js';
import { proofTarget } from '../src/proof/target.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { app, keysWorld, OWNER, quietIo, SCRATCH } from './helpers/scratch-secrets.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));
afterEach(() => { vi.mocked(interrupting).mockReturnValue(false); });

const TYPED = ['typed', 'Test', 'Value', '0123456789abcdef'].join('-');
const SK = ['STRIPE', 'SEC' + 'RET', 'KEY'].join('_');
type W = ReturnType<typeof keysWorld>;
const keysFor = (w: W) => {
  const v = new SecretVault();
  v.set(SK, TYPED);
  return new ScratchKeys(w.g.gh, proofTarget(app()), v, { io: quietIo, readByWorkflows: [SK, 'A_KEY'] });
};
const iso = (ms: number) => new Date(ms).toISOString().replace('.000', '');

describe('N1: the brand covers only runs that started after the ticket (GitHub server time)', () => {
  it('H2: run 900 ran with the real key; deleteAll, placeholders, ticket; evidence(t, [901, 900]) covers neither 900 nor the window', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.real([SK]);
    w.s.runs.set(900, { status: 'completed', run_attempt: 1, run_started_at: iso(w.s.serverTime + 500) });   // ran with the real key
    await K.deleteAll();
    await K.placeholders([SK]);
    const t = await K.ticket();
    const e = await K.evidence(t, [901, 900]);
    expect(e).toBeNull();
    expect(evidenceCovers(e, 900, 1)).toBe(false);
    expect(K.lastRefusal).toMatch(/run 900 started before the ticket/);
    // run 901 alone (started after the ticket): fine
    const e2 = await K.evidence(await K.ticket(), [901]);
    expect(evidenceCovers(e2, 901, 1)).toBe(true);
  });

  it('a run that started at the same second as the ticket gets no brand; one second later does', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders(['A_KEY']);
    const t = await K.ticket();
    const ticketTime = w.s.serverTime;   // the last secrets list answered at the ticket (the date header)
    // the evidence() lists move the fake clock on, but the ticket keeps its own time
    w.s.runs.set(5, { status: 'completed', run_attempt: 1, run_started_at: iso(ticketTime) });
    expect(await K.evidence(t, [5])).toBeNull();
    expect(K.lastRefusal).toMatch(/run 5 started before the ticket/);
    w.s.runs.set(5, { status: 'completed', run_attempt: 1, run_started_at: iso(ticketTime + 1000) });
    expect(evidenceCovers(await K.evidence(t, [5]), 5, 1)).toBe(true);
  });

  it('no date header, an unreadable one, or a run without a readable run_started_at: no brand', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders(['A_KEY']);
    w.s.dateHeader = null;
    const t1 = await K.ticket();
    expect(await K.evidence(t1, [7])).toBeNull();
    expect(K.lastRefusal).toMatch(/server time/);
    w.s.dateHeader = 'not a date';
    expect(await K.evidence(await K.ticket(), [7])).toBeNull();
    expect(K.lastRefusal).toMatch(/server time/);
    w.s.dateHeader = undefined;
    for (const started of [null, 'yesterday', '']) {
      w.s.runs.set(7, { status: 'completed', run_attempt: 1, run_started_at: started });
      expect(await K.evidence(await K.ticket(), [7]), String(started)).toBeNull();
      expect(K.lastRefusal).toMatch(/start time for run 7/);
    }
    w.s.runs.delete(7);
    expect(isExcerptEvidence(await K.evidence(await K.ticket(), [7]))).toBe(true);
  });
});

describe('N6: environment names . and .. are refused', () => {
  it('an environment named . or .. means no brand, and nothing is read under it', async () => {
    for (const name of ['.', '..']) {
      const w = keysWorld();
      const K = keysFor(w);
      await K.placeholders(['A_KEY']);
      w.s.environments = { [name]: { held: [], vars: [] } };
      expect(await K.evidence(await K.ticket(), [1]), name).toBeNull();
      expect(K.lastRefusal).toMatch(/environment name/);
      expect(w.g.calls.some((c) => c.url.pathname.startsWith(`/repos/${OWNER}/${SCRATCH}/${['envi', 'ronments'].join('')}/`))).toBe(false);
    }
  });
});

describe('N7: unscannedExcerpt is reachable only from excerpt.ts and tests', () => {
  it('no file under src/ but excerpt.ts names unscannedExcerpt', () => {
    const root = join(import.meta.dirname, '..', 'src');
    const files: string[] = [];
    const walk = (d: string) => {
      for (const f of readdirSync(d)) {
        const p = join(d, f);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.[cm]?[jt]s$/.test(f)) files.push(p);
      }
    };
    walk(root);
    expect(files.length).toBeGreaterThan(50);
    const users = files.filter((f) => readFileSync(f, 'utf8').includes('unscannedExcerpt')).map((f) => relative(root, f));
    expect(users).toEqual(['proof/excerpt.ts']);
    // and inside excerpt.ts it is used only by errorExcerpt, after the evidence check
    const src = readFileSync(join(root, 'proof', 'excerpt.ts'), 'utf8');
    const body = src.slice(src.indexOf('export async function errorExcerpt'));
    expect(body.indexOf('checkEvidence(')).toBeGreaterThan(-1);
    expect(body.indexOf('checkEvidence(')).toBeLessThan(body.indexOf('unscannedExcerpt('));
    expect(src.split('unscannedExcerpt(').length - 1).toBe(2);   // its definition and errorExcerpt's one call
  });
});
