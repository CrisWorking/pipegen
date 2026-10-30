// C6: the real `pipegen-gate` entry of data/reviewed-tools.yml, its input policy, and the cooldown rule for pipegen's own repo. Written first.
//
// The self-pin problem: the entry must pin a commit that holds the built gate/dist, which does not exist until the C6 commits land.
// Scheme (two steps): (1) these commits pin PRE_C6_SHA (the C5b head) and mark the entry `reviewedBy: PENDING` with the YAML comment
// `pending-self-pin`, so a release build refuses it exactly like any PENDING entry (ruling S21); (2) a follow-up controller commit re-pins to
// the C6 commit and fills in the delegated review. This test pins both states: while PENDING the pin is PRE_C6_SHA, afterwards it never is.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parse, stringify } from 'yaml';
import { PIPEGEN_OWN_REPO as SCRIPT_OWN_REPO, runCooldown } from '../scripts/cooldown.js';
import { loadReviewed, PIPEGEN_OWN_REPO, ReviewedListError } from '../src/engine/reviewed.js';
import { PIPEGEN_ACTION_IDS } from '../src/engine/referee.js';
import { renderScrub } from '../src/engine/render-step.js';
import { ACTION_POLICIES, GATE_USES_RE, PIPEGEN_GATE_USES, RENDERER_INPUTS } from '../src/engine/tool-flags.js';
import { PENDING } from '../src/engine/review-marker.js';
import { gateEntry } from './helpers/render.js';

const ROOT = resolve(import.meta.dirname, '..');
const DATA = join(ROOT, 'data/reviewed-tools.yml');
const PRE_C6_SHA = 'd142577a09720b07da32063bf1c214a42f544d12';
afterEach(() => { vi.unstubAllEnvs(); });

const real = () => {
  const t = loadReviewed().find((e) => e.id === PIPEGEN_ACTION_IDS.gate);
  if (t === undefined) throw new Error('no pipegen-gate entry');
  return t;
};

describe('C6: the pipegen-gate reviewed entry', () => {
  it('is there: crisworking/pipegen/gate, an action, category gate, pinned by SHA, no fixed input, no choice', () => {
    const t = real();
    expect(t.categories).toEqual(['gate']);
    expect(t.candidate).toMatchObject({ kind: 'action', repo: 'crisworking/pipegen', source: 'reviewed', reviewed: true });
    expect(t.step.action?.uses).toMatch(GATE_USES_RE);
    expect(t.step.action?.uses.startsWith(`${PIPEGEN_GATE_USES}@`)).toBe(true);
    expect(t.step.action?.uses).toBe(`${PIPEGEN_GATE_USES}@${t.candidate.pin.sha}`);
    expect(t.fixedInputs.with ?? {}).toEqual({});
    expect(t.step.action?.with ?? {}).toEqual({});
    expect(t.choices).toEqual({});
  });
  it('has an ACTION_POLICIES row with no inputs and no AI choices, and its RENDERER_INPUTS row', () => {
    expect(ACTION_POLICIES[PIPEGEN_GATE_USES]).toEqual({});
    expect(Object.keys(RENDERER_INPUTS[PIPEGEN_GATE_USES] ?? {}).length).toBeGreaterThan(5);
  });
  it('self-pin: while PENDING it pins the commit before the bundle (PRE_C6_SHA), marked pending-self-pin; once reviewed it never does', () => {
    const t = real();
    const text = readFileSync(DATA, 'utf8');
    if (t.reviewedBy === PENDING) {
      expect(t.candidate.pin.sha).toBe(PRE_C6_SHA);
      expect(t.reviewedAt).toBe(PENDING);
      expect(text).toContain('pending-self-pin');
    } else {
      expect(t.candidate.pin.sha).not.toBe(PRE_C6_SHA);
      expect(t.reviewedBy).toMatch(/delegated/);
    }
  });
  it('dev-time: once reviewed, the pinned commit\'s gate/dist and action.yml equal HEAD\'s (skipped while PENDING or when the commit is not fetched)', () => {
    const t = real();
    if (t.reviewedBy === PENDING) return;
    const pin = t.candidate.pin.sha as string;
    const git = (...args: string[]): boolean => { try { execFileSync('git', args, { cwd: ROOT, stdio: 'ignore' }); return true; } catch { return false; } };
    if (!git('cat-file', '-e', `${pin}:gate/dist/index.js`)) return; // not fetched (a depth-1 checkout)
    expect(git('merge-base', '--is-ancestor', pin, 'HEAD'), 'the pin is an ancestor of HEAD').toBe(true);
    expect(git('diff', '--quiet', pin, 'HEAD', '--', 'gate/dist', 'gate/action.yml'), 'the pinned bundle is the shipped bundle').toBe(true);
  });
  it('a release build refuses the list while the entry is PENDING (like any PENDING entry)', () => {
    if (real().reviewedBy !== PENDING) return; // after the re-pin there is nothing to refuse
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => loadReviewed()).toThrow(ReviewedListError);
    expect(() => loadReviewed()).toThrow(/pipegen-gate/);
  });
  it('the renderer accepts the real entry exactly as it accepts the fixture (same uses path, no inputs)', () => {
    const a = renderScrub('pipegen-out-sast--app', '${{ runner.temp }}/pipegen-raw/pipegen-out-sast--app/semgrep.sarif', 'semgrep', 'sarif', real());
    const b = renderScrub('pipegen-out-sast--app', '${{ runner.temp }}/pipegen-raw/pipegen-out-sast--app/semgrep.sarif', 'semgrep', 'sarif', gateEntry());
    expect({ ...a, uses: a.uses?.split('@')[0] }).toEqual({ ...b, uses: b.uses?.split('@')[0] });
  });
  it('the fixture entry stays for tests, with the same id as the real one', () => {
    expect(gateEntry().id).toBe(real().id);
  });
});

describe('C6 fix round 1: the cooldown skips the AGE rule for pipegen\'s own repo, never the tie to a gate tag', () => {
  const NOW = new Date('2026-10-30T12:00:00Z');
  const PIN = real().candidate.pin.sha as string;
  const TAG = 'gate-v0.2.0';
  const API = 'https://api.github.com/repos/crisworking/pipegen';
  const onlyGate = (over: (e: Record<string, any>) => void = () => undefined): string => {
    const doc = parse(readFileSync(DATA, 'utf8')) as { pinnedOn: string; tools: Record<string, any>[] };
    const e = doc.tools.find((t) => t.id === 'pipegen-gate') as Record<string, any>;
    over(e);
    return stringify({ pinnedOn: doc.pinnedOn, tools: [e] });
  };
  /** A stubbed upstream (no network): the routes given answer, anything else is a 404. */
  const run = async (head: string, routes: Record<string, unknown>, release = false): Promise<{ ok: boolean; calls: string[]; problems: string }> => {
    const calls: string[] = [];
    const f = (async (url: string) => {
      calls.push(String(url));
      const body = routes[String(url)];
      return body === undefined ? new Response('{}', { status: 404 }) : new Response(JSON.stringify(body), { status: 200 });
    }) as typeof fetch;
    const r = await runCooldown({ base: {}, head: { 'data/reviewed-tools.yml': head }, fetch: f, now: NOW, maxLookups: 100, ...(release ? { release: true } : {}) });
    return { ok: r.ok, calls, problems: r.findings.map((x) => x.problem).join('\n') };
  };
  const tagRoute = (sha: string = PIN, type = 'commit'): Record<string, unknown> => ({ [`${API}/git/ref/tags/${TAG}`]: { ref: `refs/tags/${TAG}`, object: { type, sha } } });
  const onMain = (sha: string = PIN, over: Record<string, unknown> = {}): Record<string, unknown> => ({
    [API]: { default_branch: 'main' },
    [`${API}/compare/${sha}...main?per_page=1`]: { status: 'ahead', behind_by: 0, merge_base_commit: { sha }, ...over },
  });

  it('the script and the loader exempt the same, exact repo, which is the gate action\'s repo', () => {
    expect(SCRIPT_OWN_REPO).toBe(PIPEGEN_OWN_REPO);
    expect(PIPEGEN_GATE_USES.startsWith(`${PIPEGEN_OWN_REPO}/`)).toBe(true);
  });
  it('the entry\'s version is a bare semver (the tag is gate-v<version>)', () => {
    expect(real().candidate.version).toBe('0.2.0');
  });
  it('tag == pin passes with no age check and no release lookup (pre-merge mode: no default-branch check)', async () => {
    const r = await run(onlyGate(), tagRoute());
    expect(r.problems).toBe('');
    expect(r.ok).toBe(true);
    expect(r.calls).toEqual([`${API}/git/ref/tags/${TAG}`]);
  });
  it('an annotated tag is followed to its commit', async () => {
    const r = await run(onlyGate(), { ...tagRoute('b'.repeat(40), 'tag'), [`${API}/git/tags/${'b'.repeat(40)}`]: { object: { type: 'commit', sha: PIN }, tagger: { date: '2026-10-30T00:00:00Z' } } });
    expect(r.problems).toBe('');
    expect(r.ok).toBe(true);
  });
  it('an impostor or missing SHA fails: no tag (404), a tag on another commit, a tag that is not a commit', async () => {
    const impostor = onlyGate((e) => { e.candidate.pin.sha = 'f'.repeat(40); e.step.action.uses = `crisworking/pipegen/gate@${'f'.repeat(40)}`; });
    expect((await run(impostor, {})).ok).toBe(false);
    expect((await run(impostor, tagRoute())).problems).toMatch(/not the commit of the tag gate-v0\.2\.0/);
    expect((await run(onlyGate(), tagRoute('a'.repeat(40)))).ok).toBe(false);
    expect((await run(onlyGate(), { [`${API}/git/ref/tags/${TAG}`]: { ref: `refs/tags/${TAG}`, object: { type: 'tree', sha: PIN } } })).ok).toBe(false);
    expect((await run(onlyGate(), {})).ok).toBe(false);
  });
  it('a version that is not a bare semver fails without a lookup (no tag name built from junk)', async () => {
    const r = await run(onlyGate((e) => { e.candidate.version = '../x'; }), tagRoute());
    expect(r.ok).toBe(false);
    expect(r.calls).toEqual([]);
  });
  it('release mode also needs the pin on the default branch: on main passes; a fork-only commit (behind or diverged) fails', async () => {
    expect((await run(onlyGate(), { ...tagRoute(), ...onMain() }, true)).ok).toBe(true);
    expect((await run(onlyGate(), { ...tagRoute(), ...onMain(PIN, { status: 'diverged' }) }, true)).ok).toBe(false);
    expect((await run(onlyGate(), { ...tagRoute(), ...onMain(PIN, { behind_by: 3 }) }, true)).ok).toBe(false);
    expect((await run(onlyGate(), { ...tagRoute(), [API]: { default_branch: 'main' } }, true)).ok).toBe(false);
    // the same fork-only commit passes pre-merge mode (the tag tie is the check there)
    expect((await run(onlyGate(), { ...tagRoute(), ...onMain(PIN, { status: 'diverged' }) }, false)).ok).toBe(true);
  });
  it('the same entry under another repo is checked as any action', async () => {
    for (const repo of ['evil/pipegen', 'crisworking/other', 'CrisWorking/pipegen', 'crisworking/pipegen-fork']) {
      const r = await run(onlyGate((e) => { e.candidate.repo = repo; e.step.action.uses = `${repo}/gate@${e.candidate.pin.sha}`; }), {});
      expect(r.ok, repo).toBe(false);
    }
  });
  it('a uses: that does not match the candidate repo and pin still fails for the own repo', async () => {
    const r = await run(onlyGate((e) => { e.step.action.uses = `crisworking/pipegen/gate@${'a'.repeat(40)}`; }), tagRoute());
    expect(r.ok).toBe(false);
    expect(r.problems).toMatch(/does not match/);
  });
  it('the loader exempts only kind action under the exact own repo', () => {
    const src = readFileSync(join(ROOT, 'src/engine/reviewed.ts'), 'utf8');
    expect(src).toMatch(/!\(t\.candidate\.kind === 'action' && t\.candidate\.repo === PIPEGEN_OWN_REPO\)/);
  });
});
