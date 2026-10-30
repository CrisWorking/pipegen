// C6: the real `pipegen-gate` entry of data/reviewed-tools.yml, its input policy, and the cooldown rule for pipegen's own repo. Written first.
//
// The self-pin problem: the entry must pin a commit that holds the built gate/dist, which does not exist until the C6 commits land.
// Scheme (two steps): (1) these commits pin PRE_C6_SHA (the C5b head) and mark the entry `reviewedBy: PENDING` with the YAML comment
// `pending-self-pin`, so a release build refuses it exactly like any PENDING entry (ruling S21); (2) a follow-up controller commit re-pins to
// the C6 commit and fills in the delegated review. This test pins both states: while PENDING the pin is PRE_C6_SHA, afterwards it never is.
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

describe('C6: the cooldown skips the 7-day rule for pipegen\'s own repo only', () => {
  const NOW = new Date('2026-10-30T12:00:00Z');
  const onlyGate = (over: (e: Record<string, any>) => void = () => undefined): string => {
    const doc = parse(readFileSync(DATA, 'utf8')) as { pinnedOn: string; tools: Record<string, any>[] };
    const e = doc.tools.find((t) => t.id === 'pipegen-gate') as Record<string, any>;
    over(e);
    return stringify({ pinnedOn: doc.pinnedOn, tools: [e] });
  };
  const run = async (head: string): Promise<{ ok: boolean; calls: string[]; problems: string }> => {
    const calls: string[] = [];
    const f = (async (url: string) => { calls.push(String(url)); return new Response('{}', { status: 404 }); }) as typeof fetch;
    const r = await runCooldown({ base: {}, head: { 'data/reviewed-tools.yml': head }, fetch: f, now: NOW, maxLookups: 100 });
    return { ok: r.ok, calls, problems: r.findings.map((x) => x.problem).join('\n') };
  };
  it('the script and the loader exempt the same, exact repo, which is the gate action\'s repo', () => {
    expect(SCRIPT_OWN_REPO).toBe(PIPEGEN_OWN_REPO);
    expect(PIPEGEN_GATE_USES.startsWith(`${PIPEGEN_OWN_REPO}/`)).toBe(true);
  });
  it('the own-repo gate entry passes with no lookup at all (its code is reviewed here, in this repository)', async () => {
    const r = await run(onlyGate());
    expect(r.problems).toBe('');
    expect(r.ok).toBe(true);
    expect(r.calls).toEqual([]);
  });
  it('the same entry under another repo is checked as any action (and fails here: the fake upstream knows nothing)', async () => {
    for (const repo of ['evil/pipegen', 'crisworking/other', 'CrisWorking/pipegen', 'crisworking/pipegen-fork']) {
      const r = await run(onlyGate((e) => { e.candidate.repo = repo; e.step.action.uses = `${repo}/gate@${e.candidate.pin.sha}`; }));
      expect(r.ok, repo).toBe(false);
      expect(r.calls.length, repo).toBeGreaterThan(0);
    }
  });
  it('a uses: that does not match the candidate repo and pin still fails for the own repo', async () => {
    const r = await run(onlyGate((e) => { e.step.action.uses = `crisworking/pipegen/gate@${'a'.repeat(40)}`; }));
    expect(r.ok).toBe(false);
    expect(r.problems).toMatch(/does not match/);
  });
});
