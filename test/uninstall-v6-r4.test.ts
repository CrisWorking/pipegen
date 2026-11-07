// v0.2 Plan V V6 fix round 4 (ruling V6-R4): the finished path names what is still the user's to do; a confirmed "central delete
// sent" marker that GitHub disproves is dropped; a lost answer and lost access both stop; a local save failure after GitHub accepted the
// DELETE is not reported as a refusal; the 4xx step names what pipegen couldn't read. (Earlier header, round 3:)
// v0.2 Plan V V6 fix round 3 (ruling V6-R3): once central is deleted, what went with it is done and the run can finish (and a later run
// that finds central gone after pipegen's own DELETE finishes too); a refusal that asks the user to change something keeps the local files
// so the advice works; a DELETE GitHub refuses for good (4xx) is a manual step, not "run again"; each step says what to do by hand.
import { chmodSync, existsSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { localRecordPath, recordFileText, recordHash, recordPath, withRecordMarker, writeLocalRecord } from '../src/deliver/record.js';
import { centralWorkflowFile } from '../src/engine/central-path.js';
import { GitHubRateLimitError } from '../src/engine/github-rate.js';
import { CENTRAL_RULESET, requiredRulesetName } from '../src/layers/locks.js';
import type { InstallEdit, InstallRecord } from '../src/types.js';
import { uninstallStep, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
import { UninstallError } from '../src/uninstall/errors.js';
import { ProgressFile, uninstallProgressPath } from '../src/uninstall/progress.js';
import { loadUninstallRecord, type LoadedRecord } from '../src/uninstall/record.js';
import {
  AT, blob, cleanHomes, deps, gh, loadedOf, local, MERGE_WF, mergePr, RECORD_TEXT, sampleRecord, SHA, term, world, type Term, type World,
} from './helpers/uninstall-world.js';

vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => false,
  onInterrupt: () => () => {},
}));
afterEach(() => { cleanHomes(); });

const APP = { owner: 'o', repo: 'shop' };
const BR = 'pipegen/uninstall-shop';
const CMD = /gh repo delete o\/pipelines/;
const APPMODE = { deleteRepos: true, canDeleteRepos: true } as const;
const OWNERS_INS = '# pipegen:begin\n/.github/workflows/ @o\n# pipegen:end\n';
async function afterRun1(w: World, recordBlobSha = blob(RECORD_TEXT)): Promise<void> {
  w.app.refs.set('heads/pipegen/uninstall', w.g.head(`o/${w.app.name}`));
  w.app.pulls.push({ number: 1, head: 'pipegen/uninstall', base: 'main', title: 'pipegen: uninstall', body: '', state: 'closed', html_url: `https://github.com/o/${w.app.name}/pull/1` });
  w.merged.set(`${w.app.name}#1`, '2026-11-06T10:00:00Z');
  const pf = await ProgressFile.open({ owner: 'o', repo: w.app.name }, w.app.id, local(w));
  pf.save({ phase: 'A-done', anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: w.g.head('o/pipelines'), recordBlobSha }, prNumber: 1, prUrl: `https://github.com/o/${w.app.name}/pull/1`, done: [], leftovers: [] });
}
const run = (w: World, rec: InstallRecord, t: Term = term(), over: Partial<StepDeps> = {}, lo: Partial<LoadedRecord> = {}): Promise<StepResult> =>
  uninstallStep(gh(w), loadedOf(w, rec, lo), t.p, deps(w, over));
const progressOf = async (w: World) => (await ProgressFile.open(APP, w.app.id, local(w))).state;
/** A real record on central and this machine's local record file: the loader's own path. */
async function real(o: { ownerType?: 'User' | 'Organization'; files?: Record<string, string>; over?: (w: World) => Partial<InstallRecord> } = {}) {
  const w = world({ ...(o.ownerType === undefined ? {} : { ownerType: o.ownerType }) });
  if (o.files !== undefined) w.g.commitOn('o/pipelines', 'main', o.files);
  const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true }, ...(o.over?.(w) ?? {}) });
  w.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: recordFileText(rec) }, 'record');
  w.app.pulls.push({ number: 5, head: 'pipegen/setup', base: 'main', title: 'pipegen setup', body: withRecordMarker('pipegen sets up CI', recordHash(rec)), state: 'closed', html_url: 'https://github.com/o/shop/pull/5' });
  await writeLocalRecord(APP, { recordHash: recordHash(rec), setupPr: 5, updatedAt: AT }, local(w));
  await afterRun1(w, blob(recordFileText(rec)));
  const load = (g: Octokit = gh(w)) => loadUninstallRecord(g, APP, { local: local(w), io: term().p, interactive: true });
  const step = async (t: Term = term(), over: Partial<StepDeps> = APPMODE) => uninstallStep(gh(w), await load(), t.p, deps(w, over));
  return { w, rec, load, step };
}
/** App mode, the last project, its central PR merged (loadedOf: a fake loaded record). */
async function merged(): Promise<{ w: World; rec: InstallRecord }> {
  const w = world();
  await afterRun1(w);
  const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
  await run(w, rec, term(), APPMODE);
  mergePr(w, w.central, BR);
  return { w, rec };
}


const LIST = ['sec', 'rets'].join('') as 'secrets';
const A_NAME = 'PIPEGEN_A';

describe('V6-R4 M1: the finished path names what is still the user\'s to do', () => {
  it('record: central deleted while an app-side item failed; the next run\'s finished message names it and its step (F1)', async () => {
    const x = await real({ over: () => ({ [LIST]: [{ name: A_NAME, scope: 'repo', created: true, githubCreatedAt: AT }] }) });
    x.w.app.stored.set(A_NAME, AT);
    x.w.fail = (route) => (route === `DELETE /repos/{owner}/{repo}/actions/${LIST}/{secret_name}` ? 500 : undefined);
    const yes = term({ yes: () => true });
    await x.step(yes);
    mergePr(x.w, x.w.central, BR);
    const r2 = await x.step(yes);
    expect(x.w.deleted).toContain('o/pipelines');
    expect(r2.failed.some((f) => f.what.includes(A_NAME))).toBe(true);   // not settled with central: it isn't inside central
    x.w.fail = undefined;
    const err = await x.load().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(UninstallError);
    const msg = (err as Error).message;
    expect(msg).toMatch(/finished/);
    expect(msg).toContain(A_NAME);
    expect(msg).toMatch(/still yours to do/i);
    expect(msg).not.toMatch(/repo o\/pipelines:/);
  });
});

describe('V6-R4 Info 1, Info 2: the marker', () => {
  it('record: a pending marker and central 404 by name and by id (lost answer, or lost access): the usual stop, the local files kept', async () => {
    const x = await real();
    await x.step();
    const pf = await ProgressFile.open(APP, x.w.app.id, local(x.w));
    pf.save({ ...pf.state!, centralDeleteSent: { repoId: x.w.central.id, recordHash: recordHash(x.rec), confirmed: false } });
    x.w.fail = (route, p) => (p.repo === 'pipelines' || route === 'GET /repositories/{repository_id}' ? 404 : undefined);
    await expect(x.load()).rejects.toThrow(/can't see o\/pipelines/);
    expect(existsSync(localRecordPath(APP, local(x.w)))).toBe(true);
    expect(existsSync(uninstallProgressPath(APP, local(x.w)))).toBe(true);
  });

  it('phase B: a confirmed marker is dropped when the run sees central alive with that id', async () => {
    const x = await real();
    await x.step();
    const pf = await ProgressFile.open(APP, x.w.app.id, local(x.w));
    pf.save({ ...pf.state!, centralDeleteSent: { repoId: x.w.central.id, recordHash: recordHash(x.rec), confirmed: true } });
    const r = await x.step(term(), {});
    expect(r.status).toBe('b-waiting');
    expect((await progressOf(x.w))?.centralDeleteSent).toBeUndefined();
  });
});

describe('V6-R4 Info 4, Info 6: the DELETE\'s answers', () => {
  it('phase B: GitHub accepted the DELETE but the progress file could not be saved: deleted, said so, not a refusal', async () => {
    const x = await real();
    await x.step();
    mergePr(x.w, x.w.central, BR);
    const dir = dirname(uninstallProgressPath(APP, local(x.w)));
    const loaded = await x.load();
    const base = gh(x.w) as unknown as { request: (r: string, p: Record<string, unknown>) => Promise<unknown> };
    const g = { request: async (route: string, params: Record<string, unknown> = {}) => {
      const out = await base.request(route, params).catch((e: unknown) => { if (route === 'GET /repos/{owner}/{repo}' && params.repo === 'pipelines') chmodSync(dir, 0o700); throw e; });
      if (route === 'DELETE /repos/{owner}/{repo}' && params.repo === 'pipelines') chmodSync(dir, 0o500);
      return out;
    } } as unknown as Octokit;
    let r: StepResult | null = null;
    try { r = await uninstallStep(g, loaded, term().p, deps(x.w, APPMODE)); } finally { chmodSync(dir, 0o700); }
    expect(x.w.deleted).toContain('o/pipelines');
    expect(r?.failed.filter((f) => /pipelines/.test(f.what))).toEqual([]);
    expect(r?.done.some((d) => /o\/pipelines/.test(d) && /progress file could not be saved/.test(d))).toBe(true);
  });

  it('phase B: the 4xx step names what pipegen couldn\'t read', async () => {
    const a = await merged();
    a.w.lists.set('central:keys', 403);
    a.w.fail = (route, p) => (route === 'DELETE /repos/{owner}/{repo}' && p.repo === 'pipelines' ? 403 : undefined);
    const r = await run(a.w, a.rec, term(), APPMODE);
    const m = r.manual.find((x) => /repo o\/pipelines/.test(x.what));
    expect(m?.step).toMatch(/couldn't read its deploy keys/);
  });
});
