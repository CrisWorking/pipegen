// v0.2 Plan V V6 fix round 3 (ruling V6-R3): once central is deleted, what went with it is done and the run can finish (and a later run
// that finds central gone after pipegen's own DELETE finishes too); a refusal that asks the user to change something keeps the local files
// so the advice works; a DELETE GitHub refuses for good (4xx) is a manual step, not "run again"; each step says what to do by hand.
import { existsSync } from 'node:fs';
import type { Octokit } from '@octokit/rest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { localRecordPath, recordFileText, recordHash, recordPath, withRecordMarker, writeLocalRecord } from '../src/deliver/record.js';
import { centralWorkflowFile } from '../src/engine/central-path.js';
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

describe('V6-R3 sec M1: once central is deleted, the run can finish', () => {
  it('phase B: the org rule removed after the merge, its required workflow still on central: --delete-repos deletes central, what went with it is done, the run ends uninstalled (C3)', async () => {
    const req = centralWorkflowFile('shop', 'required');
    const REQ = 'on: workflow_call # required\n';
    const x = await real({
      ownerType: 'Organization', files: { [req]: REQ },
      over: (w) => ({ files: [{ repo: 'central', path: '.github/workflows/shop--merge.yml', part: 'pipeline', shas: [blob(MERGE_WF)] }, { repo: 'central', path: req, part: 'pipeline', shas: [blob(REQ)] }], orgRuleset: { org: 'o', id: 77, name: requiredRulesetName('shop'), githubCreatedAt: AT, pinnedSha: SHA('c') } }),
    });
    x.w.org.set(77, { name: requiredRulesetName('shop'), rules: [{ type: 'workflows', parameters: { workflows: [{ path: req, sha: SHA('c'), repository_id: x.w.central.id }] } }] });
    const yes = term({ yes: () => true });
    const rb = await x.step(yes);
    expect(rb.status).toBe('b-waiting');
    mergePr(x.w, x.w.central, BR);
    x.w.org.delete(77);
    const rc = await x.step(yes);
    expect(x.w.deleted).toContain('o/pipelines');
    expect(rc.failed).toEqual([]);
    expect(rc.done.some((d) => d.includes(req) && /went with the repo/.test(d))).toBe(true);
    expect(rc.status).toBe('b-done');
    expect(existsSync(localRecordPath(APP, local(x.w)))).toBe(false);
    expect(existsSync(uninstallProgressPath(APP, local(x.w)))).toBe(false);
  });

  it('record: the DELETE sent, the read after it failed: the next run finds central gone after pipegen\'s own delete and finishes (S2); a DELETE GitHub refused leaves no marker', async () => {
    const x = await real();
    await x.step();
    mergePr(x.w, x.w.central, BR);
    x.w.fail = (route, p) => (route === 'GET /repos/{owner}/{repo}' && p.repo === 'pipelines' && x.w.deleted.includes('o/pipelines') ? 500 : undefined);
    const r2 = await x.step();
    expect(x.w.deleted).toContain('o/pipelines');
    expect(r2.status).toBe('b-partial');
    expect(existsSync(localRecordPath(APP, local(x.w)))).toBe(true);
    expect((await progressOf(x.w))?.centralDeleteSent).toBe(x.w.central.id);
    x.w.fail = undefined;
    const err = await x.load().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(UninstallError);
    expect((err as Error).message).toMatch(/deleted o\/pipelines/);
    expect(existsSync(localRecordPath(APP, local(x.w)))).toBe(false);
    expect(existsSync(uninstallProgressPath(APP, local(x.w)))).toBe(false);

    // GitHub refuses the DELETE: no marker; central later out of sight is "can't tell", the local files stay
    const y = await real();
    await y.step();
    mergePr(y.w, y.w.central, BR);
    y.w.fail = (route, p) => (route === 'DELETE /repos/{owner}/{repo}' && p.repo === 'pipelines' ? 403 : undefined);
    await y.step();
    expect((await progressOf(y.w))?.centralDeleteSent).toBeUndefined();
  });
});

describe('V6-R3 spec I1: a DELETE GitHub refuses for good is a manual step, not "run again"', () => {
  it('phase B: the repo DELETE answered 403: a manual step (the repo\'s settings), no failed item, no "run again"; 500: a failed item, run again', async () => {
    const a = await merged();
    a.w.fail = (route, p) => (route === 'DELETE /repos/{owner}/{repo}' && p.repo === 'pipelines' ? 403 : undefined);
    const ra = await run(a.w, a.rec, term(), APPMODE);
    expect(a.w.deleted).toEqual([]);
    expect(ra.failed.filter((f) => /pipelines/.test(f.what))).toEqual([]);
    const m = ra.manual.find((x) => /repo o\/pipelines/.test(x.what));
    expect(m?.why).toMatch(/403/);
    expect(m?.step).toMatch(/Settings/);
    expect(m?.step).not.toMatch(/again/);
    expect(m?.step ?? '').not.toMatch(CMD);
    const b = await merged();
    b.w.fail = (route, p) => (route === 'DELETE /repos/{owner}/{repo}' && p.repo === 'pipelines' ? 500 : undefined);
    const rb = await run(b.w, b.rec, term(), APPMODE);
    expect(rb.failed.some((f) => /pipelines/.test(f.what) && /again/.test(f.manual ?? ''))).toBe(true);
  });
});

describe('V6-R3 sec M2, spec M2, spec M3: each refusal\'s step', () => {
  it('phase B: wiki, Discussions and the org rule ask the user to change something: failed (the local files stay), never "delete the repo yourself"; an own branch names the branch to delete; a content refusal says pipegen can\'t delete it later', async () => {
    for (const meta of [{ has_wiki: true }, { has_discussions: true }]) {
      const a = await merged();
      a.w.meta.set('pipelines', { ...a.w.meta.get('pipelines'), ...meta });
      const ra = await run(a.w, a.rec, term(), APPMODE);
      expect(ra.failed.some((f) => /pipelines/.test(f.what))).toBe(true);
      expect(ra.status).toBe('b-partial');
      for (const s of [...ra.failed.map((f) => `${f.why} ${f.manual ?? ''}`), ...ra.manual.map((x) => `${x.why} ${x.step ?? ''}`)]) expect(s).not.toMatch(/delete the repo yourself/);
    }
    // the org rule still there: failed, the local files stay so "run again" works
    const o = world({ ownerType: 'Organization' });
    o.org.set(77, { name: requiredRulesetName('shop'), rules: [] });
    await afterRun1(o);
    const orec = sampleRecord(o, { central: { repoId: o.central.id, createdByPipegen: true }, orgRuleset: { org: 'o', id: 77, name: requiredRulesetName('shop'), githubCreatedAt: AT, pinnedSha: SHA('c') } });
    await run(o, orec, term(), APPMODE);
    mergePr(o, o.central, BR);
    const ro = await run(o, orec, term(), APPMODE);
    expect(ro.failed.some((f) => /pipelines/.test(f.what) && /pipegen-required--shop/.test(f.why))).toBe(true);
    // an own branch at a head pipegen didn't record: the step names it and how to delete it
    const b = await merged();
    b.w.central.refs.set('heads/pipegen/update-shop', b.w.g.head('o/pipelines'));
    const rb = await run(b.w, b.rec, term(), APPMODE);
    expect(rb.failed.some((f) => /pipelines/.test(f.what) && /gh api -X DELETE repos\/o\/pipelines\/git\/refs\/heads\/pipegen\/update-shop/.test(f.manual ?? ''))).toBe(true);
    // a content refusal (an issue): the step says a later run can't delete it for pipegen
    const c = await merged();
    c.w.lists.set('central:issues', [{ number: 9 }]);
    const rc = await run(c.w, c.rec, term(), APPMODE);
    expect(rc.manual.some((x) => /pipelines/.test(x.what) && /can't delete it for you after this run/.test(x.step ?? ''))).toBe(true);
  });
});

describe('V6-R3 spec M1 and sec info', () => {
  it('central: the joined-project notice on CODEOWNERS evidence alone (the central ruleset present again)', async () => {
    const w = world();
    w.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': OWNERS_INS });
    w.central.rulesets.set(55, { name: CENTRAL_RULESET, source_type: 'Repository', source: 'o/pipelines', created_at: AT });
    await afterRun1(w);
    const edits: InstallEdit[] = [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: OWNERS_INS, originalSha: null, writtenShas: [blob(OWNERS_INS)] }];
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true, rulesetId: 55, rulesetCreatedAt: AT, codeowners: { path: '.github/CODEOWNERS', created: true } }, edits });
    await run(w, rec);
    mergePr(w, w.central, BR);
    w.central.rulesets.set(55, { name: CENTRAL_RULESET, source_type: 'Repository', source: 'o/pipelines', created_at: AT });
    w.g.commitOn('o/pipelines', 'main', { [recordPath('cart')]: '{}\n', '.github/workflows/cart--merge.yml': MERGE_WF });
    const r = await run(w, rec);
    expect(r.manual.some((m) => /central locks/.test(m.what) && /cart/.test(m.why))).toBe(true);
  });

  it('record: the merged central PR at another head than pipegen set: the stop names the pull request and the local files to move away', async () => {
    const x = await real();
    await x.step(term(), {});
    x.w.g.commitOn('o/pipelines', BR, { 'NOTES.md': 'teammate\n' }, 'teammate');
    mergePr(x.w, x.w.central, BR);
    const err = await x.load().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(UninstallError);
    expect((err as Error).message).toMatch(/#\d+/);
    expect((err as Error).message).toMatch(/not at the commit pipegen set/);
    expect((err as Error).message).toContain(uninstallProgressPath(APP, local(x.w)));
  });
});
