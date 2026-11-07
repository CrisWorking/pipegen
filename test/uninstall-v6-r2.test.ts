// v0.2 Plan V V6 fix round 2 (ruling V6-R2): App mode never advises `gh repo delete` on a refusal (only after a declined `pipelines`
// once every check passed); a refusal while pipegen asked keeps the local files; App mode refuses pipegen's central branch at a head it
// never recorded; a merged central PR counts only at the head pipegen set, and after the merge this project's files and locks must be gone;
// the typed vouch survives the blob rebuild; the M5 notice's evidence. GitHub is a fake; prompts are fakes; no network.
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { localRecordPath, recordFileText, recordHash, recordPath, withRecordMarker, writeLocalRecord } from '../src/deliver/record.js';
import { CENTRAL_RULESET } from '../src/layers/locks.js';
import type { InstallEdit, InstallRecord } from '../src/types.js';
import { uninstallStep, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
import { UninstallError } from '../src/uninstall/errors.js';
import { ProgressFile, uninstallProgressPath } from '../src/uninstall/progress.js';
import { loadUninstallRecord, TYPED_DROPPED, type LoadedRecord } from '../src/uninstall/record.js';
import {
  AT, blob, cleanHomes, deps, gh, loadedOf, local, MERGE_WF, mergePr, RECORD_TEXT, sampleRecord, SHA, term, world, type Term, type World,
} from './helpers/uninstall-world.js';

const h = vi.hoisted(() => ({ stop: { now: false } }));
vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => h.stop.now,
  onInterrupt: () => () => {},
}));
afterEach(() => { cleanHomes(); h.stop.now = false; });

const APP = { owner: 'o', repo: 'shop' };
const BR = 'pipegen/uninstall-shop';
const CMD = /gh repo delete o\/pipelines/;
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
const steps = (r: StepResult): string[] => [...r.manual.map((m) => `${m.what} | ${m.why} | ${m.step ?? ''}`), ...r.failed.map((f) => `${f.what} | ${f.why} | ${f.manual ?? ''}`), ...r.lines];
function localFile(w: World): string {
  const lr = localRecordPath(APP, local(w));
  mkdirSync(dirname(lr), { recursive: true });
  writeFileSync(lr, '{}\n', { mode: 0o600 });
  return lr;
}
/** App mode, the last project, its central PR merged: the next run 2 deletes central (or says why not). */
async function merged(): Promise<{ w: World; rec: InstallRecord; lr: string }> {
  const w = world();
  await afterRun1(w);
  const lr = localFile(w);
  const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
  await run(w, rec, term(), { deleteRepos: true, canDeleteRepos: true });
  mergePr(w, w.central, BR);
  return { w, rec, lr };
}

describe('V6-R2 sec I1: App mode never advises gh repo delete on a refusal', () => {
  it('apply: App mode prints gh repo delete only after a declined `pipelines` once every check passed; a content refusal says why, a refusal while asking keeps the local files', async () => {
    const app = { deleteRepos: true, canDeleteRepos: true } as const;
    // C4a: an issue in central
    const a = await merged();
    a.w.lists.set('central:issues', [{ number: 9 }]);
    const ra = await run(a.w, a.rec, term(), app);
    expect(a.w.deleted).toEqual([]);
    expect(steps(ra).filter((s) => CMD.test(s))).toEqual([]);
    expect(ra.manual.some((m) => /pipelines/.test(m.what) && /issues/.test(m.why))).toBe(true);
    // C4b: another project lands in central while pipegen asks: refused, nothing to delete advised, the local files kept
    const b = await merged();
    const tb = term({ type: (_q, exp) => { if (exp === 'pipelines') b.w.g.commitOn('o/pipelines', 'main', { [recordPath('cart')]: '{}\n', '.github/workflows/cart--merge.yml': MERGE_WF }, 'cart joins'); return exp; } });
    const rb = await run(b.w, b.rec, tb, app);
    expect(b.w.deleted).toEqual([]);
    expect(steps(rb).filter((s) => CMD.test(s))).toEqual([]);
    expect(rb.failed.some((f) => /pipelines/.test(f.what) && /cart/.test(f.why))).toBe(true);
    expect(rb.status).toBe('b-partial');
    expect(existsSync(b.lr)).toBe(true);
    expect(existsSync(uninstallProgressPath(APP, local(b.w)))).toBe(true);
    // C4c: a file pipegen didn't write
    const c = await merged();
    c.w.g.commitOn('o/pipelines', 'main', { 'docs/runbook.md': 'ours\n' });
    const rc = await run(c.w, c.rec, term(), app);
    expect(steps(rc).filter((s) => CMD.test(s))).toEqual([]);
    expect(rc.manual.some((m) => /docs\/runbook\.md/.test(m.why))).toBe(true);
    // a PR number not typed
    const d = await merged();
    const rd = await run(d.w, d.rec, term({ type: (_q, exp) => (/^\d+$/.test(exp) ? 'no' : exp) }), app);
    expect(d.w.deleted).toEqual([]);
    expect(steps(rd).filter((s) => CMD.test(s))).toEqual([]);
    // the marker taken off after the preview
    const e = await merged();
    const te = term();
    const goe = te.p.confirm;
    te.p.confirm = async (m, dd) => { if (m.startsWith('Go ahead')) e.w.meta.set('pipelines', { ...e.w.meta.get('pipelines'), description: 'ours now' }); return goe(m, dd); };
    const re = await run(e.w, e.rec, te, app);
    expect(e.w.deleted).toEqual([]);
    expect(steps(re).filter((s) => CMD.test(s))).toEqual([]);
    // every check passed and the user declined `pipelines`: the command is theirs to run
    const f = await merged();
    const rf = await run(f.w, f.rec, term({ type: (_q, exp) => (exp === 'pipelines' ? 'no' : exp) }), app);
    expect(f.w.deleted).toEqual([]);
    expect(rf.manual.some((m) => CMD.test(m.step ?? ''))).toBe(true);
  });

  it('central: App mode refuses pipegen\'s central branch at a head pipegen never recorded, before it asks (C4d); the local files stay', async () => {
    const w = world();
    await afterRun1(w);
    const lr = localFile(w);
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
    await run(w, rec, term(), { deleteRepos: true, canDeleteRepos: true });
    mergePr(w, w.central, BR);
    w.central.refs.set('heads/pipegen/update-shop', w.g.head('o/pipelines'));
    w.g.commitOn('o/pipelines', 'pipegen/update-shop', { '.github/workflows/shop--push.yml': 'on: workflow_call # teammate wip\n' }, 'teammate wip');
    const t = term();
    const r = await run(w, rec, t, { deleteRepos: true, canDeleteRepos: true });
    expect(w.deleted).toEqual([]);
    expect(t.typed.some((q) => /Type pipelines to go on/.test(q))).toBe(false);
    expect(r.failed.some((f) => /pipelines/.test(f.what) && /pipegen\/update-shop/.test(f.why))).toBe(true);
    expect(steps(r).filter((s) => CMD.test(s))).toEqual([]);
    expect(existsSync(lr)).toBe(true);
  });
});

describe('V6-R2 sec M1: a merged central PR counts only at the head pipegen set', () => {
  /** A real record on central and this machine's local record file (the loader's path). */
  const setup = async (o: { oldMergedPr?: boolean; typed?: boolean } = {}) => {
    const w = world();
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
    w.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: recordFileText(rec) }, 'record');
    w.app.pulls.push({ number: 5, head: 'pipegen/setup', base: 'main', title: 'pipegen setup', body: withRecordMarker('pipegen sets up CI', recordHash(rec)), state: 'closed', html_url: 'https://github.com/o/shop/pull/5' });
    await writeLocalRecord(APP, { recordHash: recordHash(rec), setupPr: 5, updatedAt: AT, ...(o.typed === true ? { typed: true as const } : {}) }, local(w));
    if (o.oldMergedPr === true) {
      w.central.pulls.push({ number: 3, head: BR, base: 'main', title: 'pipegen: uninstall shop', body: '', state: 'closed', html_url: 'https://github.com/o/pipelines/pull/3' });
      w.merged.set('pipelines#3', '2026-01-01T00:00:00Z');
      w.prHeads.set('pipelines#3', SHA('9'));
    }
    await afterRun1(w, blob(recordFileText(rec)));
    const t = term();
    const load = (g: Octokit = gh(w)) => loadUninstallRecord(g, APP, { local: local(w), io: t.p, interactive: true });
    return { w, rec, t, load };
  };

  it('record: an earlier cycle\'s merged central PR doesn\'t count: the record removed by hand → the loader and the re-check stop (L2)', async () => {
    const { w, t, load, rec } = await setup({ oldMergedPr: true });
    const first = await load();
    h.stop.now = true;
    await uninstallStep(gh(w), first, t.p, deps(w));
    h.stop.now = false;
    expect((await ProgressFile.open(APP, w.app.id, local(w))).state?.phase).toBe('B');
    w.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: null }, 'remove record by hand');
    await expect(load()).rejects.toBeInstanceOf(UninstallError);
    // the re-check alone (a plan loaded before the record went): stops, nothing sent
    const n = w.g.calls.length;
    await expect(uninstallStep(gh(w), loadedOf(w, rec, { blobSha: first.blobSha }), t.p, deps(w))).rejects.toBeInstanceOf(UninstallError);
    expect(w.g.calls.slice(n).filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    expect(w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).has('.github/workflows/shop--merge.yml')).toBe(true);
    expect(existsSync(localRecordPath(APP, local(w)))).toBe(true);
  });

  it('central: after the merge, this project\'s files or the central locks still on central are leftovers: not uninstalled, the local files stay', async () => {
    // a file of this project back on central main after the merge
    const w = world();
    await afterRun1(w);
    const lr = localFile(w);
    const rec = sampleRecord(w);
    await run(w, rec);
    mergePr(w, w.central, BR);
    w.g.commitOn('o/pipelines', 'main', { '.github/workflows/shop--merge.yml': MERGE_WF }, 'back again');
    const r = await run(w, rec);
    expect(r.status).toBe('b-partial');
    expect(r.failed.some((f) => /shop--merge\.yml/.test(f.what))).toBe(true);
    expect(r.lines.join('\n')).not.toMatch(/is uninstalled/);
    expect(existsSync(lr)).toBe(true);
    // the last project's central ruleset back (or never gone) after the merge
    const x = world();
    x.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': OWNERS_INS });
    x.central.rulesets.set(55, { name: CENTRAL_RULESET, source_type: 'Repository', source: 'o/pipelines', created_at: AT });
    await afterRun1(x);
    const xlr = localFile(x);
    const edits: InstallEdit[] = [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: OWNERS_INS, originalSha: null, writtenShas: [blob(OWNERS_INS)] }];
    const xrec = sampleRecord(x, { central: { repoId: x.central.id, createdByPipegen: true, rulesetId: 55, rulesetCreatedAt: AT, codeowners: { path: '.github/CODEOWNERS', created: true } }, edits });
    await run(x, xrec);
    expect(x.central.rulesets.has(55)).toBe(false);
    mergePr(x, x.central, BR);
    x.central.rulesets.set(55, { name: CENTRAL_RULESET, source_type: 'Repository', source: 'o/pipelines', created_at: AT });
    const rx = await run(x, xrec);
    expect(rx.status).toBe('b-partial');
    expect(rx.failed.some((f) => /central ruleset/.test(f.what))).toBe(true);
    expect(existsSync(xlr)).toBe(true);
  });

  it('record: a typed vouch stays a typed trust through the blob rebuild (the view only, typed names, nothing that needs full trust)', async () => {
    const { w, t, load } = await setup({ typed: true });
    const first = await load();
    expect(first.trust).toBe('typed');
    const r1 = await uninstallStep(gh(w), first, t.p, deps(w, { deleteRepos: true, canDeleteRepos: true }));
    expect(r1.status).toBe('b-waiting');
    mergePr(w, w.central, BR);
    const again = await load();
    expect(again.trust).toBe('typed');
    expect(again.typedNames).toBe(true);
    expect(again.dropped).toEqual(TYPED_DROPPED);
    expect(again.record.central).toBeUndefined();
    const r2 = await uninstallStep(gh(w), again, t.p, deps(w, { deleteRepos: true, canDeleteRepos: true }));
    expect(w.deleted).toEqual([]);
    expect(steps(r2).filter((s) => CMD.test(s))).toEqual([]);
  });
});

describe('V6-R2 spec M1: the evidence for the joined-project notice', () => {
  const joined = async (o: { codeowners?: { created: boolean }; rulesetFail?: number }) => {
    const w = world();
    if (o.codeowners !== undefined) w.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': OWNERS_INS });
    w.central.rulesets.set(55, { name: CENTRAL_RULESET, source_type: 'Repository', source: 'o/pipelines', created_at: AT });
    await afterRun1(w);
    const edits: InstallEdit[] = o.codeowners === undefined ? [] : [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: OWNERS_INS, originalSha: o.codeowners.created ? null : SHA('7'), writtenShas: [blob(OWNERS_INS)] }];
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true, rulesetId: 55, rulesetCreatedAt: AT, ...(o.codeowners === undefined ? {} : { codeowners: { path: '.github/CODEOWNERS', created: o.codeowners.created } }) }, edits });
    await run(w, rec);
    mergePr(w, w.central, BR);
    w.g.commitOn('o/pipelines', 'main', { [recordPath('cart')]: '{}\n', '.github/workflows/cart--merge.yml': MERGE_WF });
    if (o.codeowners?.created === false) w.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': null });
    if (o.rulesetFail !== undefined) w.fail = (route) => (route === 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}' ? o.rulesetFail : undefined);
    const r = await run(w, rec);
    return r.manual.some((m) => /central locks/.test(m.what));
  };
  it('central: the joined-project notice: the ruleset alone (404) is evidence; a ruleset read that fails is not; an absent CODEOWNERS pipegen didn\'t create is not', async () => {
    expect(await joined({})).toBe(true);
    expect(await joined({ rulesetFail: 500 })).toBe(false);
    expect(await joined({ codeowners: { created: false }, rulesetFail: 500 })).toBe(false);
  });
});
