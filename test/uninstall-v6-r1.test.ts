// v0.2 Plan V V6 fix round 1 (ruling V6-R1): run 2's gates and gaps the reviews found. Token mode prints `gh repo delete` only after the
// gates App mode uses; the second run 2 loads the record from the blob pipegen read before the central PR removed it; the central uninstall
// branch moves only while it is where pipegen set it; pipegen's central branches go only with the repo; an org rule pipegen can't read is
// still there; a central 404 is "can't tell"; a project that joined after the locks came off is named; a declined name is a leftover;
// Ctrl-C and a rate stop keep the progress. GitHub is a fake; prompts are fakes; no network.
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { localRecordPath, recordFileText, recordHash, recordPath, withRecordMarker, writeLocalRecord } from '../src/deliver/record.js';
import { centralWorkflowFile } from '../src/engine/central-path.js';
import { GitHubRateLimitError } from '../src/engine/github-rate.js';
import { CENTRAL_RULESET, requiredRulesetName } from '../src/layers/locks.js';
import { StateStore } from '../src/proof/state.js';
import type { InstallEdit, InstallRecord } from '../src/types.js';
import { uninstallStep, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
import { centralNow, orgRuleNow } from '../src/uninstall/central.js';
import { UninstallError } from '../src/uninstall/errors.js';
import { ProgressFile, uninstallProgressPath } from '../src/uninstall/progress.js';
import { loadUninstallRecord, type LoadedRecord } from '../src/uninstall/record.js';
import {
  AT, blob, cleanHomes, deps, gh, loadedOf, local, MERGE_WF, mergePr, RECORD_TEXT, sampleRecord, SEC, SHA, term, world, writes, type Term, type World,
} from './helpers/uninstall-world.js';

const h = vi.hoisted(() => ({ stop: { now: false } }));
vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => h.stop.now,
  onInterrupt: () => () => {},
}));
afterEach(() => { cleanHomes(); h.stop.now = false; });

const APP = { owner: 'o', repo: 'shop' };
async function afterRun1(w: World, recordBlobSha = blob(RECORD_TEXT)): Promise<void> {
  w.app.refs.set('heads/pipegen/uninstall', w.g.head(`o/${w.app.name}`));
  w.app.pulls.push({ number: 1, head: 'pipegen/uninstall', base: 'main', title: 'pipegen: uninstall', body: '', state: 'closed', html_url: `https://github.com/o/${w.app.name}/pull/1` });
  w.merged.set(`${w.app.name}#1`, '2026-11-06T10:00:00Z');
  const pf = await ProgressFile.open({ owner: 'o', repo: w.app.name }, w.app.id, local(w));
  pf.save({ phase: 'A-done', anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: w.g.head('o/pipelines'), recordBlobSha }, prNumber: 1, prUrl: `https://github.com/o/${w.app.name}/pull/1`, done: [], leftovers: [] });
}
const run = (w: World, rec: InstallRecord, t: Term = term(), over: Partial<StepDeps> = {}, lo: Partial<LoadedRecord> = {}): Promise<StepResult> =>
  uninstallStep(gh(w), loadedOf(w, rec, lo), t.p, deps(w, over));
const BR = 'pipegen/uninstall-shop';
const A_NAME = 'PIPEGEN_A';
const OWNERS_INS = '# pipegen:begin\n/.github/workflows/ @o\n# pipegen:end\n';
const filesAtPr = (w: World): Map<string, string> => w.g.filesAt('o/pipelines', w.g.head('o/pipelines', BR));
const all = (w: World, r: StepResult): string => [...w.out, ...r.lines, ...r.manual.map((m) => `${m.what} ${m.why} ${m.step ?? ''}`), ...r.skipped.map((s) => `${s.what} ${s.why}`), ...r.failed.map((f) => `${f.what} ${f.why} ${f.manual ?? ''}`)].join('\n');
const progressOf = async (w: World) => (await ProgressFile.open(APP, w.app.id, local(w))).state;
const readApi = (w: World) => ({ read: (route: string, params: Record<string, unknown>) => (gh(w) as unknown as { request: (r: string, p: Record<string, unknown>) => Promise<{ data: unknown }> }).request(route, params) }) as never;
function localFiles(w: World): string {
  const lr = localRecordPath(APP, local(w));
  mkdirSync(dirname(lr), { recursive: true });
  writeFileSync(lr, '{}\n', { mode: 0o600 });
  return lr;
}

describe('V6-R1: token mode prints gh repo delete only after the gates App mode uses (sec I1, spec M3)', () => {
  it('apply: token mode prints gh repo delete only after the same gates as App mode (last project now, org rule gone, central PR merged, recorded id, deleteCentralRepo\'s checks)', async () => {
    const central = /gh repo delete o\/pipelines/;
    // Q1: another project lands on central between the preview and the yes
    const q1 = world();
    await afterRun1(q1);
    const rec1 = sampleRecord(q1, { central: { repoId: q1.central.id, createdByPipegen: true } });
    await run(q1, rec1, term(), { deleteRepos: true, canDeleteRepos: false });
    mergePr(q1, q1.central, BR);
    const t1 = term();
    const go1 = t1.p.confirm;
    t1.p.confirm = async (m, d) => { if (m.startsWith('Go ahead')) q1.g.commitOn('o/pipelines', 'main', { [recordPath('cart')]: '{}\n', '.github/workflows/cart--merge.yml': MERGE_WF }); return go1(m, d); };
    const r1 = await run(q1, rec1, t1, { deleteRepos: true, canDeleteRepos: false });
    expect(r1.lines.join('\n')).not.toMatch(central);
    expect(r1.manual.some((m) => central.test(m.step ?? ''))).toBe(false);
    expect([...r1.skipped, ...r1.manual].some((s) => /pipelines/.test(s.what) && /other project/.test(s.why))).toBe(true);

    // Q2: the org rule is still there (run 1 couldn't delete it)
    const q2 = world({ ownerType: 'Organization' });
    q2.org.set(77, { name: requiredRulesetName('shop'), rules: [] });
    await afterRun1(q2);
    const rec2 = sampleRecord(q2, { central: { repoId: q2.central.id, createdByPipegen: true }, orgRuleset: { org: 'o', id: 77, name: requiredRulesetName('shop'), githubCreatedAt: AT, pinnedSha: SHA('c') } });
    await run(q2, rec2, term(), { deleteRepos: true, canDeleteRepos: false });
    mergePr(q2, q2.central, BR);
    const r2 = await run(q2, rec2, term(), { deleteRepos: true, canDeleteRepos: false });
    expect(r2.lines.join('\n')).not.toMatch(central);   // the preview names the command only with its conditions
    expect(r2.manual.some((m) => /pipegen-required--shop/.test(m.why))).toBe(true);

    // Q3: the run that opens the central PR: not merged yet, so no command
    const q3 = world();
    await afterRun1(q3);
    const rec3 = sampleRecord(q3, { central: { repoId: q3.central.id, createdByPipegen: true } });
    const r3 = await run(q3, rec3, term(), { deleteRepos: true, canDeleteRepos: false });
    expect(r3.status).toBe('b-waiting');
    expect(r3.lines.join('\n')).not.toMatch(central);
    expect(q3.out.join('\n')).toMatch(/only once the central pull request/);   // the preview says when
    // merged, last, nothing but pipegen's there: now the command, and still nothing deleted
    mergePr(q3, q3.central, BR);
    const r3b = await run(q3, rec3, term(), { deleteRepos: true, canDeleteRepos: false });
    expect(r3b.lines.join('\n')).toMatch(central);
    expect(q3.deleted).toEqual([]);
    expect(q3.g.routes()).not.toContain('DELETE /repos/{owner}/{repo}');
    // merged, but central holds something pipegen didn't write: deleteCentralRepo's checks say why, no command
    const q3c = world();
    await afterRun1(q3c);
    const rec3c = sampleRecord(q3c, { central: { repoId: q3c.central.id, createdByPipegen: true } });
    await run(q3c, rec3c, term(), { deleteRepos: true, canDeleteRepos: false });
    mergePr(q3c, q3c.central, BR);
    q3c.g.commitOn('o/pipelines', 'main', { 'NOTES.md': 'mine\n' });
    const r3c = await run(q3c, rec3c, term(), { deleteRepos: true, canDeleteRepos: false });
    expect(r3c.lines.join('\n')).not.toMatch(central);
    expect(r3c.manual.some((m) => /pipelines/.test(m.what) && /NOTES\.md/.test(m.why))).toBe(true);
    // no recorded central id: no command either
    const q3d = world();
    await afterRun1(q3d);
    const rec3d = sampleRecord(q3d, { central: { createdByPipegen: true } });
    await run(q3d, rec3d, term(), { deleteRepos: true, canDeleteRepos: false });
    mergePr(q3d, q3d.central, BR);
    const r3d = await run(q3d, rec3d, term(), { deleteRepos: true, canDeleteRepos: false });
    expect(all(q3d, r3d)).not.toMatch(central);   // not planned at all: the preview doesn't name it either

    // Q4: the scratch repo carries the marker, but the record holds no id of it: never the command
    const q4 = world();
    await afterRun1(q4);
    const r4 = await run(q4, sampleRecord(q4), term(), { deleteRepos: true, canDeleteRepos: false });
    expect(all(q4, r4)).not.toMatch(/gh repo delete o\/pipegen-proof-shop/);
    // ... nor in the step for a scratch item pipegen couldn't delete
    const q4f = world();
    await afterRun1(q4f);
    q4f.runs.add(31);
    q4f.fail = (route) => (route === 'DELETE /repos/{owner}/{repo}/actions/runs/{run_id}' ? 500 : undefined);
    const r4f = await run(q4f, sampleRecord(q4f), term(), { deleteRepos: true, canDeleteRepos: false });
    expect(r4f.failed.some((f) => /run 31/.test(f.what))).toBe(true);
    expect(all(q4f, r4f)).not.toMatch(/gh repo delete o\/pipegen-proof-shop/);
    // another repo of that name (another GitHub id) after the preview: no command
    const q4e = world();
    await afterRun1(q4e);
    const t4e = term();
    const go4e = t4e.p.confirm;
    t4e.p.confirm = async (m, d) => { if (m.startsWith('Go ahead')) q4e.scratch!.id = 987_654; return go4e(m, d); };
    const r4e = await run(q4e, sampleRecord(q4e, { scratch: { repoId: q4e.scratch!.id, createdByPipegen: true } }), t4e, { deleteRepos: true, canDeleteRepos: false });
    expect(r4e.lines.join('\n')).not.toMatch(/gh repo delete o\/pipegen-proof-shop/);
    // the recorded id equal to GitHub's: the command
    const q4b = world();
    await afterRun1(q4b);
    const r4b = await run(q4b, sampleRecord(q4b, { scratch: { repoId: q4b.scratch!.id, createdByPipegen: true } }), term(), { deleteRepos: true, canDeleteRepos: false });
    expect(r4b.manual.some((m) => m.step === 'gh repo delete o/pipegen-proof-shop')).toBe(true);
    // ... but the marker taken off after the preview: no command
    const q4c = world();
    await afterRun1(q4c);
    const t4c = term();
    const go4c = t4c.p.confirm;
    t4c.p.confirm = async (m, d) => { if (m.startsWith('Go ahead')) q4c.meta.set('pipegen-proof-shop', { description: 'mine now' }); return go4c(m, d); };
    const r4c = await run(q4c, sampleRecord(q4c, { scratch: { repoId: q4c.scratch!.id, createdByPipegen: true } }), t4c, { deleteRepos: true, canDeleteRepos: false });
    expect(r4c.lines.join('\n')).not.toMatch(/gh repo delete o\/pipegen-proof-shop/);
  });
});

describe('V6-R1 hook-1: token mode and pipegen\'s own central branches', () => {
  it('apply: token mode names pipegen\'s own central branches that go with the repo, and prints gh repo delete only while each is at a head pipegen recorded', async () => {
    const central = /gh repo delete o\/pipelines/;
    const setup = async () => {
      const w = world();
      await afterRun1(w);
      const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
      await run(w, rec, term(), { deleteRepos: true, canDeleteRepos: false });
      mergePr(w, w.central, BR);
      return { w, rec };
    };
    // the central uninstall branch where pipegen set it: the command, and the branch named
    const a = await setup();
    const ra = await run(a.w, a.rec, term(), { deleteRepos: true, canDeleteRepos: false });
    const step = ra.manual.find((m) => central.test(m.step ?? ''));
    expect(step?.why).toMatch(/pipegen\/uninstall-shop/);
    // a teammate's commit on the central uninstall branch after the merge: no command, the branch named
    const b = await setup();
    b.w.g.commitOn('o/pipelines', BR, { '.github/workflows/shop--merge.yml': 'on: workflow_call # teammate\n' }, 'teammate');
    const rb = await run(b.w, b.rec, term(), { deleteRepos: true, canDeleteRepos: false });
    expect(rb.lines.join('\n')).not.toMatch(central);
    expect([...rb.manual, ...rb.failed].some((m) => /pipelines/.test(m.what) && /pipegen\/uninstall-shop/.test(m.why))).toBe(true);
    // pipegen's update branch, whose head pipegen never recorded: no command, the branch named
    const c = await setup();
    c.w.central.refs.set('heads/pipegen/update-shop', c.w.g.head('o/pipelines'));
    c.w.g.commitOn('o/pipelines', 'pipegen/update-shop', { '.github/workflows/shop--push.yml': 'on: workflow_call # wip\n' }, 'wip');
    const rc = await run(c.w, c.rec, term(), { deleteRepos: true, canDeleteRepos: false });
    expect(rc.lines.join('\n')).not.toMatch(central);
    expect([...rc.manual, ...rc.failed].some((m) => /pipelines/.test(m.what) && /pipegen\/update-shop/.test(m.why))).toBe(true);
    expect(c.w.deleted).toEqual([]);
  });
});

describe('V6-R1: the second run 2 in production (spec I1)', () => {
  it('record: after the central PR merged, the second run 2 loads the record from the blob pipegen read before (anchor and local hash both checked); any mismatch stops', async () => {
    const setup = async () => {
      const w = world();
      const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
      w.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: recordFileText(rec) }, 'record');
      w.app.pulls.push({ number: 5, head: 'pipegen/setup', base: 'main', title: 'pipegen setup', body: withRecordMarker('pipegen sets up CI', recordHash(rec)), state: 'closed', html_url: 'https://github.com/o/shop/pull/5' });
      await writeLocalRecord(APP, { recordHash: recordHash(rec), setupPr: 5, updatedAt: AT }, local(w));
      await afterRun1(w, blob(recordFileText(rec)));
      const t = term();
      const load = (g: Octokit = gh(w)) => loadUninstallRecord(g, APP, { local: local(w), io: t.p, interactive: true });
      const first = await load();
      expect(first.trust).toBe('full');
      const r1 = await uninstallStep(gh(w), first, t.p, deps(w));
      expect(r1.status).toBe('b-waiting');
      mergePr(w, w.central, BR);
      expect(w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).has(recordPath('shop'))).toBe(false);
      return { w, rec, t, load };
    };
    // the record is gone from central: rebuilt from the blob the progress file names, through the real loader
    const a = await setup();
    const again = await a.load();
    expect(again.record).toEqual(a.rec);
    expect(again.trust).toBe('full');
    expect(again.blobSha).toBe(blob(recordFileText(a.rec)));
    expect(again.warnings.join('\n')).toMatch(/central uninstall pull request #\d+ removed it/);
    const r2 = await uninstallStep(gh(a.w), again, a.t.p, deps(a.w));
    expect(r2.status).toBe('b-done');
    expect(existsSync(localRecordPath(APP, local(a.w)))).toBe(false);
    expect(existsSync(uninstallProgressPath(APP, local(a.w)))).toBe(false);

    // the local record file vouches for another hash: stop
    const b = await setup();
    await writeLocalRecord(APP, { recordHash: 'f'.repeat(64), setupPr: 5, updatedAt: AT }, local(b.w));
    await expect(b.load()).rejects.toBeInstanceOf(UninstallError);
    // the blob GitHub gives is not the one the anchor names: stop
    const c = await setup();
    const base = gh(c.w) as unknown as { request: (r: string, p: Record<string, unknown>) => Promise<{ data: unknown }> };
    const tampered = { request: async (route: string, p: Record<string, unknown> = {}) => {
      const out = await base.request(route, p);
      if (route === 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}') return { ...out, data: { ...(out.data as object), content: Buffer.from(`${recordFileText(c.rec)} `).toString('base64') } };
      return out;
    } } as unknown as Octokit;
    await expect(c.load(tampered)).rejects.toBeInstanceOf(UninstallError);
    // the progress file names another blob: stop
    const d = await setup();
    const pf = await ProgressFile.open(APP, d.w.app.id, local(d.w));
    const st = pf.state!;
    pf.save({ ...st, anchors: { ...st.anchors, recordBlobSha: blob(MERGE_WF) } });
    await expect(d.load()).rejects.toBeInstanceOf(UninstallError);
    // no merged central uninstall PR of this project (someone removed the record by hand): stop
    const e = await setup();
    e.w.merged.clear();
    await expect(e.load()).rejects.toBeInstanceOf(UninstallError);
    // the merged PR went onto another branch than central's default one: stop
    const g = await setup();
    const gp = g.w.central.pulls.find((p) => p.head === BR)!;
    gp.base = 'release';
    await expect(g.load()).rejects.toThrow(/No install record/);
    // the progress file is not at stage B (run 2 never began): "no install record"
    const k = await setup();
    const kf = await ProgressFile.open(APP, k.w.app.id, local(k.w));
    kf.save({ ...kf.state!, phase: 'A-done' });
    await expect(k.load()).rejects.toThrow(/No install record/);
    // not at stage B (no progress file): "no install record"
    const f = await setup();
    (await ProgressFile.open(APP, f.w.app.id, local(f.w))).remove();
    await expect(f.load()).rejects.toThrow(/No install record/);
  });
});

describe('V6-R1: the central branches (sec M1, M2)', () => {
  it('central: the central uninstall branch moves only while it points where pipegen set it; a teammate\'s commit stays', async () => {
    const w = world();
    await afterRun1(w);
    const rec = sampleRecord(w);
    const r1 = await run(w, rec);
    expect(r1.status).toBe('b-waiting');
    expect((await progressOf(w))?.centralUninstallHead).toBe(w.g.head('o/pipelines', BR));
    // a re-run with the branch where pipegen set it: fine
    const r1b = await run(w, rec);
    expect(r1b.failed).toEqual([]);
    const mate = w.g.commitOn('o/pipelines', BR, { 'NOTES.md': 'teammate fix\n' }, 'teammate');
    const n = w.g.calls.length;
    const r2 = await run(w, rec);
    expect(w.g.head('o/pipelines', BR)).toBe(mate);
    expect(w.g.calls.slice(n).filter((c) => !c.route.startsWith('GET ') && c.params.repo === 'pipelines')).toEqual([]);
    expect(r2.failed.some((f) => /gh api -X DELETE repos\/o\/pipelines\/git\/refs\/heads\/pipegen\/uninstall-shop/.test(f.manual ?? ''))).toBe(true);
    expect(r2.status).toBe('b-partial');
  });

  it('central: pipegen\'s central branches go only with the repo (inside deleteCentralRepo); a declined or refused delete keeps them', async () => {
    const setup = async () => {
      const w = world();
      await afterRun1(w);
      const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
      await run(w, rec, term(), { deleteRepos: true, canDeleteRepos: true });
      mergePr(w, w.central, BR);
      return { w, rec };
    };
    // (V6-R2 sec M3: an own branch at a head pipegen never recorded is refused before the question: test/uninstall-v6-r2.test.ts)
    // the user doesn't type pipelines: the repo and its branch stay
    const a = await setup();
    const ta = term({ type: (_q, exp) => (exp === 'pipelines' ? 'no' : exp) });
    await run(a.w, a.rec, ta, { deleteRepos: true, canDeleteRepos: true });
    expect(a.w.deleted).toEqual([]);
    expect(a.w.central.refs.has(`heads/${BR}`)).toBe(true);
    expect(a.w.g.routes()).not.toContain('DELETE /repos/{owner}/{repo}/git/refs/{ref}');
    // deleteCentralRepo refuses (an issue): the branches stay
    const b = await setup();
    b.w.lists.set('central:issues', [{ number: 9 }]);
    await run(b.w, b.rec, term(), { deleteRepos: true, canDeleteRepos: true });
    expect(b.w.deleted).toEqual([]);
    expect(b.w.central.refs.has(`heads/${BR}`)).toBe(true);
    // typed: the repo goes, and the question named the branches that go with it
    const c = await setup();
    const tc = term();
    await run(c.w, c.rec, tc, { deleteRepos: true, canDeleteRepos: true });
    expect(c.w.deleted).toEqual(['o/pipelines']);
    expect(tc.typed.some((q) => /Type pipelines to go on/.test(q) && /pipegen\/uninstall-shop/.test(q))).toBe(true);
    // a commit lands on pipegen's branch while pipegen asks: not deleted
    const m = await setup();
    const tm = term({ type: (_q, exp) => { if (exp === 'pipelines') m.w.g.commitOn('o/pipelines', BR, { 'later.txt': 'x\n' }, 'later'); return exp; } });
    await run(m.w, m.rec, tm, { deleteRepos: true, canDeleteRepos: true });
    expect(m.w.deleted).toEqual([]);
    // another branch still keeps it
    const d = await setup();
    d.w.central.refs.set('heads/team', d.w.g.head('o/pipelines'));
    await run(d.w, d.rec, term(), { deleteRepos: true, canDeleteRepos: true });
    expect(d.w.deleted).toEqual([]);
  });
});

describe('V6-R1: the org rule (sec M3, spec I2, spec M5)', () => {
  it('central: org rulesets pipegen can\'t read count as still there (typed trust, organization) → --required.yml kept with a manual step', async () => {
    const w = world({ ownerType: 'Organization' });
    const req = centralWorkflowFile('shop', 'required');
    const REQ = 'on: workflow_call # required\n';
    w.g.commitOn('o/pipelines', 'main', { [req]: REQ });
    w.org.set(77, { name: requiredRulesetName('shop'), rules: [{ type: 'workflows', parameters: { workflows: [{ path: req, sha: SHA('c'), repository_id: w.central.id }] } }] });
    await afterRun1(w);
    w.fail = (route) => (route.startsWith('GET /orgs/{org}/rulesets') ? 403 : undefined);
    const rec = sampleRecord(w, { files: [{ repo: 'central', path: '.github/workflows/shop--merge.yml', part: 'pipeline', shas: [blob(MERGE_WF)] }, { repo: 'central', path: req, part: 'pipeline', shas: [blob(REQ)] }] });
    const r = await run(w, rec, term(), {}, { trust: 'typed', typedNames: true });
    expect(filesAtPr(w).has(req)).toBe(true);
    expect(filesAtPr(w).has('.github/workflows/shop--merge.yml')).toBe(false);
    expect(r.manual.some((m) => m.what.includes(req) && /org/.test(m.why))).toBe(true);
  });

  it('central: the org rule by the recorded id, by its name or by the path it requires; unreadable lists and details count as there', async () => {
    const req = centralWorkflowFile('shop', 'required');
    const org = { owner: 'o', repo: 'shop', ownerType: 'Organization' as const };
    const mk = (set: (w: World) => void) => { const w = world({ ownerType: 'Organization' }); set(w); return w; };
    const rec = (w: World, over: Partial<InstallRecord> = {}) => sampleRecord(w, over);
    // not recorded: found by its name, or by the path it requires (another name)
    const byName = mk((w) => w.org.set(5, { name: requiredRulesetName('shop'), rules: [] }));
    expect(await orgRuleNow(readApi(byName), rec(byName), org, 'full')).toMatch(/pipegen-required--shop/);
    const byPath = mk((w) => w.org.set(6, { name: 'company-rules', rules: [{ type: 'workflows', parameters: { workflows: [{ path: req }] } }] }));
    expect(await orgRuleNow(readApi(byPath), rec(byPath), org, 'full')).not.toBeNull();
    const none = mk((w) => w.org.set(7, { name: 'company-rules', rules: [{ type: 'workflows', parameters: { workflows: [{ path: '.github/workflows/cart--required.yml' }] } }] }));
    expect(await orgRuleNow(readApi(none), rec(none), org, 'full')).toBeNull();
    // a detail pipegen can't read: still there
    const detail = mk((w) => { w.org.set(8, { name: 'company-rules', rules: [] }); w.fail = (route) => (route === 'GET /orgs/{org}/rulesets/{ruleset_id}' ? 500 : undefined); });
    expect(await orgRuleNow(readApi(detail), rec(detail), org, 'full')).not.toBeNull();
    // the list pipegen can't read, or 100 or more: still there for an organization, even with nothing recorded and full trust
    const unread = mk((w) => { w.fail = (route) => (route === 'GET /orgs/{org}/rulesets' ? 403 : undefined); });
    expect(await orgRuleNow(readApi(unread), rec(unread), org, 'full')).not.toBeNull();
    expect(await orgRuleNow(readApi(unread), rec(unread), org, 'typed')).not.toBeNull();
    const many = mk((w) => { for (let i = 1; i <= 100; i += 1) w.org.set(1000 + i, { name: `r${i}`, rules: [] }); });
    expect(await orgRuleNow(readApi(many), rec(many), org, 'full')).not.toBeNull();
    // a user account, full trust, nothing recorded: no org rule, nothing read
    const user = world();
    user.fail = (route) => (route.startsWith('GET /orgs/') ? 403 : undefined);
    const n = user.g.calls.length;
    expect(await orgRuleNow(readApi(user), rec(user), { owner: 'o', repo: 'shop', ownerType: 'User' }, 'full')).toBeNull();
    expect(user.g.calls.length).toBe(n);
    // a user account under typed trust (the record can't say there is none) and the list unreadable: still there
    expect(await orgRuleNow(readApi(user), rec(user), { owner: 'o', repo: 'shop', ownerType: 'User' }, 'typed')).not.toBeNull();
  });
});

describe('V6-R1: central now (sec M4, M5, spec M2, M5)', () => {
  it('phase B: central answering 404 at apply is "can\'t tell": nothing called uninstalled, the local files kept, a manual step', async () => {
    // 404 from the yes on: the re-check stops before anything is sent
    const a = world();
    await afterRun1(a);
    const lr = localFiles(a);
    const ta = term();
    const goa = ta.p.confirm;
    ta.p.confirm = async (m, d) => { if (m.startsWith('Go ahead')) a.fail = (_route, p) => (String(p.repo) === 'pipelines' ? 404 : undefined); return goa(m, d); };
    const n = a.g.calls.length;
    await expect(run(a, sampleRecord(a), ta)).rejects.toThrow(/can't see o\/pipelines/);
    expect(a.g.calls.slice(n).filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    expect(existsSync(lr)).toBe(true);
    // 404 from the central step on (after the re-check): a manual step, b-partial, local files and progress kept
    const b = world();
    await afterRun1(b);
    const lrb = localFiles(b);
    b.app.stored.set('PIPEGEN_A', AT);
    b.fail = (route, p) => {
      const first = route === `DELETE /repos/{owner}/{repo}/actions/${SEC}/{secret_name}` && Object.values(p).includes(A_NAME);
      if (first) b.fail = (_r, q) => (String(q.repo) === 'pipelines' ? 404 : undefined);
      return undefined;
    };
    const rb = await run(b, sampleRecord(b, { [SEC]: [{ name: 'PIPEGEN_A', scope: 'repo', created: true, githubCreatedAt: AT }] }));
    expect(rb.status).toBe('b-partial');
    expect(rb.lines.join('\n')).not.toMatch(/uninstalled/);
    expect(rb.manual.some((m) => /o\/pipelines/.test(m.what) && /can't see/.test(m.why))).toBe(true);
    expect(existsSync(lrb)).toBe(true);
    expect(existsSync(uninstallProgressPath(APP, local(b)))).toBe(true);
  });

  it('central: a project that joined after the last project took the central locks off is named after the merge; the central PR says so', async () => {
    const w = world();
    w.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': OWNERS_INS });
    w.central.rulesets.set(55, { name: CENTRAL_RULESET, source_type: 'Repository', source: 'o/pipelines', created_at: AT });
    w.settings.access = 'user';
    await afterRun1(w);
    const edits: InstallEdit[] = [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: OWNERS_INS, originalSha: null, writtenShas: [blob(OWNERS_INS)] }];
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true, rulesetId: 55, rulesetCreatedAt: AT, codeowners: { path: '.github/CODEOWNERS', created: true }, actionsAccess: { previous: 'none' } }, edits });
    const r1 = await run(w, rec);
    expect(r1.status).toBe('b-waiting');
    expect(w.central.pulls.find((p) => p.head === BR)?.body).toMatch(/Merge it only while no other project uses/);
    // cart installs now (no central ruleset: straight to main), then the uninstall PR merges
    mergePr(w, w.central, BR);
    w.g.commitOn('o/pipelines', 'main', { [recordPath('cart')]: '{}\n', '.github/workflows/cart--merge.yml': MERGE_WF });
    const r2 = await run(w, rec);
    expect(r2.manual.some((m) => /central locks/.test(m.what) && /cart/.test(m.why) && /pipegen finish/.test(m.step ?? ''))).toBe(true);
    // not the last project when its PR was built (the locks stayed): nothing claims they came off
    const x = world();
    x.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': OWNERS_INS, [recordPath('cart')]: '{}\n', '.github/workflows/cart--merge.yml': MERGE_WF });
    x.central.rulesets.set(55, { name: CENTRAL_RULESET, source_type: 'Repository', source: 'o/pipelines', created_at: AT });
    await afterRun1(x);
    const xrec = sampleRecord(x, { central: { repoId: x.central.id, createdByPipegen: true, rulesetId: 55, rulesetCreatedAt: AT, codeowners: { path: '.github/CODEOWNERS', created: true } }, edits });
    await run(x, xrec);
    mergePr(x, x.central, BR);
    const rx = await run(x, xrec);
    expect(rx.manual.some((m) => /central locks/.test(m.what))).toBe(false);
  });

  it('central: this project\'s merged central PR counts only from the recorded central repo onto its default branch; a record back in central is not done', async () => {
    const w = world();
    w.central.refs.set(`heads/${BR}`, w.g.head('o/pipelines'));
    w.central.pulls.push({ number: 3, head: BR, base: 'main', title: 't', body: '', state: 'closed', html_url: 'https://github.com/o/pipelines/pull/3' });
    w.merged.set('pipelines#3', AT);
    const c = await centralNow(readApi(w), APP, w.central.id);
    expect(c?.pr).toMatchObject({ number: 3, merged: true });
    // from another repo (a fork's branch of that name): not this project's PR
    expect((await centralNow(readApi(w), APP, w.central.id + 1))?.pr).toBeNull();
    // onto another branch: not merged for uninstall
    const pr = w.central.pulls[0]!;
    pr.base = 'release';
    expect((await centralNow(readApi(w), APP, w.central.id))?.pr?.merged).toBe(false);

    // the record gone from central, but the merged PR went onto another branch: the re-check stops, nothing sent
    const y = world();
    await afterRun1(y);
    y.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: null }, 'gone');
    y.central.refs.set(`heads/${BR}`, y.g.head('o/pipelines'));
    y.central.pulls.push({ number: 3, head: BR, base: 'release', title: 't', body: '', state: 'closed', html_url: 'https://github.com/o/pipelines/pull/3' });
    y.merged.set('pipelines#3', AT);
    const ny = y.g.calls.length;
    await expect(run(y, sampleRecord(y))).rejects.toBeInstanceOf(UninstallError);
    expect(y.g.calls.slice(ny).filter((c) => !c.route.startsWith('GET '))).toEqual([]);

    // a merged central PR of an earlier uninstall, and the record back in central (installed again): not done, the record stays
    const x = world();
    await afterRun1(x);
    const lr = localFiles(x);
    x.central.refs.set(`heads/${BR}`, x.g.head('o/pipelines'));
    x.central.pulls.push({ number: 3, head: BR, base: 'main', title: 't', body: '', state: 'closed', html_url: 'https://github.com/o/pipelines/pull/3' });
    x.merged.set('pipelines#3', AT);
    const rx = await run(x, sampleRecord(x));
    expect(rx.status).not.toBe('b-done');
    expect(x.g.filesAt('o/pipelines', x.g.head('o/pipelines')).has(recordPath('shop'))).toBe(true);
    expect(existsSync(lr)).toBe(true);
  });
});

describe('V6-R1: leftovers and the record (spec M1, spec M5, spec I3)', () => {
  it('phase B: a name the user declined to type is a leftover: the record question names it and the record stays', async () => {
    const w = world();
    await afterRun1(w);
    w.app.stored.set('PIPEGEN_A', AT);
    const rec = sampleRecord(w, { [SEC]: [{ name: 'PIPEGEN_A', scope: 'repo', created: true, githubCreatedAt: AT }] });
    const t = term({ type: (_q, exp) => (exp === 'PIPEGEN_A' ? 'no' : exp) });
    const r = await run(w, rec, t, {}, { typedNames: true });
    expect(w.app.stored.has('PIPEGEN_A')).toBe(true);
    expect(t.confirms.some((q) => q.startsWith('Remove the install record') && /PIPEGEN_A/.test(q))).toBe(true);
    expect(filesAtPr(w).has(recordPath('shop'))).toBe(true);
    expect(r.manual.some((m) => /PIPEGEN_A/.test(m.what))).toBe(true);
  });

  it('phase B: a leftovers-file entry for another repo keeps the leftovers file and the local record', async () => {
    const w = world();
    await afterRun1(w);
    const lr = localFiles(w);
    const lf = lr.replace(/\.json$/, '.leftovers.json');
    writeFileSync(lf, `${JSON.stringify({ updatedAt: AT, items: [{ kind: 'branch', name: 'pipegen/setup', repo: 'o/other' }] })}\n`, { mode: 0o600 });
    await run(w, sampleRecord(w));
    mergePr(w, w.central, BR);
    const r = await run(w, sampleRecord(w));
    expect(r.status).toBe('b-partial');
    expect(existsSync(lf)).toBe(true);
    expect(existsSync(lr)).toBe(true);
    expect(r.manual.some((m) => /another repo/.test(m.why))).toBe(true);
  });

  it('phase B: a saved proof state → cleanupLeftovers through the phase-B api; the scratch repo is not deleted there', async () => {
    const w = world();
    await afterRun1(w);
    const RUN = '20261106-090000-abc123';
    const store = await StateStore.open(APP, local(w));
    store.begin(RUN, { owner: 'o', repo: 'shop', private: true, ownerType: 'User', defaultBranch: 'main' }, { cap: 100, aiCap: null });
    store.markArmed(true);
    store.recordBranch('central', `proof/${RUN}`, 'main');
    w.central.refs.set(`heads/proof/${RUN}`, w.g.head('o/pipelines'));
    const r = await run(w, sampleRecord(w, { scratch: { repoId: w.scratch!.id, createdByPipegen: true } }));
    expect(w.out.join('\n')).toMatch(/clean up what the saved proof left/);
    expect(r.done.some((d) => /saved proof/.test(d) && /pipegen cleanup/.test(d))).toBe(true);
    expect(w.central.refs.has(`heads/proof/${RUN}`)).toBe(false);
    expect(w.deleted).toEqual([]);
    expect(r.status).toBe('b-waiting');   // the rest of run 2 went on after the lease came back
  });

  it('central: a central ruleset with no creation date is deleted only after its name is typed at apply time; not typed → kept, a leftover', async () => {
    const setup = () => {
      const w = world();
      w.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': OWNERS_INS });
      w.central.rulesets.set(55, { name: CENTRAL_RULESET, source_type: 'Repository', source: 'o/pipelines', created_at: AT });
      const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true, rulesetId: 55 } });
      return { w, rec };
    };
    const a = setup();
    await afterRun1(a.w);
    const ta = term();
    await run(a.w, a.rec, ta);
    expect(a.w.central.rulesets.has(55)).toBe(false);
    const asked = ta.typed.filter((q) => /ruleset/i.test(q));
    expect(asked.length).toBe(1);
    expect(asked[0]).toMatch(/55/);
    const del = a.w.g.calls.findIndex((c) => c.route === 'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}');
    const pr = a.w.g.calls.findIndex((c) => c.route === 'POST /repos/{owner}/{repo}/pulls' && c.params.repo === 'pipelines');
    expect(del).toBeGreaterThan(-1);
    expect(pr).toBeGreaterThan(del);
    // not typed: kept, and it is a leftover (the record question names it)
    const b = setup();
    await afterRun1(b.w);
    const tb = term({ type: (q, exp) => (/ruleset/i.test(q) ? 'no' : exp) });
    const rb = await run(b.w, b.rec, tb);
    expect(b.w.central.rulesets.has(55)).toBe(true);
    expect(rb.manual.some((m) => /central ruleset/.test(m.what))).toBe(true);
    expect(tb.confirms.some((q) => q.startsWith('Remove the install record') && /central ruleset/.test(q))).toBe(true);
  });
});

describe('V6-R1: Ctrl-C and a rate stop in run 2 (sec M7)', () => {
  it('phase B: Ctrl-C after the first delete → interrupted; the next item and central untouched; progress B with the PR number and the record\'s blob', async () => {
    const w = world();
    await afterRun1(w);
    w.app.stored.set('PIPEGEN_A', AT);
    w.app.stored.set('PIPEGEN_B', AT);
    const rec = sampleRecord(w, { [SEC]: [{ name: 'PIPEGEN_A', scope: 'repo', created: true, githubCreatedAt: AT }, { name: 'PIPEGEN_B', scope: 'repo', created: true, githubCreatedAt: AT }] });
    w.fail = (route, p) => { if (route === `DELETE /repos/{owner}/{repo}/actions/${SEC}/{secret_name}` && Object.values(p).includes(A_NAME)) h.stop.now = true; return undefined; };
    const r = await run(w, rec);
    expect(r.status).toBe('interrupted');
    expect(w.app.stored.has('PIPEGEN_A')).toBe(false);
    expect(w.app.stored.has('PIPEGEN_B')).toBe(true);
    expect(writes(w).filter((x) => x.includes('pipelines'))).toEqual([]);
    const st = await progressOf(w);
    expect(st?.phase).toBe('B');
    expect(st?.prNumber).toBe(1);
    expect(st?.anchors.recordBlobSha).toBe(blob(RECORD_TEXT));
  });

  it('phase B: a rate stop mid-step → thrown; progress B saved with the PR number; nothing after it', async () => {
    const w = world();
    await afterRun1(w);
    w.app.stored.set('PIPEGEN_A', AT);
    w.app.stored.set('PIPEGEN_B', AT);
    const rec = sampleRecord(w, { [SEC]: [{ name: 'PIPEGEN_A', scope: 'repo', created: true, githubCreatedAt: AT }, { name: 'PIPEGEN_B', scope: 'repo', created: true, githubCreatedAt: AT }] });
    const base = gh(w) as unknown as { request: (r: string, p: Record<string, unknown>) => Promise<unknown> };
    const g = { request: async (route: string, params: Record<string, unknown> = {}) => {
      if (route === `DELETE /repos/{owner}/{repo}/actions/${SEC}/{secret_name}` && Object.values(params).includes(A_NAME)) throw new GitHubRateLimitError('rate', { budgetSpent: true });
      return base.request(route, params);
    } } as unknown as Octokit;
    const err = await uninstallStep(g, loadedOf(w, rec), term().p, deps(w)).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(GitHubRateLimitError);
    expect(w.app.stored.has('PIPEGEN_B')).toBe(true);
    expect(writes(w).filter((x) => x.includes('pipelines'))).toEqual([]);
    const st = await progressOf(w);
    expect(st?.phase).toBe('B');
    expect(st?.prNumber).toBe(1);
    expect(st?.anchors.recordBlobSha).toBe(blob(RECORD_TEXT));
  });
});
