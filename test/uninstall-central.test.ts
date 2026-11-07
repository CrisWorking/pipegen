// v0.2 Plan V V6 (rulings V-B4, V-B5, V-S3, V-N9, V-N13; V3-hook1, V4-R1b M-r1-5, V3-wiki, V3-R2): the central part of run 2. One central pull
// request removes this project's exact files and, last, its install record; the central ruleset, CODEOWNERS and Actions access go only
// with the last project (re-computed now from the records AND the files AND the open pull requests, and checked again inside target.ts);
// --delete-repos deletes only with the App's Administration write, the exact name, the marker, the recorded id and a typed name.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { recordPath } from '../src/deliver/record.js';
import { CENTRAL_RULESET } from '../src/layers/locks.js';
import type { InstallEdit, InstallRecord } from '../src/types.js';
import { uninstallStep, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
import { ProgressFile } from '../src/uninstall/progress.js';
import type { LoadedRecord } from '../src/uninstall/record.js';
import { deleteCentralRepo, UninstallApi, UninstallRefusal, type AskName } from '../src/uninstall/target.js';
import {
  ACCESS_ROUTE, AT, blob, cleanHomes, deps, gh, loadedOf, local, MERGE_WF, mergePr, RECORD_TEXT, sampleRecord, SEC, SHA, term, world, writes, type Term, type World,
} from './helpers/uninstall-world.js';

vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => false,
  onInterrupt: () => () => {},
}));
afterEach(() => { cleanHomes(); });

async function afterRun1(w: World): Promise<void> {
  w.app.refs.set('heads/pipegen/uninstall', w.g.head(`o/${w.app.name}`));
  w.app.pulls.push({ number: 1, head: 'pipegen/uninstall', base: 'main', title: 'pipegen: uninstall', body: '', state: 'closed', html_url: `https://github.com/o/${w.app.name}/pull/1` });
  w.merged.set(`${w.app.name}#1`, '2026-11-06T10:00:00Z');
  const pf = await ProgressFile.open({ owner: 'o', repo: w.app.name }, w.app.id, local(w));
  pf.save({ phase: 'A-done', anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: w.g.head('o/pipelines'), recordBlobSha: blob(RECORD_TEXT) }, prNumber: 1, prUrl: `https://github.com/o/${w.app.name}/pull/1`, done: [], leftovers: [] });
}
const run = (w: World, rec: InstallRecord, t: Term = term(), over: Partial<StepDeps> = {}, lo: Partial<LoadedRecord> = {}): Promise<StepResult> =>
  uninstallStep(gh(w), loadedOf(w, rec, lo), t.p, deps(w, over));
const OWNERS_INS = '# pipegen:begin\n/.github/workflows/ @o\n# pipegen:end\n';
const prBranch = (w: World): string => `pipegen/uninstall-${w.app.name}`;
const filesAtPr = (w: World): Map<string, string> => w.g.filesAt('o/pipelines', w.g.head('o/pipelines', prBranch(w)));
const liveCentralRs = (over: Record<string, unknown> = {}) => ({ name: CENTRAL_RULESET, source_type: 'Repository', source: 'o/pipelines', created_at: AT, ...over });
/** The central locks of the last project: ruleset 55, the CODEOWNERS pipegen created, the Actions access it set. */
function centralLocks(w: World, over: Partial<NonNullable<InstallRecord['central']>> = {}): { central: NonNullable<InstallRecord['central']>; edits: InstallEdit[] } {
  w.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': OWNERS_INS });
  w.central.rulesets.set(55, liveCentralRs());
  w.settings.access = 'user';
  return {
    central: { repoId: w.central.id, createdByPipegen: true, rulesetId: 55, rulesetCreatedAt: AT, codeowners: { path: '.github/CODEOWNERS', created: true }, actionsAccess: { previous: 'none' }, ...over },
    edits: [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: OWNERS_INS, originalSha: null, writtenShas: [blob(OWNERS_INS)] }],
  };
}

describe('uninstall central: the last project (V-B4, V-N9)', () => {
  it('central: other projects remain → central kept', async () => {
    const w = world();
    w.g.commitOn('o/pipelines', 'main', { [recordPath('cart')]: '{}\n', '.github/workflows/cart--merge.yml': MERGE_WF });
    await afterRun1(w);
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
    const t = term();
    const r1 = await run(w, rec, t, { deleteRepos: true, canDeleteRepos: true });
    expect(r1.status).toBe('b-waiting');
    expect(w.out.join('\n')).toMatch(/other projects/);
    mergePr(w, w.central, prBranch(w));
    const n = w.g.calls.length;
    const r2 = await run(w, rec, t, { deleteRepos: true, canDeleteRepos: true });
    expect(w.g.repos.has('o/pipelines')).toBe(true);
    expect(w.g.calls.slice(n).filter((c) => !c.route.startsWith('GET ') && c.params.repo === 'pipelines')).toEqual([]);
    expect(w.deleted).not.toContain('o/pipelines');
    expect(t.typed.some((q) => /Type pipelines to go on/.test(q))).toBe(false);
    expect([...r2.skipped, ...r2.manual].some((s) => /pipelines/.test(s.what) && /other project/.test(s.why))).toBe(true);
    // the other project's files are untouched
    const now = w.g.filesAt('o/pipelines', w.g.head('o/pipelines'));
    expect(now.has(recordPath('cart'))).toBe(true);
    expect(now.has('.github/workflows/cart--merge.yml')).toBe(true);
  });

  it('central: other projects remain → central ruleset and CODEOWNERS kept', async () => {
    const w = world();
    const locks = centralLocks(w);
    w.g.commitOn('o/pipelines', 'main', { [recordPath('cart')]: '{}\n' });
    await afterRun1(w);
    const rec = sampleRecord(w, { central: locks.central, edits: locks.edits });
    const r = await run(w, rec);
    expect(w.central.rulesets.has(55)).toBe(true);
    expect(writes(w).filter((x) => x.startsWith('DELETE /repos/{owner}/{repo}/rulesets'))).toEqual([]);
    expect(filesAtPr(w).get('.github/CODEOWNERS')).toBe(OWNERS_INS);
    expect(writes(w).filter((x) => x.startsWith(ACCESS_ROUTE))).toEqual([]);
    expect(w.settings.access).toBe('user');
    expect(r.skipped.some((s) => /central ruleset|CODEOWNERS|Actions access/.test(s.what) && /other project/.test(s.why))).toBe(true);
    // this project's own files still go
    expect(filesAtPr(w).has('.github/workflows/shop--merge.yml')).toBe(false);
  });

  it('central: no project left → recorded central ruleset deleted and created CODEOWNERS removed before central is emptied or deleted', async () => {
    const w = world();
    const locks = centralLocks(w);
    await afterRun1(w);
    const rec = sampleRecord(w, { central: locks.central, edits: locks.edits });
    const t = term();
    const r1 = await run(w, rec, t, { deleteRepos: true, canDeleteRepos: true });
    expect(r1.status).toBe('b-waiting');
    expect(w.central.rulesets.has(55)).toBe(false);
    expect(w.settings.access).toBe('none');   // V-N9: back to what it was before pipegen
    const routes = w.g.routes();
    const rsDel = routes.indexOf('DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}');
    const prOpen = w.g.calls.findIndex((c) => c.route === 'POST /repos/{owner}/{repo}/pulls' && c.params.repo === 'pipelines');
    expect(rsDel).toBeGreaterThan(-1);
    expect(prOpen).toBeGreaterThan(rsDel);   // the ruleset first, so the central PR can merge
    // the CODEOWNERS pipegen created goes in the central PR, before the record (the last commit)
    expect(filesAtPr(w).has('.github/CODEOWNERS')).toBe(false);
    const hist = w.g.history('o/pipelines', w.g.head('o/pipelines', prBranch(w)), w.g.head('o/pipelines')).map((c) => c.message);
    expect(hist[0]).toMatch(/install record/);
    expect(hist.findIndex((m) => /CODEOWNERS/.test(m))).toBeGreaterThan(0);
    expect(w.deleted).toEqual([]);   // central is not deleted before its PR merged
    expect(r1.lines.join('\n')).toMatch(/merge .*then run `pipegen uninstall --delete-repos` again/i);
    expect(w.central.pulls.find((p) => p.head === prBranch(w))?.state).toBe('open');
    expect(w.central.refs.has(`heads/${prBranch(w)}`)).toBe(true);
    // merged: the repo goes, after the typed name and the typed numbers of pipegen's central pull requests
    mergePr(w, w.central, prBranch(w));
    const before = w.g.calls.length;
    const r2 = await run(w, rec, t, { deleteRepos: true, canDeleteRepos: true });
    expect(w.deleted).toContain('o/pipelines');
    expect(w.g.calls.slice(before).findIndex((c) => c.route === 'DELETE /repos/{owner}/{repo}' && c.params.repo === 'pipelines')).toBeGreaterThan(-1);
    expect(t.typed.some((q) => /Type pipelines to go on/.test(q))).toBe(true);
    expect(t.typed.some((q) => /Type 1 to go on/.test(q))).toBe(true);
    expect(r2.done.some((d) => /o\/pipelines/.test(d))).toBe(true);
  });

  it('central: recorded central ruleset whose name isn\'t pipegen → not deleted, listed as skipped', async () => {
    const w = world();
    const locks = centralLocks(w);
    w.central.rulesets.set(55, liveCentralRs({ name: 'team-rules' }));
    await afterRun1(w);
    const r = await run(w, sampleRecord(w, { central: locks.central, edits: locks.edits }));
    expect(w.central.rulesets.has(55)).toBe(true);
    expect(writes(w).filter((x) => x.startsWith('DELETE /repos/{owner}/{repo}/rulesets'))).toEqual([]);
    expect(r.skipped.some((s) => /central ruleset/.test(s.what) && /not the one pipegen created/.test(s.why))).toBe(true);
    // the name is pipegen's but GitHub says it was created at another time: not the one pipegen created either
    const w2 = world();
    const locks2 = centralLocks(w2);
    w2.central.rulesets.set(55, liveCentralRs({ created_at: '2026-01-01T00:00:00Z' }));
    await afterRun1(w2);
    await run(w2, sampleRecord(w2, { central: locks2.central, edits: locks2.edits }));
    expect(w2.central.rulesets.has(55)).toBe(true);
  });

  it('central: the last project, a central CODEOWNERS that was there before pipegen: only pipegen\'s block taken out (V2)', async () => {
    const w = world();
    const team = '* @o/team\n';
    w.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': team + OWNERS_INS });
    await afterRun1(w);
    const rec = sampleRecord(w, {
      central: { repoId: w.central.id, createdByPipegen: true, codeowners: { path: '.github/CODEOWNERS', created: false } },
      edits: [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: OWNERS_INS, originalSha: blob(team), writtenShas: [blob(team + OWNERS_INS)] }],
    });
    w.g.commitOn('o/pipelines', 'main', {});
    await run(w, rec);
    expect(filesAtPr(w).get('.github/CODEOWNERS')).toBe(team);
  });

  it('central: another project\'s workflow file or record present → not the last project, even with records deleted', async () => {
    for (const other of [
      { '.github/workflows/cart--push.yml': MERGE_WF },   // a workflow file, its record deleted
      { [recordPath('cart')]: '{}\n' },                     // a record alone
    ]) {
      const w = world();
      const locks = centralLocks(w);
      w.g.commitOn('o/pipelines', 'main', other);
      await afterRun1(w);
      await run(w, sampleRecord(w, { central: locks.central, edits: locks.edits }));
      expect(w.central.rulesets.has(55), JSON.stringify(other)).toBe(true);
      // run 2's own last-project rule (not only target.ts's): the ruleset is not even read
      expect(w.g.calls.some((c) => c.route === 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}' && c.params.repo === 'pipelines'), JSON.stringify(other)).toBe(false);
      expect(w.settings.access).toBe('user');
    }
    // an open central pull request of another project (its update branch)
    const w = world();
    const locks = centralLocks(w);
    w.central.refs.set('heads/pipegen/update-cart', w.g.head('o/pipelines'));
    w.central.pulls.push({ number: 7, head: 'pipegen/update-cart', base: 'main', title: 'x', body: '', state: 'open', html_url: 'https://github.com/o/pipelines/pull/7' });
    await afterRun1(w);
    await run(w, sampleRecord(w, { central: locks.central, edits: locks.edits }));
    expect(w.central.rulesets.has(55)).toBe(true);
    expect(w.g.calls.some((c) => c.route === 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}' && c.params.repo === 'pipelines')).toBe(false);
  });

  it('central: exact file list from the record, never a glob (repo a vs a--b)', async () => {
    const w = world({ appRepo: 'a', central: { [recordPath('a')]: RECORD_TEXT, '.github/workflows/a--merge.yml': MERGE_WF, [recordPath('a--b')]: '{}\n', '.github/workflows/a--b--merge.yml': MERGE_WF, '.github/workflows/a--b--push.yml': MERGE_WF } });
    await afterRun1(w);
    // an edited record claims a--b's file too (at its real sha): still never removed
    const rec = sampleRecord(w, { files: [...sampleRecord(w).files, { repo: 'central', path: '.github/workflows/a--b--merge.yml', part: 'pipeline', shas: [blob(MERGE_WF)] }] });
    await run(w, rec, term({ yes: () => true }));
    const files = filesAtPr(w);
    expect(files.has('.github/workflows/a--merge.yml')).toBe(false);
    expect(files.has(recordPath('a'))).toBe(false);
    expect(files.get('.github/workflows/a--b--merge.yml')).toBe(MERGE_WF);
    expect(files.get('.github/workflows/a--b--push.yml')).toBe(MERGE_WF);
    expect(files.has(recordPath('a--b'))).toBe(true);
    // a central file of this project that changed since pipegen wrote it is kept
    const w2 = world();
    w2.g.commitOn('o/pipelines', 'main', { '.github/workflows/shop--merge.yml': 'on: workflow_call # mine\n' });
    await afterRun1(w2);
    const t2 = term({ yes: () => false });
    const r2 = await run(w2, sampleRecord(w2), t2);
    expect(r2.manual.some((m) => /shop--merge\.yml/.test(m.what))).toBe(true);
    // the kept file is a leftover: the record stays at the user's no, so there is nothing to change on central
    expect(t2.confirms.some((q) => q.startsWith('Remove the install record') && /shop--merge\.yml/.test(q))).toBe(true);
    expect(w2.central.pulls).toEqual([]);
    expect(w2.g.filesAt('o/pipelines', w2.g.head('o/pipelines')).get('.github/workflows/shop--merge.yml')).toBe('on: workflow_call # mine\n');
  });

  it('apply: public app repo → records-only pipelines PR removes only the record', async () => {
    const w = world({ central: { [recordPath('shop')]: RECORD_TEXT, 'README.md': '# pipelines\n', '.github/workflows/shop--merge.yml': MERGE_WF } });
    await afterRun1(w);
    const rec = sampleRecord(w, { centralSha: null });
    await run(w, rec, term({ yes: () => true }));
    const files = filesAtPr(w);
    expect(files.has(recordPath('shop'))).toBe(false);
    expect(files.get('README.md')).toBe('# pipelines\n');
    expect(files.get('.github/workflows/shop--merge.yml')).toBe(MERGE_WF);   // not a central file of a public app: never removed
    const hist = w.g.history('o/pipelines', w.g.head('o/pipelines', prBranch(w)), w.g.head('o/pipelines'));
    expect(hist).toHaveLength(1);
  });
});

describe('uninstall central: --delete-repos (V-S3, V-B5)', () => {
  it('apply: --delete-repos deletes with the App\'s consented Administration write only (exact name, marker, recorded id, typed name); token mode prints gh repo delete and deletes nothing', async () => {
    const setup = async (over: Partial<InstallRecord> = {}) => {
      const w = world();
      await afterRun1(w);
      const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true }, scratch: { repoId: w.scratch!.id, createdByPipegen: true }, ...over });
      return { w, rec };
    };
    // App mode: the scratch repo goes now (its name typed); central after its PR merged
    const a = await setup();
    const t = term();
    const r1 = await run(a.w, a.rec, t, { deleteRepos: true, canDeleteRepos: true });
    expect(a.w.out.join('\n')).toMatch(/pipegen-proof-shop/);   // named in the preview before the one yes (M-r1-9)
    expect(a.w.deleted).toEqual(['o/pipegen-proof-shop']);
    expect(t.typed.some((q) => /Type pipegen-proof-shop to go on/.test(q))).toBe(true);
    expect(r1.done.some((d) => /pipegen-proof-shop/.test(d))).toBe(true);
    mergePr(a.w, a.w.central, prBranch(a.w));
    await run(a.w, a.rec, t, { deleteRepos: true, canDeleteRepos: true });
    expect(a.w.deleted).toEqual(['o/pipegen-proof-shop', 'o/pipelines']);

    // a name not typed, no marker, another id, no recorded id: nothing deleted
    const b = await setup();
    await run(b.w, b.rec, term({ type: (_q, exp) => (exp === 'pipegen-proof-shop' ? 'no' : exp) }), { deleteRepos: true, canDeleteRepos: true });
    expect(b.w.deleted).toEqual([]);
    const c = await setup();
    c.w.meta.set('pipegen-proof-shop', { description: 'mine' });
    await run(c.w, c.rec, term(), { deleteRepos: true, canDeleteRepos: true });
    expect(c.w.deleted).toEqual([]);
    const d = await setup();
    const rd = await run(d.w, { ...d.rec, scratch: { repoId: 999_999, createdByPipegen: true } }, term(), { deleteRepos: true, canDeleteRepos: true });
    expect(d.w.deleted).toEqual([]);
    expect([...rd.skipped, ...rd.manual].some((s) => /pipegen-proof-shop/.test(s.what))).toBe(true);
    const e = await setup({ central: { createdByPipegen: true } });
    await run(e.w, e.rec, term(), { deleteRepos: true, canDeleteRepos: true });
    mergePr(e.w, e.w.central, prBranch(e.w));
    const re = await run(e.w, e.rec, term(), { deleteRepos: true, canDeleteRepos: true });
    expect(e.w.deleted).not.toContain('o/pipelines');   // G14 R2 m4: no recorded id → kept, a manual step
    expect(re.manual.some((m) => /pipelines/.test(m.what))).toBe(true);

    // token mode: the commands are printed, nothing is deleted
    const f = await setup();
    const ft = term();
    await run(f.w, f.rec, ft, { deleteRepos: true, canDeleteRepos: false });
    expect(f.w.out.join('\n')).toMatch(/gh repo delete o\/pipegen-proof-shop/);
    mergePr(f.w, f.w.central, prBranch(f.w));
    const rf = await run(f.w, f.rec, ft, { deleteRepos: true, canDeleteRepos: false });
    expect(f.w.deleted).toEqual([]);
    expect(f.w.g.routes()).not.toContain('DELETE /repos/{owner}/{repo}');
    expect(rf.lines.join('\n')).toMatch(/gh repo delete o\/pipelines/);
    expect(ft.typed.some((q) => /Type (pipelines|pipegen-proof-shop) to go on/.test(q))).toBe(false);
  });

  it('central: org rule still present → --required.yml kept and the central repo not deleted', async () => {
    const w = world({ ownerType: 'Organization', central: { [recordPath('shop')]: RECORD_TEXT, '.github/workflows/shop--merge.yml': MERGE_WF, '.github/workflows/shop--required.yml': MERGE_WF } });
    await afterRun1(w);
    w.org.set(77, { name: 'pipegen-required--shop', source_type: 'Organization', source: 'o', created_at: AT, rules: [{ type: 'workflows', parameters: { workflows: [{ path: '.github/workflows/shop--required.yml', sha: SHA('c'), repository_id: w.central.id }] } }] });
    const rec = sampleRecord(w, {
      files: [...sampleRecord(w).files, { repo: 'central', path: '.github/workflows/shop--required.yml', part: 'pipeline', shas: [blob(MERGE_WF)] }],
      central: { repoId: w.central.id, createdByPipegen: true }, orgRuleset: { org: 'o', id: 77, name: 'pipegen-required--shop', githubCreatedAt: AT, pinnedSha: SHA('c') },
    });
    const r1 = await run(w, rec, term({ yes: () => true }), { deleteRepos: true, canDeleteRepos: true });
    expect(filesAtPr(w).get('.github/workflows/shop--required.yml')).toBe(MERGE_WF);
    expect(filesAtPr(w).has('.github/workflows/shop--merge.yml')).toBe(false);
    expect(r1.manual.some((m) => /shop--required\.yml/.test(m.what) && /org/i.test(m.why))).toBe(true);
    mergePr(w, w.central, prBranch(w));
    const r2 = await run(w, rec, term({ yes: () => true }), { deleteRepos: true, canDeleteRepos: true });
    expect(w.deleted).not.toContain('o/pipelines');
    expect([...r2.skipped, ...r2.manual].some((m) => /pipelines/.test(m.what) && /pipegen-required--shop/.test(m.why))).toBe(true);
  });
});

describe('uninstall central: inside target.ts (V3-hook1, V3-wiki, spec N3)', () => {
  const APP = (w: World) => ({ owner: 'o', repo: 'shop', repoId: w.app.id });
  const yes: AskName = async () => true;

  it('target: two projects\' records in central → the central ruleset is kept, even when the caller says lastProject', async () => {
    const w = world();
    w.central.rulesets.set(55, liveCentralRs());
    w.g.commitOn('o/pipelines', 'main', { [recordPath('cart')]: '{}\n' });
    w.central.stored.set('PIPEGEN_CENTRAL_KEY', AT);
    w.settings.access = 'user';
    const api = new UninstallApi(gh(w), APP(w), { askName: yes, centralRepoId: w.central.id });
    const o = await api.deleteIfPipegens({ kind: 'central-ruleset', id: 55, createdAt: AT });
    expect(o).toMatchObject({ status: 'kept' });
    expect((o as { why: string }).why).toMatch(/other project/);
    expect(w.central.rulesets.has(55)).toBe(true);
    expect(await api.deleteIfPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_CENTRAL_KEY', scope: 'central', created: true, githubCreatedAt: AT } })).toMatchObject({ status: 'kept' });
    expect(w.central.stored.has('PIPEGEN_CENTRAL_KEY')).toBe(true);
    expect(await api.write(ACCESS_ROUTE, { owner: 'o', repo: 'pipelines', access_level: 'none' }, { pipegenSet: 'user' })).toMatchObject({ status: 'kept' });
    expect(w.settings.access).toBe('user');
    // the central CODEOWNERS block: no commit while another project is there
    const head = w.g.head('o/pipelines');
    const tree = w.central.commits.get(head)?.tree as string;
    const edits: InstallEdit[] = [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: OWNERS_INS, originalSha: null, writtenShas: [blob(OWNERS_INS)] }];
    await expect(api.commitUninstall('central', { parent: head, baseTree: tree, files: [{ path: '.github/CODEOWNERS', content: '', mode: '100644' }], deletes: [], message: 'x', recordEdits: edits })).rejects.toBeInstanceOf(UninstallRefusal);
    // another project's central workflow alone counts too
    const w2 = world();
    w2.central.rulesets.set(55, liveCentralRs());
    w2.g.commitOn('o/pipelines', 'main', { '.github/workflows/cart--required.yml': MERGE_WF });
    const api2 = new UninstallApi(gh(w2), APP(w2), { askName: yes, centralRepoId: w2.central.id });
    expect(await api2.deleteIfPipegens({ kind: 'central-ruleset', id: 55, createdAt: AT })).toMatchObject({ status: 'kept' });
    // the last project: deleted
    const w3 = world();
    w3.central.rulesets.set(55, liveCentralRs());
    const api3 = new UninstallApi(gh(w3), APP(w3), { askName: yes, centralRepoId: w3.central.id });
    expect(await api3.deleteIfPipegens({ kind: 'central-ruleset', id: 55, createdAt: AT })).toEqual({ status: 'deleted' });
  });

  it('central: a deploy key, a webhook or a central pull request whose author can\'t be proved keeps the central repo unless its number is typed', async () => {
    const empty = () => {
      const w = world({ central: { 'README.md': '# pipelines\n' } });
      const rec = sampleRecord(w, { files: [], central: { repoId: w.central.id, createdByPipegen: true } });
      return { w, rec };
    };
    const ask = (answers: Record<string, string> = {}): AskName & { asked: string[] } => {
      const asked: string[] = [];
      return Object.assign(async (expected: string, question: string) => { asked.push(`${expected}|${question}`); return (answers[expected] ?? expected) === expected; }, { asked });
    };
    for (const k of ['keys', 'hooks']) {
      const x = empty();
      x.w.lists.set(`central:${k}`, [{ id: 1 }]);
      const res = await deleteCentralRepo(gh(x.w), { owner: 'o', repo: 'pipelines' }, x.rec, { askName: ask() });
      expect(res.deleted, k).toBe(false);
      expect(res.why, k).toMatch(k === 'keys' ? /deploy key/ : /webhook/);
      // a list the token can't read: named in the question and in `unchecked`
      const y = empty();
      y.w.lists.set(`central:${k}`, 403);
      const a = ask();
      const res2 = await deleteCentralRepo(gh(y.w), { owner: 'o', repo: 'pipelines' }, y.rec, { askName: a });
      expect(res2.deleted, k).toBe(true);
      expect(a.asked.some((q) => q.startsWith('pipelines|') && (k === 'keys' ? /deploy keys/ : /webhooks/).test(q))).toBe(true);
      expect(res2.unchecked?.join(' ')).toMatch(k === 'keys' ? /deploy keys/ : /webhooks/);
    }
    // pipegen's central uninstall PR (merged): its number typed, or the repo stays
    const z = empty();
    z.w.central.refs.set('heads/pipegen/uninstall-shop', z.w.g.head('o/pipelines'));
    z.w.central.pulls.push({ number: 4, head: 'pipegen/uninstall-shop', base: 'main', title: 'x', body: '', state: 'closed', html_url: 'https://github.com/o/pipelines/pull/4' });
    z.w.central.refs.delete('heads/pipegen/uninstall-shop');
    const no = await deleteCentralRepo(gh(z.w), { owner: 'o', repo: 'pipelines' }, z.rec, { askName: ask({ 4: 'x' }) });
    expect(no.deleted).toBe(false);
    expect(z.w.deleted).toEqual([]);
    const a = ask();
    const ok = await deleteCentralRepo(gh(z.w), { owner: 'o', repo: 'pipelines' }, z.rec, { askName: a });
    expect(ok.deleted).toBe(true);
    expect(a.asked.findIndex((q) => q.startsWith('4|'))).toBeLessThan(a.asked.findIndex((q) => q.startsWith('pipelines|')));
  });
});
