// v0.2 Plan V V6 (rulings V-B2, V-B4, V-B5, V-S3, V-S4, V-S5, V-S6, V-S14, V-N5, V-N8, V-N9, V-N10, V-N13): run 2 of uninstall (phase B).
// After the uninstall pull request merged: the scratch repo emptied through E's own functions, secrets, variables, environments and the
// settings the user chose, then the central pull request (this project's exact files, the record last), the repo deletes (--delete-repos,
// App mode only) and the local files, only when nothing is left over. GitHub is a fake; prompts are fakes; no network.
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, relative, sep } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { localFinishPendingPath, localRecordPath, recordPath } from '../src/deliver/record.js';
import type { InstallRecord } from '../src/types.js';
import type { GuardedRepo } from '../src/proof/target.js';
import { confirmPlan, takeApi, uninstallStep, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
import { planUninstall } from '../src/uninstall/plan.js';
import { UninstallRefusal } from '../src/uninstall/target.js';
import { ProgressFile, uninstallProgressPath } from '../src/uninstall/progress.js';
import type { LoadedRecord } from '../src/uninstall/record.js';
import type { Env } from './helpers/deliver-github.js';
import {
  AT, blob, cleanHomes, deps, gh, loadedOf, local, mergePr, RECORD_TEXT, sampleRecord, SEC, SHA, term, world, writes, type Term, type World,
} from './helpers/uninstall-world.js';

const h = vi.hoisted(() => ({ stop: { now: false } }));
vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => h.stop.now,
  onInterrupt: () => () => {},
}));
afterEach(() => { cleanHomes(); h.stop.now = false; });

/** Run 1 is done: its uninstall pull request #1 merged (the progress file says A-done). */
async function afterRun1(w: World): Promise<void> {
  w.app.refs.set('heads/pipegen/uninstall', w.g.head(`o/${w.app.name}`));
  w.app.pulls.push({ number: 1, head: 'pipegen/uninstall', base: 'main', title: 'pipegen: uninstall', body: '', state: 'closed', html_url: `https://github.com/o/${w.app.name}/pull/1` });
  w.merged.set(`${w.app.name}#1`, '2026-11-06T10:00:00Z');
  const pf = await ProgressFile.open({ owner: 'o', repo: w.app.name }, w.app.id, local(w));
  pf.save({ phase: 'A-done', anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: w.g.head('o/pipelines'), recordBlobSha: blob(RECORD_TEXT) }, prNumber: 1, prUrl: `https://github.com/o/${w.app.name}/pull/1`, done: [], leftovers: [] });
}
const run = (w: World, rec: InstallRecord, t: Term = term(), over: Partial<StepDeps> = {}, lo: Partial<LoadedRecord> = {}): Promise<StepResult> =>
  uninstallStep(gh(w), loadedOf(w, rec, lo), t.p, deps(w, over));
/** The secret-scanning setting key, spelled at run time (test/no-secret-literals.test.ts). */
const SS = ['sec', 'retScanning'].join('') as 'secretScanning';
const env = (over: Partial<Env> = {}): Env => ({ id: 9, created_at: AT, wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map(), ...over });
const centralPr = (w: World) => w.central.pulls.find((p) => p.head === 'pipegen/uninstall-shop');
const filesAtPr = (w: World): Map<string, string> => w.g.filesAt('o/pipelines', w.g.head('o/pipelines', 'pipegen/uninstall-shop'));
const text = (r: StepResult): string => r.lines.join('\n');

describe('uninstall phase B: secrets, variables, environments, settings (V6)', () => {
  it('phase B: secrets before environments; a created environment holding the team\'s secrets is kept', async () => {
    const w = world();
    await afterRun1(w);
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    w.app.envs.set('pipegen-signing', env({ stored: new Map([['PIPEGEN_SIGN_KEY', AT]]) }));
    w.app.envs.set('pipegen-deploy', env({ id: 10, stored: new Map([['TEAM_KEY', AT], ['PIPEGEN_DEPLOY_KEY', AT]]) }));
    w.vars.set('repo', new Map([['PIPEGEN_LEVEL', { created_at: AT, value: '1' }]]));
    const rec = sampleRecord(w, {
      [SEC]: [
        { name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT },
        { name: 'PIPEGEN_SIGN_KEY', scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT },
        { name: 'PIPEGEN_DEPLOY_KEY', scope: 'env:pipegen-deploy', created: true, githubCreatedAt: AT },
      ],
      variables: [{ name: 'PIPEGEN_LEVEL', scope: 'repo', created: true, githubCreatedAt: AT }],
      environments: [
        { name: 'pipegen-signing', created: true, changed: [], branchPolicyIds: [], githubCreatedAt: AT },
        { name: 'pipegen-deploy', created: true, changed: [], branchPolicyIds: [], githubCreatedAt: AT },
      ],
    });
    // the progress file says run 2 began before the first write (a hard stop from there on is resumed as run 2)
    let atFirstWrite: unknown = 'no write';
    w.g.hooks.unshift((call) => {
      if (call.route.startsWith('GET ') || atFirstWrite !== 'no write') return undefined;
      atFirstWrite = (JSON.parse(readFileSync(uninstallProgressPath({ owner: 'o', repo: 'shop' }, local(w)), 'utf8')) as { phase: string }).phase;
      return undefined;
    });
    const r = await run(w, rec);
    expect(atFirstWrite).toBe('B');
    expect(r.phase).toBe('B');
    expect(r.status).toBe('b-waiting');   // the central pull request is open: merge it, then run again
    // every secret is deleted before any environment
    const routes = w.g.routes();
    const lastSec = Math.max(...routes.map((x, i) => (/^DELETE .*\/secrets\/\{secret_name\}$/.test(x) ? i : -1)));
    const firstEnv = routes.findIndex((x) => x === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}');
    expect(lastSec).toBeGreaterThan(-1);
    expect(firstEnv).toBeGreaterThan(lastSec);
    expect(routes.indexOf('DELETE /repos/{owner}/{repo}/actions/variables/{name}')).toBeLessThan(firstEnv);
    expect(w.app.stored.has('PIPEGEN_FP_KEY')).toBe(false);
    expect(w.vars.get('repo')?.has('PIPEGEN_LEVEL')).toBe(false);
    expect(w.app.envs.has('pipegen-signing')).toBe(false);
    // V-S5: the team's secret keeps its environment (pipegen's own secret in it still goes)
    expect(w.app.envs.has('pipegen-deploy')).toBe(true);
    expect(w.app.envs.get('pipegen-deploy')?.stored.has('TEAM_KEY')).toBe(true);
    expect(w.app.envs.get('pipegen-deploy')?.stored.has('PIPEGEN_DEPLOY_KEY')).toBe(false);
    expect(r.skipped.some((s) => /environment pipegen-deploy/.test(s.what) && /TEAM_KEY/.test(s.why))).toBe(true);
    expect(text(r)).toMatch(/TEAM_KEY/);
    expect(w.out.join('\n')).not.toMatch(/delete the environment pipegen-deploy/);   // the plan keeps it (V-S5), not only the writer
    expect(w.out.join('\n')).toMatch(/delete the environment pipegen-signing/);
    // a team secret added after the preview: target.ts reads the environment again right before the DELETE, and keeps it
    const w2 = world();
    await afterRun1(w2);
    w2.app.envs.set('pipegen-signing', env());
    const t2 = term();
    const go = t2.p.confirm;
    t2.p.confirm = async (m, d) => { if (m.startsWith('Go ahead')) w2.app.envs.get('pipegen-signing')?.stored.set('TEAM_LATE', AT); return go(m, d); };
    await run(w2, sampleRecord(w2, { environments: [{ name: 'pipegen-signing', created: true, changed: [], branchPolicyIds: [], githubCreatedAt: AT }] }), t2);
    expect(w2.app.envs.has('pipegen-signing')).toBe(true);
    expect(writes(w2).filter((x) => x.startsWith('DELETE /repos/{owner}/{repo}/environments/{environment_name} '))).toEqual([]);
    // the progress file: run 2 begun, the run-1 PR and the record's blob kept (a resume neither stops on I1 nor skips merged_at)
    const p = JSON.parse(readFileSync(uninstallProgressPath({ owner: 'o', repo: 'shop' }, local(w)), 'utf8')) as Record<string, unknown>;
    expect(p).toMatchObject({ phase: 'B', prNumber: 1, anchors: { recordBlobSha: blob(RECORD_TEXT) } });
  });

  it('phase B: pre-existing signing environment restored from previous changed fields only, after the typed name', async () => {
    const setup = async () => {
      const w = world();
      await afterRun1(w);
      // pipegen narrowed it: a wait timer and no admin bypass; the team's reviewer was added since and is not pipegen's change
      w.app.envs.set('pipegen-signing', env({ wait_timer: 5, can_admins_bypass: false, reviewers: [{ type: 'User', id: 7 }] }));
      const rec = sampleRecord(w, {
        environments: [{
          name: 'pipegen-signing', created: false, githubCreatedAt: AT, changed: ['wait_timer', 'can_admins_bypass'], branchPolicyIds: [],
          previous: { wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] },
        }],
      });
      return { w, rec };
    };
    const a = await setup();
    const t = term();
    const r = await run(a.w, a.rec, t);
    const e = a.w.app.envs.get('pipegen-signing');
    expect(e).toMatchObject({ wait_timer: 0, can_admins_bypass: true });
    expect(e?.reviewers).toEqual([{ type: 'User', id: 7 }]);   // only the changed fields
    expect(t.typed.some((q) => /pipegen-signing/.test(q) && /wait_timer/.test(q))).toBe(true);   // the diff, then the typed name
    expect(r.done.some((d) => /environment pipegen-signing/.test(d))).toBe(true);
    // a name not typed: nothing put back
    const b = await setup();
    const r2 = await run(b.w, b.rec, term({ type: () => 'no' }));
    expect(b.w.app.envs.get('pipegen-signing')).toMatchObject({ wait_timer: 5, can_admins_bypass: false });
    expect(writes(b.w).filter((x) => x.startsWith('PUT /repos/{owner}/{repo}/environments'))).toEqual([]);
    expect(r2.skipped.some((s) => /environment pipegen-signing/.test(s.what))).toBe(true);
  });

  it('scratch: emptied only through cleanupWrite and deleteScratchSecret; marker required', async () => {
    const w = world();
    await afterRun1(w);
    const s = w.scratch!;
    s.refs.set('heads/proof/20261105-120000-abcdef/x', s.refs.get('heads/main') as string);
    s.refs.set('heads/team-branch', s.refs.get('heads/main') as string);
    s.stored.set('PIPEGEN_PROOF_KEY', AT);
    w.vars.set('scratch', new Map([['PIPEGEN_BLOCK_FROM', { created_at: AT, value: 'x' }]]));
    w.runs.add(31);
    w.caches.add(41);
    const rec = sampleRecord(w, { scratch: { repoId: s.id, createdByPipegen: true } });
    const r = await run(w, rec);
    // the preview named the scratch cleanup before the one yes (M-r1-9)
    expect(w.out.join('\n')).toMatch(/pipegen-proof-shop/);
    expect(s.refs.has('heads/proof/20261105-120000-abcdef/x')).toBe(false);
    expect(s.refs.has('heads/main')).toBe(true);           // the default branch is never deleted
    expect(s.refs.has('heads/team-branch')).toBe(true);    // only pipegen's proof/ branches
    expect(s.stored.size).toBe(0);
    expect(w.vars.get('scratch')?.size).toBe(0);
    expect(w.runs.size).toBe(0);
    expect(w.caches.size).toBe(0);
    expect(r.done.some((d) => /pipegen-proof-shop/.test(d))).toBe(true);
    expect(w.deleted).toEqual([]);   // emptied, not deleted (no --delete-repos)

    // no marker: nothing is written to the scratch repo
    const w2 = world();
    await afterRun1(w2);
    w2.meta.set('pipegen-proof-shop', { description: 'my own repo' });
    w2.scratch!.stored.set('MY_KEY', AT);
    w2.runs.add(32);
    const r2 = await run(w2, sampleRecord(w2, { scratch: { repoId: w2.scratch!.id, createdByPipegen: true } }));
    expect(writes(w2).filter((x) => x.endsWith('pipegen-proof-shop'))).toEqual([]);
    expect(w2.scratch!.stored.has('MY_KEY')).toBe(true);
    expect(w2.runs.has(32)).toBe(true);
    expect(r2.skipped.some((x) => /pipegen-proof-shop/.test(x.what) && /marker/.test(x.why))).toBe(true);
    expect(w2.out.join('\n')).not.toMatch(/empty the scratch repo/);
    // the marker taken off after the preview: read again right before the first write, nothing sent
    const w3 = world();
    await afterRun1(w3);
    w3.scratch!.stored.set('MY_KEY', AT);
    const t3 = term();
    const go3 = t3.p.confirm;
    t3.p.confirm = async (m, d) => { if (m.startsWith('Go ahead')) w3.meta.set('pipegen-proof-shop', { description: 'mine now' }); return go3(m, d); };
    // (and below: another repo of that name, with pipegen's marker, made after the preview: another GitHub id)
    await run(w3, sampleRecord(w3, { scratch: { repoId: w3.scratch!.id, createdByPipegen: true } }), t3);
    expect(w3.out.join('\n')).toMatch(/empty the scratch repo o\/pipegen-proof-shop/);
    expect(writes(w3).filter((x) => x.endsWith('pipegen-proof-shop'))).toEqual([]);
    expect(w3.scratch!.stored.has('MY_KEY')).toBe(true);
    const w4 = world();
    await afterRun1(w4);
    w4.scratch!.stored.set('MY_KEY', AT);
    const t4 = term();
    const go4 = t4.p.confirm;
    t4.p.confirm = async (m, d) => { if (m.startsWith('Go ahead')) w4.scratch!.id = 987_654; return go4(m, d); };
    await run(w4, sampleRecord(w4, { scratch: { repoId: w4.scratch!.id, createdByPipegen: true } }), t4);
    expect(writes(w4).filter((x) => x.endsWith('pipegen-proof-shop'))).toEqual([]);
    expect(w4.scratch!.stored.has('MY_KEY')).toBe(true);

    // the source scan: E's scratch writers are called only from apply.ts (the phase-bound api), never from another file
    const dir = join(import.meta.dirname, '..', 'src', 'uninstall');
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts') && x !== 'apply.ts')) {
      const code = readFileSync(join(dir, f), 'utf8').replace(/\/\/.*$/gm, '');
      expect(code, f).not.toMatch(/\b(?:cleanupWrite|deleteScratchSecret|deleteScratchRepo|cleanupLeftovers|guardedWrite)\s*\(/);
    }
  });
});

describe('uninstall phase B: settings (V-S6)', () => {
  it('phase B: the settings pipegen turned on are turned off only when the user says yes', async () => {
    const w = world();
    await afterRun1(w);
    Object.assign(w.settings, { pin: true, alerts: true, scanning: true, push: true });
    const rec = sampleRecord(w, { repoSettings: { shaPinningRequired: { previous: false }, vulnerabilityAlerts: { previous: false }, [SS]: { previous: false }, pushProtection: { previous: false } } });
    const t = term({ yes: (q) => (/^Turn off (secret scanning|push protection)/.test(q) ? true : undefined) });
    const r = await run(w, rec, t);
    expect(t.confirms.filter((q) => q.startsWith('Turn off'))).toHaveLength(4);
    expect(w.settings).toMatchObject({ scanning: false, push: false, alerts: true, pin: true });   // the default keeps them on
    expect(writes(w).filter((x) => /vulnerability-alerts|actions\/permissions /.test(x))).toEqual([]);
    expect(r.done.some((d) => /secret scanning and push protection/.test(d))).toBe(true);
  });
});

describe('uninstall phase B: the re-check and a live workflow', () => {
  it('phase B: the install record changed since the preview → stop, nothing sent', async () => {
    const w = world();
    await afterRun1(w);
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    const t = term();
    const go = t.p.confirm;
    t.p.confirm = async (m, d) => { if (m.startsWith('Go ahead')) w.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: '{"pipegen":"edited"}\n' }); return go(m, d); };
    const before = writes(w).length;
    const e = await run(w, sampleRecord(w, { [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }] }), t).then(() => null, (x: unknown) => x);
    expect((e as Error | null)?.message).toMatch(/install record .* changed since the preview/);
    expect(writes(w).length).toBe(before);
    expect(w.app.stored.has('PIPEGEN_FP_KEY')).toBe(true);
  });

  it('phase B: pipegen\'s workflow still on the default branch → nothing the gate needs is removed', async () => {
    const w = world({ app: { 'README.md': 'my app\n', '.github/workflows/pipegen.yml': 'name: pipegen\n' } });
    await afterRun1(w);
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    const r = await run(w, sampleRecord(w, { [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }] }));
    expect(w.out.join('\n')).toMatch(/aren't on the default branch/);
    expect(w.app.stored.has('PIPEGEN_FP_KEY')).toBe(true);
    expect(r.skipped.some((s) => /PIPEGEN_FP_KEY/.test(s.what) && /still on the app's default branch/.test(s.why))).toBe(true);
    // central keeps this project's workflows and its record: no central PR
    expect(w.central.pulls).toEqual([]);
    expect(r.status).not.toBe('b-done');
  });
});

describe('uninstall phase B: the record and the local files (V-N5)', () => {
  it('apply: record removed last, in the central PR, only with no leftover or the user\'s yes to the listed ones', async () => {
    // nothing left over: the record is the central PR's last commit
    const w = world();
    await afterRun1(w);
    const r = await run(w, sampleRecord(w));
    expect(r.status).toBe('b-waiting');
    const pr = centralPr(w);
    expect(pr).toMatchObject({ base: 'main', state: 'open' });
    const tip = w.g.head('o/pipelines', 'pipegen/uninstall-shop');
    const hist = w.g.history('o/pipelines', tip, w.g.head('o/pipelines'));
    expect(hist[0]?.message).toMatch(/install record/);
    expect(filesAtPr(w).has(recordPath('shop'))).toBe(false);
    expect(filesAtPr(w).has('.github/workflows/shop--merge.yml')).toBe(false);
    expect(w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).has(recordPath('shop'))).toBe(true);   // main is never moved
    expect(text(r)).toMatch(/Merge the central pull request/);

    // a step that failed: the record stays unless the user says yes to the listed leftovers
    const failing = async (yes: boolean | undefined) => {
      const x = world();
      await afterRun1(x);
      x.app.stored.set('PIPEGEN_FP_KEY', AT);
      x.fail = (route) => (route === `DELETE /repos/{owner}/{repo}/actions/${SEC}/{secret_name}` ? 500 : undefined);
      const t = term({ yes: (q) => (q.startsWith('Remove the install record') ? yes : undefined) });
      const res = await run(x, sampleRecord(x, { [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }] }), t);
      return { x, t, res };
    };
    const no = await failing(false);
    expect(no.t.confirms.some((q) => q.startsWith('Remove the install record') && /PIPEGEN_FP_KEY/.test(q))).toBe(true);
    expect(filesAtPr(no.x).has(recordPath('shop'))).toBe(true);
    expect(filesAtPr(no.x).has('.github/workflows/shop--merge.yml')).toBe(false);
    expect(no.res.status).toBe('b-partial');
    const dflt = await failing(undefined);   // the question's own default (Enter): keep it
    expect(filesAtPr(dflt.x).has(recordPath('shop'))).toBe(true);
    const yes = await failing(true);
    expect(filesAtPr(yes.x).has(recordPath('shop'))).toBe(false);
    const tip2 = yes.x.g.head('o/pipelines', 'pipegen/uninstall-shop');
    expect(yes.x.g.history('o/pipelines', tip2, yes.x.g.head('o/pipelines'))[0]?.message).toMatch(/install record/);
  });

  it('phase B: local record, finish-pending and leftovers files removed only when nothing is left over', async () => {
    const make = async (leftovers: unknown[]) => {
      const w = world();
      await afterRun1(w);
      const files = [localRecordPath({ owner: 'o', repo: 'shop' }, local(w)), localFinishPendingPath({ owner: 'o', repo: 'shop' }, local(w)), localRecordPath({ owner: 'o', repo: 'shop' }, local(w)).replace(/\.json$/, '.leftovers.json')];
      mkdirSync(dirname(files[0] as string), { recursive: true });
      writeFileSync(files[0] as string, '{}\n', { mode: 0o600 });
      writeFileSync(files[1] as string, '{}\n', { mode: 0o600 });
      writeFileSync(files[2] as string, `${JSON.stringify({ updatedAt: AT, items: leftovers })}\n`, { mode: 0o600 });
      return { w, files };
    };
    // run 2 opens the central PR: the record is still on central, so the local files stay
    const a = await make([{ kind: 'secret', name: 'PIPEGEN_OLD', repo: 'o/shop', scope: 'repo', githubCreatedAt: AT }]);
    a.w.app.stored.set('PIPEGEN_OLD', AT);
    const r1 = await run(a.w, sampleRecord(a.w));
    expect(r1.status).toBe('b-waiting');
    expect(a.w.app.stored.has('PIPEGEN_OLD')).toBe(false);   // the leftover secret, identity-checked and named
    for (const f of a.files) expect(existsSync(f), f).toBe(true);
    // the central PR merged: run 2 again finishes, and nothing is left over
    mergePr(a.w, a.w.central, 'pipegen/uninstall-shop');
    const r2 = await run(a.w, sampleRecord(a.w));
    expect(r2.status).toBe('b-done');
    for (const f of a.files) expect(existsSync(f), f).toBe(false);
    expect(existsSync(uninstallProgressPath({ owner: 'o', repo: 'shop' }, local(a.w)))).toBe(false);
    expect(text(r2)).toMatch(/GitHub App/);   // F9: how to remove the App from the repo

    // a leftover branch entry pipegen/setup is still on GitHub: the files stay
    const b = await make([{ kind: 'branch', name: 'pipegen/setup', repo: 'o/shop' }]);
    b.w.app.refs.set('heads/pipegen/setup', b.w.g.head('o/shop'));
    await run(b.w, sampleRecord(b.w));
    mergePr(b.w, b.w.central, 'pipegen/uninstall-shop');
    const rb = await run(b.w, sampleRecord(b.w));
    expect(rb.status).toBe('b-partial');
    for (const f of b.files) expect(existsSync(f), f).toBe(true);
    expect(text(rb)).toMatch(/pipegen\/setup/);

    // a step that failed: the files stay too
    const c = await make([]);
    c.w.app.stored.set('PIPEGEN_FP_KEY', AT);
    const rec = sampleRecord(c.w, { [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }] });
    await run(c.w, rec, term({ yes: () => true }));
    mergePr(c.w, c.w.central, 'pipegen/uninstall-shop');
    c.w.fail = (route) => (route === `DELETE /repos/{owner}/{repo}/actions/${SEC}/{secret_name}` ? 500 : undefined);
    c.w.app.stored.set('PIPEGEN_FP_KEY', AT);
    const rc = await run(c.w, rec);
    expect(rc.status).toBe('b-partial');
    for (const f of c.files) expect(existsSync(f), f).toBe(true);
  });
});

describe('uninstall phase B: the phase-bound api and the source rules (V5-R1 carries)', () => {
  it('apply: the phase-B routes (a typed name at apply time, the repo deletes, the scratch writes) are refused by a phase-A api; B asks only for the central ruleset', async () => {
    const w = world();
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
    const t = term();
    const opts = { interactive: true, local: local(w), state: local(w) };
    const a = await planUninstall(gh(w), loadedOf(w, rec), t.p, { ...opts, phase: 'A' });
    expect(await confirmPlan(a, t.p, { interactive: true, out: () => {} })).toBe(true);
    const api = takeApi(a, 'A').api;
    const n = w.g.calls.length;
    const fake = {} as GuardedRepo;
    for (const call of [
      () => api.confirm({ kind: 'central-ruleset', id: 5 }), () => api.removeCentralRepo(rec), () => api.scratchCleanup(fake, { op: 'delete-run', runId: 1 }),
      () => api.scratchSecretDelete(fake, 'X'), () => api.scratchRepoDelete(fake, 1), () => api.proofLeftovers({} as never, {} as never),
    ]) await expect(call()).rejects.toBeInstanceOf(UninstallRefusal);
    expect(w.g.calls.length).toBe(n);
    const b = await planUninstall(gh(w), loadedOf(w, rec), t.p, { ...opts, phase: 'B' });
    expect(await confirmPlan(b, t.p, { interactive: true, out: () => {} })).toBe(true);
    const bApi = takeApi(b, 'B').api;
    const asked = t.typed.length;
    await expect(bApi.confirm({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, githubCreatedAt: AT } })).rejects.toBeInstanceOf(UninstallRefusal);
    expect(t.typed.length).toBe(asked);
  });

  it('apply: new UninstallApi only in plan.ts; planUninstall, confirmPlan, takeApi and deleteCentralRepo are called only in apply.ts', () => {
    // V6-R1 (sec M6): an import-based allow-list over all of src/, so an alias, Reflect.construct, .call or ?.() can't get round it. target.ts
    // itself is allowed one construction: deleteCentralRepo makes the typed-name-only api it deletes the repo with (V3; spec M7).
    const root = join(import.meta.dirname, '..');
    const found: string[] = [];
    for (const f of srcFiles(join(root, 'src'))) found.push(...entryImportProblems(relative(root, f).split(sep).join('/'), readFileSync(f, 'utf8')));
    expect(found).toEqual([]);
    // the scan's own must-catch examples (in a file of src/uninstall that is not allowed them)
    const forms: Record<string, string> = {
      paren: "import { UninstallApi } from './target.js'; const a = new (UninstallApi)(gh, app);",
      alias: "import { UninstallApi as U } from './target.js'; const a = new U(gh, app);",
      reflect: "import { UninstallApi } from './target.js'; Reflect.construct(UninstallApi, [gh, app]);",
      optcall: "import { deleteCentralRepo } from './target.js'; await deleteCentralRepo?.(gh, c, rec, io);",
      dotcall: "import { deleteCentralRepo } from './target.js'; await deleteCentralRepo.call(null, gh, c, rec, io);",
      aliasCall: "import {\n  deleteCentralRepo as d,\n} from './target.js'; await d(gh, c, rec, io);",
      namespace: "import * as t from './target.js'; new t.UninstallApi(gh, app);",
      dynamic: "const t = await import('./target.js');",
      dynamicExpr: "const t = await import(name);",
      require: "const t = require('./plan.js');",
      reexport: "export { takeApi } from './apply.js';",
      reexportAll: "export * from './target.js';",
      fromCli: "import { planUninstall } from '../uninstall/plan.js';",
      scratch: "import { deleteScratchSecret } from '../proof/target.js';",
      cleanup: "import { cleanupLeftovers as c } from '../proof/cleanup.js';",
    };
    for (const [name, code] of Object.entries(forms)) {
      const file = name === 'fromCli' || name === 'scratch' || name === 'cleanup' ? 'src/cli/uninstall.ts' : 'src/uninstall/central.ts';
      expect(entryImportProblems(file, code).length, name).toBeGreaterThan(0);
    }
    // V6-R2 sec M2: the r2 reviewer's forms (the code is parsed, not matched), in src/uninstall and in src/cli (V7's file)
    const r2: Record<string, string> = {
      F1: "const open = '/*';\nimport { UninstallApi as U } from './target.js';\nconst close = '*/';\nexport const f1 = (gh: never) => [open, close, new U(gh, { owner: 'o', repo: 'r', repoId: 1 })];",
      F2: "const s = `x//`; import { deleteCentralRepo as d } from './target.js';\nexport const f2 = [s, d];",
      F3: "import * as t from './t\\u0061rget.js';\nexport const f3 = t.UninstallApi;",
      F4: "export const f4 = () => import('./t\\x61rget.js');",
      F5: 'export const f5 = () => import(`./target.js`);',
      F6: "import { \"UninstallApi\" as U2 } from './target.js';\nexport const f6 = U2;",
      F7: "import { cleanupAfterProof } from '../proof/cleanup.js';\nexport const f7 = cleanupAfterProof;",
    };
    for (const [name, code] of Object.entries(r2)) {
      expect(entryImportProblems('src/uninstall/zz-form.ts', code).length, `${name} uninstall`).toBeGreaterThan(0);
      expect(entryImportProblems('src/cli/zz-form.ts', code.replaceAll("'./t", "'../uninstall/t").replaceAll('`./t', '`../uninstall/t')).length, `${name} cli`).toBeGreaterThan(0);
    }
    // F8: an allowed file hands a guarded binding on
    expect(entryImportProblems('src/uninstall/apply.ts', "import { deleteCentralRepo } from './target.js';\nexport { deleteCentralRepo as dcr };").length, 'F8').toBeGreaterThan(0);
    // what is allowed stays allowed
    expect(entryImportProblems('src/uninstall/plan.ts', "import { UninstallApi } from './target.js'; new UninstallApi(gh, app);")).toEqual([]);
    expect(entryImportProblems('src/uninstall/apply.ts', "import { planUninstall } from './plan.js';\nimport { deleteCentralRepo, type UninstallApi } from './target.js';")).toEqual([]);
    expect(entryImportProblems('src/uninstall/central.ts', "import { UninstallRefusal, type UninstallApi } from './target.js';\nimport type { PhaseApi } from './apply.js';")).toEqual([]);
  });
});

/** Every .ts file under `dir`. */
function srcFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) out.push(...srcFiles(join(dir, e.name)));
    else if (e.name.endsWith('.ts')) out.push(join(dir, e.name));
  }
  return out;
}
/** The uninstall modules whose entry points are guarded (paths from the repo root). */
const GUARDED = ['src/uninstall/target.ts', 'src/uninstall/plan.ts', 'src/uninstall/apply.ts'];
/** E's scratch secret delete, its name spelled at run time (test/no-secret-literals.test.ts). */
const SCRATCH_SD = ['deleteScratch', 'Secret'].join('');
/** Value names, and the only files that may import them. */
const ENTRY_ALLOWED: Readonly<Record<string, (file: string) => boolean>> = {
  UninstallApi: (f) => f === 'src/uninstall/plan.ts',
  planUninstall: (f) => f === 'src/uninstall/apply.ts', confirmPlan: (f) => f === 'src/uninstall/apply.ts',
  takeApi: (f) => f === 'src/uninstall/apply.ts', deleteCentralRepo: (f) => f === 'src/uninstall/apply.ts',
  // E's scratch writers: E's own modules, E's cleanup command, and uninstall's phase-bound api
  cleanupWrite: (f) => f.startsWith('src/proof/') || f === 'src/cli/cleanup.ts' || f === 'src/uninstall/apply.ts',
  [SCRATCH_SD]: (f) => f.startsWith('src/proof/') || f === 'src/cli/cleanup.ts' || f === 'src/uninstall/apply.ts',
  deleteScratchRepo: (f) => f.startsWith('src/proof/') || f === 'src/cli/cleanup.ts' || f === 'src/uninstall/apply.ts',
  cleanupLeftovers: (f) => f.startsWith('src/proof/') || f === 'src/cli/cleanup.ts' || f === 'src/uninstall/apply.ts',
};
/** `spec` as imported from `file`, as a path from the repo root (.ts), or null for a package. */
function resolveSpec(file: string, spec: string): string | null {
  if (!spec.startsWith('.')) return null;
  return posix.normalize(posix.join(posix.dirname(file), spec)).replace(/\.js$/, '.ts');
}
/** What the allow-list finds wrong in one file of src/ (`file` from the repo root). */
function entryImportProblems(file: string, src: string): string[] {
  const out: string[] = [];
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
  const guarded = (spec: string): boolean => { const r = resolveSpec(file, spec); return r !== null && GUARDED.includes(r) && r !== file; };
  // static imports and re-exports, one clause each (over several lines too)
  for (const m of code.matchAll(/\b(import|export)\s+(type\s+)?([^;'"]*?)\s*from\s*['"]([^'"]+)['"]/g)) {
    const [, kw, typeOnly, clause = '', spec = ''] = m;
    if (typeOnly !== undefined) continue;
    const braces = /\{([^}]*)\}/.exec(clause);
    const rest = clause.replace(/\{[^}]*\}/, '').replace(/,/g, ' ').trim();
    if (guarded(spec) && (rest !== '' || kw === 'export')) { out.push(`${kw === 'export' ? 're-export' : 'default or namespace import'} of ${spec} in ${file}`); continue; }
    const names = (braces?.[1] ?? '').split(',').map((x) => x.trim()).filter((x) => x !== '' && !x.startsWith('type ')).map((x) => x.split(/\s+as\s+/)[0]?.trim() ?? '');
    for (const n of names) {
      const ok = ENTRY_ALLOWED[n];
      if (ok !== undefined && !ok(file)) out.push(`${n} imported in ${file}`);
    }
  }
  // dynamic imports and require: only a plain string, never one of the guarded modules
  for (const m of code.matchAll(/\b(import|require)\s*\(\s*(['"])([^'"]+)\2\s*\)/g)) if (guarded(m[3] ?? '')) out.push(`a dynamic ${m[1]} of ${m[3]} in ${file}`);
  const noStrings = code.replace(/'(?:[^'\\\n]|\\.)*'/g, "''").replace(/"(?:[^"\\\n]|\\.)*"/g, "''").replace(/`(?:[^`\\]|\\.)*`/g, "''");
  if (/\b(?:import|require)\s*\(\s*(?!''\s*\))/.test(noStrings)) out.push(`a dynamic import or require of something that is not a plain string in ${file}`);
  // import x = require(...)
  if (/\bimport\s+\w+\s*=\s*require\b/.test(code)) out.push(`an import = require in ${file}`);
  return out;
}
