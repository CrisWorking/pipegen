// v0.2 Plan V V6 (rulings V-B2, V-B4, V-B5, V-S3, V-S4, V-S5, V-S6, V-S14, V-N5, V-N8, V-N9, V-N10, V-N13): run 2 of uninstall (phase B).
// After the uninstall pull request merged: the scratch repo emptied through E's own functions, secrets, variables, environments and the
// settings the user chose, then the central pull request (this project's exact files, the record last), the repo deletes (--delete-repos,
// App mode only) and the local files, only when nothing is left over. GitHub is a fake; prompts are fakes; no network.
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { localFinishPendingPath, localRecordPath, recordPath } from '../src/deliver/record.js';
import type { InstallRecord } from '../src/types.js';
import { uninstallStep, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
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
    const r = await run(w, rec);
    expect(r.phase).toBe('B');
    expect(r.status).toBe('b-waiting');   // the central pull request is open: merge it, then run again
    // every secret is deleted before any environment
    const routes = w.g.routes();
    const lastSecret = Math.max(...routes.map((x, i) => (/^DELETE .*\/secrets\/\{secret_name\}$/.test(x) ? i : -1)));
    const firstEnv = routes.findIndex((x) => x === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}');
    expect(lastSecret).toBeGreaterThan(-1);
    expect(firstEnv).toBeGreaterThan(lastSecret);
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

    // the source scan: E's scratch writers are called only from apply.ts (the phase-bound api), never from another file
    const dir = join(import.meta.dirname, '..', 'src', 'uninstall');
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts') && x !== 'apply.ts')) {
      const code = readFileSync(join(dir, f), 'utf8').replace(/\/\/.*$/gm, '');
      expect(code, f).not.toMatch(/\b(?:cleanupWrite|deleteScratchSecret|deleteScratchRepo|cleanupLeftovers|guardedWrite)\s*\(/);
    }
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
    const failing = async (yes: boolean) => {
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
  it('apply: new UninstallApi only in plan.ts; planUninstall, confirmPlan, takeApi and deleteCentralRepo are called only in apply.ts', () => {
    const dir = join(import.meta.dirname, '..', 'src', 'uninstall');
    const strip = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '').replace(/'(?:[^'\\\n]|\\.)*'/g, "''").replace(/`(?:[^`\\]|\\.)*`/g, '``');
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts'))) {
      const code = strip(readFileSync(join(dir, f), 'utf8'));
      if (f !== 'plan.ts' && f !== 'target.ts') expect(code, f).not.toMatch(/\bnew\s+UninstallApi\s*\(/);
      if (f !== 'apply.ts') {
        // a definition is not a call: `function x(` and `export async function x(` are taken out first
        const calls = code.replace(/\bfunction\s+(?:planUninstall|confirmPlan|takeApi|deleteCentralRepo)\s*\(/g, '');
        expect(calls, f).not.toMatch(/\b(?:planUninstall|confirmPlan|takeApi|deleteCentralRepo)\s*\(/);
      }
    }
    // the scan sees the forms it is for
    expect(strip('const a = new UninstallApi(gh, app);')).toMatch(/\bnew\s+UninstallApi\s*\(/);
    expect(strip('// new UninstallApi(gh)\nconst s = \'new UninstallApi(\';')).not.toMatch(/\bnew\s+UninstallApi\s*\(/);
  });
});
