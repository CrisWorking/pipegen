// v0.2 Plan V V5 (rulings V-B2, V-B3, V-S9, V-S10, V-S11, V-S14, V-S16; V4-R1 and V4-R1b carries): run 1 of uninstall (phase A) sends the
// writes: the uninstall pull request on the preview's base commit, pipegen's open pull requests closed, then the merge locks. Nothing is
// sent before the one confirmation; the plan's own objects and tokens are used once, through an api bound to phase A; the progress file
// lets a stopped or failed run be resumed; the app's lease is held for the whole run. The dispatcher sends run 2 to phase B only after
// GitHub says the uninstall pull request merged (merged_at).
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PromptCancelledError, type Prompter } from '../src/cli/io.js';
import { gitBlobSha } from '../src/create/guard.js';
import { localRecordPath, recordPath } from '../src/deliver/record.js';
import { StateStore } from '../src/proof/state.js';
import type { InstallEdit, InstallRecord } from '../src/types.js';
import { applyPhaseA, confirmPlan, PhaseApi, uninstallStep, type PhaseBRunner, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
import { UninstallError } from '../src/uninstall/errors.js';
import { planUninstall, type UninstallPlan } from '../src/uninstall/plan.js';
import { ProgressFile, uninstallProgressPath } from '../src/uninstall/progress.js';
import type { LoadedRecord } from '../src/uninstall/record.js';
import { UninstallRefusal } from '../src/uninstall/target.js';
import { FakeGitHub, type Env, type Repo } from './helpers/deliver-github.js';

// the stop gate and the interrupt queue are the test's (a real signal would end the test process); target.ts reads the same gate
const h = vi.hoisted(() => ({
  stop: { now: false },
  fns: [] as ((ctx: { signal: AbortSignal; leftover: (s: string) => void }) => Promise<void>)[],
  plans: [] as unknown[],
}));
vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => h.stop.now,
  onInterrupt: (fn: (typeof h.fns)[number]) => {
    h.fns.push(fn);
    return () => { const i = h.fns.indexOf(fn); if (i >= 0) h.fns.splice(i, 1); };
  },
}));
// every plan the dispatcher makes, to check which phase it asked for and that a dropped plan is never applied
vi.mock('../src/uninstall/plan.js', async (orig) => {
  const real = await orig<typeof import('../src/uninstall/plan.js')>();
  return { ...real, planUninstall: async (...a: Parameters<typeof real.planUninstall>) => { const p = await real.planUninstall(...a); h.plans.push(p); return p; } };
});
const plans = (): UninstallPlan[] => h.plans as UninstallPlan[];

const SHA = (c: string): string => c.repeat(40).slice(0, 40);
/** The record's secrets field, spelled at run time (test/no-secret-literals.test.ts). */
const SEC = ['sec', 'rets'].join('') as 'secrets';
const AT = '2026-11-05T12:00:01Z';
const LATER = '2026-11-06T09:00:00Z';
const RECORD_TEXT = '{"pipegen":"record"}\n';
const FILES: Record<string, string> = {
  'README.md': 'my app\n',
  '.github/workflows/pipegen.yml': 'name: pipegen\n',
  'Dockerfile': 'FROM node:22\n',
  '.dockerignore': 'node_modules\n',
  'PIPEGEN.md': '# pipegen\n',
};
const PARTS: Record<string, InstallRecord['files'][number]['part']> = {
  '.github/workflows/pipegen.yml': 'pipeline', 'Dockerfile': 'docker', '.dockerignore': 'docker', 'PIPEGEN.md': 'docs',
};
const blob = (t: string): string => gitBlobSha(t);
const CLASSIC_ROUTE = 'PUT /repos/{owner}/{repo}/branches/{branch}/protection';
const PLANNED_BODY = { required_status_checks: { strict: true, checks: [{ context: 'pipegen / gate', app_id: 15368 }] }, enforce_admins: true, required_pull_request_reviews: null, restrictions: null };
const PLANNED = { method: 'PUT' as const, route: CLASSIC_ROUTE, params: { owner: 'o', repo: 'shop', branch: 'main' }, body: PLANNED_BODY };
/** GitHub's protection GET while it is exactly what pipegen set. */
const LIVE_PROTECTION = (): Record<string, unknown> => ({ required_status_checks: { strict: true, checks: [{ context: 'pipegen / gate', app_id: 15368 }], contexts: ['pipegen / gate'] }, enforce_admins: { enabled: true } });

interface World {
  g: FakeGitHub; app: Repo; central: Repo; home: string; out: string[];
  vars: Map<string, Map<string, { created_at: string; value: string }>>;
  protection: Record<string, unknown> | null; org: Map<number, Record<string, unknown>>;
  /** merged_at of app pull requests, by number. */
  merged: Map<number, string>;
  /** An HTTP status the fake answers instead (a fault the test injects). */
  fail?: (route: string, params: Record<string, unknown>) => number | undefined;
}
const homes: string[] = [];
afterEach(() => {
  for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true });
  h.plans.length = 0;
  h.stop.now = false;
  h.fns.length = 0;
});

function world(files: Record<string, string> = FILES): World {
  const g = new FakeGitHub();
  const app = g.addRepo('o/shop', { private: true, files });
  const central = g.addRepo('o/pipelines', { private: true, files: { [recordPath('shop')]: RECORD_TEXT, '.github/workflows/shop--merge.yml': 'on: workflow_call\n' } });
  const home = mkdtempSync(join(tmpdir(), 'pg-unapply-'));
  homes.push(home);
  const w: World = { g, app, central, home, out: [], vars: new Map(), protection: null, org: new Map(), merged: new Map() };
  g.hooks.push((call) => {
    const p = call.params as Record<string, string>;
    const f = w.fail?.(call.route, call.params);
    if (f !== undefined) return { status: f };
    const repoOf = (): Repo => g.repo(`${p.owner}/${p.repo}`);
    const envOf = (): Env | undefined => app.envs.get(p.environment_name as string);
    switch (call.route) {
      case 'GET /repos/{owner}/{repo}/actions/variables/{name}': {
        const v = w.vars.get('repo')?.get(p.name as string);
        return v === undefined ? { status: 404 } : { status: 200, data: { name: p.name, value: v.value, created_at: v.created_at } };
      }
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}': {
        const v = w.vars.get(`env:${p.environment_name}`)?.get(p.name as string);
        return v === undefined ? { status: 404 } : { status: 200, data: { name: p.name, value: v.value, created_at: v.created_at } };
      }
      case `GET /repos/{owner}/{repo}/environments/{environment_name}/${SEC}`: {
        const e = envOf();
        if (e === undefined) return { status: 404 };
        const list = [...e.stored].map(([name, at]) => ({ name, created_at: at }));
        return { status: 200, data: { total_count: list.length, [SEC]: list } };
      }
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables': {
        if (envOf() === undefined) return { status: 404 };
        const list = [...(w.vars.get(`env:${p.environment_name}`) ?? new Map())].map(([name, v]) => ({ name, value: v.value, created_at: v.created_at }));
        return { status: 200, data: { total_count: list.length, variables: list } };
      }
      case 'GET /repos/{owner}/{repo}/branches/{branch}/protection':
        return w.protection === null ? { status: 404 } : { status: 200, data: w.protection };
      case CLASSIC_ROUTE: {
        const { owner: _o, repo: _r, branch: _b, ...body } = call.params;
        w.protection = { ...body, enforce_admins: { enabled: body.enforce_admins === true } };
        return { status: 200, data: w.protection };
      }
      case 'DELETE /repos/{owner}/{repo}/branches/{branch}/protection':
        if (w.protection === null) return { status: 404 };
        w.protection = null;
        return { status: 204 };
      case 'GET /orgs/{org}/rulesets':
        return { status: 200, data: [...w.org.values()] };
      case 'GET /orgs/{org}/rulesets/{ruleset_id}': {
        const r = w.org.get(Number(p.ruleset_id));
        return r === undefined ? { status: 404 } : { status: 200, data: r };
      }
      case 'DELETE /orgs/{org}/rulesets/{ruleset_id}':
        return w.org.delete(Number(p.ruleset_id)) ? { status: 204 } : { status: 404 };
      case 'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}':
        return repoOf().rulesets.delete(Number(p.ruleset_id)) ? { status: 204 } : { status: 404 };
      case 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}': {
        if (call.params.state !== 'closed') return undefined;
        const pr = repoOf().pulls.find((x) => x.number === Number(p.pull_number));
        if (pr === undefined) return { status: 404 };
        pr.state = 'closed';
        return { status: 200, data: { number: pr.number, state: 'closed' } };
      }
      case 'DELETE /repos/{owner}/{repo}/git/refs/{ref}':
        return repoOf().refs.delete(p.ref as string) ? { status: 204 } : { status: 422 };
      default: return undefined;
    }
  });
  return w;
}
/** The Octokit stand-in, with GitHub's head.repo (id, full_name) and merged_at on pull requests (the fake leaves them out). */
function gh(w: World): Octokit {
  const withRepo = (owner: unknown, repo: unknown, p: unknown): unknown => {
    if (typeof p !== 'object' || p === null || typeof (p as { head?: unknown }).head !== 'object') return p;
    const r = w.g.repo(`${String(owner)}/${String(repo)}`);
    const n = (p as { number: number }).number;
    return { ...p, merged_at: r === w.app ? (w.merged.get(n) ?? null) : null, head: { ...(p as { head: object }).head, repo: { id: r.id, full_name: `${r.owner}/${r.name}` } } };
  };
  return { request: async (route: string, params: Record<string, unknown> = {}) => {
    const out = await w.g.request(route, params);
    if (route === 'GET /repos/{owner}/{repo}/pulls') {
      const per = Math.min(Number(params.per_page ?? 30), 100);
      const page = Number(params.page ?? 1);
      const all = Array.isArray(out.data) ? out.data : [];
      return { ...out, data: all.slice((page - 1) * per, page * per).map((p) => withRepo(params.owner, params.repo, p)) };
    }
    if (route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}') return { ...out, data: withRepo(params.owner, params.repo, out.data) };
    return out;
  } } as unknown as Octokit;
}
const rs = (over: Partial<InstallRecord['rulesets'][number]> = {}): InstallRecord['rulesets'][number] => ({ kind: 'gate', id: 41, name: 'pipegen', githubCreatedAt: AT, ...over });
const liveRs = (over: Record<string, unknown> = {}) => ({ name: 'pipegen', source_type: 'Repository', source: 'o/shop', created_at: AT, enforcement: 'active', ...over });
function sampleRecord(w: World, over: Partial<InstallRecord> = {}): InstallRecord {
  return {
    schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-05T12:00:00.000Z', mergedAt: '2026-11-05T13:00:00Z', centralSha: SHA('c'),
    app: { owner: 'o', repo: 'shop', repoId: w.app.id, defaultBranch: 'main', private: true, ownerType: 'User' },
    name: 'shop', serviceRoots: ['.'],
    files: [
      ...Object.entries(PARTS).map(([path, part]) => ({ repo: 'app' as const, path, part, shas: [blob(FILES[path] as string)] })),
      { repo: 'central' as const, path: '.github/workflows/shop--merge.yml', part: 'pipeline' as const, shas: [blob('on: workflow_call\n')] },
    ],
    edits: [],
    [SEC]: [],
    variables: [], environments: [], rulesets: [rs()],
    planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] },
    protectedPaths: ['.github/workflows/**'],
    ...over,
  };
}
/** V1's loaded record: the record file's real blob sha and the central head it was read at (V5 re-checks both). */
function loadedOf(w: World, record: InstallRecord, over: Partial<LoadedRecord> = {}): LoadedRecord {
  return {
    app: { owner: 'o', repo: 'shop', repoId: w.app.id, private: true, defaultBranch: w.app.defaultBranch, ownerType: 'User' },
    record, trust: 'full', typedNames: false, blobSha: blob(RECORD_TEXT), centralHead: w.g.head('o/pipelines'), centralRepoId: w.central.id,
    marker: 'match', setupPr: null, dropped: [], warnings: [], ...over,
  };
}
interface Term { p: Prompter; typed: string[]; confirms: string[] }
/** The user's terminal: types each name asked for; says yes to "Go ahead" (or what `go` says), answers the rest with their default. */
function term(o: { go?: (q: string) => boolean | Promise<boolean>; type?: (q: string, expected: string) => string } = {}): Term {
  const t: Term = { typed: [], confirms: [], p: undefined as unknown as Prompter };
  t.p = {
    confirm: async (m, d) => { t.confirms.push(m); return m.startsWith('Go ahead') ? (o.go === undefined ? true : o.go(m)) : d; },
    select: async () => { throw new Error('no select expected'); },
    text: async (m) => { t.typed.push(m); const exp = /\nType (.+) to go on;/.exec(m)?.[1] ?? ''; return o.type === undefined ? exp : o.type(m, exp); },
  };
  return t;
}
const local = (w: World) => ({ home: w.home, env: {} });
const deps = (w: World, over: Partial<StepDeps> = {}): StepDeps => ({ interactive: true, local: local(w), state: local(w), out: (s) => { w.out.push(s); }, ...over });
const run = (w: World, rec: InstallRecord, t: Term = term(), over: Partial<StepDeps> = {}, lo: Partial<LoadedRecord> = {}): Promise<StepResult> => uninstallStep(gh(w), loadedOf(w, rec, lo), t.p, deps(w, over));
const writes = (w: World): string[] => w.g.routes().filter((r) => !r.startsWith('GET '));
const writeCalls = (w: World) => w.g.calls.filter((c) => !c.route.startsWith('GET '));
const progressOf = (w: World): Record<string, unknown> => JSON.parse(readFileSync(uninstallProgressPath({ owner: 'o', repo: 'shop' }, local(w)), 'utf8')) as Record<string, unknown>;
const hasProgress = (w: World): boolean => existsSync(uninstallProgressPath({ owner: 'o', repo: 'shop' }, local(w)));
async function stops(p: Promise<unknown>, re: RegExp): Promise<Error> {
  const e = await p.then(() => null, (x: unknown) => x);
  expect(e).toBeInstanceOf(UninstallError);
  expect((e as Error).message).toMatch(re);
  return e as Error;
}
/** A phase-B runner stand-in (V6 builds the real one): records the plan and the api it was given. */
function phaseB(): { fn: PhaseBRunner; got: { plan: UninstallPlan; api: PhaseApi }[] } {
  const got: { plan: UninstallPlan; api: PhaseApi }[] = [];
  return { got, fn: async (_gh, plan, api) => { got.push({ plan, api }); return { status: 'b-done', phase: 'B', done: [], failed: [], skipped: [], manual: [], lines: ['phase B ran'] }; } };
}
const orgEntry = { org: 'o', id: 77, name: 'pipegen-required--shop', githubCreatedAt: AT, pinnedSha: SHA('c') };
const liveOrg = (w: World) => ({ id: 77, name: 'pipegen-required--shop', source_type: 'Organization', source: 'o', created_at: AT,
  conditions: { repository_id: { repository_ids: [w.app.id] }, ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } },
  rules: [{ type: 'workflows', parameters: { workflows: [{ path: '.github/workflows/shop--required.yml', sha: SHA('c'), repository_id: w.central.id }] } }] });
/** A world whose app holds pipegen's locks: ruleset 41, the org rule 77 and classic protection (none before pipegen unless `previous`). */
function locked(w: World, previous: Record<string, unknown> | null = null): Partial<InstallRecord> {
  w.app.rulesets.set(41, liveRs());
  w.org.set(77, liveOrg(w));
  w.protection = LIVE_PROTECTION();
  return { orgRuleset: orgEntry, central: { repoId: w.central.id, createdByPipegen: true }, classicProtection: { branch: 'main', previous }, planned: { ...sampleRecord(w).planned, classic: PLANNED } };
}

describe('uninstall apply, phase A (V5)', () => {
  it('apply: phase A opens the uninstall PR, then removes merge locks; secrets, environments and variables untouched', async () => {
    // pipegen's edits: CODEOWNERS unchanged since (restored), .github/CODEOWNERS with the owner's line after (stripped), docs/CODEOWNERS made by pipegen (deleted)
    const ins = '# pipegen:begin\n/.github/ @o\n# pipegen:end\n';
    const orig = '* @team\n';
    const orig2 = 'src/ @dev\n';
    const w = world({ ...FILES, CODEOWNERS: orig, '.github/CODEOWNERS': orig2 });
    w.g.commitOn('o/shop', 'main', { CODEOWNERS: orig + ins, '.github/CODEOWNERS': `${orig2}${ins}z/ @y\n`, 'docs/CODEOWNERS': ins });
    const edits: InstallEdit[] = [
      { repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: ins, originalSha: blob(orig), writtenShas: [blob(orig + ins)] },
      { repo: 'app', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: ins, originalSha: blob(orig2), writtenShas: [blob(orig2 + ins)] },
      { repo: 'app', path: 'docs/CODEOWNERS', kind: 'codeowners', inserted: ins, originalSha: null, writtenShas: [blob(ins)] },
    ];
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    const e: Env = { id: 9, created_at: AT, wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() };
    w.app.envs.set('pipegen-signing', e);
    w.vars.set('repo', new Map([['PIPEGEN_LEVEL', { created_at: AT, value: '1' }]]));
    const rec = sampleRecord(w, {
      ...locked(w), edits,
      [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }],
      variables: [{ name: 'PIPEGEN_LEVEL', scope: 'repo', created: true, githubCreatedAt: AT }],
      environments: [{ name: 'pipegen-signing', created: true, changed: [], branchPolicyIds: [], githubCreatedAt: AT }],
    });
    const base = w.g.head('o/shop');
    const r = await run(w, rec);
    expect(r.status).toBe('a-done');
    expect(r.phase).toBe('A');
    expect(r.pr).toEqual({ number: 1, url: 'https://github.com/o/shop/pull/1' });
    // the PR: from pipegen/uninstall into main, one commit per removal kind and one per revert, on the preview's base
    const pr = w.app.pulls.find((p) => p.number === 1);
    expect(pr).toMatchObject({ head: 'pipegen/uninstall', base: 'main', state: 'open' });
    const tip = w.g.head('o/shop', 'pipegen/uninstall');
    const hist = w.g.history('o/shop', tip, base);
    expect(hist).toHaveLength(5);
    expect(hist[hist.length - 1]?.parents).toEqual([base]);
    expect(hist.map((c) => c.message).reverse()).toEqual([
      'pipegen uninstall: remove pipegen\'s workflows',
      'pipegen uninstall: remove the files pipegen created',
      'pipegen uninstall: put CODEOWNERS back to its version before pipegen',
      'pipegen uninstall: take pipegen\'s part out of .github/CODEOWNERS',
      'pipegen uninstall: remove docs/CODEOWNERS (pipegen made it)',
    ]);
    const files = w.g.filesAt('o/shop', tip);
    expect(files.has('.github/workflows/pipegen.yml')).toBe(false);
    expect(files.has('PIPEGEN.md')).toBe(false);
    expect(files.get('CODEOWNERS')).toBe(orig);
    expect(files.get('.github/CODEOWNERS')).toBe(`${orig2}z/ @y\n`);
    expect(files.has('docs/CODEOWNERS')).toBe(false);
    // asked, default keep
    expect(files.get('Dockerfile')).toBe(FILES.Dockerfile);
    expect(files.get('README.md')).toBe(FILES['README.md']);
    expect(w.g.head('o/shop')).toBe(base);   // main itself is never moved
    // the PR body names what it does (names only)
    expect(pr?.body).toMatch(/removes \.github\/workflows\/pipegen\.yml/);
    expect(pr?.body).toMatch(/pipegen finish/);
    // the merge locks come off only after the PR is open
    const routes = w.g.routes();
    const opened = routes.indexOf('POST /repos/{owner}/{repo}/pulls');
    expect(opened).toBeGreaterThan(-1);
    for (const lock of ['DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}', 'DELETE /orgs/{org}/rulesets/{ruleset_id}', 'DELETE /repos/{owner}/{repo}/branches/{branch}/protection']) {
      expect(routes.indexOf(lock), lock).toBeGreaterThan(opened);
    }
    expect(w.app.rulesets.has(41)).toBe(false);
    expect(w.org.has(77)).toBe(false);
    expect(w.protection).toBeNull();
    // secrets, environments and variables untouched; nothing written to the central repo (the record stays)
    expect(writes(w).filter((x) => /secrets|variables|environments|vulnerability|actions\/permissions|PATCH \/repos\/\{owner\}\/\{repo\}$/.test(x))).toEqual([]);
    expect(w.app.stored.has('PIPEGEN_FP_KEY')).toBe(true);
    expect(w.app.envs.has('pipegen-signing')).toBe(true);
    expect(writeCalls(w).filter((c) => c.params.repo === 'pipelines')).toEqual([]);
    // the progress file: run 1 done, the PR, names only
    const p = progressOf(w);
    expect(p).toMatchObject({ version: 1, repoId: w.app.id, phase: 'A-done', prNumber: 1, prUrl: 'https://github.com/o/shop/pull/1' });
    expect(statSync(uninstallProgressPath({ owner: 'o', repo: 'shop' }, local(w))).mode & 0o777).toBe(0o600);
    // the final message: merge, then run again; finish locks again meanwhile
    const text = r.lines.join('\n');
    expect(text).toMatch(/Merge the uninstall pull request #1/);
    expect(text).toMatch(/run `pipegen uninstall` again/);
    expect(text).toMatch(/pipegen finish/);
    // the preview was shown before the one question
    expect(w.out.join('\n')).toMatch(/pipegen uninstall: what it will do in o\/shop/);
  });

  it('apply: only recorded ruleset id deleted', async () => {
    const w = world();
    w.app.rulesets.set(41, liveRs());
    w.app.rulesets.set(42, liveRs());                                    // a ruleset named pipegen the record doesn't list
    w.app.rulesets.set(43, liveRs({ name: 'pipegen-reviews' }));         // the same
    w.app.rulesets.set(44, liveRs({ created_at: LATER }));               // recorded, but GitHub's is another one now
    const rec = sampleRecord(w, { rulesets: [rs(), rs({ id: 44 })] });
    const r = await run(w, rec);
    expect(r.status).toBe('a-done');
    const deleted = writeCalls(w).filter((c) => c.route === 'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}').map((c) => c.params.ruleset_id);
    expect(deleted).toEqual([41]);
    expect([...w.app.rulesets.keys()].sort()).toEqual([42, 43, 44]);
    expect(r.skipped.some((s) => /ruleset pipegen \(id 44\)/.test(s.what))).toBe(true);
    expect(r.lines.join('\n')).toMatch(/ruleset pipegen \(id 44\)/);
    // a ruleset that turns into another one between the preview and the delete is kept too (identity re-read right before it)
    const w2 = world();
    w2.app.rulesets.set(41, liveRs());
    const t = term({ go: () => { w2.app.rulesets.set(41, liveRs({ created_at: LATER })); return true; } });
    const r2 = await run(w2, sampleRecord(w2), t);
    expect(writes(w2)).not.toContain('DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}');
    expect(r2.skipped.some((s) => /not the one pipegen created|created at another time|created_at/i.test(s.why))).toBe(true);
  });

  it('apply: failure in one step reported, others continue', async () => {
    // the uninstall PR can't be opened: pipegen's setup PR is still closed (independent), but no merge lock comes off (it depends on the PR)
    const w = world();
    const rec = sampleRecord(w, locked(w));
    w.app.pulls.push({ number: 1, head: 'pipegen/setup', base: 'main', title: 'pipegen setup', body: '', state: 'open', html_url: 'https://github.com/o/shop/pull/1' });
    w.fail = (route) => (route === 'POST /repos/{owner}/{repo}/pulls' ? 500 : undefined);
    const r = await run(w, rec, term(), {}, { setupPr: 1 });
    expect(r.status).toBe('failed');
    expect(r.failed.some((f) => /uninstall pull request/.test(f.what))).toBe(true);
    expect(w.app.pulls.find((p) => p.number === 1)?.state).toBe('closed');
    for (const lock of ['DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}', 'DELETE /orgs/{org}/rulesets/{ruleset_id}', 'DELETE /repos/{owner}/{repo}/branches/{branch}/protection', CLASSIC_ROUTE]) {
      expect(writes(w), lock).not.toContain(lock);
    }
    expect(r.failed.filter((f) => /not done: the uninstall pull request was not opened/.test(f.why)).length).toBe(3);
    // progress saved on the failure: run 1 is not done, so the next run plans run 1 again
    expect(progressOf(w)).toMatchObject({ phase: 'A' });
    expect((progressOf(w).leftovers as { what: string }[]).some((x) => /uninstall pull request/.test(x.what))).toBe(true);
    expect(writeCalls(w).filter((c) => c.params.repo === 'pipelines')).toEqual([]);   // the record stays
    expect(r.lines.join('\n')).toMatch(/run `pipegen uninstall` again/);

    // one lock fails (HTTP 500 on its DELETE): reported, the other locks still come off; run 1 stays to do
    const w2 = world();
    const rec2 = sampleRecord(w2, locked(w2));
    w2.fail = (route) => (route === 'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}' ? 500 : undefined);
    const r2 = await run(w2, rec2);
    expect(r2.status).toBe('failed');
    expect(r2.failed.map((f) => f.what)).toEqual(['ruleset pipegen (id 41)']);
    expect(r2.failed[0]?.manual).toMatch(/gh api -X DELETE/);
    expect(w2.org.has(77)).toBe(false);
    expect(w2.protection).toBeNull();
    expect(w2.app.rulesets.has(41)).toBe(true);
    expect(progressOf(w2)).toMatchObject({ phase: 'A', prNumber: 1 });
    expect(writeCalls(w2).filter((c) => c.params.repo === 'pipelines')).toEqual([]);
    // the re-run plans run 1 again and finishes it: the ruleset goes, the PR is updated (not a second one)
    w2.fail = undefined;
    const pulls = writes(w2).filter((x) => x === 'POST /repos/{owner}/{repo}/pulls').length;
    const r3 = await run(w2, rec2);
    expect(r3.status).toBe('a-done');
    expect(w2.app.rulesets.has(41)).toBe(false);
    expect(writes(w2).filter((x) => x === 'POST /repos/{owner}/{repo}/pulls').length).toBe(pulls);
    expect(progressOf(w2)).toMatchObject({ phase: 'A-done', prNumber: 1 });
  });

  it('apply: PR built on the preview\'s base commit; base moved → re-plan', async () => {
    // main moves after the preview: nothing is sent; pipegen plans again (new preview, new question) on the new head
    const w = world();
    let first = true;
    let sentBeforeSecond = -1;
    const t = term({ go: () => {
      if (first) { first = false; w.g.commitOn('o/shop', 'main', { 'README.md': 'my app, changed\n' }); return true; }
      sentBeforeSecond = writes(w).length;
      return true;
    } });
    const r = await run(w, sampleRecord(w), t);
    expect(r.status).toBe('a-done');
    expect(plans().map((p) => p.phase)).toEqual(['A', 'A']);
    expect(t.confirms.filter((q) => q.startsWith('Go ahead'))).toHaveLength(2);
    expect(sentBeforeSecond).toBe(0);
    expect(w.out.join('\n')).toMatch(/moved since the preview/);
    const [old, fresh] = plans() as [UninstallPlan, UninstallPlan];
    expect(fresh.base.appHead).toBe(w.g.head('o/shop'));
    expect(fresh.api).not.toBe(old.api);
    const tip = w.g.head('o/shop', 'pipegen/uninstall');
    const hist = w.g.history('o/shop', tip, fresh.base.appHead);
    expect(hist[hist.length - 1]?.parents).toEqual([fresh.base.appHead]);
    expect(w.g.filesAt('o/shop', tip).get('README.md')).toBe('my app, changed\n');
    // the first plan was dropped with its api: it is never applied
    const progress = await ProgressFile.open({ owner: 'o', repo: 'shop' }, w.app.id, local(w));
    const n = w.g.calls.length;
    await stops(applyPhaseA(gh(w), old, progress), /confirmed plan/);
    expect(w.g.calls.length).toBe(n);

    // main moves right after the re-check: the PR still sits on the preview's commit (never rebased silently)
    const w2 = world();
    let armed = false;
    let movedTo = '';
    w2.g.hooks.unshift((call) => {
      if (!armed || call.route !== 'GET /repos/{owner}/{repo}/git/ref/{ref}' || call.params.repo !== 'shop' || call.params.ref !== 'heads/main') return undefined;
      armed = false;
      const was = w2.g.head('o/shop');
      movedTo = w2.g.commitOn('o/shop', 'main', { 'README.md': 'later\n' });
      return { status: 200, data: { ref: 'refs/heads/main', object: { sha: was, type: 'commit' } } };
    });
    const r2 = await run(w2, sampleRecord(w2), term({ go: () => { armed = true; return true; } }));
    expect(r2.status).toBe('a-done');
    const p2 = plans()[plans().length - 1] as UninstallPlan;
    expect(movedTo).not.toBe('');
    const tip2 = w2.g.head('o/shop', 'pipegen/uninstall');
    const hist2 = w2.g.history('o/shop', tip2, p2.base.appHead);
    expect(hist2[hist2.length - 1]?.parents).toEqual([p2.base.appHead]);
    expect(w2.g.filesAt('o/shop', tip2).get('README.md')).toBe('my app\n');
    // the first commit's tree is built on the preview's tree
    const firstTree = writeCalls(w2).find((c) => c.route === 'POST /repos/{owner}/{repo}/git/trees');
    expect(firstTree?.params.base_tree).toBe(p2.base.appTree);
  });

  it('apply: record blob changed since the preview → stop, nothing sent', async () => {
    const w = world();
    w.app.rulesets.set(41, liveRs());
    const t = term({ go: () => { w.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: '{"pipegen":"edited"}\n' }); return true; } });
    await stops(run(w, sampleRecord(w), t), /install record .*changed since the preview/);
    expect(writes(w)).toEqual([]);
    expect(w.app.rulesets.has(41)).toBe(true);
    // the central default branch moved with the record unchanged: stop too
    const w2 = world();
    const t2 = term({ go: () => { w2.g.commitOn('o/pipelines', 'main', { 'other.txt': 'x\n' }); return true; } });
    await stops(run(w2, sampleRecord(w2), t2), /changed since the preview/);
    expect(writes(w2)).toEqual([]);
    // the record file gone from the central head: stop
    const w3 = world();
    const t3 = term({ go: () => { w3.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: null }); return true; } });
    await stops(run(w3, sampleRecord(w3), t3), /changed since the preview/);
    expect(writes(w3)).toEqual([]);
    // the app's default branch gone: stop
    const w4 = world();
    const t4 = term({ go: () => { w4.app.refs.delete('heads/main'); return true; } });
    await stops(run(w4, sampleRecord(w4), t4), /default branch/);
    expect(writes(w4)).toEqual([]);
    // a stop is not "run 1 done": no progress says so
    expect(hasProgress(w) ? progressOf(w).phase : 'none').not.toBe('A-done');
  });

  it('apply: Ctrl-C → no new write, progress saved, record untouched; a re-run resumes', async () => {
    const w = world();
    const rec = sampleRecord(w, locked(w));
    // this machine's local record file: uninstall never touches it in run 1
    const lr = localRecordPath({ owner: 'o', repo: 'shop' }, local(w));
    mkdirSync(dirname(lr), { recursive: true, mode: 0o700 });
    writeFileSync(lr, '{"recordHash":"x"}\n', { mode: 0o600 });
    let pending: Promise<unknown> = Promise.resolve();
    let at = -1;
    w.g.hooks.unshift((call) => {
      if (call.route !== 'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}' || h.stop.now) return undefined;
      // Ctrl-C while this delete is in flight: the stop begins, the interrupt hooks start
      h.stop.now = true;
      at = w.g.calls.length;
      pending = Promise.all(h.fns.map((f) => f({ signal: new AbortController().signal, leftover: () => {} })));
      return undefined;
    });
    const r = await run(w, rec);
    await pending;
    expect(r.status).toBe('interrupted');
    // the write in flight settled; nothing after it, not even a read
    expect(at).toBeGreaterThan(0);
    expect(w.g.calls.slice(at)).toEqual([]);
    expect(w.app.rulesets.has(41)).toBe(false);
    expect(w.org.has(77)).toBe(true);
    expect(w.protection).not.toBeNull();
    // progress saved: run 1 not done, the PR and the deleted ruleset in it
    const p = progressOf(w);
    expect(p).toMatchObject({ phase: 'A', prNumber: 1 });
    expect((p.done as string[]).some((d) => /ruleset pipegen \(id 41\)/.test(d))).toBe(true);
    // the record untouched: no central write, the local record file as it was
    expect(writeCalls(w).filter((c) => c.params.repo === 'pipelines')).toEqual([]);
    expect(readFileSync(lr, 'utf8')).toBe('{"recordHash":"x"}\n');
    expect(h.fns).toEqual([]);   // the interrupt hook is unregistered after the run
    // the re-run resumes run 1: the rest of the locks, the same PR (updated), no second delete of the ruleset
    h.stop.now = false;
    const before = w.g.calls.length;
    const r2 = await run(w, rec);
    expect(r2.status).toBe('a-done');
    const again = w.g.calls.slice(before).filter((c) => !c.route.startsWith('GET ')).map((c) => c.route);
    expect(again).not.toContain('DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}');
    expect(again).not.toContain('POST /repos/{owner}/{repo}/pulls');
    expect(again).toContain('DELETE /orgs/{org}/rulesets/{ruleset_id}');
    expect(again).toContain('DELETE /repos/{owner}/{repo}/branches/{branch}/protection');
    expect(progressOf(w)).toMatchObject({ phase: 'A-done', prNumber: 1 });
    expect(readFileSync(lr, 'utf8')).toBe('{"recordHash":"x"}\n');
  });

  it('apply: holds the app\'s lease; refuses while another pipegen run holds it', async () => {
    const w = world();
    const rec = sampleRecord(w);
    w.app.rulesets.set(41, liveRs());
    // another pipegen run (a proof, say) holds the lease of this app: uninstall stops before it reads or sends anything
    const other = await StateStore.open({ owner: 'o', repo: 'shop' }, local(w));
    other.acquireLease('proof-run');
    await stops(run(w, rec), /Another pipegen/);
    expect(w.g.calls).toEqual([]);
    expect(hasProgress(w)).toBe(false);
    other.releaseLease();
    // uninstall holds it for the whole run: another run can't take it while uninstall writes; it is given back at the end
    const probe = await StateStore.open({ owner: 'o', repo: 'shop' }, local(w));
    const tried: boolean[] = [];
    w.g.hooks.unshift((call) => {
      if (call.route.startsWith('GET ')) return undefined;
      try { probe.acquireLease('probe'); probe.releaseLease(); tried.push(true); } catch { tried.push(false); }
      return undefined;
    });
    const r = await run(w, rec);
    expect(r.status).toBe('a-done');
    expect(tried.length).toBeGreaterThan(0);
    expect(tried.every((x) => x === false)).toBe(true);
    probe.acquireLease('after');
    probe.releaseLease();
    // a run that stops (declined) gives it back too
    await run(w, rec, term({ go: () => false }));
    probe.acquireLease('after-declined');
    probe.releaseLease();
  });

  it('apply: pre-existing classic protection restored with PUT previous; none → DELETE', async () => {
    const previous = { required_status_checks: null, enforce_admins: false, required_pull_request_reviews: { required_approving_review_count: 1, dismiss_stale_reviews: false, require_code_owner_reviews: false }, restrictions: null };
    const w = world();
    const rec = sampleRecord(w, locked(w, previous));
    const t = term();
    const r = await run(w, rec, t);
    expect(r.status).toBe('a-done');
    expect(t.typed.some((q) => /branch protection of main[^]*Type main to go on/.test(q))).toBe(true);
    const puts = writeCalls(w).filter((c) => c.route === CLASSIC_ROUTE);
    expect(puts).toEqual([{ route: CLASSIC_ROUTE, params: { ...previous, owner: 'o', repo: 'shop', branch: 'main' } }]);
    expect(writes(w)).not.toContain('DELETE /repos/{owner}/{repo}/branches/{branch}/protection');
    // none before pipegen: the protection pipegen added is taken off (DELETE), never PUT
    const w2 = world();
    const r2 = await run(w2, sampleRecord(w2, locked(w2, null)));
    expect(r2.status).toBe('a-done');
    expect(writes(w2)).toContain('DELETE /repos/{owner}/{repo}/branches/{branch}/protection');
    expect(writes(w2)).not.toContain(CLASSIC_ROUTE);
    expect(w2.protection).toBeNull();
    // changed between the preview and the write: kept, a manual step, nothing sent
    const w3 = world();
    const t3 = term({ go: () => { w3.protection = { ...LIVE_PROTECTION(), enforce_admins: { enabled: false } }; return true; } });
    const r3 = await run(w3, sampleRecord(w3, locked(w3, previous)), t3);
    expect(writes(w3).filter((x) => /protection/.test(x))).toEqual([]);
    expect(r3.manual.some((m) => /branch protection of main/.test(m.what))).toBe(true);
  });
});

describe('uninstall apply: the four conditions of the V4 security review and the phase-bound api (V4-R1, M-r1-1)', () => {
  it('apply: nothing is sent before the one confirmation; a no or a cancel drops the plan and its api', async () => {
    const w = world();
    w.app.rulesets.set(41, liveRs());
    const rec = sampleRecord(w);
    let atQuestion = -1;
    const r = await run(w, rec, term({ go: () => { atQuestion = writes(w).length; return false; } }));
    expect(atQuestion).toBe(0);
    expect(r.status).toBe('declined');
    expect(writes(w)).toEqual([]);
    expect(hasProgress(w)).toBe(false);
    expect(r.lines.join('\n')).toMatch(/Nothing was changed/);
    // the declined plan can't be applied, and its api's tokens are refused by a new run's api
    const declined = plans()[0] as UninstallPlan;
    const progress = await ProgressFile.open({ owner: 'o', repo: 'shop' }, w.app.id, local(w));
    await stops(applyPhaseA(gh(w), declined, progress), /confirmed plan/);
    expect(writes(w)).toEqual([]);
    // a cancelled question is a no
    const t = term({ go: () => { throw new PromptCancelledError(); } });
    expect((await run(w, rec, t)).status).toBe('declined');
    expect(writes(w)).toEqual([]);
    // no terminal: the preview, then a stop; nothing sent
    await stops(run(w, rec, term(), { interactive: false }), /terminal/);
    expect(writes(w)).toEqual([]);
    // tokens are bound to the api that minted them: a typed-names run's token can't be used by another plan's api
    const w2 = world();
    w2.app.rulesets.set(41, liveRs());
    const a = await planUninstall(gh(w2), loadedOf(w2, sampleRecord(w2), { typedNames: true, marker: 'differs' }), term().p, { interactive: true, local: local(w2) });
    const b = await planUninstall(gh(w2), loadedOf(w2, sampleRecord(w2), { typedNames: true, marker: 'differs' }), term().p, { interactive: true, local: local(w2) });
    const tok = a.deleteRulesets[0]?.typed;
    expect(tok).toBeDefined();
    await expect(b.api.deleteIfPipegens({ kind: 'ruleset', entry: rs() }, { typed: tok })).rejects.toBeInstanceOf(UninstallRefusal);
    expect(writes(w2)).toEqual([]);
    // a plan applied once is used up: it can't be applied a second time
    expect(await confirmPlan(b, term().p, { interactive: true, out: () => {} })).toBe(true);
    const pb = await ProgressFile.open({ owner: 'o', repo: 'shop' }, w2.app.id, local(w2));
    expect((await applyPhaseA(gh(w2), b, pb)).status).toBe('a-done');
    const n = w2.g.calls.length;
    await stops(applyPhaseA(gh(w2), b, pb), /confirmed plan/);
    expect(w2.g.calls.length).toBe(n);
  });

  it('apply: a phase-A apply sends no secret, variable or environment write', async () => {
    // a typed-names run: run 1's plan holds run 2's items (secrets, variables, environments, restores, settings) with needsName and no token
    const w = world();
    w.app.rulesets.set(41, liveRs());
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    w.app.stored.set('DATABASE_URL', AT);
    const created: Env = { id: 9, created_at: AT, wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() };
    const existing: Env = { id: 10, created_at: AT, wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() };
    w.app.envs.set('pipegen-signing', created);
    w.app.envs.set('production', existing);
    w.vars.set('repo', new Map([['PIPEGEN_LEVEL', { created_at: AT, value: '1' }], ['PIPEGEN_BLOCK_FROM', { created_at: AT, value: 'pipegen-set' }]]));
    const rec = sampleRecord(w, {
      [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }, { name: 'DATABASE_URL', scope: 'repo', created: true, githubCreatedAt: AT }],
      variables: [{ name: 'PIPEGEN_LEVEL', scope: 'repo', created: true, githubCreatedAt: AT }, { name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, previous: 'before' }],
      environments: [
        { name: 'pipegen-signing', created: true, changed: [], branchPolicyIds: [], githubCreatedAt: AT },
        { name: 'production', created: false, changed: ['wait_timer'], previous: { wait_timer: 30, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] }, branchPolicyIds: [], githubCreatedAt: AT },
      ],
      blockFrom: 'pipegen-set',
      repoSettings: { secretScanning: { previous: false }, shaPinningRequired: { previous: false } },
    });
    const r = await run(w, rec, term(), {}, { typedNames: true, marker: 'differs' });
    expect(r.status).toBe('a-done');
    const a = plans()[0] as UninstallPlan;
    expect(a.phase).toBe('A');
    expect(a.deleteSecrets.length).toBe(2);
    expect(a.deleteVariables.length).toBe(1);
    expect(a.deleteEnvironments.length).toBe(1);
    expect(a.restoreEnvironments.length).toBe(1);
    expect(a.restoreVariables.length).toBe(1);
    expect(a.settings.length).toBe(2);
    expect([...a.deleteSecrets, ...a.deleteVariables, ...a.deleteEnvironments, ...a.restoreEnvironments, ...a.restoreVariables].every((x) => x.needsName === true && x.typed === undefined)).toBe(true);
    // not one of them was sent
    expect(writes(w).filter((x) => /secrets|variables|environments|vulnerability-alerts|actions\/permissions|deployment-branch-policies|^PATCH \/repos\/\{owner\}\/\{repo\}$/.test(x))).toEqual([]);
    expect(w.app.stored.has('PIPEGEN_FP_KEY')).toBe(true);
    expect(w.app.envs.has('pipegen-signing')).toBe(true);
    expect(existing.wait_timer).toBe(0);
    // run 1's own items were sent (the ruleset, with its typed name)
    expect(writes(w)).toContain('DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}');
  });

  it('apply: the phase-bound api refuses the other run\'s writes', async () => {
    const w = world();
    const a = await planUninstall(gh(w), loadedOf(w, sampleRecord(w)), term().p, { interactive: true, local: local(w) });
    const n = w.g.calls.length;
    const secretEntry = { name: 'PIPEGEN_X', scope: 'repo' as const, created: true, githubCreatedAt: AT };
    const env = { name: 'pipegen-signing', created: true, changed: [], branchPolicyIds: [5], githubCreatedAt: AT };
    const prior = { name: 'production', created: false, changed: ['wait_timer' as const], previous: { wait_timer: 30, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] }, branchPolicyIds: [5] };
    const commit = { parent: SHA('a'), baseTree: SHA('b'), files: [], deletes: ['x.txt'], message: 'm' };
    const A = new PhaseApi(a.api, 'A');
    for (const call of [
      () => A.deleteIfPipegens({ kind: 'secret', entry: secretEntry }),
      () => A.deleteIfPipegens({ kind: 'variable', entry: { name: 'PIPEGEN_V', scope: 'repo', created: true, githubCreatedAt: AT } }),
      () => A.deleteIfPipegens({ kind: 'environment', entry: env }),
      () => A.deleteIfPipegens({ kind: 'central-ruleset', id: 3, createdAt: AT }),
      () => A.restoreEnvironment(prior, { wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null }),
      () => A.restoreVariable({ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, previous: 'p' }, 'v'),
      () => A.deleteBranchPolicy(env, 5),
      () => A.write('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { owner: 'o', repo: 'shop' }),
      () => A.commitUninstall('central', commit),
      () => A.setUninstallBranch('central', SHA('a')),
      () => A.openUninstallPr('central', { base: 'main', title: 't', body: 'b' }),
      () => A.deleteBranch('central', 'pipegen/update-shop'),
      () => A.deleteBranch('app', 'pipegen/update'),
    ]) await expect(call()).rejects.toBeInstanceOf(UninstallRefusal);
    const B = new PhaseApi(a.api, 'B');
    for (const call of [
      () => B.deleteIfPipegens({ kind: 'ruleset', entry: rs() }),
      () => B.deleteIfPipegens({ kind: 'org-ruleset', entry: orgEntry }),
      () => B.restoreClassic({ branch: 'main', previous: null }, PLANNED),
      () => B.closePr('app', 1),
      () => B.deleteBranch('app', 'pipegen/setup'),
      () => B.commitUninstall('app', commit),
      () => B.setUninstallBranch('app', SHA('a')),
      () => B.openUninstallPr('app', { base: 'main', title: 't', body: 'b' }),
    ]) await expect(call()).rejects.toBeInstanceOf(UninstallRefusal);
    // refused before anything is read or sent
    expect(w.g.calls.length).toBe(n);
    expect(() => new PhaseApi(a.api, 'C' as 'A')).toThrow(UninstallRefusal);
  });

  it('apply: run 2 is a fresh plan; nothing of run 1\'s answers or tokens is kept', async () => {
    const w = world();
    w.app.rulesets.set(41, liveRs());
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    const rec = sampleRecord(w, { [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }], repoSettings: { secretScanning: { previous: false } } });
    const lo = { typedNames: true, marker: 'differs' as const };
    const t1 = term();
    expect((await run(w, rec, t1, {}, lo)).status).toBe('a-done');
    const text = readFileSync(uninstallProgressPath({ owner: 'o', repo: 'shop' }, local(w)), 'utf8');
    for (const k of ['typed', 'confirmedByName', 'turnOff', 'keepAsk', 'needsName', 'keep']) expect(text, k).not.toMatch(new RegExp(`"${k}"`));
    // the uninstall PR merged: run 2 plans phase B afresh, asks its own names again, and gets an api bound to phase B
    w.merged.set(1, LATER);
    (w.app.pulls[0] as { state: string }).state = 'closed';
    const b = phaseB();
    const t2 = term();
    const r = await run(w, rec, t2, { phaseB: b.fn }, lo);
    expect(r.status).toBe('b-done');
    expect(plans().map((p) => p.phase)).toEqual(['A', 'B']);
    const [pa, pb] = plans() as [UninstallPlan, UninstallPlan];
    expect(pb.api).not.toBe(pa.api);
    expect(b.got).toHaveLength(1);
    expect(b.got[0]?.plan).toBe(pb);
    expect(b.got[0]?.api.phase).toBe('B');
    expect(t2.typed.some((q) => q.includes('PIPEGEN_FP_KEY'))).toBe(true);   // asked again in run 2, never taken from run 1
    expect(t1.typed.some((q) => q.includes('PIPEGEN_FP_KEY'))).toBe(false);
    expect(t2.confirms.filter((q) => q.startsWith('Go ahead'))).toHaveLength(1);
    expect(pb.deleteSecrets[0]?.typed).toBeDefined();
    // the phase-B plan was used once: it can't go through applyPhaseA
    const progress = await ProgressFile.open({ owner: 'o', repo: 'shop' }, w.app.id, local(w));
    await stops(applyPhaseA(gh(w), pb, progress), /confirmed plan|phase/);
  });

  it('apply: writes use the plan\'s own objects', async () => {
    const previous = { required_status_checks: null, enforce_admins: false, required_pull_request_reviews: null, restrictions: null };
    const w = world();
    const rec = sampleRecord(w, locked(w, previous));
    const loaded = loadedOf(w, rec);
    const t = term();
    const plan = await planUninstall(gh(w), loaded, t.p, { interactive: true, local: local(w) });
    expect(await confirmPlan(plan, t.p, { interactive: true, out: () => {} })).toBe(true);
    // the plan's objects are what is sent, never one rebuilt from the record or a fresh read
    const mine = { ...previous, allow_deletions: true };
    (plan.restoreClassic as { previous: Record<string, unknown> }).previous = mine;
    (rec.classicProtection as { previous: unknown }).previous = { ...previous, lock_branch: true };
    const progress = await ProgressFile.open({ owner: 'o', repo: 'shop' }, w.app.id, local(w));
    const r = await applyPhaseA(gh(w), plan, progress);
    expect(r.status).toBe('a-done');
    expect(writeCalls(w).filter((c) => c.route === CLASSIC_ROUTE)).toEqual([{ route: CLASSIC_ROUTE, params: { ...mine, owner: 'o', repo: 'shop', branch: 'main' } }]);
    expect(writeCalls(w).filter((c) => c.route === 'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}').map((c) => c.params.ruleset_id)).toEqual([plan.deleteRulesets[0]?.id]);
  });
});

describe('uninstall: the dispatcher (phase A, the wait for the merge, phase B)', () => {
  it('apply: phase B only after the uninstall PR merged; closed unmerged → nothing more, says run finish', async () => {
    const w = world();
    w.app.rulesets.set(41, liveRs());
    const rec = sampleRecord(w);
    const b = phaseB();
    expect((await run(w, rec, term(), { phaseB: b.fn })).status).toBe('a-done');
    expect(b.got).toEqual([]);
    // open: say merge it, then run again; nothing sent, nothing planned
    let n = writes(w).length;
    const open = await run(w, rec, term(), { phaseB: b.fn });
    expect(open.status).toBe('waiting');
    expect(open.lines.join('\n')).toMatch(/#1 [^]*still open[^]*Merge it, then run `pipegen uninstall` again/);
    expect(writes(w).length).toBe(n);
    expect(b.got).toEqual([]);
    expect(plans()).toHaveLength(1);
    // closed without merging: nothing more; finish locks again; the progress file goes
    const pr = w.app.pulls[0] as { state: string };
    pr.state = 'closed';
    const closed = await run(w, rec, term(), { phaseB: b.fn });
    expect(closed.status).toBe('closed-unmerged');
    expect(closed.lines.join('\n')).toMatch(/closed without merging[^]*pipegen finish/);
    expect(b.got).toEqual([]);
    expect(writes(w).length).toBe(n);
    expect(hasProgress(w)).toBe(false);
    // merged (GitHub's merged_at): phase B, from a fresh phase-B plan
    const w2 = world();
    w2.app.rulesets.set(41, liveRs());
    const rec2 = sampleRecord(w2);
    await run(w2, rec2, term(), { phaseB: b.fn });
    (w2.app.pulls[0] as { state: string }).state = 'closed';
    w2.merged.set(1, LATER);
    n = writes(w2).length;
    const merged = await run(w2, rec2, term(), { phaseB: b.fn });
    expect(merged.status).toBe('b-done');
    expect(b.got).toHaveLength(1);
    expect(b.got[0]?.plan.phase).toBe('B');
    expect(writes(w2).length).toBe(n);   // the stand-in sends nothing; the dispatcher sent nothing of phase A
    // no phase-B runner in this build: it says so, nothing more is sent or asked
    const w3 = world();
    const rec3 = sampleRecord(w3);
    await run(w3, rec3);
    (w3.app.pulls[0] as { state: string }).state = 'closed';
    w3.merged.set(1, LATER);
    const t3 = term();
    const none = await run(w3, rec3, t3);
    expect(none.status).toBe('stopped');
    expect(t3.confirms).toEqual([]);
  });

  it('apply: no uninstall PR: unfinished → phase B in the same process; nothing to remove → phase B only when no pipegen workflow is live; a PR GitHub no longer shows → stop', async () => {
    // unfinished (the setup PR never merged, none of pipegen's workflows on main, no mergedAt): phase B right after phase A, its own preview and yes
    const bare = { 'README.md': 'my app\n' };
    const w = world(bare);
    w.app.rulesets.set(41, liveRs());
    const rec = sampleRecord(w, { mergedAt: undefined });
    const b = phaseB();
    const t = term();
    const r = await run(w, rec, t, { phaseB: b.fn });
    expect(r.status).toBe('b-done');
    expect(plans().map((p) => p.phase)).toEqual(['A', 'B']);
    expect(plans()[0]?.unfinished).toBe(true);
    expect(t.confirms.filter((q) => q.startsWith('Go ahead'))).toHaveLength(2);
    expect(b.got).toHaveLength(1);
    expect(writes(w)).not.toContain('POST /repos/{owner}/{repo}/pulls');
    expect(w.app.rulesets.has(41)).toBe(false);

    // a finished install with nothing of pipegen's left in the app: run 1 opens no PR; run 2 goes to phase B (no workflow live)
    const w2 = world(bare);
    const rec2 = sampleRecord(w2);
    const b2 = phaseB();
    const r1 = await run(w2, rec2, term(), { phaseB: b2.fn });
    expect(r1.status).toBe('a-done');
    expect(r1.pr).toBeUndefined();
    expect(r1.lines.join('\n')).toMatch(/needed no uninstall pull request/);
    expect(progressOf(w2).prNumber).toBeUndefined();
    expect(b2.got).toEqual([]);
    const r2 = await run(w2, rec2, term(), { phaseB: b2.fn });
    expect(r2.status).toBe('b-done');
    expect(b2.got).toHaveLength(1);
    expect(b2.got[0]?.plan.warnings.some((x) => /aren't on the default branch/.test(x))).toBe(false);

    // pipegen's workflow back on main before run 2 (or its verify job in a deploy workflow): phase A again, never phase B
    for (const add of [{ '.github/workflows/pipegen.yml': 'name: pipegen\n' }, { '.github/workflows/deploy.yml': 'jobs:\n  pipegen-verify:\n    runs-on: x\n' }]) {
      h.plans.length = 0;
      const w3 = world(bare);
      const rec3 = sampleRecord(w3);
      const b3 = phaseB();
      await run(w3, rec3, term(), { phaseB: b3.fn });
      w3.g.commitOn('o/shop', 'main', add);
      const again = await run(w3, rec3, term(), { phaseB: b3.fn });
      expect(b3.got, JSON.stringify(add)).toEqual([]);
      expect(plans().map((p) => p.phase)).toEqual(['A', 'A']);
      expect(again.phase).toBe('A');
      expect(w3.out.join('\n')).toMatch(/still on main[^]*first run again/);
    }

    // the progress file names a PR GitHub no longer shows (or not pipegen's uninstall PR): stop with a manual step, never phase B
    const w4 = world();
    const rec4 = sampleRecord(w4);
    const pf = await ProgressFile.open({ owner: 'o', repo: 'shop' }, w4.app.id, local(w4));
    const anchors = { appHead: SHA('1'), appTree: SHA('2'), centralHead: SHA('3'), recordBlobSha: SHA('4') };
    pf.save({ phase: 'A-done', anchors, prNumber: 99, prUrl: 'https://github.com/o/shop/pull/99', done: [], leftovers: [] });
    const b4 = phaseB();
    const gone = await run(w4, rec4, term(), { phaseB: b4.fn });
    expect(gone.status).toBe('stopped');
    expect(gone.manual.some((m) => /#99/.test(m.what + m.why))).toBe(true);
    expect(b4.got).toEqual([]);
    expect(hasProgress(w4)).toBe(true);
    expect(writes(w4)).toEqual([]);
    w4.app.pulls.push({ number: 1, head: 'feature', base: 'main', title: 'x', body: '', state: 'closed', html_url: 'https://github.com/o/shop/pull/1' });
    w4.merged.set(1, LATER);
    pf.save({ phase: 'A-done', anchors, prNumber: 1, done: [], leftovers: [] });
    const foreign = await run(w4, rec4, term(), { phaseB: b4.fn });
    expect(foreign.status).toBe('stopped');
    expect(b4.got).toEqual([]);
    expect(writes(w4)).toEqual([]);
  });
});

describe('uninstall progress file (V5)', () => {
  it('progress: unreadable progress file → stop naming it, never overwritten', async () => {
    const w = world();
    w.app.rulesets.set(41, liveRs());
    const rec = sampleRecord(w);
    const file = uninstallProgressPath({ owner: 'o', repo: 'shop' }, local(w));
    expect(file).toBe(join(w.home, '.config', 'pipegen', 'records', 'o__shop.uninstall.json'));
    // a round trip first: 0600, names and ids only
    const pf = await ProgressFile.open({ owner: 'o', repo: 'shop' }, w.app.id, local(w));
    expect(pf.state).toBeNull();
    pf.save({ phase: 'A', anchors: { appHead: SHA('1'), appTree: SHA('2'), centralHead: SHA('3'), recordBlobSha: SHA('4') }, done: ['ruleset pipegen (id 41): deleted\u001b[2J'], leftovers: [{ what: 'x', why: 'y', manual: 'gh z' }] });
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const again = await ProgressFile.open({ owner: 'o', repo: 'shop' }, w.app.id, local(w));
    expect(again.state).toMatchObject({ phase: 'A', done: [expect.not.stringContaining('\u001b')], leftovers: [{ what: 'x', why: 'y', manual: 'gh z' }] });
    again.remove();
    expect(existsSync(file)).toBe(false);
    // each unreadable form stops the run before anything is read from GitHub, names the file, and leaves it as it is
    const good = JSON.stringify({ version: 1, repoId: w.app.id, phase: 'A-done', anchors: { appHead: SHA('1'), appTree: SHA('2'), centralHead: SHA('3'), recordBlobSha: SHA('4') }, done: [], leftovers: [], updatedAt: 'x' });
    const forms: [string, () => void][] = [
      ['not JSON', () => writeFileSync(file, '{ not json', { mode: 0o600 })],
      ['not its form', () => writeFileSync(file, JSON.stringify({ phase: 'B', typed: 'main' }), { mode: 0o600 })],
      ['an unknown phase', () => writeFileSync(file, good.replace('"A-done"', '"Z"'), { mode: 0o600 })],
      ['another repo', () => writeFileSync(file, good.replace(`"repoId":${w.app.id}`, `"repoId":${w.app.id + 1}`), { mode: 0o600 })],
      ['too large', () => writeFileSync(file, `${good}${' '.repeat(600 * 1024)}`, { mode: 0o600 })],
      ['a link', () => { const target = join(w.home, 'elsewhere.json'); writeFileSync(target, good); symlinkSync(target, file); }],
    ];
    for (const [what, make] of forms) {
      rmSync(file, { force: true });
      make();
      const before = readFileSync(file);
      const calls = w.g.calls.length;
      const e = await stops(run(w, rec), /uninstall progress file/);
      expect(e.message, what).toContain(file);
      expect(e.message, what).toMatch(/Nothing was changed/);
      expect(readFileSync(file).equals(before), what).toBe(true);
      expect(w.g.calls.length, what).toBe(calls);
      await expect(ProgressFile.open({ owner: 'o', repo: 'shop' }, w.app.id, local(w)), what).rejects.toBeInstanceOf(UninstallError);
    }
    expect(writes(w)).toEqual([]);
  });
});
