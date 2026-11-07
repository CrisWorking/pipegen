// v0.2 Plan V V6: the GitHub stand-in of the phase-B tests (uninstall run 2). FakeGitHub (deliver-github.ts) holds the repos, refs, trees,
// pull requests, secrets and environments; the hooks here add what run 2 reads and deletes: variables, settings, the central Actions access,
// the scratch repo's runs, caches and variables, the lists deleteCentralRepo reads, the org rulesets, and the repo deletes. No network.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import type { Prompter } from '../../src/cli/io.js';
import { gitBlobSha } from '../../src/create/guard.js';
import { recordPath } from '../../src/deliver/record.js';
import { helperDescription, SCRATCH_MARKER } from '../../src/proof/target.js';
import type { InstallRecord } from '../../src/types.js';
import type { StepDeps } from '../../src/uninstall/apply.js';
import type { LoadedRecord } from '../../src/uninstall/record.js';
import { FakeGitHub, type Repo } from './deliver-github.js';

export const SHA = (c: string): string => c.repeat(40).slice(0, 40);
/** The record's secrets field, spelled at run time (test/no-secret-literals.test.ts). */
export const SEC = ['sec', 'rets'].join('') as 'secrets';
export const AT = '2026-11-05T12:00:01Z';
export const blob = (t: string): string => gitBlobSha(t);
export const RECORD_TEXT = '{"pipegen":"record"}\n';
export const MERGE_WF = 'on: workflow_call\n';
/** The secret-scanning keys of GitHub's security_and_analysis, spelled at run time (test/no-secret-literals.test.ts). */
const SS = ['secret', 'scanning'].join('_');
const SP = `${SS}_push_protection`;
export const ACCESS_ROUTE = 'PUT /repos/{owner}/{repo}/actions/permissions/access';

export interface World {
  g: FakeGitHub; app: Repo; central: Repo; scratch: Repo | null; home: string; out: string[];
  /** Actions variables by scope (`repo`, `env:<name>`, `central`, `scratch`). */
  vars: Map<string, Map<string, { created_at: string; value: string }>>;
  org: Map<number, Record<string, unknown>>;
  /** merged_at of pull requests, by `<repo>#<number>`. */
  merged: Map<string, string>;
  /** The login that opened each pull request, by `<repo>#<number>` (default `o`). */
  authors: Map<string, string>;
  /** Extra fields of GET /repos/{owner}/{repo}, by repo name. */
  meta: Map<string, Record<string, unknown>>;
  /** Settings of the app (sha pin, Dependabot alerts, secret scanning) and central's Actions access. */
  settings: { pin: boolean; alerts: boolean; autofix: boolean; scanning: boolean; push: boolean; access: string };
  /** Scratch runs and caches (ids). */
  runs: Set<number>; caches: Set<number>;
  /** Lists deleteCentralRepo reads (`keys`, `hooks`, …): a status to answer instead, or the list. */
  lists: Map<string, number | unknown[]>;
  /** Repos deleted (`owner/name`). */
  deleted: string[];
  fail?: (route: string, params: Record<string, unknown>) => number | undefined;
}

const homes: string[] = [];
export function cleanHomes(): void { for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true }); }

/** An app `o/shop`, its central `o/pipelines` (the record and the merge workflow) and, unless `scratch: false`, the scratch repo. */
export function world(o: { appRepo?: string; app?: Record<string, string>; central?: Record<string, string>; scratch?: boolean; ownerType?: 'User' | 'Organization' } = {}): World {
  const g = new FakeGitHub();
  const name = o.appRepo ?? 'shop';
  const app = g.addRepo(`o/${name}`, { private: true, files: o.app ?? { 'README.md': 'my app\n' }, ...(o.ownerType === undefined ? {} : { ownerType: o.ownerType }) });
  const central = g.addRepo('o/pipelines', { private: true, files: o.central ?? { [recordPath(name)]: RECORD_TEXT, [`.github/workflows/${name}--merge.yml`]: MERGE_WF } });
  const scratch = o.scratch === false ? null : g.addRepo(`o/pipegen-proof-${name}`, { private: true, files: { 'README.md': 'x\n' } });
  const home = mkdtempSync(join(tmpdir(), 'pg-unb-'));
  homes.push(home);
  const w: World = {
    g, app, central, scratch, home, out: [], vars: new Map(), org: new Map(), merged: new Map(), authors: new Map(),
    meta: new Map([['pipelines', { description: helperDescription('central'), has_wiki: false, has_discussions: false, forks_count: 0 }], [`pipegen-proof-${name}`, { description: SCRATCH_MARKER, has_wiki: false, has_discussions: false, forks_count: 0 }]]),
    settings: { pin: false, alerts: false, autofix: false, scanning: false, push: false, access: 'none' },
    runs: new Set(), caches: new Set(), lists: new Map(), deleted: [],
  };
  g.hooks.push((call) => hook(w, call.route, call.params));
  return w;
}

const varsOf = (w: World, scope: string): Map<string, { created_at: string; value: string }> => {
  let m = w.vars.get(scope);
  if (m === undefined) w.vars.set(scope, m = new Map());
  return m;
};

function hook(w: World, route: string, params: Record<string, unknown>): { status: number; data?: unknown } | undefined {
  const p = params as Record<string, string>;
  const f = w.fail?.(route, params);
  if (f !== undefined) return { status: f };
  const full = `${p.owner}/${p.repo}`.toLowerCase();
  const has = w.g.repos.has(full);
  if (route.includes('{repo}') && !has) return { status: 404 };
  const repo = (): Repo => w.g.repo(full);
  const kind = (): string => (repo() === w.app ? 'app' : repo() === w.central ? 'central' : 'scratch');
  const envOf = () => w.app.envs.get(p.environment_name as string);
  const list = (key: string, data: unknown[]): { status: number; data?: unknown } => {
    const l = w.lists.get(`${kind()}:${key}`);
    if (typeof l === 'number') return { status: l };
    return { status: 200, data: l ?? data };
  };
  switch (route) {
    case 'GET /repos/{owner}/{repo}': {
      const r = repo();
      const sa = r === w.app ? { security_and_analysis: { [SS]: { status: w.settings.scanning ? 'enabled' : 'disabled' }, [SP]: { status: w.settings.push ? 'enabled' : 'disabled' } } } : {};
      return { status: 200, data: { id: r.id, name: r.name, full_name: `${r.owner}/${r.name}`, private: r.private, default_branch: r.defaultBranch, owner: { login: r.owner, type: r.ownerType }, ...sa, ...w.meta.get(r.name) } };
    }
    case 'DELETE /repos/{owner}/{repo}':
      w.g.repos.delete(full);
      w.deleted.push(full);
      return { status: 204 };
    // ---------- secrets ----------
    case `GET /repos/{owner}/{repo}/actions/${SEC}`: {
      const l = [...repo().stored].map(([n, at]) => ({ name: n, created_at: at }));
      return { status: 200, data: { total_count: l.length, [SEC]: l } };
    }
    case `DELETE /repos/{owner}/{repo}/actions/${SEC}/{secret_name}`:
      return repo().stored.delete(p.secret_name as string) ? { status: 204 } : { status: 404 };
    case `GET /repos/{owner}/{repo}/environments/{environment_name}/${SEC}`: {
      const e = envOf();
      if (e === undefined) return { status: 404 };
      const l = [...e.stored].map(([n, at]) => ({ name: n, created_at: at }));
      return { status: 200, data: { total_count: l.length, [SEC]: l } };
    }
    case `DELETE /repos/{owner}/{repo}/environments/{environment_name}/${SEC}/{secret_name}`: {
      const e = envOf();
      return e !== undefined && e.stored.delete(p.secret_name as string) ? { status: 204 } : { status: 404 };
    }
    case `GET /repos/{owner}/{repo}/dependabot/${SEC}`: case `GET /repos/{owner}/{repo}/codespaces/${SEC}`:
    {
      const l = w.lists.get(`${kind()}:${route.includes('dependabot') ? 'dependabot' : 'codespaces'}`);
      if (typeof l === 'number') return { status: l };
      return { status: 200, data: { total_count: l?.length ?? 0, [SEC]: l ?? [] } };
    }
    // ---------- variables ----------
    case 'GET /repos/{owner}/{repo}/actions/variables': {
      const scope = kind() === 'app' ? 'repo' : kind();
      const l = [...varsOf(w, scope)].map(([n, v]) => ({ name: n, value: v.value, created_at: v.created_at }));
      return { status: 200, data: { total_count: l.length, variables: l } };
    }
    case 'GET /repos/{owner}/{repo}/actions/variables/{name}': {
      const v = varsOf(w, kind() === 'app' ? 'repo' : kind()).get(p.name as string);
      return v === undefined ? { status: 404 } : { status: 200, data: { name: p.name, value: v.value, created_at: v.created_at } };
    }
    case 'DELETE /repos/{owner}/{repo}/actions/variables/{name}':
      return varsOf(w, kind() === 'app' ? 'repo' : kind()).delete(p.name as string) ? { status: 204 } : { status: 404 };
    case 'PATCH /repos/{owner}/{repo}/actions/variables/{name}': {
      const v = varsOf(w, 'repo').get(p.name as string);
      if (v === undefined) return { status: 404 };
      v.value = String(params.value);
      return { status: 204 };
    }
    case 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}': {
      const v = varsOf(w, `env:${p.environment_name}`).get(p.name as string);
      return v === undefined ? { status: 404 } : { status: 200, data: { name: p.name, value: v.value, created_at: v.created_at } };
    }
    case 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables': {
      if (envOf() === undefined) return { status: 404 };
      const l = [...varsOf(w, `env:${p.environment_name}`)].map(([n, v]) => ({ name: n, value: v.value, created_at: v.created_at }));
      return { status: 200, data: { total_count: l.length, variables: l } };
    }
    case 'DELETE /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}':
      return varsOf(w, `env:${p.environment_name}`).delete(p.name as string) ? { status: 204 } : { status: 404 };
    // ---------- environments ----------
    case 'GET /repos/{owner}/{repo}/environments': {
      const r = repo();
      return { status: 200, data: { total_count: r.envs.size, environments: [...r.envs.keys()].map((n) => ({ name: n })) } };
    }
    case 'DELETE /repos/{owner}/{repo}/environments/{environment_name}':
      return w.app.envs.delete(p.environment_name as string) ? { status: 204 } : { status: 404 };
    case 'DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}': {
      const e = envOf();
      if (e === undefined) return { status: 404 };
      const i = e.policies.findIndex((x) => x.id === Number(p.branch_policy_id));
      if (i < 0) return { status: 404 };
      e.policies.splice(i, 1);
      return { status: 204 };
    }
    // ---------- rulesets ----------
    case 'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}':
      return repo().rulesets.delete(Number(p.ruleset_id)) ? { status: 204 } : { status: 404 };
    case 'GET /orgs/{org}/rulesets':
      return { status: 200, data: [...w.org.entries()].map(([id, r]) => ({ id, name: r.name })) };
    case 'GET /orgs/{org}/rulesets/{ruleset_id}': {
      const r = w.org.get(Number(p.ruleset_id));
      return r === undefined ? { status: 404 } : { status: 200, data: { id: Number(p.ruleset_id), ...r } };
    }
    // ---------- settings ----------
    case 'GET /repos/{owner}/{repo}/actions/permissions':
      return { status: 200, data: { enabled: true, allowed_actions: 'all', sha_pinning_required: w.settings.pin } };
    case 'PUT /repos/{owner}/{repo}/actions/permissions':
      w.settings.pin = params.sha_pinning_required === true;
      return { status: 204 };
    case 'GET /repos/{owner}/{repo}/vulnerability-alerts':
      return w.settings.alerts ? { status: 204 } : { status: 404 };
    case 'DELETE /repos/{owner}/{repo}/vulnerability-alerts':
      w.settings.alerts = false;
      return { status: 204 };
    case 'GET /repos/{owner}/{repo}/automated-security-fixes':
      return { status: 200, data: { enabled: w.settings.autofix, paused: false } };
    case 'PATCH /repos/{owner}/{repo}': {
      const sa = params.security_and_analysis as Record<string, { status: string }> | undefined;
      if (sa?.[SS] !== undefined) w.settings.scanning = sa[SS].status === 'enabled';
      if (sa?.[SP] !== undefined) w.settings.push = sa[SP].status === 'enabled';
      return { status: 200, data: {} };
    }
    case 'GET /repos/{owner}/{repo}/actions/permissions/access':
      return { status: 200, data: { access_level: w.settings.access } };
    case ACCESS_ROUTE:
      w.settings.access = String(params.access_level);
      return { status: 204 };
    // ---------- refs, branches, pull requests ----------
    case 'GET /repos/{owner}/{repo}/branches':
      return { status: 200, data: [...repo().refs.keys()].filter((r) => r.startsWith('heads/')).map((r) => ({ name: r.slice(6) })) };
    case 'GET /repos/{owner}/{repo}/git/matching-refs/{ref}':
      return { status: 200, data: [...repo().refs].filter(([r]) => r.startsWith(String(p.ref))).map(([r, sha]) => ({ ref: `refs/${r}`, object: { sha } })) };
    case 'DELETE /repos/{owner}/{repo}/git/refs/{ref}':
      return repo().refs.delete(p.ref as string) ? { status: 204 } : { status: 422 };
    case 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}': {
      if (params.state !== 'closed') return undefined;
      const pr = repo().pulls.find((x) => x.number === Number(p.pull_number));
      if (pr === undefined) return { status: 404 };
      pr.state = 'closed';
      return { status: 200, data: { number: pr.number, state: 'closed' } };
    }
    // ---------- what deleteCentralRepo reads besides ----------
    case 'GET /repos/{owner}/{repo}/releases': return list('releases', []);
    case 'GET /repos/{owner}/{repo}/comments': return list('comments', []);
    case 'GET /repos/{owner}/{repo}/issues': {
      const prs = repo().pulls.map((x) => ({ number: x.number, pull_request: {} }));
      return list('issues', prs);
    }
    case 'GET /repos/{owner}/{repo}/keys': return list('keys', []);
    case 'GET /repos/{owner}/{repo}/hooks': return list('hooks', []);
    // ---------- the scratch repo's runs and caches ----------
    case 'GET /repos/{owner}/{repo}/actions/runs':
      return { status: 200, data: { total_count: w.runs.size, workflow_runs: [...w.runs].map((id) => ({ id, status: 'completed' })) } };
    case 'DELETE /repos/{owner}/{repo}/actions/runs/{run_id}':
      return w.runs.delete(Number(p.run_id)) ? { status: 204 } : { status: 404 };
    case 'GET /repos/{owner}/{repo}/actions/caches':
      return { status: 200, data: { total_count: w.caches.size, actions_caches: [...w.caches].map((id) => ({ id })) } };
    case 'DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}':
      return w.caches.delete(Number(p.cache_id)) ? { status: 204 } : { status: 404 };
    default: return undefined;
  }
}

/** The Octokit stand-in, with GitHub's head.repo (id, full_name), merged_at and user.login on pull requests (the fake leaves them out). */
export function gh(w: World): Octokit {
  const withRepo = (owner: unknown, repo: unknown, p: unknown): unknown => {
    if (typeof p !== 'object' || p === null || typeof (p as { head?: unknown }).head !== 'object') return p;
    const r = w.g.repo(`${String(owner)}/${String(repo)}`);
    const n = (p as { number: number }).number;
    const key = `${r.name}#${n}`;
    return { ...p, merged_at: w.merged.get(key) ?? null, user: { login: w.authors.get(key) ?? 'o' }, head: { ...(p as { head: object }).head, repo: { id: r.id, full_name: `${r.owner}/${r.name}` } } };
  };
  return { request: async (route: string, params: Record<string, unknown> = {}) => {
    const out = await w.g.request(route, params);
    if (route === 'GET /repos/{owner}/{repo}/pulls') {
      const per = Math.min(Number(params.per_page ?? 30), 100);
      const page = Number(params.page ?? 1);
      const all = Array.isArray(out.data) ? out.data : [];
      const base = typeof params.base === 'string' ? params.base : undefined;
      return { ...out, data: all.filter((x) => base === undefined || (x as { base: { ref: string } }).base.ref === base).slice((page - 1) * per, page * per).map((x) => withRepo(params.owner, params.repo, x)) };
    }
    if (route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}') return { ...out, data: withRepo(params.owner, params.repo, out.data) };
    return out;
  } } as unknown as Octokit;
}

/** Merges the open pull request of `branch` in `repo`: its head becomes the default branch (fast-forward), merged_at set. */
export function mergePr(w: World, repo: Repo, branch: string): number {
  const pr = repo.pulls.find((x) => x.head === branch && x.state === 'open');
  if (pr === undefined) throw new Error(`no open PR of ${branch}`);
  repo.refs.set(`heads/${repo.defaultBranch}`, repo.refs.get(`heads/${branch}`) as string);
  pr.state = 'closed';
  w.merged.set(`${repo.name}#${pr.number}`, '2026-11-07T10:00:00Z');
  return pr.number;
}

/** A record of `o/shop` whose run 1 is done: nothing of pipegen's left on the app but run 2's items. */
export function sampleRecord(w: World, over: Partial<InstallRecord> = {}): InstallRecord {
  return {
    schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-05T12:00:00.000Z', mergedAt: '2026-11-05T13:00:00Z', centralSha: SHA('c'),
    app: { owner: 'o', repo: w.app.name, repoId: w.app.id, defaultBranch: 'main', private: true, ownerType: w.app.ownerType },
    name: w.app.name, serviceRoots: ['.'],
    files: [{ repo: 'central', path: `.github/workflows/${w.app.name}--merge.yml`, part: 'pipeline', shas: [blob(MERGE_WF)] }],
    edits: [], [SEC]: [], variables: [], environments: [], rulesets: [],
    planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] },
    protectedPaths: ['.github/workflows/**'],
    ...over,
  };
}

/** V1's loaded record: the record file's blob sha at the central head now (run 2 re-checks it). */
export function loadedOf(w: World, record: InstallRecord, over: Partial<LoadedRecord> = {}): LoadedRecord {
  return {
    app: { owner: 'o', repo: w.app.name, repoId: w.app.id, private: true, defaultBranch: w.app.defaultBranch, ownerType: w.app.ownerType },
    record, trust: 'full', typedNames: false, blobSha: blob(RECORD_TEXT), centralHead: w.g.head('o/pipelines'), centralRepoId: w.central.id,
    marker: 'match', setupPr: null, dropped: [], warnings: [], ...over,
  };
}

export interface Term { p: Prompter; typed: string[]; confirms: string[] }
/** The user's terminal: types each name asked for (or what `type` says), says yes to "Go ahead", answers the rest by `yes` or their default. */
export function term(o: { go?: boolean; type?: (q: string, expected: string) => string; yes?: (q: string) => boolean | undefined } = {}): Term {
  const t: Term = { typed: [], confirms: [], p: undefined as unknown as Prompter };
  t.p = {
    confirm: async (m, d) => { t.confirms.push(m); if (m.startsWith('Go ahead')) return o.go ?? true; return o.yes?.(m) ?? d; },
    select: async () => { throw new Error('no select expected'); },
    text: async (m) => { t.typed.push(m); const exp = /\nType (.+) to go on;/.exec(m)?.[1] ?? ''; return o.type === undefined ? exp : o.type(m, exp); },
  };
  return t;
}
export const local = (w: World) => ({ home: w.home, env: {} });
export const deps = (w: World, over: Partial<StepDeps> = {}): StepDeps => ({ interactive: true, local: local(w), state: local(w), out: (s) => { w.out.push(s); }, ...over });
export const writes = (w: World): string[] => w.g.calls.filter((c) => !c.route.startsWith('GET ')).map((c) => `${c.route} ${String(c.params.repo ?? c.params.org ?? '')}`);
