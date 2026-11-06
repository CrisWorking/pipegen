// An in-memory GitHub for the delivery tests (G10): repos with refs, commits, flat trees and blobs (real git blob shas), pull
// requests, repo and environment secrets, environments with branch policies, and branch rules. It answers `gh.request(route, params)`
// the way Octokit does ({ status, data, headers }; errors carry `status` and `response.headers`) and logs every call, so a test can
// assert which routes were (and were not) sent. No network.
import { createHash, randomBytes } from 'node:crypto';
import type { Octokit } from '@octokit/rest';
import { gitBlobSha } from '../../src/create/guard.js';

export interface Entry { mode: string; type: 'blob' | 'tree'; sha: string }
export interface Env {
  id: number; created_at: string; wait_timer: number; prevent_self_review: boolean; reviewers: { type: 'User' | 'Team'; id: number }[];
  can_admins_bypass: boolean; deployment_branch_policy: { protected_branches: boolean; custom_branch_policies: boolean } | null;
  policies: { id: number; name: string; type: 'branch' | 'tag' }[];
  /** The environment's stored secret names, each with its created_at. */
  stored: Map<string, string>;
}
export interface Pull { number: number; head: string; base: string; title: string; body: string; state: 'open' | 'closed'; html_url: string }
export interface Repo {
  owner: string; name: string; id: number; private: boolean; ownerType: 'User' | 'Organization'; defaultBranch: string;
  refs: Map<string, string>; commits: Map<string, { tree: string; parents: string[]; message: string }>; trees: Map<string, Map<string, Entry>>;
  blobs: Map<string, string>; pulls: Pull[];
  /** The repo's stored secret names, each with its created_at. */
  stored: Map<string, string>;
  envs: Map<string, Env>; rules: unknown[];
  /** Rulesets by id (GET …/rulesets/{id}). */
  rulesets: Map<number, Record<string, unknown>>;
}
export interface Call { route: string; params: Record<string, unknown> }
type Hook = (call: Call) => { status: number; data?: unknown; headers?: Record<string, string> } | undefined;

const sha1 = (s: string): string => createHash('sha1').update(s).digest('hex');
const fail = (status: number, message = 'Not Found', headers: Record<string, string> = {}): never => {
  throw Object.assign(new Error(message), { status, response: { status, headers, data: { message } } });
};

export class FakeGitHub {
  readonly repos = new Map<string, Repo>();
  readonly calls: Call[] = [];
  readonly publicKey = randomBytes(32).toString('base64');
  hooks: Hook[] = [];
  #clock = Date.UTC(2026, 10, 5, 12, 0, 0);
  #ids = 1000;

  /** A repo with one commit holding `files` on its default branch. */
  addRepo(fullName: string, opts: { files?: Record<string, string>; private?: boolean; ownerType?: 'User' | 'Organization'; defaultBranch?: string; modes?: Record<string, string> } = {}): Repo {
    const [owner, name] = fullName.split('/') as [string, string];
    const r: Repo = {
      owner, name, id: this.#ids++, private: opts.private ?? true, ownerType: opts.ownerType ?? 'User', defaultBranch: opts.defaultBranch ?? 'main',
      refs: new Map(), commits: new Map(), trees: new Map(), blobs: new Map(), pulls: [], stored: new Map(), envs: new Map(), rules: [], rulesets: new Map(),
    };
    this.repos.set(fullName.toLowerCase(), r);
    const flat = new Map<string, Entry>();
    for (const [path, content] of Object.entries(opts.files ?? {})) flat.set(path, { mode: opts.modes?.[path] ?? '100644', type: 'blob', sha: this.#blob(r, content) });
    const tree = this.#tree(r, flat);
    const commit = this.#commit(r, tree, [], 'initial');
    r.refs.set(`heads/${r.defaultBranch}`, commit);
    return r;
  }

  repo(fullName: string): Repo { const r = this.repos.get(fullName.toLowerCase()); if (r === undefined) throw new Error(`no repo ${fullName}`); return r; }
  head(fullName: string, branch?: string): string { const r = this.repo(fullName); return r.refs.get(`heads/${branch ?? r.defaultBranch}`) as string; }
  /** The files (path → text) at a commit. */
  filesAt(fullName: string, commit: string): Map<string, string> {
    const r = this.repo(fullName);
    const tree = r.trees.get(r.commits.get(commit)?.tree as string) as Map<string, Entry>;
    return new Map([...tree].filter(([, e]) => e.type === 'blob').map(([p, e]) => [p, r.blobs.get(e.sha) as string]));
  }
  modeAt(fullName: string, commit: string, path: string): string | undefined {
    const r = this.repo(fullName);
    return r.trees.get(r.commits.get(commit)?.tree as string)?.get(path)?.mode;
  }
  /** The commits from `head` back to (not including) `stop`, newest first. */
  history(fullName: string, head: string, stop?: string): { sha: string; message: string; parents: string[] }[] {
    const r = this.repo(fullName);
    const out: { sha: string; message: string; parents: string[] }[] = [];
    for (let c: string | undefined = head; c !== undefined && c !== stop; c = r.commits.get(c)?.parents[0]) {
      const x = r.commits.get(c);
      if (x === undefined) break;
      out.push({ sha: c, message: x.message, parents: x.parents });
    }
    return out;
  }
  /** Adds a commit on a branch (someone else's change). */
  commitOn(fullName: string, branch: string, files: Record<string, string | null>, message = 'change'): string {
    const r = this.repo(fullName);
    const parent = r.refs.get(`heads/${branch}`) as string;
    const flat = new Map(r.trees.get(r.commits.get(parent)?.tree as string));
    for (const [p, c] of Object.entries(files)) { if (c === null) flat.delete(p); else flat.set(p, { mode: '100644', type: 'blob', sha: this.#blob(r, c) }); }
    const sha = this.#commit(r, this.#tree(r, flat), [parent], message);
    r.refs.set(`heads/${branch}`, sha);
    return sha;
  }
  routes(): string[] { return this.calls.map((c) => c.route); }
  now(): string { this.#clock += 1000; return new Date(this.#clock).toISOString(); }

  #blob(r: Repo, content: string): string { const sha = gitBlobSha(content); r.blobs.set(sha, content); return sha; }
  #tree(r: Repo, flat: Map<string, Entry>): string {
    const sha = sha1(JSON.stringify([...flat].sort(([a], [b]) => (a < b ? -1 : 1))));
    r.trees.set(sha, flat);
    return sha;
  }
  #commit(r: Repo, tree: string, parents: string[], message: string): string {
    const sha = sha1(JSON.stringify({ tree, parents, message, n: this.#ids++ }));
    r.commits.set(sha, { tree, parents, message });
    return sha;
  }
  #ancestor(r: Repo, anc: string, of: string): boolean {
    const seen = new Set<string>();
    const todo = [of];
    while (todo.length > 0) {
      const c = todo.pop() as string;
      if (c === anc) return true;
      if (seen.has(c)) continue;
      seen.add(c);
      todo.push(...(r.commits.get(c)?.parents ?? []));
    }
    return false;
  }
  #env(r: Repo, name: string): Env { const e = r.envs.get(name); if (e === undefined) fail(404); return e as Env; }
  #envView(name: string, e: Env): unknown {
    const rules: unknown[] = [];
    if (e.wait_timer > 0) rules.push({ type: 'wait_timer', wait_timer: e.wait_timer });
    if (e.reviewers.length > 0) rules.push({ type: 'required_reviewers', prevent_self_review: e.prevent_self_review, reviewers: e.reviewers.map((x) => ({ type: x.type, reviewer: { id: x.id } })) });
    if (e.deployment_branch_policy !== null) rules.push({ type: 'branch_policy' });
    return { id: e.id, name, created_at: e.created_at, updated_at: e.created_at, can_admins_bypass: e.can_admins_bypass, protection_rules: rules, deployment_branch_policy: e.deployment_branch_policy };
  }

  /** The Octokit stand-in. */
  octokit(): Octokit {
    return { request: async (route: string, params: Record<string, unknown> = {}) => this.request(route, params) } as unknown as Octokit;
  }

  async request(route: string, params: Record<string, unknown>): Promise<{ status: number; data: unknown; headers: Record<string, string> }> {
    const call = { route, params: { ...params } };
    this.calls.push(call);
    for (const h of this.hooks) {
      const out = h(call);
      if (out !== undefined) {
        if (out.status >= 400) fail(out.status, 'hooked', out.headers ?? {});
        return { status: out.status, data: out.data, headers: out.headers ?? {} };
      }
    }
    params = call.params;   // a hook may change what GitHub receives (a fault the test injects)
    const ok = (data: unknown, status = 200) => ({ status, data, headers: {} });
    const r = this.repos.get(`${String(params.owner)}/${String(params.repo)}`.toLowerCase());
    if (r === undefined) fail(404);
    const repo = r as Repo;
    const p = params as Record<string, any>;
    switch (route) {
      case 'GET /repos/{owner}/{repo}':
        return ok({ id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, private: repo.private, default_branch: repo.defaultBranch, owner: { login: repo.owner, type: repo.ownerType } });
      case 'GET /repos/{owner}/{repo}/git/ref/{ref}': {
        const sha = repo.refs.get(p.ref);
        if (sha === undefined) fail(404);
        return ok({ ref: `refs/${p.ref}`, object: { sha, type: 'commit' } });
      }
      case 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}': {
        const c = repo.commits.get(p.commit_sha);
        if (c === undefined) fail(404);
        return ok({ sha: p.commit_sha, tree: { sha: c?.tree }, parents: c?.parents.map((s) => ({ sha: s })), message: c?.message });
      }
      case 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}': {
        const t = repo.trees.get(p.tree_sha);
        if (t === undefined) fail(404);
        return ok({ sha: p.tree_sha, truncated: false, tree: [...(t as Map<string, Entry>)].map(([path, e]) => ({ path, ...e })) });
      }
      case 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}': {
        const b = repo.blobs.get(p.file_sha);
        if (b === undefined) fail(404);
        return ok({ sha: p.file_sha, encoding: 'base64', content: Buffer.from(b as string, 'utf8').toString('base64'), size: Buffer.byteLength(b as string) });
      }
      case 'POST /repos/{owner}/{repo}/git/trees': {
        const base = p.base_tree === undefined ? new Map<string, Entry>() : new Map(repo.trees.get(p.base_tree));
        for (const e of p.tree as { path: string; mode: string; type: 'blob'; content?: string; sha?: string | null }[]) {
          if (e.sha === null) base.delete(e.path);
          else base.set(e.path, { mode: e.mode, type: 'blob', sha: e.content !== undefined ? this.#blob(repo, e.content) : e.sha as string });
        }
        return ok({ sha: this.#tree(repo, base) }, 201);
      }
      case 'POST /repos/{owner}/{repo}/git/commits':
        return ok({ sha: this.#commit(repo, p.tree, p.parents, p.message) }, 201);
      case 'POST /repos/{owner}/{repo}/git/refs': {
        const ref = String(p.ref).replace(/^refs\//, '');
        if (repo.refs.has(ref)) fail(422, 'Reference already exists');
        repo.refs.set(ref, p.sha);
        return ok({ ref: p.ref, object: { sha: p.sha } }, 201);
      }
      case 'PATCH /repos/{owner}/{repo}/git/refs/{ref}': {
        const cur = repo.refs.get(p.ref);
        if (cur === undefined) fail(422, 'Reference does not exist');
        if (repo.rules.length > 0 && p.ref === `heads/${repo.defaultBranch}`) fail(422, 'Repository rule violations found');
        if (p.force !== true && !this.#ancestor(repo, cur as string, p.sha)) fail(422, 'Update is not a fast forward');
        repo.refs.set(p.ref, p.sha);
        return ok({ ref: `refs/${p.ref}`, object: { sha: p.sha } });
      }
      case 'GET /repos/{owner}/{repo}/compare/{basehead}': {
        const [base, head] = String(p.basehead).split('...') as [string, string];
        const b = repo.refs.get(`heads/${base}`) ?? base;
        const h = repo.refs.get(`heads/${head}`) ?? head;
        if (!repo.commits.has(b) || !repo.commits.has(h)) fail(404);
        const status = b === h ? 'identical' : this.#ancestor(repo, h, b) ? 'behind' : this.#ancestor(repo, b, h) ? 'ahead' : 'diverged';
        // the files the head changed against the base (exact when head is ahead; a diverged answer lists both sides' changes)
        const tb = repo.trees.get(repo.commits.get(b)?.tree as string) as Map<string, Entry>;
        const th = repo.trees.get(repo.commits.get(h)?.tree as string) as Map<string, Entry>;
        const files = [...new Set([...tb.keys(), ...th.keys()])].filter((x) => tb.get(x)?.sha !== th.get(x)?.sha).map((filename) => ({ filename, status: 'modified' }));
        return ok({ status, files });
      }
      case 'GET /repos/{owner}/{repo}/rules/branches/{branch}':
        return ok(repo.rules);
      case 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}': {
        const rs = repo.rulesets.get(Number(p.ruleset_id));
        if (rs === undefined) fail(404);
        return ok({ id: Number(p.ruleset_id), ...rs });
      }
      case 'GET /repos/{owner}/{repo}/pulls': {
        const head = String(p.head ?? '');
        return ok(repo.pulls.filter((x) => (p.state === undefined || p.state === 'all' || x.state === p.state) && (head === '' || `${repo.owner}:${x.head}` === head)).map((x) => ({ number: x.number, html_url: x.html_url, state: x.state, head: { ref: x.head }, base: { ref: x.base }, body: x.body, title: x.title })));
      }
      case 'POST /repos/{owner}/{repo}/pulls': {
        if (repo.pulls.some((x) => x.state === 'open' && x.head === p.head)) fail(422, 'A pull request already exists');
        const pr: Pull = { number: repo.pulls.length + 1, head: p.head, base: p.base, title: p.title, body: p.body ?? '', state: 'open', html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${repo.pulls.length + 1}` };
        repo.pulls.push(pr);
        return ok({ number: pr.number, html_url: pr.html_url }, 201);
      }
      case 'GET /repos/{owner}/{repo}/pulls/{pull_number}': {
        const pr = repo.pulls.find((x) => x.number === Number(p.pull_number));
        if (pr === undefined) fail(404);
        return ok({ number: pr?.number, html_url: pr?.html_url, body: pr?.body, state: pr?.state, head: { ref: pr?.head }, base: { ref: pr?.base } });
      }
      case 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}': {
        const pr = repo.pulls.find((x) => x.number === Number(p.pull_number));
        if (pr === undefined) fail(404);
        if (typeof p.body === 'string') (pr as Pull).body = p.body;
        if (typeof p.title === 'string') (pr as Pull).title = p.title;
        return ok({ number: pr?.number, html_url: pr?.html_url });
      }
      case 'GET /repos/{owner}/{repo}/actions/secrets/public-key':
        return ok({ key_id: 'kid-1', key: this.publicKey });
      case 'GET /repos/{owner}/{repo}/actions/secrets/{secret_name}': {
        const at = repo.stored.get(p.secret_name);
        if (at === undefined) fail(404);
        return ok({ name: p.secret_name, created_at: at, updated_at: at });
      }
      case 'PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}': {
        const had = repo.stored.has(p.secret_name);
        if (!had) repo.stored.set(p.secret_name, this.now());
        return ok({}, had ? 204 : 201);
      }
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}':
        return ok(this.#envView(p.environment_name, this.#env(repo, p.environment_name)));
      case 'PUT /repos/{owner}/{repo}/environments/{environment_name}': {
        const e = repo.envs.get(p.environment_name) ?? { id: this.#ids++, created_at: this.now(), wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() };
        // as GitHub does: a setting the PUT leaves out is reset to its default (wait 0, no reviewers, admins may bypass, any branch)
        e.wait_timer = p.wait_timer ?? 0;
        e.prevent_self_review = p.prevent_self_review ?? false;
        e.reviewers = p.reviewers ?? [];
        e.can_admins_bypass = p.can_admins_bypass ?? true;
        e.deployment_branch_policy = p.deployment_branch_policy ?? null;
        repo.envs.set(p.environment_name, e);
        return ok(this.#envView(p.environment_name, e));
      }
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies': {
        const e = this.#env(repo, p.environment_name);
        return ok({ total_count: e.policies.length, branch_policies: e.policies.map((x) => ({ ...x })) });
      }
      case 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies': {
        const e = this.#env(repo, p.environment_name);
        if (e.deployment_branch_policy?.custom_branch_policies !== true) fail(404);
        const pol = { id: this.#ids++, name: p.name, type: p.type ?? 'branch' };
        e.policies.push(pol);
        return ok(pol, 200);
      }
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/public-key':
        this.#env(repo, p.environment_name);
        return ok({ key_id: 'kid-env', key: this.publicKey });
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}': {
        const at = this.#env(repo, p.environment_name).stored.get(p.secret_name);
        if (at === undefined) fail(404);
        return ok({ name: p.secret_name, created_at: at, updated_at: at });
      }
      case 'PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}': {
        const e = this.#env(repo, p.environment_name);
        const had = e.stored.has(p.secret_name);
        if (!had) e.stored.set(p.secret_name, this.now());
        return ok({}, had ? 204 : 201);
      }
      default:
        return fail(404, `fake GitHub has no route ${route}`);
    }
  }
}
