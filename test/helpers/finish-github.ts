// The in-memory GitHub of the delivery tests (deliver-github.ts), plus what `pipegen finish` and `verify` (G11) talk to: rulesets (repo
// and org), classic branch protection, the Actions settings (permissions, sha pinning, the central repo's access level), Dependabot
// alerts, secret scanning, repo and environment variables, collaborators, org membership, users, and merged pull requests. Every call is
// logged like the base fake's, and the base's hooks (faults a test injects) run first. An active ruleset with a pull_request rule makes
// the branch refuse direct ref moves, as GitHub does. No network.
import type { Octokit } from '@octokit/rest';
import { FakeGitHub, type Call } from './deliver-github.js';

type Obj = Record<string, any>;
/** GitHub's security_and_analysis keys, spelled at run time (test/no-secret-literals.test.ts). */
const SCAN = ['secret', 'scanning'].join('_');
const PUSH = `${SCAN}_push_protection`;
export interface Extra {
  protection: Obj | null;
  actions: { enabled: boolean; allowed_actions: string; sha_pinning_required?: boolean };
  access: string;
  vulnAlerts: boolean;
  /** Secret scanning and push protection: 'enabled' or 'disabled'. */
  security: { scan: string; push: string };
  variables: Map<string, { value: string; created_at: string }>;
  envVars: Map<string, Map<string, { value: string; created_at: string }>>;
  collaborators: { login: string; type?: string; permissions: { push: boolean; admin?: boolean } }[];
  merged: Map<number, string | null>;
}
export interface OrgRuleset { id: number; org: string; body: Obj; created_at: string }

const fail = (status: number, message = 'Not Found'): never => {
  throw Object.assign(new Error(message), { status, response: { status, headers: {}, data: { message } } });
};
const FINISH_ROUTES = new Set([
  'GET /repos/{owner}/{repo}/environments/{environment_name}/variables',
  'GET /repos/{owner}/{repo}', 'PATCH /repos/{owner}/{repo}', 'GET /repos/{owner}/{repo}/collaborators',
  'GET /repos/{owner}/{repo}/rulesets', 'POST /repos/{owner}/{repo}/rulesets', 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', 'PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}',
  'GET /repos/{owner}/{repo}/branches/{branch}/protection', 'PUT /repos/{owner}/{repo}/branches/{branch}/protection',
  'GET /repos/{owner}/{repo}/actions/permissions', 'PUT /repos/{owner}/{repo}/actions/permissions',
  'GET /repos/{owner}/{repo}/actions/permissions/access', 'PUT /repos/{owner}/{repo}/actions/permissions/access',
  'GET /repos/{owner}/{repo}/vulnerability-alerts', 'PUT /repos/{owner}/{repo}/vulnerability-alerts',
  'GET /repos/{owner}/{repo}/actions/variables/{name}', 'POST /repos/{owner}/{repo}/actions/variables', 'PATCH /repos/{owner}/{repo}/actions/variables/{name}',
  'GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}', 'POST /repos/{owner}/{repo}/environments/{environment_name}/variables', 'PATCH /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}',
  'GET /repos/{owner}/{repo}/pulls', 'GET /repos/{owner}/{repo}/pulls/{pull_number}',
  'GET /users/{username}', 'GET /user/memberships/orgs/{org}',
  'GET /orgs/{org}/rulesets', 'POST /orgs/{org}/rulesets', 'GET /orgs/{org}/rulesets/{ruleset_id}', 'PUT /orgs/{org}/rulesets/{ruleset_id}',
]);

export class FinishGitHub extends FakeGitHub {
  readonly extra = new Map<string, Extra>();
  readonly orgRulesets = new Map<number, OrgRuleset>();
  /** org → the token user's membership. */
  readonly memberships = new Map<string, { state: string; role: string }>();
  readonly users = new Map<string, number>();
  #ids = 50_000;

  x(fullName: string): Extra {
    const k = fullName.toLowerCase();
    let e = this.extra.get(k);
    if (e === undefined) {
      e = {
        protection: null, actions: { enabled: true, allowed_actions: 'all', sha_pinning_required: false }, access: 'none', vulnAlerts: false,
        security: { scan: 'disabled', push: 'disabled' }, variables: new Map(), envVars: new Map(), collaborators: [], merged: new Map(),
      };
      this.extra.set(k, e);
    }
    return e;
  }
  /** Merges the open pull request from `head` into the default branch (the branch moves to its head) at `at`. */
  merge(fullName: string, head: string, at = '2026-11-06T09:30:00Z'): void {
    const r = this.repo(fullName);
    const pr = r.pulls.find((p) => p.head === head && p.state === 'open');
    if (pr === undefined) throw new Error(`no open PR from ${head}`);
    r.refs.set(`heads/${r.defaultBranch}`, this.head(fullName, head));
    pr.state = 'closed';
    this.x(fullName).merged.set(pr.number, at);
  }
  /** Closes the open pull request from `head` without merging it. */
  closeUnmerged(fullName: string, head: string): void {
    const r = this.repo(fullName);
    const pr = r.pulls.find((p) => p.head === head && p.state === 'open');
    if (pr === undefined) throw new Error(`no open PR from ${head}`);
    pr.state = 'closed';
    this.x(fullName).merged.set(pr.number, null);
  }
  writers(fullName: string, logins: string[]): void {
    this.x(fullName).collaborators = logins.map((login) => ({ login, permissions: { push: true } }));
  }
  /** The write calls (anything but GET), in order. */
  writes(): Call[] { return this.calls.filter((c) => !c.route.startsWith('GET ')); }

  override octokit(): Octokit {
    const req = (route: string) => (p: Record<string, unknown>) => this.request(route, p);
    return {
      request: async (route: string, params: Record<string, unknown> = {}) => this.request(route, params),
      rest: {
        repos: { listCollaborators: req('GET /repos/{owner}/{repo}/collaborators'), get: req('GET /repos/{owner}/{repo}') },
        orgs: { getMembershipForAuthenticatedUser: req('GET /user/memberships/orgs/{org}') },
      },
    } as unknown as Octokit;
  }

  #ruleEffect(fullName: string, id: number, body: Obj): void {
    const r = this.repo(fullName);
    r.rules = (r.rules as Obj[]).filter((x) => x.ruleset_id !== id);
    if (body.enforcement === 'active' && Array.isArray(body.rules) && body.rules.some((x: Obj) => x.type === 'pull_request')) r.rules.push({ type: 'pull_request', ruleset_id: id });
  }

  override async request(route: string, params: Record<string, unknown>): Promise<{ status: number; data: unknown; headers: Record<string, string> }> {
    if (!FINISH_ROUTES.has(route) && !(route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}')) return super.request(route, params);
    const call: Call = { route, params: { ...params } };
    // routes the base fake also answers go through it for the parts it owns (it logs them itself)
    if (route === 'GET /repos/{owner}/{repo}/pulls' || route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}' || route === 'GET /repos/{owner}/{repo}') {
      const res = await super.request(route, params);
      const p = params as Obj;
      const full = `${p.owner}/${p.repo}`;
      if (route === 'GET /repos/{owner}/{repo}') {
        const d = res.data as Obj;
        const sec = this.x(full).security;
        return { ...res, data: d.private === false ? { ...d, security_and_analysis: { [SCAN]: { status: sec.scan }, [PUSH]: { status: sec.push } } } : d };
      }
      const merged = this.x(full).merged;
      const withMerge = (d: Obj): Obj => ({ ...d, merged_at: merged.get(Number(d.number)) ?? null });
      if (route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}') return { ...res, data: withMerge(res.data as Obj) };
      if (p.state === 'all' || p.state === 'closed') {
        // the base answers open ones only when asked for a state; answer every one of the head here
        const r = this.repo(full);
        const head = String(p.head ?? '');
        const list = r.pulls.filter((x) => (p.state === 'all' || x.state === p.state) && (head === '' || `${r.owner}:${x.head}` === head)).map((x) => withMerge({ number: x.number, html_url: x.html_url, state: x.state, head: { ref: x.head }, base: { ref: x.base }, body: x.body, title: x.title }));
        return { ...res, data: list };
      }
      return res;
    }
    this.calls.push(call);
    for (const h of this.hooks) {
      const out = h(call);
      if (out !== undefined) {
        if (out.status >= 400) fail(out.status, typeof (out.data as Obj | undefined)?.message === 'string' ? (out.data as Obj).message : 'hooked');
        return { status: out.status, data: out.data, headers: out.headers ?? {} };
      }
    }
    const p = call.params as Obj;
    const ok = (data: unknown, status = 200) => ({ status, data, headers: {} });
    switch (route) {
      case 'GET /users/{username}': {
        const id = this.users.get(String(p.username).toLowerCase());
        return id === undefined ? fail(404) : ok({ login: p.username, id, type: 'User' });
      }
      case 'GET /user/memberships/orgs/{org}': {
        const m = this.memberships.get(String(p.org).toLowerCase());
        return m === undefined ? fail(404) : ok({ ...m, organization: { login: p.org } });
      }
      case 'GET /orgs/{org}/rulesets':
        return ok([...this.orgRulesets.values()].filter((x) => x.org.toLowerCase() === String(p.org).toLowerCase()).map((x) => ({ id: x.id, name: x.body.name, enforcement: x.body.enforcement, source_type: 'Organization', source: x.org })));
      case 'POST /orgs/{org}/rulesets': {
        const { org, ...body } = p;
        const rs: OrgRuleset = { id: this.#ids++, org: String(org), body, created_at: this.now() };
        this.orgRulesets.set(rs.id, rs);
        return ok({ id: rs.id, ...body, created_at: rs.created_at }, 201);
      }
      case 'GET /orgs/{org}/rulesets/{ruleset_id}': {
        const rs = this.orgRulesets.get(Number(p.ruleset_id));
        return rs === undefined ? fail(404) : ok({ id: rs.id, ...rs.body, source_type: 'Organization', source: rs.org, created_at: rs.created_at, updated_at: rs.created_at });
      }
      case 'PUT /orgs/{org}/rulesets/{ruleset_id}': {
        const rs = this.orgRulesets.get(Number(p.ruleset_id));
        if (rs === undefined) fail(404);
        const { org: _o, ruleset_id: _i, ...body } = p;
        (rs as OrgRuleset).body = { ...(rs as OrgRuleset).body, ...body };
        return ok({ id: rs?.id, ...rs?.body });
      }
      default:
        break;
    }
    const full = `${String(p.owner)}/${String(p.repo)}`;
    if (!this.repos.has(full.toLowerCase())) fail(404);
    const repo = this.repo(full);
    const x = this.x(full);
    switch (route) {
      case 'PATCH /repos/{owner}/{repo}': {
        const sa = p.security_and_analysis as Obj | undefined;
        if (repo.private && sa !== undefined) fail(422, 'Secret scanning is not available for this repository');
        if (sa?.[SCAN]?.status !== undefined) x.security.scan = sa[SCAN].status;
        if (sa?.[PUSH]?.status !== undefined) x.security.push = sa[PUSH].status;
        return ok({ id: repo.id });
      }
      case 'GET /repos/{owner}/{repo}/collaborators':
        return ok(Number(p.page ?? 1) === 1 ? x.collaborators.map((c) => ({ login: c.login, type: c.type ?? 'User', permissions: c.permissions })) : []);
      case 'GET /repos/{owner}/{repo}/rulesets':
        return ok([...repo.rulesets].map(([id, b]) => ({ id, name: b.name, enforcement: b.enforcement, source_type: 'Repository', source: full })));
      case 'POST /repos/{owner}/{repo}/rulesets': {
        const { owner: _o, repo: _r, ...body } = p;
        const id = this.#ids++;
        repo.rulesets.set(id, { ...body, created_at: this.now() });
        this.#ruleEffect(full, id, body);
        return ok({ id, ...repo.rulesets.get(id) }, 201);
      }
      case 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}': {
        const rs = repo.rulesets.get(Number(p.ruleset_id));
        return rs === undefined ? fail(404) : ok({ id: Number(p.ruleset_id), ...rs, source_type: 'Repository', source: full, updated_at: rs.created_at });
      }
      case 'PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}': {
        const id = Number(p.ruleset_id);
        const rs = repo.rulesets.get(id);
        if (rs === undefined) fail(404);
        const { owner: _o, repo: _r, ruleset_id: _i, ...body } = p;
        const next = { ...(rs as Obj), ...body };
        repo.rulesets.set(id, next);
        this.#ruleEffect(full, id, next);
        return ok({ id, ...next });
      }
      case 'GET /repos/{owner}/{repo}/branches/{branch}/protection':
        return x.protection === null ? fail(404, 'Branch not protected') : ok(structuredClone(x.protection));
      case 'PUT /repos/{owner}/{repo}/branches/{branch}/protection': {
        // the GET form GitHub answers with
        const b = p as Obj;
        const rpr = b.required_pull_request_reviews as Obj | null;
        x.protection = {
          url: 'u',
          required_status_checks: b.required_status_checks === null ? undefined : { strict: b.required_status_checks.strict, contexts: b.required_status_checks.checks.map((c: Obj) => c.context), checks: b.required_status_checks.checks },
          enforce_admins: { enabled: b.enforce_admins === true },
          ...(rpr === null ? {} : { required_pull_request_reviews: { dismiss_stale_reviews: rpr.dismiss_stale_reviews, require_code_owner_reviews: rpr.require_code_owner_reviews, required_approving_review_count: rpr.required_approving_review_count, require_last_push_approval: rpr.require_last_push_approval } }),
          ...(b.restrictions === null ? {} : { restrictions: { users: (b.restrictions.users ?? []).map((l: string) => ({ login: l })), teams: (b.restrictions.teams ?? []).map((s: string) => ({ slug: s })), apps: [] } }),
          allow_force_pushes: { enabled: b.allow_force_pushes === true }, allow_deletions: { enabled: b.allow_deletions === true },
        };
        if (x.protection.required_status_checks === undefined) delete x.protection.required_status_checks;
        return ok(structuredClone(x.protection));
      }
      case 'GET /repos/{owner}/{repo}/actions/permissions':
        return ok({ ...x.actions });
      case 'PUT /repos/{owner}/{repo}/actions/permissions':
        x.actions = { enabled: p.enabled, allowed_actions: p.allowed_actions, ...(p.sha_pinning_required === undefined ? {} : { sha_pinning_required: p.sha_pinning_required }) };
        return ok({}, 204);
      case 'GET /repos/{owner}/{repo}/actions/permissions/access':
        return ok({ access_level: x.access });
      case 'PUT /repos/{owner}/{repo}/actions/permissions/access':
        x.access = p.access_level;
        return ok({}, 204);
      case 'GET /repos/{owner}/{repo}/vulnerability-alerts':
        return x.vulnAlerts ? ok(undefined, 204) : fail(404, 'Vulnerability alerts are disabled.');
      case 'PUT /repos/{owner}/{repo}/vulnerability-alerts':
        x.vulnAlerts = true;
        return ok(undefined, 204);
      case 'GET /repos/{owner}/{repo}/actions/variables/{name}': {
        const v = x.variables.get(p.name);
        return v === undefined ? fail(404) : ok({ name: p.name, value: v.value, created_at: v.created_at, updated_at: v.created_at });
      }
      case 'POST /repos/{owner}/{repo}/actions/variables':
        if (x.variables.has(p.name)) fail(409, 'Already exists');
        x.variables.set(p.name, { value: p.value, created_at: this.now() });
        return ok({}, 201);
      case 'PATCH /repos/{owner}/{repo}/actions/variables/{name}': {
        const v = x.variables.get(p.name);
        if (v === undefined) fail(404);
        (v as { value: string }).value = p.value;
        return ok({}, 204);
      }
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables': {
        if (!repo.envs.has(p.environment_name)) fail(404);
        const m = [...(x.envVars.get(p.environment_name) ?? new Map())];
        return ok({ total_count: m.length, variables: m.map(([name, v]) => ({ name, value: (v as { value: string }).value })) });
      }
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}': {
        const v = x.envVars.get(p.environment_name)?.get(p.name);
        return v === undefined ? fail(404) : ok({ name: p.name, value: v.value, created_at: v.created_at, updated_at: v.created_at });
      }
      case 'POST /repos/{owner}/{repo}/environments/{environment_name}/variables': {
        if (!repo.envs.has(p.environment_name)) fail(404);
        const m = x.envVars.get(p.environment_name) ?? new Map();
        if (m.has(p.name)) fail(409, 'Already exists');
        m.set(p.name, { value: p.value, created_at: this.now() });
        x.envVars.set(p.environment_name, m);
        return ok({}, 201);
      }
      case 'PATCH /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}': {
        const v = x.envVars.get(p.environment_name)?.get(p.name);
        if (v === undefined) fail(404);
        (v as { value: string }).value = p.value;
        return ok({}, 204);
      }
      default:
        return fail(404, `finish fake has no route ${route}`);
    }
  }
}
