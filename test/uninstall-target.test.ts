// v0.2 Plan V V3 (rulings V-B5, V-B6, V-S11, V-S13, V-S16, V-N2, V-N7): the one module of src/uninstall that sends a write.
// GitHub is a fake Octokit (a request function and a log of what was sent); the prompt is a fake; nothing touches the network.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { describe, expect, it } from 'vitest';
import type { Prompter } from '../src/cli/io.js';
import { gitBlobSha } from '../src/create/guard.js';
import { centralWorkflowFile } from '../src/engine/central-path.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { requiredRulesetName } from '../src/layers/locks.js';
import { helperDescription } from '../src/proof/target.js';
import type { InstallRecord } from '../src/types.js';
import {
  askTypedName, deleteCentralRepo, goneOr, isPipegens, UNINSTALL_WRITE_ROUTES, UninstallApi, UninstallRefusal, uninstallBranch, type Owned,
} from '../src/uninstall/target.js';

const OWNER = 'acme';
const APP = { owner: OWNER, repo: 'shop', repoId: 101 };
const CENTRAL_ID = 202;
const AT = '2026-11-01T10:00:00Z';
const SHA = 'a'.repeat(40);
const PIN = 'b'.repeat(40);

interface Call { route: string; params: Record<string, unknown> }
type Handler = (route: string, params: Record<string, unknown>) => unknown;
const httpErr = (status: number, message = ''): Error => Object.assign(new Error(`HTTP ${status}`), { status, response: { data: { message }, headers: {} } });

function fakeGh(handler: Handler = () => ({})): { gh: Octokit; calls: Call[]; writes: () => Call[] } {
  const calls: Call[] = [];
  const gh = {
    request: async (route: string, params: Record<string, unknown> = {}) => {
      calls.push({ route, params });
      const data = await handler(route, params);
      return { status: 200, data, headers: {} };
    },
  };
  return { gh: gh as unknown as Octokit, calls, writes: () => calls.filter((c) => !c.route.startsWith('GET ')) };
}
const clock = () => ({ budget: newRateBudget(), sleep: async () => {}, now: () => 0 });
const api = (h?: Handler) => { const f = fakeGh(h); return { ...f, api: new UninstallApi(f.gh, APP, clock()) }; };

function prompter(answers: string[]): Prompter & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    confirm: async () => false,
    select: async <T extends string>(_m: string, _o: unknown, d: T) => d,
    text: async (msg: string) => { asked.push(msg); return answers.shift() ?? ''; },
  };
}
const typed = async (name: string) => {
  const t = await askTypedName({ prompt: prompter([name]), interactive: true }, name, `Type ${name} to go on`);
  if (t === null) throw new Error('no typed name');
  return t;
};

// ---------- live objects as GitHub gives them ----------
const liveRuleset = (over: Record<string, unknown> = {}) => ({ id: 7, name: 'pipegen', source_type: 'Repository', source: 'acme/shop', created_at: AT, ...over });
const liveOrg = (over: Record<string, unknown> = {}) => ({
  id: 9, name: requiredRulesetName('shop'), source_type: 'Organization', source: 'acme', created_at: AT, target: 'branch',
  conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] }, repository_id: { repository_ids: [101] } },
  rules: [{ type: 'workflows', parameters: { do_not_enforce_on_create: false, workflows: [{ path: centralWorkflowFile('shop', 'required'), repository_id: CENTRAL_ID, sha: PIN }] } }],
  ...over,
});
const rsEntry = (over: Partial<InstallRecord['rulesets'][number]> = {}): InstallRecord['rulesets'][number] => ({ kind: 'gate', id: 7, name: 'pipegen', githubCreatedAt: AT, ...over });
const orgEntry = (over: Partial<NonNullable<InstallRecord['orgRuleset']>> = {}): NonNullable<InstallRecord['orgRuleset']> => ({ org: OWNER, id: 9, name: requiredRulesetName('shop'), githubCreatedAt: AT, pinnedSha: PIN, ...over });

// ---------- 1. routes ----------

describe('V3 target: routes', () => {
  it('target: only the listed uninstall routes, each with its parameter check; a source scan of src/uninstall', async () => {
    expect([...UNINSTALL_WRITE_ROUTES].sort()).toEqual([
      'DELETE /orgs/{org}/rulesets/{ruleset_id}',
      'DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}',
      'DELETE /repos/{owner}/{repo}/actions/variables/{name}',
      'DELETE /repos/{owner}/{repo}/branches/{branch}/protection',
      'DELETE /repos/{owner}/{repo}/environments/{environment_name}',
      'DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}',
      'DELETE /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}',
      'DELETE /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}',
      'DELETE /repos/{owner}/{repo}/git/refs/{ref}',
      'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}',
      'DELETE /repos/{owner}/{repo}/vulnerability-alerts',
      'PATCH /repos/{owner}/{repo}',
      'PATCH /repos/{owner}/{repo}/actions/variables/{name}',
      'PATCH /repos/{owner}/{repo}/pulls/{pull_number}',
      'PUT /repos/{owner}/{repo}/actions/permissions',
      'PUT /repos/{owner}/{repo}/actions/permissions/access',
      'PUT /repos/{owner}/{repo}/branches/{branch}/protection',
      'PUT /repos/{owner}/{repo}/environments/{environment_name}',
    ].sort());
    // the set is fixed at run time too
    expect(() => (UNINSTALL_WRITE_ROUTES as Set<string>).add('DELETE /repos/{owner}/{repo}')).toThrow();
    expect(Object.isFrozen(UNINSTALL_WRITE_ROUTES)).toBe(true);
    expect(UNINSTALL_WRITE_ROUTES.has('DELETE /repos/{owner}/{repo}')).toBe(false);

    const { api: a, calls } = api();
    const app = { owner: OWNER, repo: 'shop' };
    const refused = async (route: string, params: Record<string, unknown>) => {
      const before = calls.length;
      await expect(a.write(route, params)).rejects.toBeInstanceOf(UninstallRefusal);
      expect(calls.length).toBe(before);
    };
    // a route outside the set; the repo delete; a contents write; a POST
    await refused('DELETE /repos/{owner}/{repo}', app);
    await refused('PUT /repos/{owner}/{repo}/contents/{path}', { ...app, path: 'x' });
    await refused('POST /repos/{owner}/{repo}/rulesets', app);
    await refused('PUT /repos/{owner}/{repo}/collaborators/{username}', { ...app, username: 'x' });
    // another owner, another repo, another org
    await refused('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { owner: 'evil', repo: 'shop' });
    await refused('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { owner: OWNER, repo: 'other' });
    await refused('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { owner: OWNER, repo: 'pipelines' });   // app only
    await refused('PUT /repos/{owner}/{repo}/actions/permissions/access', { ...app, access_level: 'none' });   // central only
    // path parts: not plain, dot segments, ids
    await refused('PUT /repos/{owner}/{repo}/environments/{environment_name}', { ...app, environment_name: '../x' });
    await refused('DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}', { ...app, environment_name: 'prod', branch_policy_id: 0 });
    await refused('DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}', { ...app, environment_name: 'prod', branch_policy_id: '5' });
    // bodies: unknown keys, Octokit options, wrong values
    await refused('PATCH /repos/{owner}/{repo}', { ...app, private: false });
    await refused('PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { secret_scanning: { status: 'enabled' } }, name: 'x' });
    await refused('PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { advanced_security: { status: 'disabled' } } });
    await refused('PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { secret_scanning: { status: 'off' } } });
    await refused('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { ...app, baseUrl: 'https://evil' });
    await refused('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { ...app, headers: {} });
    await refused('PATCH /repos/{owner}/{repo}/actions/variables/{name}', { ...app, name: 'PIPEGEN_X', value: 1 });
    await refused('PATCH /repos/{owner}/{repo}/actions/variables/{name}', { ...app, name: 'PIPEGEN_X', value: 'v', visibility: 'all' });
    await refused('PUT /repos/{owner}/{repo}/actions/permissions', { ...app, enabled: true });
    await refused('PUT /repos/{owner}/{repo}/actions/permissions', { ...app, enabled: true, sha_pinning_required: false, allowed_actions: 'any' });
    await refused('PUT /repos/{owner}/{repo}/actions/permissions', { ...app, enabled: false, sha_pinning_required: false });
    await refused('PUT /repos/{owner}/{repo}/environments/{environment_name}', { ...app, environment_name: 'prod', wait_timer: -1 });
    await refused('PUT /repos/{owner}/{repo}/environments/{environment_name}', { ...app, environment_name: 'prod', reviewers: [{ type: 'Bot', id: 1 }] });
    await refused('PUT /repos/{owner}/{repo}/environments/{environment_name}', { ...app, environment_name: 'prod', url: 'x' });
    await refused('PUT /repos/{owner}/{repo}/actions/permissions/access', { owner: OWNER, repo: 'pipelines', access_level: 'all' });
    // the identity-checked deletes, the protection, PR closes and branch deletes go only through their own functions
    await refused('DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}', { ...app, ruleset_id: 7 });
    await refused('DELETE /orgs/{org}/rulesets/{ruleset_id}', { org: OWNER, ruleset_id: 9 });
    await refused('DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}', { ...app, secret_name: 'PIPEGEN_X' });
    await refused('DELETE /repos/{owner}/{repo}/environments/{environment_name}', { ...app, environment_name: 'prod' });
    await refused('DELETE /repos/{owner}/{repo}/branches/{branch}/protection', { ...app, branch: 'main' });
    await refused('PUT /repos/{owner}/{repo}/branches/{branch}/protection', { ...app, branch: 'main' });
    await refused('PATCH /repos/{owner}/{repo}/pulls/{pull_number}', { ...app, pull_number: 3, state: 'closed' });
    await refused('DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ...app, ref: 'heads/pipegen/setup' });
    expect(calls).toEqual([]);

    // and the allowed ones are sent as given, owner and repo included
    await a.write('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { owner: 'ACME', repo: 'Shop' });
    await a.write('PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { secret_scanning: { status: 'disabled' }, secret_scanning_push_protection: { status: 'disabled' } } });
    await a.write('PATCH /repos/{owner}/{repo}/actions/variables/{name}', { ...app, name: 'PIPEGEN_BLOCK_FROM', value: 'old' });
    await a.write('PUT /repos/{owner}/{repo}/actions/permissions', { ...app, enabled: true, allowed_actions: 'all', sha_pinning_required: false });
    await a.write('PUT /repos/{owner}/{repo}/actions/permissions/access', { owner: OWNER, repo: 'pipelines', access_level: 'none' });
    await a.write('PUT /repos/{owner}/{repo}/environments/{environment_name}', { ...app, environment_name: 'prod', wait_timer: 0, prevent_self_review: false, reviewers: [{ type: 'User', id: 4 }], deployment_branch_policy: null, can_admins_bypass: true });
    await a.write('DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}', { ...app, environment_name: 'prod', branch_policy_id: 5 });
    expect(calls.map((c) => c.route)).toEqual([
      'DELETE /repos/{owner}/{repo}/vulnerability-alerts', 'PATCH /repos/{owner}/{repo}', 'PATCH /repos/{owner}/{repo}/actions/variables/{name}',
      'PUT /repos/{owner}/{repo}/actions/permissions', 'PUT /repos/{owner}/{repo}/actions/permissions/access', 'PUT /repos/{owner}/{repo}/environments/{environment_name}',
      'DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}',
    ]);
    expect(calls[2]?.params).toEqual({ ...app, name: 'PIPEGEN_BLOCK_FROM', value: 'old' });

    // reads: GETs only, never the contents API, the same owner/repo/org check
    await expect(a.read('GET /repos/{owner}/{repo}/contents/{path}', { ...app, path: 'x' })).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(a.read('POST /repos/{owner}/{repo}/rulesets', app)).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(a.read('GET /repos/{owner}/{repo}', { owner: OWNER, repo: 'other' })).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(a.read('GET /orgs/{org}/rulesets/{ruleset_id}', { org: 'evil', ruleset_id: 9 })).rejects.toBeInstanceOf(UninstallRefusal);

    // the source scan (a lint beside the run-time allow-list): no other file of src/uninstall sends a GitHub write
    const dir = join(import.meta.dirname, '..', 'src', 'uninstall');
    const files = readdirSync(dir).filter((x) => x.endsWith('.ts'));
    expect(files).toContain('target.ts');
    for (const f of files) {
      const src = readFileSync(join(dir, f), 'utf8');
      expect(scanProblems(f, src), f).toEqual([]);
    }
    // the scan itself catches the obvious ways around the guard
    for (const bad of [
      'await gh.request(\'DELETE /repos/{owner}/{repo}\', p);', 'await octokit.rest.repos.delete(p);', 'import { ghWrite } from \'../deliver/git-data.js\';',
      'import { commitFiles, readTree } from \'../deliver/git-data.js\';', 'import { guardedWrite } from \'../proof/target.js\';', 'import { createHelperRepo } from \'../proof/target.js\';',
      'import { SettingsApi } from \'../deliver/settings-api.js\';', 'import { writeRecord } from \'../deliver/record.js\';', 'const { request } = gh;', 'gh[\'request\'](r)',
      'import { request } from \'@octokit/request\';', 'await fetch(url)', 'x.request.call(gh, r)', 'await storeEnvSecret(gh, a)',
    ]) expect(scanProblems('plan.ts', bad), bad).not.toEqual([]);
    for (const ok of ['import { cleanupWrite, deleteScratchSecret, deleteScratchRepo, proofTarget } from \'../proof/target.js\';', 'import { readTree, readBlobText } from \'../deliver/git-data.js\';']) {
      expect(scanProblems('plan.ts', ok), ok).toEqual([]);
    }
  });
});

/** What the scan finds wrong in one file of src/uninstall (target.ts is the one that writes). */
function scanProblems(file: string, src: string): string[] {
  const out: string[] = [];
  const no = (re: RegExp, what: string) => { if (re.test(src)) out.push(what); };
  no(/@octokit\/(?:request|graphql|core)\b/, 'an Octokit transport import');
  no(/\bfetch\s*\(/, 'a fetch');
  no(/\.graphql\s*[(.`]/, 'a graphql call');
  no(/\{[^{}]*\b(?:request|graphql)\b[^{}]*\}\s*=\s*[\w.]+/, 'a destructured request');
  no(/\b(?:gh|octokit)\s*\[/, 'bracket access on a client');
  no(/\[\s*['"`](?:request|graphql|rest)['"`]\s*\]/, 'bracket access on a client');
  no(/\.(?:request|graphql)\s*\.(?:bind|call|apply)\b/, 'a bound request');
  no(/=\s*[\w.]+\.(?:request|graphql)\s*[;,)\n]/, 'an aliased request');
  if (file === 'target.ts') return out;
  no(/\.request\s*\(/, 'gh.request');
  no(/\.rest\s*\.\s*[a-zA-Z]+/, 'gh.rest');
  no(/\b(?:ghWrite|commitFiles|setBranch|openOrUpdatePr|writeRecord|writeLocalRecord|SettingsApi|guardedWrite|createHelperRepo|makeRepoPrivate|scratchSecretSink|storeEnvSecret|storeCosignKey|ensureSigningEnvironment|writeFinishPending|addLocalLeftovers)\b/, 'a write function of another module');
  no(/\bmethod\s*:\s*['"`](?:POST|PUT|PATCH|DELETE)/, 'a write method');
  return out;
}

// ---------- 2. identity ----------

describe('V3 target: identity of what pipegen created', () => {
  it('apply: ruleset deleted only when GET says pipegen\'s name, this repo as source and the recorded created_at', async () => {
    const run = async (live: Record<string, unknown>, entry = rsEntry(), opts: { typed?: boolean } = {}) => {
      const f = api((route) => (route.startsWith('GET ') ? live : {}));
      const t = opts.typed === true ? await typed(entry.name) : undefined;
      const out = await f.api.deleteIfPipegens({ kind: 'ruleset', entry }, t === undefined ? {} : { typed: t });
      return { out, writes: f.writes() };
    };
    const ok = await run(liveRuleset());
    expect(ok.out.status).toBe('deleted');
    expect(ok.writes).toEqual([{ route: 'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}', params: { owner: OWNER, repo: 'shop', ruleset_id: 7 } }]);
    // GitHub may write the same instant with milliseconds
    expect((await run(liveRuleset({ created_at: '2026-11-01T10:00:00.000Z' }))).out.status).toBe('deleted');
    // each identity part, wrong → kept, nothing sent
    for (const live of [
      liveRuleset({ name: 'mine' }), liveRuleset({ name: 'pipegen-reviews' }), liveRuleset({ id: 8 }), liveRuleset({ source_type: 'Organization' }),
      liveRuleset({ source: 'acme/other' }), liveRuleset({ source: 'evil/shop' }), liveRuleset({ created_at: '2026-11-01T10:00:01Z' }), liveRuleset({ source: undefined }),
    ]) {
      const r = await run(live);
      expect(r.out.status, JSON.stringify(live)).toBe('kept');
      expect(r.writes).toEqual([]);
    }
    // a record naming a ruleset pipegen never makes is not pipegen's, whatever GitHub says
    expect((await run(liveRuleset({ name: 'main-rules' }), rsEntry({ name: 'main-rules' as 'pipegen' }))).out.status).toBe('kept');
    expect((await run(liveRuleset({ name: 'pipegen' }), rsEntry({ kind: 'reviews' }))).out.status).toBe('kept');
    // the reviews ruleset
    expect((await run(liveRuleset({ name: 'pipegen-reviews' }), rsEntry({ kind: 'reviews', name: 'pipegen-reviews' }))).out.status).toBe('deleted');
    // the central ruleset: name pipegen, source <owner>/pipelines
    const c = api((route) => (route.startsWith('GET ') ? liveRuleset({ id: 11, source: 'acme/pipelines' }) : {}));
    expect((await c.api.deleteIfPipegens({ kind: 'central-ruleset', id: 11, createdAt: AT })).status).toBe('deleted');
    expect(c.writes()[0]?.params).toEqual({ owner: OWNER, repo: 'pipelines', ruleset_id: 11 });
    const c2 = api((route) => (route.startsWith('GET ') ? liveRuleset({ id: 11, source: 'acme/shop' }) : {}));
    expect((await c2.api.deleteIfPipegens({ kind: 'central-ruleset', id: 11, createdAt: AT })).status).toBe('kept');
    // the pure check agrees
    expect(isPipegens({ kind: 'ruleset', entry: rsEntry() }, liveRuleset(), APP).is).toBe('yes');
    expect(isPipegens({ kind: 'ruleset', entry: rsEntry() }, liveRuleset({ source: 'acme/other' }), APP).is).toBe('no');
    expect(isPipegens({ kind: 'ruleset', entry: rsEntry() }, null, APP).is).toBe('no');
  });

  it('target: unconfirmed or missing created_at → ask, never pipegen\'s', async () => {
    const cases: [Owned, unknown][] = [
      [{ kind: 'ruleset', entry: rsEntry({ githubCreatedAt: undefined, unconfirmed: true }) }, liveRuleset()],
      [{ kind: 'ruleset', entry: rsEntry({ githubCreatedAt: undefined }) }, liveRuleset()],
      [{ kind: 'ruleset', entry: rsEntry({ unconfirmed: true }) }, liveRuleset()],   // both (the schema refuses it): never yes
      [{ kind: 'ruleset', entry: rsEntry() }, liveRuleset({ created_at: undefined })],
      [{ kind: 'ruleset', entry: rsEntry() }, liveRuleset({ created_at: 'yesterday' })],
      [{ kind: 'central-ruleset', id: 7 }, liveRuleset({ source: 'acme/pipelines' })],
      [{ kind: 'org-ruleset', entry: orgEntry({ githubCreatedAt: undefined, unconfirmed: true }), centralRepoId: CENTRAL_ID }, liveOrg()],
      [{ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, unconfirmed: true } }, { name: 'PIPEGEN_X', created_at: AT }],
      [{ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true } }, { name: 'PIPEGEN_X', created_at: AT }],
      [{ kind: 'variable', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, unconfirmed: true } }, { name: 'PIPEGEN_X', created_at: AT }],
      [{ kind: 'environment', entry: { name: 'prod', created: true, changed: [], branchPolicyIds: [], unconfirmed: true } }, { name: 'prod', created_at: AT }],
      [{ kind: 'environment', entry: { name: 'prod', created: true, changed: [], branchPolicyIds: [] } }, { name: 'prod', created_at: AT }],
      // V-S12: a secret pipegen created under the user's own key name is asked about, even with its created_at equal
      [{ kind: 'secret', entry: { name: 'DATABASE_URL', scope: 'env:test', created: true, githubCreatedAt: AT } }, { name: 'DATABASE_URL', created_at: AT }],
    ];
    for (const [o, live] of cases) expect(isPipegens(o, live, APP).is, JSON.stringify(o)).toBe('ask');
    // known and equal → yes; known and different → no (never ask about another object)
    expect(isPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_X', created_at: AT }, APP).is).toBe('yes');
    expect(isPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_X', created_at: '2026-11-02T00:00:00Z' }, APP).is).toBe('no');
    expect(isPipegens({ kind: 'variable', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_X', created_at: AT }, APP).is).toBe('yes');
    expect(isPipegens({ kind: 'variable', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_Y', created_at: AT }, APP).is).toBe('no');
    expect(isPipegens({ kind: 'environment', entry: { name: 'prod', created: true, changed: [], branchPolicyIds: [], githubCreatedAt: AT } }, { name: 'prod', created_at: AT }, APP).is).toBe('yes');
    expect(isPipegens({ kind: 'environment', entry: { name: 'prod', created: true, changed: [], branchPolicyIds: [], githubCreatedAt: AT } }, { name: 'prod', created_at: '2025-01-01T00:00:00Z' }, APP).is).toBe('no');
    // not created, or a secret pipegen overwrote: never pipegen's (V-N6)
    expect(isPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: false, overwritten: true } }, { name: 'PIPEGEN_X', created_at: AT }, APP).is).toBe('no');
    expect(isPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, overwritten: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_X', created_at: AT }, APP).is).toBe('no');
    expect(isPipegens({ kind: 'variable', entry: { name: 'PIPEGEN_X', scope: 'repo', created: false, previous: 'v' } }, { name: 'PIPEGEN_X', created_at: AT }, APP).is).toBe('no');
    expect(isPipegens({ kind: 'environment', entry: { name: 'prod', created: false, changed: [], branchPolicyIds: [] } }, { name: 'prod', created_at: AT }, APP).is).toBe('no');

    // an ask is not sent without the typed name, and the typed name only counts for that object, once
    const f = api((route) => (route.startsWith('GET ') ? liveRuleset() : {}));
    const unconf = { kind: 'ruleset' as const, entry: rsEntry({ githubCreatedAt: undefined, unconfirmed: true }) };
    expect((await f.api.deleteIfPipegens(unconf)).status).toBe('ask');
    expect(f.writes()).toEqual([]);
    await expect(f.api.deleteIfPipegens(unconf, { typed: await typed('pipegen-reviews') })).rejects.toBeInstanceOf(UninstallRefusal);
    expect(f.writes()).toEqual([]);
    const t = await typed('pipegen');
    expect((await f.api.deleteIfPipegens(unconf, { typed: t })).status).toBe('deleted');
    expect(f.writes().length).toBe(1);
    await expect(f.api.deleteIfPipegens(unconf, { typed: t })).rejects.toBeInstanceOf(UninstallRefusal);   // used once
    await expect(f.api.deleteIfPipegens(unconf, { typed: Object.freeze({ name: 'pipegen' }) as never })).rejects.toBeInstanceOf(UninstallRefusal);   // a look-alike
    // a typed name never turns a "not pipegen's" into a delete
    const g = api((route) => (route.startsWith('GET ') ? liveRuleset({ source: 'acme/other' }) : {}));
    expect((await g.api.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() }, { typed: await typed('pipegen') })).status).toBe('kept');
    expect(g.writes()).toEqual([]);

    // typed names come only from the interactive terminal (V-S13)
    expect(await askTypedName({ prompt: prompter(['pipegen']), interactive: false }, 'pipegen', 'q')).toBeNull();
    expect(await askTypedName({ prompt: prompter(['pipegen']), interactive: 'yes' as unknown as boolean }, 'pipegen', 'q')).toBeNull();
    expect(await askTypedName({ prompt: prompter(['pipegen-x']), interactive: true }, 'pipegen', 'q')).toBeNull();
    expect(await askTypedName({ prompt: prompter(['  PipeGen ']), interactive: true }, 'pipegen', 'q')).not.toBeNull();
  });

  it('target: org rule only when it targets exactly this repo id and pins this project\'s required workflow at pinnedSha', async () => {
    const o = (over: Partial<NonNullable<InstallRecord['orgRuleset']>> = {}): Owned => ({ kind: 'org-ruleset', entry: orgEntry(over), centralRepoId: CENTRAL_ID });
    expect(isPipegens(o(), liveOrg(), APP).is).toBe('yes');
    const wf = (w: Record<string, unknown>[]) => [{ type: 'workflows', parameters: { do_not_enforce_on_create: false, workflows: w } }];
    const good = { path: centralWorkflowFile('shop', 'required'), repository_id: CENTRAL_ID, sha: PIN };
    for (const live of [
      liveOrg({ conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] }, repository_id: { repository_ids: [101, 102] } } }),
      liveOrg({ conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] }, repository_id: { repository_ids: [102] } } }),
      liveOrg({ conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] }, repository_name: { include: ['~ALL'], exclude: [] } } }),
      liveOrg({ conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] }, repository_id: { repository_ids: [101] }, repository_property: { include: [] } } }),
      liveOrg({ conditions: undefined }),
      liveOrg({ rules: wf([{ ...good, sha: 'c'.repeat(40) }]) }),
      liveOrg({ rules: wf([{ ...good, path: centralWorkflowFile('other', 'required') }]) }),
      liveOrg({ rules: wf([{ ...good, repository_id: 999 }]) }),
      liveOrg({ rules: wf([good, { ...good, path: '.github/workflows/x.yml' }]) }),
      liveOrg({ rules: wf([]) }),
      liveOrg({ rules: [] }),
      liveOrg({ rules: [...wf([good]), { type: 'deletion' }] }),
      liveOrg({ name: 'pipegen-required--other' }),
      liveOrg({ source_type: 'Repository' }),
      liveOrg({ source: 'evil' }),
      liveOrg({ id: 10 }),
      liveOrg({ created_at: '2026-11-01T10:00:01Z' }),
    ]) expect(isPipegens(o(), live, APP).is, JSON.stringify(live.conditions ?? live.rules ?? live)).toBe('no');
    // the record itself must name this project's rule in the app's own org
    expect(isPipegens(o({ name: 'pipegen-required--other' }), liveOrg({ name: 'pipegen-required--other' }), APP).is).toBe('no');
    expect(isPipegens(o({ org: 'evil' }), liveOrg({ source: 'evil' }), APP).is).toBe('no');
    // the delete sends the org route only on yes
    const f = api((route) => (route.startsWith('GET ') ? liveOrg() : {}));
    expect((await f.api.deleteIfPipegens(o())).status).toBe('deleted');
    expect(f.writes()).toEqual([{ route: 'DELETE /orgs/{org}/rulesets/{ruleset_id}', params: { org: OWNER, ruleset_id: 9 } }]);
    const g = api((route) => (route.startsWith('GET ') ? liveOrg({ rules: wf([{ ...good, sha: 'c'.repeat(40) }]) }) : {}));
    expect((await g.api.deleteIfPipegens(o())).status).toBe('kept');
    expect(g.writes()).toEqual([]);
  });

  it('secrets, variables and environments: each GET and DELETE names the scope\'s route', async () => {
    const run = async (o: Owned, live: Record<string, unknown>) => {
      const f = api((route) => (route.startsWith('GET ') ? live : {}));
      const out = await f.api.deleteIfPipegens(o);
      return { out, calls: f.calls };
    };
    const s = await run({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_X', created_at: AT });
    expect(s.out.status).toBe('deleted');
    expect(s.calls.map((c) => [c.route, c.params])).toEqual([
      ['GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', { owner: OWNER, repo: 'shop', environment_name: 'pipegen-signing', secret_name: 'PIPEGEN_X' }],
      ['DELETE /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', { owner: OWNER, repo: 'shop', environment_name: 'pipegen-signing', secret_name: 'PIPEGEN_X' }],
    ]);
    const c = await run({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'central', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_X', created_at: AT });
    expect(c.calls.at(-1)).toEqual({ route: 'DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}', params: { owner: OWNER, repo: 'pipelines', secret_name: 'PIPEGEN_X' } });
    const v = await run({ kind: 'variable', entry: { name: 'PIPEGEN_COSIGN_PUB', scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_COSIGN_PUB', created_at: AT });
    expect(v.calls.at(-1)?.route).toBe('DELETE /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}');
    const r = await run({ kind: 'variable', entry: { name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_BLOCK_FROM', created_at: AT });
    expect(r.calls.at(-1)).toEqual({ route: 'DELETE /repos/{owner}/{repo}/actions/variables/{name}', params: { owner: OWNER, repo: 'shop', name: 'PIPEGEN_BLOCK_FROM' } });
    const e = await run({ kind: 'environment', entry: { name: 'pipegen-signing', created: true, changed: [], branchPolicyIds: [], githubCreatedAt: AT } }, { name: 'pipegen-signing', created_at: AT });
    expect(e.calls.at(-1)).toEqual({ route: 'DELETE /repos/{owner}/{repo}/environments/{environment_name}', params: { owner: OWNER, repo: 'shop', environment_name: 'pipegen-signing' } });
    // a scope or name that isn't plain is refused before anything is sent
    const f = api();
    await expect(f.api.deleteIfPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'env:../x' as 'env:x', created: true, githubCreatedAt: AT } })).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(f.api.deleteIfPipegens({ kind: 'variable', entry: { name: 'A/B', scope: 'repo', created: true, githubCreatedAt: AT } })).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(f.api.deleteIfPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'org' as 'repo', created: true, githubCreatedAt: AT } })).rejects.toBeInstanceOf(UninstallRefusal);
    expect(f.calls).toEqual([]);
  });
});

// ---------- 3. HTTP answers ----------

describe('V3 target: HTTP answers (V-S11)', () => {
  it('apply: 404 is gone only after the parent read succeeds; 403 → leftover with the manual step', async () => {
    // the pure helper
    const ok = async () => ({});
    const fail = async () => { throw httpErr(404); };
    expect(await goneOr(httpErr(404), ok, 'the ruleset pipegen', 'gh api -X DELETE x')).toEqual({ gone: true });
    const noParent = await goneOr(httpErr(404), fail, 'the ruleset pipegen', 'gh api -X DELETE x');
    expect(noParent.gone).toBe(false);
    expect(noParent).toMatchObject({ manual: 'gh api -X DELETE x' });
    const forbidden = await goneOr(httpErr(403, 'Resource not accessible by integration'), ok, 'the ruleset pipegen', 'gh api -X DELETE x');
    expect(forbidden).toMatchObject({ gone: false, manual: 'gh api -X DELETE x' });
    expect((forbidden as { leftover: string }).leftover).toMatch(/403/);
    expect(await goneOr(httpErr(422), ok, 'w', 'm')).toMatchObject({ gone: false, manual: 'm' });
    await expect(goneOr(httpErr(401), ok, 'w', 'm')).rejects.toMatchObject({ status: 401 });
    await expect(goneOr(httpErr(404), async () => { throw httpErr(401); }, 'w', 'm')).rejects.toMatchObject({ status: 401 });
    await expect(goneOr(new Error('a bug'), ok, 'w', 'm')).rejects.toThrow('a bug');

    // through the API: a 404 on the object's GET, the repo read answers → gone, nothing deleted
    const parentOk = api((route) => { if (route === 'GET /repos/{owner}/{repo}') return { id: 101 }; throw httpErr(404); });
    expect((await parentOk.api.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() })).status).toBe('gone');
    expect(parentOk.calls.map((c) => c.route)).toEqual(['GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', 'GET /repos/{owner}/{repo}']);
    expect(parentOk.writes()).toEqual([]);
    // the repo read also 404s (no access to a private repo looks the same) → leftover
    const parentGone = api(() => { throw httpErr(404); });
    const lp = await parentGone.api.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() });
    expect(lp.status).toBe('leftover');
    expect(lp).toMatchObject({ manual: 'gh api -X DELETE repos/acme/shop/rulesets/7' });
    // 403 on the GET or on the DELETE → leftover with the exact manual step
    const f403 = api(() => { throw httpErr(403); });
    expect(await f403.api.deleteIfPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, githubCreatedAt: AT } })).toMatchObject({ status: 'leftover', manual: 'gh secret delete PIPEGEN_X --repo acme/shop' });
    const d403 = api((route) => { if (route.startsWith('GET ')) return liveOrg(); throw httpErr(403); });
    expect(await d403.api.deleteIfPipegens({ kind: 'org-ruleset', entry: orgEntry(), centralRepoId: CENTRAL_ID })).toMatchObject({ status: 'leftover', manual: 'gh api -X DELETE orgs/acme/rulesets/9' });
    // a 404 on the DELETE: gone only after the repo read; an org rule's parent is the org's ruleset list
    const d404 = api((route) => { if (route === 'GET /orgs/{org}/rulesets/{ruleset_id}') return liveOrg(); if (route === 'GET /orgs/{org}/rulesets') return []; throw httpErr(404); });
    expect((await d404.api.deleteIfPipegens({ kind: 'org-ruleset', entry: orgEntry(), centralRepoId: CENTRAL_ID })).status).toBe('gone');
    expect(d404.calls.map((c) => c.route)).toEqual(['GET /orgs/{org}/rulesets/{ruleset_id}', 'DELETE /orgs/{org}/rulesets/{ruleset_id}', 'GET /orgs/{org}/rulesets']);
    // 401 stops the run (the token is wrong), never a leftover
    const f401 = api(() => { throw httpErr(401); });
    await expect(f401.api.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() })).rejects.toMatchObject({ status: 401, name: 'GitHubAccessError' });
    await expect(f401.api.write('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { owner: OWNER, repo: 'shop' })).rejects.toMatchObject({ status: 401, name: 'GitHubAccessError' });
    // a rate stop is rethrown
    const rate = api(() => { throw Object.assign(httpErr(403), { response: { data: {}, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '999999999' } } }); });
    await expect(rate.api.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() })).rejects.toMatchObject({ name: 'GitHubRateLimitError' });
  });
});

// ---------- 4. classic protection ----------

describe('V3 target: classic protection is restored, never deleted blind', () => {
  const planned = { method: 'PUT' as const, route: '/repos/{owner}/{repo}/branches/{branch}/protection', params: { owner: OWNER, repo: 'shop', branch: 'main' }, body: { enforce_admins: true, required_status_checks: { strict: true, checks: [{ context: 'pipegen / gate', app_id: 15368 }] } } };
  const liveGet = (over: Record<string, unknown> = {}) => ({ required_status_checks: { strict: true, checks: [{ context: 'pipegen / gate', app_id: 15368 }] }, enforce_admins: { enabled: true }, ...over });
  const prev = { required_status_checks: null, enforce_admins: false, required_pull_request_reviews: null, restrictions: null };
  it('previous null: DELETE only when the live protection holds pipegen\'s rules; else PUT previous; the typed branch name always', async () => {
    const f = api((route) => (route.startsWith('GET ') ? liveGet() : {}));
    await expect(f.api.restoreClassic({ branch: 'main', previous: null }, planned)).rejects.toBeInstanceOf(UninstallRefusal);   // no typed name
    await expect(f.api.restoreClassic({ branch: 'main', previous: null }, planned, await typed('dev'))).rejects.toBeInstanceOf(UninstallRefusal);
    expect(f.writes()).toEqual([]);
    expect(await f.api.restoreClassic({ branch: 'main', previous: null }, planned, await typed('main'))).toEqual({ status: 'deleted' });
    expect(f.writes()).toEqual([{ route: 'DELETE /repos/{owner}/{repo}/branches/{branch}/protection', params: { owner: OWNER, repo: 'shop', branch: 'main' } }]);
    // the owner changed the protection since: kept, manual
    const g = api((route) => (route.startsWith('GET ') ? liveGet({ enforce_admins: { enabled: false } }) : {}));
    expect((await g.api.restoreClassic({ branch: 'main', previous: null }, planned, await typed('main'))).status).toBe('kept');
    expect(g.writes()).toEqual([]);
    // no plan (a typed view) → kept
    const h = api((route) => (route.startsWith('GET ') ? liveGet() : {}));
    expect((await h.api.restoreClassic({ branch: 'main', previous: null }, undefined, await typed('main'))).status).toBe('kept');
    expect(h.writes()).toEqual([]);
    // previous: PUT exactly it
    const p = api((route) => (route.startsWith('GET ') ? liveGet() : {}));
    expect(await p.api.restoreClassic({ branch: 'main', previous: prev }, planned, await typed('main'))).toEqual({ status: 'restored' });
    expect(p.writes()).toEqual([{ route: 'PUT /repos/{owner}/{repo}/branches/{branch}/protection', params: { owner: OWNER, repo: 'shop', branch: 'main', ...prev } }]);
    // a previous with keys the PUT doesn't take is refused
    const q = api((route) => (route.startsWith('GET ') ? liveGet() : {}));
    await expect(q.api.restoreClassic({ branch: 'main', previous: { ...prev, baseUrl: 'x' } }, planned, await typed('main'))).rejects.toBeInstanceOf(UninstallRefusal);
    expect(q.writes()).toEqual([]);
    // already gone and nothing to restore
    const r = api((route) => { if (route === 'GET /repos/{owner}/{repo}') return {}; throw httpErr(404); });
    expect((await r.api.restoreClassic({ branch: 'main', previous: null }, planned, await typed('main'))).status).toBe('gone');
    expect(r.writes()).toEqual([]);
  });
});

// ---------- 5. PRs and branches ----------

describe('V3 target: pull requests and branches', () => {
  it('target: a PR close or branch delete outside pipegen/* is refused before it is sent', async () => {
    const pr = (ref: string, over: Record<string, unknown> = {}) => ({ number: 3, state: 'open', head: { ref, repo: { full_name: 'acme/shop' } }, ...over });
    const run = async (live: Record<string, unknown>, where: 'app' | 'central' = 'app') => {
      const f = api((route) => (route.startsWith('GET ') ? live : {}));
      let err: unknown;
      try { await f.api.closePr(where, 3); } catch (e) { err = e; }
      return { err, writes: f.writes() };
    };
    for (const live of [pr('main'), pr('feature/pipegen/x'), pr('pipegen'), pr('pipegen/setup', { head: { ref: 'pipegen/setup', repo: { full_name: 'evil/shop' } } }), pr('pipegen/setup', { head: { ref: 'pipegen/setup', repo: null } })]) {
      const r = await run(live);
      expect(r.err, JSON.stringify(live)).toBeInstanceOf(UninstallRefusal);
      expect(r.writes).toEqual([]);
    }
    const ok = await run(pr('pipegen/setup'));
    expect(ok.err).toBeUndefined();
    expect(ok.writes).toEqual([{ route: 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}', params: { owner: OWNER, repo: 'shop', pull_number: 3, state: 'closed' } }]);
    // already closed: nothing sent
    const closed = await run(pr('pipegen/update', { state: 'closed' }));
    expect(closed.writes).toEqual([]);
    // central: only this project's branches
    const centralPr = (ref: string) => ({ number: 3, state: 'open', head: { ref, repo: { full_name: 'acme/pipelines' } } });
    expect((await run(centralPr('pipegen/update-shop'), 'central')).writes.length).toBe(1);
    expect((await run(centralPr('pipegen/uninstall-shop'), 'central')).writes.length).toBe(1);
    for (const ref of ['pipegen/update-other', 'pipegen/update-shop-x', 'main', 'proof/20261101-000000-abcdef']) {
      const r = await run(centralPr(ref), 'central');
      expect(r.err, ref).toBeInstanceOf(UninstallRefusal);
      expect(r.writes).toEqual([]);
    }
    await expect(api().api.closePr('app', 0)).rejects.toBeInstanceOf(UninstallRefusal);

    // branch deletes
    const f = api();
    for (const [where, b] of [['app', 'main'], ['app', 'pipegen'], ['app', 'pipegen/../main'], ['app', 'xpipegen/setup'], ['central', 'pipegen/update-other'], ['central', 'main'], ['app', '']] as const) {
      await expect(f.api.deleteBranch(where, b), `${where} ${b}`).rejects.toBeInstanceOf(UninstallRefusal);
    }
    expect(f.calls).toEqual([]);
    await f.api.deleteBranch('app', 'pipegen/setup');
    await f.api.deleteBranch('central', 'pipegen/update-shop');
    expect(f.calls).toEqual([
      { route: 'DELETE /repos/{owner}/{repo}/git/refs/{ref}', params: { owner: OWNER, repo: 'shop', ref: 'heads/pipegen/setup' } },
      { route: 'DELETE /repos/{owner}/{repo}/git/refs/{ref}', params: { owner: OWNER, repo: 'pipelines', ref: 'heads/pipegen/update-shop' } },
    ]);
  });

  it('the uninstall PRs: their branch only, files and deletes through the git data API', async () => {
    expect(uninstallBranch(APP, 'app')).toBe('pipegen/uninstall');
    expect(uninstallBranch(APP, 'central')).toBe('pipegen/uninstall-shop');
    const sha = (n: number) => String(n).repeat(40).slice(0, 40);
    const f = api((route) => {
      if (route === 'POST /repos/{owner}/{repo}/git/trees') return { sha: sha(1) };
      if (route === 'POST /repos/{owner}/{repo}/git/commits') return { sha: sha(2) };
      if (route === 'GET /repos/{owner}/{repo}/git/ref/{ref}') throw httpErr(404);
      if (route === 'GET /repos/{owner}/{repo}/pulls') return [];
      if (route === 'POST /repos/{owner}/{repo}/pulls') return { number: 12, html_url: 'u' };
      return {};
    });
    const c = await f.api.commitUninstall('app', { parent: SHA, baseTree: SHA, files: [{ path: 'package.json', content: '{}\n', mode: '100644' }], deletes: ['.github/workflows/pipegen.yml'], message: 'pipegen: uninstall' });
    expect(c).toEqual({ commit: sha(2), tree: sha(1) });
    expect(f.calls[0]?.params).toEqual({ owner: OWNER, repo: 'shop', base_tree: SHA, tree: [
      { path: 'package.json', mode: '100644', type: 'blob', content: '{}\n' },
      { path: '.github/workflows/pipegen.yml', mode: '100644', type: 'blob', sha: null },
    ] });
    expect(await f.api.setUninstallBranch('central', sha(2))).toBe('created');
    expect(f.calls.at(-1)).toEqual({ route: 'POST /repos/{owner}/{repo}/git/refs', params: { owner: OWNER, repo: 'pipelines', ref: 'refs/heads/pipegen/uninstall-shop', sha: sha(2) } });
    expect(await f.api.openUninstallPr('app', { base: 'main', title: 't', body: 'b' })).toEqual({ number: 12, url: 'u', opened: true });
    expect(f.calls.at(-1)?.params).toMatchObject({ owner: OWNER, repo: 'shop', head: 'pipegen/uninstall', base: 'main' });
    // paths that are not plain, an empty commit, a mode pipegen doesn't write
    for (const bad of [
      { files: [], deletes: [] }, { files: [], deletes: ['../x'] }, { files: [], deletes: ['/etc/x'] }, { files: [], deletes: ['a//b'] }, { files: [], deletes: ['a\\b'] },
      { files: [{ path: 'x', content: '', mode: '120000' }], deletes: [] }, { files: [], deletes: ['.git/config'] }, { files: [{ path: 'a', content: '', mode: '100644' }], deletes: ['a'] },
    ]) {
      const g = api();
      await expect(g.api.commitUninstall('app', { parent: SHA, baseTree: SHA, message: 'm', ...bad }), JSON.stringify(bad)).rejects.toBeInstanceOf(UninstallRefusal);
      expect(g.calls).toEqual([]);
    }
  });
});

// ---------- 6. the central repo delete ----------

describe('V3 target: deleteCentralRepo', () => {
  const DESC = helperDescription('central');
  const readme = '# pipelines\npipegen central workflows and install records';
  const recOf = (over: Partial<InstallRecord> = {}): InstallRecord => ({
    schema: 2, pipegenVersion: '0.2.0', createdAt: AT, centralSha: SHA,
    app: { owner: OWNER, repo: 'shop', repoId: 101, defaultBranch: 'main', private: true, ownerType: 'Organization' },
    name: 'shop', serviceRoots: [], files: [{ repo: 'central', path: '.github/workflows/shop--merge.yml', part: 'pipeline', shas: [gitBlobSha('merge')] }],
    edits: [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: 'x', originalSha: null, writtenShas: [gitBlobSha('owners')] }],
    secrets: [], variables: [], environments: [], rulesets: [], central: { repoId: CENTRAL_ID, createdByPipegen: true },
    planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] }, protectedPaths: [], ...over,
  });
  interface World { repo: Record<string, unknown>; tree: { path: string; sha: string; type?: string }[]; branches?: string[]; afterDelete?: 'gone' | 'there' | 'empty' }
  const world = (w: Partial<World> = {}): World => ({
    repo: { id: CENTRAL_ID, name: 'pipelines', full_name: 'acme/pipelines', owner: { login: OWNER }, description: DESC, default_branch: 'main', private: true },
    tree: [{ path: 'README.md', sha: gitBlobSha(readme) }, { path: '.github/CODEOWNERS', sha: gitBlobSha('owners') }], ...w,
  });
  const run = async (w: World, opts: { rec?: InstallRecord; typedAs?: string; interactive?: boolean; central?: { owner: string; repo: string } } = {}) => {
    let deleted = false;
    const f = fakeGh((route) => {
      if (route === 'GET /repos/{owner}/{repo}') { if (deleted) { if (w.afterDelete === 'there') return w.repo; throw httpErr(404); } return w.repo; }
      if (route === 'GET /repos/{owner}/{repo}/branches') return (w.branches ?? ['main']).map((name) => ({ name }));
      if (route === 'GET /repos/{owner}/{repo}/git/ref/{ref}') { if (w.afterDelete === 'empty') throw httpErr(409); return { object: { sha: SHA } }; }
      if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { tree: { sha: SHA }, parents: [] };
      if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { truncated: false, tree: w.tree.map((e) => ({ path: e.path, sha: e.sha, mode: '100644', type: e.type ?? 'blob' })) };
      if (route === 'DELETE /repos/{owner}/{repo}') { deleted = true; return {}; }
      throw httpErr(500);
    });
    const p = prompter([opts.typedAs ?? 'pipelines']);
    const out = await deleteCentralRepo(f.gh, opts.central ?? { owner: OWNER, repo: 'pipelines' }, opts.rec ?? recOf(), { prompt: p, interactive: opts.interactive ?? true, clock: clock() });
    return { out, deletes: f.calls.filter((c) => c.route === 'DELETE /repos/{owner}/{repo}'), asked: p.asked, calls: f.calls };
  };

  it('central: repo deleted only with no record and no file pipegen didn\'t write left', async () => {
    const ok = await run(world());
    expect(ok.out).toEqual({ deleted: true });
    expect(ok.deletes).toEqual([{ route: 'DELETE /repos/{owner}/{repo}', params: { owner: OWNER, repo: 'pipelines' } }]);
    expect(ok.asked.length).toBe(1);
    // an empty repo (no commit) is fine too
    expect((await run(world({ afterDelete: 'empty' }))).out.deleted).toBe(true);
    const notDeleted = async (w: World, opts: Parameters<typeof run>[1] = {}, why?: RegExp) => {
      const r = await run(w, opts);
      expect(r.out.deleted, JSON.stringify({ w, opts })).toBe(false);
      expect(r.deletes).toEqual([]);
      expect(r.out.command).toBe('gh repo delete acme/pipelines');
      if (why !== undefined) expect(r.out.why).toMatch(why);
      return r;
    };
    // a record left (this project's or another's)
    await notDeleted(world({ tree: [...world().tree, { path: 'installs/shop.json', sha: gitBlobSha('{}') }] }), {}, /install record/);
    await notDeleted(world({ tree: [...world().tree, { path: 'installs/other.json', sha: gitBlobSha('{}') }] }), {}, /install record/);
    // a file pipegen didn't write: the user's own, a pipegen path with other bytes, an edited README, a link
    await notDeleted(world({ tree: [...world().tree, { path: 'notes.md', sha: gitBlobSha('mine') }] }), {}, /notes\.md/);
    await notDeleted(world({ tree: [{ path: '.github/workflows/shop--merge.yml', sha: gitBlobSha('changed') }] }));
    await notDeleted(world({ tree: [{ path: 'README.md', sha: gitBlobSha(`${readme}\nmy notes\n`) }] }));
    await notDeleted(world({ tree: [{ path: '.github/workflows/shop--merge.yml', sha: gitBlobSha('merge'), type: 'commit' }] }));
    // a pipegen file of this record is fine (its recorded bytes)
    expect((await run(world({ tree: [{ path: '.github/workflows/shop--merge.yml', sha: gitBlobSha('merge') }] }))).out.deleted).toBe(true);
    // ... unless adopted or owner-edited
    await notDeleted(world({ tree: [{ path: '.github/workflows/shop--merge.yml', sha: gitBlobSha('merge') }] }), { rec: recOf({ files: [{ repo: 'central', path: '.github/workflows/shop--merge.yml', part: 'pipeline', shas: [gitBlobSha('merge')], adopted: true }] }) });
    await notDeleted(world({ tree: [{ path: '.github/workflows/shop--merge.yml', sha: gitBlobSha('merge') }] }), { rec: recOf({ files: [{ repo: 'central', path: '.github/workflows/shop--merge.yml', part: 'pipeline', shas: [gitBlobSha('merge')], ownerEdited: true }] }) });
    // an app file of the record never counts for central
    await notDeleted(world({ tree: [{ path: '.github/workflows/shop--merge.yml', sha: gitBlobSha('merge') }] }), { rec: recOf({ files: [{ repo: 'app', path: '.github/workflows/shop--merge.yml', part: 'pipeline', shas: [gitBlobSha('merge')] }] }) });
    // a CODEOWNERS that was there before pipegen's edit
    await notDeleted(world(), { rec: recOf({ edits: [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: 'x', originalSha: SHA, writtenShas: [gitBlobSha('owners')] }] }) });
    // other branches
    await notDeleted(world({ branches: ['main', 'wip'] }), {}, /wip/);
    // the repo GitHub names: id, marker, name, owner
    await notDeleted(world({ repo: { ...world().repo, id: 999 } }), {}, /id/);
    await notDeleted(world({ repo: { ...world().repo, description: 'my pipelines' } }), {}, /marker/);
    await notDeleted(world({ repo: { ...world().repo, full_name: 'acme/pipelines2' } }));
    await notDeleted(world({ repo: { ...world().repo, owner: { login: 'evil' } } }));
    // the record: created by pipegen, with its id
    await notDeleted(world(), { rec: recOf({ central: { repoId: CENTRAL_ID, createdByPipegen: false } }) });
    await notDeleted(world(), { rec: recOf({ central: { createdByPipegen: true } }) });
    await notDeleted(world(), { rec: recOf({ central: undefined }) });
    // the typed name, from the terminal only
    await notDeleted(world(), { typedAs: 'pipeline' });
    const ni = await notDeleted(world(), { interactive: false });
    expect(ni.asked).toEqual([]);
    // GitHub still shows the repo after the DELETE
    const still = await run(world({ afterDelete: 'there' }));
    expect(still.out.deleted).toBe(false);
    expect(still.out.why).toMatch(/still/);
    // another repo than <owner>/pipelines is refused before any call
    for (const central of [{ owner: OWNER, repo: 'shop' }, { owner: 'evil', repo: 'pipelines' }, { owner: OWNER, repo: 'Pipelines2' }]) {
      const f = fakeGh();
      await expect(deleteCentralRepo(f.gh, central, recOf(), { prompt: prompter(['pipelines']), interactive: true, clock: clock() })).rejects.toBeInstanceOf(UninstallRefusal);
      expect(f.calls).toEqual([]);
    }
  });

  it('central: the checks run again after the typed name; a change in between keeps the repo', async () => {
    let n = 0;
    const w = world();
    const f = fakeGh((route) => {
      if (route === 'GET /repos/{owner}/{repo}') return w.repo;
      if (route === 'GET /repos/{owner}/{repo}/branches') return [{ name: 'main' }];
      if (route === 'GET /repos/{owner}/{repo}/git/ref/{ref}') return { object: { sha: (n++ === 0 ? 'a' : 'c').repeat(40) } };
      if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { tree: { sha: SHA }, parents: [] };
      if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { truncated: false, tree: w.tree.map((e) => ({ path: e.path, sha: e.sha, mode: '100644', type: 'blob' })) };
      return {};
    });
    const out = await deleteCentralRepo(f.gh, { owner: OWNER, repo: 'pipelines' }, recOf(), { prompt: prompter(['pipelines']), interactive: true, clock: clock() });
    expect(out.deleted).toBe(false);
    expect(out.why).toMatch(/changed/);
    expect(f.calls.some((c) => c.route === 'DELETE /repos/{owner}/{repo}')).toBe(false);
  });
});
