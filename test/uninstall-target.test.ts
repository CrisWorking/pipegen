// v0.2 Plan V V3 (rulings V-B5, V-B6, V-S11, V-S13, V-S16, V-N2, V-N7): the one module of src/uninstall that sends a write.
// GitHub is a fake Octokit (a request function and a log of what was sent); the prompt is a fake; nothing touches the network.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Octokit } from '@octokit/rest';
import { moduleRefs } from './helpers/import-scan.js';
import { describe, expect, it } from 'vitest';
import { gitBlobSha } from '../src/create/guard.js';
import { centralWorkflowFile } from '../src/engine/central-path.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { requiredRulesetName } from '../src/layers/locks.js';
import { helperDescription } from '../src/proof/target.js';
import type { InstallRecord } from '../src/types.js';
import {
  deleteCentralRepo, environmentOwned, goneOr, isPipegens, pipegenBranch, UNINSTALL_WRITE_ROUTES, UninstallApi, UninstallRefusal, uninstallBranch,
  type AskName, type Confirmable, type Owned, type TypedName,
} from '../src/uninstall/target.js';

const OWNER = 'acme';
const APP = { owner: OWNER, repo: 'shop', repoId: 101 };
const CENTRAL_ID = 202;
const AT = '2026-11-01T10:00:00Z';
const SHA = 'a'.repeat(40);
const PIN = 'b'.repeat(40);
// key names built at runtime: written out, they look like secret assignments to the redactor (test/no-secret-literals.test.ts)
const SN = ['secret', 'name'].join('_');
const SS = ['secret', 'scanning'].join('_');
const SP = `${SS}_push_protection`;
const LIST = ['sec', 'rets'].join('') as 'secrets';

interface Call { route: string; params: Record<string, unknown> }
type Handler = (route: string, params: Record<string, unknown>) => unknown;
const httpErr = (status: number, message = ''): Error => Object.assign(new Error(`HTTP ${status}`), { status, response: { data: { message }, headers: {} } });

/** GitHub's ids of the repos (the app and its central repo); a repo read answers them unless the test answers it itself (`raw`). */
const IDS: Record<string, number> = { shop: 101, pipelines: 202 };
function fakeGh(handler: Handler = () => ({}), opts: { raw?: boolean; repo?: Record<string, unknown> } = {}): { gh: Octokit; calls: Call[]; writes: () => Call[] } {
  const calls: Call[] = [];
  const gh = {
    request: async (route: string, params: Record<string, unknown> = {}) => {
      calls.push({ route, params });
      if (opts.raw !== true && route === 'GET /repos/{owner}/{repo}') {
        const n = String(params.repo).toLowerCase();
        return { status: 200, data: { id: IDS[n] ?? 999, full_name: `${OWNER}/${n}`, default_branch: 'main', ...opts.repo }, headers: {} };
      }
      // V6 (V3-hook1): the central default branch target.ts reads before a shared central write: no other project there
      if (opts.raw !== true && String(params.repo).toLowerCase() === 'pipelines') {
        if (route === 'GET /repos/{owner}/{repo}/git/ref/{ref}' && params.ref === 'heads/main') return { status: 200, data: { object: { sha: CENTRAL_HEAD } }, headers: {} };
        if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}' && params.commit_sha === CENTRAL_HEAD) return { status: 200, data: { sha: CENTRAL_HEAD, tree: { sha: CENTRAL_HEAD } }, headers: {} };
        if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}' && params.tree_sha === CENTRAL_HEAD) return { status: 200, data: { truncated: false, tree: [] }, headers: {} };
      }
      const data = await handler(route, params);
      return { status: 200, data, headers: {} };
    },
  };
  return { gh: gh as unknown as Octokit, calls, writes: () => calls.filter((c) => !c.route.startsWith('GET ')) };
}
const clock = () => ({ budget: newRateBudget(), sleep: async () => {}, now: () => 0 });
/** The central default head the fake answers (V6's last-project read), with an empty tree. */
const CENTRAL_HEAD = 'e'.repeat(40);
/** The terminal's typed-name question (V1's askTypedName in the real run): answers yes for `answer` (true: every name). */
function asker(answer: boolean | string = true): AskName & { asked: { expected: string; question: string }[] } {
  const asked: { expected: string; question: string }[] = [];
  // V6 (spec N3): the number of each of pipegen's own central pull requests is typed too before the central repo goes
  const fn = async (expected: string, question: string) => { asked.push({ expected, question }); return answer === true || answer === expected || (typeof answer === 'string' && /^[0-9]+$/.test(expected)); };
  return Object.assign(fn, { asked });
}
type ApiOpts = { askName?: AskName; centralRepoId?: number; typedNames?: boolean; raw?: boolean; repo?: Record<string, unknown> };
const api = (h?: Handler, o: ApiOpts = {}) => {
  const f = fakeGh(h, { raw: o.raw, repo: o.repo });
  const ask = o.askName ?? asker(true);
  return { ...f, ask, api: new UninstallApi(f.gh, APP, { clock: clock(), askName: ask, centralRepoId: o.centralRepoId ?? CENTRAL_ID, typedNames: o.typedNames }) };
};
const typedOn = async (a: UninstallApi, c: Confirmable): Promise<TypedName> => {
  const t = await a.confirm(c);
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

/** GitHub's answers to the settings reads, as pipegen left them (sec N-M5). */
const pipegenSa = { security_and_analysis: { [SS]: { status: 'enabled' }, [SP]: { status: 'enabled' } } };
const settingsNow = (over: { perms?: unknown; access?: unknown; alerts?: number; autofix?: unknown } = {}): Handler => (route) => {
  if (route === 'GET /repos/{owner}/{repo}/automated-security-fixes') { if (typeof over.autofix === 'number') throw httpErr(over.autofix); return over.autofix ?? { enabled: false, paused: false }; }
  if (route === 'GET /repos/{owner}/{repo}/actions/permissions') return over.perms ?? { enabled: true, allowed_actions: 'all', sha_pinning_required: true };
  if (route === 'GET /repos/{owner}/{repo}/actions/permissions/access') return over.access ?? { access_level: 'organization' };
  if (route === 'GET /repos/{owner}/{repo}/vulnerability-alerts') { if (over.alerts === 404) throw httpErr(404); return undefined; }
  return {};
};

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

    // GitHub's settings now: what pipegen set (sec N-M5: a settings write is sent only while they are)
    const { api: a, calls } = api(settingsNow(), { repo: pipegenSa });
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
    await refused('PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { [SS]: { status: 'enabled' } }, name: 'x' });
    await refused('PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { advanced_security: { status: 'disabled' } } });
    await refused('PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { [SS]: { status: 'off' } } });
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
    // the restores of what pipegen changed go only through their own functions too (sec M7): a live compare, the record entry, a typed name
    await refused('PUT /repos/{owner}/{repo}/environments/{environment_name}', { ...app, environment_name: 'prod', wait_timer: 0 });
    await refused('PATCH /repos/{owner}/{repo}/actions/variables/{name}', { ...app, name: 'PIPEGEN_BLOCK_FROM', value: 'old' });
    await refused('DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}', { ...app, environment_name: 'prod', branch_policy_id: 5 });
    // the identity-checked deletes, the protection, PR closes and branch deletes go only through their own functions
    await refused('DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}', { ...app, ruleset_id: 7 });
    await refused('DELETE /orgs/{org}/rulesets/{ruleset_id}', { org: OWNER, ruleset_id: 9 });
    await refused('DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}', { ...app, [SN]: 'PIPEGEN_X' });
    await refused('DELETE /repos/{owner}/{repo}/environments/{environment_name}', { ...app, environment_name: 'prod' });
    await refused('DELETE /repos/{owner}/{repo}/branches/{branch}/protection', { ...app, branch: 'main' });
    await refused('PUT /repos/{owner}/{repo}/branches/{branch}/protection', { ...app, branch: 'main' });
    await refused('PATCH /repos/{owner}/{repo}/pulls/{pull_number}', { ...app, pull_number: 3, state: 'closed' });
    await refused('DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ...app, ref: 'heads/pipegen/setup' });
    expect(calls).toEqual([]);

    // and the allowed ones are sent as given, owner and repo included
    await a.write('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { owner: 'ACME', repo: 'Shop' });
    await a.write('PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { [SS]: { status: 'disabled' }, [SP]: { status: 'disabled' } } });
    await a.write('PUT /repos/{owner}/{repo}/actions/permissions', { ...app, enabled: true, allowed_actions: 'all', sha_pinning_required: false });
    expect(await a.write('PUT /repos/{owner}/{repo}/actions/permissions/access', { owner: OWNER, repo: 'pipelines', access_level: 'none' }, { pipegenSet: 'organization' })).toEqual({ status: 'done' });
    expect(calls.filter((c) => !c.route.startsWith('GET ')).map((c) => c.route)).toEqual([
      'DELETE /repos/{owner}/{repo}/vulnerability-alerts', 'PATCH /repos/{owner}/{repo}', 'PUT /repos/{owner}/{repo}/actions/permissions', 'PUT /repos/{owner}/{repo}/actions/permissions/access',
    ]);
    expect(calls.filter((c) => c.route === 'PATCH /repos/{owner}/{repo}')[0]?.params).toEqual({ ...app, security_and_analysis: { [SS]: { status: 'disabled' }, [SP]: { status: 'disabled' } } });

    // reads: GETs only, never the contents API, the same owner/repo/org check
    await expect(a.read('GET /repos/{owner}/{repo}/contents/{path}', { ...app, path: 'x' })).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(a.read('POST /repos/{owner}/{repo}/rulesets', app)).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(a.read('GET /repos/{owner}/{repo}', { owner: OWNER, repo: 'other' })).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(a.read('GET /orgs/{org}/rulesets/{ruleset_id}', { org: 'evil', ruleset_id: 9 })).rejects.toBeInstanceOf(UninstallRefusal);

    // the source scan (a lint beside the run-time allow-list): no other file of src/uninstall sends a GitHub write
    const dir = join(import.meta.dirname, '..', 'src', 'uninstall');
    // V7 (V6-R3 M3): every code file, whatever its extension (a .mts or .js file was never read), and src/cli/uninstall.ts (V7's file) too
    const files = readdirSync(dir).filter((x) => /\.(?:[cm]?[jt]s|[jt]sx)$/.test(x));
    expect(files).toContain('target.ts');
    expect(readdirSync(dir).filter((x) => !files.includes(x))).toEqual([]);
    for (const f of files) {
      const src = readFileSync(join(dir, f), 'utf8');
      expect(scanProblems(f, src), f).toEqual([]);
    }
    expect(scanProblems('uninstall.ts', readFileSync(join(dir, '..', 'cli', 'uninstall.ts'), 'utf8')), 'src/cli/uninstall.ts').toEqual([]);
    // the scan itself catches the obvious ways around the guard
    for (const bad of [
      'await gh.request(\'DELETE /repos/{owner}/{repo}\', p);', 'await octokit.rest.repos.delete(p);', 'import { ghWrite } from \'../deliver/git-data.js\';',
      'import { commitFiles, readTree } from \'../deliver/git-data.js\';', 'import { guardedWrite } from \'../proof/target.js\';', 'import { createHelperRepo } from \'../proof/target.js\';',
      'import { SettingsApi } from \'../deliver/settings-api.js\';', 'import { writeRecord } from \'../deliver/record.js\';', 'const { request } = gh;', 'gh[\'request\'](r)',
      'import { request } from \'@octokit/request\';', 'await fetch(url)', 'x.request.call(gh, r)', 'await storeEnvSecret(gh, a)',
      // sec I7: the forms the deny-list missed
      'import { ensureActionsAccess } from \'../proof/repos.js\';', 'import { setScratchDefaultBranch } from \'../proof/repos.js\';',
      'import { cleanupAfterProof } from \'../proof/cleanup.js\';', 'import { storeRepoSecret } from \'../create/secrets.js\';',
      'import { storeSecrets as keep } from \'../create/secrets.js\';', 'import { storeSecretsVia } from \'../create/secrets.js\';',
      'import { finish } from \'../deliver/finish.js\';', 'import { deliver, deliverCentral } from \'../deliver/deliver.js\';', 'import { update } from \'../deliver/update.js\';',
      'Reflect.apply(api.gh.request, api.gh, [r]);', 'const send = api.gh.request;', 'const { gh: { request: send } } = api;', 'call(gh, "request")',
      'import * as gd from \'../deliver/git-data.js\';', 'const m = await import(\'../deliver/git-data.js\');', 'const m = require(\'../deliver/git-data.js\');',
      'import {\n  readTree,\n  ghWrite,\n} from \'../deliver/git-data.js\';', 'export { ghWrite } from \'../deliver/git-data.js\';',
      'import { readTree, setBranch as move } from \'../deliver/git-data.js\';', 'import git from \'../deliver/git-data.js\';',
    ]) expect(scanProblems('plan.ts', bad), bad).not.toEqual([]);
    for (const ok of [
      'import { cleanupWrite, deleteScratchSecret, deleteScratchRepo, proofTarget } from \'../proof/target.js\';', 'import { readTree, readBlobText } from \'../deliver/git-data.js\';',
      // V1's record.ts imports (src/uninstall/record.ts on v0.2/plan-V-V1)
      'import { DeliverError, ghRead, readHead, readRepo, statusOf, type RepoRef } from \'../deliver/git-data.js\';', 'import { SETUP_BRANCH } from \'../deliver/deliver.js\';',
      'import { clockOf, GitHubAccessError } from \'../github/client.js\';', 'import type { SettingsApi } from \'../deliver/settings-api.js\';',
      'import { UNINSTALL_WRITE_ROUTES, UninstallApi } from \'./target.js\';', '// close the pull request\nconst s = \'the pull request\';',
    ]) {
      expect(scanProblems('plan.ts', ok), ok).toEqual([]);
    }
  });
});

/**
 * The code of a file without its comments and string literals (so "pull request" in a message is not a `request`). A template literal's
 * text goes, but the code of each `${…}` in it stays (sec M-r2-4), nested templates and braces included.
 */
function codeOnly(src: string): string {
  let out = '';
  let depth = 0;
  const open: number[] = [];   // the brace depth at each `${` still open
  let i = 0;
  /** A template's text from `i` to its end or its next `${`. */
  const templateText = (): void => {
    while (i < src.length && src[i] !== '`' && !(src[i] === '$' && src[i + 1] === '{')) i += src[i] === '\\' ? 2 : 1;
    out += "''";
    if (src[i] === '$') { open.push(depth); out += ' '; i += 2; } else i += 1;
  };
  while (i < src.length) {
    const ch = src[i] as string;
    const next = src[i + 1];
    if (ch === '/' && next === '*') { const e = src.indexOf('*/', i + 2); i = e < 0 ? src.length : e + 2; out += ' '; continue; }
    if (ch === '/' && next === '/') { const e = src.indexOf('\n', i); i = e < 0 ? src.length : e; out += ' '; continue; }
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== ch && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      i = j + 1; out += "''"; continue;
    }
    if (ch === '`') { i += 1; templateText(); continue; }
    if (ch === '}' && open.length > 0 && open[open.length - 1] === depth) { open.pop(); i += 1; templateText(); continue; }
    if (ch === '{') depth += 1;
    if (ch === '}') depth -= 1;
    out += ch;
    i += 1;
  }
  return out;
}
/** Per module of src/, the value names another file of src/uninstall may import (sec I7: an allow-list, not a deny-list). */
const GIT_DATA_READS = ['DeliverError', 'ISO_RE', 'isoAt', 'statusOf', 'refusedMove', 'checkBranch', 'ghRead', 'readRepo', 'readHead', 'readTree', 'readBlobText', 'compareStatus', 'findOpenPr'];
const PROOF_OK = ['cleanupWrite', 'deleteScratchSecret', 'deleteScratchRepo', 'proofTarget', 'assertScratch', 'isProofTarget', 'validBranchName', 'SCRATCH_MARKER', 'SCRATCH_PREFIX', 'CENTRAL_REPO', 'helperDescription', 'githubRead', 'cleanupLeftovers', 'StateStore', 'loadState', 'ProofStopError', 'ScratchGuardError', 'StateError'];
const WRITERS = /\b(?:ghWrite|commitFiles|setBranch|openOrUpdatePr|writeRecord|writeLocalRecord|SettingsApi|guardedWrite|createHelperRepo|makeRepoPrivate|scratchSecretSink|storeEnvSecret|storeCosignKey|ensureSigningEnvironment|writeFinishPending|addLocalLeftovers|ensureActionsAccess|setScratchDefaultBranch|cleanupAfterProof|storeRepoSecret|storeSecrets|storeSecretsVia|deliverCentral)\b/;
function importProblems(src: string): string[] {
  const out: string[] = [];
  // V6-R2 sec M2: read from the parsed code (test/helpers/import-scan.ts), so a comment or string trick can't hide an import
  for (const r of moduleRefs(src).refs) {
    if (r.spec === null || r.kind === 'dynamic' || r.kind === 'require') { out.push(`a dynamic import or require of ${r.spec ?? 'something that is not a plain string'}`); continue; }
    const spec = r.spec;
    if (spec.startsWith('node:') || spec === '@octokit/rest' || spec === 'yaml' || spec === 'zod') continue;
    const mod = spec.replace(/^(?:\.\.?\/)+/, '').replace(/\.js$/, '');
    if (mod === 'target' && spec.startsWith('./')) continue;   // the guarded module itself
    if (r.namespace || r.default) { out.push(`a default or namespace import from ${spec}`); continue; }
    for (const n of r.names.map((x) => x.imported)) {
      const ok = mod === 'deliver/git-data' ? GIT_DATA_READS.includes(n)
        : mod.startsWith('proof/') ? PROOF_OK.includes(n)
          : mod === 'create/secrets' ? false
            : ['deliver/finish', 'deliver/deliver', 'deliver/update'].includes(mod) ? /^[A-Z][A-Z0-9_]*$/.test(n) || n === 'centralFilesOf' || n === 'readEnv'
              : !WRITERS.test(n);
      if (!ok) out.push(`${n} from ${spec}`);
    }
  }
  return out;
}
/**
 * Sec M-r2-4: the client's own namespaces, read from an Octokit at test time (every key whose value is an object of functions:
 * `repos`, `pulls`, … and whatever a later @octokit/rest adds), never a hand-written list.
 */
const OCTOKIT_NAMESPACES: readonly string[] = (() => {
  const o = new Octokit() as unknown as Record<string, unknown>;
  return Object.keys(o).filter((k) => {
    const v = o[k];
    return typeof v === 'object' && v !== null && Object.keys(v).length > 0 && Object.values(v).every((f) => typeof f === 'function');
  });
})();
/** A namespace of the client, or `rest` (which holds them all). */
const NS = `(?:${[...OCTOKIT_NAMESPACES, 'rest'].join('|')})`;
/** `.` or `?.` */
const DOT = String.raw`\s*\??\.\s*`;
const ARRAY_METHODS = 'filter|map|find|findIndex|findLast|findLastIndex|some|every|forEach|reduce|includes|indexOf|slice|concat|flat|flatMap|join|sort|toSorted|at|keys|values|entries|length';
/** `<x>.<namespace>.<method>(` (`?.` anywhere): an Octokit endpoint method (with or without `.rest`); an array method on a list of that name is not one. */
const OCTOKIT_ENDPOINT_RE = new RegExp(String.raw`${DOT}${NS}${DOT}(?!(?:${ARRAY_METHODS})\b)[A-Za-z]+\s*(?:\?\.\s*)?\(`);
/** `<namespace>.<method>.call(` / `.apply(` / `.bind(`. */
const ENDPOINT_CALL_RE = new RegExp(String.raw`${DOT}${NS}${DOT}[A-Za-z]+${DOT}(?:call|apply|bind)\b`);
/** A bracket right after a namespace (`gh.repos['delete']`, `gh.repos[m]`, `?.[`), a number index of a list excepted. */
const NS_BRACKET_RE = new RegExp(String.raw`${DOT}${NS}\s*(?:\?\.\s*)?\[(?!\s*\d+\s*\])`);
/** A namespace in a destructuring pattern (`const { repos } = gh`, `{ repos: r }`, `{ rest: { repos } }`); a `...rest` element is not one. */
const NS_DESTRUCTURE_RE = new RegExp(String.raw`\{[^{}]*(?<!\.\.\.\s*)\b${NS}\b[^{}]*\}(?:\s*\})*\s*=(?![=>])`);
/** A namespace given a name of its own (`const r = gh.repos;`, `= api.gh?.pulls`). */
const NS_ALIAS_RE = new RegExp(String.raw`=\s*[\w$.?]+?${DOT}${NS}\s*(?:[;,)}\]]|$)`, 'm');
/** What the scan finds wrong in one file of src/uninstall (target.ts is the one that writes). */
function scanProblems(file: string, src: string): string[] {
  const out: string[] = [];
  const code = codeOnly(src);
  const no = (re: RegExp, what: string, text = src) => { if (re.test(text)) out.push(what); };
  no(/@octokit\/(?:request|graphql|core)\b/, 'an Octokit transport import');
  no(/\bfetch\s*\(/, 'a fetch', code);
  no(/\.graphql\s*[(.`]/, 'a graphql call', code);
  no(/\{[^{}]*\b(?:request|graphql)\b[^{}]*\}\s*=\s*[\w.]+/, 'a destructured request');
  no(/\b(?:gh|octokit)\s*\[/, 'bracket access on a client', code);
  no(new RegExp(String.raw`\[\s*['"\`](?:request|graphql|paginate|hook|${NS.slice(3, -1)})['"\`]\s*\]`), 'bracket access on a client');
  no(/\.(?:request|graphql)\s*\.(?:bind|call|apply)\b/, 'a bound request', code);
  no(/=\s*[\w.]+\.(?:request|graphql)\s*[;,)\n]/, 'an aliased request', code);
  if (file === 'target.ts') return out;
  const body = code.replace(/\b(?:import|export)\b[^;]*?\bfrom\s*''\s*;?/g, ' ');   // the imports are checked by name below
  no(/\brequest\b/, 'the word request in code', body);
  no(/['"`]request['"`]/, 'the name request as a string');
  no(/\bReflect\s*\./, 'Reflect', code);
  no(/\bimport\s*\(/, 'a dynamic import', code);
  no(/\brequire\s*\(/, 'a require', code);
  no(/\.rest\s*\.\s*[a-zA-Z]+/, 'gh.rest', code);
  // sec N-I2: @octokit/rest also hangs every endpoint method on the client itself (legacyRestEndpointMethods: gh.repos.delete, …), and
  // paginate / graphql / hook send whatever their route or query says; none of them belongs outside target.ts
  no(OCTOKIT_ENDPOINT_RE, 'an Octokit endpoint method', code);
  // sec M-r2-4: the same methods reached another way
  no(ENDPOINT_CALL_RE, 'an endpoint method called through .call, .apply or .bind', code);
  no(NS_BRACKET_RE, 'a bracket after an Octokit namespace', code);
  no(NS_DESTRUCTURE_RE, 'a destructured Octokit namespace', code);
  no(NS_ALIAS_RE, 'an aliased Octokit namespace', code);
  no(/\bpaginate\b/, 'paginate', code);
  no(/\bgraphql\b/, 'graphql', code);
  no(/\.\s*hook\b|\bhook\s*[,}]/, 'an Octokit hook', code);
  no(WRITERS, 'a write function of another module', body);
  no(/\bmethod\s*:\s*['"`](?:POST|PUT|PATCH|DELETE)/, 'a write method');
  out.push(...importProblems(src));
  return out;
}

// ---------- 2. identity ----------

describe('V3 target: identity of what pipegen created', () => {
  it('apply: ruleset deleted only when GET says pipegen\'s name, this repo as source and the recorded created_at', async () => {
    const run = async (live: Record<string, unknown>, entry = rsEntry(), opts: { typed?: boolean } = {}) => {
      const f = api((route) => (route.startsWith('GET ') ? live : {}));
      const t = opts.typed === true ? await typedOn(f.api, { kind: 'ruleset', entry }) : undefined;
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
    const other = await typedOn(f.api, { kind: 'ruleset', entry: rsEntry({ kind: 'reviews', id: 8, name: 'pipegen-reviews' }) });
    await expect(f.api.deleteIfPipegens(unconf, { typed: other })).rejects.toBeInstanceOf(UninstallRefusal);
    expect(f.writes()).toEqual([]);
    const t = await typedOn(f.api, unconf);
    expect((await f.api.deleteIfPipegens(unconf, { typed: t })).status).toBe('deleted');
    expect(f.writes().length).toBe(1);
    await expect(f.api.deleteIfPipegens(unconf, { typed: t })).rejects.toBeInstanceOf(UninstallRefusal);   // used once
    await expect(f.api.deleteIfPipegens(unconf, { typed: Object.freeze({ name: 'pipegen' }) as never })).rejects.toBeInstanceOf(UninstallRefusal);   // a look-alike
    // a typed name never turns a "not pipegen's" into a delete
    const g = api((route) => (route.startsWith('GET ') ? liveRuleset({ source: 'acme/other' }) : {}));
    expect((await g.api.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() }, { typed: await typedOn(g.api, { kind: 'ruleset', entry: rsEntry() }) })).status).toBe('kept');
    expect(g.writes()).toEqual([]);

    // typed names come only from the terminal's question (V1's askTypedName, injected): none → refused; another answer → null
    const n = new UninstallApi(fakeGh().gh, APP, { clock: clock() });
    await expect(n.confirm(unconf)).rejects.toBeInstanceOf(UninstallRefusal);
    const no = api(undefined, { askName: asker(false) });
    expect(await no.api.confirm(unconf)).toBeNull();
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
      const f = api((route) => (route.endsWith('/secrets') || route.endsWith('/variables') ? { total_count: 0, [LIST]: [], variables: [] } : route.startsWith('GET ') ? live : {}));
      const out = await f.api.deleteIfPipegens(o);
      return { out, calls: f.calls.filter((c) => c.route !== 'GET /repos/{owner}/{repo}') };
    };
    const s = await run({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_X', created_at: AT });
    expect(s.out.status).toBe('deleted');
    expect(s.calls.map((c) => [c.route, c.params])).toEqual([
      ['GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', { owner: OWNER, repo: 'shop', environment_name: 'pipegen-signing', [SN]: 'PIPEGEN_X' }],
      ['DELETE /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', { owner: OWNER, repo: 'shop', environment_name: 'pipegen-signing', [SN]: 'PIPEGEN_X' }],
    ]);
    const c = await run({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'central', created: true, githubCreatedAt: AT } }, { name: 'PIPEGEN_X', created_at: AT });
    expect(c.calls.at(-1)).toEqual({ route: 'DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}', params: { owner: OWNER, repo: 'pipelines', [SN]: 'PIPEGEN_X' } });
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
    const parentOk = api((route) => { if (route === 'GET /repos/{owner}/{repo}') return { id: 101 }; throw httpErr(404); }, { raw: true });
    expect((await parentOk.api.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() })).status).toBe('gone');
    expect(parentOk.calls.map((c) => c.route)).toEqual(['GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', 'GET /repos/{owner}/{repo}']);
    expect(parentOk.writes()).toEqual([]);
    // the repo read also 404s (no access to a private repo looks the same) → leftover
    const parentGone = api(() => { throw httpErr(404); }, { raw: true });
    const lp = await parentGone.api.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() });
    expect(lp.status).toBe('leftover');
    expect(lp).toMatchObject({ manual: 'gh api -X DELETE repos/acme/shop/rulesets/7' });
    // 403 on the GET or on the DELETE → leftover with the exact manual step
    const f403 = api(() => { throw httpErr(403); });
    expect(await f403.api.deleteIfPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, githubCreatedAt: AT } })).toMatchObject({ status: 'leftover', manual: 'gh secret delete PIPEGEN_X --repo acme/shop' });
    const d403 = api((route) => { if (route.startsWith('GET ')) return liveOrg(); throw httpErr(403); });
    expect(await d403.api.deleteIfPipegens({ kind: 'org-ruleset', entry: orgEntry(), centralRepoId: CENTRAL_ID })).toMatchObject({ status: 'leftover', manual: 'gh api -X DELETE orgs/acme/rulesets/9' });
    // a 404 on the DELETE: gone only after the repo read; an org rule's parent is the org's ruleset list
    let reads = 0;
    const d404 = api((route) => { if (route === 'GET /orgs/{org}/rulesets/{ruleset_id}' && reads++ === 0) return liveOrg(); if (route === 'GET /orgs/{org}/rulesets') return []; throw httpErr(404); });
    expect((await d404.api.deleteIfPipegens({ kind: 'org-ruleset', entry: orgEntry() })).status).toBe('gone');
    expect(d404.calls.map((c) => c.route).filter((r) => r !== 'GET /repos/{owner}/{repo}')).toEqual(['GET /orgs/{org}/rulesets/{ruleset_id}', 'DELETE /orgs/{org}/rulesets/{ruleset_id}', 'GET /orgs/{org}/rulesets/{ruleset_id}', 'GET /orgs/{org}/rulesets']);
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
    const main = { kind: 'classic' as const, branch: 'main' };
    const f = api((route) => (route.startsWith('GET ') ? liveGet() : {}));
    await expect(f.api.restoreClassic({ branch: 'main', previous: null }, planned)).rejects.toBeInstanceOf(UninstallRefusal);   // no typed name
    await expect(f.api.restoreClassic({ branch: 'main', previous: null }, planned, await typedOn(f.api, { kind: 'classic', branch: 'dev' }))).rejects.toBeInstanceOf(UninstallRefusal);
    expect(f.writes()).toEqual([]);
    expect(await f.api.restoreClassic({ branch: 'main', previous: null }, planned, await typedOn(f.api, main))).toEqual({ status: 'deleted' });
    expect(f.writes()).toEqual([{ route: 'DELETE /repos/{owner}/{repo}/branches/{branch}/protection', params: { owner: OWNER, repo: 'shop', branch: 'main' } }]);
    // the owner changed the protection since: kept, manual
    const g = api((route) => (route.startsWith('GET ') ? liveGet({ enforce_admins: { enabled: false } }) : {}));
    expect((await g.api.restoreClassic({ branch: 'main', previous: null }, planned, await typedOn(g.api, main))).status).toBe('kept');
    expect(g.writes()).toEqual([]);
    // no plan (a typed view) → kept
    const h = api((route) => (route.startsWith('GET ') ? liveGet() : {}));
    expect((await h.api.restoreClassic({ branch: 'main', previous: null }, undefined, await typedOn(h.api, main))).status).toBe('kept');
    expect(h.writes()).toEqual([]);
    // previous: PUT exactly it
    const p = api((route) => (route.startsWith('GET ') ? liveGet() : {}));
    expect(await p.api.restoreClassic({ branch: 'main', previous: prev }, planned, await typedOn(p.api, main))).toEqual({ status: 'restored' });
    expect(p.writes()).toEqual([{ route: 'PUT /repos/{owner}/{repo}/branches/{branch}/protection', params: { owner: OWNER, repo: 'shop', branch: 'main', ...prev } }]);
    // a previous with keys the PUT doesn't take is refused
    const q = api((route) => (route.startsWith('GET ') ? liveGet() : {}));
    await expect(q.api.restoreClassic({ branch: 'main', previous: { ...prev, baseUrl: 'x' } }, planned, await typedOn(q.api, main))).rejects.toBeInstanceOf(UninstallRefusal);
    expect(q.writes()).toEqual([]);
    // already gone and nothing to restore
    const r = api((route) => { if (route === 'GET /repos/{owner}/{repo}') return { id: 101 }; throw httpErr(404); }, { raw: true });
    expect((await r.api.restoreClassic({ branch: 'main', previous: null }, planned, await typedOn(r.api, main))).status).toBe('gone');
    expect(r.writes()).toEqual([]);
  });
});

// ---------- 5. PRs and branches ----------

describe('V3 target: pull requests and branches', () => {
  it('target: a PR close or branch delete outside pipegen/* is refused before it is sent', async () => {
    const pr = (ref: string, over: Record<string, unknown> = {}) => ({ number: 3, state: 'open', head: { ref, repo: { id: 101, full_name: 'acme/shop' } }, ...over });
    const run = async (live: Record<string, unknown>, where: 'app' | 'central' = 'app') => {
      const f = api((route) => (route.startsWith('GET ') ? live : {}));
      let err: unknown;
      let out: unknown;
      try { out = await f.api.closePr(where, 3); } catch (e) { err = e; }
      return { err, out, writes: f.writes() };
    };
    for (const live of [pr('main'), pr('feature/pipegen/x'), pr('pipegen'), pr('pipegen/setup', { head: { ref: 'pipegen/setup', repo: { full_name: 'evil/shop' } } }), pr('pipegen/setup', { head: { ref: 'pipegen/setup', repo: null } })]) {
      const r = await run(live);
      expect(r.err, JSON.stringify(live)).toBeInstanceOf(UninstallRefusal);
      expect(r.writes).toEqual([]);
    }
    const ok = await run(pr('pipegen/setup'));
    expect(ok.err).toBeUndefined();
    expect(ok.out).toEqual({ status: 'closed' });
    expect(ok.writes).toEqual([{ route: 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}', params: { owner: OWNER, repo: 'shop', pull_number: 3, state: 'closed' } }]);
    // already closed: nothing sent
    const closed = await run(pr('pipegen/update', { state: 'closed' }));
    expect(closed.writes).toEqual([]);
    // central: only this project's branches
    const centralPr = (ref: string) => ({ number: 3, state: 'open', head: { ref, repo: { id: CENTRAL_ID, full_name: 'acme/pipelines' } } });
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
    expect(await f.api.deleteBranch('app', 'pipegen/setup')).toEqual({ status: 'deleted' });
    await f.api.deleteBranch('central', 'pipegen/update-shop');
    expect(f.writes()).toEqual([
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
      if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { sha: SHA, tree: { sha: SHA } };
      // PL-E6: commitFiles checks a delete against the base tree
      if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { truncated: false, tree: [{ path: '.github/workflows/pipegen.yml', sha: SHA, mode: '100644', type: 'blob' }] };
      if (route === 'GET /repos/{owner}/{repo}/git/ref/{ref}') throw httpErr(404);
      if (route === 'GET /repos/{owner}/{repo}/pulls') return [];
      if (route === 'POST /repos/{owner}/{repo}/pulls') return { number: 12, html_url: 'u' };
      return {};
    });
    const c = await f.api.commitUninstall('app', { parent: SHA, baseTree: SHA, files: [{ path: 'package.json', content: '{}\n', mode: '100644' }], deletes: ['.github/workflows/pipegen.yml'], message: 'pipegen: uninstall' });
    expect(c).toEqual({ commit: sha(2), tree: sha(1) });
    expect(f.calls.find((x) => x.route === 'POST /repos/{owner}/{repo}/git/trees')?.params).toEqual({ owner: OWNER, repo: 'shop', base_tree: SHA, tree: [
      { path: 'package.json', mode: '100644', type: 'blob', content: '{}\n' },
      { path: '.github/workflows/pipegen.yml', mode: '100644', type: 'blob', sha: null },
    ] });
    // PL-E6: a delete of a path the base tree doesn't hold is an uninstall refusal, nothing written
    const gone = await f.api.commitUninstall('app', { parent: SHA, baseTree: SHA, files: [], deletes: ['.github/workflows/gone.yml'], message: 'm' }).catch((e: unknown) => e);
    expect(gone).toBeInstanceOf(UninstallRefusal);
    expect(f.calls.filter((x) => x.route.startsWith('POST')).length).toBe(2);
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
    edits: [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: 'x', originalSha: null, writtenShas: [gitBlobSha('owners')], baseShas: [null] } as InstallRecord['edits'][number]],   // V6b: chained from null
    [LIST]: [], variables: [], environments: [], rulesets: [], central: { repoId: CENTRAL_ID, createdByPipegen: true },
    planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] }, protectedPaths: [], ...over,
  });
  interface World {
    repo: Record<string, unknown>; tree: { path: string; sha: string; type?: string }[]; branches?: string[]; afterDelete?: 'gone' | 'there' | 'empty' | 'error';
    tags?: unknown[]; releases?: unknown[]; issues?: unknown[]; pulls?: unknown[]; secrets?: unknown[]; variables?: unknown[]; environments?: unknown[];
  }
  const world = (w: Partial<World> = {}): World => ({
    repo: { id: CENTRAL_ID, name: 'pipelines', full_name: 'acme/pipelines', owner: { login: OWNER }, description: DESC, default_branch: 'main', private: true, forks_count: 0, has_wiki: false, has_discussions: false },
    tree: [{ path: 'README.md', sha: gitBlobSha(readme) }, { path: '.github/CODEOWNERS', sha: gitBlobSha('owners') }], ...w,
  });
  /** A central world answering every read deleteCentralRepo makes. */
  const centralHandler = (w: World, state: { deleted: boolean }, head: () => string = () => SHA): Handler => (route, p) => {
    if (route === 'GET /repos/{owner}/{repo}') { if (state.deleted) { if (w.afterDelete === 'there') return w.repo; throw httpErr(w.afterDelete === 'error' ? 500 : 404); } return w.repo; }
    if (route === 'GET /repos/{owner}/{repo}/branches') return (w.branches ?? ['main']).map((name) => ({ name }));
    if (route === 'GET /repos/{owner}/{repo}/git/ref/{ref}') { if (w.afterDelete === 'empty') throw httpErr(409); return { object: { sha: head() } }; }
    if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { tree: { sha: SHA }, parents: [] };
    if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { truncated: false, tree: w.tree.map((e) => ({ path: e.path, sha: e.sha, mode: '100644', type: e.type ?? 'blob' })) };
    if (route === 'GET /repos/{owner}/{repo}/git/matching-refs/{ref}') return p.ref === '' ? [{ ref: 'refs/heads/main' }] : w.tags ?? [];
    if (route === 'GET /repos/{owner}/{repo}/comments') return [];
    if (route === 'GET /repos/{owner}/{repo}/releases') return w.releases ?? [];
    if (route === 'GET /repos/{owner}/{repo}/issues') return w.issues ?? [];
    if (route === 'GET /repos/{owner}/{repo}/pulls') return w.pulls ?? [];
    if (route === 'GET /repos/{owner}/{repo}/actions/secrets') return { total_count: (w.secrets ?? []).length, [LIST]: w.secrets ?? [] };
    if (route === 'GET /repos/{owner}/{repo}/dependabot/secrets' || route === 'GET /repos/{owner}/{repo}/codespaces/secrets') return { total_count: 0, [LIST]: [] };
    if (route === 'GET /repos/{owner}/{repo}/actions/variables') return { total_count: (w.variables ?? []).length, variables: w.variables ?? [] };
    if (route === 'GET /repos/{owner}/{repo}/environments') return { total_count: (w.environments ?? []).length, environments: w.environments ?? [] };
    if (route === 'DELETE /repos/{owner}/{repo}') { state.deleted = true; return {}; }
    if (route === 'GET /repos/{owner}/{repo}/keys' || route === 'GET /repos/{owner}/{repo}/hooks') return [];   // V6: no deploy key, no webhook
    throw httpErr(500);
  };
  const run = async (w: World, opts: { rec?: InstallRecord; typedAs?: string; askName?: AskName; central?: { owner: string; repo: string } } = {}) => {
    const f = fakeGh(centralHandler(w, { deleted: false }), { raw: true });
    const ask = asker(opts.typedAs ?? 'pipelines');
    const out = await deleteCentralRepo(f.gh, opts.central ?? { owner: OWNER, repo: 'pipelines' }, opts.rec ?? recOf(), { askName: opts.askName ?? ask, clock: clock() });
    return { out, deletes: f.calls.filter((c) => c.route === 'DELETE /repos/{owner}/{repo}'), asked: ask.asked, calls: f.calls };
  };

  it('V6b (G17C m4): the central CODEOWNERS counts as pipegen\'s file before the repo delete only when its writes chain from null', async () => {
    const owners = gitBlobSha('owners');
    const withEdit = (writtenShas: string[], baseShas?: (string | null)[]): InstallRecord => recOf({ edits: [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: 'x', originalSha: null, writtenShas, ...(baseShas === undefined ? {} : { baseShas }) } as InstallRecord['edits'][number]] });
    // m4: the owner's blob held as a write (bases [null, owner]); an older record with no bases; short; broken
    for (const rec of [withEdit([SHA, owners], [null, owners]), withEdit([owners]), withEdit([SHA, owners], [null]), withEdit([SHA, owners], [null, gitBlobSha('other')])]) {
      const r = await run(world(), { rec });
      expect(r.out.deleted, JSON.stringify(rec.edits)).toBe(false);
      expect(r.out.why).toMatch(/files pipegen didn't write.*CODEOWNERS/);
      expect(r.deletes).toEqual([]);
    }
    // chained from null: pipegen's
    expect((await run(world(), { rec: withEdit([owners], [null]) })).out).toEqual({ deleted: true });
    expect((await run(world(), { rec: withEdit([SHA, owners], [null, SHA]) })).out).toEqual({ deleted: true });
  });

  it('V6b (G17C-R1 m1): the central repo is deleted only with createdByPipegen and a recorded id equal to the live one', async () => {
    expect((await run(world(), { rec: recOf({ central: { repoId: CENTRAL_ID, createdByPipegen: true } }) })).out).toEqual({ deleted: true });
    for (const [central, live] of [
      [{ repoId: CENTRAL_ID, createdByPipegen: false }, CENTRAL_ID],   // the id, but pipegen didn't create it
      [{ createdByPipegen: true }, CENTRAL_ID],                         // created, but no id
      [{ repoId: CENTRAL_ID + 1, createdByPipegen: true }, CENTRAL_ID], // a stale id: another repo of the same name
      [{ repoId: CENTRAL_ID, createdByPipegen: true }, CENTRAL_ID + 1], // the same, from GitHub's side
      [undefined, CENTRAL_ID],
    ] as [InstallRecord['central'], number][]) {
      const r = await run(world({ repo: { ...world().repo, id: live } }), { rec: recOf({ central }) });
      expect(r.out.deleted, JSON.stringify([central, live])).toBe(false);
      expect(r.deletes).toEqual([]);
      expect(r.asked).toEqual([]);
    }
  });

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
      expect(r.out.command).toBeUndefined();   // V6-R2 sec I1: a refusal never advises the delete
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
    // the typed name, from the terminal only (V1's askTypedName stops a run without one: nothing is deleted)
    const declined = await run(world(), { typedAs: 'pipeline' });
    expect(declined.out.deleted).toBe(false);
    expect(declined.deletes).toEqual([]);
    expect(declined.out.command).toBe('gh repo delete acme/pipelines');   // V6-R2: every check passed, the user declined: theirs to run
    const stop = fakeGh(centralHandler(world(), { deleted: false }), { raw: true });
    await expect(deleteCentralRepo(stop.gh, { owner: OWNER, repo: 'pipelines' }, recOf(), { askName: async () => { throw new Error('no terminal'); }, clock: clock() })).rejects.toThrow('no terminal');
    expect(stop.calls.some((c) => c.route === 'DELETE /repos/{owner}/{repo}')).toBe(false);
    // GitHub still shows the repo after the DELETE
    const still = await run(world({ afterDelete: 'there' }));
    expect(still.out.deleted).toBe(false);
    expect(still.out.why).toMatch(/still/);
    // another repo than <owner>/pipelines is refused before any call
    for (const central of [{ owner: OWNER, repo: 'shop' }, { owner: 'evil', repo: 'pipelines' }, { owner: OWNER, repo: 'Pipelines2' }]) {
      const f = fakeGh();
      await expect(deleteCentralRepo(f.gh, central, recOf(), { askName: asker(), clock: clock() })).rejects.toBeInstanceOf(UninstallRefusal);
      expect(f.calls).toEqual([]);
    }
  });

  it('central: the checks run again after the typed name; a change in between keeps the repo', async () => {
    let n = 0;
    const f = fakeGh(centralHandler(world(), { deleted: false }, () => (n++ === 0 ? 'a' : 'c').repeat(40)), { raw: true });
    const out = await deleteCentralRepo(f.gh, { owner: OWNER, repo: 'pipelines' }, recOf(), { askName: asker(), clock: clock() });
    expect(out.deleted).toBe(false);
    expect(out.why).toMatch(/changed/);
    expect(f.calls.some((c) => c.route === 'DELETE /repos/{owner}/{repo}')).toBe(false);
  });
});

// ---------- 7. fix round 1 (VL/review-V3-security.md, VL/review-V3-spec.md, ruling V3-R1) ----------

describe('V3 fix round 1', () => {
  const planned = { method: 'PUT' as const, route: '/repos/{owner}/{repo}/branches/{branch}/protection', params: { owner: OWNER, repo: 'shop', branch: 'main' }, body: { required_status_checks: { strict: false, checks: [{ context: 'pipegen / gate', app_id: 15368 }] }, enforce_admins: true, required_pull_request_reviews: { required_approving_review_count: 0, require_code_owner_reviews: false, dismiss_stale_reviews: true, require_last_push_approval: false }, restrictions: null, allow_force_pushes: false, allow_deletions: false } };
  const asSet = (over: Record<string, unknown> = {}) => ({ required_status_checks: { strict: false, checks: [{ context: 'pipegen / gate', app_id: 15368 }] }, enforce_admins: { enabled: true }, required_pull_request_reviews: { required_approving_review_count: 0, require_code_owner_reviews: false, dismiss_stale_reviews: true, require_last_push_approval: false }, allow_force_pushes: { enabled: false }, allow_deletions: { enabled: false }, ...over });
  const prev = { required_status_checks: null, enforce_admins: false, required_pull_request_reviews: null, restrictions: null };
  const main = { kind: 'classic' as const, branch: 'main' };

  it('R1 sec I1 / spec I1: a previous holding a path key never moves the classic PUT to another branch', async () => {
    for (const k of ['branch', 'owner', 'repo']) {
      const f = api((route) => (route.startsWith('GET ') ? asSet() : {}));
      const bad = { ...prev, [k]: k === 'branch' ? 'release' : k === 'owner' ? OWNER : 'shop' };
      await expect(f.api.restoreClassic({ branch: 'main', previous: bad }, planned, await typedOn(f.api, main)), k).rejects.toBeInstanceOf(UninstallRefusal);
      expect(f.writes()).toEqual([]);
    }
    // the PUT goes to the recorded (typed) branch
    const ok = api((route) => (route.startsWith('GET ') ? asSet() : {}));
    expect((await ok.api.restoreClassic({ branch: 'main', previous: prev }, planned, await typedOn(ok.api, main))).status).toBe('restored');
    expect(ok.writes()[0]?.params.branch).toBe('main');
  });

  it('R1 sec I2: the classic PUT only replaces the protection pipegen set; changed since or gone → kept with the manual step', async () => {
    // the owner added their own check and linear history after the install
    for (const live of [
      asSet({ required_status_checks: { strict: false, checks: [{ context: 'pipegen / gate', app_id: 15368 }, { context: 'my-ci', app_id: null }] } }),
      asSet({ required_linear_history: { enabled: true } }),
      asSet({ enforce_admins: { enabled: false } }),
    ]) {
      const f = api((route) => (route.startsWith('GET ') ? live : {}));
      const out = await f.api.restoreClassic({ branch: 'main', previous: prev }, planned, await typedOn(f.api, main));
      expect(out.status, JSON.stringify(live)).toBe('kept');
      expect(out).toMatchObject({ manual: expect.stringContaining('gh api -X PUT repos/acme/shop/branches/main/protection') });
      expect(f.writes()).toEqual([]);
    }
    // no plan to compare with → kept
    const np = api((route) => (route.startsWith('GET ') ? asSet() : {}));
    expect((await np.api.restoreClassic({ branch: 'main', previous: prev }, undefined, await typedOn(np.api, main))).status).toBe('kept');
    expect(np.writes()).toEqual([]);
    // the owner removed the protection: never created again
    const gone = api((route) => { if (route === 'GET /repos/{owner}/{repo}') return { id: 101 }; throw httpErr(404); }, { raw: true });
    const g = await gone.api.restoreClassic({ branch: 'main', previous: prev }, planned, await typedOn(gone.api, main));
    expect(g.status).toBe('kept');
    expect((g as { why: string }).why).toMatch(/is gone/);
    // pipegen's plan for another branch says nothing about this one
    const other = api((route) => (route.startsWith('GET ') ? asSet() : {}));
    expect((await other.api.restoreClassic({ branch: 'main', previous: prev }, { ...planned, params: { ...planned.params, branch: 'release' } }, await typedOn(other.api, main))).status).toBe('kept');
    expect(other.writes()).toEqual([]);
    expect(gone.writes()).toEqual([]);
  });

  it('R1 sec I3: a typed name is bound to the object (kind, scope, id), asked by target.ts, and consumed on any use', async () => {
    // (a) a token passed with a `yes` verdict is used up
    const f = api((route) => (route.startsWith('GET ') ? { name: 'PIPEGEN_X', created_at: AT } : {}));
    const repoOne: Owned = { kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, githubCreatedAt: AT } };
    const envOne: Owned = { kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'env:prod', created: true, unconfirmed: true } };
    const t = await typedOn(f.api, repoOne);
    expect((await f.api.deleteIfPipegens(repoOne, { typed: t })).status).toBe('deleted');
    await expect(f.api.deleteIfPipegens(repoOne, { typed: t })).rejects.toBeInstanceOf(UninstallRefusal);
    // (b) the same name in another scope, or the central ruleset under the gate ruleset's name: another object
    const t2 = await typedOn(f.api, repoOne);
    await expect(f.api.deleteIfPipegens(envOne, { typed: t2 })).rejects.toBeInstanceOf(UninstallRefusal);
    const r = api((route) => (route.startsWith('GET ') ? liveRuleset({ id: 11, source: 'acme/pipelines' }) : {}));
    const gateTyped = await typedOn(r.api, { kind: 'ruleset', entry: rsEntry() });
    await expect(r.api.deleteIfPipegens({ kind: 'central-ruleset', id: 11 }, { typed: gateTyped })).rejects.toBeInstanceOf(UninstallRefusal);
    const sameId = await typedOn(r.api, { kind: 'ruleset', entry: rsEntry({ id: 11 }) });   // the kind and repo bind it, not the id alone
    await expect(r.api.deleteIfPipegens({ kind: 'central-ruleset', id: 11 }, { typed: sameId })).rejects.toBeInstanceOf(UninstallRefusal);
    expect(r.writes()).toEqual([]);
    // a token of another run (another UninstallApi) never counts here
    const o = api((route) => (route.startsWith('GET ') ? { name: 'PIPEGEN_X', created_at: AT } : {}));
    await expect(o.api.deleteIfPipegens(envOne, { typed: await typedOn(f.api, envOne) })).rejects.toBeInstanceOf(UninstallRefusal);
    // (c) the question is target.ts's, naming the object as GitHub knows it
    const ask = asker(true);
    const q = api(undefined, { askName: ask });
    await q.api.confirm(envOne);
    await q.api.confirm({ kind: 'central-ruleset', id: 11 });
    expect(ask.asked[0]).toMatchObject({ expected: 'PIPEGEN_X' });
    expect(ask.asked[0]?.question).toMatch(/environment prod/);
    expect(ask.asked[0]?.question).toMatch(/acme\/shop/);
    expect(ask.asked[1]?.question).toMatch(/acme\/pipelines/);
    expect(ask.asked[1]?.question).toMatch(/id 11/);
  });

  it('R1 sec I4: the central repo is kept while tags, releases, issues, PRs, a wiki, forks, secrets, variables or environments of the user are there', async () => {
    const DESC = helperDescription('central');
    const readme = '# pipelines\npipegen central workflows and install records';
    const rec = (over: Partial<InstallRecord> = {}): InstallRecord => ({
      schema: 2, pipegenVersion: '0.2.0', createdAt: AT, centralSha: SHA,
      app: { owner: OWNER, repo: 'shop', repoId: 101, defaultBranch: 'main', private: true, ownerType: 'Organization' },
      name: 'shop', serviceRoots: [], files: [], edits: [], [LIST]: [{ name: 'PIPEGEN_CENTRAL', scope: 'central', created: true, githubCreatedAt: AT }], variables: [], environments: [], rulesets: [],
      central: { repoId: CENTRAL_ID, createdByPipegen: true }, planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] }, protectedPaths: [], ...over,
    });
    const base = { id: CENTRAL_ID, name: 'pipelines', full_name: 'acme/pipelines', owner: { login: OWNER }, description: DESC, default_branch: 'main', forks_count: 0, has_wiki: false, has_discussions: false };
    const ourPr = { number: 4, head: { ref: 'pipegen/update-shop', repo: { id: CENTRAL_ID } } };
    const go = async (w: { repo?: Record<string, unknown>; tags?: unknown[]; releases?: unknown[]; issues?: unknown[]; pulls?: unknown[]; secrets?: unknown[]; variables?: unknown[]; environments?: unknown[] }) => {
      const state = { deleted: false };
      const f = fakeGh((route, p) => {
        if (route === 'GET /repos/{owner}/{repo}') { if (state.deleted) throw httpErr(404); return w.repo ?? base; }
        if (route === 'GET /repos/{owner}/{repo}/branches') return [{ name: 'main' }];
        if (route === 'GET /repos/{owner}/{repo}/git/ref/{ref}') return { object: { sha: SHA } };
        if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { tree: { sha: SHA }, parents: [] };
        if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { truncated: false, tree: [{ path: 'README.md', sha: gitBlobSha(readme), mode: '100644', type: 'blob' }] };
        if (route === 'GET /repos/{owner}/{repo}/git/matching-refs/{ref}') return p.ref === '' ? [{ ref: 'refs/heads/main' }] : w.tags ?? [];
        if (route === 'GET /repos/{owner}/{repo}/comments') return [];
        if (route === 'GET /repos/{owner}/{repo}/releases') return w.releases ?? [];
        if (route === 'GET /repos/{owner}/{repo}/issues') return w.issues ?? [];
        if (route === 'GET /repos/{owner}/{repo}/pulls') return w.pulls ?? [];
        if (route === 'GET /repos/{owner}/{repo}/actions/secrets') return { total_count: (w.secrets ?? []).length, [LIST]: w.secrets ?? [] };
        if (route === 'GET /repos/{owner}/{repo}/dependabot/secrets' || route === 'GET /repos/{owner}/{repo}/codespaces/secrets') return { total_count: 0, [LIST]: [] };
        if (route === 'GET /repos/{owner}/{repo}/actions/variables') return { total_count: (w.variables ?? []).length, variables: w.variables ?? [] };
        if (route === 'GET /repos/{owner}/{repo}/environments') return { total_count: (w.environments ?? []).length, environments: w.environments ?? [] };
        if (route === 'GET /repos/{owner}/{repo}/keys' || route === 'GET /repos/{owner}/{repo}/hooks') return [];   // V6: no deploy key, no webhook
        if (route === 'DELETE /repos/{owner}/{repo}') { state.deleted = true; return {}; }
        throw httpErr(500);
      }, { raw: true });
      const out = await deleteCentralRepo(f.gh, { owner: OWNER, repo: 'pipelines' }, rec(), { askName: asker('pipelines'), clock: clock() });
      return { out, deleted: f.calls.some((c) => c.route === 'DELETE /repos/{owner}/{repo}') };
    };
    // pipegen's own PRs and its own secret (created_at equal) are fine
    const ok = await go({ issues: [{ number: 4, pull_request: {} }], pulls: [ourPr], [LIST]: [{ name: 'PIPEGEN_CENTRAL', created_at: AT }] });
    expect(ok.out).toEqual({ deleted: true });
    for (const [w, why] of [
      [{ tags: [{ ref: 'refs/tags/v1' }] }, /tag/],
      [{ releases: [{ id: 1 }] }, /release/],
      [{ issues: [{ number: 9 }] }, /issue/],
      [{ issues: [{ number: 5, pull_request: {} }], pulls: [{ number: 5, head: { ref: 'my-work', repo: { id: CENTRAL_ID } } }] }, /pull request/],
      [{ issues: [{ number: 5, pull_request: {} }], pulls: [{ number: 5, head: { ref: 'pipegen/update-shop', repo: { id: 999 } } }] }, /pull request/],
      [{ issues: [{ number: 5, pull_request: {} }], pulls: [{ number: 5, head: { ref: 'pipegen/update-shop', repo: null } }] }, /pull request/],
      [{ repo: { ...base, has_wiki: true } }, /wiki.*then run `npx pipegen uninstall` again/],
      [{ repo: { ...base, has_wiki: undefined } }, /wiki/],
      [{ repo: { ...base, forks_count: 3 } }, /fork/],
      [{ repo: { ...base, forks_count: undefined } }, /fork/],
      [{ [LIST]: [{ name: 'MY_TOKEN', created_at: AT }] }, /secret/],
      [{ [LIST]: [{ name: 'PIPEGEN_CENTRAL', created_at: '2026-11-03T00:00:00Z' }] }, /secret/],
      [{ variables: [{ name: 'MINE', created_at: AT }] }, /variable/],
      [{ environments: [{ name: 'prod' }] }, /environment/],
      [{ issues: Array.from({ length: 100 }, (_x, i) => ({ number: i + 1, pull_request: {} })), pulls: [ourPr] }, /issue|pull request/],
    ] as const) {
      const r = await go(w as never);
      expect(r.deleted, JSON.stringify(w)).toBe(false);
      expect(r.out.why, JSON.stringify(w)).toMatch(why);
      expect(r.out.command).toBeUndefined();   // V6-R2 sec I1: a refusal never advises the delete
    }
  });

  it('R1 sec I5: an environment holding a secret or variable pipegen didn\'t add (or can\'t prove) is kept', async () => {
    const envEntry = { name: 'pipegen-signing', created: true, changed: [], branchPolicyIds: [], githubCreatedAt: AT };
    const rec = { [LIST]: [{ name: 'PIPEGEN_COSIGN_KEY', scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT }, { name: 'PIPEGEN_OTHER', scope: 'env:pipegen-signing', created: true, unconfirmed: true }], variables: [{ name: 'PIPEGEN_COSIGN_PUB', scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT }] } as unknown as InstallRecord;
    const o = environmentOwned(rec, envEntry as InstallRecord['environments'][number]);
    const go = async (held: unknown[], variables: unknown[], total?: number) => {
      const f = api((route) => {
        if (route.endsWith('/secrets')) return { total_count: total ?? held.length, [LIST]: held };
        if (route.endsWith('/variables')) return { total_count: variables.length, variables };
        if (route.startsWith('GET ')) return { name: 'pipegen-signing', created_at: AT };
        return {};
      });
      return { out: await f.api.deleteIfPipegens(o), writes: f.writes() };
    };
    expect((await go([{ name: 'PIPEGEN_COSIGN_KEY', created_at: AT }], [{ name: 'PIPEGEN_COSIGN_PUB', created_at: AT }])).out.status).toBe('deleted');
    expect((await go([], [])).out.status).toBe('deleted');
    for (const [s, v, total] of [
      [[{ name: 'PROD_DB_PASSWORD', created_at: AT }], [], undefined],
      [[], [{ name: 'MINE', created_at: AT }], undefined],
      [[{ name: 'PIPEGEN_COSIGN_KEY', created_at: '2026-11-04T00:00:00Z' }], [], undefined],   // the user made it again
      [[{ name: 'PIPEGEN_OTHER', created_at: AT }], [], undefined],                            // unconfirmed: can't prove it
      [[], [], 3],                                                                               // more than GitHub listed
    ] as const) {
      const r = await go([...s] as unknown[], [...v] as unknown[], total);
      expect(r.out.status, JSON.stringify([s, v, total])).toBe('kept');
      expect(r.writes).toEqual([]);
    }
    // names only, never a value, in the reason
    const r = await go([{ name: 'PROD_DB_PASSWORD', created_at: AT }], []);
    expect((r.out as { why: string }).why).toMatch(/PROD_DB_PASSWORD/);
  });

  it('R1 sec I6: on the app only pipegen/setup, pipegen/update and pipegen/uninstall are closed or deleted', async () => {
    expect(['pipegen/setup', 'pipegen/update', 'pipegen/uninstall'].every((b) => pipegenBranch(APP, 'app', b))).toBe(true);
    for (const b of ['pipegen/my-own-work', 'pipegen/setup-2', 'pipegen/update/x', 'pipegen/uninstall-shop']) expect(pipegenBranch(APP, 'app', b), b).toBe(false);
    const f = api((route) => (route.startsWith('GET ') ? { number: 3, state: 'open', head: { ref: 'pipegen/my-own-work', repo: { id: 101, full_name: 'acme/shop' } } } : {}));
    await expect(f.api.deleteBranch('app', 'pipegen/my-own-work')).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(f.api.closePr('app', 3)).rejects.toBeInstanceOf(UninstallRefusal);
    expect(f.writes()).toEqual([]);
    // the head repo is GitHub's id of this repo, not just its name
    const g = api((route) => (route.startsWith('GET ') && route.includes('pulls') ? { number: 3, state: 'open', head: { ref: 'pipegen/setup', repo: { id: 555, full_name: 'acme/shop' } } } : {}));
    await expect(g.api.closePr('app', 3)).rejects.toBeInstanceOf(UninstallRefusal);
    expect(g.writes()).toEqual([]);
  });

  it('R1 sec M1: read() takes path parts and known query keys only, never an Octokit option', async () => {
    const f = api();
    for (const k of ['baseUrl', 'headers', 'request', 'mediaType', 'url', 'method', 'data', 'foo']) {
      await expect(f.api.read('GET /repos/{owner}/{repo}', { owner: OWNER, repo: 'shop', [k]: k === 'headers' ? {} : 'x' }), k).rejects.toBeInstanceOf(UninstallRefusal);
    }
    await expect(f.api.read('GET /repos/{owner}/{repo}/pulls', { owner: OWNER, repo: 'shop', state: { a: 1 } })).rejects.toBeInstanceOf(UninstallRefusal);
    expect(f.calls).toEqual([]);
    await f.api.read('GET /repos/{owner}/{repo}/pulls', { owner: OWNER, repo: 'shop', state: 'all', per_page: 100, page: 1 });
    expect(f.calls.length).toBe(1);
  });

  it('R1 sec M2: a 404 on the DELETE while GitHub still shows the object is a leftover, never gone', async () => {
    const f = api((route) => { if (route.startsWith('GET ')) return liveRuleset(); throw httpErr(404); });
    const out = await f.api.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() });
    expect(out.status).toBe('leftover');
    expect(out).toMatchObject({ manual: 'gh api -X DELETE repos/acme/shop/rulesets/7' });
  });

  it('R1 sec M3: a write is refused when GitHub\'s id of the app (or of central) is not the recorded one', async () => {
    const other = new UninstallApi(fakeGh((route) => (route === 'GET /repos/{owner}/{repo}' ? { id: 999 } : { name: 'PIPEGEN_X', created_at: AT }), { raw: true }).gh, APP, { clock: clock(), askName: asker() });
    await expect(other.deleteIfPipegens({ kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, unconfirmed: true } }, { typed: await typedOn(other, { kind: 'secret', entry: { name: 'PIPEGEN_X', scope: 'repo', created: true, unconfirmed: true } }) })).rejects.toBeInstanceOf(UninstallRefusal);
    const f = fakeGh((route, p) => (route === 'GET /repos/{owner}/{repo}' ? { id: p.repo === 'pipelines' ? 777 : 101 } : route.endsWith('/automated-security-fixes') ? { enabled: false } : {}), { raw: true });
    const c = new UninstallApi(f.gh, APP, { clock: clock(), centralRepoId: CENTRAL_ID });
    await expect(c.write('PUT /repos/{owner}/{repo}/actions/permissions/access', { owner: OWNER, repo: 'pipelines', access_level: 'none' })).rejects.toBeInstanceOf(UninstallRefusal);
    await expect(c.deleteBranch('central', 'pipegen/update-shop')).rejects.toBeInstanceOf(UninstallRefusal);
    expect(f.writes()).toEqual([]);
    // a 404 is not "gone" when the parent repo GitHub answers for is another one (deleted and made again)
    const p = new UninstallApi(fakeGh((route) => { if (route === 'GET /repos/{owner}/{repo}') return { id: 999 }; throw httpErr(404); }, { raw: true }).gh, APP, { clock: clock() });
    await expect(p.deleteIfPipegens({ kind: 'ruleset', entry: rsEntry() })).rejects.toBeInstanceOf(UninstallRefusal);
    // the app's own id passes
    expect(await c.write('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { owner: OWNER, repo: 'shop' })).toEqual({ status: 'done' });
  });

  it('R1 sec M4: an app named pipelines is refused (it would be its own central repo)', () => {
    for (const repo of ['pipelines', 'Pipelines', 'PIPELINES']) expect(() => new UninstallApi(fakeGh().gh, { owner: OWNER, repo, repoId: 1 }), repo).toThrow(UninstallRefusal);
  });

  it('R1 sec M5: the central commit changes only this project\'s files, on a base tree that is the parent\'s', async () => {
    const sha = (n: number) => String(n).repeat(40).slice(0, 40);
    const mk = (tree = SHA) => api((route, params) => {
      if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { sha: SHA, tree: { sha: tree } };
      // PL-E6: commitFiles checks a delete against the base tree
      if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}' && params.tree_sha === SHA) return { truncated: false, tree: [centralWorkflowFile('shop', 'merge'), 'installs/shop.json'].map((path) => ({ path, sha: SHA, mode: '100644', type: 'blob' })) };
      if (route === 'POST /repos/{owner}/{repo}/git/trees') return { sha: sha(1) };
      if (route === 'POST /repos/{owner}/{repo}/git/commits') return { sha: sha(2) };
      return {};
    });
    const commit = (a: UninstallApi, files: { path: string; content: string; mode: string }[], deletes: string[]) => a.commitUninstall('central', { parent: SHA, baseTree: SHA, files, deletes, message: 'm' });
    for (const [files, deletes] of [
      [[], ['installs/other.json']], [[], ['.github/workflows/other--merge.yml']], [[], ['README.md']],
      [[{ path: '.github/workflows/shop--merge.yml', content: 'x', mode: '100644' }], []], [[{ path: 'installs/shop.json', content: '{}', mode: '100644' }], []],
    ] as const) {
      const g = mk();
      await expect(commit(g.api, [...files], [...deletes]), JSON.stringify([files, deletes])).rejects.toBeInstanceOf(UninstallRefusal);
      expect(g.writes()).toEqual([]);
    }
    const ok = mk();
    expect(await ok.api.commitUninstall('central', { parent: SHA, baseTree: SHA, files: [{ path: '.github/CODEOWNERS', content: '* @acme/team\n', mode: '100644' }], deletes: [centralWorkflowFile('shop', 'merge'), 'installs/shop.json'], message: 'm', recordEdits: [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: 'x', originalSha: SHA, writtenShas: [] }] })).toEqual({ commit: sha(2), tree: sha(1) });
    // a base tree that isn't the parent's would revert every commit between them
    const stale = mk('d'.repeat(40));
    await expect(stale.api.commitUninstall('app', { parent: SHA, baseTree: SHA, files: [], deletes: ['.github/workflows/pipegen.yml'], message: 'm' })).rejects.toBeInstanceOf(UninstallRefusal);
    expect(stale.writes()).toEqual([]);
  });

  it('R1 sec M6 / spec M2: the classic DELETE keeps a protection the owner added rules to', async () => {
    for (const extra of [{ required_linear_history: { enabled: true } }, { lock_branch: { enabled: true } }, { block_creations: { enabled: true } }, { required_conversation_resolution: { enabled: true } },
      { required_pull_request_reviews: { ...asSet().required_pull_request_reviews, dismissal_restrictions: { users: [{ login: 'boss' }], teams: [] } } }]) {
      const f = api((route) => (route.startsWith('GET ') ? asSet(extra) : {}));
      expect((await f.api.restoreClassic({ branch: 'main', previous: null }, planned, await typedOn(f.api, main))).status, JSON.stringify(extra)).toBe('kept');
      expect(f.writes()).toEqual([]);
    }
    // the switches GitHub reports off are pipegen's form still
    const ok = api((route) => (route.startsWith('GET ') ? asSet({ required_linear_history: { enabled: false }, lock_branch: { enabled: false } }) : {}));
    expect((await ok.api.restoreClassic({ branch: 'main', previous: null }, planned, await typedOn(ok.api, main))).status).toBe('deleted');
  });

  it('R1 sec M7: environment, variable and branch-policy restores go through their own checked functions', async () => {
    const was = { wait_timer: 30, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] };   // wait_timer: not changed by pipegen
    const entry = { name: 'pipegen-signing', created: false, githubCreatedAt: AT, previous: was, changed: ['deployment_branch_policy'], branchPolicyIds: [41] } as InstallRecord['environments'][number];
    const liveEnv = (dbp: unknown, created = AT) => ({ name: 'pipegen-signing', created_at: created, can_admins_bypass: true, protection_rules: [], deployment_branch_policy: dbp });
    const narrowed = { protected_branches: false, custom_branch_policies: true };
    const shown = { wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: narrowed };
    const env = (live: unknown) => api((route) => {
      if (route === 'GET /repos/{owner}/{repo}/environments/{environment_name}') return live;
      if (route === 'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies') return { total_count: 1, branch_policies: [{ id: 41, name: 'main', type: 'branch' }] };
      // V9a (V8 sec I1): the environment's secrets, listed right before the PUT: none of the record's left
      if (route === `GET /repos/{owner}/{repo}/environments/{environment_name}/${['sec', 'rets'].join('')}`) return { total_count: 0, [['sec', 'rets'].join('')]: [] };
      return {};
    });
    const er = { kind: 'environment-restore' as const, entry };
    // no typed environment name → refused
    const a = env(liveEnv(narrowed));
    await expect(a.api.restoreEnvironment(entry, shown, [])).rejects.toBeInstanceOf(UninstallRefusal);
    // as shown → the changed field back, the others as they are now
    expect((await a.api.restoreEnvironment(entry, shown, [], await typedOn(a.api, er))).status).toBe('restored');
    expect(a.writes()).toEqual([{ route: 'PUT /repos/{owner}/{repo}/environments/{environment_name}', params: { owner: OWNER, repo: 'shop', environment_name: 'pipegen-signing', ...shown, deployment_branch_policy: null } }]);
    // changed since the diff, or another environment of that name → kept
    const b = env(liveEnv({ protected_branches: true, custom_branch_policies: false }));
    expect((await b.api.restoreEnvironment(entry, shown, [], await typedOn(b.api, er))).status).toBe('kept');
    const c = env(liveEnv(narrowed, '2026-11-05T00:00:00Z'));
    expect((await c.api.restoreEnvironment(entry, shown, [], await typedOn(c.api, er))).status).toBe('kept');
    expect([...b.writes(), ...c.writes()]).toEqual([]);

    // variable: PATCH previous only while GitHub holds pipegen's value
    const v = { name: 'PIPEGEN_BLOCK_FROM', scope: 'repo' as const, created: false, previous: 'old' };
    const vr = (value: string) => api((route) => (route.startsWith('GET ') ? { name: 'PIPEGEN_BLOCK_FROM', value, created_at: AT } : {}));
    const ok = vr('pipegens');
    expect((await ok.api.restoreVariable(v, 'pipegens')).status).toBe('restored');
    expect(ok.writes()).toEqual([{ route: 'PATCH /repos/{owner}/{repo}/actions/variables/{name}', params: { owner: OWNER, repo: 'shop', name: 'PIPEGEN_BLOCK_FROM', value: 'old' } }]);
    const mine = vr('the user set this');
    expect((await mine.api.restoreVariable(v, 'pipegens')).status).toBe('kept');
    expect((await mine.api.restoreVariable(v, undefined)).status).toBe('kept');
    const noValue = api((route) => (route.startsWith('GET ') ? { name: 'PIPEGEN_BLOCK_FROM', created_at: AT } : {}));
    expect((await noValue.api.restoreVariable(v, undefined)).status).toBe('kept');
    expect(noValue.writes()).toEqual([]);
    expect(mine.writes()).toEqual([]);
    const envVar = vr('pipegens');
    expect((await envVar.api.restoreVariable({ ...v, scope: 'env:prod' }, 'pipegens'))).toMatchObject({ status: 'leftover', manual: expect.stringContaining('gh variable set PIPEGEN_BLOCK_FROM --env prod') });
    expect(envVar.writes()).toEqual([]);

    // branch policy: only an id the record holds for that environment
    const p = api();
    await expect(p.api.deleteBranchPolicy(entry, 42)).rejects.toBeInstanceOf(UninstallRefusal);
    expect(p.writes()).toEqual([]);
    expect((await p.api.deleteBranchPolicy(entry, 41)).status).toBe('deleted');
    expect(p.writes()).toEqual([{ route: 'DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}', params: { owner: OWNER, repo: 'shop', environment_name: 'pipegen-signing', branch_policy_id: 41 } }]);
  });

  it('R1 sec M8 / spec M4: the org rule\'s central repo id is read from GitHub (and must be the recorded one), never the caller\'s', async () => {
    // the caller passes a wrong id: ignored, GitHub's id decides
    const f = api((route) => (route.startsWith('GET ') ? liveOrg() : {}));
    expect((await f.api.deleteIfPipegens({ kind: 'org-ruleset', entry: orgEntry(), centralRepoId: 999 })).status).toBe('deleted');
    // GitHub's central repo is another one than the recorded: nothing deleted
    const g = new UninstallApi(fakeGh((route, p) => (route === 'GET /repos/{owner}/{repo}' ? { id: p.repo === 'pipelines' ? 303 : 101 } : route.startsWith('GET ') ? liveOrg({ rules: [{ type: 'workflows', parameters: { workflows: [{ path: centralWorkflowFile('shop', 'required'), repository_id: 303, sha: PIN }] } }] }) : {}), { raw: true }).gh, APP, { clock: clock(), centralRepoId: CENTRAL_ID });
    await expect(g.deleteIfPipegens({ kind: 'org-ruleset', entry: orgEntry(), centralRepoId: 303 })).rejects.toBeInstanceOf(UninstallRefusal);
  });

  it('R1 spec I2: one askTypedName (V1\'s): target.ts takes the injected question and defines none', async () => {
    const mod = await import('../src/uninstall/target.js');
    expect('askTypedName' in mod).toBe(false);
    const src = readFileSync(join(import.meta.dirname, '..', 'src', 'uninstall', 'target.ts'), 'utf8');
    expect(src).not.toMatch(/\.text\s*\(/);   // never prompts by itself
  });

  it('R1 spec M1: a run that needs typed names (typed trust, a missing marker) asks for every delete and restore', async () => {
    const f = api((route) => (route.startsWith('GET ') ? liveRuleset() : {}), { typedNames: true });
    const o: Owned = { kind: 'ruleset', entry: rsEntry() };
    expect((await f.api.deleteIfPipegens(o)).status).toBe('ask');
    expect(f.writes()).toEqual([]);
    expect((await f.api.deleteIfPipegens(o, { typed: await typedOn(f.api, o) })).status).toBe('deleted');
    const v = api((route) => (route.startsWith('GET ') ? { name: 'PIPEGEN_BLOCK_FROM', value: 'p', created_at: AT } : {}), { typedNames: true });
    const ve = { name: 'PIPEGEN_BLOCK_FROM', scope: 'repo' as const, created: false, previous: 'old' };
    await expect(v.api.restoreVariable(ve, 'p')).rejects.toBeInstanceOf(UninstallRefusal);
    expect((await v.api.restoreVariable(ve, 'p', await typedOn(v.api, { kind: 'variable-restore', entry: ve }))).status).toBe('restored');
  });

  it('R1 spec M3: PR closes, branch deletes and settings writes map GitHub\'s answers through goneOr', async () => {
    const gonePr = api((route) => { throw httpErr(route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}' ? 404 : 500); });
    expect((await gonePr.api.closePr('app', 3)).status).toBe('gone');
    const ref = api((route) => { if (route.startsWith('GET ')) return {}; throw httpErr(422); });
    expect(await ref.api.deleteBranch('app', 'pipegen/setup')).toMatchObject({ status: 'leftover', manual: 'gh api -X DELETE repos/acme/shop/git/refs/heads/pipegen/setup' });
    const w = api((route) => { if (route.startsWith('GET ')) return route.endsWith('/automated-security-fixes') ? { enabled: false } : {}; throw httpErr(403); });
    expect(await w.api.write('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { owner: OWNER, repo: 'shop' })).toMatchObject({ status: 'leftover', manual: expect.stringContaining('gh api -X DELETE repos/acme/shop/vulnerability-alerts') });
  });

  it('R1 spec M5 / M6: GitHub\'s README with a blank line is accepted; an unreadable answer after the delete says "could not confirm"', async () => {
    const DESC = helperDescription('central');
    const rec: InstallRecord = {
      schema: 2, pipegenVersion: '0.2.0', createdAt: AT, centralSha: SHA, app: { owner: OWNER, repo: 'shop', repoId: 101, defaultBranch: 'main', private: true, ownerType: 'Organization' },
      name: 'shop', serviceRoots: [], files: [], edits: [], [LIST]: [], variables: [], environments: [], rulesets: [], central: { repoId: CENTRAL_ID, createdByPipegen: true },
      planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] }, protectedPaths: [],
    };
    const go = async (readme: string, after: 'gone' | 'error') => {
      let deleted = false;
      const f = fakeGh((route, p) => {
        if (route === 'GET /repos/{owner}/{repo}') { if (deleted) throw httpErr(after === 'gone' ? 404 : 500); return { id: CENTRAL_ID, name: 'pipelines', full_name: 'acme/pipelines', owner: { login: OWNER }, description: DESC, default_branch: 'main', forks_count: 0, has_wiki: false, has_discussions: false }; }
        if (route === 'GET /repos/{owner}/{repo}/branches') return [{ name: 'main' }];
        if (route === 'GET /repos/{owner}/{repo}/git/ref/{ref}') return { object: { sha: SHA } };
        if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { tree: { sha: SHA }, parents: [] };
        if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { truncated: false, tree: [{ path: 'README.md', sha: gitBlobSha(readme), mode: '100644', type: 'blob' }] };
        if (route.endsWith('/secrets') || route.endsWith('/variables') || route.endsWith('/environments')) return { total_count: 0, [LIST]: [], variables: [], environments: [] };
        if (route === 'GET /repos/{owner}/{repo}/git/matching-refs/{ref}' && p.ref === '') return [{ ref: 'refs/heads/main' }];
        if (route.startsWith('GET ')) return [];
        if (route === 'DELETE /repos/{owner}/{repo}') { deleted = true; return {}; }
        throw httpErr(500);
      }, { raw: true });
      return deleteCentralRepo(f.gh, { owner: OWNER, repo: 'pipelines' }, rec, { askName: asker('pipelines'), clock: clock() });
    };
    expect(await go(`# pipelines\n\n${DESC}\n`, 'gone')).toEqual({ deleted: true });
    expect(await go(`# pipelines\n\n${DESC}`, 'gone')).toEqual({ deleted: true });
    const e = await go(`# pipelines\n${DESC}\n`, 'error');
    expect(e.deleted).toBe(false);
    expect(e.why).toMatch(/could not confirm/);
  });
});

// ---------- 8. fix round 2 (VL/review-V3-security-r1.md, ruling V3-R2) ----------

describe('V3 fix round 2', () => {
  const DESC = helperDescription('central');
  const readme = '# pipelines\npipegen central workflows and install records';
  const rec = (over: Partial<InstallRecord> = {}): InstallRecord => ({
    schema: 2, pipegenVersion: '0.2.0', createdAt: AT, centralSha: SHA,
    app: { owner: OWNER, repo: 'shop', repoId: 101, defaultBranch: 'main', private: true, ownerType: 'Organization' },
    name: 'shop', serviceRoots: [], files: [], edits: [], [LIST]: [], variables: [], environments: [], rulesets: [],
    central: { repoId: CENTRAL_ID, createdByPipegen: true }, planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] }, protectedPaths: [], ...over,
  });
  const base = { id: CENTRAL_ID, name: 'pipelines', full_name: 'acme/pipelines', owner: { login: OWNER }, description: DESC, default_branch: 'main', forks_count: 0, has_wiki: false, has_discussions: false };
  const ourPr = { number: 4, head: { ref: 'pipegen/update-shop', repo: { id: CENTRAL_ID } } };
  interface W { repo?: Record<string, unknown>; refs?: unknown[]; refsAnswer?: unknown; pulls?: unknown[]; dependabot?: unknown[] | number; codespaces?: unknown[] | number; dependabotLater?: number; comments?: unknown[] | number; empty?: boolean }
  const listOf = (x: unknown[] | number | undefined) => { if (typeof x === 'number') throw httpErr(x); return { total_count: (x ?? []).length, [LIST]: x ?? [] }; };
  const go = async (w: W) => {
    const state = { deleted: false };
    let dependabotReads = 0;
    const f = fakeGh((route, p) => {
      if (route === 'GET /repos/{owner}/{repo}') { if (state.deleted) throw httpErr(404); return w.repo ?? base; }
      if (route === 'GET /repos/{owner}/{repo}/branches') return [{ name: 'main' }];
      if (route === 'GET /repos/{owner}/{repo}/git/ref/{ref}') { if (w.empty === true) throw httpErr(409); return { object: { sha: SHA } }; }
      if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { tree: { sha: SHA }, parents: [] };
      if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { truncated: false, tree: [{ path: 'README.md', sha: gitBlobSha(readme), mode: '100644', type: 'blob' }] };
      if (route === 'GET /repos/{owner}/{repo}/git/matching-refs/{ref}') return p.ref === '' ? ('refsAnswer' in w ? w.refsAnswer : [{ ref: 'refs/heads/main' }, ...(w.refs ?? [])]) : [];
      if (route === 'GET /repos/{owner}/{repo}/issues') return (w.pulls ?? []).map((x) => ({ number: (x as { number: number }).number, pull_request: {} }));
      if (route === 'GET /repos/{owner}/{repo}/pulls') return w.pulls ?? [];
      if (route === 'GET /repos/{owner}/{repo}/dependabot/secrets') { if (w.dependabotLater !== undefined && dependabotReads++ > 0) throw httpErr(w.dependabotLater); return listOf(w.dependabot); }
      if (route === 'GET /repos/{owner}/{repo}/codespaces/secrets') return listOf(w.codespaces);
      if (route.endsWith('/secrets') || route.endsWith('/variables') || route.endsWith('/environments')) return { total_count: 0, [LIST]: [], variables: [], environments: [] };
      if (route === 'GET /repos/{owner}/{repo}/releases') return [];
      if (route === 'GET /repos/{owner}/{repo}/comments') { if (typeof w.comments === 'number') throw httpErr(w.comments); return w.comments ?? []; }
      if (route === 'DELETE /repos/{owner}/{repo}') { state.deleted = true; return {}; }
      if (route === 'GET /repos/{owner}/{repo}/keys' || route === 'GET /repos/{owner}/{repo}/hooks') return [];   // V6: no deploy key, no webhook
      throw httpErr(500);
    }, { raw: true });
    const ask = asker('pipelines');
    const out = await deleteCentralRepo(f.gh, { owner: OWNER, repo: 'pipelines' }, rec(), { askName: ask, clock: clock() });
    return { out, deleted: f.calls.some((c) => c.route === 'DELETE /repos/{owner}/{repo}'), asked: ask.asked, calls: f.calls };
  };

  it('R2 sec N-I1: Discussions turned on (or not reported) keep the central repo', async () => {
    expect((await go({})).out).toEqual({ deleted: true });
    for (const repo of [{ ...base, has_discussions: true }, { ...base, has_discussions: undefined }]) {
      const r = await go({ repo });
      expect(r.deleted, JSON.stringify(repo)).toBe(false);
      expect(r.out.why).toMatch(/Discussions/);
      expect(r.out.command).toBeUndefined();   // V6-R2 sec I1: a refusal never advises the delete
      expect(r.asked).toEqual([]);
    }
  });

  it('R2 sec N-M2: Dependabot or Codespaces secrets and refs other than the branch and pipegen\'s PR refs keep the central repo; an unreadable list is named before the typed name', async () => {
    // pipegen's own PR refs are fine
    expect((await go({ pulls: [ourPr], refs: [{ ref: 'refs/pull/4/head' }, { ref: 'refs/pull/4/merge' }] })).out).toEqual({ deleted: true });
    for (const [w, why] of [
      [{ dependabot: [{ name: 'NPM_TOKEN' }] }, /Dependabot/],
      [{ codespaces: [{ name: 'MY_KEY' }] }, /Codespaces/],
      [{ dependabot: 500 }, /Dependabot/],
      [{ refs: [{ ref: 'refs/notes/commits' }] }, /refs\/notes\/commits/],
      [{ refs: [{ ref: 'refs/custom/x' }] }, /refs\/custom\/x/],
      [{ pulls: [ourPr], refs: [{ ref: 'refs/pull/5/head' }] }, /refs\/pull\/5\/head/],
      [{ refs: [{ ref: 'refs/heads/wip' }] }, /refs\/heads\/wip/],
      [{ refs: [{ nope: 1 }] }, /ref/],
      [{ refsAnswer: { ref: 'refs/heads/main' } }, /refs/],
      [{ dependabotLater: 403 }, /read less/],   // readable when asked, unreadable after the typed name
    ] as const) {
      const r = await go(w as W);
      expect(r.deleted, JSON.stringify(w)).toBe(false);
      expect(r.out.why, JSON.stringify(w)).toMatch(why);
    }
    // a list the token can't read (App permission): the typed-name question names it, and the result carries the manual step
    for (const w of [{ dependabot: 403 }, { codespaces: 404 }] as W[]) {
      const r = await go(w);
      expect(r.deleted, JSON.stringify(w)).toBe(true);
      expect(r.asked.length).toBe(1);
      const lines = r.asked[0]?.question.split('\n') ?? [];
      expect(lines.length).toBe(2);
      expect(lines[1]).toMatch(/^pipegen couldn't read .*(Dependabot|Codespaces)/);
      expect(lines.every((l) => l.length <= 300)).toBe(true);
      expect(r.out.unchecked?.join(' ')).toMatch(/Dependabot|Codespaces/);
    }
    // every secret list and the refs are read again after the typed name
    const twice = await go({});
    for (const route of ['GET /repos/{owner}/{repo}/dependabot/secrets', 'GET /repos/{owner}/{repo}/codespaces/secrets']) expect(twice.calls.filter((c) => c.route === route).length, route).toBe(2);
    expect(twice.calls.filter((c) => c.route === 'GET /repos/{owner}/{repo}/git/matching-refs/{ref}' && c.params.ref === '').length).toBe(2);
  });

  it('R2 sec N-I2: the scan refuses Octokit endpoint methods, paginate, graphql, hook and request outside target.ts', () => {
    for (const bad of [
      'await gh.repos.delete({ owner, repo });', 'await gh.pulls.update({ ...p, state: \'closed\' });', 'await gh.git.deleteRef(p);', 'await api.gh.actions.deleteRepoSecret(p);',
      'const g = api.gh; await g.repos.update({ ...p, private: false });', 'await gh.paginate(\'DELETE /repos/{owner}/{repo}\', p);', 'for await (const x of gh.paginate.iterator(\'POST /x\', p)) {}',
      'const o = makeOctokit(t); await o.repos.delete(p);', 'await gh\n  .repos\n  .delete(p);', 'await gh . issues . update(p);', 'gh.hook.before(\'x\', f);', 'const q = gh.graphql;',
      'await gh.graphql(\'mutation { x }\');', 'await o.orgs.deleteWebhook(p);', 'await o.secretScanning.updateAlert(p);', 'await o.codespaces.deleteRepoSecret(p);', 'await o.dependabot.deleteRepoSecret(p);',
      'const { paginate } = gh;', 'const send = gh.request;', 'await run(gh.graphql, q);',
    ]) expect(scanProblems('plan.ts', bad), bad).not.toEqual([]);
    for (const ok of [
      'const open = d.issues.filter((x) => x.state === \'open\');', 'const n = rec.secrets.map((s) => s.name);', 'const ids = data.pulls.map((p) => p.number);',
      'const n = d.issues.length;', '// gh.repos.delete is target.ts\'s only\nconst s = \'gh.repos.delete\';',
    ]) expect(scanProblems('plan.ts', ok), ok).toEqual([]);
  });

  it('R2 sec N-M1: a live protection field outside pipegen\'s body (signed commits, bypass lists) keeps the classic protection', async () => {
    const planned = { method: 'PUT' as const, route: '/repos/{owner}/{repo}/branches/{branch}/protection', params: { owner: OWNER, repo: 'shop', branch: 'main' }, body: { required_status_checks: { strict: false, checks: [{ context: 'pipegen / gate', app_id: 15368 }] }, enforce_admins: true, required_pull_request_reviews: { required_approving_review_count: 0, require_code_owner_reviews: false, dismiss_stale_reviews: true, require_last_push_approval: false }, restrictions: null, allow_force_pushes: false, allow_deletions: false } };
    const u = 'https://api.github.com/x';
    // GitHub's own answer, urls included
    const asGitHub = (over: Record<string, unknown> = {}) => ({
      url: u, required_status_checks: { url: u, contexts_url: u, strict: false, contexts: ['pipegen / gate'], checks: [{ context: 'pipegen / gate', app_id: 15368 }] },
      enforce_admins: { url: u, enabled: true }, required_pull_request_reviews: { url: u, required_approving_review_count: 0, require_code_owner_reviews: false, dismiss_stale_reviews: true, require_last_push_approval: false },
      allow_force_pushes: { enabled: false }, allow_deletions: { enabled: false }, required_signatures: { url: u, enabled: false }, ...over,
    });
    const main = { kind: 'classic' as const, branch: 'main' };
    const prev = { required_status_checks: null, enforce_admins: false, required_pull_request_reviews: null, restrictions: null };
    for (const previous of [null, prev]) {
      const ok = api((route) => (route.startsWith('GET ') ? asGitHub() : {}));
      expect((await ok.api.restoreClassic({ branch: 'main', previous }, planned, await typedOn(ok.api, main))).status).toBe(previous === null ? 'deleted' : 'restored');
      for (const over of [
        { required_signatures: { url: u, enabled: true } },
        { required_pull_request_reviews: { ...asGitHub().required_pull_request_reviews, bypass_pull_request_allowances: { users: [{ login: 'boss' }], teams: [], apps: [] } } },
        { required_pull_request_reviews: { ...asGitHub().required_pull_request_reviews, dismissal_restrictions: { url: u, users: [], teams: [], apps: [{ slug: 'bot' }] } } },
        { required_status_checks: { ...asGitHub().required_status_checks, enforcement_level: 'everyone' } },
        { some_new_rule: { enabled: true } },
        { some_new_setting: 'on' },
      ]) {
        const f = api((route) => (route.startsWith('GET ') ? asGitHub(over) : {}));
        const out = await f.api.restoreClassic({ branch: 'main', previous }, planned, await typedOn(f.api, main));
        expect(out.status, JSON.stringify(over)).toBe('kept');
        expect(out).toMatchObject({ manual: expect.stringContaining('repos/acme/shop/branches/main/protection') });
        expect(f.writes(), JSON.stringify(over)).toEqual([]);
      }
    }
  });

  it('R2 sec N-M3: the central commit writes or deletes only the CODEOWNERS path the record holds, and deletes it only when pipegen created it', async () => {
    const sha = (n: number) => String(n).repeat(40).slice(0, 40);
    const mk = () => api((route) => {
      if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { sha: SHA, tree: { sha: SHA } };
      if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { truncated: false, tree: [{ path: '.github/CODEOWNERS', sha: sha(3), mode: '100644', type: 'blob' }, { path: 'installs/shop.json', sha: sha(7), mode: '100644', type: 'blob' }] };
      if (route === 'POST /repos/{owner}/{repo}/git/trees') return { sha: sha(1) };
      if (route === 'POST /repos/{owner}/{repo}/git/commits') return { sha: sha(2) };
      return {};
    });
    // V6b: the base of the one write recorded, as deliver does (chained from the original)
    const edit = (path: string, originalSha: string | null): InstallRecord['edits'][number] => ({ repo: 'central', path, kind: 'codeowners', inserted: 'x', originalSha, writtenShas: [sha(3)], baseShas: [originalSha] }) as InstallRecord['edits'][number];
    const file = (path: string) => ({ path, content: '* @evil\n', mode: '100644' });
    const commit = (a: UninstallApi, files: { path: string; content: string; mode: string }[], deletes: string[], recordEdits?: InstallRecord['edits']) =>
      a.commitUninstall('central', { parent: SHA, baseTree: SHA, files, deletes, message: 'm', ...(recordEdits === undefined ? {} : { recordEdits }) });
    const created = [edit('.github/CODEOWNERS', null)];
    const there = [edit('.github/CODEOWNERS', SHA)];
    for (const [files, deletes, edits] of [
      [[file('docs/CODEOWNERS')], [], created],                                   // another CODEOWNERS path than the record's
      [[], ['CODEOWNERS'], created], [[], ['docs/CODEOWNERS'], created],
      [[file('docs/CODEOWNERS')], ['.github/CODEOWNERS', 'CODEOWNERS'], created],  // the reviewer's probe P7c
      [[], ['.github/CODEOWNERS'], there],                                        // there before pipegen: never deleted
      [[], ['.github/CODEOWNERS'], [{ ...edit('.github/CODEOWNERS', null), ownerEdited: true as const }]],   // the owner's lines are in it now
      [[file('.github/CODEOWNERS')], [], undefined],                              // no record edits: no CODEOWNERS change
      [[], ['.github/CODEOWNERS'], undefined],
      [[file('.github/CODEOWNERS')], [], [edit('.github/CODEOWNERS', null), edit('docs/CODEOWNERS', null)]],   // two CODEOWNERS edits: which one?
      [[file('.github/CODEOWNERS')], [], [{ ...edit('.github/CODEOWNERS', null), repo: 'app' as const }]],      // an app edit doesn't count
    ] as const) {
      const g = mk();
      await expect(commit(g.api, [...files], [...deletes], edits === undefined ? undefined : [...edits]), JSON.stringify([files, deletes, edits])).rejects.toBeInstanceOf(UninstallRefusal);
      expect(g.writes()).toEqual([]);
    }
    const del = mk();
    expect(await commit(del.api, [], ['.github/CODEOWNERS', 'installs/shop.json'], created)).toEqual({ commit: sha(2), tree: sha(1) });
    const put = mk();
    expect(await commit(put.api, [file('.github/CODEOWNERS')], ['installs/shop.json'], there)).toEqual({ commit: sha(2), tree: sha(1) });
    // a commit without CODEOWNERS needs no edits
    const plain = mk();
    expect(await commit(plain.api, [], ['installs/shop.json'])).toEqual({ commit: sha(2), tree: sha(1) });
  });

  it('R2 sec N-M4: a read route with a . or .. segment is refused before it is sent', async () => {
    const f = api();
    const app = { owner: OWNER, repo: 'shop' };
    for (const route of ['GET /repos/{owner}/{repo}/../other/actions/secrets', 'GET /repos/{owner}/{repo}/../../user', 'GET /repos/{owner}/{repo}/./actions/secrets', 'GET /repos/{owner}/{repo}/actions/..', 'GET /repos/{owner}/{repo}/.', 'GET /repos/{owner}/{repo}/x/../../other']) {
      await expect(f.api.read(route, app), route).rejects.toBeInstanceOf(UninstallRefusal);
    }
    expect(f.calls).toEqual([]);
    await f.api.read('GET /repos/{owner}/{repo}/git/matching-refs/{ref}', { ...app, ref: 'tags' });
    expect(f.calls.length).toBe(1);
  });

  it('R2 sec N-M5: settings writes read GitHub first and change only what pipegen set; anything else is kept with the manual step', async () => {
    const app = { owner: OWNER, repo: 'shop' };
    const perms = 'PUT /repos/{owner}/{repo}/actions/permissions';
    const keptNoWrite = async (f: ReturnType<typeof api>, route: string, params: Record<string, unknown>, opts?: { pipegenSet?: string }) => {
      const out = await f.api.write(route, params, opts);
      expect(out.status, `${route} ${JSON.stringify(params)}`).toBe('kept');
      expect(f.writes()).toEqual([]);
      return out;
    };
    // Actions permissions: Actions turned off since, narrowed, or the pin already off → kept; never turned back on or widened
    await keptNoWrite(api(settingsNow({ perms: { enabled: false, sha_pinning_required: true } })), perms, { ...app, enabled: true, sha_pinning_required: false });   // no manual step: R2b M-r2-3
    await keptNoWrite(api(settingsNow({ perms: { enabled: true, allowed_actions: 'selected', sha_pinning_required: true } })), perms, { ...app, enabled: true, allowed_actions: 'all', sha_pinning_required: false });
    await keptNoWrite(api(settingsNow({ perms: { enabled: true, allowed_actions: 'all', sha_pinning_required: false } })), perms, { ...app, enabled: true, sha_pinning_required: false });
    await keptNoWrite(api(settingsNow({ perms: {} })), perms, { ...app, enabled: true, sha_pinning_required: false });
    // as pipegen set it: the pin is sent back, with GitHub's allowed_actions as they are (R2b M-r2-2)
    const p = api(settingsNow({ perms: { enabled: true, allowed_actions: 'selected', sha_pinning_required: true } }));
    expect(await p.api.write(perms, { ...app, enabled: true, allowed_actions: 'selected', sha_pinning_required: false })).toEqual({ status: 'done' });
    expect(p.writes()).toEqual([{ route: perms, params: { ...app, enabled: true, allowed_actions: 'selected', sha_pinning_required: false } }]);
    // Dependabot alerts already off → kept, nothing sent; on → DELETE
    await keptNoWrite(api(settingsNow({ alerts: 404 })), 'DELETE /repos/{owner}/{repo}/vulnerability-alerts', app);
    // secret scanning: only the switch still on is turned off; both off already, or unknown → kept
    const half = api(settingsNow(), { repo: { security_and_analysis: { [SS]: { status: 'enabled' }, [SP]: { status: 'disabled' } } } });
    expect(await half.api.write('PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { [SS]: { status: 'disabled' }, [SP]: { status: 'disabled' } } })).toEqual({ status: 'done' });
    expect(half.writes()).toEqual([{ route: 'PATCH /repos/{owner}/{repo}', params: { ...app, security_and_analysis: { [SS]: { status: 'disabled' } } } }]);
    await keptNoWrite(api(settingsNow(), { repo: { security_and_analysis: { [SS]: { status: 'disabled' }, [SP]: { status: 'disabled' } } } }), 'PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { [SS]: { status: 'disabled' }, [SP]: { status: 'disabled' } } });
    expect(await keptNoWrite(api(settingsNow()), 'PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { [SS]: { status: 'disabled' } } })).toMatchObject({ manual: expect.stringContaining('repos/acme/shop') });
    expect(await keptNoWrite(api(settingsNow(), { repo: { security_and_analysis: { [SS]: { status: 'disabled' }, [SP]: { status: 'enabled' } } } }), 'PATCH /repos/{owner}/{repo}', { ...app, security_and_analysis: { [SS]: { status: 'enabled' } } })).toMatchObject({ why: expect.stringMatching(/only turns/) });
    // central Actions access: only while it is the level pipegen set (given by the caller from the record's owner type)
    const access = 'PUT /repos/{owner}/{repo}/actions/permissions/access';
    const central = { owner: OWNER, repo: 'pipelines', access_level: 'none' };
    await keptNoWrite(api(settingsNow()), access, central);
    await keptNoWrite(api(settingsNow({ access: { access_level: 'enterprise' } })), access, central, { pipegenSet: 'organization' });
    await keptNoWrite(api(settingsNow({ access: {} })), access, central, { pipegenSet: 'organization' });
    await keptNoWrite(api(settingsNow()), access, central, { pipegenSet: 'everyone' });
    await keptNoWrite(api(settingsNow({ access: { access_level: 'enterprise' } })), access, central, { pipegenSet: 'enterprise' });   // finish never sets it
    const ok = api(settingsNow({ access: { access_level: 'user' } }));
    expect(await ok.api.write(access, central, { pipegenSet: 'user' })).toEqual({ status: 'done' });
    expect(ok.writes()).toEqual([{ route: access, params: central }]);
    // each live read comes after the repo id check and right before its write
    expect(ok.calls.map((c) => c.route)).toEqual(['GET /repos/{owner}/{repo}', 'GET /repos/{owner}/{repo}/git/ref/{ref}', 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}', 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}', 'GET /repos/{owner}/{repo}/actions/permissions/access', access]);
  });

  describe('V3 fix round 2b (ruling V3-R2b)', () => {
    const app = { owner: OWNER, repo: 'shop' };
    const perms = 'PUT /repos/{owner}/{repo}/actions/permissions';
    const patch = 'PATCH /repos/{owner}/{repo}';
    const alerts = 'DELETE /repos/{owner}/{repo}/vulnerability-alerts';

    it('R2b sec M-r2-2: the pin restore sends GitHub\'s allowed_actions back as they are; an unknown value keeps the setting', async () => {
      for (const allowed of ['all', 'local_only', 'selected']) {
        const f = api(settingsNow({ perms: { enabled: true, allowed_actions: allowed, sha_pinning_required: true } }));
        expect(await f.api.write(perms, { ...app, enabled: true, sha_pinning_required: false }), allowed).toEqual({ status: 'done' });
        expect(f.writes()).toEqual([{ route: perms, params: { ...app, enabled: true, allowed_actions: allowed, sha_pinning_required: false } }]);
      }
      for (const allowed of [undefined, null, 'everything', 1]) {
        const f = api(settingsNow({ perms: { enabled: true, allowed_actions: allowed, sha_pinning_required: true } }));
        const out = await f.api.write(perms, { ...app, enabled: true, sha_pinning_required: false });
        expect(out.status, String(allowed)).toBe('kept');
        expect(out).toMatchObject({ manual: expect.stringContaining('repos/acme/shop/actions/permissions') });
        expect(f.writes()).toEqual([]);
      }
    });

    it('R2b sec M-r2-1: Dependabot alerts stay on while security updates are on (or unknown); secret scanning stays on while another secret_scanning switch is on', async () => {
      for (const autofix of [{ enabled: true, paused: false }, { enabled: true, paused: true }, {}, 403, 404, 500]) {
        const f = api(settingsNow({ autofix }));
        const out = await f.api.write(alerts, app);
        expect(out.status, JSON.stringify(autofix)).toBe('kept');
        expect(out).toMatchObject({ manual: expect.stringMatching(/Dependabot security updates[\s\S]*Dependabot alerts/) });
        expect(f.writes()).toEqual([]);
      }
      const off = api(settingsNow({ autofix: { enabled: false, paused: false } }));
      expect(await off.api.write(alerts, app)).toEqual({ status: 'done' });
      expect(off.calls.map((c) => c.route)).toEqual(['GET /repos/{owner}/{repo}', 'GET /repos/{owner}/{repo}/vulnerability-alerts', 'GET /repos/{owner}/{repo}/automated-security-fixes', alerts]);

      const both = { ...app, security_and_analysis: { [SS]: { status: 'disabled' }, [SP]: { status: 'disabled' } } };
      for (const extra of [`${SS}_validity_checks`, `${SS}_non_provider_patterns`, `${SS}_ai_detection`, `${SS}_delegated_bypass`]) {
        const f = api(settingsNow(), { repo: { security_and_analysis: { ...pipegenSa.security_and_analysis, [extra]: { status: 'enabled' } } } });
        const out = await f.api.write(patch, both);
        expect(out.status, extra).toBe('kept');
        expect(out).toMatchObject({ why: expect.stringContaining(extra), manual: expect.stringContaining(extra) });
        expect(f.writes()).toEqual([]);
      }
      // secret scanning alone turned off while push protection (which needs it) stays on
      const pp = api(settingsNow(), { repo: pipegenSa });
      expect((await pp.api.write(patch, { ...app, security_and_analysis: { [SS]: { status: 'disabled' } } })).status).toBe('kept');
      expect(pp.writes()).toEqual([]);
      // a switch that is off, or not a secret_scanning one, doesn't keep it
      const ok = api(settingsNow(), { repo: { security_and_analysis: { ...pipegenSa.security_and_analysis, [`${SS}_validity_checks`]: { status: 'disabled' }, advanced_security: { status: 'enabled' } } } });
      expect(await ok.api.write(patch, both)).toEqual({ status: 'done' });
    });

    it('R2b sec M-r2-3: no manual step turns Actions back on; the shared central access level\'s step says to check the other projects first', async () => {
      const off = await api(settingsNow({ perms: { enabled: false, sha_pinning_required: true } })).api.write(perms, { ...app, enabled: true, sha_pinning_required: false });
      expect(off).not.toHaveProperty('manual');
      const access = await api(settingsNow({ access: { access_level: 'enterprise' } })).api.write('PUT /repos/{owner}/{repo}/actions/permissions/access', { owner: OWNER, repo: 'pipelines', access_level: 'none' }, { pipegenSet: 'organization' });
      expect(access).toMatchObject({ status: 'kept', manual: expect.stringMatching(/^Check first that no other project of acme\/pipelines relies on/) });
    });

    it('R2b sec M-r2-7: the all-refs answer must list the default branch, else the central repo is kept', async () => {
      const r = await go({ refsAnswer: [] });
      expect(r.deleted).toBe(false);
      expect(r.out.why).toMatch(/refs\/heads\/main/);
      // a repo with no commit yet has no branch ref: an empty list is whole then
      expect((await go({ empty: true, refsAnswer: [] })).out).toEqual({ deleted: true });
    });

    it('R2b sec M-r2-8: a commit comment (or an unreadable list of them) keeps the central repo', async () => {
      const ok = await go({});
      expect(ok.out).toEqual({ deleted: true });
      const reads = ok.calls.filter((c) => c.route === 'GET /repos/{owner}/{repo}/comments');
      expect(reads.length).toBe(2);
      expect(reads[0]?.params).toEqual({ owner: OWNER, repo: 'pipelines', per_page: 1 });
      for (const comments of [[{ id: 1, body: 'note' }], 403, 500, {}] as W['comments'][]) {
        const r = await go({ comments });
        expect(r.deleted, JSON.stringify(comments)).toBe(false);
        expect(r.out.why).toMatch(/comment/);
      }
    });

    it('R2b sec M-r2-5: the central CODEOWNERS is deleted only while the parent tree holds a version pipegen wrote', async () => {
      const sha = (n: number) => String(n).repeat(40).slice(0, 40);
      const mk = (tree: unknown) => api((route) => {
        if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { sha: SHA, tree: { sha: SHA } };
        if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return tree;
        if (route === 'POST /repos/{owner}/{repo}/git/trees') return { sha: sha(1) };
        if (route === 'POST /repos/{owner}/{repo}/git/commits') return { sha: sha(2) };
        return {};
      });
      const created: InstallRecord['edits'] = [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: 'x', originalSha: null, writtenShas: [sha(3), sha(4)], baseShas: [null, sha(3)] } as InstallRecord['edits'][number]];   // V6b: chained from null
      const entry = (s: string, over: Record<string, unknown> = {}) => ({ path: '.github/CODEOWNERS', sha: s, mode: '100644', type: 'blob', ...over });
      const del = (a: UninstallApi) => a.commitUninstall('central', { parent: SHA, baseTree: SHA, files: [], deletes: ['.github/CODEOWNERS', 'installs/shop.json'], message: 'm', recordEdits: created });
      for (const tree of [
        { truncated: false, tree: [entry(sha(5))] },                    // the owner's version: a sha pipegen never wrote
        { truncated: false, tree: [{ ...entry(sha(3)), path: 'CODEOWNERS' }] },   // not at the record's path
        { truncated: false, tree: [] },
        { truncated: true, tree: [entry(sha(3))] },                     // a partial list
        { truncated: false, tree: [entry(sha(3), { type: 'commit' })] },
        {},
      ]) {
        const g = mk(tree);
        await expect(del(g.api), JSON.stringify(tree)).rejects.toBeInstanceOf(UninstallRefusal);
        expect(g.writes()).toEqual([]);
      }
      const ok = mk({ truncated: false, tree: [{ path: 'README.md', sha: sha(6), mode: '100644', type: 'blob' }, entry(sha(4)), { path: 'installs/shop.json', sha: sha(7), mode: '100644', type: 'blob' }] });
      expect(await del(ok.api)).toEqual({ commit: sha(2), tree: sha(1) });
      // the parent tree only (V6's read of the central default branch, CENTRAL_HEAD, is the last-project check): the CODEOWNERS check,
      // then PL-E6's delete check in commitFiles
      expect(ok.calls.filter((c) => c.route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}' && c.params.tree_sha !== CENTRAL_HEAD).map((c) => c.params)).toEqual([{ owner: OWNER, repo: 'pipelines', tree_sha: SHA, recursive: '1' }, { owner: OWNER, repo: 'pipelines', tree_sha: SHA, recursive: '1' }]);
    });

    it('V6b (G17C m4): the central CODEOWNERS is deleted only when the record\'s writes chain from null, never over an owner blob an older record holds', async () => {
      const sha = (n: number) => String(n).repeat(40).slice(0, 40);
      const mk = () => api((route) => {
        if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { sha: SHA, tree: { sha: SHA } };
        if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { truncated: false, tree: [{ path: '.github/CODEOWNERS', sha: sha(5), mode: '100644', type: 'blob' }] };
        if (route === 'POST /repos/{owner}/{repo}/git/trees') return { sha: sha(1) };
        if (route === 'POST /repos/{owner}/{repo}/git/commits') return { sha: sha(2) };
        return {};
      });
      const ed = (writtenShas: string[], baseShas?: (string | null)[]): InstallRecord['edits'] => [{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: 'x', originalSha: null, writtenShas, ...(baseShas === undefined ? {} : { baseShas }) } as InstallRecord['edits'][number]];
      const del = (a: UninstallApi, edits: InstallRecord['edits']) => a.commitUninstall('central', { parent: SHA, baseTree: SHA, files: [], deletes: ['.github/CODEOWNERS'], message: 'm', recordEdits: edits });
      for (const edits of [
        ed([sha(4), sha(5)], [null, sha(5)]),   // m4: a re-run that wrote nothing appended the owner's blob (a write based on itself)
        ed([sha(5)]),                           // an older record: no bases
        ed([sha(4), sha(5)], [null]),           // short
        ed([sha(4), sha(5)], [null, sha(6)]),   // broken
        ed([sha(5)], [sha(7)]),                 // the first base is not null (not created from nothing)
      ]) {
        const g = mk();
        await expect(del(g.api, edits), JSON.stringify(edits)).rejects.toBeInstanceOf(UninstallRefusal);
        expect(g.writes()).toEqual([]);
      }
      for (const edits of [ed([sha(5)], [null]), ed([sha(4), sha(5)], [null, sha(4)])]) {
        const ok = mk();
        expect(await del(ok.api, edits), JSON.stringify(edits)).toEqual({ commit: sha(2), tree: sha(1) });
      }
    });

    it('R2b sec M-r2-4: the scan takes the Octokit namespaces from a client and refuses destructured, aliased, ?., bracket and .call forms and code inside ${…}', () => {
      expect(OCTOKIT_NAMESPACES).toEqual(expect.arrayContaining(['repos', 'pulls', 'git', 'issues', 'campaigns', 'codeSecurity', 'credentials', 'enterpriseTeamMemberships', 'enterpriseTeamOrganizations', 'enterpriseTeams', 'hostedCompute', 'privateRegistries']));
      for (const bad of [
        // a namespace destructured or aliased
        'const { repos } = gh;', 'const { repos: r } = api.gh;', 'const { rest: { repos } } = gh;', 'const { git, pulls } = this.gh;', 'const r = gh.repos;', 'const r = gh.rest;', 'const r = api.gh?.pulls;',
        // ?. anywhere in the chain
        'await gh?.repos.delete(p);', 'await gh.repos?.delete(p);', 'await gh?.repos?.delete(p);', 'await gh.repos.delete?.(p);', 'await gh.rest?.repos.delete(p);',
        // a bracket after (or around) a namespace
        'await gh.repos[\'delete\'](p);', 'await gh.repos[m](p);', 'await gh.repos?.[m](p);', 'await gh[\'repos\'].delete(p);', 'await client[\'repos\'].delete(p);', 'await gh.rest[\'git\'].deleteRef(p);',
        // .call / .apply / .bind on an endpoint method
        'await gh.repos.delete.call(gh, p);', 'await gh.pulls.update.apply(gh, [p]);', 'const f = gh.git.deleteRef.bind(gh);',
        // code inside a template literal's ${…}
        'const s = `${await gh.repos.delete(p)}`;', 'const s = `a ${`b ${gh.git.deleteRef(p)}`} c`;', 'const s = `${{ x: 1 }.x} ${gh.request(r)}`;', 'const s = `${ { a: 1 }.a + gh.repos.delete(p) }`;',
        // the namespaces the hand-written list missed
        'await o.codeSecurity.deleteConfiguration(p);', 'await o.privateRegistries.deleteOrgPrivateRegistry(p);', 'await o.hostedCompute.deleteNetworkConfigurationFromOrg(p);',
        'await o.campaigns.deleteCampaign(p);', 'await o.credentials.revoke(p);', 'await o.enterpriseTeams.delete(p);', 'await o.enterpriseTeamMemberships.remove(p);', 'await o.enterpriseTeamOrganizations.delete(p);',
      ]) expect(scanProblems('plan.ts', bad), bad).not.toEqual([]);
      for (const ok of [
        'const n = d.issues[0];', 'const s = `${d.issues.length} issues`;', 'const s = `gh.repos.delete(p)`;', 'const open = d.issues?.filter((x) => x.open);',
        'const s = `${a}-${b}`;', 'if (x) { const y = `${z}`; }', 'const t = { a: `${b}` };',
        'const { githubCreatedAt: _drop, ...rest } = e;',
      ]) expect(scanProblems('plan.ts', ok), ok).toEqual([]);
    });
  });
});

// PL-E6 fold R1: a 401 or a rate stop on the base-tree read of a delete passes through commitUninstall as it is (not an UninstallRefusal).
describe('PL-E6 R1 commitUninstall passes 401 and rate stops through', async () => {
  const { GitHubAccessError } = await import('../src/github/client.js');
  const { isRateStop } = await import('../src/engine/github-rate.js');
  const S = 'a'.repeat(40);
  const httpErr = (status: number, headers: Record<string, string> = {}): Error => Object.assign(new Error(`HTTP ${status}`), { status, response: { data: { message: 'x' }, headers } });
  const mk = (treeErr: Error) => {
    const calls: string[] = [];
    const gh = { request: async (route: string) => {
      calls.push(route);
      if (route === 'GET /repos/{owner}/{repo}') return { status: 200, data: { id: 101, full_name: 'acme/shop', default_branch: 'main' }, headers: {} };
      if (route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}') return { status: 200, data: { sha: S, tree: { sha: S } }, headers: {} };
      if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') throw treeErr;
      if (route.startsWith('POST')) return { status: 201, data: { sha: S }, headers: {} };
      throw new Error(`unexpected ${route}`);
    } } as unknown as Octokit;
    const api = new UninstallApi(gh, APP, { clock: { budget: newRateBudget(), sleep: async () => {}, now: () => 0 }, askName: async () => true, centralRepoId: 202 });
    const run = () => api.commitUninstall('app', { parent: S, baseTree: S, files: [], deletes: ['a.yml'], message: 'm' }).catch((e: unknown) => e);
    return { run, posts: () => calls.filter((r) => r.startsWith('POST')) };
  };
  it('commitUninstall: a 401 on the base-tree read → GitHubAccessError, nothing POSTed', async () => {
    const f = mk(httpErr(401));
    const e = await f.run();
    expect(e).toBeInstanceOf(GitHubAccessError);
    expect(e).not.toBeInstanceOf(UninstallRefusal);
    expect(f.posts()).toEqual([]);
  });
  it('commitUninstall: a rate stop on the base-tree read → a rate stop, nothing POSTed', async () => {
    const f = mk(httpErr(403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '999999999' }));
    const e = await f.run();
    expect(isRateStop(e)).toBe(true);
    expect(e).not.toBeInstanceOf(UninstallRefusal);
    expect(f.posts()).toEqual([]);
  });
});
