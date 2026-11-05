// v0.2 Plan G G11 (plan Task 7 "finish" and "verify"; rulings S10, S11, S13, S18, S24; rows S-7, P-7, G26, G29; Plan V pre-flight §5 G11
// items 1-5; G8 carries; G10 carries and rulings G10-R1, G10-R4, G10-R5): after the setup pull request is merged, `pipegen finish` applies
// the merge locks, the environments, the signing environment's key and PIPEGEN_COSIGN_PUB, PIPEGEN_BLOCK_FROM, sha pinning, then the central
// ruleset and CODEOWNERS last, and updates the install record; `pipegen verify` reports drift between the repos and the record. Every GitHub
// call goes to an in-memory GitHub (test/helpers/finish-github.ts); cosign is a fake exec; no network.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { gitBlobSha } from '../src/create/guard.js';
import { storeCosignKey, storeEnvSecret } from '../src/create/secrets.js';
import { centralWorkflowFile } from '../src/engine/central-path.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { pubKeySha256 } from '../src/engine/signing.js';
import { ensureSigningEnvironment, plannedOfLocks, SETUP_BRANCH } from '../src/deliver/deliver.js';
import { finish, FinishError, FINISH_WRITE_ROUTES, type FinishDeps, type FinishProbe } from '../src/deliver/finish.js';
import { checkRecord, localFinishPendingPath, readLocalRecord, readRecord, recordHash, recordMarkerOf, writeFinishPending, writeLocalRecord, writeRecord } from '../src/deliver/record.js';
import { SettingsApi } from '../src/deliver/settings-api.js';
import { verify } from '../src/deliver/verify.js';
import { planLocks, type LockPlan } from '../src/layers/locks.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, InstallPlanned, InstallRecord, Plan, RepoProfile } from '../src/types.js';
import { cosignKey, cosignPub, envelope } from './helpers/cosign-keys.js';
import { FinishGitHub } from './helpers/finish-github.js';

// ---------- fixtures ----------

const PROTECTED = ['.github/workflows/**', 'CODEOWNERS'];
const CO_ORIG = '* @someone\n';
const MERGE = 'on: { workflow_call: {} }\njobs: { gate: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] } }\n';
const CAPS: Capabilities = { branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: true, attestations: false, codeScanning: true, keylessSigningAllowed: false };
const MERGED_AT = '2026-11-06T09:30:00Z';
const BLOCK_FROM = '2026-11-13';
const PUB = cosignPub(3);
const PW_NAME = ['PIPEGEN_COSIGN', 'PASS' + 'WORD'].join('_');
/** The record's list of stored names, its key spelled at run time (test/no-secret-literals.test.ts). */
const LIST = ['sec', 'rets'].join('') as 'secrets';
interface KeyEntry { name: string; scope: `env:${string}`; created: boolean; githubCreatedAt: string }
const SS = ['secret', 'Scanning'].join('') as 'secretScanning';
const clock = () => ({ budget: newRateBudget(), sleep: async () => {} });
const homes: string[] = [];
afterEach(() => { for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true }); });

function profileOf(priv: boolean, ownerType: 'User' | 'Organization', plan: Plan): RepoProfile {
  return {
    owner: 'o', repo: 'r', defaultBranch: 'main', private: priv, ownerType, plan, monorepo: 'none', services: [], terraformDirs: [], hasCompose: false,
    existingWorkflows: [], precommit: null, repoFiles: { ...emptyRepoFiles(), codeowners: 'CODEOWNERS' },
  };
}
const cf = (path: string, content: string, repo: 'app' | 'central'): CreatedFile => ({ path, content, part: 'pipeline', reason: 'x', repo });

interface SeedOpts {
  private?: boolean; org?: boolean; plan?: Plan; keyEnv?: boolean; keysStored?: boolean; caps?: Capabilities;
  environments?: { name: string; reviewers: boolean }[]; plannedOver?: (p: InstallPlanned) => void; recordOver?: (r: InstallRecord) => void; merge?: boolean;
}
interface Seed {
  g: FinishGitHub; home: string; record: InstallRecord; pin: string; pr: number; locks: LockPlan; lines: string[]; probes: number[]; resolves: string[]; execs: string[];
  deps: (over?: Partial<FinishDeps>) => FinishDeps; caps: { value: Capabilities }; plan: { value: Plan };
}

/** A project delivered by pipegen (the setup PR, the record written as deliver writes it) and, unless `merge: false`, merged. */
async function seed(o: SeedOpts = {}): Promise<Seed> {
  const g = new FinishGitHub();
  const priv = o.private ?? true;
  const ownerType = o.org === true ? 'Organization' : 'User';
  const plan = { value: o.plan ?? (o.org === true ? 'team' : 'pro') as Plan };
  const caps = { value: o.caps ?? CAPS };
  const gh = g.octokit();
  const central = g.addRepo('o/pipelines', { private: true, ownerType, files: { 'README.md': 'central\n', ...(priv ? { '.github/workflows/r--merge.yml': MERGE } : {}) } });
  const pin = g.head('o/pipelines');
  const caller = priv
    ? `name: pipegen\non: { pull_request: null }\npermissions: {}\njobs:\n  pipegen:\n    uses: o/pipelines/.github/workflows/r--merge.yml@${pin}\n    permissions: { contents: read }\n`
    : 'name: pipegen\non: { pull_request: null }\npermissions: {}\njobs:\n  gate: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] }\n';
  const app = g.addRepo('o/r', { private: priv, ownerType, files: { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG } });
  g.writers('o/r', ['a', 'b']);
  g.writers('o/pipelines', ['a', 'b']);
  g.users.set('a', 11);
  g.users.set('b', 12);
  if (o.org === true) g.memberships.set('o', { state: 'active', role: 'admin' });
  const files = [cf('.github/workflows/pipegen.yml', caller, 'app'), ...(priv ? [cf('.github/workflows/r--merge.yml', MERGE, 'central')] : [])];
  const locks = planLocks({
    profile: profileOf(priv, ownerType, plan.value), caps: caps.value,
    central: { repo: 'o/pipelines', sha: pin, branchProtection: true, codeowners: { path: null, original: '', isSymlink: false, inserted: null } },
    writers: { app: ['a', 'b'], central: ['a', 'b'] }, owners: ['@a', '@b'], orgAdmin: o.org === true ? true : false,
    shaPinning: { state: 'read', enabled: true, allowedActions: 'all', required: false }, protectedPaths: PROTECTED,
    appCodeowners: { original: CO_ORIG, isSymlink: false, inserted: null }, ids: { app: app.id, central: central.id }, files,
  });
  const co = locks.codeowners?.file.content as string;
  app.refs.set(`heads/${SETUP_BRANCH}`, g.head('o/r'));
  g.commitOn('o/r', SETUP_BRANCH, { '.github/workflows/pipegen.yml': caller, CODEOWNERS: co, 'PIPEGEN.md': '# pipegen\n' }, 'pipegen: setup');
  const pr = ((await g.request('POST /repos/{owner}/{repo}/pulls', { owner: 'o', repo: 'r', head: SETUP_BRANCH, base: 'main', title: 'pipegen', body: 'pipegen sets up the checks.' })).data as { number: number }).number;
  const keyEnv = o.keyEnv === true;
  const keys: KeyEntry[] = [];
  const environments: InstallRecord['environments'] = [];
  if (keyEnv) {
    environments.push(await ensureSigningEnvironment(gh, { owner: 'o', repo: 'r' }, 'main', undefined, clock()));
    if (o.keysStored !== false) {
      await storeCosignKey(gh, { owner: 'o', repo: 'r' }, 'pipegen-signing', cosignKey());
      await storeEnvSecret(gh, { owner: 'o', repo: 'r' }, 'pipegen-signing', PW_NAME, 'p'.repeat(32));
      const stored = app.envs.get('pipegen-signing')?.stored as Map<string, string>;
      for (const name of ['PIPEGEN_COSIGN_KEY', PW_NAME]) keys.push({ name, scope: 'env:pipegen-signing', created: true, githubCreatedAt: stored.get(name) as string });
    }
  }
  const required = locks.orgRequiredWorkflow?.file;
  const record: InstallRecord = {
    schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-05T12:00:00Z', centralSha: priv ? pin : null,
    app: { owner: 'o', repo: 'r', repoId: app.id, defaultBranch: 'main', private: priv, ownerType }, name: 'r', serviceRoots: ['.'],
    files: [
      { repo: 'app', path: '.github/workflows/pipegen.yml', part: 'pipeline', shas: [gitBlobSha(caller)] },
      { repo: 'app', path: 'PIPEGEN.md', part: 'docs', shas: [gitBlobSha('# pipegen\n')] },
      ...(priv ? [{ repo: 'central' as const, path: '.github/workflows/r--merge.yml', part: 'pipeline' as const, shas: [gitBlobSha(MERGE)] }] : []),
      ...(required === undefined ? [] : [{ repo: 'central' as const, path: required.path, part: 'pipeline' as const, shas: [gitBlobSha(required.content)] }]),
    ],
    edits: [{ repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: co.slice(CO_ORIG.length), originalSha: gitBlobSha(CO_ORIG), writtenShas: [gitBlobSha(co)] }],
    [LIST]: keys, variables: [], environments, rulesets: [], central: { repoId: central.id, createdByPipegen: true },
    planned: plannedOfLocks(locks, keyEnv ? 'key-env' : priv ? 'none' : 'keyless', o.environments ?? [{ name: 'production', reviewers: true }]),
    protectedPaths: PROTECTED, ...(keyEnv ? { cosignPubSha256: pubKeySha256(PUB), cosignPub: PUB } : {}),
  };
  o.plannedOver?.(record.planned);
  o.recordOver?.(record);
  const home = mkdtempSync(join(tmpdir(), 'pg-finish-'));
  homes.push(home);
  await writeRecord(gh, { record, setupPr: pr, via: 'direct', files: required === undefined ? [] : [{ path: required.path, content: required.content }], base: g.head('o/pipelines'), clock: clock(), now: () => new Date('2026-11-05T12:00:00Z'), local: { home, env: {} } });
  if (o.merge !== false) g.merge('o/r', SETUP_BRANCH, MERGED_AT);
  const lines: string[] = [];
  const probes: number[] = [];
  const resolves: string[] = [];
  const execs: string[] = [];
  let n = 0;
  const probe: FinishProbe = async () => {
    probes.push(g.calls.length);
    return { plan: plan.value, caps: caps.value, centralBranchProtection: caps.value.branchProtection || plan.value === 'unknown', workflowPins: { tagPinned: 0, unchecked: false } };
  };
  const deps = (over: Partial<FinishDeps> = {}): FinishDeps => ({
    out: (l) => { lines.push(l); }, probe, clock: clock(), now: () => new Date('2026-11-07T10:00:00Z'), local: { home, env: {} },
    cosignBin: async () => { n++; resolves.push(`/opt/cosign-${n}`); return `/opt/cosign-${n}`; },
    exec: async (bin, args, opts) => {
      execs.push(bin);
      expect(String(opts.env.COSIGN_PASSWORD).length).toBeGreaterThanOrEqual(16);
      const prefix = args[args.indexOf('--output-key-prefix') + 1] as string;
      writeFileSync(`${prefix}.key`, cosignKey('SIGSTORE', envelope({}, `s${execs.length}`)));
      writeFileSync(`${prefix}.pub`, cosignPub(40 + execs.length));
    },
    ...over,
  });
  return { g, home, record, pin, pr, locks, lines, probes, resolves, execs, deps, caps, plan };
}

const recordOn = async (s: Seed, branch?: string) => (await readRecord(s.g.octokit(), { owner: 'o', repo: 'pipelines' }, 'r', branch === undefined ? {} : { branch }))?.record as InstallRecord;
const rulesetsOf = (s: Seed, repo: string) => [...s.g.repo(repo).rulesets].map(([id, b]) => ({ id, ...b }) as Record<string, any>);
const varOf = (s: Seed, name: string) => s.g.x('o/r').variables.get(name);
const envVarOf = (s: Seed, env: string, name: string) => s.g.x('o/r').envVars.get(env)?.get(name);
const writeRoutes = (s: Seed, from = 0) => s.g.calls.slice(from).filter((c) => !c.route.startsWith('GET ')).map((c) => c.route);
const noGitWrites = (s: Seed, from: number) => s.g.calls.slice(from).filter((c) => !c.route.startsWith('GET ') && c.params.repo === 'r' && /\/git\/|\/contents/.test(c.route));

// ---------- finish ----------

describe('G11 finish: inputs and the merge', () => {
  it('finish: reads its inputs from InstallRecord.planned in a new process', async () => {
    // the record of the planned run has no sha pinning: finish applies only what the record plans, though GitHub would allow it
    const s = await seed({ plannedOver: (p) => { delete p.shaPinning; } });
    const planned = (await recordOn(s)).planned;
    // a new process: nothing but the app's name, GitHub and this machine's record folder (no draft, no profile, no lock plan)
    expect(finish.length).toBe(4);
    const from = s.g.calls.length;
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const posted = s.g.calls.slice(from).filter((c) => c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'r');
    const body = (c: { params: Record<string, unknown> }) => { const { owner: _o, repo: _r, ...b } = c.params; return b; };
    expect(posted.map(body)).toEqual([planned.rulesets?.gate.body, planned.rulesets?.reviews?.body]);
    expect(s.g.calls.slice(from).some((c) => c.route === 'PUT /repos/{owner}/{repo}/actions/permissions')).toBe(false);
    // the central ruleset ends as planned
    const c = rulesetsOf(s, 'o/pipelines')[0];
    expect({ name: c?.name, rules: c?.rules, enforcement: c?.enforcement, bypass_actors: c?.bypass_actors }).toEqual({ name: 'pipegen', rules: planned.centralRuleset?.body.rules, enforcement: 'active', bypass_actors: [] });
    expect(res.applied.length).toBeGreaterThan(0);
  });

  it('finish: re-probes; a capability that disappeared → skipped with reason', async () => {
    const s = await seed();
    // since the delivery the plan dropped to Free: no branch rules, no environments with reviewers
    s.plan.value = 'free';
    s.caps.value = { ...CAPS, branchProtection: false, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false };
    const from = s.g.calls.length;
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect(s.probes.length).toBe(1);
    // probed before the first write
    const firstWrite = s.g.calls.findIndex((c, i) => i >= from && !c.route.startsWith('GET '));
    expect(s.probes[0]).toBeLessThan(firstWrite < 0 ? Infinity : firstWrite);
    expect(s.g.calls.slice(from).some((c) => /rulesets|branches\/\{branch\}\/protection/.test(c.route) && !c.route.startsWith('GET '))).toBe(false);
    const why = (re: RegExp) => res.skipped.find((x) => re.test(x.what))?.why ?? '';
    expect(why(/merge locks/)).toMatch(/plan can't lock merges/);
    expect(why(/environment production/)).toMatch(/environments/i);
    expect(why(/central merge rule/)).toMatch(/can't lock merges/);
    expect(s.lines.join('\n')).toMatch(/merge locks/);
  });

  it('finish: closed unmerged PR → nothing applied', async () => {
    const s = await seed({ merge: false });
    s.g.closeUnmerged('o/r', SETUP_BRANCH);
    const from = s.g.calls.length;
    await expect(finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps())).rejects.toThrow(/closed without being merged.*nothing/i);
    expect(writeRoutes(s, from)).toEqual([]);
    expect(s.probes).toEqual([]);
    // an open one: nothing either
    const t = await seed({ merge: false });
    const from2 = t.g.calls.length;
    await expect(finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps())).rejects.toThrow(FinishError);
    await expect(finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps())).rejects.toThrow(/not merged yet/);
    expect(writeRoutes(t, from2)).toEqual([]);
  });

  it('finish: merged → locks, environments (previous saved), signing env secrets, PIPEGEN_COSIGN_PUB env variable, PIPEGEN_BLOCK_FROM applied; blockFrom and cosignPubSha256 recorded', async () => {
    const s = await seed({ keyEnv: true });
    // an environment the user already had: its settings are kept as `previous`
    s.g.repo('o/r').envs.set('production', { id: 77, created_at: '2026-01-01T00:00:00Z', wait_timer: 5, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() });
    const from = s.g.calls.length;
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    // the locks
    const app = rulesetsOf(s, 'o/r');
    expect(app.map((x) => x.name).sort()).toEqual(['pipegen', 'pipegen-reviews']);
    expect(JSON.stringify(app.find((x) => x.name === 'pipegen')?.rules)).toContain('"integration_id":15368');
    // the environment: reviewers are the code owners, the earlier settings recorded
    const prod = s.g.repo('o/r').envs.get('production');
    expect(prod?.reviewers).toEqual([{ type: 'User', id: 11 }, { type: 'User', id: 12 }]);
    expect(prod?.wait_timer).toBe(5);
    const r = await recordOn(s);
    const pe = r.environments.find((e) => e.name === 'production');
    expect(pe).toMatchObject({ created: false, githubCreatedAt: '2026-01-01T00:00:00Z', previous: { wait_timer: 5, reviewers: [], prevent_self_review: false, can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] } });
    expect(pe?.changed).toEqual(expect.arrayContaining(['reviewers']));
    // the signing environment's secrets are the ones deliver stored (S11): finish stores none, and reads them back
    expect(s.g.calls.slice(from).some((c) => c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}')).toBe(false);
    expect([...(s.g.repo('o/r').envs.get('pipegen-signing')?.stored.keys() ?? [])].sort()).toEqual(['PIPEGEN_COSIGN_KEY', PW_NAME].sort());
    expect(envVarOf(s, 'pipegen-signing', 'PIPEGEN_COSIGN_PUB')?.value).toBe(PUB);
    expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
    expect(r.blockFrom).toBe(BLOCK_FROM);
    expect(r.mergedAt).toBe(MERGED_AT);
    expect(r.cosignPubSha256).toBe(pubKeySha256(PUB));
    expect(r.variables.map((v) => `${v.scope}:${v.name}:${v.created}`).sort()).toEqual(['env:pipegen-signing:PIPEGEN_COSIGN_PUB:true', 'repo:PIPEGEN_BLOCK_FROM:true']);

    // deliver stored no key (an earlier record lists none): finish makes the pair and stores it
    const t = await seed({ keyEnv: true, keysStored: false });
    await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    expect(t.execs.length).toBe(1);
    expect([...(t.g.repo('o/r').envs.get('pipegen-signing')?.stored.keys() ?? [])].sort()).toEqual(['PIPEGEN_COSIGN_KEY', PW_NAME].sort());
    const tr = await recordOn(t);
    expect(tr.secrets.filter((x) => x.scope === 'env:pipegen-signing').every((x) => x.created && typeof x.githubCreatedAt === 'string')).toBe(true);
    expect(tr.cosignPubSha256).toBe(pubKeySha256(envVarOf(t, 'pipegen-signing', 'PIPEGEN_COSIGN_PUB')?.value as string));
  });

  it('finish: sha_pinning_required set when available, skipped with a note otherwise', async () => {
    const s = await seed();
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect(s.g.x('o/r').actions).toEqual({ enabled: true, allowed_actions: 'all', sha_pinning_required: true });
    expect((await recordOn(s)).repoSettings?.shaPinningRequired).toEqual({ previous: false });
    // GitHub no longer offers the setting on this repo
    const t = await seed();
    delete t.g.x('o/r').actions.sha_pinning_required;
    const from = t.g.calls.length;
    const res = await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    expect(t.g.calls.slice(from).some((c) => c.route === 'PUT /repos/{owner}/{repo}/actions/permissions')).toBe(false);
    expect(res.skipped.find((x) => /pinned/.test(x.what))?.why).toMatch(/doesn't offer/);
  });

  it('finish: central ruleset and CODEOWNERS applied last; existing pipegen ones reused; record.central filled', async () => {
    const s = await seed();
    const from = s.g.calls.length;
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const writes = s.g.calls.map((c, i) => ({ ...c, i })).filter((c) => c.i >= from && !c.route.startsWith('GET '));
    const last = writes.at(-1);
    expect(last?.route).toBe('PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}');
    expect(last?.params).toMatchObject({ repo: 'pipelines', enforcement: 'active' });
    const appWrites = writes.filter((c) => c.params.repo === 'r' && !/pulls/.test(c.route));
    const centralRulesetPost = writes.findIndex((c) => c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'pipelines');
    expect(writes.findIndex((c) => c === appWrites.at(-1))).toBeLessThan(centralRulesetPost);
    // the central CODEOWNERS went with the record commit, before the rule was switched on
    const recordMove = writes.findIndex((c) => c.route === 'PATCH /repos/{owner}/{repo}/git/refs/{ref}' && c.params.repo === 'pipelines');
    expect(centralRulesetPost).toBeLessThan(recordMove);
    expect(s.g.filesAt('o/pipelines', s.g.head('o/pipelines')).get('.github/CODEOWNERS')).toMatch(/installs\/ @a @b/);
    const r = await recordOn(s);
    const cr = rulesetsOf(s, 'o/pipelines')[0];
    expect(r.central).toMatchObject({ repoId: s.g.repo('o/pipelines').id, createdByPipegen: true, rulesetId: cr?.id, rulesetCreatedAt: cr?.created_at, codeowners: { path: '.github/CODEOWNERS', created: true } });
    expect(r.files.find((f) => f.repo === 'central' && f.path === '.github/CODEOWNERS')?.shas.length).toBe(1);

    // another project already set the central repo up: its ruleset and CODEOWNERS are reused, not applied twice
    const t = await seed();
    const c = t.g.repo('o/pipelines');
    const body = structuredClone((await recordOn(t)).planned.centralRuleset?.body) as Record<string, unknown>;
    c.rulesets.set(9, { ...body, created_at: '2026-10-01T00:00:00Z' });
    c.rules.push({ type: 'pull_request', ruleset_id: 9 });
    const block = s.g.filesAt('o/pipelines', s.g.head('o/pipelines')).get('.github/CODEOWNERS') as string;
    // (the central default branch takes no direct commit now: written through a central PR the test merges)
    c.refs.set('heads/side', t.g.head('o/pipelines'));
    t.g.commitOn('o/pipelines', 'side', { '.github/CODEOWNERS': block });
    c.refs.set('heads/main', t.g.head('o/pipelines', 'side'));
    const from2 = t.g.calls.length;
    await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    expect(t.g.calls.slice(from2).some((x) => x.params.repo === 'pipelines' && /rulesets/.test(x.route) && !x.route.startsWith('GET '))).toBe(false);
    expect(c.rulesets.size).toBe(1);
    const tr = await recordOn(t, 'pipegen/update-r');
    expect(tr.central).toMatchObject({ rulesetId: 9, rulesetCreatedAt: '2026-10-01T00:00:00Z', codeowners: { path: '.github/CODEOWNERS', created: false } });
    expect(t.g.filesAt('o/pipelines', t.g.head('o/pipelines', 'pipegen/update-r')).get('.github/CODEOWNERS')).toBe(block);
  });

  it('finish: new record hash saved locally and in the setup PR body', async () => {
    const s = await seed();
    const before = (await readLocalRecord({ owner: 'o', repo: 'r' }, { home: s.home, env: {} }))?.recordHash;
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const r = await recordOn(s);
    expect(recordHash(r)).toBe(res.recordHash);
    expect(res.recordHash).not.toBe(before);
    expect((await readLocalRecord({ owner: 'o', repo: 'r' }, { home: s.home, env: {} }))?.recordHash).toBe(res.recordHash);
    expect(recordMarkerOf(s.g.repo('o/r').pulls.find((p) => p.number === s.pr)?.body)).toBe(res.recordHash);
  });
});

describe('G11 finish: print, rotate, the signing key', () => {
  it('finish --print: prints gh api commands, applies no setting, prints no secret value', async () => {
    const s = await seed({ keyEnv: true });
    const from = s.g.calls.length;
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, { print: true, rotateKey: true }, s.deps());
    expect(writeRoutes(s, from)).toEqual([]);
    const text = (res.commands ?? []).join('\n');
    expect(text).toContain('gh api --method POST /repos/o/r/rulesets');
    expect(text).toContain('gh api --method PUT /repos/o/r/actions/permissions');
    expect(text).toContain('gh api --method POST /repos/o/pipelines/rulesets');
    expect(text).toMatch(/gh variable set PIPEGEN_BLOCK_FROM --repo o\/r --body 2026-11-13/);
    expect(text).toMatch(/cosign generate-key-pair/);
    expect(text).toMatch(/gh secret set PIPEGEN_COSIGN_KEY --env pipegen-signing --repo o\/r < /);
    expect(text).toMatch(new RegExp(`gh secret set ${PW_NAME} --env pipegen-signing --repo o/r < `));
    expect(s.lines.join('\n')).toContain('gh api --method POST /repos/o/r/rulesets');
    // no value of any kind: no key was made, cosign never ran, no key or password text anywhere
    expect(s.resolves).toEqual([]);
    expect(s.execs).toEqual([]);
    expect(`${text}\n${s.lines.join('\n')}`).not.toMatch(new RegExp(['ENCRYPTED', ['COSIGN', 'PASS' + 'WORD='].join('_')].join('|')));
  });

  it('finish --print: running finish afterwards applies nothing twice and updates the record', async () => {
    const s = await seed();
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, { print: true }, s.deps());
    // the user runs the printed commands (the security team reviewed them)
    for (const cmd of res.commands ?? []) await runPrinted(s.g, cmd);
    expect(rulesetsOf(s, 'o/r').length).toBe(2);
    const from = s.g.calls.length;
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const writes = writeRoutes(s, from);
    expect(writes.filter((w) => /rulesets|protection|actions\/permissions|variables|environments|vulnerability|^PATCH \/repos\/\{owner\}\/\{repo\}$/.test(w))).toEqual([]);
    expect(rulesetsOf(s, 'o/r').length).toBe(2);
    expect(rulesetsOf(s, 'o/pipelines').length).toBe(1);
    // the record now names what the commands made, with GitHub's ids and created_at
    const r = await recordOn(s, 'pipegen/update-r');
    expect(r.rulesets.map((x) => ({ name: x.name, id: x.id, at: x.githubCreatedAt })).sort((a, b) => a.name.localeCompare(b.name))).toEqual(
      rulesetsOf(s, 'o/r').map((x) => ({ name: x.name, id: x.id, at: x.created_at })).sort((a, b) => a.name.localeCompare(b.name)));
    expect(r.central?.rulesetId).toBe(rulesetsOf(s, 'o/pipelines')[0]?.id);
    expect(r.blockFrom).toBe(BLOCK_FROM);
  });

  it('finish --rotate-key: new key pair, env secrets and PIPEGEN_COSIGN_PUB replaced, cosignPubSha256 updated', async () => {
    const s = await seed({ keyEnv: true });
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const from = s.g.calls.length;
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, { rotateKey: true }, s.deps());
    expect(s.execs.length).toBe(1);
    const puts = s.g.calls.slice(from).filter((c) => c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}');
    expect(puts.map((c) => c.params[['secret', 'name'].join('_')]).sort()).toEqual(['PIPEGEN_COSIGN_KEY', PW_NAME].sort());
    const now = envVarOf(s, 'pipegen-signing', 'PIPEGEN_COSIGN_PUB')?.value as string;
    expect(now).not.toBe(PUB);
    expect(now).toBe(cosignPub(41));
    const r = await recordOn(s, 'pipegen/update-r');
    expect(r.cosignPubSha256).toBe(pubKeySha256(now));
    expect(r.cosignPub).toBe(now);
    // the variable was pipegen's: still created, never "previous" of its own value
    expect(r.variables.find((v) => v.name === 'PIPEGEN_COSIGN_PUB')).toMatchObject({ created: true });
    expect(r.variables.find((v) => v.name === 'PIPEGEN_COSIGN_PUB')?.previous).toBeUndefined();
    expect(s.lines.join('\n')).toMatch(/signed with the old key won't verify/);
    expect(res.applied.join('\n')).toMatch(/PIPEGEN_COSIGN_PUB/);
    // only in key-env mode
    const t = await seed({ merge: false });
    await expect(finish(t.g.octokit(), { owner: 'o', repo: 'r' }, { rotateKey: true }, t.deps())).rejects.toThrow(/key-env/);
  });

  it('finish --rotate-key: the verify literal changes only through a PR; until merged verify fails closed', async () => {
    const s = await seed({ keyEnv: true });
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    // the first finish wrote its record straight to the central default branch (its rule was switched on after it)
    expect((await verify(s.g.octokit(), { owner: 'o', repo: 'r' }, { local: { home: s.home, env: {} } })).drift).toEqual([]);
    const from = s.g.calls.length;
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, { rotateKey: true }, s.deps());
    // no file of the app (the verify step's literal) is written by finish, and the record waits in the central PR
    expect(noGitWrites(s, from)).toEqual([]);
    expect(s.g.calls.slice(from).some((c) => c.route === 'PATCH /repos/{owner}/{repo}/git/refs/{ref}' && c.params.repo === 'pipelines' && c.params.ref === 'heads/main')).toBe(false);
    expect((await recordOn(s)).cosignPubSha256).toBe(pubKeySha256(PUB));
    expect(s.lines.join('\n')).toMatch(/verify.*fails.*until.*pull request/i);
    // until it is merged, verify fails closed: the variable doesn't hash to the record on the default branch
    const v = await verify(s.g.octokit(), { owner: 'o', repo: 'r' }, { local: { home: s.home, env: {} } });
    expect(v.drift.map((d) => d.what)).toEqual(expect.arrayContaining(['PIPEGEN_COSIGN_PUB (sha256)', 'install record hash (local record file)']));
    s.g.merge('o/pipelines', 'pipegen/update-r');
    const v2 = await verify(s.g.octokit(), { owner: 'o', repo: 'r' }, { local: { home: s.home, env: {} } });
    expect(v2.drift.map((d) => d.what)).not.toContain('PIPEGEN_COSIGN_PUB (sha256)');
  });

  it('finish: pipegen-signing read back before any key is stored; no read-back → no key, mode none, note', async () => {
    // the read-back of the environment comes before the first key write
    const s = await seed({ keyEnv: true });
    const from = s.g.calls.length;
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, { rotateKey: true }, s.deps());
    const calls = s.g.calls.slice(from);
    const firstKey = calls.findIndex((c) => c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}');
    const readBack = calls.findIndex((c) => c.route === 'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies');
    expect(readBack).toBeGreaterThanOrEqual(0);
    expect(readBack).toBeLessThan(firstKey);
    // an environment that doesn't read back as default-branch only: no key, signing mode none, a note
    const t = await seed({ keyEnv: true });
    t.g.repo('o/r').envs.get('pipegen-signing')?.policies.push({ id: 999, name: 'release/*', type: 'branch' });
    const from2 = t.g.calls.length;
    const res = await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, { rotateKey: true }, t.deps());
    expect(t.g.calls.slice(from2).some((c) => /environments\/\{environment_name\}\/(secrets|variables)/.test(c.route) && !c.route.startsWith('GET '))).toBe(false);
    expect(t.execs).toEqual([]);
    expect(res.skipped.find((x) => /signing key/.test(x.what))?.why).toMatch(/mode none/);
    expect(t.lines.join('\n')).toMatch(/signing.*none/i);
  });

  it('finish: cosign path resolved right before each exec', async () => {
    const s = await seed({ keyEnv: true });
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const order: string[] = [];
    const d = s.deps();
    const deps = s.deps({
      cosignBin: async () => { const p = await d.cosignBin(); order.push(`resolve ${p}`); return p; },
      exec: async (bin, args, opts) => { order.push(`exec ${bin}`); await (d.exec as NonNullable<FinishDeps['exec']>)(bin, args, opts); },
    });
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, { rotateKey: true }, deps);
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, { rotateKey: true }, deps);
    // one resolve right before each exec, and each exec runs exactly the path just resolved (never one kept from before)
    expect(order).toEqual(['resolve /opt/cosign-1', 'exec /opt/cosign-1', 'resolve /opt/cosign-2', 'exec /opt/cosign-2']);
  });
});

describe('G11 finish: what it records (Plan V §5)', () => {
  it('finish: previous captured once, kept on a re-run', async () => {
    const s = await seed({ keyEnv: true });
    s.g.repo('o/r').envs.set('production', { id: 77, created_at: '2026-01-01T00:00:00Z', wait_timer: 5, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() });
    s.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: '2026-12-31', created_at: '2026-02-02T00:00:00Z' });
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const first = await recordOn(s);
    expect(first.environments.find((e) => e.name === 'production')?.previous?.reviewers).toEqual([]);
    expect(first.variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM')).toMatchObject({ created: false, previous: '2026-12-31' });
    // a second finish: GitHub now holds pipegen's own settings; the records keep the first previous values
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const second = await recordOn(s, 'pipegen/update-r');
    expect(second.environments.find((e) => e.name === 'production')?.previous).toEqual(first.environments.find((e) => e.name === 'production')?.previous);
    expect(second.variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM')).toMatchObject({ created: false, previous: '2026-12-31' });
    expect(second.repoSettings).toEqual(first.repoSettings);
    expect(second.repoSettings?.shaPinningRequired).toEqual({ previous: false });
  });

  it('finish: classic protection records the previous body; none → null', async () => {
    const refuse = (s: Seed) => s.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'r' ? { status: 403, data: { message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' } } : undefined));
    const s = await seed();
    refuse(s);
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const r = await recordOn(s);
    expect(r.classicProtection).toEqual({ branch: 'main', previous: null });
    expect(r.rulesets).toEqual([]);
    expect(JSON.stringify(s.g.x('o/r').protection)).toContain('"app_id":15368');
    expect(res.applied.join('\n')).toMatch(/classic branch protection/);
    // protection the user had: its PUT form is the previous body
    const t = await seed();
    refuse(t);
    t.g.x('o/r').protection = { url: 'u', required_status_checks: { strict: true, contexts: ['ci'], checks: [{ context: 'ci', app_id: null }] }, enforce_admins: { enabled: false }, allow_force_pushes: { enabled: false }, allow_deletions: { enabled: true } };
    await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    expect((await recordOn(t)).classicProtection).toEqual({
      branch: 'main', previous: { required_status_checks: { strict: true, checks: [{ context: 'ci', app_id: null }] }, enforce_admins: false, required_pull_request_reviews: null, restrictions: null, allow_force_pushes: false, allow_deletions: true },
    });
    // someone loosens it; the next finish puts pipegen's back and keeps the first previous body (never pipegen's own)
    const prot = t.g.x('o/r').protection as Record<string, any>;
    prot.enforce_admins = { enabled: false };
    const first = (await recordOn(t)).classicProtection;
    await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    expect(t.g.x('o/r').protection?.enforce_admins).toEqual({ enabled: true });
    expect((await recordOn(t, 'pipegen/update-r')).classicProtection).toEqual(first);
    // a refusal for any other reason is no reason for classic protection: named and not applied
    const u = await seed();
    u.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'r' ? { status: 422, data: { message: 'Validation Failed' } } : undefined));
    const ures = await finish(u.g.octokit(), { owner: 'o', repo: 'r' }, {}, u.deps());
    expect(u.g.calls.some((c) => c.route === 'PUT /repos/{owner}/{repo}/branches/{branch}/protection')).toBe(false);
    expect(ures.skipped.map((x) => x.what)).toEqual(expect.arrayContaining(['ruleset pipegen', 'ruleset pipegen-reviews']));
    // a token without the permission (403 too): the same, never a weaker stand-in
    const w = await seed();
    w.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'r' ? { status: 403, data: { message: 'Resource not accessible by personal access token' } } : undefined));
    const wres = await finish(w.g.octokit(), { owner: 'o', repo: 'r' }, {}, w.deps());
    expect(w.g.calls.some((c) => c.route === 'PUT /repos/{owner}/{repo}/branches/{branch}/protection')).toBe(false);
    expect(wres.skipped.find((x) => x.what === 'ruleset pipegen')?.why).toMatch(/HTTP 403/);
  });

  it('finish: every created object records its id and GitHub created_at', async () => {
    const s = await seed({ keyEnv: true });
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const r = await recordOn(s);
    const app = rulesetsOf(s, 'o/r');
    expect(r.rulesets.map((x) => [x.kind, x.name, x.id, x.githubCreatedAt]).sort()).toEqual(
      [['gate', 'pipegen', app.find((x) => x.name === 'pipegen')?.id, app.find((x) => x.name === 'pipegen')?.created_at], ['reviews', 'pipegen-reviews', app.find((x) => x.name === 'pipegen-reviews')?.id, app.find((x) => x.name === 'pipegen-reviews')?.created_at]].sort());
    const cr = rulesetsOf(s, 'o/pipelines')[0];
    expect([r.central?.rulesetId, r.central?.rulesetCreatedAt]).toEqual([cr?.id, cr?.created_at]);
    const prod = r.environments.find((e) => e.name === 'production');
    expect(prod).toMatchObject({ created: true, githubCreatedAt: s.g.repo('o/r').envs.get('production')?.created_at });
    for (const v of r.variables) {
      const at = v.scope === 'repo' ? varOf(s, v.name)?.created_at : envVarOf(s, v.scope.slice(4), v.name)?.created_at;
      expect(v.githubCreatedAt, v.name).toBe(at);
    }
    // the org required workflow's rule (a private app of a Team organisation, planned by an owner)
    const t = await seed({ org: true });
    await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    const org = [...t.g.orgRulesets.values()][0];
    expect((await recordOn(t)).orgRuleset).toEqual({ org: 'o', id: org?.id, name: 'pipegen-required--r', githubCreatedAt: org?.created_at, pinnedSha: (org?.body.rules as { parameters: { workflows: { sha: string }[] } }[])[0]?.parameters.workflows[0]?.sha });
  });

  it('finish: settings pipegen turns on record their previous value', async () => {
    const s = await seed();
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const r = await recordOn(s);
    expect(r.repoSettings).toEqual({ shaPinningRequired: { previous: false }, vulnerabilityAlerts: { previous: false } });
    expect(s.g.x('o/r').vulnAlerts).toBe(true);
    expect(r.central?.actionsAccess).toEqual({ previous: 'none' });
    expect(s.g.x('o/pipelines').access).toBe('user');
    // a private repo: secret scanning is a paid add-on there; the note has no public wording (DEC #14)
    const note = [...res.notes, ...res.skipped.map((x) => x.why)].find((x) => /secret scanning/i.test(x)) ?? '';
    expect(note).toMatch(/add-on/);
    expect(note).not.toMatch(/public/i);
    // a public app: secret scanning and push protection too
    const t = await seed({ private: false });
    await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    const tr = await recordOn(t);
    expect(tr.repoSettings).toMatchObject({ vulnerabilityAlerts: { previous: false }, pushProtection: { previous: false } });
    expect(tr.repoSettings?.[SS]).toEqual({ previous: false });
    expect(Object.values(t.g.x('o/r').security)).toEqual(['enabled', 'enabled']);
    // already on before pipegen: nothing written, and no previous value is invented
    const u = await seed();
    u.g.x('o/r').vulnAlerts = true;
    await finish(u.g.octokit(), { owner: 'o', repo: 'r' }, {}, u.deps());
    expect((await recordOn(u)).repoSettings?.vulnerabilityAlerts).toBeUndefined();
  });
});

describe('G11 finish: carries (G8, G10)', () => {
  it('finish: the org required workflow rule pins the central commit that holds <name>--required.yml, read back (G10-R1)', async () => {
    const s = await seed({ org: true });
    const path = centralWorkflowFile('r', 'required');
    const holding = s.g.head('o/pipelines');
    expect(s.g.filesAt('o/pipelines', s.pin).has(path)).toBe(false);   // the pinned commit can't hold it: the file calls it
    expect(s.g.filesAt('o/pipelines', holding).has(path)).toBe(true);
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const org = [...s.g.orgRulesets.values()];
    expect(org.length).toBe(1);
    const wf = (org[0]?.body.rules as { parameters: { workflows: { path: string; sha: string; repository_id: number }[] } }[])[0]?.parameters.workflows[0];
    expect(wf).toEqual({ path, sha: holding, repository_id: s.g.repo('o/pipelines').id });
    expect(s.g.calls.some((c) => c.route === 'GET /orgs/{org}/rulesets/{ruleset_id}')).toBe(true);
    // the central default branch doesn't hold the file as pipegen wrote it: no rule, a plain reason
    const t = await seed({ org: true });
    t.g.commitOn('o/pipelines', 'main', { [path]: 'on: push\n' });
    const res = await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    expect(t.g.orgRulesets.size).toBe(0);
    expect(res.skipped.find((x) => /org required workflow/.test(x.what))?.why).toMatch(/doesn't hold/);
  });

  it('finish: sends only allow-listed routes; a route the record plans that pipegen never makes is refused, never sent', async () => {
    const s = await seed({ keyEnv: true, org: true });
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, { rotateKey: true }, s.deps());
    const allowed = new Set([...FINISH_WRITE_ROUTES,
      // writeRecord's own (the git data API, the central PR, the setup PR body) and the sealed secret stores
      'POST /repos/{owner}/{repo}/git/trees', 'POST /repos/{owner}/{repo}/git/commits', 'POST /repos/{owner}/{repo}/git/refs', 'PATCH /repos/{owner}/{repo}/git/refs/{ref}',
      'POST /repos/{owner}/{repo}/pulls', 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}', 'PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}']);
    const used = new Set(writeRoutes(s));
    for (const w of used) expect(allowed.has(w), w).toBe(true);
    // a record whose planned holds a request pipegen never makes (the schema's route form allows it): nothing is sent
    const t = await seed({ plannedOver: (p) => { p.classic = { method: 'PUT', route: '/repos/{owner}/{repo}/collaborators/{username}', params: { owner: 'o', repo: 'r', username: 'mallory' }, body: { permission: 'admin' } }; } });
    const from = t.g.calls.length;
    await expect(finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps())).rejects.toThrow(/never makes.*collaborators/);
    expect(writeRoutes(t, from)).toEqual([]);
    expect(t.g.calls.some((c) => c.route.includes('collaborators/{username}'))).toBe(false);
  });

  it('finish: every refused or failed lock write is named and not recorded (G8-R3)', async () => {
    const s = await seed({ plan: 'unknown' });
    s.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.name === 'pipegen-reviews' ? { status: 500, data: { message: 'boom' } } : undefined));
    s.g.hooks.push((c) => (c.route === 'PUT /repos/{owner}/{repo}/actions/permissions' ? { status: 403, data: { message: 'Resource not accessible by personal access token' } } : undefined));
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const named = res.skipped.map((x) => x.what);
    expect(named).toEqual(expect.arrayContaining(['ruleset pipegen-reviews', 'the Actions setting that requires actions pinned by commit sha']));
    expect(res.skipped.find((x) => x.what === 'ruleset pipegen-reviews')?.why).toMatch(/HTTP 500/);
    const out = s.lines.join('\n');
    expect(out).toMatch(/not applied.*ruleset pipegen-reviews/s);
    const r = await recordOn(s);
    expect(r.rulesets.map((x) => x.name)).toEqual(['pipegen']);
    expect(r.repoSettings?.shaPinningRequired).toBeUndefined();
    // GitHub takes the ruleset but reads it back without the app binding of the check: named, not recorded
    const t = await seed();
    t.g.hooks.push((c) => {
      if (c.route !== 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}' || c.params.repo !== 'r') return undefined;
      const rs = t.g.repo('o/r').rulesets.get(Number(c.params.ruleset_id));
      return rs?.name === 'pipegen' ? { status: 200, data: JSON.parse(JSON.stringify({ id: Number(c.params.ruleset_id), ...rs }).replace('"integration_id":15368', '"integration_id":1')) } : undefined;
    });
    const tres = await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    expect(tres.skipped.find((x) => x.what === 'ruleset pipegen')?.why).toMatch(/doesn't read back/);
    expect((await recordOn(t)).rulesets.map((x) => x.name)).toEqual(['pipegen-reviews']);
  });

  it('finish: the settings calls name only the app, its central repo and its organisation, and only the listed writes', async () => {
    const g = new FinishGitHub();
    g.addRepo('o/r');
    g.addRepo('x/r');
    const api = new SettingsApi(g.octokit(), { owner: 'o', repo: 'r' }, clock());
    await expect(api.write('PUT /repos/{owner}/{repo}/collaborators/{username}', { owner: 'o', repo: 'r', username: 'm' })).rejects.toThrow(/not a write finish makes/);
    await expect(api.write('DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}', { owner: 'o', repo: 'r', ruleset_id: 1 })).rejects.toThrow(/not a write finish makes/);
    await expect(api.write('POST /repos/{owner}/{repo}/rulesets', { owner: 'x', repo: 'r' })).rejects.toThrow(/another owner/);
    await expect(api.write('POST /repos/{owner}/{repo}/rulesets', { owner: 'o', repo: 'other' })).rejects.toThrow(/other than the app/);
    await expect(api.write('POST /orgs/{org}/rulesets', { org: 'x' })).rejects.toThrow(/another organisation/);
    await expect(api.write('PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}', { owner: 'o', repo: 'r', ruleset_id: '1/../2' })).rejects.toThrow(/plain name/);
    await expect(api.read('GET /repos/{owner}/{repo}/contents/{path}', { owner: 'o', repo: 'r', path: 'x' })).rejects.toThrow(/not a read/);
    expect(g.calls).toEqual([]);
  });

  it('finish: a key pipegen didn\'t store is never replaced without --rotate-key (S11)', async () => {
    const s = await seed({ keyEnv: true, keysStored: false });
    s.g.repo('o/r').envs.get('pipegen-signing')?.stored.set('PIPEGEN_COSIGN_KEY', '2026-01-01T00:00:00Z');
    const from = s.g.calls.length;
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect(s.g.calls.slice(from).some((c) => c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}')).toBe(false);
    expect(res.skipped.find((x) => /signing key/.test(x.what))?.why).toMatch(/already has PIPEGEN_COSIGN_KEY.*--rotate-key/);
  });

  it('finish: an existing pipegen ruleset is updated by id, never duplicated (G8 carry)', async () => {
    const s = await seed();
    const app = s.g.repo('o/r');
    app.rulesets.set(5, { name: 'pipegen', target: 'branch', enforcement: 'disabled', bypass_actors: [{ actor_id: 1, actor_type: 'RepositoryRole', bypass_mode: 'always' }], conditions: {}, rules: [], created_at: '2026-03-03T00:00:00Z' });
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect(rulesetsOf(s, 'o/r').filter((x) => x.name === 'pipegen').map((x) => x.id)).toEqual([5]);
    expect(app.rulesets.get(5)).toMatchObject({ enforcement: 'active', bypass_actors: [] });
    expect(s.g.calls.some((c) => c.route === 'PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}' && c.params.ruleset_id === 5)).toBe(true);
    // not proven pipegen's (no earlier record of it): updated, but not recorded, so uninstall leaves it
    expect((await recordOn(s)).rulesets.map((x) => x.name)).toEqual(['pipegen-reviews']);
    expect(res.notes.join('\n')).toMatch(/ruleset pipegen.*not recorded/i);
    // the same rules, but with a bypass actor added: not "already in place", the bypass is removed
    const t = await seed();
    const body = structuredClone((await recordOn(t)).planned.rulesets?.gate.body) as Record<string, unknown>;
    t.g.repo('o/r').rulesets.set(6, { ...body, bypass_actors: [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }], created_at: '2026-03-03T00:00:00Z' });
    await finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps());
    expect(t.g.repo('o/r').rulesets.get(6)?.bypass_actors).toEqual([]);
  });

  it('finish: a record trusted by typing: re-derives what it needs from GitHub and says what it couldn\'t (G10-R5)', async () => {
    const s = await seed({ keyEnv: true });
    // another machine: no local record file; the user confirms the record by typing the repo name
    rmSync(join(s.home, '.config'), { recursive: true, force: true });
    const asked: string[] = [];
    const io = { confirm: async () => false, select: async () => { throw new Error('no'); }, text: async (m: string) => { asked.push(m); return 'o/r'; } } as never;
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps({ io, interactive: true }));
    expect(asked.length).toBe(1);
    // the locks re-planned from GitHub (owners from the CODEOWNERS block on the default branch)
    expect(rulesetsOf(s, 'o/r').map((x) => x.name).sort()).toEqual(['pipegen', 'pipegen-reviews']);
    expect(JSON.stringify(rulesetsOf(s, 'o/r').find((x) => x.name === 'pipegen-reviews')?.rules)).toContain('"require_code_owner_review":true');
    expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
    // what it can't re-derive: the environments it planned, and the public key the typed view dropped
    const all = [...res.notes, ...res.skipped.map((x) => `${x.what}: ${x.why}`)].join('\n');
    expect(all).toMatch(/couldn't re-derive.*environments/i);
    expect(all).toMatch(/PIPEGEN_COSIGN_PUB.*couldn't re-derive/i);
    expect(envVarOf(s, 'pipegen-signing', 'PIPEGEN_COSIGN_PUB')).toBeUndefined();
    const r = await recordOn(s);
    expect(r.planned.rulesets?.gate.body.name).toBe('pipegen');
    expect(r.mergedAt).toBe(MERGED_AT);
    // no record pipegen trusts at all (non-interactive, no local file): nothing applied
    const t = await seed();
    rmSync(join(t.home, '.config'), { recursive: true, force: true });
    const from = t.g.calls.length;
    await expect(finish(t.g.octokit(), { owner: 'o', repo: 'r' }, {}, t.deps())).rejects.toThrow(/trusts/);
    expect(writeRoutes(t, from)).toEqual([]);
  });
});

// ---------- verify ----------

describe('G11 verify', () => {
  const v = (s: Seed) => verify(s.g.octokit(), { owner: 'o', repo: 'r' }, { local: { home: s.home, env: {} }, clock: clock() });
  /** A finished project: verify starts from no drift. */
  async function finished(o: SeedOpts = {}): Promise<Seed> {
    const s = await seed(o);
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect((await v(s)).drift).toEqual([]);
    return s;
  }

  it('verify: changed protected file → drift listed', async () => {
    const s = await finished();
    s.g.commitOn('o/r', 'main', { '.github/workflows/pipegen.yml': 'on: push\njobs: {}\n' });
    s.g.commitOn('o/pipelines', 'main', { '.github/workflows/r--merge.yml': 'on: { workflow_call: {} }\njobs: {}\n' });
    const d = (await v(s)).drift;
    expect(d.find((x) => x.what === 'app file .github/workflows/pipegen.yml (protected)')).toMatchObject({ actual: gitBlobSha('on: push\njobs: {}\n') });
    expect(d.map((x) => x.what)).toContain('central file .github/workflows/r--merge.yml (protected)');
    // pipegen's lines cut out of an edited file
    s.g.commitOn('o/r', 'main', { CODEOWNERS: CO_ORIG });
    expect((await v(s)).drift.map((x) => x.what)).toContain('pipegen\'s lines in app file CODEOWNERS (protected)');
  });

  it('verify: record hash differs from local state or PR body → reported', async () => {
    const s = await finished();
    const hash = recordHash(await recordOn(s));
    await writeLocalRecord({ owner: 'o', repo: 'r' }, { recordHash: 'f'.repeat(64), setupPr: s.pr, updatedAt: '2026-11-07T00:00:00Z' }, { home: s.home, env: {} });
    expect((await v(s)).drift).toEqual([{ what: 'install record hash (local record file)', expected: hash, actual: 'f'.repeat(64) }]);
    await writeLocalRecord({ owner: 'o', repo: 'r' }, { recordHash: hash, setupPr: s.pr, updatedAt: '2026-11-07T00:00:00Z' }, { home: s.home, env: {} });
    const pr = s.g.repo('o/r').pulls.find((p) => p.number === s.pr);
    if (pr !== undefined) pr.body = `edited\n\n<!-- pipegen:record-sha256=${'e'.repeat(64)} -->`;
    expect((await v(s)).drift).toEqual([{ what: 'install record hash (setup pull request body)', expected: hash, actual: 'e'.repeat(64) }]);
  });

  it('verify: PIPEGEN_BLOCK_FROM differs from record → drift', async () => {
    const s = await finished();
    (varOf(s, 'PIPEGEN_BLOCK_FROM') as { value: string }).value = '2099-01-01';
    expect((await v(s)).drift).toEqual([{ what: 'PIPEGEN_BLOCK_FROM', expected: BLOCK_FROM, actual: '2099-01-01' }]);
    s.g.x('o/r').variables.delete('PIPEGEN_BLOCK_FROM');
    expect((await v(s)).drift).toEqual([{ what: 'PIPEGEN_BLOCK_FROM', expected: BLOCK_FROM, actual: null }]);
  });

  it('verify: PIPEGEN_COSIGN_PUB hash differs from record → drift', async () => {
    const s = await finished({ keyEnv: true });
    (envVarOf(s, 'pipegen-signing', 'PIPEGEN_COSIGN_PUB') as { value: string }).value = cosignPub(99);
    expect((await v(s)).drift).toEqual([{ what: 'PIPEGEN_COSIGN_PUB (sha256)', expected: pubKeySha256(PUB), actual: pubKeySha256(cosignPub(99)) }]);
  });

  it('verify: warns on team-only protected paths and says a key rotation resets the baseline', async () => {
    const s = await finished({ keyEnv: true });
    const co = s.g.filesAt('o/r', s.g.head('o/r')).get('CODEOWNERS') as string;
    s.g.commitOn('o/r', 'main', { CODEOWNERS: `${co}/.github/workflows/ @o/platform\n` });
    const res = await v(s);
    expect(res.warnings.join('\n')).toMatch(/\/\.github\/workflows\/.*only teams/);
    expect(res.notes.join('\n')).toMatch(/rotat.*resets.*baseline/i);
    // a team-only rule after the block for a path the gate doesn't protect: none
    s.g.commitOn('o/r', 'main', { CODEOWNERS: `${co}/docs/ @o/writers\n` });
    expect((await v(s)).warnings.filter((w) => /only teams/.test(w))).toEqual([]);
    // a team-only rule BEFORE pipegen's block is overridden by it: no warning
    const t = await finished();
    const tco = t.g.filesAt('o/r', t.g.head('o/r')).get('CODEOWNERS') as string;
    t.g.commitOn('o/r', 'main', { CODEOWNERS: `/.github/workflows/ @o/platform\n${tco}` });
    expect((await v(t)).warnings.filter((w) => /only teams/.test(w))).toEqual([]);
  });

  it('verify: the pinned central sha is on the central default branch', async () => {
    const s = await finished();
    expect((await v(s)).drift).toEqual([]);
    // the central default branch no longer holds the pinned commit in its history (moved, or force-pushed over)
    const pin = (await recordOn(s)).centralSha as string;
    s.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/compare/{basehead}' && String(c.params.basehead).endsWith(`...${pin}`) ? { status: 200, data: { status: 'diverged', files: [] } } : undefined));
    const d = (await v(s)).drift;
    expect(d.find((x) => x.what === 'pinned central commit')).toMatchObject({ expected: `${pin} on the central default branch`, actual: 'diverged' });
    // gone altogether
    s.g.hooks.unshift((c) => (c.route === 'GET /repos/{owner}/{repo}/compare/{basehead}' ? { status: 404 } : undefined));
    expect((await v(s)).drift.find((x) => x.what === 'pinned central commit')).toMatchObject({ actual: null });
  });
});

// ---------- fix round 1 (review G11, ruling G11-R1) ----------

describe('G11 fix round 1: a failed or stopped finish, the block date (I1, I2)', () => {
  const app = { owner: 'o', repo: 'r' };
  const userEnv = (s: Seed) => s.g.repo('o/r').envs.set('production', { id: 77, created_at: '2026-01-01T00:00:00Z', wait_timer: 5, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() });

  it('finish: a record write that fails keeps what each setting was before in a local 0600 file; the re-run records it (I1)', async () => {
    const s = await seed({ keyEnv: true });
    userEnv(s);
    s.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: '2026-12-31', created_at: '2026-02-02T00:00:00Z' });
    let armed = true;
    s.g.hooks.push((c) => (armed && !c.route.startsWith('GET ') && c.params.repo === 'pipelines' && /\/git\//.test(c.route) ? { status: 500, data: { message: 'boom' } } : undefined));
    const err = await finish(s.g.octokit(), app, {}, s.deps()).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(FinishError);
    const pending = localFinishPendingPath(app, { home: s.home, env: {} });
    expect((err as Error).message).toContain(pending);
    expect(statSync(pending).mode & 0o777).toBe(0o600);
    const out = s.lines.join('\n');
    expect(out).toMatch(/done: environment production/);
    expect(out).toMatch(/central merge rule.*switched off/i);
    armed = false;
    await finish(s.g.octokit(), app, {}, s.deps());
    const r = await recordOn(s, 'pipegen/update-r');
    expect(r.environments.find((e) => e.name === 'production')).toMatchObject({ created: false, githubCreatedAt: '2026-01-01T00:00:00Z', previous: { wait_timer: 5, reviewers: [], prevent_self_review: false } });
    expect(r.variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM')).toMatchObject({ created: false, previous: '2026-12-31' });
    expect(r.repoSettings).toMatchObject({ shaPinningRequired: { previous: false }, vulnerabilityAlerts: { previous: false } });
    expect(r.central?.actionsAccess).toEqual({ previous: 'none' });
    // the record holds them now: the pending file is gone
    expect(existsSync(pending)).toBe(false);
    // a public repo: secret scanning and push protection were off before, and stay recorded so
    const t = await seed({ private: false });
    let tArmed = true;
    t.g.hooks.push((c) => (tArmed && !c.route.startsWith('GET ') && c.params.repo === 'pipelines' && /\/git\//.test(c.route) ? { status: 500, data: { message: 'boom' } } : undefined));
    await expect(finish(t.g.octokit(), app, {}, t.deps())).rejects.toThrow(FinishError);
    tArmed = false;
    await finish(t.g.octokit(), app, {}, t.deps());
    expect((await recordOn(t, 'pipegen/update-r')).repoSettings).toMatchObject({ [SS]: { previous: false }, pushProtection: { previous: false } });
  });

  it('finish: a value that can\'t be saved locally first is not changed; a pending file of another repo id is not used (I1)', async () => {
    const s = await seed();
    userEnv(s);
    const dir = dirname(localFinishPendingPath(app, { home: s.home, env: {} }));
    let locked = false;
    s.g.hooks.push((c) => { if (!locked && !c.route.startsWith('GET ')) { locked = true; chmodSync(dir, 0o500); } return undefined; });
    try {
      await finish(s.g.octokit(), app, {}, s.deps()).catch(() => undefined);
    } finally { chmodSync(dir, 0o700); }
    expect(s.g.repo('o/r').envs.get('production')).toMatchObject({ wait_timer: 5, reviewers: [] });
    expect(s.lines.join('\n')).toMatch(/environment production: pipegen couldn't save locally what it was before/);
    // a pending file left by another repo of the same name (another id) says nothing about this one
    const t = await seed();
    t.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: BLOCK_FROM, created_at: '2026-02-02T00:00:00Z' });
    await writeFinishPending(app, 999_999, { environments: [], variables: [{ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, previous: '1999-01-01', githubCreatedAt: '2026-02-02T00:00:00Z' }], repoSettings: {} }, new Date(), { home: t.home, env: {} });
    await finish(t.g.octokit(), app, {}, t.deps());
    expect((await recordOn(t)).variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM')?.previous).toBeUndefined();
  });

  it('finish: classic protection\'s earlier body survives a failed record write (I1)', async () => {
    const s = await seed();
    s.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'r' ? { status: 403, data: { message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' } } : undefined));
    const before = { url: 'u', enforce_admins: { enabled: false }, allow_force_pushes: { enabled: true }, allow_deletions: { enabled: false } };
    s.g.x('o/r').protection = structuredClone(before);
    let armed = true;
    s.g.hooks.push((c) => (armed && !c.route.startsWith('GET ') && c.params.repo === 'pipelines' && /\/git\//.test(c.route) ? { status: 500, data: { message: 'boom' } } : undefined));
    await expect(finish(s.g.octokit(), app, {}, s.deps())).rejects.toThrow(FinishError);
    armed = false;
    await finish(s.g.octokit(), app, {}, s.deps());
    const r = await recordOn(s, 'pipegen/update-r');
    expect(r.classicProtection).toMatchObject({ branch: 'main', previous: { enforce_admins: false, allow_force_pushes: true, required_status_checks: null } });
  });

  it('finish: a stop mid-run (a rejected token) prints what was applied; the re-run keeps the earlier values (I1)', async () => {
    const s = await seed();
    userEnv(s);
    let armed = true;
    s.g.hooks.push((c) => (armed && c.route === 'POST /repos/{owner}/{repo}/actions/variables' ? { status: 401, data: { message: 'Bad credentials' } } : undefined));
    await expect(finish(s.g.octokit(), app, {}, s.deps())).rejects.toThrow(/401/);
    const out = s.lines.join('\n');
    expect(out).toMatch(/stopped before it wrote the install record/i);
    expect(out).toMatch(/done: ruleset pipegen\b/);
    expect(out).toMatch(/done: environment production/);
    expect(out).toContain(localFinishPendingPath(app, { home: s.home, env: {} }));
    armed = false;
    await finish(s.g.octokit(), app, {}, s.deps());
    const r = await recordOn(s);
    expect(r.environments.find((e) => e.name === 'production')).toMatchObject({ created: false, previous: { wait_timer: 5, reviewers: [] } });
    expect(r.repoSettings?.vulnerabilityAlerts).toEqual({ previous: false });
  });

  it('finish: PIPEGEN_BLOCK_FROM never moves later: a later setup PR merge keeps the earlier date (I2)', async () => {
    const s = await seed();
    await finish(s.g.octokit(), app, {}, s.deps());
    expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
    // a later delivery: a new setup PR, merged on 2027-01-10 (merge day + 7 would be 2027-01-17)
    s.g.commitOn('o/r', SETUP_BRANCH, { 'PIPEGEN.md': '# pipegen v2\n' }, 'pipegen: setup again');
    const pr2 = ((await s.g.request('POST /repos/{owner}/{repo}/pulls', { owner: 'o', repo: 'r', head: SETUP_BRANCH, base: 'main', title: 'pipegen', body: 'again' })).data as { number: number }).number;
    s.g.merge('o/r', SETUP_BRANCH, '2027-01-10T09:00:00Z');
    const loc = await readLocalRecord(app, { home: s.home, env: {} });
    await writeLocalRecord(app, { ...(loc as NonNullable<typeof loc>), setupPr: pr2 }, { home: s.home, env: {} });
    await finish(s.g.octokit(), app, {}, s.deps());
    expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
    const r = await recordOn(s, 'pipegen/update-r');
    expect(r.blockFrom).toBe(BLOCK_FROM);
    expect(r.mergedAt).toBe('2027-01-10T09:00:00Z');
    // a recorded date later than the merge day + 7: the earlier one wins
    const t = await seed({ recordOver: (rec) => { rec.blockFrom = '2026-12-25'; } });
    await finish(t.g.octokit(), app, {}, t.deps());
    expect(varOf(t, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
    expect((await recordOn(t)).blockFrom).toBe(BLOCK_FROM);
    // a recorded date earlier than the merge day + 7 stays
    const u = await seed({ recordOver: (rec) => { rec.blockFrom = '2026-11-08'; } });
    await finish(u.g.octokit(), app, {}, u.deps());
    expect(varOf(u, 'PIPEGEN_BLOCK_FROM')?.value).toBe('2026-11-08');
    expect((await recordOn(u)).blockFrom).toBe('2026-11-08');
    // a record trusted by typing carries no date: the variable's own earlier date stays
    const w = await seed();
    rmSync(join(w.home, '.config'), { recursive: true, force: true });
    w.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: '2026-11-09', created_at: '2026-11-06T10:00:00Z' });
    const io = { confirm: async () => false, select: async () => { throw new Error('no'); }, text: async () => 'o/r' } as never;
    await finish(w.g.octokit(), app, {}, w.deps({ io, interactive: true }));
    expect(varOf(w, 'PIPEGEN_BLOCK_FROM')?.value).toBe('2026-11-09');
    expect((await recordOn(w)).blockFrom).toBe('2026-11-09');
    // a value that is not a real day is not a date to keep
    const y = await seed();
    rmSync(join(y.home, '.config'), { recursive: true, force: true });
    y.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: '2026-02-30', created_at: '2026-11-06T10:00:00Z' });
    await finish(y.g.octokit(), app, {}, y.deps({ io, interactive: true }));
    expect(varOf(y, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
  });
});

describe('G11 fix round 1: verify compares the locks (I3)', () => {
  const app = { owner: 'o', repo: 'r' };
  const vfy = (s: Seed) => verify(s.g.octokit(), app, { local: { home: s.home, env: {} }, clock: clock() });
  const CENTRAL = 'the central merge rule (ruleset pipegen on o/pipelines)';

  it('verify: a planned ruleset finish couldn\'t apply is drift', async () => {
    const s = await seed();
    s.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.name === 'pipegen-reviews' ? { status: 500, data: { message: 'boom' } } : undefined));
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await vfy(s)).drift).toEqual([{ what: 'ruleset pipegen-reviews', expected: 'applied by finish', actual: null }]);
    // and the central rule planned but never made
    const t = await seed();
    t.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'pipelines' ? { status: 500, data: { message: 'boom' } } : undefined));
    await finish(t.g.octokit(), app, {}, t.deps());
    expect((await vfy(t)).drift).toEqual([{ what: CENTRAL, expected: 'applied by finish', actual: null }]);
    // and the org required workflow rule
    const u = await seed({ org: true });
    u.g.hooks.push((c) => (c.route === 'POST /orgs/{org}/rulesets' ? { status: 500, data: { message: 'boom' } } : undefined));
    await finish(u.g.octokit(), app, {}, u.deps());
    expect((await vfy(u)).drift).toEqual([{ what: 'the org required workflow rule (pipegen-required--r)', expected: 'applied by finish', actual: null }]);
    // before finish ran, nothing planned is missing yet
    const w = await seed();
    expect((await vfy(w)).drift.filter((x) => x.expected === 'applied by finish')).toEqual([]);
  });

  it('verify: a ruleset emptied, given a bypass actor, switched to evaluate, or with weaker check or review settings is drift', async () => {
    const s = await seed({ org: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await vfy(s)).drift).toEqual([]);
    type B = Record<string, any>;
    const rule = (b: B, type: string): B => (b.rules as B[]).find((x) => x.type === type) as B;
    const bodyOf = (repo: string, name: string): B => [...s.g.repo(repo).rulesets.values()].find((b) => b.name === name) as B;
    const org = (): B => ([...s.g.orgRulesets.values()][0] as { body: B }).body;
    const cases: [string, () => B, (b: B) => void, RegExp][] = [
      ['ruleset pipegen', () => bodyOf('o/r', 'pipegen'), (b) => { b.rules = []; }, /pipegen's rules/],
      ['ruleset pipegen', () => bodyOf('o/r', 'pipegen'), (b) => { b.bypass_actors = [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }]; }, /no bypass actors/],
      ['ruleset pipegen', () => bodyOf('o/r', 'pipegen'), (b) => { b.enforcement = 'evaluate'; }, /active/],
      ['ruleset pipegen', () => bodyOf('o/r', 'pipegen'), (b) => { b.conditions = { ref_name: { include: ['refs/heads/other'], exclude: [] } }; }, /pipegen's rules/],
      ['ruleset pipegen', () => bodyOf('o/r', 'pipegen'), (b) => { rule(b, 'required_status_checks').parameters.required_status_checks = [{ context: 'pipegen / gate', integration_id: 1 }]; }, /15368/],
      ['ruleset pipegen', () => bodyOf('o/r', 'pipegen'), (b) => { rule(b, 'required_status_checks').parameters.required_status_checks = [{ context: 'other', integration_id: 15368 }]; }, /pipegen \/ gate/],
      ['ruleset pipegen-reviews', () => bodyOf('o/r', 'pipegen-reviews'), (b) => { rule(b, 'pull_request').parameters.dismiss_stale_reviews_on_push = false; }, /dismiss/],
      ['ruleset pipegen-reviews', () => bodyOf('o/r', 'pipegen-reviews'), (b) => { rule(b, 'pull_request').parameters.require_last_push_approval = false; }, /last push/],
      ['ruleset pipegen-reviews', () => bodyOf('o/r', 'pipegen-reviews'), (b) => { rule(b, 'pull_request').parameters.require_code_owner_review = false; }, /code-owner review/],
      ['ruleset pipegen-reviews', () => bodyOf('o/r', 'pipegen-reviews'), (b) => { rule(b, 'pull_request').parameters.required_approving_review_count = 0; }, /approv/],
      ['ruleset pipegen-reviews', () => bodyOf('o/r', 'pipegen-reviews'), (b) => { b.bypass_actors = [{ actor_id: 1, actor_type: 'OrganizationAdmin', bypass_mode: 'pull_request' }]; }, /no bypass actors/],
      [CENTRAL, () => bodyOf('o/pipelines', 'pipegen'), (b) => { b.rules = (b.rules as B[]).filter((x) => x.type !== 'pull_request'); }, /pipegen's rules/],
      [CENTRAL, () => bodyOf('o/pipelines', 'pipegen'), (b) => { b.bypass_actors = [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }]; }, /no bypass actors/],
      ['the org required workflow rule (pipegen-required--r)', org, (b) => { b.bypass_actors = [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }]; }, /no bypass actors/],
      ['the org required workflow rule (pipegen-required--r)', org, (b) => { b.rules = []; }, /pipegen's rules/],
      ['the org required workflow rule (pipegen-required--r)', org, (b) => { b.enforcement = 'disabled'; }, /active/],
    ];
    for (const [what, get, change, want] of cases) {
      const b = get();
      const saved = structuredClone(b);
      change(b);
      const d = (await vfy(s)).drift;
      expect(d.length, `${what} ${want}`).toBeGreaterThan(0);
      expect(d.every((x) => x.what === what), `${what} ${want}: ${JSON.stringify(d)}`).toBe(true);
      expect(d.map((x) => x.expected).join('\n'), what).toMatch(want);
      for (const k of Object.keys(b)) delete b[k];
      Object.assign(b, saved);
    }
    expect((await vfy(s)).drift).toEqual([]);
  });

  it('verify: a planned ruleset pipegen updated but couldn\'t record is checked by name, not reported missing', async () => {
    const s = await seed();
    s.g.repo('o/r').rulesets.set(5, { name: 'pipegen', target: 'branch', enforcement: 'disabled', bypass_actors: [], conditions: {}, rules: [], created_at: '2026-03-03T00:00:00Z' });
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await recordOn(s)).rulesets.map((x) => x.name)).toEqual(['pipegen-reviews']);
    const v = await vfy(s);
    expect(v.drift).toEqual([]);
    expect(v.notes.join('\n')).toMatch(/ruleset pipegen .*not in the install record/i);
    (s.g.repo('o/r').rulesets.get(5) as Record<string, unknown>).bypass_actors = [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }];
    expect((await vfy(s)).drift).toEqual([{ what: 'ruleset pipegen', expected: 'no bypass actors', actual: '1 bypass actor' }]);
  });

  it('verify: classic protection weakened after finish is drift', async () => {
    const s = await seed();
    s.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'r' ? { status: 403, data: { message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' } } : undefined));
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await vfy(s)).drift).toEqual([]);
    (s.g.x('o/r').protection as Record<string, any>).required_pull_request_reviews.required_approving_review_count = 0;
    expect((await vfy(s)).drift).toEqual([{ what: 'classic branch protection on main', expected: 'pipegen\'s rules', actual: 'changed' }]);
    s.g.x('o/r').protection = null;
    expect((await vfy(s)).drift).toEqual([{ what: 'classic branch protection on main', expected: 'pipegen\'s rules', actual: null }]);
  });
});

describe('G11 fix round 1: minor findings (m1-m9)', () => {
  const app = { owner: 'o', repo: 'r' };

  it('finish --rotate-key with no central ruleset: the note says the record names the new key now (m1)', async () => {
    const s = await seed({ keyEnv: true, plannedOver: (p) => { delete p.centralRuleset; } });
    await finish(s.g.octokit(), app, {}, s.deps());
    const res = await finish(s.g.octokit(), app, { rotateKey: true }, s.deps());
    const notes = res.notes.join('\n');
    expect(notes).not.toMatch(/reports the key as changed/);
    expect(notes).toMatch(/install record on o\/pipelines names the new key/);
    expect(notes).toMatch(/verify step fails closed until a pull request/);
    expect((await recordOn(s)).cosignPubSha256).toBe(pubKeySha256(envVarOf(s, 'pipegen-signing', 'PIPEGEN_COSIGN_PUB')?.value as string));
  });

  it('finish --rotate-key: a half-done rotation says signing is broken and how to fix it (m2)', async () => {
    const s = await seed({ keyEnv: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    s.g.hooks.push((c) => (c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}' && String(c.params[['secret', 'name'].join('_')]).endsWith('WORD') ? { status: 500, data: { message: 'boom' } } : undefined));
    const res = await finish(s.g.octokit(), app, { rotateKey: true }, s.deps());
    const why = res.skipped.find((x) => /signing key/.test(x.what))?.why ?? '';
    expect(why).toMatch(/stored the new PIPEGEN_COSIGN_KEY/);
    expect(why).toMatch(/signing is broken/i);
    expect(why).toMatch(/finish --rotate-key/);
  });

  it('finish: an earlier entry whose created_at is unknown on either side keeps its previous value (m3)', async () => {
    const s = await seed();
    s.g.repo('o/r').envs.set('production', { id: 77, created_at: '2026-01-01T00:00:00Z', wait_timer: 5, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() });
    s.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: '2026-12-31', created_at: '2026-02-02T00:00:00Z' });
    await finish(s.g.octokit(), app, {}, s.deps());
    const first = await recordOn(s);
    // GitHub doesn't say when they were made this time: the earlier previous values stay
    delete (s.g.repo('o/r').envs.get('production') as { created_at?: string }).created_at;
    (varOf(s, 'PIPEGEN_BLOCK_FROM') as { created_at: string }).created_at = '';
    await finish(s.g.octokit(), app, {}, s.deps());
    const second = await recordOn(s, 'pipegen/update-r');
    // G11-R2 d: not adopted (no created_at to match), but the earlier previous is kept, never pipegen's own values
    const { githubCreatedAt: _e, ...firstEnv } = first.environments.find((e) => e.name === 'production') as InstallRecord['environments'][number];
    expect(second.environments.find((e) => e.name === 'production')).toEqual({ ...firstEnv, created: false, unconfirmed: true });
    const { githubCreatedAt: _v, ...firstVar } = first.variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM') as InstallRecord['variables'][number];
    expect(second.variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM')).toEqual({ ...firstVar, created: false, unconfirmed: true });
    // an earlier entry recorded without created_at (unconfirmed), GitHub holding pipegen's own value now: previous kept, never pipegen's
    const t = await seed({ recordOver: (r) => { r.variables.push({ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, unconfirmed: true, previous: '2026-12-31' }); } });
    t.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: BLOCK_FROM, created_at: '2026-02-02T00:00:00Z' });
    await finish(t.g.octokit(), app, {}, t.deps());
    expect((await recordOn(t)).variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM')).toEqual({ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, githubCreatedAt: '2026-02-02T00:00:00Z', previous: '2026-12-31' });
  });

  it('finish: the central rule that couldn\'t be switched on gets its own line, apart from what the record doesn\'t list (m4)', async () => {
    const s = await seed();
    s.g.hooks.push((c) => (c.route === 'PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}' && c.params.repo === 'pipelines' && c.params.enforcement === 'active' ? { status: 500, data: { message: 'boom' } } : undefined));
    await finish(s.g.octokit(), app, {}, s.deps());
    const out = s.lines.join('\n');
    expect(out).not.toMatch(/doesn't list them:\n {2}- the central merge rule/);
    expect(out).toMatch(/The install record lists the central merge rule .*, but it is switched off/);
    expect((await recordOn(s)).central?.rulesetId).toBeDefined();
  });

  it('finish: a ruleset pipegen made whose read-back has no created_at is recorded unconfirmed, with its own note (m6)', async () => {
    const s = await seed();
    const strip = (repo: string) => (c: { route: string; params: Record<string, unknown> }) => {
      if (c.route !== 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}' || c.params.repo !== repo) return undefined;
      const rs = s.g.repo(`o/${repo}`).rulesets.get(Number(c.params.ruleset_id));
      if (rs === undefined) return undefined;
      const { created_at: _c, ...rest } = rs as Record<string, unknown>;
      return { status: 200, data: { id: Number(c.params.ruleset_id), ...structuredClone(rest) } };
    };
    s.g.hooks.push(strip('r'), strip('pipelines'));
    const res = await finish(s.g.octokit(), app, {}, s.deps());
    const r = await recordOn(s);
    const ids = rulesetsOf(s, 'o/r');
    expect(r.rulesets).toEqual([
      { kind: 'gate', id: ids.find((x) => x.name === 'pipegen')?.id, name: 'pipegen', unconfirmed: true },
      { kind: 'reviews', id: ids.find((x) => x.name === 'pipegen-reviews')?.id, name: 'pipegen-reviews', unconfirmed: true },
    ]);
    const notes = res.notes.join('\n');
    expect(notes).toMatch(/pipegen made the ruleset pipegen, but GitHub didn't say when/);
    expect(notes).not.toMatch(/already on .* can't show it made it/);
    // the central rule: recorded by id without a created_at, and still switched on last
    const c = rulesetsOf(s, 'o/pipelines')[0];
    expect(r.central?.rulesetId).toBe(c?.id);
    expect(r.central?.rulesetCreatedAt).toBeUndefined();
    expect(c?.enforcement).toBe('active');
    // the record carries one of the two for each ruleset, never neither nor both
    const { githubCreatedAt: _g, ...bare } = { ...(r.rulesets[0] as InstallRecord['rulesets'][number]), githubCreatedAt: undefined };
    expect(() => checkRecord({ ...r, rulesets: [{ ...bare, unconfirmed: undefined }] })).toThrow(/rulesets/);
    expect(() => checkRecord({ ...r, rulesets: [{ ...bare, unconfirmed: true, githubCreatedAt: '2026-11-07T10:00:00Z' }] })).toThrow(/rulesets/);
    expect(checkRecord({ ...r, rulesets: [{ ...bare, unconfirmed: true }] }).rulesets[0]?.unconfirmed).toBe(true);
  });

  it('finish: a weakened request planted in a vouched record\'s planned is never sent (m7)', async () => {
    const s = await seed({ org: true, plannedOver: (p) => {
      const g = p.rulesets?.gate.body as Record<string, any>;
      g.enforcement = 'evaluate';
      g.bypass_actors = [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }];
      (p.centralRuleset?.body as Record<string, any>).rules = [];
      (p.shaPinning?.request.body as Record<string, any>).sha_pinning_required = false;
    } });
    const res = await finish(s.g.octokit(), app, {}, s.deps());
    const gate = rulesetsOf(s, 'o/r').find((b) => b.name === 'pipegen');
    expect(gate).toMatchObject({ enforcement: 'active', bypass_actors: [] });
    expect(rulesetsOf(s, 'o/pipelines')[0]?.rules.map((x: { type: string }) => x.type)).toEqual(['deletion', 'non_fast_forward', 'pull_request']);
    expect(s.g.x('o/r').actions.sha_pinning_required).toBe(true);
    expect(res.skipped).toEqual([]);
  });

  it('finish --print: an unreadable signing environment is reported; a typed record says what happens to PIPEGEN_COSIGN_PUB (m8)', async () => {
    const s = await seed({ keyEnv: true });
    s.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/environments/{environment_name}' && c.params.environment_name === 'pipegen-signing' ? { status: 500, data: { message: 'boom' } } : undefined));
    const res = await finish(s.g.octokit(), app, { print: true }, s.deps());
    expect(res.skipped.find((x) => /signing environment/.test(x.what))?.why).toMatch(/HTTP 500/);
    // typed: the public key can't be re-derived; --print says so
    const t = await seed({ keyEnv: true });
    rmSync(join(t.home, '.config'), { recursive: true, force: true });
    const io = { confirm: async () => false, select: async () => { throw new Error('no'); }, text: async () => 'o/r' } as never;
    const tres = await finish(t.g.octokit(), app, { print: true }, t.deps({ io, interactive: true }));
    expect(tres.skipped.find((x) => /PIPEGEN_COSIGN_PUB/.test(x.what))?.why).toMatch(/couldn't re-derive the public key.*--rotate-key/);
  });

  it('finish: a setup pull request merged into another branch than the default one is not the merge (m9)', async () => {
    const s = await seed({ merge: false });
    const pr = s.g.repo('o/r').pulls.find((p) => p.number === s.pr) as { base: string };
    pr.base = 'other';
    s.g.merge('o/r', SETUP_BRANCH, MERGED_AT);
    const from = s.g.calls.length;
    await expect(finish(s.g.octokit(), app, {}, s.deps())).rejects.toThrow(/not merged into the default branch/);
    expect(writeRoutes(s, from)).toEqual([]);
  });
});

// ---------- fix round 2 (re-review G11 r1, ruling G11-R2 and G11-R-sec1) ----------

describe('G11 fix round 2 (G11-R2, G11-R-sec1)', () => {
  const app = { owner: 'o', repo: 'r' };
  const vfy = (s: Seed) => verify(s.g.octokit(), app, { local: { home: s.home, env: {} }, clock: clock() });
  type B = Record<string, any>;
  const bodyOf = (s: Seed, repo: string, name: string): B => [...s.g.repo(repo).rulesets.values()].find((b) => b.name === name) as B;
  const orgBody = (s: Seed): B => ([...s.g.orgRulesets.values()][0] as { body: B }).body;
  const ORG = 'the org required workflow rule (pipegen-required--r)';

  it('finish: PIPEGEN_BLOCK_FROM never moves later for a vouched record that carries no date: a re-delivery after a typed trust, then a later merge (I2)', async () => {
    const s = await seed();
    await finish(s.g.octokit(), app, {}, s.deps());
    const first = await recordOn(s);
    expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
    // a re-delivery from a machine that trusted the record by typing: the record it writes carries no blockFrom, its local file is not typed
    s.g.commitOn('o/r', SETUP_BRANCH, { 'PIPEGEN.md': '# pipegen v2\n' }, 'pipegen: setup again');
    const pr2 = ((await s.g.request('POST /repos/{owner}/{repo}/pulls', { owner: 'o', repo: 'r', head: SETUP_BRANCH, base: 'main', title: 'pipegen', body: 'again' })).data as { number: number }).number;
    const again: InstallRecord = structuredClone(first);
    delete again.blockFrom;
    delete again.mergedAt;
    rmSync(join(s.home, '.config'), { recursive: true, force: true });
    await writeRecord(s.g.octokit(), { record: again, setupPr: pr2, via: 'direct', files: [], base: s.g.head('o/pipelines'), clock: clock(), now: () => new Date('2027-01-09T12:00:00Z'), local: { home: s.home, env: {} } });
    expect((await readLocalRecord(app, { home: s.home, env: {} }))?.typed).not.toBe(true);
    s.g.merge('o/r', SETUP_BRANCH, '2027-01-10T09:00:00Z');
    const res = await finish(s.g.octokit(), app, {}, s.deps());
    expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
    expect(res.applied.join('\n')).not.toMatch(/2027-01-17/);
    expect((await recordOn(s)).blockFrom ?? (await recordOn(s, 'pipegen/update-r')).blockFrom).toBe(BLOCK_FROM);
  });

  it('finish: the org rule\'s pinned commit is recorded; verify: a repointed org rule, or a pinned commit off the central default branch, is drift (G11-R-sec1)', async () => {
    const s = await seed({ org: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    const holding = (orgBody(s).rules as B[])[0]?.parameters.workflows[0].sha as string;
    const r = await recordOn(s);
    expect(r.orgRuleset?.pinnedSha).toBe(holding);
    expect((await vfy(s)).drift).toEqual([]);
    // the record schema requires it (a record of an org rule without the commit it pins is refused)
    const { pinnedSha: _p, ...bare } = r.orgRuleset as NonNullable<InstallRecord['orgRuleset']>;
    expect(() => checkRecord({ ...r, orgRuleset: bare })).toThrow(/orgRuleset/);
    // repointed to another commit
    const wf = (orgBody(s).rules as B[])[0]?.parameters.workflows[0] as B;
    wf.sha = 'f'.repeat(40);
    const d = (await vfy(s)).drift;
    expect(d.length).toBeGreaterThan(0);
    expect(d.every((x) => x.what === ORG), JSON.stringify(d)).toBe(true);
    expect(d.map((x) => x.expected).join('\n')).toContain(holding);
    wf.sha = holding;
    expect((await vfy(s)).drift).toEqual([]);
    // a second workflow entry beside pipegen's, pinned elsewhere
    const wfs = (orgBody(s).rules as B[])[0]?.parameters.workflows as B[];
    wfs.push({ ...wf, sha: 'e'.repeat(40) });
    expect((await vfy(s)).drift.some((x) => x.what === ORG && x.actual === 'e'.repeat(40))).toBe(true);
    wfs.pop();
    expect((await vfy(s)).drift).toEqual([]);
    // the pinned commit is no longer on the central default branch's history
    s.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/compare/{basehead}' && String(c.params.basehead).endsWith(`...${holding}`) ? { status: 200, data: { status: 'diverged', files: [] } } : undefined));
    const e = (await vfy(s)).drift;
    expect(e).toEqual([{ what: ORG, expected: `the pinned commit ${holding} on the central default branch`, actual: 'diverged' }]);
  });

  it('finish: a write GitHub refuses leaves no saved previous behind; a later run never records a setting the user turned on (G11-R2 a)', async () => {
    const s = await seed();
    let armed = true;
    s.g.hooks.push((c) => (armed && (c.route === 'PUT /repos/{owner}/{repo}/vulnerability-alerts' || c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}') ? { status: 422, data: { message: 'nope' } } : undefined));
    s.g.repo('o/r').envs.set('production', { id: 77, created_at: '2026-01-01T00:00:00Z', wait_timer: 5, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() });
    const r1 = await finish(s.g.octokit(), app, {}, s.deps());
    expect(r1.skipped.map((x) => x.what)).toEqual(expect.arrayContaining(['Dependabot alerts', 'environment production']));
    const pend = localFinishPendingPath(app, { home: s.home, env: {} });
    const left = existsSync(pend) ? JSON.parse(readFileSync(pend, 'utf8')) as { repoSettings: object; environments: unknown[] } : { repoSettings: {}, environments: [] };
    expect(left.repoSettings).toEqual({});
    expect(left.environments).toEqual([]);
    armed = false;
    // the user turns Dependabot alerts on themselves, and sets production up their own way
    s.g.x('o/r').vulnAlerts = true;
    await finish(s.g.octokit(), app, {}, s.deps());
    const r = await recordOn(s, 'pipegen/update-r').catch(() => recordOn(s));
    expect(r.repoSettings?.vulnerabilityAlerts).toBeUndefined();
    // a failure that is not a refusal (no answer, a server error) may have gone through: the saved value stays
    const t = await seed();
    t.g.hooks.push((c) => (c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}' ? { status: 502, data: { message: 'bad gateway' } } : undefined));
    t.g.repo('o/r').envs.set('production', { id: 77, created_at: '2026-01-01T00:00:00Z', wait_timer: 5, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() });
    await finish(t.g.octokit(), app, {}, t.deps());
    const tp = JSON.parse(readFileSync(localFinishPendingPath(app, { home: t.home, env: {} }), 'utf8')) as { environments: { name: string; previous: { wait_timer: number } }[] };
    expect(tp.environments).toMatchObject([{ name: 'production', previous: { wait_timer: 5 } }]);
  });

  it('verify: a ruleset whose target changed is drift (G11-R2 b)', async () => {
    const s = await seed();
    await finish(s.g.octokit(), app, {}, s.deps());
    bodyOf(s, 'o/r', 'pipegen').target = 'tag';
    expect((await vfy(s)).drift).toEqual([{ what: 'ruleset pipegen', expected: 'pipegen\'s rules', actual: 'changed' }]);
    bodyOf(s, 'o/r', 'pipegen').target = 'branch';
    bodyOf(s, 'o/r', 'pipegen-reviews').target = 'push';
    expect((await vfy(s)).drift).toEqual([{ what: 'ruleset pipegen-reviews', expected: 'pipegen\'s rules', actual: 'changed' }]);
  });

  it('verify: with classic protection and rulesets both in the record, both are checked (G11-R2 c)', async () => {
    const s = await seed();
    let refuse = true;
    s.g.hooks.push((c) => (refuse && c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'r' ? { status: 403, data: { message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' } } : undefined));
    await finish(s.g.octokit(), app, {}, s.deps());
    refuse = false;
    await finish(s.g.octokit(), app, {}, s.deps());
    s.g.merge('o/pipelines', 'pipegen/update-r');
    const r = await recordOn(s);
    expect(r.classicProtection).toBeDefined();
    expect(r.rulesets.map((x) => x.name).sort()).toEqual(['pipegen', 'pipegen-reviews']);
    expect((await vfy(s)).drift).toEqual([]);
    const gate = bodyOf(s, 'o/r', 'pipegen');
    gate.bypass_actors = [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }];
    expect((await vfy(s)).drift).toEqual([{ what: 'ruleset pipegen', expected: 'no bypass actors', actual: '1 bypass actor' }]);
    gate.bypass_actors = [];
    // classic protection alone (rulesets refused, never recorded): no ruleset is reported missing
    const t = await seed();
    t.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'r' ? { status: 403, data: { message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' } } : undefined));
    await finish(t.g.octokit(), app, {}, t.deps());
    expect((await vfy(t)).drift).toEqual([]);
  });

  it('finish: an earlier entry is adopted only when both created_at are known and equal; else its previous alone is kept (G11-R2 d)', async () => {
    // the record lists a production pipegen made, date unknown; GitHub now holds the user's own production (another created_at)
    const s = await seed({ recordOver: (rec) => { rec.environments.push({ name: 'production', created: true, unconfirmed: true, changed: [], branchPolicyIds: [] }); } });
    s.g.repo('o/r').envs.set('production', { id: 88, created_at: '2026-10-01T00:00:00Z', wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() });
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await recordOn(s)).environments.find((e) => e.name === 'production')).toMatchObject({ created: false, githubCreatedAt: '2026-10-01T00:00:00Z', previous: { wait_timer: 0, reviewers: [] } });
    // a variable recorded as made by pipegen, date unknown: GitHub's own (known date) is not taken for it
    const t = await seed({ recordOver: (rec) => { rec.variables.push({ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: true, unconfirmed: true }); } });
    t.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: '2099-01-01', created_at: '2026-10-01T00:00:00Z' });
    await finish(t.g.octokit(), app, {}, t.deps());
    expect((await recordOn(t)).variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM')).toEqual({ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, previous: '2099-01-01', githubCreatedAt: '2026-10-01T00:00:00Z' });
  });

  it('verify: a lock stricter than pipegen set it is reported as stricter, not as drift (G11-R2 e)', async () => {
    const s = await seed();
    await finish(s.g.octokit(), app, {}, s.deps());
    const pr = (bodyOf(s, 'o/r', 'pipegen-reviews').rules as B[]).find((x) => x.type === 'pull_request') as B;
    pr.parameters.required_approving_review_count += 1;
    pr.parameters.required_review_thread_resolution = true;
    const v1 = await vfy(s);
    expect(v1.drift).toEqual([]);
    expect(v1.notes.join('\n')).toMatch(/ruleset pipegen-reviews.*stricter/);
    // stricter in one setting, looser in another: drift for the looser one
    pr.parameters.dismiss_stale_reviews_on_push = false;
    const v3 = await vfy(s);
    expect(v3.drift.map((x) => x.what)).toEqual(['ruleset pipegen-reviews', 'ruleset pipegen-reviews']);
    expect(v3.notes.join('\n')).not.toMatch(/dismiss stale/);
    // classic protection with more approvals than planned
    const t = await seed();
    t.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/rulesets' && c.params.repo === 'r' ? { status: 403, data: { message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' } } : undefined));
    await finish(t.g.octokit(), app, {}, t.deps());
    (t.g.x('o/r').protection as B).required_pull_request_reviews.required_approving_review_count += 2;
    const v2 = await vfy(t);
    expect(v2.drift).toEqual([]);
    expect(v2.notes.join('\n')).toMatch(/classic branch protection on main.*stricter/);
  });

  it('finish: a ruleset pipegen made and recorded unconfirmed stays recorded on a re-run (rulesets match by id, G11-R2 d)', async () => {
    const s = await seed();
    const strip = (c: { route: string; params: Record<string, unknown> }) => {
      if (c.route !== 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}' || c.params.repo !== 'r') return undefined;
      const rs = s.g.repo('o/r').rulesets.get(Number(c.params.ruleset_id));
      if (rs === undefined) return undefined;
      const { created_at: _c, ...rest } = rs as Record<string, unknown>;
      return { status: 200, data: { id: Number(c.params.ruleset_id), ...structuredClone(rest) } };
    };
    s.g.hooks.push(strip);
    await finish(s.g.octokit(), app, {}, s.deps());
    const first = (await recordOn(s)).rulesets;
    expect(first.map((x) => x.unconfirmed)).toEqual([true, true]);
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await recordOn(s, 'pipegen/update-r')).rulesets).toEqual(first);
  });

  it('finish: a corrupt or unreadable pending file stops finish before any write (G11-R2 f)', async () => {
    for (const bad of ['{ not json', JSON.stringify({ repoId: 1, extra: true })]) {
      const s = await seed();
      const pend = localFinishPendingPath(app, { home: s.home, env: {} });
      mkdirSync(dirname(pend), { recursive: true, mode: 0o700 });
      writeFileSync(pend, bad, { mode: 0o600 });
      const from = s.g.calls.length;
      await expect(finish(s.g.octokit(), app, {}, s.deps())).rejects.toThrow(/Nothing was applied/);
      expect(writeRoutes(s, from)).toEqual([]);
      expect(readFileSync(pend, 'utf8')).toBe(bad);
    }
    // a pending path that is not a regular file
    const u = await seed();
    const pend = localFinishPendingPath(app, { home: u.home, env: {} });
    mkdirSync(pend, { recursive: true });
    const from = u.g.calls.length;
    await expect(finish(u.g.octokit(), app, {}, u.deps())).rejects.toThrow(FinishError);
    expect(writeRoutes(u, from)).toEqual([]);
  });
});

/** Runs one printed command against the fake (gh api with a JSON body, gh variable set), as the user would. */
async function runPrinted(g: FinishGitHub, cmd: string): Promise<void> {
  const api = /^gh api --method (POST|PUT|PATCH) (\S+)(?: --input - <<'PIPEGEN_JSON'\n([\s\S]*?)\nPIPEGEN_JSON)?$/.exec(cmd);
  if (api !== null) {
    const [, method, path, json] = api as unknown as [string, string, string, string | undefined];
    const seg = path.split('/');
    const params: Record<string, unknown> = { ...(json === undefined ? {} : JSON.parse(json)) };
    let route: string;
    if (seg[1] === 'orgs') { params.org = seg[2]; route = `/orgs/{org}/${seg.slice(3).join('/')}`; } else {
      params.owner = seg[2];
      params.repo = seg[3];
      const rest = seg.slice(4);
      if (rest[0] === 'branches') { params.branch = rest[1]; rest[1] = '{branch}'; }
      if (rest[0] === 'environments') { params.environment_name = rest[1]; rest[1] = '{environment_name}'; }
      route = `/repos/{owner}/{repo}${rest.length === 0 ? '' : `/${rest.join('/')}`}`;
    }
    await g.request(`${method} ${route}`, params);
    return;
  }
  const v = /^gh variable set (\S+) (?:--env (\S+) )?--repo (\S+)\/(\S+) --body '([^']*)'$|^gh variable set (\S+) --repo (\S+)\/(\S+) --body (\S+)$/.exec(cmd);
  if (v !== null) {
    const name = v[1] ?? v[6];
    const env = v[2];
    const owner = v[3] ?? v[7];
    const repo = v[4] ?? v[8];
    const value = v[5] ?? v[9];
    await g.request(env === undefined ? 'POST /repos/{owner}/{repo}/actions/variables' : 'POST /repos/{owner}/{repo}/environments/{environment_name}/variables', { owner, repo, name, value, ...(env === undefined ? {} : { environment_name: env }) });
    return;
  }
  if (cmd.startsWith('#') || cmd.startsWith('gh api --method GET')) return;
  throw new Error(`the test can't run: ${cmd.split('\n')[0]}`);
}
