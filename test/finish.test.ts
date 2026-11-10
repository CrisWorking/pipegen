// v0.2 Plan G G11 (plan Task 7 "finish" and "verify"; rulings S10, S11, S13, S18, S24; rows S-7, P-7, G26, G29; Plan V pre-flight §5 G11
// items 1-5; G8 carries; G10 carries and rulings G10-R1, G10-R4, G10-R5): after the setup pull request is merged, `pipegen finish` applies
// the merge locks, the environments, the signing environment's key and PIPEGEN_COSIGN_PUB, PIPEGEN_BLOCK_FROM, sha pinning, then the central
// ruleset and CODEOWNERS last, and updates the install record; `pipegen verify` reports drift between the repos and the record. Every GitHub
// call goes to an in-memory GitHub (test/helpers/finish-github.ts); cosign is a fake exec; no network.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { gitBlobSha } from '../src/create/guard.js';
import { storeCosignKey, storeEnvSecret } from '../src/create/secrets.js';
import { centralWorkflowFile } from '../src/engine/central-path.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { pubKeySha256 } from '../src/engine/signing.js';
import { ensureSigningEnvironment, plannedOfLocks, readEnv, SETUP_BRANCH } from '../src/deliver/deliver.js';
import { earliestBlockFrom, finish, FinishError, FINISH_WRITE_ROUTES, githubFinishProbe, type FinishDeps, type FinishProbe } from '../src/deliver/finish.js';
import { checkRecord, protectedPathsForRecord, recordFileText, recordPath, localFinishPendingPath, localRecordPath, readLocalRecord, readRecord, recordHash, recordMarkerOf, writeFinishPending, writeLocalRecord, writeRecord } from '../src/deliver/record.js';
import { SettingsApi } from '../src/deliver/settings-api.js';
import { verify } from '../src/deliver/verify.js';
import { isMemoryFolder } from '../src/layers/deploy.js';
import { planLocks, type LockPlan } from '../src/layers/locks.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, InstallPlanned, InstallRecord, Plan, RepoProfile } from '../src/types.js';
import { cosignKey, cosignPub, envelope } from './helpers/cosign-keys.js';
import { FinishGitHub } from './helpers/finish-github.js';
import { hostname } from 'node:os';
import { update, UpdateError } from '../src/deliver/update.js';
import { StateStore } from '../src/proof/state.js';
import { runExitHooks } from '../src/util/exit-hooks.js';

// ---------- fixtures ----------

const PROTECTED = ['.github/workflows/**', 'CODEOWNERS'];
const CO_ORIG = '* @someone\n';
const MERGE = 'on: { workflow_call: {} }\njobs: { gate: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] } }\n';
const CAPS: Capabilities = { branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: true, attestations: false, codeScanning: true, keylessSigningAllowed: false };
const MERGED_AT = '2026-11-06T09:30:00Z';
const BLOCK_FROM = '2026-11-13';
const PUB = cosignPub(3);
const PW_NAME = ['PIPEGEN_COSIGN', 'PASS' + 'WORD'].join('_');
const KNOWN_PW = 'Zq9Kd7LmZq9Kd7LmZq9Kd7LmZq9Kd7LmZq9Kd7LmZq9K';   // 44 characters, the fake base64's output
const PW_VAR = ['COSIGN', 'PASS' + 'WORD'].join('_');   // built at runtime: a redact pattern reads `NAME="…"` as a value
/** G17-R4 (sec C1): the key-pair commands finish --print gives (app o/r), one subshell block a failure ends. */
const KEY_BLOCK = [
  '(',
  '  set -eu +x',
  '  umask 077',
  '  d="$(mktemp -d -p /dev/shm)"',
  '  trap \'rm -rf -- "$d"\' EXIT',
  '  trap \'exit 130\' HUP INT TERM',
  '  test -d "$d"',
  '  case "$(stat -f -c %T "$d")" in tmpfs|ramfs) ;; *) exit 1 ;; esac',
  '  cd "$d"',
  `  ${PW_VAR}="$(head -c 32 /dev/urandom | base64 | tr -d '\\n')"; export ${PW_VAR}`,
  '  test "${#COSIGN_PASSWORD}" -eq 44',
  '  cosign generate-key-pair --output-key-prefix pipegen-signing',
  '  gh secret set PIPEGEN_COSIGN_KEY --env pipegen-signing --repo o/r < pipegen-signing.key',
  `  printf '%s' "$COSIGN_PASSWORD" | gh secret set ${PW_NAME} --env pipegen-signing --repo o/r`,
  '  gh variable set PIPEGEN_COSIGN_PUB --env pipegen-signing --repo o/r < pipegen-signing.pub',
  ')',
].join('\n');
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
  deps: (over?: Partial<FinishDeps>) => FinishDeps; caps: { value: Capabilities }; plan: { value: Plan }; shm: string;
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
    version: '0.2.0',   // PL-D1-R1: the version of the record below (not the package's 0.1.0): finish plans the required workflow again with the record's version, so the central file's sha still matches
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
  // G13 (carry 28): finish makes the key pair with generateCosignKeys, only in a memory folder; the tests name a folder they treat as one
  const shm = join(home, 'shm');
  mkdirSync(shm);
  const deps = (over: Partial<FinishDeps> = {}): FinishDeps => ({
    out: (l) => { lines.push(l); }, probe, clock: clock(), now: () => new Date('2026-11-07T10:00:00Z'), local: { home, env: {} },
    keyBase: shm, isMemory: (d) => d === shm,
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
  return { g, home, shm, record, pin, pr, locks, lines, probes, resolves, execs, deps, caps, plan };
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
    // G-FINREC: recorded as one edit chained from null (never a files entry), so uninstall can prove it is pipegen's whole file
    const made = s.g.filesAt('o/pipelines', s.g.head('o/pipelines')).get('.github/CODEOWNERS') as string;
    expect(r.files.find((f) => f.repo === 'central' && f.path === '.github/CODEOWNERS')).toBeUndefined();
    expect(r.edits.filter((e) => e.repo === 'central' && e.path === '.github/CODEOWNERS')).toEqual([{ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: made, originalSha: null, writtenShas: [gitBlobSha(made)], baseShas: [null] }]);

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
    expect(text).toMatch(new RegExp(`\\| gh secret set ${PW_NAME} --env pipegen-signing --repo o/r$`, 'm'));   // G17 row 45: from COSIGN_PASSWORD
    expect(s.lines.join('\n')).toContain('gh api --method POST /repos/o/r/rulesets');
    // no value of any kind: no key was made, cosign never ran, no key or password text anywhere
    expect(s.resolves).toEqual([]);
    expect(s.execs).toEqual([]);
    // G17 row 45: COSIGN_PASSWORD is set only from a command substitution (random bytes), never a value
    expect(`${text}\n${s.lines.join('\n')}`).not.toMatch(new RegExp(['ENCRYPTED', `${['COSIGN', 'PASS' + 'WORD='].join('_')}(?!"\\$\\(head -c 32 /dev/urandom)`].join('|')));
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

  it('G-COCASE-R3 N1: finish whose record waits in the central pull request: verify says to merge it, else run finish', async () => {
    const s = await seed();
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, { print: true }, s.deps());
    for (const cmd of res.commands ?? []) await runPrinted(s.g, cmd);
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    // the central ruleset is on, so the record went to the central pull request; the default branch still holds no merge
    expect((await recordOn(s, 'pipegen/update-r')).mergedAt).toBeDefined();
    expect((await recordOn(s)).mergedAt).toBeUndefined();
    const v = await verify(s.g.octokit(), { owner: 'o', repo: 'r' }, { local: { home: s.home, env: {} } });
    const d = v.drift.filter((x) => /finish has not completed/.test(String(x.actual)));
    expect(d).toHaveLength(1);
    expect(d[0]?.actual).toBe('finish has not completed, or the install record it wrote waits in the central pull request `pipegen/update-r`: merge it, else run `npx pipegen finish`');
    // merged: the record names the merge, no such drift
    s.g.merge('o/pipelines', 'pipegen/update-r');
    const v2 = await verify(s.g.octokit(), { owner: 'o', repo: 'r' }, { local: { home: s.home, env: {} } });
    expect(v2.drift.filter((x) => /finish has not completed/.test(String(x.actual)))).toEqual([]);
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
    // G13-R2 6: the way to open that pull request is the full run, never the bare audit
    expect(s.lines.join('\n')).toMatch(/run `npx pipegen run` again to open it/);
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

describe('G13 finish: the key pair only in memory (carry 28, BINDING)', () => {
  /** A folder on a disk: the repo's own folder when the OS temp folder is a tmpfs. */
  const diskFolder = (): string => {
    for (const base of [tmpdir(), resolve(import.meta.dirname, '..')]) {
      if (isMemoryFolder(base)) continue;
      const d = mkdtempSync(join(base, '.pg-disk-'));
      homes.push(d);
      return d;
    }
    throw new Error('no disk-backed folder to test with');
  };

  it('finish: the cosign key is made in memory; no key file on a disk-backed folder', async () => {
    const s = await seed({ keyEnv: true, keysStored: false });
    const disk = diskFolder();
    // the real memory check (no isMemory override) on a folder that is on a disk: refused before cosign runs
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps({ keyBase: disk, isMemory: undefined }));
    expect(s.execs).toEqual([]);
    expect(s.resolves).toEqual([]);
    expect(readdirSync(disk)).toEqual([]);
    const why = res.skipped.find((x) => /signing key/.test(x.what))?.why ?? '';
    expect(why).toMatch(/only in memory/);
    expect(why).toMatch(/keyless signing/);
    expect(why).not.toMatch(/npx pipegen finish/);
    expect(s.g.repo('o/r').envs.get('pipegen-signing')?.stored.has('PIPEGEN_COSIGN_KEY') ?? false).toBe(false);
    expect(envVarOf(s, 'pipegen-signing', 'PIPEGEN_COSIGN_PUB')).toBeUndefined();
  });

  it('finish: a memory folder gets the key pair, and the pair folder is gone afterwards', async () => {
    const s = await seed({ keyEnv: true, keysStored: false });
    const dirs: string[] = [];
    const d = s.deps();
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps({
      exec: async (bin, args, opts) => { dirs.push(opts.cwd); await (d.exec as NonNullable<FinishDeps['exec']>)(bin, args, opts); },
    }));
    expect(dirs).toHaveLength(1);
    expect((dirs[0] as string).startsWith(`${s.shm}/`)).toBe(true);
    expect(readdirSync(s.shm)).toEqual([]);
    expect(envVarOf(s, 'pipegen-signing', 'PIPEGEN_COSIGN_PUB')?.value).toBe(cosignPub(41));
  });
});

describe('G13 finish: the real re-probe (carry 59)', () => {
  it('finish: githubFinishProbe re-reads plan, capabilities and workflow pins', async () => {
    const s = await seed();
    s.g.commitOn('o/r', 'main', {
      '.github/workflows/ci.yml': `on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@${'a'.repeat(40)}\n`,
    }, 'ci');
    const base = s.g.octokit() as unknown as { request: unknown; rest: Record<string, Record<string, unknown>> };
    const req = (route: string) => async (p: Record<string, unknown> = {}) => s.g.request(route, p);
    const gh = {
      ...base,
      rest: {
        ...base.rest,
        users: { getAuthenticated: async () => ({ status: 200, data: { login: 'o', type: 'User', plan: { name: 'pro' } }, headers: {} }) },
        repos: { ...base.rest.repos, getRepoRulesets: req('GET /repos/{owner}/{repo}/rulesets'), getAllEnvironments: req('GET /repos/{owner}/{repo}/environments') },
        codeScanning: { listRecentAnalyses: req('GET /repos/{owner}/{repo}/code-scanning/analyses') },
      },
    } as unknown as Parameters<typeof finish>[0];
    const notes: string[] = [];
    const r = await githubFinishProbe('o')(gh, { owner: 'o', repo: 'r' }, { private: true, ownerType: 'User', defaultBranch: 'main', centralDefaultBranch: 'main' }, notes, clock());
    expect(r.plan).toBe('pro');
    expect(r.workflowPins).toEqual({ tagPinned: 1, unchecked: false });
    expect(Object.keys(r.caps).sort()).toEqual(['attestations', 'branchProtection', 'codeScanning', 'deploymentBranchPolicies', 'envRequiredReviewers', 'environments', 'keylessSigningAllowed']);
    expect(r.caps.keylessSigningAllowed).toBe(false);   // a private repo
    // G13-R1: the values, not only the keys (a private User repo on Pro: rulesets read, no environments or code scanning answer)
    expect(r.caps).toEqual({ branchProtection: true, environments: false, deploymentBranchPolicies: false, envRequiredReviewers: false, attestations: false, codeScanning: false, keylessSigningAllowed: false });
    expect(r.centralBranchProtection).toBe(true);
    // it read the app's and the central repo's capabilities, and the app's workflow file on its default branch
    const read = s.g.calls.map((c) => `${c.route} ${String(c.params.repo)}`);
    expect(read).toContain('GET /repos/{owner}/{repo}/rulesets r');
    expect(read).toContain('GET /repos/{owner}/{repo}/rulesets pipelines');
    expect(read.some((c) => c.startsWith('GET /repos/{owner}/{repo}/git/blobs/{file_sha} r'))).toBe(true);
    // the central value is the central repo's own ruleset read: GitHub refusing rulesets there (an upgrade message) makes it false, the app's stays true
    s.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/rulesets' && c.params.repo === 'pipelines' ? { status: 403, data: { message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' } } : undefined));
    const r2 = await githubFinishProbe('o')(gh, { owner: 'o', repo: 'r' }, { private: true, ownerType: 'User', defaultBranch: 'main', centralDefaultBranch: 'main' }, [], clock());
    expect(r2.caps.branchProtection).toBe(true);
    expect(r2.centralBranchProtection).toBe(false);
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

  it('finish: an access level GitHub doesn\'t name is never recorded (V9a-R2: uninstall prints the recorded level in a step)', async () => {
    const s = await seed();
    s.g.x('o/pipelines').access = 'user_x';
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect((await recordOn(s)).central?.actionsAccess).toBeUndefined();
    expect(s.g.x('o/pipelines').access).toBe('user');
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
    // PL-D1 Fold R2 (security I4): both ways on: merge the open central pull request, or run pipegen again
    expect(res.skipped.find((x) => /org required workflow/.test(x.what))?.why).toMatch(/central pull request.*still open, merge it.*otherwise run pipegen again/i);
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

  it('verify: pipegen-signing no longer limited to the default branch → drift', async () => {
    const what = 'environment pipegen-signing (default branch only)';
    const env = (s: Seed) => s.g.repo('o/r').envs.get('pipegen-signing') as NonNullable<ReturnType<ReturnType<Seed['g']['repo']>['envs']['get']>>;
    // missing policy (any branch may deploy)
    let s = await finished({ keyEnv: true });
    env(s).deployment_branch_policy = null;
    expect((await v(s)).drift.filter((d) => d.what === what)).toEqual([{ what, expected: 'only main may use it', actual: 'any branch' }]);
    // not custom: protected branches instead of the one default-branch rule
    s = await finished({ keyEnv: true });
    env(s).deployment_branch_policy = { protected_branches: true, custom_branch_policies: false };
    expect((await v(s)).drift.filter((d) => d.what === what)).toEqual([{ what, expected: 'only main may use it', actual: 'protected branches' }]);
    // a second branch rule, and a tag rule
    s = await finished({ keyEnv: true });
    env(s).policies.push({ id: 900, name: 'dev', type: 'branch' });
    expect((await v(s)).drift.filter((d) => d.what === what)).toEqual([{ what, expected: 'only main may use it', actual: 'branch main, branch dev' }]);
    s = await finished({ keyEnv: true });
    env(s).policies.splice(0, 1, { id: 901, name: 'main', type: 'tag' });
    expect((await v(s)).drift.filter((d) => d.what === what)).toEqual([{ what, expected: 'only main may use it', actual: 'tag main' }]);
    // the environment gone
    s = await finished({ keyEnv: true });
    s.g.repo('o/r').envs.delete('pipegen-signing');
    expect((await v(s)).drift.filter((d) => d.what === what)).toEqual([{ what, expected: 'only main may use it', actual: null }]);
    // not key-env: no such check
    s = await finished();
    expect((await v(s)).drift).toEqual([]);
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

describe('G11 exception round 3 (G11-R3)', () => {
  const app = { owner: 'o', repo: 'r' };
  const vfy = (s: Seed) => verify(s.g.octokit(), app, { local: { home: s.home, env: {} }, clock: clock() });
  type B = Record<string, any>;
  const orgWf = (s: Seed): B[] => (([...s.g.orgRulesets.values()][0] as { body: B }).body.rules as B[])[0]?.parameters.workflows as B[];
  const ORG = 'the org required workflow rule (pipegen-required--r)';
  const io = { confirm: async () => false, select: async () => { throw new Error('no'); }, text: async () => 'o/r' } as never;
  const typedRun = async (s: Seed) => {
    rmSync(join(s.home, '.config'), { recursive: true, force: true });
    const res = await finish(s.g.octokit(), app, {}, s.deps({ io, interactive: true }));
    try { s.g.merge('o/pipelines', 'pipegen/update-r'); } catch { /* recorded directly */ }
    return res;
  };
  const refOnly = (s: Seed, ref: string) => { const wf = orgWf(s)[0] as B; delete wf.sha; wf.ref = ref; };
  const unpinned = (ref: string) => ({ what: ORG, expected: 'every required workflow pinned to a commit', actual: ref });
  const prod = (s: Seed) => s.g.repo('o/r').envs.get('production') as B;
  const PROD_WAS = { wait_timer: 5, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] };
  const userProd = (s: Seed) => s.g.repo('o/r').envs.set('production', { id: 77, created_at: '2026-01-01T00:00:00Z', wait_timer: 5, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() } as never);
  const latest = async (s: Seed) => { try { const r = await recordOn(s, 'pipegen/update-r'); if (r) return r; } catch { /* none */ } return recordOn(s); };

  it('verify: with no recorded pin (after a typed trust), an org rule entry that names a branch instead of a commit is drift (R2-1: O6)', async () => {
    const s = await seed({ org: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await recordOn(s)).orgRuleset?.pinnedSha).toMatch(/^[0-9a-f]{40}$/);
    // G17 row 41: a live pin that still holds pipegen's required workflow is kept (and then recorded); one that doesn't is re-pinned, which
    // a typed run can't show it made
    (orgWf(s)[0] as B).sha = s.pin;
    await typedRun(s);
    expect((await recordOn(s)).orgRuleset).toBeUndefined();
    expect((await vfy(s)).drift).toEqual([]);
    s.g.repo('o/pipelines').refs.set('heads/evil', s.g.head('o/pipelines'));
    refOnly(s, 'refs/heads/evil');
    expect((await vfy(s)).drift).toContainEqual(unpinned('refs/heads/evil'));
    // a sha that is not a commit id (already off the default branch check) gets the same line
    const wf = orgWf(s)[0] as B;
    delete wf.ref; wf.sha = 'main';
    expect((await vfy(s)).drift).toContainEqual(unpinned('main'));
  });

  it('verify: the unrecorded org rule stays checked after a later normal run (R2-1: O6b)', async () => {
    const s = await seed({ org: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    (orgWf(s)[0] as B).sha = s.pin;   // G17 row 41: a pin finish can't keep (see O6)
    await typedRun(s);
    (orgWf(s)[0] as B).sha = s.pin;
    await finish(s.g.octokit(), app, {}, s.deps());
    try { s.g.merge('o/pipelines', 'pipegen/update-r'); } catch { /* recorded directly */ }
    expect((await recordOn(s)).orgRuleset).toBeUndefined();
    expect((await vfy(s)).drift).toEqual([]);
    refOnly(s, 'refs/heads/main');
    expect((await vfy(s)).drift).toContainEqual(unpinned('refs/heads/main'));
  });

  it('verify: a same-name org rule found and updated (unrecorded) with a branch entry is drift (R2-1: O8)', async () => {
    const s = await seed({ org: true });
    const body = structuredClone((await recordOn(s)).planned.orgRequiredWorkflow?.rule.body) as B;
    body.enforcement = 'disabled';
    s.g.orgRulesets.set(4242, { id: 4242, org: 'o', body: { ...body }, created_at: '2026-01-01T00:00:00Z' } as never);
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await recordOn(s)).orgRuleset).toBeUndefined();
    expect((await vfy(s)).drift).toEqual([]);
    refOnly(s, 'refs/heads/main');
    expect((await vfy(s)).drift).toContainEqual(unpinned('refs/heads/main'));
  });

  it('verify: an org rule entry with a key beside path, repository_id and sha (a ref) is drift (R2-5: O4)', async () => {
    const s = await seed({ org: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await vfy(s)).drift).toEqual([]);
    (orgWf(s)[0] as B).ref = 'refs/heads/evil';
    expect((await vfy(s)).drift).toEqual([{ what: ORG, expected: 'each required workflow named by path, repository_id and sha only', actual: 'path, ref, repository_id, sha' }]);
    // the same with no recorded pin
    delete (orgWf(s)[0] as B).ref;
    await typedRun(s);
    expect((await vfy(s)).drift).toEqual([]);
    (orgWf(s)[0] as B).ref = 'refs/heads/evil';
    expect((await vfy(s)).drift).toContainEqual({ what: ORG, expected: 'each required workflow named by path, repository_id and sha only', actual: 'path, ref, repository_id, sha' });
  });

  it('finish: a typed run also counts the default-branch record\'s blockFrom, so a deleted variable never moves the date later (R2-6: I2-e)', async () => {
    const s = await seed();
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await recordOn(s)).blockFrom).toBe(BLOCK_FROM);
    s.g.commitOn('o/r', SETUP_BRANCH, { 'PIPEGEN.md': '# pipegen v2\n' }, 'pipegen: setup again');
    await s.g.request('POST /repos/{owner}/{repo}/pulls', { owner: 'o', repo: 'r', head: SETUP_BRANCH, base: 'main', title: 'pipegen', body: 'again' });
    s.g.merge('o/r', SETUP_BRANCH, '2027-01-10T09:00:00Z');
    s.g.x('o/r').variables.delete('PIPEGEN_BLOCK_FROM');
    const res = await typedRun(s);
    expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
    expect(res.applied.join('\n')).not.toMatch(/2027-01-17/);
    expect((await latest(s)).blockFrom).toBe(BLOCK_FROM);
  });

  it('finish: an unvouched date later than the merge day + 7, or no real day, never sets a typed run\'s date (R2-6)', async () => {
    for (const day of ['2027-06-01', '2026-02-30']) {
      const s = await seed();
      await finish(s.g.octokit(), app, {}, s.deps());
      // the default-branch record now names that day (the central PR merged)
      const r = await recordOn(s);
      if (day === '2026-02-30') {
        // G17C row 34: the record can't hold a day that isn't real; writeRecord refuses it, and a typed run over such a record committed by hand stops (fail closed)
        await expect(writeRecord(s.g.octokit(), { record: { ...r, blockFrom: day }, setupPr: s.pr, via: 'direct', files: [], base: s.g.head('o/pipelines'), clock: clock(), now: () => new Date('2026-11-08T12:00:00Z'), local: { home: s.home, env: {} } })).rejects.toThrow(/form pipegen writes \(at blockFrom\)/);
        s.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText({ ...r, blockFrom: day }) });
        s.g.x('o/r').variables.delete('PIPEGEN_BLOCK_FROM');
        await expect(typedRun(s)).rejects.toThrow(/block date 2026-02-30 is not a real day/);
        expect(varOf(s, 'PIPEGEN_BLOCK_FROM'), day).toBeUndefined();
        // G17C-R1 (F4): the control: the same hand commit with a real day is trusted, so the day is the reason
        s.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText({ ...r, blockFrom: '2026-11-08' }) });
        await typedRun(s);
        expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value, day).toBe('2026-11-08');
        continue;
      }
      await writeRecord(s.g.octokit(), { record: { ...r, blockFrom: day }, setupPr: s.pr, via: 'direct', files: [], base: s.g.head('o/pipelines'), clock: clock(), now: () => new Date('2026-11-08T12:00:00Z'), local: { home: s.home, env: {} } });
      try { s.g.merge('o/pipelines', 'pipegen/update-r'); } catch { /* recorded directly */ }
      expect((await recordOn(s)).blockFrom).toBe(day);
      s.g.x('o/r').variables.delete('PIPEGEN_BLOCK_FROM');
      await typedRun(s);
      expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value, day).toBe(BLOCK_FROM);
    }
  });

  it('typed finish, record date 2026-02-30 → message names 2026-02-30', async () => {
    const s = await seed();
    await finish(s.g.octokit(), app, {}, s.deps());
    const r = await recordOn(s);
    s.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText({ ...r, blockFrom: '2026-02-30' }) });
    const msg = await typedRun(s).then(() => '', (e: Error) => e.message);
    expect(msg).toMatch(/block date 2026-02-30 is not a real day/);
    expect(msg).toContain(`fix the date in ${recordPath('r')}`);
    expect(msg).toMatch(/finish stops/);
    // Fold R1: the message does not claim a branch, and the notes of the generic stop are kept
    expect(msg.split("claims nothing")[0]).not.toMatch(/fix the date in [^,]*default branch/);
    expect(msg).toMatch(/pipegen claims nothing from it/);
    const lp = localRecordPath(app, { home: s.home, env: {} });
    mkdirSync(dirname(lp), { recursive: true });
    mkdirSync(lp);
    const withNotes = await finish(s.g.octokit(), app, {}, s.deps({ io, interactive: true })).then(() => '', (e: Error) => e.message);
    expect(withNotes).toMatch(/block date 2026-02-30 is not a real day/);
    expect(withNotes).toMatch(/can't be checked|local record file/);
    rmSync(lp, { recursive: true, force: true });
    // a record unreadable for another reason keeps the plain message, no date named
    s.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText({ ...r, blockFrom: '2026-02-30', createdAt: 'not a time' }) });
    const other = await typedRun(s).then(() => '', (e: Error) => e.message);
    expect(other).toMatch(/found no install record/);
    expect(other).not.toMatch(/block date/);
  });

  it('finish: a re-run vouched by an earlier typed confirmation also counts the unvouched blockFrom (R2-6)', async () => {
    const s = await seed();
    await finish(s.g.octokit(), app, {}, s.deps());
    s.g.commitOn('o/r', SETUP_BRANCH, { 'PIPEGEN.md': '# pipegen v2\n' }, 'pipegen: setup again');
    await s.g.request('POST /repos/{owner}/{repo}/pulls', { owner: 'o', repo: 'r', head: SETUP_BRANCH, base: 'main', title: 'pipegen', body: 'again' });
    s.g.merge('o/r', SETUP_BRANCH, '2027-01-10T09:00:00Z');
    // a typed run that stops before its record is written: the local file vouches the default-branch record by typing
    rmSync(join(s.home, '.config'), { recursive: true, force: true });
    let armed = true;
    s.g.hooks.push((c) => (armed && !c.route.startsWith('GET ') && c.params.repo === 'pipelines' && /\/git\//.test(c.route) ? { status: 500, data: { message: 'boom' } } : undefined));
    await expect(finish(s.g.octokit(), app, {}, s.deps({ io, interactive: true }))).rejects.toThrow();
    armed = false;
    expect((await readLocalRecord(app, { home: s.home, env: {} }))?.typed).toBe(true);
    s.g.x('o/r').variables.delete('PIPEGEN_BLOCK_FROM');
    await finish(s.g.octokit(), app, {}, s.deps());
    expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
  });

  it('finish: an environment whose created_at is empty or carries an offset keeps its previous value, from the record and from the pending file (R2-4: P1, P2, P4)', async () => {
    for (const at of ['', '2026-01-01T01:00:00+01:00']) {
      const s = await seed();
      userProd(s);
      await finish(s.g.octokit(), app, {}, s.deps());
      expect((await recordOn(s)).environments.find((e) => e.name === 'production')?.previous).toEqual(PROD_WAS);
      prod(s).created_at = at;
      prod(s).wait_timer = 9;
      await finish(s.g.octokit(), app, {}, s.deps());
      const e = (await latest(s)).environments.find((x) => x.name === 'production');
      expect(e, at).toMatchObject({ created: false, previous: PROD_WAS, unconfirmed: true });
    }
    // P2: saved in the pending file by a stopped run, the created_at empty now
    const s = await seed();
    userProd(s);
    let armed = true;
    s.g.hooks.push((c) => (armed && !c.route.startsWith('GET ') && c.params.repo === 'pipelines' && /\/git\//.test(c.route) ? { status: 500, data: { message: 'boom' } } : undefined));
    await expect(finish(s.g.octokit(), app, {}, s.deps())).rejects.toThrow();
    armed = false;
    prod(s).created_at = '';
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await latest(s)).environments.find((x) => x.name === 'production')).toMatchObject({ created: false, previous: PROD_WAS });
  });

  it('readEnv: an environment\'s created_at is ISO-Z or null, as setVariable reads a variable\'s (R2-4)', async () => {
    const s = await seed();
    userProd(s);
    for (const [at, want] of [['', null], ['2026-01-01T01:00:00+01:00', null], ['soon', null], ['2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'], ['2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z']] as const) {
      prod(s).created_at = at;
      expect((await readEnv(s.g.octokit(), app, clock(), 'production'))?.createdAt, at).toBe(want);
    }
  });

  it('finish: the same created_at instant written another way is the same object (R2-4: P4 ms, P5)', async () => {
    const s = await seed();
    userProd(s);
    s.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: '2026-12-31', created_at: '2026-02-02T00:00:00Z' } as never);
    await finish(s.g.octokit(), app, {}, s.deps());
    prod(s).created_at = '2026-01-01T00:00:00.000Z';
    (varOf(s, 'PIPEGEN_BLOCK_FROM') as B).created_at = '2026-02-02T00:00:00.000Z';
    await finish(s.g.octokit(), app, {}, s.deps());
    const r = await latest(s);
    expect(r.environments.find((x) => x.name === 'production')).toMatchObject({ created: false, previous: PROD_WAS, githubCreatedAt: '2026-01-01T00:00:00Z' });
    expect(r.variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM')).toMatchObject({ created: false, previous: '2026-12-31', githubCreatedAt: '2026-02-02T00:00:00Z' });
  });

  it('finish: an unvouched blockFrom in year 0000 (no date to the gate) never replaces a typed run\'s date, kept or deleted (N3-1)', async () => {
    // G17C row 34: the record can't hold a year-0000 day any more (writeRecord refuses it; a typed run over such a record committed by hand stops).
    // The finish point stays on the GitHub side: the same day on the variable alone never survives a typed run.
    for (const day of ['0000-01-01', '0000-02-29']) {
      for (const del of [false, true]) {
        const s = await seed();
        await finish(s.g.octokit(), app, {}, s.deps());
        const r = await recordOn(s);
        await expect(writeRecord(s.g.octokit(), { record: { ...r, blockFrom: day }, setupPr: s.pr, via: 'direct', files: [], base: s.g.head('o/pipelines'), clock: clock(), now: () => new Date('2026-11-08T12:00:00Z'), local: { home: s.home, env: {} } })).rejects.toThrow(/form pipegen writes \(at blockFrom\)/);
        if (del) {
          s.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText({ ...r, blockFrom: day }) });
          s.g.x('o/r').variables.delete('PIPEGEN_BLOCK_FROM');
          await expect(typedRun(s), day).rejects.toThrow(/block date .* is not a real day/);
          expect(varOf(s, 'PIPEGEN_BLOCK_FROM'), day).toBeUndefined();
          continue;
        }
        (varOf(s, 'PIPEGEN_BLOCK_FROM') as B).value = day;
        await typedRun(s);
        expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value, `${day} ${del}`).toBe(BLOCK_FROM);
        expect((await latest(s)).blockFrom, `${day} ${del}`).toBe(BLOCK_FROM);
      }
    }
  });

  it('finish: a variable already at 0000-01-01 is not kept or recorded; verify reports it as drift (N3-1: I2-f)', async () => {
    const s = await seed();
    s.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: '0000-01-01', created_at: '2026-02-02T00:00:00Z' } as never);
    await finish(s.g.octokit(), app, {}, s.deps());
    expect(varOf(s, 'PIPEGEN_BLOCK_FROM')?.value).toBe(BLOCK_FROM);
    expect((await recordOn(s)).blockFrom).toBe(BLOCK_FROM);
    expect((await vfy(s)).drift).toEqual([]);
    (varOf(s, 'PIPEGEN_BLOCK_FROM') as B).value = '0000-01-01';
    expect((await vfy(s)).drift).toContainEqual({ what: 'PIPEGEN_BLOCK_FROM', expected: BLOCK_FROM, actual: '0000-01-01' });
    // a record that holds the same gate-invalid date as the variable (an older pipegen wrote it): G17C row 34 makes writeRecord refuse it,
    // and verify reports such a record committed by hand as drift (the record itself), never a crash
    const r = await recordOn(s);
    await expect(writeRecord(s.g.octokit(), { record: { ...r, blockFrom: '0000-01-01' }, setupPr: s.pr, via: 'direct', files: [], base: s.g.head('o/pipelines'), clock: clock(), now: () => new Date('2026-11-08T12:00:00Z'), local: { home: s.home, env: {} } })).rejects.toThrow(/form pipegen writes \(at blockFrom\)/);
    s.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText({ ...r, blockFrom: '0000-01-01' }) });
    await expect(recordOn(s)).rejects.toThrow(/blockFrom/);
    const d = (await vfy(s)).drift;
    expect(d.length).toBeGreaterThan(0);
    expect(d[0]?.what).toBe('install record');
  });

  it('finish: an ISO-shaped created_at that is no real instant is unknown, so the previous value is kept (N3-2)', async () => {
    for (const at of ['2026-02-30T00:00:00Z', '2026-13-45T25:61:61Z', '2026-01-01T24:00:00Z']) {
      const s = await seed();
      userProd(s);
      prod(s).created_at = at;
      expect((await readEnv(s.g.octokit(), app, clock(), 'production'))?.createdAt, at).toBeNull();
      prod(s).created_at = '2026-01-01T00:00:00Z';
      await finish(s.g.octokit(), app, {}, s.deps());
      prod(s).created_at = at;
      prod(s).wait_timer = 9;
      await finish(s.g.octokit(), app, {}, s.deps());
      const e = (await latest(s)).environments.find((x) => x.name === 'production');
      expect(e, at).toMatchObject({ created: false, previous: PROD_WAS, unconfirmed: true });
      expect(e, at).not.toHaveProperty('githubCreatedAt');
    }
    // a variable's created_at the same way
    const s = await seed();
    s.g.x('o/r').variables.set('PIPEGEN_BLOCK_FROM', { value: '2026-12-31', created_at: '2026-02-02T00:00:00Z' } as never);
    await finish(s.g.octokit(), app, {}, s.deps());
    (varOf(s, 'PIPEGEN_BLOCK_FROM') as B).created_at = '2026-02-30T00:00:00Z';
    (varOf(s, 'PIPEGEN_BLOCK_FROM') as B).value = '2026-12-30';
    await finish(s.g.octokit(), app, {}, s.deps());
    const v = (await latest(s)).variables.find((x) => x.name === 'PIPEGEN_BLOCK_FROM');
    expect(v).toMatchObject({ created: false, previous: '2026-12-31' });
    expect(v).not.toHaveProperty('githubCreatedAt');
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

describe('G13-R2b: protected paths in the record (m7, m1)', () => {
  const v = (s: Seed) => verify(s.g.octokit(), { owner: 'o', repo: 'r' }, { local: { home: s.home, env: {} }, clock: clock() });

  it('finish: a record with protectedPaths [./trivy.yaml, .github/workflows/**] applies with no LockError (m7)', async () => {
    const s = await seed({ recordOver: (r) => { r.protectedPaths = ['./trivy.yaml', '.github/workflows/**']; } });
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect(res.applied.length).toBeGreaterThan(0);
    expect((await recordOn(s)).protectedPaths).toEqual(['./trivy.yaml', '.github/workflows/**']);
  });

  it('verify: a root trivy.yaml is labelled protected, sub/trivy.yaml is not (m7)', async () => {
    const s = await seed({ recordOver: (r) => {
      r.protectedPaths = ['./trivy.yaml', '.github/workflows/**', 'CODEOWNERS'];
      r.files.push({ repo: 'app', path: 'trivy.yaml', part: 'pipeline', shas: ['a'.repeat(40)] } as never, { repo: 'app', path: 'sub/trivy.yaml', part: 'pipeline', shas: ['b'.repeat(40)] } as never);
    } });
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const what = (await v(s)).drift.map((d) => d.what);
    expect(what).toContain('app file trivy.yaml (protected)');
    expect(what).toContain('app file sub/trivy.yaml');
  });

  it('record: ./, .//x and ././x are refused by checkRecord; verify reports such a record as drift, never a crash (m1)', async () => {
    const s = await seed();
    const r = await recordOn(s);
    for (const bad of ['./', './/x', '././x', 'a//b', 'a/./b', '.', '']) expect(() => checkRecord({ ...r, protectedPaths: [bad] }), JSON.stringify(bad)).toThrow(/protectedPaths/);
    for (const ok of ['./trivy.yaml', '.github/workflows/**', 'CODEOWNERS', 'svc/.gitleaks.toml']) expect(checkRecord({ ...r, protectedPaths: [ok] }).protectedPaths).toEqual([ok]);
    // the conversion refuses what it can't keep exactly
    for (const bad of ['//x', '/./x', '/a//b', '/']) expect(() => protectedPathsForRecord([bad]), bad).toThrow();
    expect(protectedPathsForRecord(['/trivy.yaml', 'CODEOWNERS'])).toEqual(['./trivy.yaml', 'CODEOWNERS']);
    // a record on the central default branch with such a path: verify says so as drift
    s.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText({ ...r, protectedPaths: ['.//x'] }) });
    const res = await v(s);
    expect(res.drift.length).toBeGreaterThan(0);
    expect(res.drift[0]?.what).toBe('install record');
  });
});

describe('G17 group D: finish and verify (rows 40-46)', () => {
  const app = { owner: 'o', repo: 'r' };
  const vfy = (s: Seed) => verify(s.g.octokit(), app, { local: { home: s.home, env: {} }, clock: clock() });
  type B = Record<string, any>;
  const orgRs = (s: Seed) => [...s.g.orgRulesets.values()][0] as { id: number; body: B; created_at: string };
  const orgWf = (s: Seed): B[] => (orgRs(s).body.rules as B[])[0]?.parameters.workflows as B[];
  const ORG = 'the org required workflow rule (pipegen-required--r)';
  const REQ = centralWorkflowFile('r', 'required');
  const MERGE_PATH = centralWorkflowFile('r', 'merge');
  const CALLER = '.github/workflows/pipegen.yml';
  const mergeCentral = (s: Seed) => { try { s.g.merge('o/pipelines', 'pipegen/update-r'); } catch { /* recorded directly */ } };
  const latest = async (s: Seed) => { try { const r = await recordOn(s, 'pipegen/update-r'); if (r) return r; } catch { /* none */ } return recordOn(s); };
  const orgDrift = async (s: Seed) => (await vfy(s)).drift.filter((d) => d.what === ORG);
  const central = (s: Seed, path: string, sha = s.g.head('o/pipelines')) => s.g.filesAt('o/pipelines', sha).get(path) as string;

  it('finish: a re-run keeps the org rule\'s live pin while that commit is on the central default branch and holds pipegen\'s required workflow (row 41, R2-3)', async () => {
    const s = await seed({ org: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    const pinned = orgWf(s)[0]?.sha as string;
    expect((await recordOn(s)).orgRuleset?.pinnedSha).toBe(pinned);
    expect(s.g.head('o/pipelines')).not.toBe(pinned);   // the record commit moved the central head
    const from = s.g.calls.length;
    const res = await finish(s.g.octokit(), app, {}, s.deps());
    expect(orgWf(s)[0]?.sha).toBe(pinned);
    expect(s.g.calls.slice(from).filter((c) => c.route === 'PUT /orgs/{org}/rulesets/{ruleset_id}')).toEqual([]);
    expect(res.applied.join('\n')).toMatch(/the org required workflow \(ruleset pipegen-required--r, pinned to [0-9a-f]{12}\) \(already in place\)/);
    expect((await latest(s)).orgRuleset?.pinnedSha).toBe(pinned);
    // the re-run's record waits in the central pull request: verify reports the record hash, but no org rule drift
    expect(await orgDrift(s)).toEqual([]);
    mergeCentral(s);
    expect((await vfy(s)).drift).toEqual([]);
    // a live pin whose commit doesn't hold pipegen's required workflow (here: before it was written) is not kept: re-pinned to the head
    orgWf(s)[0]!.sha = s.pin;
    let head = s.g.head('o/pipelines');
    await finish(s.g.octokit(), app, {}, s.deps());
    expect(orgWf(s)[0]?.sha).toBe(head);
    expect((await latest(s)).orgRuleset?.pinnedSha).toBe(head);
    mergeCentral(s);
    // a live pin off the central default branch is not kept either
    const off = orgWf(s)[0]?.sha as string;
    s.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/compare/{basehead}' && String(c.params.basehead).endsWith(`...${off}`) ? { status: 200, data: { status: 'diverged', files: [] } } : undefined));
    head = s.g.head('o/pipelines');
    await finish(s.g.octokit(), app, {}, s.deps());
    expect(orgWf(s)[0]?.sha).toBe(head);
  });

  it('finish: a ruleset whose created_at GitHub writes another way (…03Z, …03.000Z) is the same ruleset: no false "can\'t show it made it" (row 42)', async () => {
    const s = await seed({ org: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    const r = await recordOn(s);
    const orgWas = r.orgRuleset?.githubCreatedAt as string;
    const gateWas = r.rulesets.find((x) => x.name === 'pipegen')?.githubCreatedAt as string;
    expect(orgWas).toMatch(/\.000Z$/);
    expect(gateWas).toMatch(/\.000Z$/);
    // the same instants, written without the milliseconds; each live rule differs a little, so finish updates it by id
    const rs = orgRs(s);
    rs.created_at = orgWas.replace('.000Z', 'Z');
    rs.body.enforcement = 'evaluate';
    const gate = [...s.g.repo('o/r').rulesets.values()].find((b) => b.name === 'pipegen') as B;
    gate.created_at = gateWas.replace('.000Z', 'Z');
    gate.enforcement = 'evaluate';
    const res = await finish(s.g.octokit(), app, {}, s.deps());
    expect(res.notes.join('\n')).not.toMatch(/can't show it made it/);
    expect(res.applied.join('\n')).toMatch(/ruleset pipegen\b/);
    const after = await latest(s);
    expect(after.orgRuleset).toMatchObject({ id: rs.id, githubCreatedAt: orgWas });
    expect(after.rulesets.find((x) => x.name === 'pipegen')).toMatchObject({ githubCreatedAt: gateWas });
  });

  it('finish --rotate-key: a stored key whose created_at GitHub writes another way is still pipegen\'s own: created, never "overwritten" (row 43)', async () => {
    const s = await seed({ keyEnv: true, recordOver: (r) => {
      for (const k of (r as unknown as Record<string, { githubCreatedAt?: string }[]>)[LIST] ?? []) if (k.githubCreatedAt !== undefined) k.githubCreatedAt = k.githubCreatedAt.replace('.000Z', 'Z');
    } });
    const before = ((await recordOn(s)) as unknown as Record<string, { githubCreatedAt?: string }[]>)[LIST] ?? [];
    expect(before.length).toBe(2);
    expect(before.every((k) => /T\d\d:\d\d:\d\dZ$/.test(k.githubCreatedAt ?? ''))).toBe(true);
    await finish(s.g.octokit(), app, { rotateKey: true }, s.deps());
    const keys = ((await latest(s)) as unknown as Record<string, { name: string; scope: string; created: boolean; overwritten?: true }[]>)[LIST]?.filter((k) => k.scope === 'env:pipegen-signing') ?? [];
    expect(keys.map((k) => k.name).sort()).toEqual(['PIPEGEN_COSIGN_KEY', PW_NAME].sort());
    for (const k of keys) expect(k, k.name).toMatchObject({ created: true });
    for (const k of keys) expect(k, k.name).not.toHaveProperty('overwritten');
  });

  it('finish: the record\'s planned is the plan finish applied, never a weaker plan planted in the record; verify holds the live locks to it (row 44)', async () => {
    const weaken = (b: B | undefined) => {
      const pr = (b?.rules as B[]).find((x) => x.type === 'pull_request') as B;
      pr.parameters.required_approving_review_count = 0;
      pr.parameters.require_code_owner_review = false;
      pr.parameters.require_last_push_approval = false;
    };
    const s = await seed({ org: true, plannedOver: (p) => { weaken(p.rulesets?.reviews?.body as B); weaken(p.centralRuleset?.body as B); } });
    await finish(s.g.octokit(), app, {}, s.deps());
    const r = await recordOn(s);
    const live = [...s.g.repo('o/r').rulesets.values()].find((b) => b.name === 'pipegen-reviews') as B;
    const livePr = (live.rules as B[]).find((x) => x.type === 'pull_request')?.parameters as B;
    expect(livePr.required_approving_review_count).toBeGreaterThan(0);
    const recPr = ((r.planned.rulesets?.reviews?.body.rules as B[]).find((x) => x.type === 'pull_request') as B).parameters;
    expect(recPr).toEqual(livePr);
    expect(r.planned.centralRuleset?.body).toEqual(s.locks.centralRuleset?.body);
    expect(r.planned.rulesets?.gate.body).toEqual(s.locks.rulesets?.gate.body);
    expect((await vfy(s)).drift).toEqual([]);
    // the live lock weakened to the planted values: drift (the planted plan is no baseline)
    livePr.required_approving_review_count = 0;
    livePr.require_code_owner_review = false;
    const d = (await vfy(s)).drift.filter((x) => x.what === 'ruleset pipegen-reviews');
    expect(d.map((x) => x.expected).join('\n')).toMatch(/code-owner review/);
    expect(d.map((x) => x.expected).join('\n')).toMatch(/approving review/);
  });

  it('finish --print: the key pair commands start in a memory folder and pass the password through COSIGN_PASSWORD, never a file (row 45, sec M5)', async () => {
    const s = await seed({ keyEnv: true });
    const res = await finish(s.g.octokit(), app, { print: true, rotateKey: true }, s.deps());
    const cmds = res.commands ?? [];
    // G17-R4 (sec C1): one subshell block a failure ends; the folder is a variable the trap removes, never "$OLDPWD"
    const block = cmds.find((c) => c.includes('cosign generate-key-pair')) as string;
    expect(block).toBe(KEY_BLOCK);
    expect(block.indexOf('mktemp -d -p /dev/shm')).toBeLessThan(block.indexOf('cosign generate-key-pair'));
    expect(block.indexOf(`${PW_VAR}=`)).toBeLessThan(block.indexOf('cosign generate-key-pair'));
    const text = cmds.join('\n');
    expect(text).not.toMatch(/\.password\b/);
    expect(text).not.toMatch(/OLDPWD|cd -/);
    expect(text).toMatch(new RegExp(`^  printf '%s' "\\$COSIGN_PASSWORD" \\| gh secret set ${PW_NAME} --env pipegen-signing --repo o/r$`, 'm'));
    // nothing of the block outside it: no umask, password or folder left in the user's shell
    for (const c of cmds.filter((x) => x !== block && !x.startsWith('#'))) expect(c).not.toMatch(/umask|COSIGN_PASSWORD|mktemp|cosign /);
    expect(cmds[cmds.indexOf(block) - 1]).toMatch(/^# .*POSIX shell.*stops at the first failure.*npx pipegen finish --rotate-key/);
    expect(s.execs).toEqual([]);
  });

  it('verify: after update re-pinned the app, the org rule\'s stale pin is named plainly; finish then re-pins it to the commit holding the new required workflow (row 46)', async () => {
    const s = await seed({ org: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await vfy(s)).drift).toEqual([]);
    const p0 = orgWf(s)[0]?.sha as string;
    // what `pipegen update` leaves once its pull requests are merged: a new central merge file (c1), the app calling it, the required
    // workflow calling it, the record at c1
    const merge2 = MERGE.replace('run: "true"', 'run: "echo v2"');
    const c1 = s.g.commitOn('o/pipelines', 'main', { [MERGE_PATH]: merge2 }, 'update the merge workflow');
    const caller2 = (s.g.filesAt('o/r', s.g.head('o/r')).get(CALLER) as string).replace(s.pin, c1);
    s.g.commitOn('o/r', 'main', { [CALLER]: caller2 }, 'update the app');
    const req1 = central(s, REQ);
    const req2 = req1.replace(s.pin, c1);
    expect(req2).not.toBe(req1);
    s.g.commitOn('o/pipelines', 'main', { [REQ]: req2 }, 'update the required workflow');
    const r = await recordOn(s);
    const add = (f: InstallRecord['files'][number], text: string) => ({ ...f, shas: [...f.shas, gitBlobSha(text)] });
    const next: InstallRecord = { ...r, centralSha: c1, files: r.files.map((f) => (f.path === REQ ? add(f, req2) : f.path === MERGE_PATH ? add(f, merge2) : f.path === CALLER ? add(f, caller2) : f)) };
    await writeRecord(s.g.octokit(), { record: next, setupPr: s.pr, via: 'direct', files: [], base: s.g.head('o/pipelines'), clock: clock(), now: () => new Date('2026-11-08T12:00:00Z'), local: { home: s.home, env: {} } });
    mergeCentral(s);
    const v = await vfy(s);
    expect(v.drift.filter((d) => d.what !== ORG)).toEqual([]);
    expect(v.drift).toContainEqual({ what: ORG, expected: `the required workflow at the pinned commit ${p0} calling the merge workflow at the app's central commit ${c1}`, actual: `it calls it at ${s.pin} (a stale pin)` });
    expect(v.notes.join('\n')).toMatch(/npx pipegen finish/);
    // finish re-pins the rule to the central commit that holds the new required workflow
    await finish(s.g.octokit(), app, {}, s.deps());
    const p1 = orgWf(s)[0]?.sha as string;
    expect(p1).not.toBe(p0);
    expect(central(s, REQ, p1)).toBe(req2);
    expect((await latest(s)).orgRuleset?.pinnedSha).toBe(p1);
    mergeCentral(s);
    expect((await vfy(s)).drift).toEqual([]);
  });

  it('verify: with no recorded pin, the required workflow at the commit the live rule names must be one pipegen wrote (row 40, R2-2)', async () => {
    const s = await seed({ org: true });
    // a same-name org rule found and updated: finish can't show it made it, so it records no pin (O8)
    const body = structuredClone((await recordOn(s)).planned.orgRequiredWorkflow?.rule.body) as B;
    body.enforcement = 'disabled';
    s.g.orgRulesets.set(4242, { id: 4242, org: 'o', body: { ...body }, created_at: '2026-01-01T00:00:00Z' } as never);
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await recordOn(s)).orgRuleset).toBeUndefined();
    expect(await orgDrift(s)).toEqual([]);
    const good = orgWf(s)[0]?.sha as string;
    // an older default-branch commit, before pipegen wrote the required workflow
    orgWf(s)[0]!.sha = s.pin;
    expect(await orgDrift(s)).toContainEqual({ what: ORG, expected: `${REQ} at ${s.pin} as pipegen wrote it`, actual: null });
    // a default-branch commit whose required workflow is not one pipegen wrote
    const other = 'name: not pipegen\non: { pull_request: null }\njobs: {}\n';
    const c = s.g.commitOn('o/pipelines', 'main', { [REQ]: other }, 'someone else');
    orgWf(s)[0]!.sha = c;
    expect(await orgDrift(s)).toContainEqual({ what: ORG, expected: `${REQ} at ${c} as pipegen wrote it`, actual: gitBlobSha(other) });
    orgWf(s)[0]!.sha = good;
    expect(await orgDrift(s)).toEqual([]);
  });
});

describe('G17 group D fix round 1 (G17-R4)', () => {
  const app = { owner: 'o', repo: 'r' };
  const vfy = (s: Seed) => verify(s.g.octokit(), app, { local: { home: s.home, env: {} }, clock: clock() });
  type B = Record<string, any>;
  const orgRs = (s: Seed) => [...s.g.orgRulesets.values()][0] as { id: number; body: B; created_at: string };
  const orgWf = (s: Seed): B[] => (orgRs(s).body.rules as B[])[0]?.parameters.workflows as B[];
  const ORG = 'the org required workflow rule (pipegen-required--r)';
  const REQ = centralWorkflowFile('r', 'required');
  const latest = async (s: Seed) => { try { const r = await recordOn(s, 'pipegen/update-r'); if (r) return r; } catch { /* none */ } return recordOn(s); };
  const orgDrift = async (s: Seed) => (await vfy(s)).drift.filter((d) => d.what === ORG);
  const central = (s: Seed, path: string, sha = s.g.head('o/pipelines')) => s.g.filesAt('o/pipelines', sha).get(path) as string;
  const io = { confirm: async () => false, select: async () => { throw new Error('no'); }, text: async () => 'o/r' } as never;
  /** A finished project whose org rule pins a commit that is not the central head (the record commit moved it). */
  const pinnedOff = async () => {
    const s = await seed({ org: true });
    await finish(s.g.octokit(), app, {}, s.deps());
    const pinned = orgWf(s)[0]?.sha as string;
    expect(s.g.head('o/pipelines')).not.toBe(pinned);
    return { s, pinned };
  };
  /** A project whose org rule finish found and couldn't show it made: no recorded pin (O8), so verify checks the file the rule runs. */
  const unpinned = async () => {
    const s = await seed({ org: true });
    const body = structuredClone((await recordOn(s)).planned.orgRequiredWorkflow?.rule.body) as B;
    body.enforcement = 'disabled';
    s.g.orgRulesets.set(4242, { id: 4242, org: 'o', body: { ...body }, created_at: '2026-01-01T00:00:00Z' } as never);
    await finish(s.g.octokit(), app, {}, s.deps());
    expect((await recordOn(s)).orgRuleset).toBeUndefined();
    expect(await orgDrift(s)).toEqual([]);
    return s;
  };

  // ---------- C1: the printed key-pair block, run as the user would ----------

  const SHELLS = ['sh', 'bash', 'dash', 'zsh'].filter((sh) => spawnSync('sh', ['-c', `command -v ${sh}`], { stdio: 'ignore' }).status === 0);
  /** Every path under `dir` (files and folders), sorted, with each file's text: what a run may not change. */
  const tree = (dir: string): string[] => readdirSync(dir, { recursive: true, encoding: 'utf8' }).sort().map((p) => (statSync(join(dir, p)).isDirectory() ? `${p}/` : `${p}=${readFileSync(join(dir, p), 'utf8')}`));
  /**
   * Runs the printed block under `sh` from a stand-in clone, with a fake cosign and gh first on PATH and /dev/shm swapped for `shm` (an
   * existing folder, or one that doesn't exist). After the block the same script prints what the user's shell holds then.
   */
  const runBlock = (block: string, sh: string, o: { shmExists: boolean; cosignFails?: boolean; disk?: boolean; noBase64?: boolean; xtrace?: boolean }) => {
    const root = mkdtempSync(join(tmpdir(), 'pg-keyblock-'));
    homes.push(root);
    const bin = join(root, 'bin');
    const clone = join(root, 'clone');
    const shm = join(root, 'shm');
    const log = join(root, 'calls.log');
    mkdirSync(bin);
    mkdirSync(clone);
    if (o.shmExists) mkdirSync(shm);
    writeFileSync(join(clone, 'keep.txt'), 'uncommitted work\n');
    mkdirSync(join(clone, 'src'));
    writeFileSync(join(clone, 'src', 'app.ts'), 'export {};\n');
    writeFileSync(join(bin, 'cosign'), `#!/bin/sh\necho "cosign $* in=$(pwd) len=\${#${PW_VAR}}" >> "$PG_LOG"\nprintf 'KEY\\n' > pipegen-signing.key\nprintf 'PUB\\n' > pipegen-signing.pub\n${o.cosignFails === true ? 'exit 1\n' : ''}`);
    writeFileSync(join(bin, 'gh'), '#!/bin/sh\necho "gh $* stdin=$(wc -c | tr -d \' \')" >> "$PG_LOG"\n');
    chmodSync(join(bin, 'cosign'), 0o755);
    chmodSync(join(bin, 'gh'), 0o755);
    // the stand-in /dev/shm is a temp folder on disk: a fake stat says what it is (tmpfs, or a disk file system); base64 gives a known
    // 44-character password, or fails
    writeFileSync(join(bin, 'stat'), `#!/bin/sh\necho ${o.disk === true ? 'ext2/ext3' : 'tmpfs'}\n`);
    writeFileSync(join(bin, 'base64'), o.noBase64 === true ? '#!/bin/sh\ncat > /dev/null\nexit 127\n' : `#!/bin/sh\ncat > /dev/null\nprintf '%s\\n' ${KNOWN_PW}\n`);
    chmodSync(join(bin, 'stat'), 0o755);
    chmodSync(join(bin, 'base64'), 0o755);
    const script = join(root, 'paste.sh');
    writeFileSync(script, `umask 022\n${o.xtrace === true ? 'set -x\n' : ''}${block.split('/dev/shm').join(shm)}\necho "rc=$? env=\${${PW_VAR}-unset} umask=$(umask) cwd=$(pwd)"\n`);
    writeFileSync(log, '');
    const before = tree(root);
    const r = spawnSync(sh, sh === 'zsh' ? ['-f', script] : [script], { cwd: clone, env: { PATH: `${bin}:${process.env.PATH ?? '/usr/bin:/bin'}`, PG_LOG: log, HOME: root }, encoding: 'utf8' });
    const calls = readFileSync(log, 'utf8').split('\n').filter((l) => l !== '');
    writeFileSync(log, '');
    return { r, out: r.stdout, before, after: tree(root), calls, clone, shm };
  };
  const keyBlock = async () => {
    const s = await seed({ keyEnv: true });
    const res = await finish(s.g.octokit(), app, { print: true, rotateKey: true }, s.deps());
    // every printed command of the key pair (the row 45 test pins their exact form), pasted in order
    const block = (res.commands ?? []).filter((c) => !c.startsWith('#') && /mktemp|umask|COSIGN_PASSWORD|cosign |pipegen-signing\.|OLDPWD/.test(c)).join('\n');
    expect(block).toContain('cosign generate-key-pair');
    return block;
  };

  it('finish --print: the key-pair block, run in a POSIX shell without /dev/shm, stops before any key: nothing written, the clone untouched, no secret stored (G17-R4, sec C1)', async () => {
    const block = await keyBlock();
    expect(SHELLS).toContain('sh');
    for (const sh of SHELLS) {
      const x = runBlock(block, sh, { shmExists: false });
      expect(x.r.status, `${sh}: ${x.r.stderr}`).toBe(0);
      expect(x.out, sh).toMatch(/^rc=[1-9]\d* /m);
      expect(x.calls, sh).toEqual([]);   // no cosign, no gh
      expect(x.after, sh).toEqual(x.before);   // no pipegen-signing.* anywhere, keep.txt and src/ still there
      expect(x.after, sh).toContain('clone/keep.txt=uncommitted work\n');
      expect(x.out, sh).toContain(`env=unset umask=${sh === 'zsh' ? '022' : '0022'} cwd=${x.clone}`);
    }
  });

  it('finish --print: the key-pair block, run in a POSIX shell, makes the pair in the memory folder only and removes it; a failed cosign stores nothing (G17-R4, sec C1)', async () => {
    const block = await keyBlock();
    for (const sh of SHELLS) {
      const ok = runBlock(block, sh, { shmExists: true });
      expect(ok.out, `${sh}: ${ok.r.stderr}`).toMatch(/^rc=0 /m);
      expect(ok.calls[0], sh).toMatch(new RegExp(`^cosign generate-key-pair --output-key-prefix pipegen-signing in=${ok.shm}/[^/]+ len=4[0-9]$`));
      expect(ok.calls.slice(1), sh).toEqual([
        'gh secret set PIPEGEN_COSIGN_KEY --env pipegen-signing --repo o/r stdin=4',
        `gh secret set ${PW_NAME} --env pipegen-signing --repo o/r stdin=${(ok.calls[0] as string).replace(/.* len=/, '')}`,
        'gh variable set PIPEGEN_COSIGN_PUB --env pipegen-signing --repo o/r stdin=4',
      ]);
      expect(ok.after, sh).toEqual(ok.before);   // the memory folder is gone; nothing written anywhere else
      expect(ok.out, sh).toContain(`env=unset umask=${sh === 'zsh' ? '022' : '0022'} cwd=${ok.clone}`);
      // cosign fails (after writing a key): no gh call, nothing stored, the folder still removed
      const bad = runBlock(block, sh, { shmExists: true, cosignFails: true });
      expect(bad.out, sh).toMatch(/^rc=[1-9]\d* /m);
      expect(bad.calls.length, sh).toBe(1);
      expect(bad.calls[0], sh).toMatch(/^cosign /);
      expect(bad.after, sh).toEqual(bad.before);
      expect(bad.out, sh).toContain(`env=unset umask=${sh === 'zsh' ? '022' : '0022'} cwd=${bad.clone}`);
    }
  });

  it('finish --print: the key-pair block stops before cosign when /dev/shm is not a memory folder (a disk folder, as on Windows Git Bash), in every shell (G17-R5, sec m1)', async () => {
    const block = await keyBlock();
    for (const sh of SHELLS) {
      const x = runBlock(block, sh, { shmExists: true, disk: true });
      expect(x.out, `${sh}: ${x.r.stderr}`).toMatch(/^rc=[1-9]\d* /m);
      expect(x.calls, sh).toEqual([]);   // no cosign, no gh
      expect(x.after, sh).toEqual(x.before);   // the folder removed, nothing written
      expect(x.out, sh).toContain(`env=unset umask=${sh === 'zsh' ? '022' : '0022'} cwd=${x.clone}`);
    }
  });

  it('finish --print: with set -x in the user\'s shell the block never prints the password, and still makes the pair (G17-R5, sec m2)', async () => {
    const block = await keyBlock();
    for (const sh of SHELLS) {
      const x = runBlock(block, sh, { shmExists: true, xtrace: true });
      expect(x.out, `${sh}: ${x.r.stderr}`).toMatch(/^rc=0 /m);
      expect(x.calls.length, sh).toBe(4);
      expect(x.out + x.r.stderr, sh).not.toContain(KNOWN_PW);
    }
  });

  it('finish --print: a failing base64 (an empty password) stops the block before cosign, in every shell (G17-R5, sec i1)', async () => {
    const block = await keyBlock();
    for (const sh of SHELLS) {
      const x = runBlock(block, sh, { shmExists: true, noBase64: true });
      expect(x.out, `${sh}: ${x.r.stderr}`).toMatch(/^rc=[1-9]\d* /m);
      expect(x.calls, sh).toEqual([]);
      expect(x.after, sh).toEqual(x.before);
    }
  });

  it('finish --print: no printed # line holds a backtick or $( (a stock zsh runs them when pasted) and the key-pair note says to run the whole block again (G17-R5, sec i3, i4)', async () => {
    const s = await seed({ keyEnv: true });
    const res = await finish(s.g.octokit(), app, { print: true, rotateKey: true }, s.deps());
    const hashes = (res.commands ?? []).filter((c) => c.startsWith('#'));
    expect(hashes.length).toBeGreaterThan(0);
    for (const c of hashes) expect(c).not.toMatch(/`|\$\(/);
    expect(hashes.find((c) => c.includes('A new key pair'))).toMatch(/stopped after a gh line, run the whole block again/);
  });

  // ---------- M1: the fail-closed guards rows 40-51 added ----------

  it('finish: a live pin is not kept when GitHub says it is ahead of the central default branch, or the compare can\'t be read (row 41, M1: S41g, S41h)', async () => {
    for (const answer of [{ status: 200, data: { status: 'ahead', files: [] } }, { status: 200, data: { files: [] } }]) {
      const { s, pinned } = await pinnedOff();
      s.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/compare/{basehead}' && String(c.params.basehead).endsWith(`...${pinned}`) ? answer : undefined));
      const head = s.g.head('o/pipelines');
      await finish(s.g.octokit(), app, {}, s.deps());
      expect(orgWf(s)[0]?.sha, JSON.stringify(answer.data)).toBe(head);
      expect((await latest(s)).orgRuleset?.pinnedSha).toBe(head);
    }
  });

  it('finish: a live pin whose required workflow has pipegen\'s blob but another mode is not kept (row 41, M1: S41f)', async () => {
    const { s } = await pinnedOff();
    const rp = s.g.repo('o/pipelines');
    const text = central(s, REQ);
    const c = s.g.commitOn('o/pipelines', 'main', { 'other.txt': 'x\n' }, 'an executable required workflow');
    const t = rp.trees.get(rp.commits.get(c)?.tree as string) as Map<string, { mode: string }>;
    (t.get(REQ) as { mode: string }).mode = '100755';
    s.g.commitOn('o/pipelines', 'main', { [REQ]: text, 'other.txt': 'y\n' }, 'back to 100644');
    expect(s.g.modeAt('o/pipelines', c, REQ)).toBe('100755');
    expect(s.g.modeAt('o/pipelines', s.g.head('o/pipelines'), REQ)).toBe('100644');
    orgWf(s)[0]!.sha = c;
    const head = s.g.head('o/pipelines');
    await finish(s.g.octokit(), app, {}, s.deps());
    expect(orgWf(s)[0]?.sha).toBe(head);
  });

  it('verify: with no recorded pin, a commit GitHub won\'t show, or one whose required workflow is another pipegen file, is drift (row 40, M1: S40c, S40b)', async () => {
    const s = await unpinned();
    const good = orgWf(s)[0]?.sha as string;
    s.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}' && c.params.repo === 'pipelines' && c.params.commit_sha === good ? { status: 404, data: { message: 'Not Found' } } : undefined));
    expect(await orgDrift(s)).toContainEqual({ what: ORG, expected: `the required workflow at ${good} as pipegen wrote it`, actual: 'unreadable' });
    s.g.hooks.pop();
    expect(await orgDrift(s)).toEqual([]);
    // the required workflow's path holding the blob of another file pipegen wrote (the merge workflow)
    const c = s.g.commitOn('o/pipelines', 'main', { [REQ]: MERGE }, 'the merge workflow at the required path');
    orgWf(s)[0]!.sha = c;
    expect(await orgDrift(s)).toContainEqual({ what: ORG, expected: `${REQ} at ${c} as pipegen wrote it`, actual: gitBlobSha(MERGE) });
  });

  it('finish: a weaker gate ruleset, classic protection or org rule planted in the record is never recorded as planned; verify holds the live locks to pipegen\'s (row 44, M1: S44c, S44d, S44f)', async () => {
    const s = await seed({ org: true, plannedOver: (p) => {
      const gate = p.rulesets?.gate.body as B;
      gate.rules = (gate.rules as B[]).filter((r) => r.type !== 'non_fast_forward');
      (p.classic?.body as B).enforce_admins = false;
      (p.orgRequiredWorkflow?.rule.body as B).enforcement = 'evaluate';
    } });
    await finish(s.g.octokit(), app, {}, s.deps());
    const r = await recordOn(s);
    expect(r.planned.rulesets?.gate.body).toEqual(s.locks.rulesets?.gate.body);
    expect(r.planned.classic?.body).toEqual(s.locks.classic?.body);
    expect((r.planned.orgRequiredWorkflow?.rule.body as B).enforcement).toBe('active');
    expect((await vfy(s)).drift).toEqual([]);
    // the live gate ruleset loses non_fast_forward: drift against pipegen's plan, not the planted one
    const gate = [...s.g.repo('o/r').rulesets.values()].find((b) => b.name === 'pipegen') as B;
    gate.rules = (gate.rules as B[]).filter((x) => x.type !== 'non_fast_forward');
    expect((await vfy(s)).drift.map((d) => d.what)).toContain('ruleset pipegen');
  });

  it('finish --rotate-key: a stored key whose earlier entry has no created_at is never claimed as pipegen\'s own (row 43, M1: S43b)', async () => {
    const s = await seed({ keyEnv: true, recordOver: (r) => {
      for (const k of (r as unknown as Record<string, { githubCreatedAt?: string; unconfirmed?: true }[]>)[LIST] ?? []) { delete k.githubCreatedAt; k.unconfirmed = true; }
    } });
    await finish(s.g.octokit(), app, { rotateKey: true }, s.deps());
    const keys = ((await latest(s)) as unknown as Record<string, { name: string; scope: string; created: boolean; overwritten?: true }[]>)[LIST]?.filter((k) => k.scope === 'env:pipegen-signing') ?? [];
    expect(keys.map((k) => k.name).sort()).toEqual(['PIPEGEN_COSIGN_KEY', PW_NAME].sort());
    for (const k of keys) expect(k, k.name).toMatchObject({ created: false, overwritten: true });
  });

  // ---------- I1: what a typed run records when it keeps the pin ----------

  it('finish: a typed run that keeps a good org-rule pin records the rule, its created_at and the kept pin (row 41, I1)', async () => {
    const { s, pinned } = await pinnedOff();
    const id = orgRs(s).id;
    rmSync(join(s.home, '.config'), { recursive: true, force: true });
    const res = await finish(s.g.octokit(), app, {}, s.deps({ io, interactive: true }));
    try { s.g.merge('o/pipelines', 'pipegen/update-r'); } catch { /* recorded directly */ }
    expect(orgWf(s)[0]?.sha).toBe(pinned);
    expect(res.applied.join('\n')).toMatch(/the org required workflow \(ruleset pipegen-required--r, pinned to [0-9a-f]{12}\) \(already in place\)/);
    expect((await recordOn(s)).orgRuleset).toEqual({ org: 'o', id, name: 'pipegen-required--r', githubCreatedAt: expect.stringMatching(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$/), pinnedSha: pinned });
    expect((await vfy(s)).drift).toEqual([]);
  });
});

describe('G17C-R1: finish (F4, F6)', () => {
  const app = { owner: 'o', repo: 'r' };
  it('finish: the block date takes the earliest real day only; an impossible day or year 0000 never counts (F4: earliestBlockFrom)', () => {
    expect(earliestBlockFrom('2026-11-12', [undefined, '', ''])).toBe('2026-11-12');
    expect(earliestBlockFrom('2026-11-12', ['2026-02-30', '0000-01-01', '2026-13-01'])).toBe('2026-11-12');
    expect(earliestBlockFrom('2026-11-12', ['2026-11-10', '2026-11-11', '2027-01-01'])).toBe('2026-11-10');
    expect(earliestBlockFrom('2026-11-12', ['2027-01-01', '0000-02-29', '2026-11-09'])).toBe('2026-11-09');
  });
  it('finish: a local record file that is a folder → stop naming the file and `npx pipegen finish` (F6, m2)', async () => {
    const s = await seed();
    const f = join(s.home, '.config', 'pipegen', 'records', 'o__r.json');
    rmSync(f, { force: true });
    mkdirSync(f, { recursive: true });
    const e = await finish(s.g.octokit(), app, {}, s.deps()).then(() => null, (x: unknown) => x) as Error;
    expect(e).toBeInstanceOf(FinishError);
    expect(e.message).toContain(f);
    expect(e.message).toContain('npx pipegen finish');
    expect(e.message).not.toMatch(/npx pipegen run/);
  });
});

// ---------- Plan V M5: the app's lease ----------

describe('Plan V M5: finish holds the app lease', () => {
  const app = { owner: 'o', repo: 'r' };
  const st = (s: Seed) => ({ home: s.home, env: {} });
  /** `base` with `before` awaited ahead of each of its request() calls (the rest of the Octokit unchanged). */
  const withRequest = (base: ReturnType<FinishGitHub['octokit']>, before: (route: string) => Promise<void>): ReturnType<FinishGitHub['octokit']> =>
    new Proxy(base, { get: (t, k, r) => (k === 'request'
      ? async (route: string, params?: Record<string, unknown>) => { await before(route); return t.request(route as never, params as never); }
      : Reflect.get(t, k, r)) });
  const noIo = { confirm: async () => false, select: async () => { throw new Error('no select'); }, text: async () => { throw new Error('no text'); } };
  /** finish's Octokit, with `rival` run (to its end) right before finish's first write: the two pipegen commands side by side. */
  const sideBySide = (s: Seed, rival: () => Promise<unknown>) => {
    const base = s.g.octokit();
    const seen: { result?: unknown; callsDuring?: number } = {};
    const gh = withRequest(base, async (route) => {
      if (!route.startsWith('GET ') && !('result' in seen)) {
        const before = s.g.calls.length;
        seen.result = await rival().then(() => 'ran', (e: unknown) => e);
        seen.callsDuring = s.g.calls.length - before;
      }
    });
    return { gh, seen };
  };

  it('finish: another pipegen holding the app lease (an uninstall\'s phase A) stops finish before any GitHub call, naming it', async () => {
    const s = await seed();
    const other = await StateStore.open(app, st(s));
    other.acquireLease('uninstall-abc', 'uninstall');
    const from = s.g.calls.length;
    const e = await finish(s.g.octokit(), app, {}, s.deps()).then(() => null, (x: unknown) => x);
    expect(e).toBeInstanceOf(FinishError);
    expect((e as Error).message).toMatch(/^Another pipegen \(`pipegen uninstall`, process \d+\) is working on .* Wait for it to finish, or stop it, then run pipegen again\. If process \d+ is not pipegen, remove \S+lease\.json and run pipegen again\. Nothing was applied\.$/);
    expect(s.g.calls.length).toBe(from);
    // --print too: it reads what the uninstall is changing
    await expect(finish(s.g.octokit(), app, { print: true }, s.deps())).rejects.toThrow(/`pipegen uninstall`/);
    expect(s.g.calls.length).toBe(from);
    other.releaseLease();
    // once the uninstall is over, finish runs
    expect((await finish(s.g.octokit(), app, {}, s.deps())).applied.length).toBeGreaterThan(0);
  });

  it('finish: update beside finish: update stops before any GitHub call, naming finish; finish ends as planned and gives the lease back', async () => {
    const s = await seed();
    const { gh, seen } = sideBySide(s, () => update(s.g.octokit(), app, { io: noIo, reviewed: [], local: { home: s.home, env: {} } }));
    const res = await finish(gh, app, {}, s.deps());
    expect(seen.result).toBeInstanceOf(UpdateError);
    expect((seen.result as Error).message).toMatch(/Another pipegen \(`pipegen finish`, process \d+\) is working on .* Nothing was changed\.$/);
    expect(seen.callsDuring).toBe(0);
    expect(res.applied.length).toBeGreaterThan(0);
    const probe = await StateStore.open(app, st(s));
    probe.acquireLease('after', 'update');
    probe.releaseLease();
  });

  it('finish: a second finish beside finish stops too (the same lease, same stale-lease rules)', async () => {
    const s = await seed();
    const { gh, seen } = sideBySide(s, () => finish(s.g.octokit(), app, {}, s.deps()));
    await finish(gh, app, {}, s.deps());
    expect(seen.result).toBeInstanceOf(FinishError);
    expect((seen.result as Error).message).toMatch(/`pipegen finish`/);
    expect(seen.callsDuring).toBe(0);
    // a lease left by a process that is gone is taken over, as run's is
    const lease = join(s.home, '.cache', 'pipegen', 'o__r', 'lease.json');
    writeFileSync(lease, JSON.stringify({ pid: 2 ** 22 + 12345, host: hostname(), runId: 'gone', [['to', 'ken'].join('')]: 't', command: 'uninstall' }), { mode: 0o600 });
    expect((await finish(s.g.octokit(), app, {}, s.deps())).applied).toBeDefined();
    expect(existsSync(lease)).toBe(false);
  });

  it('finish: G-LEASE-R1 (spec I1) a corrupt or 0644 proof state file beside the lease does not stop finish (it never reads it)', async () => {
    for (const bad of ['corrupt', '0644'] as const) {
      const s = await seed();
      const dir = join(s.home, '.cache', 'pipegen', 'o__r');
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      chmodSync(join(s.home, '.cache'), 0o700); chmodSync(join(s.home, '.cache', 'pipegen'), 0o700);
      writeFileSync(join(dir, 'state.json'), bad === 'corrupt' ? '{' : '{"version":1}', { mode: 0o600 });
      if (bad === '0644') chmodSync(join(dir, 'state.json'), 0o644);
      expect((await finish(s.g.octokit(), app, {}, s.deps())).applied.length).toBeGreaterThan(0);
      expect(readFileSync(join(dir, 'state.json'), 'utf8')).toBe(bad === 'corrupt' ? '{' : '{"version":1}');
    }
  });

  it('finish: run passes its lease down: finish takes no second one (no self-deadlock) and leaves it held', async () => {
    const s = await seed();
    const run = await StateStore.open(app, st(s));
    run.acquireLease('20261106-100000-abc123', 'run');
    const res = await finish(s.g.octokit(), app, {}, s.deps({ lease: run }));
    expect(res.applied.length).toBeGreaterThan(0);
    expect(run.holdsLeaseFor(app)).toBe(true);
    run.releaseLease();
  });

  it('finish: the lease is given back on an error and is dropped by the exit hook on an interrupt', async () => {
    // an error: no install record → FinishError, lease given back
    const s = await seed();
    rmSync(join(s.home, '.config'), { recursive: true, force: true });
    await expect(finish(s.g.octokit(), app, {}, s.deps())).rejects.toThrow(FinishError);
    const probe = await StateStore.open(app, st(s));
    probe.acquireLease('after-error', 'update');
    probe.releaseLease();
    // an interrupt: the sync exit hooks (what SIGINT/SIGTERM run after the interrupt hooks) drop finish's lease while it runs
    const s2 = await seed();
    const lease = join(s2.home, '.cache', 'pipegen', 'o__r', 'lease.json');
    let heldAtWrite: boolean | null = null;
    let afterHooks: boolean | null = null;
    const base = s2.g.octokit();
    const gh = withRequest(base, async (route) => {
      if (!route.startsWith('GET ') && heldAtWrite === null) {
        heldAtWrite = existsSync(lease);
        runExitHooks();
        afterHooks = existsSync(lease);
      }
    });
    // another pipegen may take the lease once the hook dropped it; finish's own release never removes that one
    await finish(gh, app, {}, s2.deps()).catch(() => undefined);
    expect(heldAtWrite).toBe(true);
    expect(afterHooks).toBe(false);
    expect(existsSync(lease)).toBe(false);
  });
});
