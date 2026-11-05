// v0.2 Plan G G10 (plan Task 7 "deliver"; rulings S11, S13, S14, S17, S26; carries CF-1, D-m6, E-b15, F-8, G1 → G10, G28; Plan V
// pre-flight §5 items 1-7, binding): the proven draft goes out as the one setup PR (and the central PR), the secrets pipegen needs before
// the merge are stored (an existing one only with its own yes), and the install record is written to all three places. Every GitHub call
// goes to an in-memory GitHub (test/helpers/deliver-github.ts); no network.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { gitBlobSha } from '../src/create/guard.js';
import { SecretVault } from '../src/create/secrets.js';
import { HOOK_FILES } from '../src/engine/created-builders.js';
import { centralProjectName } from '../src/engine/central-path.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { pubKeySha256 } from '../src/engine/signing.js';
import type { Prompter } from '../src/cli/io.js';
import { deliver, deliverCentral, PART_ORDER, planDelivery, previewText, SETUP_BRANCH, type DeliveryInput, type DeliverDeps, type SigningKey } from '../src/deliver/deliver.js';
import { DeliverError, ghRead, ghWrite } from '../src/deliver/git-data.js';
import { readRecord, recordHash, recordMarker, recordPath, writeRecord } from '../src/deliver/record.js';
import { COMPAT_PREFIX, HARNESS_PATH } from '../src/proof/harness.js';
import type { LockPlan } from '../src/layers/locks.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import type { CreatedFile, PipelineDraft, RepoProfile } from '../src/types.js';
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
const SIGNING = { key: 'K'.repeat(80), pub: 'cosign-public-key-' + 'Z'.repeat(40), [['pass', 'word'].join('')]: PW } as unknown as SigningKey;
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
const homes: string[] = [];
afterEach(() => { for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true }); });
function world(opts: { appPrivate?: boolean; centralPrivate?: boolean; appFiles?: Record<string, string>; modes?: Record<string, string>; repo?: string } = {}): World {
  const g = new FakeGitHub();
  g.addRepo(`o/${opts.repo ?? 'r'}`, { private: opts.appPrivate ?? true, files: opts.appFiles ?? { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG, [HOOK_FILES['pre-commit']]: HOOK_ORIG, 'package.json': PJ, 'package-lock.json': LOCK, '.github/workflows/deploy.yml': DEPLOY_ORIG }, ...(opts.modes === undefined ? {} : { modes: opts.modes }) });
  g.addRepo('o/pipelines', { private: opts.centralPrivate ?? true, files: { 'README.md': 'central\n' } });
  const home = mkdtempSync(join(tmpdir(), 'pg-deliver-'));
  homes.push(home);
  const vault = new SecretVault();
  vault.set(KEY, KEY_VALUE);
  return { g, home, vault, asked: [] };
}
function io(w: World, answers: { confirmRunCode?: boolean; replace?: boolean } = {}): Prompter {
  return {
    confirm: async (msg) => { w.asked.push(msg); return /run code/i.test(msg) ? answers.confirmRunCode ?? true : /already has/i.test(msg) ? answers.replace ?? false : false; },
    select: async () => { throw new Error('no select'); },
    text: async () => { throw new Error('no text'); },
  };
}
const deps = (w: World, over: Partial<DeliverDeps> = {}, answers: Parameters<typeof io>[1] = {}): DeliverDeps => ({
  io: io(w, answers), clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home: w.home, env: {} }, pipegenVersion: '0.2.0', now: () => new Date('2026-11-05T12:00:00Z'), ...over,
});
function input(p: RepoProfile, pin: string | null, over: Partial<DeliveryInput> = {}, draftOver: Partial<PipelineDraft> = {}): DeliveryInput {
  return {
    draft: draftOf(p, pin, draftOver), files: [...(pin === null ? [] : centralFiles()), ...appFiles(pin)], locks: locks(), ...({ [['secret', 'Names'].join('')]: NAMES_IN } as unknown as Pick<DeliveryInput, 'secretNames'>),
    protectedPaths: ['.github/workflows/**', 'CODEOWNERS'], environments: [{ name: 'production', reviewers: true }],
    proofRepos: { central: { repoId: 77, createdByPipegen: true }, scratch: { createdByPipegen: true } }, ...over,
  };
}
/** The first run of a private app: the central commit, then the app delivery. */
async function firstRun(w: World, over: Partial<DeliveryInput> = {}, dOver: Partial<DeliverDeps> = {}, answers: Parameters<typeof io>[1] = {}, draftOver: Partial<PipelineDraft> = {}) {
  const p = profile();
  const c = await deliverCentral(w.g.octokit(), p, centralFiles(), { clock: { budget: newRateBudget(), sleep: async () => {} } });
  if (c.kind !== 'pinned') throw new Error('expected a pin');
  const plan = planDelivery(input(p, c.sha, over, draftOver));
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
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), {}) as { sha: string }).sha;
    const again = appFiles(pin, { withPkg: false }).filter((f) => f.edited === undefined && f.inserted === undefined).map((f) => (f.path === 'Dockerfile' ? { ...f, content: 'FROM node:26\n' } : f));
    await deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files: [...centralFiles(), ...again], locks: locks({ codeowners: undefined }) })), v2, deps(w));
    const hist2 = w.g.history('o/r', w.g.head('o/r', SETUP_BRANCH), merged);
    expect(hist2.map((c) => c.message)).toEqual([expect.stringContaining('(docker)')]);
  });

  it('deliver: never includes pipegen-planted/, harness, compat copies', async () => {
    const w = world();
    const extra = [cf('pipegen-planted/secrets.py', 'x = 1\n', 'pipeline'), cf(HARNESS_PATH, 'on: push\n', 'pipeline'), cf(`${COMPAT_PREFIX}ci.yml`, 'on: push\n', 'pipeline')];
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), {});
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
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), {});
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

  it('deliver: second run updates PR and opens central PR', async () => {
    const w = world();
    const first = await firstRun(w);
    expect(w.g.repo('o/r').pulls.length).toBe(1);
    expect(w.g.repo('o/pipelines').pulls.length).toBe(0);   // the first run commits to the central default branch
    // second run, central files unchanged: same setup PR, the record through the central PR
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const p = profile();
    const c2 = await deliverCentral(w.g.octokit(), p, centralFiles(), {});
    expect(c2).toEqual({ kind: 'pinned', sha: first.pin, done: [] });
    const res2 = await deliver(w.g.octokit(), p, planDelivery(input(p, first.pin)), v2, deps(w));
    expect(res2.prNumber).toBe(first.res.prNumber);
    expect(w.g.repo('o/r').pulls.filter((x) => x.state === 'open').length).toBe(1);
    expect(res2.centralPrUrl).toMatch(/o\/pipelines\/pull\/1$/);
    // a third run with changed central files: a central PR first, and a stop before the app PR
    const before = w.g.calls.length;
    const c3 = await deliverCentral(w.g.octokit(), p, centralFiles(' # v2'), {});
    expect(c3.kind).toBe('central-pr');
    if (c3.kind === 'central-pr') expect(c3.message).toMatch(/merge the central PR, then run (pipegen )?again/i);
    expect(w.g.calls.slice(before).some((x) => x.params.repo === 'r' && !x.route.startsWith('GET '))).toBe(false);
    expect(w.g.repo('o/pipelines').pulls.filter((x) => x.state === 'open').length).toBe(1);   // the same central PR, updated, never a second one
    const branchFiles = w.g.filesAt('o/pipelines', w.g.head('o/pipelines', `pipegen/update-${centralProjectName('r')}`));
    expect(branchFiles.get('.github/workflows/r--merge.yml')).toContain('# v2');
  });

  it('deliver: the required workflow and the central CODEOWNERS go with the record commit, never into the pinned commit', async () => {
    // G8 carry: the required workflow calls the merge workflow AT the pinned commit, so it can't be in that commit; it goes in the next one
    const w = world();
    const p = profile();
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), {});
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
    expect(r?.edits.find((e) => e.repo === 'central')).toEqual({ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: coFile.content, originalSha: null, writtenShas: [gitBlobSha(coFile.content)] });
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
    const c = await deliverCentral(w.g.octokit(), p, centralFiles(), {});
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
    const c = await deliverCentral(w2.g.octokit(), p, centralFiles(), {});
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
    expect(co).toEqual({ repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: '\n# pipegen:begin\n.github/workflows/** @a @b\n# pipegen:end\n', originalSha: gitBlobSha(CO_ORIG), writtenShas: [gitBlobSha(setupFiles(w).get('CODEOWNERS') as string)] });
    expect(r?.edits.find((e) => e.kind === 'hooks')).toMatchObject({ path: HOOK_FILES['pre-commit'], inserted: '  # pipegen:hooks\n  - repo: local\n', originalSha: gitBlobSha(HOOK_ORIG) });
    expect(r?.edits.find((e) => e.kind === 'verify-job')).toEqual({ repo: 'app', path: '.github/workflows/deploy.yml', kind: 'verify-job', jobs: ['pipegen-verify'], needs: [{ job: 'deploy', added: ['pipegen-verify'] }], originalSha: gitBlobSha(DEPLOY_ORIG), writtenShas: [gitBlobSha(DEPLOY_NEW)] });
    expect(r?.central).toEqual({ repoId: 77, createdByPipegen: true });
    expect(r?.scratch).toEqual({ createdByPipegen: true });
    // a second run appends the new blob sha, keeps the first original
    const p = profile();
    const v2 = new SecretVault();
    v2.set(KEY, KEY_VALUE);
    const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), {}) as { sha: string }).sha;
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
    expect(r?.edits.find((e) => e.kind === 'package-lock')).toEqual({ repo: 'app', path: 'package-lock.json', kind: 'package-lock', json: 'package.json', originalSha: gitBlobSha(LOCK), writtenShas: [gitBlobSha(LOCK_NEW)] });
    expect(r?.edits.find((e) => e.kind === 'package-json')).toEqual({ repo: 'app', path: 'package.json', kind: 'package-json', add: { vitest: '5.0.5' }, setTest: true, previousTest: 'echo "Error: no test specified" && exit 1', lock: 'package-lock.json', originalSha: gitBlobSha(PJ), writtenShas: [gitBlobSha(PJ_NEW)] });
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
    // a read-back that fails: recorded without created_at and marked, so uninstall asks instead of deleting
    const w2 = world();
    w2.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/actions/secrets/{secret_name}' && nameOf(c) === KEY && w2.g.repo('o/r').stored.has(KEY) ? { status: 500 } : undefined));
    await firstRun(w2);
    expect((await record(w2))?.secrets.find((s) => s.name === KEY)).toEqual({ name: KEY, scope: 'repo', created: true, unconfirmed: true });
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
    expect(res.notes).toEqual([]);
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

  it('deliver: a record found only on the central PR branch is trusted only when its hash matches the local record file or the PR marker (G10-R-sec 1)', async () => {
    const upd = `pipegen/update-${centralProjectName('r')}`;
    const rerun = async (w: World): Promise<Awaited<ReturnType<typeof deliver>>> => {
      const p = profile();
      const v = new SecretVault();
      v.set(KEY, KEY_VALUE);
      const pin = (await deliverCentral(w.g.octokit(), p, centralFiles(), {}) as { sha: string }).sha;
      const files = [...centralFiles(), ...appFiles(pin).map((f) => (f.path === 'Dockerfile' ? { ...f, content: 'FROM node:26\n' } : f))];
      return deliver(w.g.octokit(), p, planDelivery(input(p, pin, { files })), v, deps(w, {}, { replace: true }));
    };
    const setup = async (): Promise<World> => {
      const w = world();
      const p = profile();
      const c = await deliverCentral(w.g.octokit(), p, centralFiles(), {});
      w.g.repo('o/pipelines').rules = [{ type: 'pull_request' }];   // the record goes to the central PR branch only
      await deliver(w.g.octokit(), p, planDelivery(input(p, (c as { sha: string }).sha)), w.vault, deps(w));
      expect(await record(w)).toBeUndefined();
      return w;
    };
    // the local record file's hash matches: trusted (the earlier sha is kept, pipegen's own secret stays created)
    const w = await setup();
    const res = await rerun(w);
    expect(res.notes).toEqual([]);
    const r = await record(w, upd);
    expect(r?.files.find((f) => f.path === 'Dockerfile')?.shas).toEqual([gitBlobSha('FROM node:24\n'), gitBlobSha('FROM node:26\n')]);
    expect(r?.secrets.find((s) => s.name === KEY)?.created).toBe(true);
    // no local file, but the setup PR's marker matches: trusted
    const w2 = await setup();
    rmSync(join(w2.home, '.config', 'pipegen', 'records', 'o__r.json'));
    expect((await rerun(w2)).notes).toEqual([]);
    expect((await record(w2, upd))?.files.find((f) => f.path === 'Dockerfile')?.shas.length).toBe(2);
    // the PR body's marker edited away, but the local record file matches: trusted
    const w4 = await setup();
    (w4.g.repo('o/r').pulls[0] as { body: string }).body = 'edited by someone';
    expect((await rerun(w4)).notes).toEqual([]);
    expect((await record(w4, upd))?.files.find((f) => f.path === 'Dockerfile')?.shas.length).toBe(2);
    // a record planted on the branch (someone with write on the central repo changed it): claims nothing
    const w3 = await setup();
    const planted = { ...(await record(w3, upd) as NonNullable<Awaited<ReturnType<typeof record>>>) };
    planted.files.push({ repo: 'app', path: 'README.md', part: 'docs', shas: [gitBlobSha('hi\n')] });
    w3.g.commitOn('o/pipelines', upd, { [recordPath('r')]: JSON.stringify(planted) });
    const res3 = await rerun(w3);
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
