// The starter-test creator (v0.2 Plan D, D7; preflight S9, B2; plan Task 5). A Node service with no tests gets AI-written starter tests.
// The AI's code runs in the user's CI, so it is hostile input:
//   - the framework is FIXED: Vitest 5.0.5 for Node (the AI does not choose; Python is v0.4 and gets a not-proven note). The devDependencies and the
//     lockfile come from D6's planNpmDeps (the reviewed pins and nothing else, every edit needsConfirm), and scripts.test must end up exactly `vitest run`;
//   - the package edit is planned BEFORE the AI is asked, so a service whose lock can not be generated costs no AI call;
//   - every file the AI writes is judged by the rules leaf (test-rules.ts: a real parse and a tree walk), the same one the referee's judge and the guard
//     run, plus the path, the size, the 20-file cap and "no overwrite" (validateGeneratedTests); a refused answer is asked once more with the reasons, and a
//     second refusal throws StarterTestsError (Plan E makes the part failed);
//   - the AI's `reasoning` goes only into a note, through formatAiText, never into a file; the file reasons are fixed text.
// checkAttempt is for Plan E's fix loop: a new attempt may not have fewer tests or fewer assertions than the one before.
import { z } from 'zod';
import { TESTS_SYSTEM, testsInstructions } from '../ai/prompts/tests.js';
import { completeValidated, formatAiText } from '../ai/provider.js';
import { bundleText, type CodeBundle } from '../ai/redact.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import { duplicatePathProblems } from '../engine/created-files.js';
import { createdPathProblem } from '../engine/job-rules.js';
import { isProtectedPath } from '../engine/protected-match.js';
import type { AiProvider, AiRequest, AiUsage, CreatedFile, RepoProfile, ReviewedTool, Service } from '../types.js';
import { activeSafeText as safeText } from '../util/known-values.js';
import { planNpmDeps, type NpmDepsInput } from './npm-deps.js';
import { VITEST_TEST_SCRIPT } from './package-rules.js';
import { analyzeTestFile, packageModuleType, fileStats, isTestName, MAX_TEST_FILE_BYTES, MAX_TEST_FILES, STARTER_FRAMEWORK, STARTER_VITEST_VERSION, starterOwner, starterTestPathProblem } from './test-rules.js';

const TIMEOUT_MS = 240_000;
const MAX_OUTPUT_TOKENS = 16_000;
const MAX_AI_FILES = MAX_TEST_FILES + 5;   // so a 21st file reaches the validator and is refused with a reason

export interface TestPlan {
  /** `vitest 5.0.5` for a Node service; '' when nothing is created. */
  framework: string;
  /** Plain reasons for the choice (fixed text: the framework is not the AI's). */
  reasons: string[];
  /** The test files (and helpers) to write: new files only. */
  files: CreatedFile[];
  /** package.json and package-lock.json edits (D6's planNpmDeps): every one has needsConfirm. */
  configEdits: CreatedFile[];
  /** Why nothing was created (not proven), or notes for the developer (the AI's explanation). */
  notes: string[];
  usage?: AiUsage;
}

/** What the creator can not know from the profile. `fileExists` takes a repo-relative path (the caller maps it to the local tree and the base tree). */
export interface StarterDeps {
  fileExists: (path: string) => boolean;
  /** package.json and package-lock.json of the service, exactly as on disk; the lock is null when the service has none of its own. */
  packageJson: string;
  packageLock: string | null;
  workspaceMember?: boolean;
  /** The reviewed list (for the reviewed closure D6 uses). */
  reviewed: readonly ReviewedTool[];
  /** Test hooks for planNpmDeps (the npm runner, the closure). */
  npm?: Pick<NpmDepsInput, 'runner' | 'closureBefore' | 'closure'>;
  /** true only when Plan G's isolated starter-test job exists (no secrets, egress blocked, read-only token); the validator alone is not a boundary (D7-R7). */
  isolatedTestJob?: boolean;
}

/** The second answer was refused too. Plan E makes the tests part failed. `usage` is the AI cost of both attempts. */
export class StarterTestsError extends Error {
  constructor(message: string, readonly problems: readonly string[], readonly usage?: AiUsage) {
    super(safeText(message, 1200));
    this.name = 'StarterTestsError';
  }
}

type AiTests = { files: { path: string; content: string }[]; reasoning: string };
export const testsSchema: AiSchema<AiTests> = aiSchema<AiTests>(z.strictObject({
  files: z.array(z.strictObject({ path: z.string().max(200), content: z.string().max(60_000) })).max(MAX_AI_FILES),
  reasoning: z.string().max(4_000),
}));

const rootPrefix = (svcPath: string): string => svcPath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');
const plainFolder = (dir: string): boolean => createdPathProblem(dir === '' ? 'a' : `${dir}/a`) === null && !dir.split('/').some((s) => s.startsWith('.') || s === 'node_modules');
const show = (s: Service): string => `"${safeText(s.name, 80)}"`;
const notProven = (message: string): TestPlan => ({ framework: '', reasons: [], files: [], configEdits: [], notes: [message] });

// ---------- validation ----------

/**
 * Judges the files the AI wrote for service `s`. `files` carry repo paths (the service folder first). A file is accepted only if its path is a starter-test
 * path of `s` that the gate does not protect, it does not exist yet (`fileExists`, a repo-relative path), it is among the first 20, and the rules leaf
 * (size, a real parse, the import allowlist, the banned forms, the assertions) finds nothing. `ownDeps` is ignored (the service's dependencies are not importable, S9 amended in D7 round 3); it is kept so callers need not change.
 */
export function validateGeneratedTests(files: CreatedFile[], s: Service, fileExists: (path: string) => boolean, ownDeps: readonly string[] = [], moduleType: 'module' | 'commonjs' = 'commonjs'): { accepted: CreatedFile[]; rejected: { path: string; why: string }[] } {
  const dir = rootPrefix(s.path);
  const accepted: CreatedFile[] = [];
  const rejected: { path: string; why: string }[] = [];
  const clash = new Map<CreatedFile, string>();
  for (const c of duplicatePathProblems(files.filter((f) => typeof f === 'object' && f !== null && typeof f.path === 'string' && typeof f.repo === 'string'))) clash.set(c.file, c.message);
  const reject = (f: CreatedFile, why: string): void => { rejected.push({ path: safeText(String(f?.path), 120), why: safeText(why, 600) }); };
  let seen = 0;
  for (const f of files) {
    if (typeof f !== 'object' || f === null || typeof f.path !== 'string' || typeof f.content !== 'string') { rejected.push({ path: '', why: 'this is not a file with a path and text' }); continue; }
    const pathProblem = createdPathProblem(f.path);
    if (pathProblem !== null) { reject(f, `the path is refused: ${pathProblem}`); continue; }
    const owner = starterOwner(f.path, [dir]);
    if (owner === null) {
      reject(f, `the path is not inside the service folder ${dir === '' ? '(the repository root)' : safeText(dir, 80)}, or ${starterTestPathProblem(dir !== '' && f.path.startsWith(`${dir}/`) ? f.path.slice(dir.length + 1) : f.path) ?? 'it is not a starter-test path'}`);
      continue;
    }
    if (isProtectedPath(f.path, [dir])) { reject(f, 'the path is one the merge gate protects, so pipegen does not write it'); continue; }
    if (fileExists(f.path)) { reject(f, 'a file already exists at this path, and pipegen never overwrites your files'); continue; }
    const dup = clash.get(f);
    if (dup !== undefined) { reject(f, dup); continue; }
    if (seen >= MAX_TEST_FILES) { reject(f, `pipegen writes at most ${MAX_TEST_FILES} test files per service`); continue; }
    seen++;
    const report = analyzeTestFile(owner.rel, f.content, ownDeps, moduleType);
    if (report.problems.length > 0) { reject(f, report.problems.slice(0, 4).join('; ')); continue; }
    accepted.push(f);
  }
  return { accepted, rejected };
}

/** The tests in the test files (static count of it(...) and test(...) calls found by the parser); a file that does not parse counts 0. */
export function countTests(files: CreatedFile[]): number {
  let n = 0;
  for (const f of files) if (isTestName(f.path.slice(f.path.lastIndexOf('/') + 1))) n += fileStats(f.path, f.content)?.tests ?? 0;
  return n;
}
/** The assertions written directly in the tests of the test files. */
export function countAssertions(files: CreatedFile[]): number {
  let n = 0;
  for (const f of files) if (isTestName(f.path.slice(f.path.lastIndexOf('/') + 1))) n += fileStats(f.path, f.content)?.assertions ?? 0;
  return n;
}

/** Problems with a new attempt: it may not have fewer tests or fewer assertions than the previous one (spec section 19), so a failing test can not be "fixed" by deleting it. */
export function checkAttempt(prev: TestPlan | null, next: TestPlan): string[] {
  if (prev === null) return [];
  const out: string[] = [];
  const before = countTests(prev.files), after = countTests(next.files);
  if (after < before) out.push(`The new attempt has ${after} test${after === 1 ? '' : 's'}, fewer than the ${before} of the attempt before; a failing test is fixed, not removed.`);
  const a0 = countAssertions(prev.files), a1 = countAssertions(next.files);
  if (a1 < a0) out.push(`The new attempt has ${a1} assertion${a1 === 1 ? '' : 's'}, fewer than the ${a0} of the attempt before; a test is not made to pass by checking less.`);
  return out;
}

// ---------- the creator ----------

/**
 * Creates starter tests for a Node service without tests, or says why not (one not-proven note, nothing written). See the file header. Throws
 * StarterTestsError when the AI's answer is refused twice, and SecretScanRequiredError when the bundle was not secret-scanned.
 */
export async function createStarterTests(s: Service, _p: RepoProfile, bundle: CodeBundle, ai: AiProvider, deps: StarterDeps): Promise<TestPlan> {
  const code = bundleText(bundle);   // first: throws SecretScanRequiredError before anything else happens
  if (deps.isolatedTestJob !== true) {
    return notProven(`No starter tests for ${show(s)}: pipegen runs AI-written tests only in an isolated CI job (no secrets, no network, read-only token), and that job is not set up in this version, so its tests are not proven.`);
  }
  const dir = rootPrefix(s.path);
  const at = (name: string): string => (dir === '' ? name : `${dir}/${name}`);

  if (s.language === 'python') return notProven(`Starter tests for Python services (pytest) come in v0.4, so ${show(s)} got none: its tests are not proven.`);
  if (s.language !== 'node') return notProven(`pipegen writes starter tests only for Node services in this version; ${show(s)} is not one, so none were created.`);
  if (s.hasTests) return notProven(`${show(s)} already has tests, so pipegen wrote no starter tests.`);
  if (s.packageManager !== 'npm') return notProven(`pipegen writes starter tests only for npm services in this version (it adds the reviewed Vitest through npm); ${show(s)} uses ${safeText(s.packageManager ?? 'no recognised package manager', 20)}, so none were created.`);
  if (!plainFolder(dir)) return notProven(`The folder of ${show(s)} is not a plain path that pipegen can write into, so no starter tests were created.`);

  // the package edit first: the reviewed Vitest pins and scripts.test (D6). Nothing else is added, and the AI does not choose a package.
  const pkg = planNpmDeps({ service: s, tool: 'vitest', packageJson: deps.packageJson, packageLock: deps.packageLock, ...(deps.workspaceMember === undefined ? {} : { workspaceMember: deps.workspaceMember }), reviewed: deps.reviewed, ...deps.npm });
  if (pkg.files.length === 0 && pkg.notes.length > 0) return notProven(`No starter tests for ${show(s)}: ${pkg.notes.join(' ')}`);
  let testScript: unknown;
  try { testScript = ((JSON.parse((pkg.files.find((f) => f.path === at('package.json')) ?? { content: deps.packageJson }).content) as { scripts?: { test?: unknown } }).scripts ?? {}).test; } catch { testScript = undefined; }
  if (testScript !== VITEST_TEST_SCRIPT) {
    return notProven(`No starter tests for ${show(s)}: its test script is ${typeof testScript === 'string' ? JSON.stringify(safeText(testScript, 60)) : 'not a plain command'}, and pipegen sets it to "${VITEST_TEST_SCRIPT}" only when it is missing or npm's default, so the new tests would not run.`);
  }

  const ext = s.quality.tsconfig ? 'ts' : 'js';
  const factsBlock = `<service-facts>\n${JSON.stringify({ framework: STARTER_FRAMEWORK, version: STARTER_VITEST_VERSION, fileExtension: ext, port: typeof s.port === 'number' ? s.port : null }, null, 1)}\n</service-facts>`;
  const req: AiRequest = {
    system: TESTS_SYSTEM,
    user: `${code}\n${factsBlock}\n\n${testsInstructions({ ext })}`,
    schemaName: 'starter_tests', jsonSchema: testsSchema.jsonSchema, timeoutMs: TIMEOUT_MS, maxOutputTokens: MAX_OUTPUT_TOKENS,
  };

  const usage: AiUsage = { inputTokens: 0, outputTokens: 0 };
  const addUsage = (u: AiUsage): void => {
    usage.inputTokens += u.inputTokens; usage.outputTokens += u.outputTokens;
    if (u.cacheReadTokens !== undefined) usage.cacheReadTokens = (usage.cacheReadTokens ?? 0) + u.cacheReadTokens;
    if (u.cacheWriteTokens !== undefined) usage.cacheWriteTokens = (usage.cacheWriteTokens ?? 0) + u.cacheWriteTokens;
  };
  const reason = `A starter test for ${show(s)}: it describes how the service behaves today, so it protects against changes but does not prove the behaviour is right.`;
  const attempt = async (request: AiRequest): Promise<{ answer: AiTests; accepted: CreatedFile[]; problems: string[] }> => {
    const { data, usage: u } = await completeValidated(ai, request, testsSchema.zod);
    addUsage(u);
    const made: CreatedFile[] = data.files.map((f) => {
      const body = f.content.replace(/\r\n/g, '\n');
      return { path: at(f.path), content: body.endsWith('\n') ? body : `${body}\n`, part: 'tests', repo: 'app', reason };
    });
    const { accepted, rejected } = validateGeneratedTests(made, s, deps.fileExists, [], packageModuleType(deps.packageJson));
    const problems = rejected.map((r) => `${r.path === '' ? 'a file' : r.path}: ${r.why}`);
    if (made.length === 0) problems.push('no test file was written');
    else if (rejected.length === 0 && !accepted.some((f) => isTestName(f.path.slice(f.path.lastIndexOf('/') + 1)))) problems.push('no test file (<name>.test.ts or .js) was written, only helpers');
    if (byteLength(accepted) > MAX_TEST_FILES * MAX_TEST_FILE_BYTES) problems.push('the files are too large together');
    return { answer: data, accepted, problems };
  };
  const tell = (e: unknown): never => { if (e instanceof Error && 'usage' in e) addUsage((e as { usage?: AiUsage }).usage ?? { inputTokens: 0, outputTokens: 0 }); throw e; };

  let got = await attempt(req).catch(tell);
  if (got.problems.length > 0) {
    const list = got.problems.slice(0, 20).map((p) => `- ${p}`).join('\n');
    got = await attempt({ ...req, user: `${req.user}\n\nThe files you wrote were refused for these reasons:\n${list}\nWrite all the files again so that none of these applies, and answer with JSON that matches the schema.` }).catch(tell);
    if (got.problems.length > 0) throw new StarterTestsError(`The starter tests for ${show(s)} were refused twice: ${got.problems.slice(0, 5).join('; ')}`, got.problems, usage);
  }
  return {
    framework: `${STARTER_FRAMEWORK} ${STARTER_VITEST_VERSION}`,
    reasons: [
      `${STARTER_FRAMEWORK} ${STARTER_VITEST_VERSION} is pipegen's reviewed test tool for Node services, so the same version runs on your machine and in CI.`,
      'The tests describe what the code does today (they are a safety net against change, not a proof that the behaviour is right).',
    ],
    files: got.accepted,
    configEdits: pkg.files.map((f) => ({ ...f, needsConfirm: true })),
    notes: [`The AI explained the starter tests for ${show(s)}: ${formatAiText(got.answer.reasoning, 300)}`],
    usage,
  };
}

const byteLength = (files: readonly CreatedFile[]): number => files.reduce((n, f) => n + Buffer.byteLength(f.content, 'utf8'), 0);
