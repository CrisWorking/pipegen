// The producer of the repo-code test tools (v0.2 Plan D, D6; ruling B2): adds pipegen's reviewed devDependencies to a Node service's
// package.json and package-lock.json, or says why it can not (a not-proven note, nothing written).
//
//   - Only the B2 pins: `vitest` + `@vitest/coverage-v8` at 5.0.5 (starter tests, or vitest coverage), or `c8` at 12.0.0 (coverage for a
//     node:test repo), each only when the package is absent from the repo's dependency fields. An existing version is never changed.
//   - `scripts.test` is set to `vitest run` only when absent or npm's default, and only with the vitest pair.
//   - The lock is generated in a temp folder that holds only package.json + package-lock.json, with empty user and global npm configs, and
//     `--before` taken from the reviewed closure's meta (NOT now - 7 days: npm would pick transitive versions outside the reviewed set).
//   - The result goes through the same judges the referee and the guard use (packageJsonProblems, the exact-text rebuild, lockProblems); a
//     lock the judge does not accept is not written.
//   - v0.2 scope (S13): an npm service with its own package-lock.json. Everything else gets one not-proven note.
//   - The npm runner is injected, so tests run offline on fixture locks.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CreatedFile, ReviewedTool, Service } from '../types.js';
import { activeSafeText } from '../util/known-values.js';
import { packageDataPath } from '../util/package-data.js';
import { buildPackageJson } from './package-edit.js';
import { B2_DEVDEPS, lockProblems, packageJsonProblems, parseJsonStrict } from './package-rules.js';
import { loadReviewedClosure, type ReviewedClosure } from './reviewed-closure.js';

/** Which reviewed tool the service needs: vitest (starter tests, vitest coverage) or c8 (coverage for a node:test repo). */
export type NpmTool = 'vitest' | 'c8';
const VITEST_PAIR = ['vitest', '@vitest/coverage-v8'] as const;
const MAX_LOCK_BYTES = 8 * 1024 * 1024;
/** The registry npm is told to use, and the only one the lock judge accepts. */
export const NPM_REGISTRY = 'https://registry.npmjs.org/';
const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;

/** Runs `npm` with `argv` in `cwd` (the runner may write package-lock.json there). Injected; the default spawns the real npm. */
export type NpmRunner = (cwd: string, argv: readonly string[], env: Readonly<Record<string, string>>) => { status: number | null; output: string };

export const spawnNpm: NpmRunner = (cwd, argv, env) => {
  const r = spawnSync('npm', [...argv], { cwd, env: { ...env }, encoding: 'utf8', timeout: 240_000, maxBuffer: 8 * 1024 * 1024 });
  return { status: r.status, output: `${r.stdout ?? ''}${r.stderr ?? ''}` };
};

export interface NpmDepsInput {
  service: Pick<Service, 'path' | 'packageManager'>;
  tool: NpmTool;
  /** package.json and package-lock.json of the service, exactly as on disk; the lock is null when the service has none of its own. */
  packageJson: string;
  packageLock: string | null;
  /** The service sits in a workspace (a parent package.json lists it). The service's own package.json is checked for `workspaces` here. */
  workspaceMember?: boolean;
  /** The reviewed list (for the closure). */
  reviewed: readonly ReviewedTool[];
  runner?: NpmRunner;
  /** The closure's `before` date, per closure id; default: data/npm-closures/<id>.meta.json. */
  closureBefore?: (id: string) => string;
  closure?: ReviewedClosure | null;
}
export interface NpmDepsResult { files: CreatedFile[]; notes: string[] }

class SkipNpm extends Error {}
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const notProven = (reason: string): NpmDepsResult => ({ files: [], notes: [reason] });

/** The closure ids whose `before` the lock is generated with (all must agree: one date for one npm run). */
const CLOSURE_OF: Record<NpmTool, string> = { vitest: 'vitest-coverage', c8: 'c8' };
const defaultBefore = (id: string): string => {
  const meta = JSON.parse(readFileSync(packageDataPath(`npm-closures/${id}.meta.json`), 'utf8')) as { before?: unknown };
  if (typeof meta.before !== 'string' || !/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(meta.before)) throw new Error('the closure meta has no usable before date');
  return meta.before;
};

const rootPrefix = (p: string): string => p.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');

/** Where the dependency `name` is declared in a package.json object, or null. */
const declaredIn = (pkg: Record<string, unknown>, name: string): string | null => DEP_FIELDS.find((f) => isObj(pkg[f]) && Object.hasOwn(pkg[f] as object, name)) ?? null;

export function planNpmDeps(input: NpmDepsInput): NpmDepsResult {
  const { service, tool } = input;
  const where = service.path === '' || service.path === '.' ? 'the service' : `the service in ${activeSafeText(service.path, 60)}`;
  if (service.packageManager !== 'npm') return notProven(`${where} does not use npm, and pipegen adds test tools only to npm packages in this version, so no test tools were added`);
  if (input.workspaceMember === true) return notProven(`${where} is a member of an npm workspace, so its lockfile is the workspace root's; pipegen does not edit it in this version`);
  if (input.packageLock === null) return notProven(`${where} has no package-lock.json of its own, so pipegen can not add test tools with a proven lock`);
  if (input.packageJson.length > 1024 * 1024 || input.packageLock.length > MAX_LOCK_BYTES) return notProven(`package.json or package-lock.json of ${where} is too large to edit`);
  let pkg: unknown;
  try { pkg = parseJsonStrict(input.packageJson); } catch { return notProven(`package.json of ${where} can not be read as plain JSON, so no test tools were added`); }
  if (!isObj(pkg)) return notProven(`package.json of ${where} is not a JSON object`);
  if (Object.hasOwn(pkg, 'workspaces')) return notProven(`package.json of ${where} has \`workspaces\`; pipegen edits only a single npm package in this version`);
  if (Object.hasOwn(pkg, 'packageManager') && !(typeof pkg.packageManager === 'string' && /^npm@/.test(pkg.packageManager))) return notProven(`package.json of ${where} names a package manager other than npm`);

  // what to add, and what is already there
  const notes: string[] = [];
  const add: Record<string, string> = {};
  if (tool === 'vitest') {
    const vitestIn = declaredIn(pkg, 'vitest');
    const dev = isObj(pkg.devDependencies) ? pkg.devDependencies : {};
    if (vitestIn !== null) {
      if (vitestIn !== 'devDependencies' || dev.vitest !== B2_DEVDEPS.vitest) return notProven(`${where} has its own Vitest (${activeSafeText(String((pkg[vitestIn] as Record<string, unknown>).vitest), 40)}); its tests run with it, but pipegen's reviewed Vitest is ${B2_DEVDEPS.vitest}, so coverage is not proven`);
      if (declaredIn(pkg, '@vitest/coverage-v8') === null) add['@vitest/coverage-v8'] = B2_DEVDEPS['@vitest/coverage-v8'] as string;
      // both there at the reviewed version: nothing to add, but scripts.test is set when it is absent or npm's default (B2)
    } else {
      if (declaredIn(pkg, '@vitest/coverage-v8') !== null) return notProven(`${where} lists @vitest/coverage-v8 without Vitest ${B2_DEVDEPS.vitest}, and pipegen does not change an existing version, so coverage is not proven`);
      for (const n of VITEST_PAIR) add[n] = B2_DEVDEPS[n] as string;
    }
  } else {
    const at = declaredIn(pkg, 'c8');
    if (at !== null) {
      const v = (pkg[at] as Record<string, unknown>).c8;
      return at === 'devDependencies' && v === B2_DEVDEPS.c8 ? { files: [], notes: [] } : notProven(`${where} has its own c8 (${activeSafeText(String(v), 40)}); pipegen's reviewed c8 is ${B2_DEVDEPS.c8}, so coverage is not proven`);
    }
    add.c8 = B2_DEVDEPS.c8 as string;
  }
  const scripts = isObj(pkg.scripts) ? pkg.scripts : {};
  const setTest = tool === 'vitest' && (scripts.test === undefined || scripts.test === 'echo "Error: no test specified" && exit 1');
  if (Object.keys(add).length === 0 && !setTest) return { files: [], notes: [] };   // everything is already there
  const newJson = buildPackageJson(input.packageJson, { add, setTest });
  if (newJson === null) return notProven(`package.json of ${where} has a shape pipegen can not edit in place, so no test tools were added`);
  const problems = packageJsonProblems(input.packageJson, newJson);
  if (problems.length > 0) return notProven(`the package.json edit for ${where} did not pass pipegen's own check, so it is not written`);

  // the lock, generated in a temp folder with only these two files
  const closureId = CLOSURE_OF[tool];
  let before: string;
  try { before = (input.closureBefore ?? defaultBefore)(closureId); } catch { return notProven(`pipegen's reviewed closure for ${closureId} has no usable date, so the lockfile can not be generated`); }
  const closure = input.closure === undefined ? loadReviewedClosure(input.reviewed) : input.closure;
  const run = input.runner ?? spawnNpm;
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-npm-deps-'));
  let newLock: string;
  try {
    if (Object.keys(add).length === 0) throw new SkipNpm();   // only scripts.test changes: the lock stays as it is
    const empty1 = join(dir, 'user.npmrc');
    const empty2 = join(dir, 'global.npmrc');
    const home = join(dir, 'home');
    const work = join(dir, 'work');
    writeFileSync(empty1, ''); writeFileSync(empty2, '');
    mkdirSync(home); mkdirSync(work);
    writeFileSync(join(work, 'package.json'), newJson);
    writeFileSync(join(work, 'package-lock.json'), input.packageLock);
    const argv = ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', '--save-exact', `--before=${before}`, `--registry=${NPM_REGISTRY}`];
    const env = { PATH: process.env.PATH ?? '', HOME: home, npm_config_userconfig: empty1, npm_config_globalconfig: empty2 };
    const r = run(work, argv, env);
    if (r.status !== 0) return notProven(`npm could not generate the lockfile for ${where} (a private registry, a workspace or a conflict?), so no test tools were added`);
    const lockPath = join(work, 'package-lock.json');
    const text = readFileSync(lockPath, 'utf8');
    if (text.length > MAX_LOCK_BYTES) return notProven(`the generated lockfile for ${where} is too large`);
    // npm may have rewritten package.json too; pipegen writes its own text, and the lock must agree with it
    newLock = text;
  } catch (e) {
    if (!(e instanceof SkipNpm)) return notProven(`the lockfile for ${where} could not be generated, so no test tools were added`);
    newLock = input.packageLock;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const lp = lockProblems(input.packageLock, newLock, { packageJson: newJson, closure });
  if (lp.length > 0) return notProven(`the generated lockfile for ${where} is not provably the reviewed one, so no test tools were added`);

  const prefix = rootPrefix(service.path);
  const at = (n: string): string => (prefix === '' ? n : `${prefix}/${n}`);
  const names = Object.keys(add).join(' and ');
  const reason = `Adds ${names} at the reviewed version${setTest ? ' and sets the test script to vitest run' : ''} so tests and coverage can run.`;
  return {
    files: [
      { path: at('package.json'), content: newJson, part: 'tests', reason, repo: 'app', needsConfirm: true, edited: { original: input.packageJson } },
      { path: at('package-lock.json'), content: newLock, part: 'tests', reason: `Records ${names} and what it needs in the lockfile, from the registry, at the reviewed versions.`, repo: 'app', needsConfirm: true, edited: { original: input.packageLock } },
    ],
    notes,
  };
}
