// The secret-scanner upgrade checklist (Plan P P34-P38, Plan R): any betterleaks or gitleaks version bump in
// data/pinned-binaries.yml must pass these live tests, on the real pinned binaries, before it merges and before a
// release:
//   1. the canary tests: every scanned file and every piece of the file list must be confirmed by its canary, and a scan
//      path the scanners skip fails closed;
//   2. the belt drift test: the belt mirrors every folder-level pattern of each scanner's default path allowlist;
//   3. the chunk-size pin test: two files of exactly SCAN_CHUNK_SAFE_BYTES are read whole (every token reported). If it
//      fails, lower SCAN_CHUNK_SAFE_BYTES; never skip the test.
// A live test that is skipped passes in vitest, so the exit code alone proves nothing: this script runs the scanner
// live test files with PIPEGEN_LIVE_TESTS=1 and vitest's JSON report, and fails unless each required test is there and
// passed, and every other test in those files passed too. Run by the `test` job in .github/workflows/ci.yml (every pull
// request, so every scanner bump) and by scripts/release-check.ts (check 7). By hand: `node scripts/scanner-live.ts`.
// Keep to syntax Node's type stripping can run.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** The live test files run together: the required tests' file and the two scanners' own live tests. */
export const SCANNER_LIVE_FILES = ['test/secret-scan-skip-live.test.ts', 'test/betterleaks-live.test.ts', 'test/gitleaks-live.test.ts'] as const;

export interface RequiredTest { label: string; file: string; title: RegExp }

/** The three required tests (the canary tests are two), matched by title. A rename must update this list (code owner review). */
export const REQUIRED_SCANNER_TESTS: readonly RequiredTest[] = Object.freeze([
  { label: 'canary: a skipped scan path fails closed', file: 'test/secret-scan-skip-live.test.ts', title: /the canary alone fails closed/ },
  { label: 'canary: every file and every paths piece confirmed', file: 'test/secret-scan-skip-live.test.ts', title: /both scanners report every canary/ },
  { label: 'belt drift', file: 'test/secret-scan-skip-live.test.ts', title: /^live \(belt drift\)/ },
  { label: 'chunk-size pin', file: 'test/secret-scan-skip-live.test.ts', title: /^live \(P38 pin\)/ },
]);

export interface ScannerCheck { name: string; ok: boolean; problems: string[] }

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const NAME = 'secret-scanner live tests (canary, belt drift, chunk-size pin)';

/** Judges vitest's JSON report (`--reporter=json`) of a run of SCANNER_LIVE_FILES under `root`. Fails closed. */
export function checkScannerLive(report: unknown, root: string): ScannerCheck {
  const problems: string[] = [];
  const files = isObj(report) && Array.isArray(report.testResults) ? report.testResults.filter(isObj) : null;
  if (files === null) return { name: NAME, ok: false, problems: ['no readable vitest report: the live tests did not run (failing closed)'] };
  const norm = (p: unknown) => String(p).replaceAll('\\', '/');
  const base = norm(root).replace(/\/$/, '');
  const fileOf = (rel: string) => files.find((f) => norm(f.name) === `${base}/${rel}` || norm(f.name).endsWith(`/${rel}`));
  const testsOf = (f: Obj | undefined) => (f !== undefined && Array.isArray(f.assertionResults) ? f.assertionResults.filter(isObj) : []);
  for (const rel of SCANNER_LIVE_FILES) {
    const f = fileOf(rel);
    const tests = testsOf(f);
    if (f === undefined || tests.length === 0) {
      problems.push(`${rel} did not run (no test results)`);
      continue;
    }
    for (const t of tests) if (t.status !== 'passed') problems.push(`${rel}: "${String(t.title)}" is ${String(t.status)}, not passed`);
  }
  for (const r of REQUIRED_SCANNER_TESTS) {
    const hits = testsOf(fileOf(r.file)).filter((t) => r.title.test(String(t.title)));
    if (hits.length === 0) problems.push(`${r.label}: not found in ${r.file} (renamed or deleted? update scripts/scanner-live.ts with owner review)`);
    else for (const t of hits) if (t.status !== 'passed') problems.push(`${r.label}: ${String(t.status)}, not passed (a scanner bump must pass it live; never skip it)`);
  }
  return { name: NAME, ok: problems.length === 0, problems: [...new Set(problems)] };
}

/** Runs SCANNER_LIVE_FILES live under `root` (downloads the pinned scanners once) and judges the report. */
export function runScannerLive(root: string): ScannerCheck {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-scanner-live-'));
  const out = join(dir, 'report.json');
  try {
    try {
      execFileSync(process.execPath, [join(root, 'node_modules', 'vitest', 'vitest.mjs'), 'run', ...SCANNER_LIVE_FILES, '--reporter=default', '--reporter=json', `--outputFile.json=${out}`], {
        cwd: root, env: { ...process.env, PIPEGEN_LIVE_TESTS: '1' }, stdio: ['ignore', 'inherit', 'inherit'], timeout: 30 * 60_000,
      });
    } catch {
      // a failing test exits non-zero; the report says which (no report at all fails below)
    }
    let report: unknown = null;
    try {
      report = JSON.parse(readFileSync(out, 'utf8'));
    } catch {
      report = null;
    }
    return checkScannerLive(report, root);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  const c = runScannerLive(process.cwd());
  console.log([`${c.ok ? 'ok  ' : 'FAIL'} ${c.name}`, ...c.problems.map((p) => `       ${p}`)].join('\n'));
  process.exit(c.ok ? 0 : 1);
}
