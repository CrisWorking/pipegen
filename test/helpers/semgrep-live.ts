// Live-test helper (PIPEGEN_LIVE_TESTS=1): the pinned semgrep (the version of the reviewed entry) as a pip venv, because the
// reviewed step runs it in a docker image that CI test machines may not have. PIPEGEN_SEMGREP_BIN names an existing binary.
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { entry } from './render.js';
import { makeTempDir } from './make-repo.js';

export function semgrepBin(): string {
  const given = process.env.PIPEGEN_SEMGREP_BIN;
  if (given !== undefined && given !== '') return given;
  const version = entry('semgrep').step.cli?.install.version as string;
  const venv = join(homedir(), '.cache', 'pipegen-test', `semgrep-${version}`);
  const bin = join(venv, 'bin', 'semgrep');
  if (!existsSync(bin)) {
    mkdirSync(join(homedir(), '.cache', 'pipegen-test'), { recursive: true });
    execFileSync('python3', ['-m', 'venv', venv], { stdio: 'pipe' });
    execFileSync(join(venv, 'bin', 'pip'), ['install', '--quiet', `semgrep==${version}`], { stdio: 'pipe', timeout: 600_000 });
  }
  return bin;
}

/** A rule that flags `eval(...)` in JavaScript: every file the scan reads shows up as a result. */
export function evalRule(): string {
  const path = join(makeTempDir(), 'rule.yaml');
  writeFileSync(path, 'rules:\n- id: eval\n  pattern: eval(...)\n  message: eval\n  languages: [javascript]\n  severity: ERROR\n');
  return path;
}

/** The files semgrep reports in `cwd`, sorted; the environment is only a fresh HOME (no ambient settings). */
export function semgrepPaths(bin: string, cwd: string, args: string[], rule = evalRule()): string[] {
  const home = makeTempDir();
  const r = spawnSync(bin, ['scan', '--metrics=off', '--disable-version-check', '--config', rule, '--json', ...args], { cwd, encoding: 'utf8', env: { HOME: home, PATH: process.env.PATH ?? '' } });
  const out = JSON.parse(r.stdout) as { results: { path: string }[] };
  return out.results.map((x) => x.path).sort();
}
