// A harness that really runs a rendered step in a temp folder (no network): a sandbox with a runner temp and a workspace,
// the step's env as the runner would set it, and stand-ins for the installed tools.
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, expect } from 'vitest';
import type { RenderedStep } from '../../src/engine/render-step.js';

export const FIXED_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

const tmps: string[] = [];
// a checker's install tree and a finished result folder are made read-only, so the sandbox is made writable again first
afterAll(() => { for (const d of tmps) { spawnSync('chmod', ['-R', 'u+w', d]); rmSync(d, { recursive: true, force: true }); } });
export interface Sandbox { dir: string; rt: string; ws: string }
export function sandbox(): Sandbox {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-6b-'));
  tmps.push(dir);
  const rt = join(dir, 'rt');
  const ws = join(dir, 'ws');
  mkdirSync(rt);
  mkdirSync(ws);
  return { dir, rt, ws };
}
/** The step's env as the runner would set it (a `${{ secrets.X }}` is replaced by the given value), plus the runner's own variables. */
export function stepEnv(step: RenderedStep, sb: Sandbox, declared: Record<string, string> = {}, extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = { PATH: process.env.PATH ?? FIXED_PATH, RUNNER_TEMP: sb.rt, GITHUB_WORKSPACE: sb.ws, ...extra };
  for (const [k, v] of Object.entries(step.env ?? {})) env[k] = v.replace(/^\$\{\{ secrets\.([A-Z0-9_]+) \}\}$/, (_m, n: string) => declared[n] ?? '');
  return env;
}
export function exec(step: RenderedStep, sb: Sandbox, env: Record<string, string>): { status: number | null; stdout: string; stderr: string } {
  expect(step.shell).toBe('bash');
  const r = spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', step.run ?? ''], { cwd: sb.ws, env, encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}
/** A stand-in for the installed tool: records its argv (NUL separated) and its environment into the working folder. */
export function fakeTool(sb: Sandbox, artifact: string, exe: string, extra = ''): void {
  const dir = join(sb.rt, 'pipegen-bin', artifact);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, exe);
  writeFileSync(path, `#!/bin/sh\nfor a in "$@"; do printf '%s\\0' "$a"; done > ./argv.bin\nenv > ./env.txt\n${extra}\n`);
  chmodSync(path, 0o755);
}
export const argvOf = (sb: Sandbox): string[] => readFileSync(join(sb.ws, 'argv.bin'), 'utf8').split('\0').slice(0, -1);
export const envNames = (sb: Sandbox): string[] => readFileSync(join(sb.ws, 'env.txt'), 'utf8').split('\n').filter((l) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(l)).map((l) => l.slice(0, l.indexOf('=')));

