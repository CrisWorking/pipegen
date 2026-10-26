import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

const fixtures = resolve(import.meta.dirname, '../fixtures/repos');
const made: string[] = [];

/** A fresh empty temp dir, removed by cleanupRepos(). */
export function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-test-'));
  made.push(dir);
  return dir;
}

/** Copies a fixture to a temp dir, runs `git init` (test-only; pipegen itself never runs git), optionally adds `origin`. */
export function makeRepo(fixture: string, remote?: string): string {
  const dir = makeTempDir();
  cpSync(join(fixtures, fixture), dir, { recursive: true });
  execFileSync('git', ['init', '-q'], { cwd: dir, stdio: 'pipe' });
  if (remote) execFileSync('git', ['remote', 'add', 'origin', remote], { cwd: dir, stdio: 'pipe' });
  return dir;
}

export function writeIn(dir: string, rel: string, content: string): void {
  const path = join(dir, rel);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

export function cleanupRepos(): void {
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true });
}
