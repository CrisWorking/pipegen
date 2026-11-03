// A small local git repo with one commit (E3 harness/compat tests). No network.
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

// ---------- a git repo for the compat reads ----------
export function gitRepoWith(files: Record<string, string>): string {
  const dir = execFileSync('mktemp', ['-d']).toString().trim();
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' };
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: dir, env });
  for (const [p, c] of Object.entries({ 'README.md': 'x\n', ...files })) {
    execFileSync('mkdir', ['-p', join(dir, p, '..')]);
    execFileSync('bash', ['-c', 'cat > "$1"', '_', join(dir, p)], { input: c });
  }
  execFileSync('git', ['add', '-A'], { cwd: dir, env });
  execFileSync('git', ['commit', '-q', '-m', 'x'], { cwd: dir, env });
  return dir;
}
