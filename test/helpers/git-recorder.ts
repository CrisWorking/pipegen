// A `git` wrapper for the git transport tests (E0c): put first on PATH, it records each call's argv and the exact
// environment it was started with (/proc/self/environ of the wrapper, Linux), plus the askpass script, its mode and its
// directory's mode when GIT_ASKPASS is set, then execs the real git. Paths are baked into the script, because the
// transport hands git an environment built from scratch (no variable of ours would reach the wrapper).
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const REAL_GIT = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).trim();

export interface GitCall {
  argv: string[];
  env: Record<string, string>;
  /** The working directory git was started in. */
  cwd: string;
  askpass?: { script: string; path: string; fileMode: string; dirMode: string };
}

export interface GitRecorder {
  bin: string;
  calls(): GitCall[];
  clear(): void;
}

export function makeGitRecorder(root: string): GitRecorder {
  const bin = join(root, 'bin');
  const rec = join(root, 'rec');
  mkdirSync(bin, { recursive: true });
  mkdirSync(rec, { recursive: true });
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  writeFileSync(join(bin, 'git'), [
    '#!/bin/sh',
    `n=$(date +%s%N)-$$`,
    `printf '%s\\0' "$@" > ${q(rec)}/argv.$n`,
    `cat /proc/$$/environ > ${q(rec)}/env.$n 2>/dev/null`,
    `pwd -P > ${q(rec)}/cwd.$n`,
    'if [ -n "$GIT_ASKPASS" ]; then',
    `  cp "$GIT_ASKPASS" ${q(rec)}/askpass.$n`,
    `  printf '%s' "$GIT_ASKPASS" > ${q(rec)}/askpath.$n`,
    `  stat -c '%a' "$GIT_ASKPASS" > ${q(rec)}/askmode.$n`,
    `  stat -c '%a' "$(dirname "$GIT_ASKPASS")" > ${q(rec)}/askdir.$n`,
    'fi',
    // A test must never reach github.com: a push there that a check failed to refuse stops here (and the test sees exit 97).
    'case "$*" in *github.com*) echo "git recorder: refused to reach github.com" >&2; exit 97 ;; esac',
    `exec ${q(REAL_GIT)} "$@"`,
    '',
  ].join('\n'));
  chmodSync(join(bin, 'git'), 0o755);
  const read = (f: string) => readFileSync(join(rec, f), 'utf8');
  return {
    bin,
    clear: () => {
      rmSync(rec, { recursive: true, force: true });
      mkdirSync(rec, { recursive: true });
    },
    calls: () => {
      const ids = readdirSync(rec).filter((f) => f.startsWith('argv.')).map((f) => f.slice(5)).sort();
      return ids.map((id) => {
        const argv = read(`argv.${id}`).split('\0');
        argv.pop();
        const env: Record<string, string> = {};
        for (const kv of read(`env.${id}`).split('\0')) {
          if (kv === '') continue;
          const i = kv.indexOf('=');
          env[kv.slice(0, i)] = kv.slice(i + 1);
        }
        const call: GitCall = { argv, env, cwd: read(`cwd.${id}`).trim() };
        if (existsSync(join(rec, `askpass.${id}`))) {
          call.askpass = { script: read(`askpass.${id}`), path: read(`askpath.${id}`), fileMode: read(`askmode.${id}`).trim(), dirMode: read(`askdir.${id}`).trim() };
        }
        return call;
      });
    },
  };
}
