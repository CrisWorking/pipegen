// A `git` wrapper for the git transport tests (E0c): put first on PATH, it records each call's argv, the exact environment
// it was started with (/proc/self/environ of the wrapper, Linux) and its working dir, plus the askpass script, its mode and
// its directory's mode when GIT_ASKPASS is set: all as pipegen started git. Then:
// - a call that names github.com exits 97 (nothing reaches github.com), unless the test routed it (route(port)): then every
//   https://github.com/... argument becomes http://127.0.0.1:<port>/app.git (the loopback server, test/helpers/git-http.ts),
//   http is allowed, and GIT_ASKPASS points at a shim that turns git's 127.0.0.1 prompts back into the github.com ones and
//   asks pipegen's own askpass script. So the push under test is the production gitPush, argv and askpass included;
// - any other call execs the real git.
// Paths are baked into the scripts, because the transport hands git an environment built from scratch.
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
  /** Forgets the recorded calls and the route. */
  clear(): void;
  /** Sends github.com pushes to the loopback server on `port` (until clear()). */
  route(port: number): void;
  /** Drops GIT_NO_LAZY_FETCH before git starts, as a git older than that variable ignores it (until clear()). */
  oldGit(): void;
}

export function makeGitRecorder(root: string): GitRecorder {
  const bin = join(root, 'bin');
  const rec = join(root, 'rec');
  mkdirSync(bin, { recursive: true });
  mkdirSync(rec, { recursive: true });
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  const routeFile = join(root, 'route');
  const oldGitFile = join(root, 'old-git');
  const shim = join(bin, 'askpass-shim');
  writeFileSync(shim, [
    '#!/bin/sh',
    // 'http://[user@]127.0.0.1:<port>' → 'https://[user@]github.com', the user kept as git sent it.
    `p=$(printf '%s' "$1" | sed -e "s#'http://\\([^'@]*@\\)\\{0,1\\}127\\.0\\.0\\.1:[0-9]*'#'https://\\1github.com'#")`,
    'exec "$PIPEGEN_TEST_REAL_ASKPASS" "$p"',
    '',
  ].join('\n'));
  chmodSync(shim, 0o755);
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
    `if [ -f ${q(oldGitFile)} ]; then unset GIT_NO_LAZY_FETCH; fi`,
    // A test must never reach github.com: unrouted, a call naming it stops here (and the test sees exit 97).
    'case "$*" in *github.com*)',
    `  if [ -f ${q(routeFile)} ]; then`,
    `    port=$(cat ${q(routeFile)})`,
    '    for a do shift; case "$a" in https://github.com/*) a="http://127.0.0.1:$port/app.git" ;; esac; set -- "$@" "$a"; done',
    // Anything still naming github.com after the rewrite (http://github.com/..., github.com.evil, a -c value) is refused too.
    '    case "$*" in *github.com*) echo "git recorder: refused to reach github.com" >&2; exit 97 ;; esac',
    `    if [ -n "$GIT_ASKPASS" ]; then PIPEGEN_TEST_REAL_ASKPASS="$GIT_ASKPASS"; GIT_ASKPASS=${q(shim)}; export PIPEGEN_TEST_REAL_ASKPASS GIT_ASKPASS; fi`,
    `    exec ${q(REAL_GIT)} -c protocol.http.allow=always "$@"`,
    '  fi',
    '  echo "git recorder: refused to reach github.com" >&2; exit 97 ;;',
    'esac',
    `exec ${q(REAL_GIT)} "$@"`,
    '',
  ].join('\n'));
  chmodSync(join(bin, 'git'), 0o755);
  const read = (f: string) => readFileSync(join(rec, f), 'utf8');
  return {
    bin,
    route: (port: number) => writeFileSync(routeFile, String(port)),
    oldGit: () => writeFileSync(oldGitFile, ''),
    clear: () => {
      rmSync(routeFile, { force: true });
      rmSync(oldGitFile, { force: true });
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
