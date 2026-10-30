// A stub linter executable for the linters tests: a small sh script that records each run (argv, cwd, env, the files it can
// see, the config file it was given) and prints canned output, then exits with a canned code.
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { makeTempDir } from './make-repo.js';

export interface Rec { args: string[]; cwd: string; env: Record<string, string>; files: string[]; cfg: string[] }
export interface Stub { bin: string; set(out: string, code?: number): void; records(): Rec[] }

/** A stub linter: records each run (appended) and prints `out`, then exits with `code`. */
export function stub(): Stub {
  const dir = makeTempDir();
  const bin = join(dir, 'linter-stub.sh');
  writeFileSync(join(dir, 'out'), '');
  writeFileSync(bin, `#!/bin/sh
d='${dir}'
{
echo '@@ARGS'; for a in "$@"; do printf '%s\\n' "$a"; done
echo '@@CWD'; pwd
echo '@@ENV'; /usr/bin/env
echo '@@FILES'; /usr/bin/find . -type f
prev=''; for a in "$@"; do case "$prev" in --config|-config-file) echo '@@CFG'; /bin/cat "$a";; esac; prev="$a"; done
echo '@@END'
} >> "$d/rec"
/bin/cat "$d/out"
exit $(/bin/cat "$d/code")
`);
  chmodSync(bin, 0o700);
  writeFileSync(join(dir, 'code'), '0');
  return {
    bin,
    set(out, code = 0) { writeFileSync(join(dir, 'out'), out); writeFileSync(join(dir, 'code'), String(code)); },
    records() {
      const text = existsSync(join(dir, 'rec')) ? readFileSync(join(dir, 'rec'), 'utf8') : '';
      return text.split('@@ARGS\n').slice(1).map((chunk) => {
        const sec = (name: string, next: string) => chunk.split(`@@${name}\n`)[1]?.split(`@@${next}\n`)[0]?.split('\n').filter((l) => l !== '') ?? [];
        const env = Object.fromEntries(sec('ENV', 'FILES').filter((l) => !/^(PWD|OLDPWD|SHLVL|_)=/.test(l)).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
        const cfgPart = chunk.split('@@CFG\n')[1]?.split('@@END\n')[0] ?? '';
        return {
          args: chunk.split('@@CWD\n')[0]?.split('\n').slice(0, -1) ?? [],
          cwd: sec('CWD', 'ENV')[0] ?? '', env, files: sec('FILES', chunk.includes('@@CFG') ? 'CFG' : 'END').sort(), cfg: cfgPart === '' ? [] : [cfgPart],
        };
      });
    },
  };
}

