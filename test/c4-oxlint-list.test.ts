// Plan C Task C4 fix round 2 (review-C4-r1.md, ruling 3): oxlint 1.89.0 walks a directory with the `ignore` crate, so a nested .gitignore
// hides tracked files from it and no flag turns that off (its --no-ignore covers .eslintignore only). It does lint every file it is
// GIVEN. So the rendered step lints an explicit list: the regular tracked files with oxlint's extensions (`git ls-files -z -s`, mode
// 100644/100755), through `xargs -0 -r`, with `--no-ignore --`. xargs exit 123 (a batch had findings) fails the step. An empty list is
// "0 files checked": the step succeeds with a notice and never shows it as coverage.
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { fileListLines, fileListRun, OXLINT_EXTENSIONS } from '../src/engine/render-cli.js';
import { renderStepWith } from '../src/engine/render-step.js';
import { ARGV_POLICIES } from '../src/engine/tool-flags.js';
import { ctxFor, entry, platform, service, specFor } from './helpers/render.js';

const run = (): string => {
  const t = entry('oxlint-typeaware');
  const r = renderStepWith(specFor(t, { needId: 'lint' }), t, platform(), ctxFor([service({ name: 'app', path: '.' })]));
  return r.steps.filter((s) => s.run !== undefined).at(-1)?.run ?? '';
};

describe('oxlint runs over an explicit list of tracked files', () => {
  it('the entry and the policy: --no-ignore is required, the policy names the extensions, .gitignore and .eslintignore are not protected configs', () => {
    const t = entry('oxlint-typeaware');
    expect(t.step.cli?.command).toEqual(['oxlint', '--type-aware', '--deny-warnings', '--no-ignore']);
    expect(t.fixedInputs.args).toEqual(['--type-aware', '--deny-warnings', '--no-ignore']);
    expect(ARGV_POLICIES['oxlint-typeaware']?.required?.['no-ignore']).toBe('true');
    expect(ARGV_POLICIES['oxlint-typeaware']?.fileList?.extensions).toEqual([...OXLINT_EXTENSIONS]);
    for (const n of ['.gitignore', '.eslintignore', '.ignore']) expect(t.configFiles).not.toContain(n);
  });
  it('the rendered step builds the list from git ls-files -z -s, keeps modes 100644/100755 and the extensions, runs xargs -0 -r with --no-ignore --, and passes the exit code on', () => {
    const r = run();
    expect(r).toContain('git ls-files -z -s -- .');
    expect(r).toMatch(/100644\|100755\) ;; \*\) continue ;; esac/);
    for (const e of OXLINT_EXTENSIONS) expect(r).toContain(`*.${e}`);
    expect(r).toMatch(/xargs -0 -r -a "\$list" "\$\{pg_env\[@\]\}" .*oxlint" --config "[^"]+" --type-aware --deny-warnings --no-ignore --\s*\|\| rc=\$\?/);
    expect(r).not.toMatch(/oxlint" [^\n]* \. \|\| rc/);   // no directory argument any more
    expect(r).toContain('exit "$rc"');
    expect(r).toContain('0 files');
  });
  it('the list helper refuses an extension that is not a plain word', () => {
    expect(() => fileListLines(['js', 'x;rm'], '"$list"')).toThrow();
    expect(() => fileListLines([], '"$list"')).toThrow();
  });
});

// a live check of the exact shell the renderer emits, with the pinned oxlint (npm oxlint 1.89.0 and its binding); set PIPEGEN_LIVE_OXLINT to
// node_modules/.bin/oxlint of an install of the pinned versions (see task-C4-report.md); skipped without it
const OXLINT = process.env.PIPEGEN_LIVE_OXLINT ?? '/tmp/c4npm/node_modules/.bin/oxlint';
describe.skipIf(!existsSync(OXLINT) || process.platform === 'win32')('live, with the pinned oxlint', () => {
  const sh = (dir: string, body: string): { code: number | null; out: string } => {
    const script = ['set -euo pipefail', `sys=(/usr/bin/env -i "PATH=/usr/local/bin:/usr/bin:/bin" "HOME=${dir}")`, `pg_env=(/usr/bin/env -i "PATH=/usr/local/bin:/usr/bin:/bin" "HOME=${dir}")`, `list="${dir}/list.bin"`, 'cd -- "$1"', body].join('\n');
    const r = spawnSync('bash', ['-c', script, 'bash', join(dir, 'repo')], { encoding: 'utf8' });
    return { code: r.status, out: `${r.stdout}${r.stderr}` };
  };
  const body = (): string => [
    ...fileListLines([...OXLINT_EXTENSIONS], '"$list"'),
    'rc=0',
    ...fileListRun(`"\${pg_env[@]}" "${OXLINT}" --deny-warnings --no-ignore`, '"$list"'),
    'exit "$rc"',
  ].join('\n');
  const repo = (): string => {
    const dir = mkdtempSync(join(tmpdir(), 'pg-oxl-'));
    mkdirSync(join(dir, 'repo/src/sub'), { recursive: true });
    mkdirSync(join(dir, 'repo/.git'), { recursive: true });
    spawnSync('git', ['init', '-q', join(dir, 'repo')]);
    return dir;
  };
  const add = (dir: string, rel: string, text: string): void => { mkdirSync(join(dir, 'repo', rel, '..'), { recursive: true }); writeFileSync(join(dir, 'repo', rel), text); spawnSync('git', ['-C', join(dir, 'repo'), 'add', '-f', '--', rel]); };
  it('a tracked file hidden by a nested .gitignore is linted (the directory run says "No files found to lint")', () => {
    const dir = repo();
    add(dir, 'src/sub/.gitignore', '*\n');
    add(dir, 'src/sub/bad.js', 'debugger;\n');
    const dirRun = spawnSync(OXLINT, ['--deny-warnings', 'src'], { cwd: join(dir, 'repo'), encoding: 'utf8' });
    expect(`${dirRun.stdout}${dirRun.stderr}`).toMatch(/No files found/);
    const r = sh(dir, body());
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toMatch(/bad\.js/);
  });
  it('a clean list passes; a symlink and a non-lintable name are not listed; an empty list is "0 files" and succeeds', () => {
    const dir = repo();
    add(dir, 'src/ok.js', 'export const a = 1;\n');
    add(dir, 'README.md', 'debugger;\n');
    symlinkSync('/etc/passwd', join(dir, 'repo/src/link.js'));
    spawnSync('git', ['-C', join(dir, 'repo'), 'add', '-f', 'src/link.js']);
    const ok = sh(dir, body());
    expect(ok.code, ok.out).toBe(0);
    const empty = repo();
    add(empty, 'README.md', 'x\n');
    const e = sh(empty, body());
    expect(e.code, e.out).toBe(0);
    expect(e.out).toContain('0 files');
  });
  it('findings in any batch fail the step (xargs exit 123 is kept), also when another batch is clean', () => {
    const dir = repo();
    add(dir, 'a.js', 'export const a = 1;\n');
    add(dir, 'b.js', 'debugger;\n');
    const r = sh(dir, body().replace('xargs -0 -r', 'xargs -0 -r -n 1'));
    expect(r.code, r.out).toBe(123);
  });
  it('a path that starts with a dash is a file, not a flag', () => {
    const dir = repo();
    add(dir, '-weird.js', 'debugger;\n');
    const r = sh(dir, body());
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toMatch(/weird\.js/);
  });
});
void chmodSync;
