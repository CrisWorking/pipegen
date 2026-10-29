// Plan B 6d fix round 1, ruling 6 (DECISIONS #108): Semgrep's scan scope is pipegen's, not the repo's. Semgrep reads every
// `.semgrepignore` of the tree (the root one and nested ones) and, with none, applies built-in defaults that skip test/, tests/,
// build/, vendor/ and dist/ at any depth. A file at the scan root REPLACES the defaults (measured on semgrep 1.181.0), so the
// step deletes every repo `.semgrepignore` and writes its own, which holds only node_modules.
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { renderStep, type RenderedStep } from '../src/engine/render-step.js';
import { ARGV_POLICIES } from '../src/engine/tool-flags.js';
import { NEED_IDS } from '../src/engine/need-ids.js';
import type { ReviewedTool, StepSpec } from '../src/types.js';
import { ctxFor, entry, platform, reviewedList, service, specFor } from './helpers/render.js';
import { sandbox } from './helpers/step-harness.js';

const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
const ctx = ctxFor([service({ name: 'app', path: '.' })], { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080' });
const stepOf = (id: string, over: Partial<StepSpec> = {}): RenderedStep => {
  const t = entry(id);
  return renderStep(specFor(t, { needId: needFor(t), ...over }), t, platform(), ctx).steps.filter((s) => s.run !== undefined).at(-1) as RenderedStep;
};
const BEGIN = '# pipegen scope: begin';
const END = '# pipegen scope: end';
/** The lines of the scope block of a rendered script (between the two marker comments). */
const blockOf = (run: string): string[] => {
  const lines = run.split('\n');
  const a = lines.indexOf(BEGIN);
  const b = lines.indexOf(END);
  return a < 0 || b < a ? [] : lines.slice(a, b + 1);
};
const SYS = 'sys=(/usr/bin/env -i "PATH=/usr/local/bin:/usr/bin:/bin")';

describe('semgrep scope (ruling 6)', () => {
  it('only the semgrep policy has a scope ignore, and it holds exactly node_modules', () => {
    for (const [id, pol] of Object.entries(ARGV_POLICIES)) {
      if (id === 'semgrep') expect(pol.scopeIgnore, id).toEqual({ file: '.semgrepignore', lines: ['node_modules'] });
      else expect(pol.scopeIgnore, id).toBeUndefined();
    }
  });

  it('the semgrep step deletes every repo .semgrepignore and writes its own, before semgrep starts; no other step has the block', () => {
    const run = stepOf('semgrep').run as string;
    const block = blockOf(run);
    expect(block.length).toBeGreaterThan(2);
    expect(block.join('\n')).toContain('-name .semgrepignore');
    expect(block.join('\n')).toContain("printf '%s\\n' node_modules > .semgrepignore");
    expect(run.indexOf(BEGIN)).toBeLessThan(run.indexOf('/usr/bin/docker run'));
    expect(run).not.toContain('--no-git-ignore');
    for (const t of reviewedList()) {
      if (t.id === 'semgrep' || t.step.cli === undefined || ARGV_POLICIES[t.id] === undefined) continue;
      let st: RenderedStep | undefined;
      try { st = stepOf(t.id); } catch { continue; }
      expect(blockOf(st.run as string), t.id).toEqual([]);
    }
  });

  it('really run: nested and root repo ignore files (a file and a symlink) are gone, a symlink target is untouched, the new file is exactly node_modules', () => {
    const block = blockOf(stepOf('semgrep').run as string).join('\n');
    const sb = sandbox();
    const ws = sb.ws;
    mkdirSync(join(ws, 'a/b'), { recursive: true });
    mkdirSync(join(ws, 'src'));
    writeFileSync(join(ws, '.semgrepignore'), 'src/\ntest/\n');
    writeFileSync(join(ws, 'a/.semgrepignore'), 'b\n');
    const outside = join(sb.dir, 'outside.txt');
    writeFileSync(outside, 'KEEP\n');
    symlinkSync(outside, join(ws, 'a/b/.semgrepignore'));
    symlinkSync('/nonexistent/target', join(ws, 'src/.semgrepignore'));
    const r = spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', `${SYS}\n${block}`], { cwd: ws, encoding: 'utf8' });
    expect(r.status, r.stderr).toBe(0);
    expect(readFileSync(join(ws, '.semgrepignore'), 'utf8')).toBe('node_modules\n');
    for (const p of ['a/.semgrepignore', 'a/b/.semgrepignore', 'src/.semgrepignore']) expect(existsSync(join(ws, p)) || (() => { try { lstatSync(join(ws, p)); return true; } catch { return false; } })(), p).toBe(false);
    expect(readFileSync(outside, 'utf8')).toBe('KEEP\n');
  });

  it('really run: a root .semgrepignore that is a symlink is replaced by a regular file, and nothing is written through the link', () => {
    const block = blockOf(stepOf('semgrep').run as string).join('\n');
    const sb = sandbox();
    const victim = join(sb.dir, 'victim.txt');
    writeFileSync(victim, 'KEEP\n');
    symlinkSync(victim, join(sb.ws, '.semgrepignore'));
    const r = spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', `${SYS}\n${block}`], { cwd: sb.ws, encoding: 'utf8' });
    expect(r.status, r.stderr).toBe(0);
    expect(readFileSync(victim, 'utf8')).toBe('KEEP\n');
    expect(lstatSync(join(sb.ws, '.semgrepignore')).isFile()).toBe(true);
    expect(readFileSync(join(sb.ws, '.semgrepignore'), 'utf8')).toBe('node_modules\n');
  });

  it('the block is valid shell inside the whole script', () => {
    const r = spawnSync('bash', ['-n'], { input: stepOf('semgrep').run, encoding: 'utf8' });
    expect(r.status, r.stderr).toBe(0);
  });
});
