// Plan C, C1b fix round 2, review R1-I1: a repo `.gitleaksignore` / `.betterleaksignore` (a `file:rule:line` entry) silences a finding, and
// `--gitleaks-ignore-path` does not turn that off (the scan root's file is always read). So the rendered secrets step deletes every such
// file under the scan root before the scan, links included and never followed, as semgrep's scope step does for `.semgrepignore`.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { NEED_IDS } from '../src/engine/need-ids.js';
import { renderStep, type RenderedStep } from '../src/engine/render-step.js';
import { ARGV_POLICIES } from '../src/engine/tool-flags.js';
import type { ReviewedTool } from '../src/types.js';
import { parseSarifText } from '../gate/src/sarif.js';
import { ctxFor, entry, platform, reviewedList, service, specFor } from './helpers/render.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { git, runEntry } from './helpers/secrets-live.js';
import { sandbox } from './helpers/step-harness.js';

const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
const ctx = ctxFor([service({ name: 'app', path: '.' })], { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080' });
const stepOf = (id: string): RenderedStep => {
  const t = entry(id);
  return renderStep(specFor(t, { needId: needFor(t) }), t, platform(), ctx).steps.filter((s) => s.run !== undefined).at(-1) as RenderedStep;
};
const BEGIN = '# pipegen ignore files: begin';
const END = '# pipegen ignore files: end';
const blockOf = (run: string): string[] => {
  const lines = run.split('\n');
  const a = lines.indexOf(BEGIN);
  const b = lines.indexOf(END);
  return a < 0 || b < a ? [] : lines.slice(a, b + 1);
};
const SYS = 'sys=(/usr/bin/env -i "PATH=/usr/local/bin:/usr/bin:/bin")\npg_fail() { echo "pipegen: $1" >&2; exit 1; }';
const bash = (script: string, cwd: string) => spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script], { cwd, encoding: 'utf8' });
const NAMES = ['.gitleaksignore', '.betterleaksignore'];

describe('the secrets steps remove the repo ignore files', () => {
  it('the policy: both secrets tools name the ignore files they read; no other tool has the field', () => {
    for (const [id, pol] of Object.entries(ARGV_POLICIES)) {
      if (id === 'betterleaks' || id === 'gitleaks') expect([...(pol.removeFiles ?? [])].sort(), id).toEqual([...NAMES].sort());
      else expect(pol.removeFiles, id).toBeUndefined();
    }
  });

  it('the rendered step has the block before the tool starts, and no other step has it', () => {
    for (const id of ['betterleaks', 'gitleaks']) {
      const run = stepOf(id).run as string;
      const block = blockOf(run).join('\n');
      for (const n of NAMES) expect(block, `${id} ${n}`).toContain(`-name ${n}`);
      expect(run.indexOf(BEGIN), id).toBeGreaterThan(-1);
      expect(run.indexOf(END), id).toBeLessThan(run.indexOf(`/${id}" dir`));
      expect(spawnSync('bash', ['-n'], { input: run, encoding: 'utf8' }).status, id).toBe(0);
    }
    for (const t of reviewedList()) {
      if (t.id === 'betterleaks' || t.id === 'gitleaks' || t.step.cli === undefined || ARGV_POLICIES[t.id] === undefined) continue;
      let st: RenderedStep | undefined;
      try { st = stepOf(t.id); } catch { continue; }
      expect(blockOf(st.run as string), t.id).toEqual([]);
    }
  });

  for (const id of ['betterleaks', 'gitleaks']) {
    it(`${id}: really run: nested and root ignore files (a file and a link) are gone, a link's target is untouched, other files stay`, () => {
      const block = blockOf(stepOf(id).run as string).join('\n');
      const sb = sandbox();
      mkdirSync(join(sb.ws, 'a/b'), { recursive: true });
      for (const n of NAMES) {
        writeFileSync(join(sb.ws, n), 'a.js:rule:1\n');
        writeFileSync(join(sb.ws, 'a', n), 'a.js:rule:1\n');
      }
      const outside = join(sb.dir, 'outside.txt');
      writeFileSync(outside, 'KEEP\n');
      symlinkSync(outside, join(sb.ws, 'a/b/.gitleaksignore'));
      symlinkSync('/nonexistent/target', join(sb.ws, 'a/b/.betterleaksignore'));
      writeFileSync(join(sb.ws, 'a/keep.txt'), 'KEEP\n');
      writeFileSync(join(sb.ws, '.gitleaksignore.bak'), 'KEEP\n');
      const r = bash(`${SYS}\n${block}`, sb.ws);
      expect(r.status, r.stderr).toBe(0);
      const gone = (p: string) => { try { lstatSync(join(sb.ws, p)); return false; } catch { return true; } };
      for (const n of NAMES) for (const d of ['', 'a/', 'a/b/']) expect(gone(`${d}${n}`), `${d}${n}`).toBe(true);
      expect(readFileSync(outside, 'utf8')).toBe('KEEP\n');
      expect(readFileSync(join(sb.ws, 'a/keep.txt'), 'utf8')).toBe('KEEP\n');
      expect(existsSync(join(sb.ws, '.gitleaksignore.bak'))).toBe(true);
    });

    it(`${id}: really run: a folder with an ignore file's name at the scan root fails the step with a pipegen message and nothing in it is touched`, () => {
      const block = blockOf(stepOf(id).run as string).join('\n');
      for (const n of NAMES) {
        const sb = sandbox();
        mkdirSync(join(sb.ws, n));
        writeFileSync(join(sb.ws, n, 'keep.txt'), 'KEEP\n');
        const r = bash(`${SYS}\n${block}`, sb.ws);
        expect(r.status, n).toBe(1);
        expect(r.stderr, n).toMatch(/^pipegen: the repository has a folder named \.\w+ignore at the scan root/);
        expect(r.stderr).not.toMatch(/Is a directory|line \d+/);
        expect(readdirSync(join(sb.ws, n))).toEqual(['keep.txt']);
      }
    });
  }
});

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
describe.skipIf(!live)('live: a repo ignore entry no longer hides a finding (r1-ign), with the pinned binaries', () => {
  const bins: Record<string, string> = {};
  beforeAll(async () => {
    bins.betterleaks = await ensurePinnedBinary('betterleaks');
    bins.gitleaks = await ensurePinnedBinary('gitleaks');
  }, 600_000);
  afterAll(cleanupRepos);

  for (const id of ['betterleaks', 'gitleaks'] as const) {
    for (const ignoreName of id === 'gitleaks' ? ['.gitleaksignore'] : NAMES) {   // gitleaks reads only .gitleaksignore
      it(`${id}: an entry in ${ignoreName} (root and nested) silences the scan without the step's block, and the block restores the finding`, () => {
        const key = 'sk' + '_live_' + createHash('sha256').update('ign').digest('hex').slice(0, 24);
        const make = () => {
          const dir = makeTempDir();
          git(dir, 'init', '-q');
          writeIn(dir, 'a.js', `stripe = "${key}"\n`);
          writeIn(dir, 'sub/b.js', `stripe = "${key}"\n`);
          git(dir, 'add', '-A');
          git(dir, 'commit', '-q', '-m', 'x');
          return dir;
        };
        const count = (dir: string) => parseSarifText(runEntry(id, bins[id], dir), id, { workspace: dir }).findings.length;
        const plain = make();
        expect(count(plain), 'control').toBe(2);
        const ruleId = parseSarifText(runEntry(id, bins[id], plain), id, { workspace: plain }).findings[0].ruleId.replace(/^sec[r]et:/, '');
        const ignored = make();
        writeIn(ignored, ignoreName, `a.js:${ruleId}:1\nsub/b.js:${ruleId}:1\n`);
        execFileSync('git', ['add', '-A'], { cwd: ignored });
        expect(count(ignored), 'the repo ignore file hides both findings (the gap)').toBe(0);
        const block = blockOf(stepOf(id).run as string).join('\n');
        const r = bash(`${SYS}\n${block}`, ignored);
        expect(r.status, r.stderr).toBe(0);
        expect(count(ignored), 'after the block').toBe(2);
      });
    }
  }
});
