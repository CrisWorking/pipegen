// Plan C Task C4 fix round 1 (review-C4.md finding 1, ruling 1): tool configs are found below the folder the tool starts in, and a
// .gitignore hides tracked files from directory walkers. So (a) every configFiles name without a slash is protected at any depth,
// (b) the tools that honour .gitignore run with the flag that turns it off (checked against the pinned binaries' --help and by running
// them: ruff 0.17.1, prettier 3.9.10, knip 6.42.1, osv-scanner v2.7.0, jscpd v5.4.2), and (c) bandit's discovery of a `.bandit` file is
// replaced by an explicit empty one. oxlint 1.89.0 has no such switch (its --no-ignore only covers .eslintignore): see task-C4-report.md.
import { describe, expect, it } from 'vitest';
import { integrityFindings, type PrFile } from '../gate/src/integrity.js';
import { effectiveProtectedPaths } from '../src/engine/reviewed.js';
import { renderStepWith } from '../src/engine/render-step.js';
import { ARGV_POLICIES } from '../src/engine/tool-flags.js';
import { ctxFor, entry, platform, reviewedList, service, specFor } from './helpers/render.js';

const file = (filename: string): PrFile => ({ filename, status: 'modified', changes: 2, patch: '@@ -1 +1 @@\n-a\n+b' });
const pr = (files: PrFile[]) => ({ number: 1, headSha: 'a'.repeat(40), baseSha: 'b'.repeat(40), isFork: false, files, filesComplete: true, approvals: [], approvalsComplete: true, problems: [] });
const protectedNow = (path: string): boolean => integrityFindings(pr([file(path)]), effectiveProtectedPaths(reviewedList()), []).some((f) => f.ruleId === 'integrity:protected-path');

describe('the real reviewed list protects tool configs at any depth', () => {
  it('tests/fixtures/.bandit and services/api/mypy.ini are protected (the review-C4 probes)', () => {
    for (const p of ['tests/fixtures/.bandit', 'services/api/.bandit', '.bandit', 'services/api/mypy.ini', 'a/b/.coveragerc', 'web/knip.json', 'web/.c8rc.json', 'web/.prettierrc.json', 'web/eslint.config.mjs', 'x/.hadolint.yaml', 'x/biome.json', 'x/.gitleaksignore', 'x/.trivyignore', 'x/.semgrepignore']) {
      expect(protectedNow(p), p).toBe(true);
    }
  });
  it('.gitignore and .ignore are NOT protected anywhere (they change too often); the tools that read them are told not to', () => {
    for (const p of ['.gitignore', 'src/.gitignore', 'web/.ignore']) expect(protectedNow(p), p).toBe(false);
    for (const t of reviewedList()) {
      expect(t.configFiles, t.id).not.toContain('.gitignore');
      expect(t.configFiles, t.id).not.toContain('.ignore');
    }
  });
  it('a slash entry stays anchored', () => {
    expect(protectedNow('x/.github/workflows/a.yml')).toBe(false);
    expect(protectedNow('.github/workflows/a.yml')).toBe(true);
  });
});

describe('every tool that honours .gitignore runs with it turned off', () => {
  const runOf = (id: string): string => {
    const t = entry(id);
    const r = renderStepWith(specFor(t, { needId: t.categories[0] as string }), t, platform(), ctxFor([service({ name: 'app', path: '.' })]));
    return r.steps.filter((s) => s.run !== undefined).at(-1)?.run ?? '';
  };
  it('ruff and ruff-format: the pinned config sets respect-gitignore = false (top level, before any table), in the entry and the policy', () => {
    for (const id of ['ruff', 'ruff-format']) {
      const c = entry(id).fixedInputs.config?.content ?? '';
      expect(c.split('\n').filter((l) => !l.startsWith('#') && l.trim() !== '')[0], id).toBe('respect-gitignore = false');
      expect(ARGV_POLICIES[id]?.config?.content, id).toBe(c);
    }
    expect(entry('ruff').fixedInputs.config?.content).toContain('[lint.mccabe]');
  });
  it('knip, osv-scanner and jscpd: the flag is in the command, the fixed args and (rendered) the run step', () => {
    for (const [id, flag] of [['knip', '--no-gitignore'], ['osv-scanner', '--no-ignore'], ['jscpd', '--no-gitignore']] as const) {
      const t = entry(id);
      expect(t.step.cli?.command, id).toContain(flag);
      expect(t.fixedInputs.args, id).toContain(flag);
      expect(ARGV_POLICIES[id]?.required?.[flag.slice(2)], id).toBe('true');
      expect(runOf(id), id).toContain(` ${flag} `);
    }
  });
  it('prettier: the checkout .prettierignore is kept and a pinned empty ignore file is added, so a .gitignore hides nothing', () => {
    const t = entry('prettier');
    expect(t.fixedInputs.config?.passAs).toEqual({ flag: '--ignore-path' });
    expect((t.fixedInputs.config?.content ?? '').split('\n').every((l) => l.trim() === '' || l.startsWith('#'))).toBe(true);
    expect(t.step.cli?.command).toEqual(['prettier', '--check', '--ignore-path', '.prettierignore', '.']);
    expect(ARGV_POLICIES.prettier?.config?.flag).toBe('--ignore-path');
    expect(ARGV_POLICIES.prettier?.config?.content).toBe(t.fixedInputs.config?.content);
    const run = runOf('prettier');
    expect(run).toMatch(/prettier\.cjs" --ignore-path "\$npmdir\/prettierignore" --check --ignore-path \.prettierignore \./);
  });
  it('bandit: --ini points at a pinned file with an empty [bandit] section, so no .bandit file in the tree is found', () => {
    const t = entry('bandit');
    expect(t.fixedInputs.config?.passAs).toEqual({ flag: '--ini' });
    expect(t.fixedInputs.config?.content).toBe('[bandit]\n');
    expect(ARGV_POLICIES.bandit?.config).toEqual({ flag: '--ini', content: '[bandit]\n', fileName: 'bandit.ini' });
  });
});

describe('the entries changed here are reviewed by delegation (DECISIONS 105) on 2026-10-30', () => {
  it('ruff, ruff-format, prettier, knip, osv-scanner, jscpd, bandit and oxlint-typeaware', () => {
    for (const id of ['ruff', 'ruff-format', 'prettier', 'knip', 'osv-scanner', 'jscpd', 'bandit', 'oxlint-typeaware']) {
      const t = entry(id === 'oxlint-typeaware' ? 'oxlint-typeaware' : id);
      expect(t.reviewedBy, id).toBe('Claude delegated DECISIONS 105');
      expect(t.reviewedAt, id).toBe('2026-10-30');
    }
  });
});
