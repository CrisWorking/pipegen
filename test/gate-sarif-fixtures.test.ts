// Plan C Task C1a: every real fixture parses with no toolError, and what it holds is pinned. The fixtures are the real
// output of the pinned release binaries over a tiny planted repo (provenance: test/fixtures/sarif/README.md). They were
// captured with the planted repo at /home/runner/work/fixture/fixture, which is the workspace the parser is given.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseSarifText } from '../gate/src/sarif.js';
import type { Severity } from '../src/types.js';

const DIR = join(import.meta.dirname, 'fixtures', 'sarif');
const WS = '/home/runner/work/fixture/fixture';
const SEC = 'sec' + 'ret:';   // the prefix of a secret rule id (built here: no secret-like literal in a committed test file)
const read = (name: string) => readFileSync(join(DIR, name));
const parse = (name: string, tool: string, opts: { workspace?: string } = { workspace: WS }) => parseSarifText(read(name), tool, opts);
const histogram = (sevs: Severity[]) => Object.fromEntries((['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => [s, sevs.filter((x) => x === s).length] as const).filter(([, n]) => n !== 0));

// [fixture, tool, results, severity histogram (S8 sources), a known case: ruleId, severity, file, line]
const PLANTED: [string, string, number, Record<string, number>, [string, Severity, string | undefined, number | undefined]][] = [
  ['betterleaks.sarif', 'betterleaks', 2, { critical: 2 }, [SEC + 'github-pat', 'critical', 'src/config.js', 1]],
  ['gitleaks.sarif', 'gitleaks', 2, { critical: 2 }, [SEC + 'github-pat', 'critical', 'src/config.js', 2]],
  ['semgrep.sarif', 'semgrep', 7, { high: 4, medium: 2, low: 1 }, ['home.runner.pipegen-rules.javascript.lang.security.detect-child-process', 'high', 'src/app.js', 5]],
  ['osv-scanner.sarif', 'osv-scanner', 8, { critical: 1, high: 3, medium: 4 }, ['CVE-2021-44906', 'critical', 'package-lock.json', undefined]],
  ['trivy-config.sarif', 'trivy-config', 36, { high: 12, medium: 7, low: 17 }, ['AWS-0092', 'high', 'terraform/main.tf', 3]],
  ['trivy-image.sarif', 'trivy-image', 3, { critical: 1, high: 1, medium: 1 }, [SEC + 'github-pat', 'critical', undefined, 1]],
  ['trivy-licence.sarif', 'trivy-licence', 2, { critical: 1, high: 1 }, ['acme/agpl:AGPL-3.0-only', 'critical', 'php/composer.lock', 1]],
  ['hadolint.sarif', 'hadolint', 6, { high: 1, medium: 3, low: 2 }, ['DL3020', 'high', 'Dockerfile', 3]],
  ['kube-linter.sarif', 'kube-linter', 5, { high: 5 }, ['latest-tag', 'high', 'k8s/deploy.yaml', 1]],
  ['nuclei.sarif', 'nuclei', 1, { medium: 1 }, ['git-config', 'medium', undefined, 1]],
  ['ruff.sarif', 'ruff', 1, { high: 1 }, ['C901', 'high', 'py/complex.py', 1]],
  ['gosec.sarif', 'gosec', 2, { medium: 2 }, ['G401', 'medium', 'main.go', 9]],
  ['bandit.sarif', 'bandit', 4, { high: 1, medium: 1, low: 2 }, ['B602', 'high', 'py/app.py', 6]],
];
const CLEAN = ['betterleaks', 'gitleaks', 'semgrep', 'osv-scanner', 'trivy-config', 'trivy-licence', 'hadolint', 'kube-linter', 'ruff', 'gosec', 'bandit'];

describe('real fixtures: planted findings', () => {
  for (const [file, tool, count, hist, [ruleId, severity, path, line]] of PLANTED) {
    it(`fixture ${file}: no toolError, ${count} findings, severities pinned, the known case maps as expected`, () => {
      const out = parse(file, tool);
      expect(out.toolError).toBeUndefined();
      expect(out.findings).toHaveLength(count);
      expect(histogram(out.findings.map((f) => f.severity))).toEqual(hist);
      expect(out.findings.every((f) => f.tool === tool)).toBe(true);
      const known = out.findings.find((f) => f.ruleId === ruleId && f.line === line);
      expect(known, `${ruleId} at line ${line}`).toBeDefined();
      expect(known).toMatchObject({ severity, file: path });
      // the parser never invents a fingerprint (that is C1b), and no finding keeps a text that could hide a path or a secret
      for (const f of out.findings) {
        expect(Object.hasOwn(f, 'fingerprint')).toBe(false);
        expect(f.message.length).toBeLessThanOrEqual(2000);
        expect(f.file ?? '').not.toMatch(/^\/|\.\.|:\/\//);
      }
    });
  }

  it('fixture notes: only kube-linter says anything (no severity anywhere in its SARIF); an image or web finding has no repo path by design and says nothing', () => {
    const notes = Object.fromEntries(PLANTED.map(([file, tool]) => [tool, parse(file, tool).notes.length]));
    expect(notes).toEqual({ betterleaks: 0, gitleaks: 0, semgrep: 0, 'osv-scanner': 0, 'trivy-config': 0, 'trivy-image': 0, 'trivy-licence': 0, hadolint: 0, 'kube-linter': 1, nuclei: 0, ruff: 0, gosec: 0, bandit: 0 });
    expect(parse('kube-linter.sarif', 'kube-linter').notes[0]).toMatch(/5 finding\(s\).*no severity/i);
  });

  it('fixture betterleaks and gitleaks: both secrets are found at their own lines, with the message never the tool\'s text', () => {
    for (const [file, tool] of [['betterleaks.sarif', 'betterleaks'], ['gitleaks.sarif', 'gitleaks']]) {
      const out = parse(file, tool);
      expect(out.findings.map((f) => [f.ruleId, f.file, f.line])).toEqual([[SEC + 'github-pat', 'src/config.js', 1], [SEC + 'github-pat', 'src/config.js', 2]]);
      expect(JSON.stringify(out)).not.toMatch(/commit|@example\.com/);
    }
  });

  it('fixture osv-scanner: the file:// + workspace uri maps to the lockfile; without the workspace it is unmapped, not a path', () => {
    const withWs = parse('osv-scanner.sarif', 'osv-scanner');
    expect(new Set(withWs.findings.map((f) => f.file))).toEqual(new Set(['package-lock.json']));
    expect(withWs.findings.some((f) => f.ruleId.startsWith('MAL-'))).toBe(false);
    const without = parse('osv-scanner.sarif', 'osv-scanner', {});
    expect(without.toolError).toBeUndefined();
    expect(without.findings.every((f) => f.file === undefined && f.uriUnmapped)).toBe(true);
  });

  it('fixture ruff: file:///workspace/py/complex.py maps to py/complex.py', () => {
    expect(parse('ruff.sarif', 'ruff').findings[0]).toMatchObject({ file: 'py/complex.py', ruleId: 'C901', severity: 'high' });
  });

  it('fixture trivy-licence: the licence classification (Forbidden critical, Restricted high) comes through the rule-level number', () => {
    const out = parse('trivy-licence.sarif', 'trivy-licence');
    expect(Object.fromEntries(out.findings.map((f) => [f.ruleId, f.severity]))).toEqual({ 'acme/gpl:GPL-3.0-only': 'high', 'acme/agpl:AGPL-3.0-only': 'critical' });
  });

  it('fixture trivy-licence-unfiltered (no --severity, so Unknown reaches the SARIF): an Unknown licence is info (rule number 0.0, tag UNKNOWN), never high by default', () => {
    const out = parse('trivy-licence-unfiltered.sarif', 'trivy-licence');
    expect(out.toolError).toBeUndefined();
    expect(Object.fromEntries(out.findings.map((f) => [f.ruleId, f.severity]))).toEqual({ 'acme/gpl:GPL-3.0-only': 'high', 'acme/weird:SomeWeirdLicense-1.0': 'info' });
    expect(out.notes).toEqual([]);
  });

  it('fixture trivy-image: the secret in the image is a secret finding with a generic message; the image archive path is not a file', () => {
    const out = parse('trivy-image.sarif', 'trivy-image');
    expect(out.findings.every((f) => f.file === undefined && f.uriUnmapped)).toBe(true);
    const leak = out.findings.find((f) => f.ruleId.startsWith(SEC));
    expect(leak?.message).not.toContain('Match');
    expect(out.findings.filter((f) => !f.ruleId.startsWith(SEC)).map((f) => f.ruleId).sort()).toEqual(['CVE-2020-28928', 'CVE-2021-28831']);
    expect(JSON.stringify(out)).not.toContain('image.tar');
  });

  it('fixture nuclei: executionSuccessful is false in a run that worked (measured), and that does not make a toolError; the "." uri is unmapped', () => {
    expect(JSON.stringify(JSON.parse(read('nuclei.sarif').toString()).runs[0].invocations)).toContain('"executionSuccessful":false');
    expect(parse('nuclei.sarif', 'nuclei').findings[0]).toMatchObject({ file: undefined, uriUnmapped: true });
  });

  it('fixture kube-linter: executionSuccessful is false because it found something (measured); five findings, all high with a note', () => {
    expect(JSON.stringify(JSON.parse(read('kube-linter.sarif').toString()).runs[0].invocations)).toContain('"executionSuccessful":false');
    expect(parse('kube-linter.sarif', 'kube-linter').findings).toHaveLength(5);
  });
});

describe('real fixtures: clean runs (a real clean scan is not a tool error)', () => {
  for (const tool of CLEAN) {
    it(`fixture clean/${tool}.sarif: no toolError, no findings, no note (results is [], the tool still wrote it)`, () => {
      const out = parse(`clean/${tool}.sarif`, tool);
      expect(out).toEqual({ findings: [], notes: [] });
    });
  }
});

describe('real fixtures: the failed scans', () => {
  it('fixture semgrep-timeout.sarif: the real 20 MB padded file shape (executionSuccessful true, zero results, Timeout warnings) → toolError', () => {
    const raw = JSON.parse(read('semgrep-timeout.sarif').toString());
    expect(raw.runs[0].invocations[0].executionSuccessful).toBe(true);
    expect(raw.runs[0].results).toEqual([]);
    expect(raw.runs[0].invocations[0].toolExecutionNotifications[0]).toMatchObject({ descriptor: { id: 'Timeout' }, level: 'warning' });
    const out = parse('semgrep-timeout.sarif', 'semgrep');
    expect(out.toolError).toMatch(/Timeout/);
    expect(out.findings).toEqual([]);
  });

  it('fixtures: each one is rejected when read as another tool (the driver name is checked)', () => {
    expect(parse('semgrep.sarif', 'hadolint').toolError).toMatch(/driver/i);
    expect(parse('hadolint.sarif', 'semgrep').toolError).toMatch(/driver/i);
    expect(parse('gitleaks.sarif', 'betterleaks').toolError).toMatch(/driver/i);
    expect(parse('trivy-config.sarif', 'osv-scanner').toolError).toMatch(/driver/i);
  });

  it('fixtures: trivy-config, trivy-image and trivy-licence share a driver name, so the tool id alone says which one a file is (not checked by the parser)', () => {
    expect(parse('trivy-licence.sarif', 'trivy-config').toolError).toBeUndefined();
  });
});
