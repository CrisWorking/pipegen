// v0.2 Plan G, sub-task G15a round 3, item (a) (PF-3; ruling G15-R0 6, G15a-R0b): OpenSSF Scorecard, weekly. Reported, never gated,
// publish_results false. The gate's scrub reads its SARIF (the real v5.6.0 runs in test/fixtures/scorecard, the library scorecard-action
// v2.5.0 runs); the image runs as a `docker://…@sha256` step pinned to the reviewed entry's recorded digest.
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { parseSarif, parseSarifText, SARIF_TOOLS } from '../gate/src/sarif.js';
import { readScrubbed, scrubBytes } from '../gate/src/scrub.js';

type Obj = Record<string, unknown>;
const FIX = 'test/fixtures/scorecard';
const KEY = 'k'.repeat(64);
const PUSH_EVENT = JSON.stringify({ repository: { id: 1 } });
const fixture = (f: string): Buffer => readFileSync(`${FIX}/${f}`);
const doc = (f: string): Obj => JSON.parse(fixture(f).toString('utf8')) as Obj;

describe('G15a round 3 (a): the gate reads Scorecard SARIF (scrub only, never gated)', () => {
  it('gate: the Scorecard reader reads the real v5.6.0 SARIF: each result with its check, its rule severity and its file; a result about no file has none', () => {
    expect(SARIF_TOOLS['scorecard-action']).toMatchObject({ driver: 'Scorecard', severity: 'security-severity', secrets: false, fileMode: 'repo' });
    for (const f of ['scorecard-action.sarif', 'hello-world.sarif']) {
      const r = parseSarifText(fixture(f), 'scorecard-action');
      expect(r.toolError, f).toBeUndefined();
      const raw = doc(f);
      const results = (raw.runs as Obj[]).flatMap((run) => run.results as Obj[]);
      expect(r.findings.length, f).toBe(results.length);
      for (const x of r.findings) {
        expect(x.ruleId, f).toMatch(/^[A-Za-z]+ID$/);
        expect(['critical', 'high', 'medium', 'low']).toContain(x.severity);
        expect(x.uriUnmapped, f).toBe(false);
        expect(x.secret).toBe(false);
        // Scorecard's placeholder is never a repository file
        expect(x.file).not.toBe('no file associated with this alert');
      }
    }
    const sa = parseSarifText(fixture('scorecard-action.sarif'), 'scorecard-action').findings;
    const pinned = sa.filter((x) => x.ruleId === 'PinnedDependenciesID').map((x) => [x.file, x.line]);
    expect(pinned).toEqual([['.github/workflows/postsubmits.yml', 80], ['.github/workflows/canary.yml', 47]]);
    const fuzz = sa.find((x) => x.ruleId === 'FuzzingID');
    expect(fuzz?.file).toBeUndefined();
    expect(fuzz?.line).toBeUndefined();
    // the severity is the rule's security-severity (Branch-Protection 7.5 → high, Fuzzing 4.0 → medium), never the result's text
    expect(sa.find((x) => x.ruleId === 'BranchProtectionID')?.severity).toBe('high');
    expect(fuzz?.severity).toBe('medium');
    // every reported check is one of the enforced checks of the policy the fixtures were made with
    const policy = parse(fixture('policy.yml').toString('utf8')) as { policies: Record<string, { mode: string }> };
    const enforced = new Set(Object.entries(policy.policies).filter(([, p]) => p.mode === 'enforced').map(([k]) => `${k.replace(/-/g, '')}ID`));
    for (const f of ['scorecard-action.sarif', 'hello-world.sarif']) {
      for (const x of parseSarifText(fixture(f), 'scorecard-action').findings) expect(enforced, `${f} ${x.ruleId}`).toContain(x.ruleId);
    }
  });

  it('gate: the Scorecard reader fails closed: another driver, the placeholder under another base, or another tool id', () => {
    const other = doc('hello-world.sarif');
    ((other.runs as Obj[])[1]!.tool as Obj).driver = { ...(((other.runs as Obj[])[1]!.tool as Obj).driver as Obj), name: 'scorecard' };
    expect(parseSarif(other, 'scorecard-action').toolError).toMatch(/driver/i);
    // the placeholder is no-file only exactly, and only under %SRCROOT% (or no base): elsewhere it is an ordinary uri
    const based = doc('scorecard-action.sarif');
    const loc = ((((based.runs as Obj[])[1]!.results as Obj[])[0]!.locations as Obj[])[0]!.physicalLocation as Obj).artifactLocation as Obj;
    loc.uriBaseId = 'ELSEWHERE';
    const r = parseSarif(based, 'scorecard-action');
    const fz = r.findings.find((x) => x.ruleId === 'FuzzingID');
    expect(fz?.file === undefined ? fz?.uriUnmapped : true).toBe(true);
    const near = doc('scorecard-action.sarif');
    const loc2 = ((((near.runs as Obj[])[1]!.results as Obj[])[0]!.locations as Obj[])[0]!.physicalLocation as Obj).artifactLocation as Obj;
    loc2.uri = 'no file associated with this alert ';
    expect(parseSarif(near, 'scorecard-action').findings.find((x) => x.ruleId === 'FuzzingID')?.line).toBe(1);
    // another tool's SARIF table entry never reads Scorecard's file
    expect(parseSarif(doc('hello-world.sarif'), 'semgrep').toolError).toMatch(/driver/i);
  });

  it('gate: the Scorecard scrub writes the scrubbed SARIF the code-scanning upload sends', () => {
    const out = scrubBytes(fixture('scorecard-action.sarif'), { tool: 'scorecard-action', format: 'sarif', fpKey: KEY, eventText: PUSH_EVENT, workspace: '/home/runner/work/r/r' });
    expect(out.status).toBe('ok');
    if (out.status !== 'ok') return;
    expect(out.findings).toBe(parseSarifText(fixture('scorecard-action.sarif'), 'scorecard-action').findings.length);
    const back = readScrubbed(out.bytes, 'sarif');
    expect(back.findings.length).toBe(out.findings);
    expect(back.findings.some((x) => x.file === '.github/workflows/canary.yml')).toBe(true);
    expect(out.bytes.toString('utf8')).not.toContain('no file associated with this alert');
  });
});
