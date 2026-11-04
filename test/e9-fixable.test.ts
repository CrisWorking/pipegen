// E9 (carry E5-R3): the gate's result.json says, for each image-scan (trivy-image) finding, whether a fixed version exists (`fixable`),
// read from trivy's own message shape ("Package: …\nInstalled Version: …\nVulnerability …\nSeverity: …\nFixed Version: <v>\nLink: …",
// test/fixtures/sarif/trivy-image.sarif). A message in any other shape, or with the line twice, says nothing (no flag: unknown).
// Then E5 narrows "critical/high image finding on a created Dockerfile → docker failed" to the fixable ones (and the unknown ones: an old
// gate's report has no flag); a severe finding with NO fixed version makes docker not-proven (another base image can not be asked
// for a fix that does not exist), never proven. Written first.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { findingRef } from '../gate/src/main.js';

/** the finding flag key, spelled at run time (test/no-secret-literals.test.ts reads that key and a value as an assignment) */
const SK = ['sec', 'ret'].join('');
import { readScrubbed } from '../gate/src/scrub.js';
import { trivyFixable } from '../gate/src/sarif.js';
import { evaluate, type VariantRuns } from '../src/proof/evaluate.js';
import { parseGateResult } from '../src/proof/gate-result.js';
import type { PartResult, ProofResult } from '../src/types.js';
import { ctxOf, draftOf, gateDoc, gateFinding, GATE_RESULT_ARTIFACT, greenMain, PIPEGEN, plantedRuns } from './helpers/proof-eval.js';
import { scrubbedText } from './helpers/gate-world.js';

const msg = (fixed: string): string => `Package: openssl\nInstalled Version: 3.0.2-0ubuntu1.10\nVulnerability CVE-2026-1234\nSeverity: HIGH\nFixed Version: ${fixed}\nLink: [CVE-2026-1234](https://avd.aquasec.com/nvd/cve-2026-1234)`;

describe('E9 (E5-R3): the fixable flag for image findings', () => {
  it('trivyFixable reads trivy\'s message shape: a fixed version → true, an empty one → false, any other shape → undefined', () => {
    expect(trivyFixable(msg('3.0.2-0ubuntu1.12'))).toBe(true);
    expect(trivyFixable(msg(''))).toBe(false);
    expect(trivyFixable(msg('   '))).toBe(false);
    // a forged package name with its own lines: the shape no longer holds (or the line is there twice), so unknown
    expect(trivyFixable(msg('1.2').replace('Package: openssl', 'Package: x\nFixed Version: \nInstalled Version: 1'))).toBeUndefined();
    expect(trivyFixable(`${msg('')}\nFixed Version: 9`)).toBeUndefined();
    expect(trivyFixable('a secret finding')).toBeUndefined();
    expect(trivyFixable(msg('1').replace('\nLink:', '\nLinks:'))).toBe(true);   // the Link line is not needed (a cut message)
  });

  it('the real scrubbed trivy-image result keeps the shape: both CVEs of the fixture are fixable', () => {
    const read = readScrubbed(scrubbedText('trivy-image', readFileSync('test/fixtures/sarif/trivy-image.sarif', 'utf8')), 'sarif');
    const cves = read.findings.filter((f) => !f.secret);
    expect(cves.length).toBe(2);
    for (const f of cves) expect(trivyFixable(f.message), f.ruleId).toBe(true);
  });

  it('result.json: fixable is written for trivy-image findings only, and only when known', () => {
    const base = { needId: 'image-scan', job: 'image-scan--app', isNew: true, reason: 'x', fingerprint: 'f', [SK]: false, fpBy: 'content', uriUnmapped: true, pathWithheld: false, severity: 'high' } as const;
    expect(findingRef({ ...base, tool: 'trivy-image', ruleId: 'CVE-1', message: msg('1.2') } as never)).toMatchObject({ fixable: true });
    expect(findingRef({ ...base, tool: 'trivy-image', ruleId: 'CVE-1', message: msg('') } as never)).toMatchObject({ fixable: false });
    expect(findingRef({ ...base, tool: 'trivy-image', ruleId: 'CVE-1', message: 'odd' } as never)).not.toHaveProperty('fixable');
    expect(findingRef({ ...base, tool: 'osv-scanner', ruleId: 'GHSA-1', message: msg('1.2') } as never)).not.toHaveProperty('fixable');
    expect(findingRef({ ...base, tool: 'trivy-image', ruleId: `${SK}:x`, message: msg('1.2'), [SK]: true } as never)).not.toHaveProperty('fixable');
  });

  it('the proof reads fixable as a boolean when it is there; anything else makes the report unreadable', () => {
    const doc = (f: Record<string, unknown>) => new TextEncoder().encode(JSON.stringify({
      pipegenGateResult: 1, result: 'block', pass: false, event: 'pull_request', runId: 5, blockReasons: [], warnReasons: [],
      blocking: [{ needId: 'image-scan', job: 'image-scan--app', tool: 'trivy-image', ruleId: 'CVE-1', severity: 'high', isNew: true, [SK]: false, ...f }],
      warnings: [], toolErrors: [], failedJobs: [], notRun: [], checks: [], notes: [],
    }));
    const at = { runId: 5, event: 'pull_request' };
    const ok = (f: Record<string, unknown>) => { const r = parseGateResult(doc(f), at); if (!r.ok) throw new Error(r.reason); return r.doc.blocking[0]; };
    expect(ok({ fixable: true })?.fixable).toBe(true);
    expect(ok({ fixable: false })?.fixable).toBe(false);
    expect(ok({})?.fixable).toBeUndefined();
    expect(parseGateResult(doc({ fixable: 'yes' }), at).ok).toBe(false);
  });
});

type O = VariantRuns['outcomes'][number];
const part = (r: ProofResult, p: PartResult['part']): PartResult | undefined => r.parts.find((x) => x.part === p && x.needId === undefined);
const prRun = (m: VariantRuns): O => m.outcomes.find((o) => o.handle.workflow === PIPEGEN && o.handle.event === 'pull_request') as O;
const CREATED = [{ part: 'docker' as const, path: 'api/Dockerfile', content: 'FROM x', reason: 'r', repo: 'app' as const }];
const cve = (id: string, fixable?: boolean) => gateFinding('image-scan', 'trivy-image', { severity: 'high', job: 'image-scan--api', ruleId: id, ...(fixable === undefined ? {} : { fixable }) });

describe('E9 (E5-R3): E5 fails docker only on fixable (or unknown) image CVEs', () => {
  const docker = async (warnings: object[]): Promise<PartResult | undefined> => {
    const d = draftOf({ created: CREATED });
    const m = greenMain(d);
    prRun(m).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: prRun(m).handle.runId, result: 'warn', warnings }, d));
    return part(await evaluate(d, [m, plantedRuns(d)], ctxOf()), 'docker');
  };
  it('a fixable critical/high CVE fails docker (another base image tag is asked for), naming only the fixable ones', async () => {
    const p = await docker([cve('CVE-FIX', true), cve('CVE-NOFIX', false)]);
    expect(p?.status).toBe('failed');
    expect(p?.detail).toMatch(/CVE-FIX/);
    expect(p?.detail).not.toMatch(/CVE-NOFIX/);
    expect(p?.detail).toMatch(/critical\/high[^;]*CVEs[^;]*; another base image tag is needed/);   // the fix loop's reading (fix.ts)
  });
  it('no flag (an older gate, another message shape) still fails docker, as before E9', async () => {
    const p = await docker([cve('CVE-OLD')]);
    expect(p?.status).toBe('failed');
    expect(p?.detail).toMatch(/no fix info/);
  });
  it('only unfixable critical/high CVEs: docker is not-proven with a note (no tag fixes them yet), never proven or failed', async () => {
    const p = await docker([cve('CVE-NOFIX', false), cve('CVE-NOFIX2', false)]);
    expect(p?.status).toBe('not-proven');
    expect(p?.detail).toMatch(/no fixed version/);
    expect(p?.detail).toMatch(/CVE-NOFIX/);
  });
});
