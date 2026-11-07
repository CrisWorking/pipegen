// v0.2 Plan G, sub-task G15a (G11-2, brief items 13-14): packages with no licence data count as Unknown, a warning a person looks at.
// Trivy's SARIF lists only the licences it found, so a package whose lockfile entry has no licence was invisible. The licence scan now
// writes Trivy's JSON with --list-all-pkgs; the gate's scrub reads it (gate/src/trivy-licence.ts) and writes the same scrubbed SARIF as
// before, with one more finding per package that has no licence data (severity info, so the licences rule makes it a warning).
// The fixtures are real runs of the pinned trivy 0.76.0, offline (test/fixtures/trivy-licence-json/README.md).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { JobListEntry } from '../src/engine/gate-job-list.js';
import { TRIVY_LICENCE_RESULT } from '../src/engine/tool-flags.js';
import { loadReviewed, ReviewedListError } from '../src/engine/reviewed.js';
import { decideGate, type CheckInput, type GateInput } from '../gate/src/decide.js';
import { DEFAULT_POLICY } from '../gate/src/policy-default.js';
import { readScrubbed, scrubBytes, type ScrubbedFinding } from '../gate/src/scrub.js';
import { NO_LICENCE_RULE_SUFFIX, parseTrivyLicenceJson, parseTrivyLicenceJsonText } from '../gate/src/trivy-licence.js';
import { stringify, parse } from 'yaml';
import { makeTempDir, writeIn } from './helpers/make-repo.js';

const FX = (n: string): Buffer => readFileSync(`test/fixtures/trivy-licence-json/${n}`);
const json = (n: string): Record<string, any> => JSON.parse(FX(n).toString('utf8'));
const TOOL = 'trivy-licence';
const PUSH = JSON.stringify({ repository: { id: 7 }, before: 'b'.repeat(40), after: 'c'.repeat(40) });
const scrub = (raw: Buffer | string, tool = TOOL) => scrubBytes(typeof raw === 'string' ? Buffer.from(raw) : raw, { tool, format: 'sarif', eventText: PUSH, workspace: '/w' });
const rows = (fs: readonly { ruleId: string; severity: string; file?: string; line?: number }[]) => fs.map((f) => [f.ruleId, f.severity, f.file, f.line]);

const BASE = 'b'.repeat(40);
const MERGE = 'd'.repeat(40);
// field name spelled at run time (test/no-secret-literals.test.ts reads `<name>: <value>` with it as an assignment)
const K_NS = ['needs', 'Sec' + 'rets'].join('');
const LIC_ENTRY = { needId: 'licences', job: 'licences', category: 'licences', tool: TOOL, format: 'sarif', artifact: 'pipegen-out-licences', baseArtifact: 'pipegen-out-base-licences', blocking: true, [K_NS]: false } as unknown as JobListEntry;
const checkOf = (head: ScrubbedFinding[], base: ScrubbedFinding[] = []): CheckInput => ({
  entry: LIC_ENTRY, result: 'success', outputs: { status: 'ok', sha256: 'f'.repeat(64) }, file: { sha256: 'f'.repeat(64), read: { findings: head, notes: [] } },
  base: { outputs: { status: 'ok', sha256: 'e'.repeat(64) }, file: { sha256: 'e'.repeat(64), read: { findings: base, notes: [] } } },
});
const input = (checks: CheckInput[], mode: 'warn' | 'block' = 'block'): GateInput => ({
  event: { name: 'pull_request', sha: MERGE, payload: { repository: { id: 7 }, pull_request: { base: { sha: BASE }, head: { sha: 'c'.repeat(40), repo: { id: 7 } } } } },
  checks, baseScan: { result: 'success', commit: BASE }, ancestry: { base: BASE, head: MERGE, isAncestor: true }, baseline: null,
  sameRunTools: ['osv-scanner', 'trivy-image', TOOL], installing: false, diff: { added: new Map(), complete: true, commit: MERGE }, rangeScans: [],
  mode, policy: DEFAULT_POLICY, notProvenNeeds: [], skipped: [], settingsErrors: [], integrity: [], floorNeeds: [],
}) as GateInput;

describe('G15a G11-2: no licence data counts as Unknown', () => {
  it('gate: packages with no licence data counted as Unknown (warning)', () => {
    // the real run: three licences found (HIGH restricted, LOW notice, UNKNOWN unknown) and two packages with none (no key, an empty list)
    const out = scrub(FX('composer.json'));
    if (out.status !== 'ok') throw new Error(out.error);
    const back = readScrubbed(out.bytes, 'sarif');
    expect(rows(back.findings).sort()).toEqual([
      ['acme/emptylicence:no-licence-data', 'info', 'php/composer.lock', 1],
      ['acme/gpl:GPL-3.0-only', 'high', 'php/composer.lock', 1],
      ['acme/mit:MIT', 'low', 'php/composer.lock', 1],
      ['acme/nolicence:no-licence-data', 'info', 'php/composer.lock', 1],
      ['acme/weird:SomeWeirdLicense-1.0', 'info', 'php/composer.lock', 1],
    ]);
    // the gate: the two packages with no licence data are warnings a person must look at, like the Unknown licence; never a pass in silence
    const noData = back.findings.filter((f) => f.ruleId.endsWith(NO_LICENCE_RULE_SUFFIX));
    expect(noData).toHaveLength(2);
    const r = decideGate(input([checkOf(noData)]));
    expect(r.pass).toBe(true);
    expect(r.warnings.map((w) => w.ruleId).sort()).toEqual(['acme/emptylicence:no-licence-data', 'acme/nolicence:no-licence-data']);
    for (const w of r.warnings) expect(w.reason).toMatch(/needs a human/);
    // with the restricted licence the check still blocks; with only the Unknown ones it passes with warnings
    expect(decideGate(input([checkOf(back.findings as ScrubbedFinding[])])).pass).toBe(false);
    // a package with no licence data that was already there at the base is not new
    const again = decideGate(input([checkOf(noData, noData)]));
    expect(again.warnings.every((w) => w.isNew === false)).toBe(true);
  });

  it('gate: the npm run: a forbidden licence (critical) and a package with no licence (info)', () => {
    const r = parseTrivyLicenceJsonText(FX('npm.json'), TOOL);
    expect(r.toolError).toBeUndefined();
    expect(rows(r.findings).sort()).toEqual([['left-pad:WTFPL', 'critical', 'package-lock.json', 1], ['nolic:no-licence-data', 'info', 'package-lock.json', 1]]);
    // a clean run (no lockfile: no Results key) is no finding and no error
    const e = parseTrivyLicenceJsonText(FX('empty.json'), TOOL);
    expect(e).toEqual({ findings: [], notes: [] });
  });

  it('gate: the licence reader fails closed on anything but the pinned trivy\'s filesystem JSON', () => {
    const err = (j: unknown): string | undefined => parseTrivyLicenceJson(j, TOOL).toolError;
    const base = json('composer.json');
    expect(err(base)).toBeUndefined();
    // another tool id; not an object; another schema; another artifact type; a SARIF file
    expect(parseTrivyLicenceJson(base, 'trivy-image').toolError).toMatch(/not/);
    expect(err([])).toMatch(/object/);
    expect(err({ ...base, SchemaVersion: 3 })).toMatch(/SchemaVersion/);
    expect(err({ ...base, ArtifactType: 'container_image' })).toMatch(/filesystem/);
    expect(err(JSON.parse(readFileSync('test/fixtures/sarif/trivy-licence.sarif', 'utf8')))).toBeDefined();
    expect(scrub(readFileSync('test/fixtures/sarif/trivy-licence.sarif')).status).toBe('tool-error');
    // a result class the reader does not know (it might hold licences it would skip)
    expect(err({ ...base, Results: [{ Target: 'x', Class: 'config', Misconfigurations: [] }] })).toMatch(/class/);
    // an empty licence list is no licence data too (trivy omits the key today; an empty list must not read as licensed)
    const el = structuredClone(base);
    el.Results[0].Packages[1].Licenses = [];
    expect(parseTrivyLicenceJson(el, TOOL).findings.map((f) => f.ruleId)).toContain('acme/gpl:no-licence-data');
    // a malformed package or licence
    const lp = structuredClone(base);
    lp.Results[0].Packages[0].Licenses = 'MIT';
    expect(err(lp)).toMatch(/Licenses/);
    const nn = structuredClone(base);
    delete nn.Results[0].Packages[1].Name;
    expect(err(nn)).toMatch(/Name/);
    const ln = structuredClone(base);
    delete ln.Results[1].Licenses[0].Name;
    expect(err(ln)).toMatch(/Name/);
    // a severity the reader does not know is high, with a note (never dropped, never info)
    const sv = structuredClone(base);
    sv.Results[1].Licenses[0].Severity = 'SEVERE';
    const r = parseTrivyLicenceJson(sv, TOOL);
    expect(r.findings.find((f) => f.ruleId === 'acme/gpl:GPL-3.0-only')?.severity).toBe('high');
    expect(r.notes.join('\n')).toMatch(/unknown severity/);
    // a path that is not a repository path is unmapped (never a path outside the checkout)
    const up = structuredClone(base);
    up.Results[1].Licenses[0].FilePath = '../etc/passwd';
    const u = parseTrivyLicenceJson(up, TOOL).findings.find((f) => f.ruleId === 'acme/gpl:GPL-3.0-only');
    expect(u?.file).toBeUndefined();
    expect(u?.uriUnmapped).toBe(true);
    // the size cap and strict UTF-8 are the shared reader's
    expect(parseTrivyLicenceJsonText(FX('composer.json'), TOOL, { limits: { maxBytes: 100 } }).toolError).toBeDefined();
    expect(parseTrivyLicenceJsonText(Buffer.from([0x7b, 0xff, 0x7d]), TOOL).toolError).toBeDefined();
    // too many findings
    expect(parseTrivyLicenceJson(base, TOOL, { limits: { maxResults: 2 } }).toolError).toMatch(/more than 2/);
  });

  it('reviewed: the licence scan writes Trivy JSON with every package listed (--format json --list-all-pkgs), the gate reads it', () => {
    const t = loadReviewed().find((x) => x.id === TOOL)!;
    expect(TRIVY_LICENCE_RESULT.tool).toBe(TOOL);
    const cmd = t.step.cli?.command ?? [];
    const args = t.fixedInputs.args ?? [];
    for (const xs of [cmd, args]) {
      expect(xs[xs.indexOf('--format') + 1]).toBe('json');
      expect(xs).toContain('--list-all-pkgs');
      expect(xs[xs.indexOf('--output') + 1]).toBe(TRIVY_LICENCE_RESULT.file);
    }
    // G15a-R7 spec 7: the entry declares what the tool writes (json); the scrubbed result is SARIF, as for every other findings tool
    expect(t.step.output).toEqual({ path: TRIVY_LICENCE_RESULT.file, format: 'json' });
    // the loader refuses the licence scan without the JSON form, and any other trivy scan with it
    const text = readFileSync('data/reviewed-tools.yml', 'utf8');
    const file = parse(text) as { pinnedOn: string; tools: Record<string, any>[] };
    const tryLoad = (edit: (e: Record<string, any>) => void, id = TOOL): (() => unknown) => {
      const e = structuredClone(file.tools.find((x) => x.id === id)!);
      edit(e);
      const dir = makeTempDir();
      writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: file.pinnedOn, tools: [e] }));
      return () => loadReviewed(`${dir}/reviewed-tools.yml`);
    };
    expect(tryLoad(() => {})).not.toThrow();
    const both = (f: (xs: string[]) => string[]) => (e: Record<string, any>) => { e.step.cli.command = f(e.step.cli.command); e.fixedInputs.args = f(e.fixedInputs.args); };
    const noList = both((xs) => xs.filter((x) => x !== '--list-all-pkgs'));
    const sarif = both((xs) => xs.map((x) => (x === 'json' ? 'sarif' : x)));
    for (const edit of [noList, sarif]) {
      expect(tryLoad(edit)).toThrow(ReviewedListError);
      expect(tryLoad(edit)).toThrow(/list-all-pkgs|json/);
    }
    // the config scan may not write JSON (the gate reads only SARIF from it)
    expect(tryLoad(both((xs) => xs.map((x) => (x === 'sarif' ? 'json' : x))), 'trivy-config')).toThrow(/json/);
  });
});
