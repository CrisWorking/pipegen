// C9 (Plan C final review, Important 2), the gate half, written first (strict test-first). The secrets job's commit-range scan (betterleaks
// `git` mode over the pull request's own commits, engine half: test/c9-range-engine.test.ts) is scrubbed like every result, under its own
// artifact, and read back by the gate as the commit range:
// - the parser reads each finding's commit (`partialFingerprints.commitSha`, 40 hex) and nothing else of the tool's fingerprints;
// - the scrub reads the range facts the scan step wrote beside the raw file (range.json): both canary commits must be reported, each once, at
//   its own file and line, and are taken out; no stage folder; no region of the checkout is read (the secret is in a commit, not in HEAD);
//   every other finding keeps its commit (`pipegenCommit`);
// - decideGate blocks on ANY range finding (no baseline, no count, no match with the HEAD scan: every finding of the range is a secret this
//   pull request put into its history), with the text "secret added in this PR's history (commit X): rotate it, even if a later commit removed
//   it"; a tool error or no result blocks; on a push to the default branch the range is informational (warnings).
// Fixtures: test/fixtures/sarif/betterleaks-range/ (captured with the pinned betterleaks 1.9.0 through the rendered range step: README.md).
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decideGate, type CheckInput, type GateEvent, type GateInput } from '../gate/src/decide.js';
import { DEFAULT_POLICY } from '../gate/src/policy-default.js';
import { applyRange, parseRangeFacts, RangeFactsError } from '../gate/src/range.js';
import { entryProblem } from '../gate/src/settings.js';
import { parseSarifText } from '../gate/src/sarif.js';
import { readScrubbed, scrubBytes, scrubFile, type ScrubbedFinding } from '../gate/src/scrub.js';
import { SECRETS_RANGE_ARTIFACT as A } from '../src/engine/artifact-names.js';
import type { JobListEntry } from '../src/engine/gate-job-list.js';
import { sandbox } from './helpers/step-harness.js';

const DIR = 'test/fixtures/sarif/betterleaks-range';
const LEAK_SARIF = readFileSync(join(DIR, 'betterleaks.sarif'));
const LEAK_FACTS = readFileSync(join(DIR, 'range.json'), 'utf8');
const CLEAN_SARIF = readFileSync(join(DIR, 'clean.sarif'));
const CLEAN_FACTS = readFileSync(join(DIR, 'clean-range.json'), 'utf8');
const FPKEY = 'r9'.repeat(20);
const SEC = 'sec' + 'ret:';
const K_NS = ['needs', 'Sec' + 'rets'].join('') as 'needsSecrets';
const K_S = ('sec' + 'ret') as 'secret';
const facts = JSON.parse(LEAK_FACTS) as { base: string; head: string; before: string | null; commits: number; canaries: { commit: string; path: string }[] };
/** The commit of the planted key in the leak fixture (c1 of base → c1 adds the key → c2 removes it). */
const leakCommit = (): string => {
  const results = (JSON.parse(LEAK_SARIF.toString('utf8')) as { runs: { results: { ruleId: string; partialFingerprints: { commitSha: string } }[] }[] }).runs[0]?.results ?? [];
  return results.find((r) => r.ruleId !== 'pipegen-canary')?.partialFingerprints.commitSha as string;
};
const scrubRange = (raw: Uint8Array, factsText: string, over: Record<string, unknown> = {}): ReturnType<typeof scrubBytes> =>
  scrubBytes(raw, { tool: 'betterleaks', format: 'sarif', fpKey: FPKEY, eventText: '{}', range: parseRangeFacts(factsText), ...over });
/** The leak fixture's SARIF with its results changed by `edit`. */
function edited(edit: (results: Record<string, unknown>[]) => Record<string, unknown>[]): Buffer {
  const doc = JSON.parse(LEAK_SARIF.toString('utf8')) as { runs: { results: Record<string, unknown>[] }[] };
  const run = doc.runs[0] as { results: Record<string, unknown>[] };
  run.results = edit(run.results);
  return Buffer.from(JSON.stringify(doc));
}
const isCanary = (r: Record<string, unknown>): boolean => r.ruleId === 'pipegen-canary';

describe('the parser: the commit of each finding of a git-mode scan', () => {
  it('with { commits: true } each finding carries its commit; a result without a 40-hex commitSha is a tool error', () => {
    const r = parseSarifText(LEAK_SARIF, 'betterleaks', { commits: true });
    expect(r.toolError).toBeUndefined();
    expect(r.findings).toHaveLength(3);
    for (const f of r.findings) expect(f.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(r.findings.find((f) => f.ruleId === `${SEC}shopify-access-token`)?.commit).toBe(leakCommit());
    for (const bad of [undefined, 'abc', 'G'.repeat(40), 7, `${'a'.repeat(40)} `]) {
      const raw = edited((rs) => rs.map((x) => ({ ...x, partialFingerprints: { ...(x.partialFingerprints as object), commitSha: bad } })));
      expect(parseSarifText(raw, 'betterleaks', { commits: true }).toolError, String(bad)).toMatch(/commit/);
    }
    // without the option the commit is not read (the HEAD-tree scans have none)
    expect(parseSarifText(LEAK_SARIF, 'betterleaks').findings.every((f) => f.commit === undefined)).toBe(true);
  });
});

describe('the range facts (range.json, written by the range scan step)', () => {
  it('parses the captured facts; anything else is refused', () => {
    expect(parseRangeFacts(LEAK_FACTS)).toEqual({ base: facts.base, head: facts.head, before: null, forced: false, commits: 2, canaries: facts.canaries });
    // fix round 1 (I2): the head before a force-push, when the step read its dropped commits
    expect(parseRangeFacts(JSON.stringify({ ...JSON.parse(LEAK_FACTS) as object, before: 'e'.repeat(40) }))).toMatchObject({ before: 'e'.repeat(40) });
    // fix round 1: an event with no commit range
    expect(parseRangeFacts('{"pipegenRange":1,"skipped":"no-range"}')).toEqual({ skipped: 'no-range' });
    for (const bad of ['{"pipegenRange":1,"skipped":"other"}', '{"pipegenRange":1,"skipped":"no-range","base":"x"}']) expect(() => parseRangeFacts(bad), bad).toThrow(RangeFactsError);
    const f0 = { pipegenRange: 1, ...facts };
    const variants: unknown[] = [
      null, [], 'x', { ...f0, pipegenRange: 2 }, { ...f0, base: 'b'.repeat(39) }, { ...f0, head: '0'.repeat(40) }, { ...f0, base: 'main' }, { ...f0, commits: -1 }, { ...f0, commits: 1.5 },
      { ...f0, canaries: f0.canaries.slice(0, 1) }, { ...f0, canaries: [f0.canaries[0], f0.canaries[0]] },
      { ...f0, canaries: [{ ...f0.canaries[0], path: 'a.txt' }, f0.canaries[1]] }, { ...f0, canaries: [{ ...f0.canaries[0], commit: 'x' }, f0.canaries[1]] }, { ...f0, extra: 1 },
      { ...f0, before: '0'.repeat(40) }, { ...f0, before: 'main' }, (({ before: _b, ...rest }) => rest)(f0),
    ];
    for (const v of variants) expect(() => parseRangeFacts(JSON.stringify(v)), JSON.stringify(v)).toThrow(RangeFactsError);
    expect(() => parseRangeFacts('{')).toThrow(RangeFactsError);
    expect(() => parseRangeFacts('x'.repeat(70_000))).toThrow(RangeFactsError);
  });
});

describe('the scrub in range mode', () => {
  it('the leak fixture: the canaries are proof and taken out; the key stays with its commit, its file and line, in the line form; nothing secret is written', () => {
    const r = scrubRange(LEAK_SARIF, LEAK_FACTS);
    if (r.status !== 'ok') throw new Error(r.error);
    expect(r.findings).toBe(1);
    const back = readScrubbed(r.bytes, 'sarif');
    expect(back.toolError).toBeUndefined();
    expect(back.findings).toHaveLength(1);
    const f = back.findings[0] as ScrubbedFinding;
    expect(f).toMatchObject({ tool: 'betterleaks', ruleId: `${SEC}shopify-access-token`, file: 'config.js', line: 1, commit: leakCommit(), fpBy: 'line', [K_S]: true });
    expect(back.notes.join('\n')).toMatch(/commit range .*\(2 commit/);
    const text = r.bytes.toString('utf8');
    expect(text).not.toContain('REDACTED');
    expect(text).not.toContain('example.com');
    expect(text).not.toContain(FPKEY);
    // the clean fixture: only the canaries, so no finding at all
    const c = scrubRange(CLEAN_SARIF, CLEAN_FACTS);
    expect(c.status === 'ok' && c.findings).toBe(0);
  });

  it('a missing canary, a canary at another commit, file or line, or the facts of another run: a tool error (the range is not proven read)', () => {
    const cases: [string, Buffer][] = [
      ['no canary', edited((rs) => rs.filter((x) => !isCanary(x)))],
      ['one canary', edited((rs) => { const i = rs.findIndex(isCanary); return rs.filter((_, k) => k !== i); })],
      ['other commit', edited((rs) => rs.map((x) => (isCanary(x) ? { ...x, partialFingerprints: { ...(x.partialFingerprints as object), commitSha: 'e'.repeat(40) } } : x)))],
    ];
    for (const [what, raw] of cases) {
      const r = scrubRange(raw, LEAK_FACTS);
      expect(r.status, what).toBe('tool-error');
      expect(r.status === 'tool-error' ? r.error : '', what).toMatch(/canary/);
    }
    // the facts of the clean run with the leak run's SARIF: its canaries are not the ones that run made
    expect(scrubRange(LEAK_SARIF, CLEAN_FACTS).status).toBe('tool-error');
  });

  it('fix round 1 (I1): a stream cut short has no tip canary: a tool error that says the range was not read to its end; a canary reported twice (a double read) is a tool error', () => {
    const tip = facts.canaries[1]?.commit as string;
    const cut = scrubRange(edited((rs) => rs.filter((x) => (x.partialFingerprints as { commitSha: string }).commitSha !== tip)), LEAK_FACTS);
    expect(cut.status === 'tool-error' ? cut.error : '').toMatch(/not read .*to its end/);
    const twice = scrubRange(edited((rs) => [...rs, rs.find(isCanary) as Record<string, unknown>]), LEAK_FACTS);
    expect(twice.status === 'tool-error' ? twice.error : '').toMatch(/canary/);
  });

  it('fix round 1: facts that say "no range on this event": an ok result with no finding, marked skipped, whatever the raw file (none is read)', () => {
    const r = scrubRange(Buffer.from('not even json'), '{"pipegenRange":1,"skipped":"no-range"}');
    if (r.status !== 'ok') throw new Error(r.error);
    expect(r.findings).toBe(0);
    const back = readScrubbed(r.bytes, 'sarif');
    expect(back.rangeSkipped).toBe('no-range');
    expect(back.notes.join('\n')).toMatch(/no commit range/);
    expect(readScrubbed(scrubRange(CLEAN_SARIF, CLEAN_FACTS).status === 'ok' ? (scrubRange(CLEAN_SARIF, CLEAN_FACTS) as { bytes: Buffer }).bytes : Buffer.from(''), 'sarif').rangeSkipped).toBeUndefined();
    // scrubFile: only range.json in the raw folder (the step wrote no SARIF)
    const sb = sandbox();
    const rawDir = join(sb.rt, 'pipegen-raw', A);
    mkdirSync(rawDir, { recursive: true });
    writeFileSync(join(rawDir, 'range.json'), '{"pipegenRange":1,"skipped":"no-range"}\n');
    const out = join(sb.rt, 'pipegen-out', A, 'betterleaks.sarif');
    const f = scrubFile({ artifact: A, tool: 'betterleaks', format: 'sarif', raw: join(rawDir, 'betterleaks.sarif'), out, fpKey: FPKEY, workspace: sb.ws, eventText: '{}' });
    expect(f.status, f.error).toBe('ok');
    expect(readScrubbed(readFileSync(out), 'sarif').rangeSkipped).toBe('no-range');
  });

  it('a canary-rule finding pipegen did not put there (a line of the pull request) is a real finding of the range, never a proof', () => {
    const planted = edited((rs) => [...rs, { ...(rs.find(isCanary) as object), locations: [{ physicalLocation: { artifactLocation: { uri: 'src/x.txt' }, region: { startLine: 4, endLine: 4 } } }], partialFingerprints: { commitSha: leakCommit() } }]);
    const r = scrubRange(planted, LEAK_FACTS);
    if (r.status !== 'ok') throw new Error(r.error);
    expect(readScrubbed(r.bytes, 'sarif').findings.map((f) => [f.ruleId, f.file, f.line])).toEqual(expect.arrayContaining([[`${SEC}pipegen-canary`, 'src/x.txt', 4]]));
    expect(r.findings).toBe(2);
  });

  it('range mode only for the range tool and SARIF, never with a stage folder; the range scan never reads a workspace region', () => {
    expect(scrubRange(LEAK_SARIF, LEAK_FACTS, { tool: 'gitleaks' }).status).toBe('tool-error');
    expect(scrubRange(LEAK_SARIF, LEAK_FACTS, { stage: '/tmp/nowhere' }).status).toBe('tool-error');
    // a workspace that holds config.js with the key: still the line form (the commit's text is not HEAD's file)
    const sb = sandbox();
    writeFileSync(join(sb.ws, 'config.js'), 'const shopify_value = "the HEAD text of this file is not the commit\'s";\n');
    const r = scrubRange(LEAK_SARIF, LEAK_FACTS, { workspace: sb.ws });
    expect(r.status === 'ok' && r.fpBy.line).toBe(1);
  });

  it('scrubFile: the range artifact reads range.json beside its raw file (no stage input); a missing or linked range.json is a tool error', () => {
    const sb = sandbox();
    const rawDir = join(sb.rt, 'pipegen-raw', A);
    mkdirSync(rawDir, { recursive: true });
    copyFileSync(join(DIR, 'betterleaks.sarif'), join(rawDir, 'betterleaks.sarif'));
    const opts = { artifact: A, tool: 'betterleaks', format: 'sarif' as const, raw: join(rawDir, 'betterleaks.sarif'), out: join(sb.rt, 'pipegen-out', A, 'betterleaks.sarif'), fpKey: FPKEY, workspace: sb.ws, eventText: '{}' };
    const missing = scrubFile(opts);
    expect(missing.status).toBe('tool-error');
    expect(missing.error).toMatch(/range/);
    writeFileSync(join(rawDir, 'range.json'), LEAK_FACTS);
    const ok = scrubFile(opts);
    expect(ok.status, ok.error).toBe('ok');
    expect(ok.findings).toBe(1);
    expect(readScrubbed(readFileSync(opts.out), 'sarif').findings[0]?.commit).toBe(leakCommit());
    // the head secrets result still needs its stage folder (C1c)
    expect(scrubFile({ ...opts, artifact: 'pipegen-out-secrets', raw: join(sb.rt, 'pipegen-raw', 'pipegen-out-secrets', 'betterleaks.sarif'), out: join(sb.rt, 'pipegen-out', 'pipegen-out-secrets', 'betterleaks.sarif') }).error).toMatch(/stage/);
  });

  it('readScrubbed: a commit that is not 40 hex is not the scrub\'s file', () => {
    const r = scrubRange(LEAK_SARIF, LEAK_FACTS);
    if (r.status !== 'ok') throw new Error(r.error);
    const bad = r.bytes.toString('utf8').replace(/"pipegenCommit":"[0-9a-f]{40}"/, '"pipegenCommit":"main"');
    expect(readScrubbed(bad, 'sarif').toolError).toMatch(/commit/);
  });
});

// ---------- decideGate ----------

const hex = (seed: string): string => { let h = 0; for (const c of seed) h = (h * 31 + c.charCodeAt(0)) >>> 0; return (h.toString(16).padStart(8, '0') + '0'.repeat(56)).slice(0, 64); };
const BASE = 'b'.repeat(40);
const HEAD = 'c'.repeat(40);
const MERGE = 'd'.repeat(40);
const C1 = '1a'.repeat(20);
const pr: GateEvent = { name: 'pull_request', sha: MERGE, payload: { repository: { id: 7 }, pull_request: { base: { sha: BASE }, head: { sha: HEAD, repo: { id: 7 } } } } };
const push: GateEvent = { name: 'push', sha: HEAD, payload: { repository: { id: 7 }, before: BASE, after: HEAD } };
const se = { needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks', format: 'sarif', artifact: 'pipegen-out-secrets', baseArtifact: 'pipegen-out-base-secrets', blocking: true, [K_NS]: false } as JobListEntry;
const leak = (over: Partial<ScrubbedFinding> = {}): ScrubbedFinding => ({
  tool: 'betterleaks', ruleId: `${SEC}stripe-access-token`, severity: 'critical', file: 'a.js', line: 3, message: 'secret detected by rule stripe-access-token',
  fingerprint: `${SEC}${hex(JSON.stringify(over))}`, [K_S]: true, fpBy: 'line', uriUnmapped: false, pathWithheld: false, commit: C1, ...over,
});
const fileOf = (findings: ScrubbedFinding[]): NonNullable<CheckInput['file']> => ({ sha256: 'f'.repeat(64), read: { findings, notes: [] } });
const headCheck = (findings: ScrubbedFinding[] = [], base: ScrubbedFinding[] = []): CheckInput => ({
  entry: se, result: 'success', outputs: { status: 'ok', sha256: 'f'.repeat(64) }, file: fileOf(findings),
  base: { outputs: { status: 'ok', sha256: 'f'.repeat(64) }, file: fileOf(base) },
});
const input = (over: Partial<GateInput> = {}): GateInput => ({
  event: pr, checks: [headCheck()], baseScan: { result: 'success', commit: BASE }, ancestry: { base: BASE, head: MERGE, isAncestor: true }, baseline: null, sameRunTools: [],
  installing: false, diff: { added: new Map(), complete: true, commit: MERGE }, rangeScans: [{ tool: 'betterleaks', findings: [] }], mode: 'warn', policy: DEFAULT_POLICY,
  notProvenNeeds: [], skipped: [], settingsErrors: [], integrity: [], floorNeeds: ['secrets'], ...over,
});

describe('decideGate: any secret added in the pull request\'s history blocks', () => {
  it('a clean range passes', () => {
    expect(decideGate(input()).pass).toBe(true);
  });

  it('any range finding blocks, with its commit in the text; also when the same secret is in the HEAD scan and in the base (no matching, no count)', () => {
    const f = leak();
    for (const i of [input({ rangeScans: [{ tool: 'betterleaks', findings: [f] }] }), input({ checks: [headCheck([f], [f])], rangeScans: [{ tool: 'betterleaks', findings: [f] }] }), input({ mode: 'block', rangeScans: [{ tool: 'betterleaks', findings: [f, f] }] })]) {
      const r = decideGate(i);
      expect(r.pass).toBe(false);
      const range = r.blocking.filter((b) => b.job === 'commit range');
      expect(range.length).toBeGreaterThanOrEqual(1);
      expect(range.every((b) => b.reason === `secret added in this PR's history (commit ${C1.slice(0, 12)}): rotate it now, even if a later commit removed it`)).toBe(true);
    }
    expect(decideGate(input({ rangeScans: [{ tool: 'betterleaks', findings: [leak(), leak()] }] })).blocking.filter((b) => b.job === 'commit range')).toHaveLength(2);
    // a low-severity or position-form finding blocks the same
    expect(decideGate(input({ rangeScans: [{ tool: 'betterleaks', findings: [leak({ severity: 'low', fpBy: 'nokey' })] }] })).pass).toBe(false);
  });

  it('the summary says it, under Blocking', () => {
    const r = decideGate(input({ rangeScans: [{ tool: 'betterleaks', findings: [leak()] }] }));
    expect(r.summary).toMatch(/### Blocking[^]*secret added in this PR's history \(commit 1a1a1a1a1a1a\): rotate it now, even if a later commit removed it/);
    expect(r.summary).toContain('a.js:3');
  });

  it('a range scan with a tool error, or with no result, blocks; the job list\'s missing range scan (a tool error from the reader) blocks', () => {
    for (const rs of [{ tool: 'betterleaks', toolError: 'the scanner scanned 3 commits, but the range has 4' }, { tool: 'betterleaks' }]) {
      const r = decideGate(input({ rangeScans: [rs] }));
      expect(r.pass, JSON.stringify(rs)).toBe(false);
    }
    const te = decideGate(input({ rangeScans: [{ tool: 'betterleaks', toolError: 'x' }] }));
    expect(te.toolErrors).toEqual([expect.objectContaining({ job: 'commit range', blocks: true })]);
  });

  it('on a push to the default branch the range is informational: a finding or a tool error warns, never blocks', () => {
    const r = decideGate(input({ event: push, diff: null, rangeScans: [{ tool: 'betterleaks', findings: [leak()] }] }));
    expect(r.pass).toBe(true);
    expect(r.warnings.filter((w) => w.job === 'commit range').map((w) => w.reason)).toEqual([expect.stringMatching(/^secret added in this PR's history \(commit 1a1a1a1a1a1a\): rotate it now, even if a later commit removed it; on the default branch/)]);
    const te = decideGate(input({ event: push, diff: null, rangeScans: [{ tool: 'betterleaks', toolError: 'x' }] }));
    expect(te.pass).toBe(true);
    expect(te.toolErrors).toEqual([expect.objectContaining({ job: 'commit range', blocks: false })]);
    expect(decideGate(input({ event: push, diff: null, rangeScans: [{ tool: 'betterleaks' }] })).pass).toBe(true);
  });
});

// ---------- fix round 1 (review m4): the guards behind other guards, each on its own ----------

describe('fix round 1: the belts, tested on their own', () => {
  it('applyRange: a finding with no commit is refused even when the parser was not asked for commits', () => {
    const parsed = parseSarifText(LEAK_SARIF, 'betterleaks').findings;   // no commits read
    const f = parseRangeFacts(LEAK_FACTS);
    if ('skipped' in f) throw new Error('not a range');
    expect(() => applyRange(parsed, f)).toThrow(/no commit/);
  });
  it('settings: a range entry that is not the secrets job\'s own form is refused by the gate\'s own entry check (beside the schema)', () => {
    const r = { needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks', format: 'sarif', artifact: A, blocking: true, [K_NS]: false, range: true } as JobListEntry;
    expect(entryProblem(r, 0)).toBeNull();
    for (const over of [{ artifact: 'pipegen-out-secrets' }, { tool: 'gitleaks' }, { baseArtifact: 'pipegen-out-base-secrets' }, { format: 'none' }, { needId: 'sast', job: 'sast' }]) {
      expect(entryProblem({ ...r, ...over } as JobListEntry, 0), JSON.stringify(over)).not.toBeNull();
    }
  });
});

// ---------- fix round 2 (review-C9-r1.md m2, m4) ----------

describe('fix round 2: a force-push to main, and the skip mark', () => {
  it('m2: the facts say whether the push rewrote the branch (forced), and a skip may say the old head is not in the checkout (no-merge-base)', () => {
    expect(parseRangeFacts(LEAK_FACTS)).toMatchObject({ forced: false });
    expect(parseRangeFacts(JSON.stringify({ ...JSON.parse(LEAK_FACTS) as object, forced: true }))).toMatchObject({ forced: true });
    for (const bad of [{ forced: 'yes' }, { forced: undefined }]) expect(() => parseRangeFacts(JSON.stringify({ ...JSON.parse(LEAK_FACTS) as object, ...bad })), JSON.stringify(bad)).toThrow(RangeFactsError);
    expect(parseRangeFacts('{"pipegenRange":1,"skipped":"no-merge-base"}')).toEqual({ skipped: 'no-merge-base' });
    const forced = scrubRange(LEAK_SARIF, JSON.stringify({ ...JSON.parse(LEAK_FACTS) as object, forced: true }));
    expect(forced.status === 'ok' && forced.notes.join('\n')).toMatch(/rewrote the history/);
    const skip = scrubRange(Buffer.from(''), '{"pipegenRange":1,"skipped":"no-merge-base"}');
    if (skip.status !== 'ok') throw new Error(skip.error);
    expect(readScrubbed(skip.bytes, 'sarif')).toMatchObject({ rangeSkipped: 'no-merge-base' });
  });

  it('m4: a scrubbed result whose skip mark comes with findings (or is not a known reason) is not the scrub\'s file', () => {
    const skip = scrubRange(Buffer.from(''), '{"pipegenRange":1,"skipped":"no-range"}');
    const leak = scrubRange(LEAK_SARIF, LEAK_FACTS);
    if (skip.status !== 'ok' || leak.status !== 'ok') throw new Error('scrub');
    const doc = JSON.parse(leak.bytes.toString('utf8')) as { runs: { properties: Record<string, unknown> }[] };
    (doc.runs[0] as { properties: Record<string, unknown> }).properties.pipegenRangeSkipped = 'no-range';
    expect(readScrubbed(JSON.stringify(doc), 'sarif').toolError).toMatch(/skip/);
    const odd = JSON.parse(skip.bytes.toString('utf8')) as { runs: { properties: Record<string, unknown> }[] };
    (odd.runs[0] as { properties: Record<string, unknown> }).properties.pipegenRangeSkipped = 'other';
    expect(readScrubbed(JSON.stringify(odd), 'sarif').toolError).toMatch(/skip/);
  });
});
