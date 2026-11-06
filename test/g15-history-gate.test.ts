// G15a round 4 (b1, P-4): betterleaks over the full history, nightly. The gate half, written first. The history scan reuses the commit-range
// scan step (C9) with no base: its facts (history.json's form, written as range.json beside the raw result) name the head it started from, the
// commits it counted and the two canary commits on that head. The scrub reads them only for the history artifact, and the range artifact never
// accepts them (nor the history artifact the range forms): the two scans never stand in for each other.
// The SARIF is the real one of the pinned betterleaks 1.9.0 in git mode (test/fixtures/sarif/betterleaks-range, captured through the rendered
// range step: the history scan runs the same command with other revisions, so its output format is the same).
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { applyRange, parseRangeFacts, RangeFactsError } from '../gate/src/range.js';
import { readScrubbed, scrubBytes, scrubFile } from '../gate/src/scrub.js';
import { SECRETS_HISTORY_ARTIFACT as H, SECRETS_RANGE_ARTIFACT as A } from '../src/engine/artifact-names.js';
import { parseSarifText } from '../gate/src/sarif.js';
import { sandbox } from './helpers/step-harness.js';

const DIR = 'test/fixtures/sarif/betterleaks-range';
const LEAK_SARIF = readFileSync(join(DIR, 'betterleaks.sarif'));
const RANGE_FACTS = readFileSync(join(DIR, 'range.json'), 'utf8');
const rf = JSON.parse(RANGE_FACTS) as { head: string; canaries: { commit: string; path: string }[] };
const FPKEY = 'h4'.repeat(20);
const histFacts = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ pipegenRange: 1, history: true, head: rf.head, commits: 3, canaries: rf.canaries, ...over });
const HIST = JSON.stringify(histFacts());

describe('the history facts (the commit-range facts with no base)', () => {
  it('history: the facts of a full-history scan parse only as the history kind; the range kind never reads them, nor the history kind a range form', () => {
    expect(parseRangeFacts(HIST, 'history')).toEqual({ history: true, head: rf.head, commits: 3, canaries: rf.canaries });
    expect(() => parseRangeFacts(HIST)).toThrow(RangeFactsError);
    expect(() => parseRangeFacts(HIST, 'range')).toThrow(RangeFactsError);
    expect(() => parseRangeFacts(RANGE_FACTS, 'history')).toThrow(RangeFactsError);
    expect(() => parseRangeFacts('{"pipegenRange":1,"skipped":"no-range"}', 'history')).toThrow(RangeFactsError);
    const bad: unknown[] = [
      histFacts({ history: false }), histFacts({ history: 'true' }), histFacts({ head: '0'.repeat(40) }), histFacts({ head: 'main' }), histFacts({ head: 'a'.repeat(39) }),
      histFacts({ commits: -1 }), histFacts({ commits: 1.5 }), histFacts({ commits: '3' }), histFacts({ base: 'a'.repeat(40) }), histFacts({ before: null }), histFacts({ extra: 1 }),
      histFacts({ pipegenRange: 2 }), histFacts({ canaries: rf.canaries.slice(0, 1) }), histFacts({ canaries: [rf.canaries[0], rf.canaries[0]] }),
      histFacts({ canaries: [{ ...rf.canaries[0], path: 'x.txt' }, rf.canaries[1]] }), (({ head: _h, ...rest }) => rest)(histFacts()),
    ];
    for (const b of bad) expect(() => parseRangeFacts(JSON.stringify(b), 'history'), JSON.stringify(b)).toThrow(RangeFactsError);
  });

  it('history: applyRange takes both canaries out and notes the whole history from the head; a missing tip canary is a tool error', () => {
    const parsed = parseSarifText(LEAK_SARIF, 'betterleaks', { commits: true });
    const facts = parseRangeFacts(HIST, 'history');
    if ('skipped' in facts) throw new Error('skipped');
    const r = applyRange(parsed.findings, facts);
    expect(r.findings).toHaveLength(1);
    expect(r.notes.join('\n')).toMatch(new RegExp(`whole history .*${rf.head.slice(0, 12)} \\(3 commit`));
    const tip = rf.canaries[1]?.commit as string;
    expect(() => applyRange(parsed.findings.filter((f) => f.commit !== tip), facts)).toThrow(/to its end/);
  });
});

describe('the scrub of the history artifact', () => {
  const rawOf = (sb: ReturnType<typeof sandbox>, art: string): { dir: string; opts: Parameters<typeof scrubFile>[0] } => {
    const dir = join(sb.rt, 'pipegen-raw', art);
    mkdirSync(dir, { recursive: true });
    copyFileSync(join(DIR, 'betterleaks.sarif'), join(dir, 'betterleaks.sarif'));
    return { dir, opts: { artifact: art, tool: 'betterleaks', format: 'sarif', raw: join(dir, 'betterleaks.sarif'), out: join(sb.rt, 'pipegen-out', art, 'betterleaks.sarif'), fpKey: FPKEY, workspace: sb.ws, eventText: '{}' } };
  };

  it('history: scrubFile reads the history facts beside the history artifact\'s raw file; range facts there, or history facts beside the range artifact, are a tool error', () => {
    const sb = sandbox();
    const h = rawOf(sb, H);
    expect(scrubFile(h.opts).status).toBe('tool-error');   // no facts
    writeFileSync(join(h.dir, 'range.json'), RANGE_FACTS);
    expect(scrubFile(h.opts).status).toBe('tool-error');
    writeFileSync(join(h.dir, 'range.json'), HIST, { flag: 'w' });
    const ok = scrubFile(h.opts);
    expect(ok.status, ok.error).toBe('ok');
    expect(ok.findings).toBe(1);
    const back = readScrubbed(readFileSync(h.opts.out), 'sarif');
    expect(back.findings[0]?.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(back.notes.join('\n')).toMatch(/whole history/);
    const a = rawOf(sandbox(), A);
    writeFileSync(join(a.dir, 'range.json'), HIST);
    const wrong = scrubFile(a.opts);
    expect(wrong.status).toBe('tool-error');
    expect(wrong.error).toMatch(/range/);
    // never with a stage folder
    expect(scrubFile({ ...h.opts, stage: join(sb.rt, 'stage') }).status).toBe('tool-error');
  });

  it('history: scrubBytes takes history facts for the range tool only', () => {
    const facts = parseRangeFacts(HIST, 'history');
    expect(scrubBytes(LEAK_SARIF, { tool: 'gitleaks', format: 'sarif', fpKey: FPKEY, eventText: '{}', range: facts }).status).toBe('tool-error');
    const r = scrubBytes(LEAK_SARIF, { tool: 'betterleaks', format: 'sarif', fpKey: FPKEY, eventText: '{}', range: facts });
    expect(r.status === 'ok' && r.findings).toBe(1);
  });
});
