// C9 (Plan C final review, Important 2): the commit-range secrets scan, the scrub's half. The range scan step (src/engine/render-cli.ts
// renderRangeScan) runs betterleaks in `git` mode over the pull request's own commits plus two canary commits it made on the head, and writes
// the facts of that run beside its raw SARIF (RANGE_FACTS_FILE): this event's base and head, the number of the pull request's commits it
// counted (merges not counted), and the two canary commits with the file each adds. The scrub reads the facts here and:
// - requires each canary commit's canary finding exactly once, at its own file, on line 1. Fix round 1 (review I1): the scanner reads one
//   ordered stream whose last commit is the tip canary (the step checks the order), so the tip canary's finding proves the stream was read to
//   its end; a missing one (a parse error, a git log that died) is a tool error;
// - takes those two findings out; any other finding of the canary rule (a canary-looking line the pull request added) is a real finding of
//   the range (C1c P35);
// - keeps every finding's commit (the parser read it, ParseOptions.commits).
// Treat the facts file as hostile: a strict shape, a size cap, no link.
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { RANGE_CANARY_FILES } from '../../src/engine/artifact-names.js';

// the names the scrub needs, from the one leaf that spells them (scrub.ts imports only gate/src files and a few leaves)
export { RANGE_FACTS_FILE, SECRETS_RANGE_ARTIFACT, SECRETS_RANGE_TOOL } from '../../src/engine/artifact-names.js';
import { CANARY_RULE } from '../../src/ai/scan-staging.js';
import type { ParsedFinding } from './parse-common.js';

export class RangeFactsError extends Error {}
/**
 * The facts of one range scan. `before` (fix round 1, I2): on a synchronize, the head before this push, whose dropped commits the stream also
 * read; null otherwise. `commits`: the commits of the stream that are not canaries (merges included since fix round 1).
 */
export interface RangeFacts { base: string; head: string; before: string | null; forced: boolean; commits: number; canaries: readonly { commit: string; path: string }[] }
/**
 * Why the step scanned nothing: `no-range`, no commit range on this event (an all-zero base or head; fix round 1); `no-merge-base`, a push that
 * rewrote the branch and whose old head is gone from the checkout (fix round 2, m2).
 */
export const SKIP_REASONS = ['no-range', 'no-merge-base'] as const;
export type SkipReason = (typeof SKIP_REASONS)[number];
export interface RangeSkipped { skipped: SkipReason }
export type RangeRun = RangeFacts | RangeSkipped;
export const isRangeSkipped = (r: RangeRun): r is RangeSkipped => Object.hasOwn(r, 'skipped');

const SHA_RE = /^[0-9a-f]{40}$/;
const ZERO = '0'.repeat(40);
const MAX_FACTS_BYTES = 64 * 1024;
const MAX_COMMITS = 10_000_000;
const KEYS = ['base', 'before', 'canaries', 'commits', 'forced', 'head', 'pipegenRange'];
const CANARY_RULE_ID = `secret:${CANARY_RULE}`;
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The facts of one range scan, from the text of its facts file; throws RangeFactsError for anything but the forms the step writes. */
export function parseRangeFacts(text: string): RangeRun {
  const bad = (why: string): never => { throw new RangeFactsError(`the commit-range facts ${why}`); };
  if (typeof text !== 'string' || text.length > MAX_FACTS_BYTES) bad('are over the size cap');
  let d: unknown;
  try { d = JSON.parse(text); } catch { return bad('are not JSON'); }
  if (!isObj(d)) return bad('are not in the form the range scan step writes');
  if (d.pipegenRange !== 1) bad('are of a version this gate does not read');
  if (Object.keys(d).sort().join() === 'pipegenRange,skipped') {
    if (!(SKIP_REASONS as readonly unknown[]).includes(d.skipped)) bad('say the scan was skipped for a reason this gate does not know');
    return { skipped: d.skipped as SkipReason };
  }
  if (Object.keys(d).sort().join() !== KEYS.join()) return bad('are not in the form the range scan step writes');
  for (const k of ['base', 'head'] as const) if (typeof d[k] !== 'string' || !SHA_RE.test(d[k] as string) || d[k] === ZERO) bad(`have a ${k} that is not a commit sha`);
  if (d.before !== null && (typeof d.before !== 'string' || !SHA_RE.test(d.before) || d.before === ZERO)) bad('have a before that is not a commit sha');
  if (typeof d.forced !== 'boolean') bad('do not say whether the push rewrote the branch');
  if (typeof d.commits !== 'number' || !Number.isSafeInteger(d.commits) || d.commits < 0 || d.commits > MAX_COMMITS) bad('have a commit count that is not a whole number');
  const list = d.canaries;
  if (!Array.isArray(list) || list.length !== RANGE_CANARY_FILES.length) return bad(`do not name ${RANGE_CANARY_FILES.length} canary commits`);
  const canaries = list.map((c, i) => {
    if (!isObj(c) || Object.keys(c).sort().join() !== 'commit,path') return bad('have a canary that is not { commit, path }');
    if (typeof c.commit !== 'string' || !SHA_RE.test(c.commit)) return bad('have a canary commit that is not a commit sha');
    const path = RANGE_CANARY_FILES[i] as string;
    if (c.path !== path) return bad('have a canary file that is not the one the step writes');
    return { commit: c.commit, path };
  });
  if (new Set(canaries.map((c) => c.commit)).size !== canaries.length) bad('name one canary commit twice');
  return { base: d.base as string, head: d.head as string, before: d.before as string | null, forced: d.forced as boolean, commits: d.commits as number, canaries };
}

/** Reads the facts file at `path`: never through a link, a regular file, never blocking, at most 64 KiB. Throws RangeFactsError. */
export function readRangeFacts(path: string): RangeRun {
  let st;
  try { st = lstatSync(path); } catch { throw new RangeFactsError('the commit-range facts (range.json beside the raw result) are missing: the range scan step did not finish'); }
  if (st.isSymbolicLink() || !st.isFile()) throw new RangeFactsError('the commit-range facts are a link or not a regular file');
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY);
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== st.dev || opened.ino !== st.ino || opened.size > MAX_FACTS_BYTES) throw new RangeFactsError('the commit-range facts changed while they were opened, or are over the size cap');
    const buf = Buffer.alloc(opened.size);
    let got = 0;
    while (got < buf.length) { const n = readSync(fd, buf, got, buf.length - got, got); if (n === 0) break; got += n; }
    return parseRangeFacts(buf.subarray(0, got).toString('utf8'));
  } catch (e) {
    if (e instanceof RangeFactsError) throw e;
    throw new RangeFactsError('the commit-range facts could not be read');
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
  }
}

/**
 * The findings of a range scan with its two canary findings taken out (each required exactly once: the canary rule, its own file, line 1, its
 * own commit), and the notes to keep. Fix round 1 (I1): the tip canary is the last commit of the scanner's one ordered stream (the step checks
 * the order), so without it the stream was not read to its end. Throws RangeFactsError when a canary is missing or reported twice, or a
 * finding has no commit.
 */
export function applyRange(findings: readonly ParsedFinding[], facts: RangeFacts): { findings: ParsedFinding[]; notes: string[] } {
  const seen = facts.canaries.map(() => 0);
  const kept: ParsedFinding[] = [];
  for (const f of findings) {
    if (f.commit === undefined || !SHA_RE.test(f.commit)) throw new RangeFactsError('a finding of the commit range has no commit');
    const i = facts.canaries.findIndex((c) => f.ruleId === CANARY_RULE_ID && f.commit === c.commit && f.file === c.path && f.line === 1 && (f.endLine ?? 1) === 1);
    if (i >= 0) { seen[i] = (seen[i] ?? 0) + 1; continue; }
    kept.push(f);
  }
  const tip = facts.canaries.length - 1;
  if ((seen[tip] ?? 0) === 0) throw new RangeFactsError(`the scanner did not report the canary of the stream's last commit (${(facts.canaries[tip] as { commit: string }).commit.slice(0, 12)}), so it has not read the commit range to its end`);
  const wrong = facts.canaries.filter((_, i) => seen[i] !== 1);
  if (wrong.length > 0) throw new RangeFactsError(`the scanner did not report the canary of commit ${wrong.map((c) => c.commit.slice(0, 12)).join(' and ')} exactly once, so it is not proven to have read the commit range once`);
  const dropped = facts.before === null ? '' : `, and the commits the push replaced (the head before it, ${facts.before.slice(0, 12)})`;
  return {
    findings: kept,
    notes: [
      `the commit range ${facts.base.slice(0, 12)}..${facts.head.slice(0, 12)} (${facts.commits} commit(s), merges included${dropped}) was scanned to its end; both canary commits were read`,
      ...(facts.forced ? ['this push rewrote the history of the branch: the range was scanned from where its old and new heads meet'] : []),
    ],
  };
}

/** The note of a range scan that scanned nothing, by its reason (fix rounds 1 and 2). */
export const SKIP_NOTES: Readonly<Record<SkipReason, string>> = Object.freeze({
  'no-range': 'no commit range on this event (a push that made the branch, workflow_dispatch or schedule), so no commit range was scanned',
  'no-merge-base': 'this push rewrote the history of the branch and its old head is not in the checkout, so its commit range was not scanned',
});
