// The short terminal report (Plan J J4, DECISIONS #123): what a person needs to act on, in about thirty lines. The full
// report stays behind `--verbose`, and the Markdown (`--out`) and JSON reports are always in full.
//
// Layout, in order: the title, the audited commit and one "changed nothing / sent nothing" line; every warning and every
// secret-like finding on disk (ruling B5: the short report hides nothing that is a warning); `Type:` one line per service;
// `Verdict:`; `Fix first` (serious gaps, at most 5); `Consider` (the other gaps, at most 5; the credit notes); `Couldn't
// tell` when any row is unknown; `Already good:`; `Not needed here:`; the plan limits that block a Fix-first item; the
// cost totals; the pointer to the details.
//
// Rows of the same check and service on push and on merge are one line (the worst status wins); the same check on several
// services is one line naming them. A check's pre-commit hook is its own line. Every value from the repo goes through the
// report's cleaning (`c.v`) once; pipegen's own sentences are written here.
import { ACTIVITY_CAPPED_PREFIX } from '../estimate/estimate.js';
import type { NeedCategory } from '../types.js';
import { num, plural } from '../util/format.js';
import { OUTPUT_CAP } from '../util/safe-output.js';
import type { Coverage } from './coverage.js';
import { buildsNoImage, creditNotes, isOwnCommand, LIMIT, needLabel, type AuditReport } from './model.js';
import {
  aiCostText, andList, commitLine, isSerious, layerViews, typeText, verdictOf, wrap, type Doc, type RenderCtx,
} from './render.js';

/** One line of the Fix first / Consider lists: a check (rows of every layer merged), the services it is for, and why. */
export interface GapLine {
  /** The check's plain name (needLabel), or its id when pipegen doesn't know it. Raw: cleaned at output. */
  check: string;
  /** The services it is missing for, in report order; empty for a repo-wide check. */
  services: string[];
  /** The coverage row's own explanation (raw). */
  why: string;
  /** The tool the setup would add or run, when the model names one; else null. Raw. */
  tool: string | null;
}

/**
 * Which checks each plan limit (AuditReport.limits, the LIMIT texts) keeps from working. The short report prints a limit
 * only when one of these checks is in its Fix first list; the full report lists every limit.
 */
export const LIMIT_CATEGORIES: Readonly<Record<keyof typeof LIMIT, readonly string[]>> = Object.freeze({
  noLock: ['gate'], fakeGate: ['gate'], noSigning: ['signing'], noReleaseSigning: ['signing'], noAttestations: ['attestation'],
  noCodeScanning: ['sast', 'scorecard'], noApprovals: ['deploy-verify'],
});

const MAX_LIST = 5;
const MAX_GOOD = 8;
const MAX_SECRET_FILES = 3;
const WIDTH = 100;
const STATUS_RANK: Readonly<Record<Coverage['status'], number>> = { missing: 3, partial: 2, unknown: 1, covered: 0 };

const groupOf = (cov: Coverage): 'hook' | 'ci' => (cov.need.layer === 'pre-commit' ? 'hook' : 'ci');
const isGap = (cov: Coverage) => cov.status === 'missing' || cov.status === 'partial';
/** The worst row of two (missing, partial, unknown, covered); on a tie the first. */
const worse = (a: Coverage, b: Coverage) => (STATUS_RANK[b.status] > STATUS_RANK[a.status] ? b : a);

/** A GapLine with what the layout needs besides. */
interface Gap extends GapLine { partial: boolean; serious: boolean; floor: boolean; category: string }

/**
 * A check's name: needLabel (with the release wording for a service that builds no image), or the raw id. A pre-commit
 * hook that shares its name with its CI twin (the secret scan) says "before each commit", so no two lines read alike.
 */
function labelsOf(r: AuditReport): (cov: Coverage) => string {
  const base = (cov: Coverage) => needLabel(cov.need.id, { noImage: buildsNoImage(cov.need, r.profile) }) ?? cov.need.id;
  const ci = new Set(r.coverage.filter((x) => groupOf(x) === 'ci').map(base));
  return (cov) => (groupOf(cov) === 'hook' && ci.has(base(cov)) ? `${base(cov)} before each commit` : base(cov));
}

/**
 * The rows that are gaps (missing or partial), merged so a check shows once: the same check on push, merge and the
 * other CI layers is one row per service (the worst status wins), then the same check and status on several services is
 * one line naming them. Serious rows (isSerious) and the rest are kept apart; pipegen's floor checks come first in each.
 */
function gapsOf(r: AuditReport): { serious: Gap[]; other: Gap[] } {
  const label = labelsOf(r);
  const tools = toolsOf(r);
  const perService = new Map<string, { cov: Coverage; serious: boolean }>();
  for (const cov of r.coverage) {
    if (!isGap(cov)) continue;
    const key = `${cov.need.id}\u0000${groupOf(cov)}\u0000${cov.need.service ?? ''}`;
    const prev = perService.get(key);
    perService.set(key, { cov: prev === undefined ? cov : worse(prev.cov, cov), serious: (prev?.serious ?? false) || isSerious(cov) });
  }
  const lines = new Map<string, Gap>();
  for (const { cov, serious } of perService.values()) {
    const svc = cov.need.service;
    const key = `${cov.need.id}\u0000${groupOf(cov)}\u0000${cov.status}\u0000${serious ? 1 : 0}\u0000${svc === undefined ? cov.why : ''}`;
    const prev = lines.get(key);
    if (prev === undefined) {
      lines.set(key, { check: label(cov), services: svc === undefined ? [] : [svc], why: cov.why, tool: tools.get(cov.need.id) ?? null, partial: cov.status === 'partial', serious, floor: cov.need.floor, category: cov.need.category });
    } else if (svc !== undefined) prev.services.push(svc);
  }
  const all = [...lines.values()];
  const ranked = [...all.filter((g) => g.floor), ...all.filter((g) => !g.floor)];
  return { serious: ranked.filter((g) => g.serious), other: ranked.filter((g) => !g.serious) };
}

/** The tool the setup names for each check id (the first row with one): a reviewed tool, or the repo's own tool or script. pipegen's own checks name none. */
function toolsOf(r: AuditReport): Map<string, string> {
  const out = new Map<string, string>();
  for (const w of r.wouldAdd) {
    const t = w.tool;
    if (t === null || out.has(w.need.id)) continue;
    if ('kind' in t) {
      if (t.kind === 'repo-tool') out.set(w.need.id, `your own ${t.tool}`);
      else if (t.kind === 'project-script') out.set(w.need.id, `your own ${t.script} script`);
    } else out.set(w.need.id, t.candidate.name);
  }
  return out;
}

const plainLine = (g: Gap): GapLine => ({ check: g.check, services: g.services, why: g.why, tool: g.tool });

/**
 * The gaps of a report, ranked: `fixFirst` are the serious ones (a blocking check that is missing or partial, which a
 * tool or the project's own script should cover), `consider` the rest (warning-only checks, and pipegen's own gate and
 * deploy check). Neither list is cut: the short report shows the first five of each.
 */
export function rankGaps(r: AuditReport): { fixFirst: GapLine[]; consider: GapLine[] } {
  const g = gapsOf(r);
  return { fixFirst: g.serious.map(plainLine), consider: g.other.map(plainLine) };
}

/** Cuts `s` to `room` characters at a word, with an ellipsis; '' when there is no room worth using. */
function fit(s: string, room: number): string {
  const chars = [...s];
  if (chars.length <= room) return s;
  if (room < 24) return '';
  const cut = chars.slice(0, room - 1).join('');
  const at = cut.lastIndexOf(' ');
  return `${at > room / 2 ? cut.slice(0, at) : cut}…`;
}

/** "- Check for a and b (partial): why. Tool: x" cut to one line. */
function gapText(c: RenderCtx, g: GapLine, partial: boolean): string {
  const head = `${c.v(g.check)}${g.services.length === 0 ? '' : ` for ${andList(g.services.map((s) => c.v(s)))}`}${partial ? ' (partial)' : ''}`;
  const tool = g.tool === null ? '' : ` [${c.v(g.tool)}]`;
  const room = WIDTH - 4 - [...head].length - [...tool].length - 2; // "  - " lead and ": "
  const why = fit(c.v(g.why, OUTPUT_CAP.text), room);
  return `${head}${why === '' ? '' : `: ${why}`}${tool}`;
}

function list(c: RenderCtx, title: string, lines: Gap[], out: string[], extra: string[] = []): void {
  const shown = lines.slice(0, MAX_LIST);
  const more = lines.length - shown.length;
  out.push(`${title}${more > 0 ? ` (${shown.length} of ${lines.length}; the rest: --verbose)` : ''}`);
  for (const g of shown) out.push(...wrap(gapText(c, g, g.partial), '  - ', '    '));
  for (const e of extra) out.push(...wrap(e, '  - ', '    '));
}

/** The secret-like findings on disk as the short report's one line (rule names and file names only, never values). */
function secretLine(r: AuditReport, c: RenderCtx): string | null {
  if (r.secretsInTree.length === 0) return null;
  const files: string[] = [];
  for (const s of r.secretsInTree) {
    const f = c.v(s.file, OUTPUT_CAP.path);
    if (!files.includes(f)) files.push(f);
  }
  return `Secret-like text on disk: ${plural(files.length, 'file', 'files')} (${files.slice(0, MAX_SECRET_FILES).join(', ')}; --verbose for all)`;
}

/** "Not needed here: <labels> (<reason>); …", grouped by reason in the model's order. */
function notNeededLine(r: AuditReport, c: RenderCtx): string | null {
  if (r.skipped.length === 0) return null;
  const parts = r.skipped.map((g) => {
    const labels = [...new Set(g.categories.map((k) => needLabel(k as NeedCategory) ?? c.v(k)))];
    return `${labels.join(', ')} (${c.v(g.why, OUTPUT_CAP.text)})`;
  });
  return `Not needed here: ${parts.join('; ')}`;
}

/** "Full setup cost: …": setup minutes, monthly minutes, AI range; one line. */
function costLine(r: AuditReport, c: RenderCtx): string {
  const e = r.estimates;
  const atLeast = e.basis.some((b) => b.startsWith(ACTIVITY_CAPPED_PREFIX));
  const ai = e.aiCostUsd === 'local' ? 'no AI cost (a local model)' : `AI ${c.usd(e.aiCostUsd.low)}–${c.usd(e.aiCostUsd.high)}`;
  const included = e.includedMinutes;
  const heavy = typeof included === 'number' && Number.isFinite(included) && included > 0 && e.monthlyMinutes > included / 2
    ? ` (more than half of the ${num(included)} your plan includes)` : '';
  return `Full setup cost: about ${num(e.setupMinutes)} Actions minutes to set up (cap ${num(e.setupMinutesCap)}), ${num(e.monthlyMinutes)}${atLeast ? ' or more' : ''} minutes a month${heavy}; ${ai}`;
}

/** The short terminal report as a Doc: `terminal` holds its lines (cleaned and wrapped at 100). */
export function buildShortDoc(r: AuditReport, c: RenderCtx): Doc {
  const views = layerViews(r);
  const verdict = verdictOf(views.filter((v) => v.layer !== 'scheduled'));
  const out: string[] = [];
  const title = `pipegen audit: ${c.v(`${r.profile.owner}/${r.profile.repo}`, OUTPUT_CAP.path)}`;
  const commit = commitLine(r, c);
  out.push(...wrap(title, ''), ...wrap(commit, ''));
  out.push(...wrap(r.ai === undefined ? 'pipegen changed nothing in the repo or on GitHub, and sent nothing to an AI.' : 'pipegen changed nothing in the repo or on GitHub. You ran it with --ai: the AI cost is below.', ''));

  // warnings come first, and hide nothing (ruling B5)
  const secrets = secretLine(r, c);
  if (secrets !== null) out.push(...wrap(secrets, '⚠ ', '  '));
  for (const w of r.warnings) {
    out.push(...wrap(c.v(w.text, OUTPUT_CAP.text), '⚠ ', '  '));
    if (w.command !== undefined) out.push(isOwnCommand(w.command) ? `    ${w.command}` : `    ${c.v(w.command, OUTPUT_CAP.text)}`);
  }
  if (r.wouldAddNote !== null) out.push(...wrap(c.v(r.wouldAddNote, OUTPUT_CAP.text), '⚠ ', '  '));

  out.push('');
  for (const s of r.profile.services) {
    const t = typeText(c, s);
    if (t !== null) out.push(...wrap(`Type: ${t}`, '', '      '));
  }
  out.push(...wrap(`Verdict: ${verdict}`, ''));

  // the gaps
  const g = gapsOf(r);
  out.push('');
  if (g.serious.length > 0) list(c, 'Fix first', g.serious, out);
  else out.push('Fix first: nothing serious.');
  const notes = creditNotes(r.coverage, r.profile).map((n) => c.v(n, OUTPUT_CAP.text));
  if (g.other.length > 0 || notes.length > 0) list(c, 'Consider', g.other, out, notes);
  const unknown = new Set(r.coverage.filter((x) => x.status === 'unknown').map((x) => `${x.need.id}\u0000${groupOf(x)}\u0000${x.need.service ?? ''}`)).size;
  if (unknown > 0) out.push(...wrap(`Couldn't tell: ${plural(unknown, 'check', 'checks')} (--verbose)`, ''));

  out.push('');
  const label = labelsOf(r);
  const open = new Set(r.coverage.filter(isGap).map((x) => `${x.need.id}\u0000${groupOf(x)}`));
  const good = [...new Set(r.coverage.filter((x) => x.status === 'covered' && !open.has(`${x.need.id}\u0000${groupOf(x)}`)).map((x) => c.v(label(x))))];
  const goodShown = good.slice(0, MAX_GOOD);
  out.push(...wrap(`Already good: ${good.length === 0 ? 'nothing yet' : `${goodShown.join(', ')}${good.length > goodShown.length ? ` and ${num(good.length - goodShown.length)} more` : ''}`}`, '', '  '));
  const skipped = notNeededLine(r, c);
  if (skipped !== null) out.push(...wrap(skipped, '', '  '));

  // a plan limit, only when it blocks a Fix-first item
  for (const [key, text] of Object.entries(LIMIT) as [keyof typeof LIMIT, string][]) {
    if (!r.limits.includes(text)) continue;
    if (!LIMIT_CATEGORIES[key].some((cat) => g.serious.some((x) => x.category === cat))) continue;
    out.push(...wrap(c.v(text, OUTPUT_CAP.text), '⚠ ', '  '));
  }

  out.push(...wrap(costLine(r, c), '', '  '));
  if (r.ai !== undefined) out.push(...wrap(`AI cost of this audit: ${aiCostText(r.ai, c)}`, '', '  '));
  out.push('Details: pipegen --verbose · full report: --out report.md');
  return { title, intro: [], commit, verdict, sections: [], terminal: out };
}
