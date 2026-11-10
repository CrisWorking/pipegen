// The short terminal report (Plan J J4, DECISIONS #123; Plan P PL-A4: by parts, Cristiano's look): what a person needs to
// act on, in a screenful. The full report stays behind `--verbose`, and the Markdown (`--out`) and JSON reports are always
// in full.
//
// Layout, in order (80 columns): the title with the audited commit; the summary line ("3 to fix · 4 to consider · 9
// already good", counts over all parts); one "changed nothing / sent nothing" line; every warning and every secret-like
// finding on disk (ruling B5: the short report hides nothing that is a warning); `Type:` one line per service; the six
// parts (src/audit/parts.ts), each with its checks as one ✗ line (fix first), one ⚠ line (consider) and one ✓ line
// (already good), and empty parts left out; "Not needed here" and "Couldn't tell"; `What now?` (the setup cost, the plan
// limits that block a ✗ check, the pointers to the details). No file:line and no how-to-fix text: they are in `--verbose`.
//
// Rows of the same check and service on push and on merge are one check (the worst status wins); the same check on several
// services is one check naming them. A check's pre-commit hook is its own check. Every value from the repo goes through
// the report's cleaning (`c.v`) once; pipegen's own sentences are written here.
import { ACTIVITY_CAPPED_PREFIX } from '../estimate/estimate.js';
import type { NeedCategory } from '../types.js';
import { num, plural } from '../util/format.js';
import { OUTPUT_CAP } from '../util/safe-output.js';
import type { Coverage } from './coverage.js';
import { noImageCheck, creditNotes, isOwnCommand, LIMIT, needLabel, type AuditReport } from './model.js';
import { PART_TITLE, partOf, type PartId } from './parts.js';
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

const MAX_SECRET_FILES = 3;
/** Lines the ✗ checks of one part may take (the rest: --verbose); ⚠ and ✓ take one line each. */
const MAX_FIX_LINES = 2;
/** Terminal width of the short report (PL-A4, owner choice 3: was 100). */
const WIDTH = 80;
const PART_IDS: readonly PartId[] = [1, 2, 3, 4, 5, 6];
const w80 = (s: string, first: string, rest?: string): string[] => wrap(s, first, rest, WIDTH);
const STATUS_RANK: Readonly<Record<Coverage['status'], number>> = { missing: 3, partial: 2, unknown: 1, covered: 0 };

const groupOf = (cov: Coverage): 'hook' | 'ci' => (cov.need.layer === 'pre-commit' ? 'hook' : 'ci');
const isGap = (cov: Coverage) => cov.status === 'missing' || cov.status === 'partial';
/** The worst row of two (missing, partial, unknown, covered); on a tie the first. */
const worse = (a: Coverage, b: Coverage) => (STATUS_RANK[b.status] > STATUS_RANK[a.status] ? b : a);

/** A GapLine with what the layout needs besides: whether the check is only partly there, and its category. */
export interface ShortGap extends GapLine { partial: boolean; category: string }

/** A ShortGap with what the ranking needs besides. */
interface Gap extends ShortGap { serious: boolean; floor: boolean; part: PartId }

/**
 * A check's name: needLabel (with the release wording for a service that builds no image), or the raw id. A pre-commit
 * hook that shares its name with its CI twin (the secret scan) says "before each commit", so no two lines read alike.
 */
function labelsOf(r: AuditReport): (cov: Coverage) => string {
  const noImage = noImageCheck(r.profile); // G17-R2 (F10): services indexed once
  const base = (cov: Coverage) => needLabel(cov.need.id, { noImage: noImage(cov.need) }) ?? cov.need.id;
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
    perService.set(key, { cov: prev === undefined ? cov : worse(prev.cov, cov), serious: (prev?.serious ?? false) || isSerious(cov, r.profile) });
  }
  const lines = new Map<string, Gap>();
  for (const { cov, serious } of perService.values()) {
    const svc = cov.need.service;
    // PL-A3: the tool is the service's own, so services with different tools split into one line per tool
    const tool = toolFor(tools, cov.need.id, svc);
    const key = `${cov.need.id}\u0000${groupOf(cov)}\u0000${cov.status}\u0000${serious ? 1 : 0}\u0000${svc === undefined ? cov.why : ''}\u0000${tool ?? ''}`;
    const prev = lines.get(key);
    if (prev === undefined) {
      lines.set(key, { check: label(cov), services: svc === undefined ? [] : [svc], why: cov.why, tool, partial: cov.status === 'partial', serious, floor: cov.need.floor, category: cov.need.category, part: partOf(cov.need) });
    } else if (svc !== undefined) prev.services.push(svc);
  }
  const all = [...lines.values()];
  const ranked = [...all.filter((g) => g.floor), ...all.filter((g) => !g.floor)];
  return { serious: ranked.filter((g) => g.serious), other: ranked.filter((g) => !g.serious) };
}

const toolKey = (id: string, service: string | undefined) => `${id}\u0000${service ?? ''}`;

/**
 * The tool the setup names for each check id and service (the first row with one): a reviewed tool, or the repo's own
 * tool or script. pipegen's own checks name none. PL-A3: keyed by service too, so a node and a python service each name
 * their own lint tool.
 */
function toolsOf(r: AuditReport): Map<string, string> {
  const out = new Map<string, string>();
  for (const w of r.wouldAdd) {
    const t = w.tool;
    const key = toolKey(w.need.id, w.need.service);
    if (t === null || out.has(key)) continue;
    if ('kind' in t) {
      if (t.kind === 'repo-tool') out.set(key, `your own ${t.tool}`);
      else if (t.kind === 'project-script') out.set(key, `your own ${t.script} script`);
    } else out.set(key, t.candidate.name);
  }
  return out;
}

/** The tool for a check on a service: the service's own row, else a repo-wide row of the check; never another service's. */
function toolFor(tools: Map<string, string>, id: string, service: string | undefined): string | null {
  return tools.get(toolKey(id, service)) ?? tools.get(toolKey(id, undefined)) ?? null;
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

/** What closes a group of checks that are for every service: said once per line, not on each check. */
const ALL_SERVICES = ' for all services';

/**
 * `items` joined by `sep` after `lead`, in at most `maxLines` lines of the short report: as many as fit, then "and N more
 * (--verbose)". At least one item is always shown (it wraps if it is longer than a line). The items from `groupFrom` on
 * are for every service: when any of them is shown the line says "for all services" once, after the last one shown.
 */
function capLine(items: string[], sep: string, lead: string, maxLines: number, groupFrom = items.length): string {
  const rest = ' '.repeat([...lead].length);
  const more = (left: number) => `${sep}and ${num(left)} more (--verbose)`;
  const text = (k: number) => items.slice(0, k).join(sep) + (k > groupFrom ? ALL_SERVICES : '') + (k < items.length ? more(items.length - k) : '');
  for (let k = items.length; k > 1; k--) if (w80(text(k), lead, rest).length <= maxLines) return text(k);
  return text(1);
}

/** Whether a check is for every service of a repo that has more than one (the one line says so once: see capLine). */
function forEveryService(g: ShortGap, all: readonly string[]): boolean {
  return all.length > 1 && g.services.length === all.length && all.every((x) => g.services.includes(x));
}

/** A part's checks of one mark as the items of capLine (the named ones first, then those for every service) and `groupFrom`. */
function markItems(c: RenderCtx, gs: ShortGap[], all: readonly string[]): { items: string[]; groupFrom: number } {
  const own = gs.filter((g) => !forEveryService(g, all));
  const everyone = gs.filter((g) => forEveryService(g, all));
  return { items: [...own, ...everyone].map((g) => gapText(c, g, all)), groupFrom: own.length };
}

/** "Check for a and b (partial) [tool]": one check as it reads inside a part line. A one-service repo leaves the service out, and a check on every service leaves it to the line (markItems). */
function gapText(c: RenderCtx, g: ShortGap, all: readonly string[]): string {
  const onlyService = all.length === 1 && g.services.length === 1 && g.services[0] === all[0];
  const named = g.services.length > 0 && !forEveryService(g, all) && !onlyService;
  const head = `${c.v(g.check)}${named ? ` for ${andList(g.services.map((x) => c.v(x)))}` : ''}${g.partial ? ' (partial)' : ''}`;
  return g.tool === null ? head : `${head} [${c.v(g.tool)}]`;
}

/** One part of the short report: its checks by mark, and the notes that belong to it. The summary's counts are sums of these. */
export interface PartView {
  part: PartId;
  title: string;
  /** Checks to fix first, then the ones to consider (the same lines rankGaps ranks). */
  fix: ShortGap[];
  consider: ShortGap[];
  /** Labels of the checks already good (every row of the check covered, in every layer and service). Raw. */
  good: string[];
  /** What a credit leaves unchecked (creditNotes) for the rows of this part. Raw. */
  notes: string[];
}

/** Every part of a report, in order (empty ones included: the layout leaves them out). */
export function shortParts(r: AuditReport): PartView[] {
  const g = gapsOf(r);
  const label = labelsOf(r);
  // a check is good only when EVERY row of it (all layers, all services) is covered: a missing, partial or unknown row keeps it out (U23)
  const open = new Set(r.coverage.filter((x) => x.status !== 'covered').map((x) => x.need.id));
  const good = new Map<PartId, Set<string>>(PART_IDS.map((p) => [p, new Set<string>()]));
  for (const x of r.coverage) if (x.status === 'covered' && !open.has(x.need.id)) good.get(partOf(x.need))?.add(label(x));
  return PART_IDS.map((part) => ({
    part, title: PART_TITLE[part],
    fix: g.serious.filter((x) => x.part === part),
    consider: g.other.filter((x) => x.part === part),
    good: [...(good.get(part) ?? [])],
    notes: creditNotes(r.coverage.filter((x) => partOf(x.need) === part), r.profile),
  }));
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

/** "Not needed here: <labels>": the checks that don't apply, on one line (the reasons are in --verbose). */
function notNeededLine(r: AuditReport, c: RenderCtx): string | null {
  if (r.skipped.length === 0) return null;
  const labels = [...new Set(r.skipped.flatMap((g) => g.categories.map((k) => c.v(needLabel(k as NeedCategory) ?? k))))];
  return `Not needed here: ${capLine(labels, ', ', 'Not needed here: ', 1)}`;
}

/** "Setup cost: …": setup minutes, monthly minutes, AI range. */
function costLine(r: AuditReport, c: RenderCtx): string {
  const e = r.estimates;
  const atLeast = e.basis.some((b) => b.startsWith(ACTIVITY_CAPPED_PREFIX));
  const ai = e.aiCostUsd === 'local' ? 'no AI cost (a local model)' : `AI ${c.usd(e.aiCostUsd.low)}–${c.usd(e.aiCostUsd.high)}`;
  const included = e.includedMinutes;
  const heavy = typeof included === 'number' && Number.isFinite(included) && included > 0 && e.monthlyMinutes > included / 2
    ? ` (more than half of the ${num(included)} your plan includes)` : '';
  return `Setup cost: ${num(e.setupMinutes)} Actions minutes, then ${num(e.monthlyMinutes)}${atLeast ? ' or more' : ''} a month${heavy}; ${ai}`;
}

/** The audited commit as the title's tail: "(f4bcfab on main)". */
function commitTail(r: AuditReport, c: RenderCtx): string {
  const k = r.commit;
  if (k === null || k === undefined) return '(no commit read)';
  return `(${c.v(k.short)}${k.branch === null ? ', detached HEAD' : ` on ${c.v(k.branch, OUTPUT_CAP.path)}`})`;
}

/** The short terminal report as a Doc: `terminal` holds its lines (cleaned and wrapped at 80). */
export function buildShortDoc(r: AuditReport, c: RenderCtx): Doc {
  const views = layerViews(r);
  const verdict = verdictOf(views.filter((v) => v.layer !== 'scheduled'));
  const parts = shortParts(r);
  const sum = (f: (p: PartView) => number) => parts.reduce((n, p) => n + f(p), 0);
  const unknown = new Set(r.coverage.filter((x) => x.status === 'unknown').map((x) => `${x.need.id}\u0000${groupOf(x)}\u0000${x.need.service ?? ''}`)).size;
  const out: string[] = [];
  const title = `pipegen audit: ${c.v(`${r.profile.owner}/${r.profile.repo}`, OUTPUT_CAP.path)}`;
  const commit = commitLine(r, c);
  out.push(...w80(`${title} ${commitTail(r, c)}`, ''));
  out.push(`${num(sum((p) => p.fix.length))} to fix · ${num(sum((p) => p.consider.length))} to consider · ${num(sum((p) => p.good.length))} already good${unknown > 0 ? ` · ${num(unknown)} couldn't tell` : ''}`);
  out.push(...w80(r.ai === undefined ? 'pipegen changed nothing in the repo or on GitHub, and sent nothing to an AI.' : 'pipegen changed nothing in the repo or on GitHub. You ran it with --ai: the AI cost is below.', ''));

  // warnings come first, and hide nothing (ruling B5)
  const secrets = secretLine(r, c);
  if (secrets !== null) out.push(...w80(secrets, '⚠ ', '  '));
  for (const w of r.warnings) {
    out.push(...w80(c.v(w.text, OUTPUT_CAP.text), '⚠ ', '  '));
    if (w.command !== undefined) out.push(isOwnCommand(w.command) ? `    ${w.command}` : `    ${c.v(w.command, OUTPUT_CAP.text)}`);
  }
  if (r.wouldAddNote !== null) out.push(...w80(c.v(r.wouldAddNote, OUTPUT_CAP.text), '⚠ ', '  '));

  for (const s of r.profile.services) {
    const t = typeText(c, s);
    if (t !== null) out.push(...w80(fit(`Type: ${t}`, WIDTH), ''));
  }

  // the parts: ✗ fix first, ⚠ consider, ✓ already good; an empty part is left out
  const all = r.profile.services.map((x) => x.name);
  for (const p of parts) {
    if (p.fix.length + p.consider.length + p.good.length + p.notes.length === 0) continue;
    out.push(`${p.part} ${p.title}`);
    const fix = markItems(c, p.fix, all);
    const consider = markItems(c, p.consider, all);
    if (p.fix.length > 0) out.push(...w80(capLine(fix.items, '; ', '  ✗ ', MAX_FIX_LINES, fix.groupFrom), '  ✗ ', '    '));
    if (p.consider.length > 0) out.push(...w80(capLine(consider.items, '; ', '  ⚠ ', 1, consider.groupFrom), '  ⚠ ', '    '));
    if (p.good.length > 0) out.push(...w80(capLine(p.good.map((x) => c.v(x)), ', ', '  ✓ ', 1), '  ✓ ', '    '));
    for (const n of p.notes) out.push(...w80(`Note: ${c.v(n, OUTPUT_CAP.text)}`, '  ', '    '));
  }
  const skipped = notNeededLine(r, c);
  if (skipped !== null) out.push(...w80(skipped, ''));
  if (unknown > 0) out.push(`Couldn't tell: ${plural(unknown, 'check', 'checks')} (--verbose)`);

  // what now: the setup cost, a plan limit when it blocks a ✗ check, the pointers
  out.push('What now?');
  out.push(...w80(costLine(r, c), '  ', '    '));
  if (r.ai !== undefined) out.push(...w80(`AI cost of this audit: ${aiCostText(r.ai, c)}`, '  ', '    '));
  const fixed = parts.flatMap((p) => p.fix);
  for (const [key, text] of Object.entries(LIMIT) as [keyof typeof LIMIT, string][]) {
    if (!r.limits.includes(text)) continue;
    if (!LIMIT_CATEGORIES[key].some((cat) => fixed.some((x) => x.category === cat))) continue;
    out.push(...w80(c.v(text, OUTPUT_CAP.text), '  ⚠ ', '    '));
  }
  if (r.support.nextCommand !== null && r.support.nextCommand !== undefined && isOwnCommand(r.support.nextCommand)) out.push(`    ${r.support.nextCommand}`);
  out.push('  More: pipegen --verbose (file, line, how to fix) · --out report.md');
  return { title, intro: [], commit, verdict, sections: [], terminal: out };
}
