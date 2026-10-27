// The audit report (Plan U Task 3): AuditReport as terminal text, as a Markdown file (`--out`) and as JSON (`--json`).
// Written for small teams with nobody doing security: plain English, warnings first, nothing claimed that the model
// doesn't say.
//
// Order (the brief, 1-9): the verdict; ⚠ warnings (secrets in the files on disk, then `warnings`); what the GitHub plan
// allows (its limits first); the four layers; what pipegen would add and create (with `--ai`: the AI's extra checks
// and its mention-only tools); the full setup's costs with their basis; what the full setup would send to the AI; the
// permissions it needs; the notes and what this audit can't see; the next step.
//
// Rulings: S8 (the next step is the model's text, keyed by CURRENT_MILESTONE; no command that doesn't exist in v0.1),
// S12 (monthly minutes highlighted only when the plan's included minutes are known and the estimate is over half of
// them; the basis always shown), S13 (renderJson: every string cleaned, wouldAdd tools slimmed), S14 (a layer is
// serious when a blocking floor need in it is missing or partial; a layer with no needs is "not needed" and isn't
// counted), S27 (starter-tests and 0-services texts as given), S29 (the terminal groups the excluded patterns with the
// consent screen's builder; Markdown and JSON list every one), U10 (one output helper for every repo, GitHub or AI
// string: known values, then redact, then safeText / safeMarkdown), Review Focus 3 (never "make the repo public").
//
// Every value from the report goes through safeOutput() exactly once, here; pipegen's own sentences are written
// Markdown-safe by hand. Repo values are never put inside backticks. No colours: plain text, ⚠ and simple markers.
import { excludedSummaryLines } from '../ai/redact.js';
import type { Layer, Part } from '../types.js';
import { OUTPUT_CAP, safeOutput, type OutputTarget } from '../util/safe-output.js';
import { safeMarkdown } from '../util/safe-text.js';
import type { Coverage } from './coverage.js';
import type { AuditAi, AuditReport, WouldAddRow, WouldAddTool } from './model.js';

export interface RenderOptions {
  /**
   * The GitHub token (when set) and the AI key in use (rulings S19, U10). Scrubbed from every output string, in every
   * form scrubKnownValues knows; never printed. Pass [] only when there is neither.
   */
  knownValues: readonly string[];
  /** Clock for the Markdown report's date; default Date.now. */
  now?: () => number;
}

/** What this audit can't see (the Plan U Task 1 parked limits), in plain words. Shown in every report. */
export const CANT_SEE: readonly string[] = Object.freeze([
  "pipegen checks that a tool runs on the right trigger and can fail the build; it doesn't check the tool's other settings.",
  'A tool and a test joined on one line, like `{ tool; [[ … ]] } || true`, can hide a failing tool, and pipegen may still count it as covered (rare).',
  "Commands inside `bash -c '…'` or a quoted `\"$(…)\"` aren't read, so a tool run there shows as partial or missing.",
  "A `runs-on` set by an expression is read as Linux.",
  'Tools inside shell functions, and jobs whose matrix includes Windows, show as partial.',
  'Very large repos (over 10,000 folders with runs, or 5,000 services) show some checks as unknown.',
  "Reusable workflows from other repos, and actions from your own account, can't be looked inside: those checks show as unknown.",
]);

const LAYERS: readonly Layer[] = ['pre-commit', 'push', 'merge', 'deploy'];
const LAYER_TITLE: Readonly<Record<Layer, string>> = {
  'pre-commit': "Before each commit (git hooks on the developer's machine)",
  push: 'On every push',
  merge: 'On every pull request, before merge',
  deploy: 'When the code is deployed or released',
};
const LAYER_WHEN: Readonly<Record<Layer, string>> = {
  'pre-commit': 'before each commit',
  push: 'on every push',
  merge: 'on every pull request',
  deploy: 'at deploy',
};
const NOT_NEEDED: Readonly<Record<Layer, string>> = {
  'pre-commit': 'not needed: no checks apply here',
  push: 'not needed: no checks apply here',
  merge: 'not needed: no checks apply here',
  deploy: 'not needed: nothing here runs or deploys',
};
const PART_LABEL: Readonly<Record<Part, string>> = {
  pipeline: 'Pipeline', precommit: 'Pre-commit hooks', docker: 'Dockerfile', compose: 'Compose file', tests: 'Starter tests',
  'test-migration': 'Test migration', codeowners: 'Code owners', 'deploy-verify': 'Deploy check', docs: 'Docs',
};
const CAPABILITY_NAMES: readonly [keyof AuditReport['capabilities'], string][] = [
  ['branchProtection', 'merge rules'], ['environments', 'environments'], ['envRequiredReviewers', 'required deploy reviewers'],
  ['attestations', 'artifact attestations'], ['codeScanning', 'code scanning'], ['keylessSigningAllowed', 'keyless signing'],
];
const PLAN_UNKNOWN = "not known (GitHub shows it only to the account's own token, or to an organisation member)";
const MAX_TOP_FOLDERS = 10;
/** Files listed under "secret-like text" in the terminal; Markdown and JSON list them all. */
const MAX_SECRET_FILES_TERMINAL = 30;
const WIDTH = 100;

// ---------- the document: target-neutral blocks of cleaned text ----------

interface Row { serious: boolean; status: Coverage['status']; check: string; why: string; found: string | null }
type Block =
  | { kind: 'text'; text: string }
  | { kind: 'item'; text: string; depth: number; warn: boolean }
  | { kind: 'sub'; title: string }
  | { kind: 'rows'; rows: Row[] };
interface Section { title: string; blocks: Block[] }
interface Doc { title: string; intro: string[]; verdict: string; sections: Section[] }

/** How values are cleaned and amounts written for one target. */
interface Ctx {
  target: OutputTarget;
  /** A repo, GitHub or AI string (ruling U10). */
  v(s: string, max?: number): string;
  /** pipegen's own fixed table (the permissions): every step but redact (see safeOutput). */
  own(s: string, max?: number): string;
  usd(n: number): string;
}

function ctxFor(target: OutputTarget, knownValues: readonly string[]): Ctx {
  return {
    target,
    v: (s, max = OUTPUT_CAP.name) => safeOutput(s, { target, knownValues, max }),
    own: (s, max = OUTPUT_CAP.text) => safeOutput(s, { target, knownValues, max, redact: false }),
    // Markdown: safeMarkdown puts U+200B and a backslash before the $, so GitHub math can't start
    usd: (n) => (target === 'markdown' ? safeMarkdown(money(n)) : money(n)),
  };
}

const money = (n: number) => `$${(Number.isFinite(n) ? n : 0).toFixed(2)}`;
const num = (n: number) => (Number.isFinite(n) ? n : 0).toLocaleString('en-US');
const plural = (n: number, one: string, many: string) => `${num(n)} ${n === 1 ? one : many}`;
const size = (bytes: number) => (bytes >= 1024 * 1024 ? `about ${(bytes / (1024 * 1024)).toFixed(1)} MB` : `about ${Math.max(1, Math.round(bytes / 1024))} KB`);
const text = (t: string): Block => ({ kind: 'text', text: t });
const item = (t: string, depth = 0, warn = false): Block => ({ kind: 'item', text: t, depth, warn });

// ---------- layers and the verdict (ruling S14) ----------

interface LayerView { layer: Layer; rows: Coverage[]; needed: boolean; gaps: boolean; serious: boolean; unknown: boolean; covered: number }

/** A blocking floor need (every coverage row is a floor need) that is missing or partial. */
const isSerious = (c: Coverage) => c.need.blocking === true && (c.status === 'missing' || c.status === 'partial');

function layerViews(r: AuditReport): LayerView[] {
  return LAYERS.map((layer) => {
    const rows = r.coverage.filter((c) => c.need.layer === layer);
    return {
      layer, rows, needed: rows.length > 0,
      gaps: rows.some((c) => c.status === 'missing' || c.status === 'partial'),
      serious: rows.some(isSerious),
      unknown: rows.some((c) => c.status === 'unknown'),
      covered: rows.filter((c) => c.status === 'covered').length,
    };
  });
}

function verdictOf(views: LayerView[]): string {
  const needed = views.filter((v) => v.needed);
  const m = needed.length;
  const g = needed.filter((v) => v.gaps).length;
  const s = needed.filter((v) => v.serious).length;
  const u = needed.filter((v) => v.unknown).length;
  if (m === 0) return 'no layer needs a check here.';
  if (g === 0 && u === 0) return `all ${m} layers are covered.`;
  let out = `${g} of ${m} layers ${g === 1 ? 'has' : 'have'} gaps`;
  out += g === 0 ? '.' : s === 0 ? '; none is serious.' : `; ${s} ${s === 1 ? 'is' : 'are'} serious.`;
  if (u > 0) out += ` pipegen couldn't check everything in ${plural(u, 'layer', 'layers')}.`;
  return out;
}

function layerStatus(v: LayerView): string {
  if (!v.needed) return NOT_NEEDED[v.layer];
  const of = `${v.covered} of ${v.rows.length} checks covered`;
  if (v.serious) return `serious gaps (${of})`;
  if (v.gaps) return `gaps (${of})`;
  if (v.unknown) return `pipegen couldn't check everything (${of})`;
  return `covered (${of})`;
}

const checkLabel = (c: Ctx, id: string, service: string | undefined) => `${c.v(id)}${service === undefined ? '' : ` (${c.v(service)})`}`;

function row(c: Ctx, cov: Coverage): Row {
  const by = cov.by === undefined ? null : c.v(cov.by, OUTPUT_CAP.path);
  const where = cov.where === undefined ? null : c.v(cov.where, OUTPUT_CAP.path);
  return {
    serious: isSerious(cov), status: cov.status, check: checkLabel(c, cov.need.id, cov.need.service), why: c.v(cov.why, OUTPUT_CAP.text),
    found: by !== null && where !== null ? `${by} in ${where}` : by ?? where,
  };
}

// ---------- sections ----------

function warningsSection(r: AuditReport, c: Ctx): Section | null {
  const blocks: Block[] = [];
  if (r.secretsInTree.length > 0) {
    blocks.push(item('Secret-like text in the files on disk now (pipegen never shows the values):', 0, true));
    // one line per file, its rules together, in the model's order
    const files = new Map<string, { rules: string[]; note: string | null }>();
    for (const s of r.secretsInTree) {
      const file = c.v(s.file, OUTPUT_CAP.path);
      const entry = files.get(file) ?? { rules: [], note: null };
      const rule = c.v(s.rule);
      if (!entry.rules.includes(rule)) entry.rules.push(rule);
      if (s.note !== undefined && entry.note === null) entry.note = c.v(s.note, OUTPUT_CAP.text);
      files.set(file, entry);
    }
    const all = [...files];
    const shown = c.target === 'terminal' ? all.slice(0, MAX_SECRET_FILES_TERMINAL) : all;
    for (const [file, e] of shown) blocks.push(item(`${file}: ${e.rules.join(', ')}${e.note === null ? '' : ` ${e.note}`}`, 1));
    if (shown.length < all.length) blocks.push(item(`…and ${plural(all.length - shown.length, 'more file', 'more files')}.`, 1));
  }
  for (const w of r.warnings) blocks.push(item(c.v(w, OUTPUT_CAP.text), 0, true));
  return blocks.length === 0 ? null : { title: '⚠ Warnings', blocks };
}

function planSection(r: AuditReport, c: Ctx): Section {
  const blocks: Block[] = [];
  // the limits first (Review Focus 3: never "make the repo public")
  for (const l of r.limits) blocks.push(item(c.v(l, OUTPUT_CAP.text), 0, true));
  if (r.limits.length === 0) blocks.push(text('Nothing here limits the pipeline pipegen would build.'));
  const available = CAPABILITY_NAMES.filter(([k]) => r.capabilities[k] === true).map(([, name]) => name);
  blocks.push(text(`Available here: ${available.length === 0 ? 'none of the GitHub features pipegen uses' : available.join(', ')}.`));
  const p = r.profile;
  const owner = p.ownerType === 'Organization' ? 'an organisation' : 'a user account';
  const plan = p.plan === 'unknown' ? PLAN_UNKNOWN : c.v(p.plan);
  blocks.push(text(`Repo: ${p.private ? 'private' : 'public'}, owned by ${owner}, GitHub plan: ${plan}.`));
  return { title: 'What your GitHub plan allows', blocks };
}

function layersSection(c: Ctx, views: LayerView[]): Section {
  const blocks: Block[] = [];
  for (const v of views) {
    blocks.push({ kind: 'sub', title: `${LAYER_TITLE[v.layer]}: ${layerStatus(v)}` });
    if (v.needed) blocks.push({ kind: 'rows', rows: v.rows.map((cov) => row(c, cov)) });
  }
  return { title: 'Checks by layer', blocks };
}

function toolText(c: Ctx, w: WouldAddRow): string {
  const note = c.v(w.note, OUTPUT_CAP.text);
  const t: WouldAddTool = w.tool;
  if (t === null) return `no reviewed tool yet (${note})`;
  if ('kind' in t) return note; // pipegen's own check, or the service's own script
  return `${c.v(t.candidate.name)} ${c.v(t.candidate.version)} (${c.v(t.candidate.repo)}), ${note}`;
}

function aiBlocks(ai: AuditAi, reviewedUnavailable: boolean, c: Ctx): Block[] {
  const blocks: Block[] = [{ kind: 'sub', title: 'What the AI suggests (--ai)' }];
  if (ai.extraNeeds.length === 0) blocks.push(text('The AI suggests no extra checks.'));
  for (const n of ai.extraNeeds) {
    const when = LAYER_WHEN[n.layer] ?? c.v(n.layer);
    blocks.push(item(`the AI also suggests checking ${checkLabel(c, n.id, n.service)}, ${when}: ${c.v(n.why, OUTPUT_CAP.text)}`));
  }
  if (ai.suggestions.length > 0) {
    blocks.push(text('Tools the AI mentions (not reviewed, never run by pipegen):'));
    for (const s of ai.suggestions) blocks.push(item(`${c.v(s.name)} (${c.v(s.repo, OUTPUT_CAP.path)}): ${c.v(s.why, OUTPUT_CAP.text)}`));
  } else {
    blocks.push(text(reviewedUnavailable ? 'The AI mentions no tools (the reviewed list was unavailable).' : 'The AI mentions no tools.'));
  }
  const notes = dedupe(ai.notes.map((n) => c.v(n, OUTPUT_CAP.text)));
  if (notes.length > 0) {
    blocks.push(text('Notes from the AI step:'));
    for (const n of notes) blocks.push(item(n));
  }
  blocks.push(text(`AI cost of this audit: ${aiCostText(ai, c)}`));
  return blocks;
}

/** About what the AI step cost: the meter's per-attempt list costs, summed (AuditAi.costUsd). */
function aiCostText(ai: AuditAi, c: Ctx): string {
  const calls = ai.attempts.length;
  if (calls === 0 && !(ai.costUsd > 0)) {
    return "No AI usage was recorded. (A call that ended without reporting its usage, such as a timeout, isn't counted.)";
  }
  const cost = ai.costUsd > 0 && ai.costUsd < 0.005 ? `less than ${c.usd(0.01)}` : `about ${c.usd(ai.costUsd)}`;
  const u = ai.usage;
  const cached = u.cacheReadTokens + u.cacheWriteTokens;
  const tokens = `${num(u.inputTokens)} input${cached > 0 ? ` (plus ${num(cached)} cached)` : ''} and ${num(u.outputTokens)} output tokens`;
  return `${cost} at list price (${plural(calls, 'AI call', 'AI calls')}; ${tokens}).`;
}

function addSection(r: AuditReport, c: Ctx): Section {
  const blocks: Block[] = [];
  if (r.wouldAdd.length > 0) {
    blocks.push(text("For each check that isn't covered:"));
    for (const w of r.wouldAdd) {
      blocks.push(item(`${checkLabel(c, w.need.id, w.need.service)}, ${LAYER_WHEN[w.need.layer]} (now ${w.status}): ${toolText(c, w)}`));
    }
  }
  if (r.testsNote !== null) blocks.push(text(c.v(r.testsNote, OUTPUT_CAP.text)));
  if (r.wouldCreate.length > 0) {
    blocks.push(text('pipegen would also create:'));
    for (const w of r.wouldCreate) blocks.push(item(`${PART_LABEL[w.what] ?? c.v(w.what)}: ${c.v(w.why, OUTPUT_CAP.text)}`));
  }
  if (blocks.length === 0) blocks.push(text('Nothing: every check is already covered.'));
  if (r.ai !== undefined) blocks.push(...aiBlocks(r.ai, r.reviewedUnavailable, c));
  return { title: 'What pipegen would add', blocks };
}

function costsSection(r: AuditReport, c: Ctx): Section {
  const e = r.estimates;
  const blocks: Block[] = [];
  blocks.push(item(`Setup: about ${num(e.setupMinutes)} GitHub Actions minutes, with a hard limit of ${num(e.setupMinutesCap)} (the proof stops there).`));
  // a capped activity count (ruling S12) makes the monthly figure a lower bound
  const atLeast = e.basis.some((b) => b.startsWith('Activity: at least'));
  blocks.push(item(`After setup: about ${num(e.monthlyMinutes)} minutes a month${atLeast ? ', or more (pipegen could count only part of the activity)' : ''}.`));
  const included = e.includedMinutes;
  if (typeof included === 'number' && Number.isFinite(included) && included > 0) {
    if (e.monthlyMinutes > included / 2) {
      const pct = Math.round((e.monthlyMinutes / included) * 100);
      blocks.push(item(`That is more than half of the ${num(included)} minutes your plan includes each month (${pct}%).`, 1, true));
    } else {
      blocks.push(item(`Your plan includes ${num(included)} minutes a month for private repos.`, 1));
    }
  }
  if (e.aiCostUsd === 'local') {
    blocks.push(item('AI: none counted (a local model).'));
  } else {
    const a = e.aiCostUsd;
    const range = (x: { low: number; high: number }) => `${c.usd(x.low)}–${c.usd(x.high)}`;
    const cap = e.aiCostCapUsd === null ? '' : `; pipegen stops calling the AI at ${c.usd(e.aiCostCapUsd)}`;
    blocks.push(item(`AI: input ${range(a.input)}, output ${range(a.output)} (total ${range(a)})${cap}.`));
  }
  blocks.push(item(`Time: about ${num(e.durationMinutes.low)}–${num(e.durationMinutes.high)} minutes.`));
  if (e.basis.length > 0) {
    blocks.push(text('How these estimates were made:'));
    for (const b of e.basis) blocks.push(item(c.v(b, OUTPUT_CAP.text)));
  }
  return { title: 'Costs of the full setup (estimates)', blocks };
}

function bundleSection(r: AuditReport, c: Ctx): Section {
  const b = r.aiBundle;
  const blocks: Block[] = [text(`pipegen would send ${plural(b.files, 'file', 'files')} (${size(b.bytes)}) to the AI.`)];
  if (b.truncated) blocks.push(text('That is as much as fits: the code reached its size limit, so the rest would not be sent.'));
  const shown = b.topFolders.slice(0, MAX_TOP_FOLDERS).map((f) => c.v(f, OUTPUT_CAP.path));
  const more = b.topFolders.length - shown.length;
  blocks.push(text(`Top folders: ${shown.length === 0 ? '(all at the top level)' : `${shown.join(', ')}${more > 0 ? ` and ${num(more)} more` : ''}`}.`));
  if (c.target === 'terminal') {
    blocks.push(text('Never sent:'));
    // ruling S29: the consent screen's grouped summary, from the same builder
    for (const line of excludedSummaryLines()) blocks.push({ kind: 'item', text: line.replace(/^- /, ''), depth: 0, warn: false });
  } else {
    blocks.push(text('Never sent (every pattern; one that starts with ! keeps a file):'));
    for (const p of b.excludedPatterns) blocks.push(item(c.v(p, OUTPUT_CAP.path)));
  }
  blocks.push(text('These are counts only, never file contents. They were made without the gitleaks check; before anything is sent, '
    + 'gitleaks checks every file for secrets and secret-looking values are hidden, so the real bundle can differ slightly.'));
  return { title: 'What the full setup would send to the AI', blocks };
}

function permissionsSection(r: AuditReport, c: Ctx): Section {
  const blocks = r.permissions.map((p) => item(`${c.own(p.permission, OUTPUT_CAP.name)}: ${c.own(p.why)}`));
  return { title: 'Permissions the full setup needs', blocks: blocks.length === 0 ? [text('None listed.')] : blocks };
}

function notesSection(r: AuditReport, c: Ctx): Section | null {
  const notes = dedupe(r.notes.map((n) => c.v(n, OUTPUT_CAP.text)));
  return notes.length === 0 ? null : { title: 'Notes', blocks: notes.map((n) => item(n)) };
}

function nextSection(r: AuditReport, c: Ctx): Section {
  const blocks: Block[] = r.support.reasons.map((x) => item(c.v(x, OUTPUT_CAP.text)));
  blocks.push(text(c.v(r.support.nextStep, OUTPUT_CAP.text)));
  return { title: 'Next step', blocks };
}

const dedupe = (xs: string[]) => [...new Set(xs)];

function buildDoc(r: AuditReport, c: Ctx): Doc {
  const views = layerViews(r);
  const intro = ['pipegen changed nothing in the repo or on GitHub.'];
  intro.push(r.ai === undefined ? 'Nothing was sent to an AI.' : 'You ran it with --ai: the AI part below says what the AI step found.');
  const sections = [
    warningsSection(r, c), planSection(r, c), layersSection(c, views), addSection(r, c), costsSection(r, c), bundleSection(r, c),
    permissionsSection(r, c), notesSection(r, c), { title: "What this audit can't see", blocks: CANT_SEE.map((l) => item(l)) }, nextSection(r, c),
  ].filter((s): s is Section => s !== null);
  return { title: `pipegen audit: ${c.v(`${r.profile.owner}/${r.profile.repo}`, OUTPUT_CAP.path)}`, intro, verdict: verdictOf(views), sections };
}

// ---------- terminal ----------

/** Words wrapped to WIDTH code points; a word longer than a line is cut across lines. */
function wrap(s: string, first: string, rest: string = ' '.repeat([...first].length)): string[] {
  const out: string[] = [];
  let line = first;
  let len = [...first].length;
  let fresh = true;
  const restLen = [...rest].length;
  for (const word of s.split(' ')) {
    if (word === '') continue;
    let w = [...word];
    if (!fresh && len + 1 + w.length > WIDTH) {
      out.push(line);
      line = rest;
      len = restLen;
      fresh = true;
    }
    while ((fresh ? 0 : 1) + w.length > WIDTH - len && WIDTH - len > 10) {
      const take = WIDTH - len - (fresh ? 0 : 1);
      out.push(`${line}${fresh ? '' : ' '}${w.slice(0, take).join('')}`);
      w = w.slice(take);
      line = rest;
      len = restLen;
      fresh = true;
    }
    line += `${fresh ? '' : ' '}${w.join('')}`;
    len += (fresh ? 0 : 1) + w.length;
    fresh = false;
  }
  out.push(line);
  return out;
}

const STATUS_WIDTH = 8;

function terminalBlocks(blocks: Block[]): string[] {
  const out: string[] = [];
  for (const b of blocks) {
    if (b.kind === 'text') out.push(...wrap(b.text, '  '));
    else if (b.kind === 'item') out.push(...wrap(b.text, `${'  '.repeat(b.depth + 1)}${b.warn ? '⚠ ' : '- '}`));
    else if (b.kind === 'sub') out.push('', ...wrap(b.title, '  '));
    else {
      for (const r of b.rows) {
        const lead = `    ${r.serious ? '⚠' : ' '} ${r.status.padEnd(STATUS_WIDTH)} `;
        const pad = ' '.repeat(lead.length);
        out.push(...wrap(r.check, lead, pad), ...wrap(r.why, pad));
        if (r.found !== null) out.push(...wrap(`Found: ${r.found}`, pad));
      }
    }
  }
  return out;
}

/** The report for the terminal: plain text, no colours, lines wrapped at 100 characters. */
export function renderTerminal(r: AuditReport, opts: RenderOptions): string {
  const doc = buildDoc(r, ctxFor('terminal', opts.knownValues));
  const lines = [...wrap(doc.title, ''), ...doc.intro.flatMap((l) => wrap(l, '')), '', ...wrap(`Verdict: ${doc.verdict}`, '')];
  for (const s of doc.sections) lines.push('', s.title, ...terminalBlocks(s.blocks));
  return lines.join('\n');
}

// ---------- Markdown ----------

function markdownBlocks(blocks: Block[]): string[] {
  const out: string[] = [];
  let last: Block['kind'] | null = null;
  for (const b of blocks) {
    // items run together as one list; anything else is its own paragraph
    if (last !== null && !(b.kind === 'item' && last === 'item')) out.push('');
    if (b.kind === 'text') out.push(b.text);
    else if (b.kind === 'item') out.push(`${'  '.repeat(b.depth)}- ${b.warn ? '⚠ ' : ''}${b.text}`);
    else if (b.kind === 'sub') out.push(`### ${b.title}`);
    else {
      out.push('| | Status | Check | Why | Found |', '|---|---|---|---|---|');
      for (const r of b.rows) out.push(`| ${r.serious ? '⚠' : ' '} | ${r.status} | ${r.check} | ${r.why} | ${r.found ?? '—'} |`);
    }
    last = b.kind;
  }
  return out;
}

/** The report as a Markdown file (`--out`): every value through safeMarkdown, every excluded pattern listed. */
export function renderMarkdown(r: AuditReport, opts: RenderOptions): string {
  const doc = buildDoc(r, ctxFor('markdown', opts.knownValues));
  const at = (opts.now ?? Date.now)();
  const date = Number.isFinite(at) ? `Audited on ${new Date(at).toISOString().slice(0, 10)}. ` : '';
  const lines = [`# ${doc.title}`, '', `${date}${doc.intro.join(' ')}`, '', `**Verdict:** ${doc.verdict}`];
  for (const s of doc.sections) lines.push('', `## ${s.title}`, '', ...markdownBlocks(s.blocks));
  return `${lines.join('\n')}\n`;
}

// ---------- JSON (ruling S13) ----------

/** Keys whose strings are prose (why texts, notes, basis lines): the long cap. */
const PROSE_KEYS: ReadonlySet<string> = new Set(['why', 'note', 'notes', 'basis', 'reasons', 'warnings', 'limits', 'nextStep', 'testsNote', 'message']);
/** Keys whose strings are paths (or lists of paths): a larger cap than names. */
const PATH_KEYS: ReadonlySet<string> = new Set(['path', 'file', 'where', 'by', 'dockerfile', 'evidence', 'topFolders', 'excludedPatterns', 'terraformDirs', 'repo']);
const capFor = (key: string) => (PROSE_KEYS.has(key) ? OUTPUT_CAP.text : PATH_KEYS.has(key) ? OUTPUT_CAP.path : OUTPUT_CAP.name);

/** A wouldAdd tool as `{ kind, id, name, repo, version }` (only the fields it has). */
function slimTool(t: WouldAddTool): Record<string, string> | null {
  if (t === null) return null;
  if ('kind' in t) return t.kind === 'built-in' ? { kind: 'built-in' } : { kind: 'project-script', id: t.needId, name: t.script };
  return { kind: 'reviewed', id: t.id, name: t.candidate.name, repo: t.candidate.repo, version: t.candidate.version };
}

/** Every string (keys too) through safeOutput; numbers, booleans and null kept; anything else dropped. */
function deepClean(v: unknown, key: string, own: boolean, knownValues: readonly string[], ancestors: Set<object>): unknown {
  if (typeof v === 'string') return safeOutput(v, { target: 'terminal', knownValues, max: capFor(key), redact: !own });
  if (typeof v === 'number' || typeof v === 'boolean' || v === null) return v;
  // `ancestors`: only a cycle is dropped; an object shared by two rows (a row's need) is written in both
  if (typeof v !== 'object' || ancestors.has(v)) return null;
  ancestors.add(v);
  try {
    if (Array.isArray(v)) return v.map((x) => deepClean(x, key, own, knownValues, ancestors));
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      if (x === undefined || typeof x === 'function' || typeof x === 'symbol' || typeof x === 'bigint') continue;
      // the permission table is pipegen's own: redact would cut "Secrets: read and write"
      out[safeOutput(k, { target: 'terminal', knownValues })] = deepClean(x, k, own || k === 'permissions', knownValues, ancestors);
    }
    return out;
  } finally {
    ancestors.delete(v);
  }
}

/** The report as JSON (`--json`): JSON.stringify(deepClean(r), null, 2), with wouldAdd tools slimmed. */
export function renderJson(r: AuditReport, opts: RenderOptions): string {
  const slim = { ...r, wouldAdd: r.wouldAdd.map((w) => ({ ...w, tool: slimTool(w.tool) })) };
  return JSON.stringify(deepClean(slim, '', false, opts.knownValues, new Set()), null, 2);
}
