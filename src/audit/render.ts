// The audit report (Plan U Task 3): AuditReport as terminal text, as a Markdown file (`--out`) and as JSON (`--json`).
// Written for small teams with nobody doing security: plain English, warnings first, nothing claimed that the model
// doesn't say.
//
// Order (the brief, 1-9): the verdict; ⚠ warnings (secrets in the files on disk, then `warnings`); what the GitHub plan
// allows (its limits first); the four layers and the scheduled group (Plan P Task 9); the checks that don't apply
// here; what pipegen would add and create (with `--ai`: the AI's extra checks
// and its mention-only tools); the full setup's costs with their basis; what the full setup would send to the AI; the
// permissions it needs (after the settings `finish` would turn on); the notes and what this audit can't see; the next
// step.
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
// U16: pipegen's own checks (gate, deploy-verify) are gaps pipegen fills, never "serious". U17: pipegen's own fixed
// commands (AuditWarning.command, support.nextCommand) are printed unescaped on a line of their own, never wrapped, and
// in a Markdown code block, after isOwnCommand() confirms they are exactly what the model builds (no repo data).
// Arrays whose size depends on the repo are appended with loops, never spread into a call (a spread of ~100k lines
// overflows the stack).
import { excludedSummaryLines, type ScanFound } from '../ai/redact.js';
import { SCHEDULED_CATEGORIES } from '../engine/need-ids.js';
import { ACTIVITY_CAPPED_PREFIX } from '../estimate/estimate.js';
import type { RepoToolStep } from '../engine/reviewed.js';
import type { Layer, Need, Part, ReviewedTool } from '../types.js';
import type { SkippedGroup, WouldSet } from './choose.js';
import { num, plural, size, usd as money } from '../util/format.js';
import { makeSafeOutput, OUTPUT_CAP, type OutputTarget } from '../util/safe-output.js';
import { safeMarkdown } from '../util/safe-text.js';
import { K8S_FOLDERS } from '../read/quality.js';
import { COVERAGE_LIMITS, type Coverage } from './coverage.js';
import {
  buildsNoImage, isBuiltInNeed, isOwnCommand, needLabel, SECRET_CHECK, type AuditAi, type GitHubFact, type AuditReport, type LocalAudit, type WouldAddRow, type WouldAddTool,
} from './model.js';

export interface RenderOptions {
  /**
   * The GitHub token (when set) and the AI key in use (rulings S19, U10). Scrubbed from every output string, in every
   * form scrubKnownValues knows; never printed. Pass [] only when there is neither.
   */
  knownValues: readonly string[];
  /**
   * P40/P45: in an `audit --ai` run, what the secret scan found (the checked bundle's `found`: flagged names, found
   * values). Masked in every output string, the plain-audit sections and JSON keys too, before any cut; never printed.
   */
  found?: ScanFound;
  /** Clock for the Markdown report's date; default Date.now. */
  now?: () => number;
}

const L = COVERAGE_LIMITS;
/**
 * What this audit can't see (the Plan U Task 1 parked limits), in plain words. Shown in every report, and in `--json`
 * as `cantSee`. The Plan U final review (M3) lined it up with the code: paths filters and `if:` conditions read partial,
 * the per-run budgets (numbers from COVERAGE_LIMITS, the ones mapCoverage uses) and nested local actions read unknown,
 * and a visible TOX… / NOX… variable reads partial.
 */
export const CANT_SEE: readonly string[] = Object.freeze([
  "pipegen checks that a tool runs on the right trigger and can fail the build; it doesn't check the tool's other settings.",
  "Workflows limited by `paths:` or `paths-ignore:`, and jobs or steps with an `if:` condition, show as partial: pipegen can't tell when they run.",
  'A tool and a test joined on one line, like `{ tool; [[ … ]] } || true`, can hide a failing tool, and pipegen may still count it as covered (rare).',
  "Commands inside `bash -c '…'` or a quoted `\"$(…)\"` aren't read, so a tool run there shows as partial or missing.",
  "A `runs-on` set by an expression is read as Linux.",
  'Tools inside shell functions, and jobs whose matrix includes Windows, show as partial.',
  `Very large repos show some checks as unknown: past ${num(L.workflows)} workflow files, ${num(L.jobs)} jobs in a workflow, ${num(L.steps)} steps in a job or action, `
    + `${num(L.localFiles)} local workflows and actions followed, ${num(L.runTextMb)} MB of run text, ${num(L.stepVisits)} steps visited in all, `
    + `${num(L.hits)} tool findings, ${num(L.hitDirs)} folders with runs, or ${num(L.services)} services.`,
  "Reusable workflows from other repos, and actions from your own account, can't be looked inside: those checks show as unknown.",
  "Shell tricks such as `trap … EXIT`, `alias`, or a function named like the test tool aren't modelled, so a repo built to fool the audit could make a check look covered.",
  "A local action or reusable workflow that calls another local one isn't followed past the first level, so those checks show as unknown.",
  // Plan U Task 5 fix round 2 (review M4): limits of the checks Task 5 added, each erring toward covered
  "`tox` counts as your own test run whatever environments its config lists: pipegen doesn't read tox's env_list.",
  "A tox or nox run whose environments a TOX… or NOX… variable in the job picks (like TOXENV from a matrix) shows as partial: pipegen doesn't read the variable's value, so it can't tell if the tests run.",
  "Variables that change what runs (SKIP for pre-commit, TOX… and NOX… for tox and nox, NPM_CONFIG_DRY_RUN) aren't seen when an action from another repo sets them, or when a step writes them under a name built while it runs.",
  "Dockerfile RUN lines count only when a `docker build`, docker/build-push-action or `docker compose build` step names the Dockerfile with plain paths, and only for the stages the final stage (or the target) needs. Build arguments, Compose profiles, `extends` and `include` aren't read.",
  "A pre-commit hook pinned to a commit SHA (`rev:`) isn't checked to be a commit of the hook's own repo, so it could come from a fork.",
  'pipegen knows the PyPI publish action up to v1.14.3: a newer release pinned by its commit SHA shows as partial until pipegen is updated.',
  "A test or lint script whose runner pipegen doesn't know (like `node test.js`) is trusted by its name: pipegen only lowers it when the script clearly does nothing or can't fail.",
  // Plan P Task 9
  "Coverage minimums in JS or TS config files (like jest.config.js or vitest.config.ts) are read as text: pipegen finds the setting but can't run the file, so it can't confirm the minimum.",
  "Renovate presets (`extends`) aren't followed, so a setting that comes from a shared preset isn't seen.",
  "Repo settings on GitHub (required checks, secret scanning, the default token permissions) aren't read, so pipegen can't say whether they are already on.",
  "A workflow without a `permissions:` block gets the repo's default token permissions, a setting pipegen can't see.",
  "A deploy workflow that uses no secret and no write grant isn't seen as a release.",
  'Network egress control (blocking unexpected traffic from release jobs) is only partly read on larger runners.',
  "Environment variables set by third-party actions aren't seen, so a check one of them turns off can show as covered.",
  "pipegen can't check yet that an ESLint config reads .vue, .svelte and .astro files (the parsers and plugins come in v0.2): such a repo never shows a clean pass for ESLint.",
  // hand checks 2026-10-29 (fix 1, ruling P55)
  "The quick secret check on the files on disk looks only for a few secret formats (private keys, some token formats, JWTs, passwords in connection strings); it doesn't read `name = value` lines, such as an API key or a password set in code or in a .env file, so it is not a secret scan.",
  // final review m1
  `Kubernetes manifests are looked for only in YAML under folders named ${K8S_FOLDERS.slice(0, -1).join(', ')} or ${K8S_FOLDERS.at(-1)} (and a Chart.yaml anywhere), so manifests kept elsewhere, like infra/, aren't seen.`,
]);

/** Plan P Task 9: the four layers, and a fifth group for the SCHEDULED_CATEGORIES rows (merge-layer needs read on their own trigger). */
type Group = Layer | 'scheduled';
const GROUPS: readonly Group[] = ['pre-commit', 'push', 'merge', 'deploy', 'scheduled'];
const GROUP_TITLE: Readonly<Record<Group, string>> = {
  'pre-commit': "Before each commit (git hooks on the developer's machine)",
  push: 'On every push',
  merge: 'On every pull request, before merge',
  deploy: 'When the code is deployed or released',
  scheduled: 'On a schedule and in repo files',
};
const WARNING_ONLY = 'warning only';
const isScheduled = (n: Pick<Need, 'category'>) => (SCHEDULED_CATEGORIES as ReadonlySet<string>).has(n.category);
const LAYER_WHEN: Readonly<Record<Layer, string>> = {
  'pre-commit': 'before each commit',
  push: 'on every push',
  merge: 'on every pull request',
  deploy: 'at deploy',
};
const NOT_NEEDED: Readonly<Record<Group, string>> = {
  'pre-commit': 'not needed: no checks apply here',
  push: 'not needed: no checks apply here',
  merge: 'not needed: no checks apply here',
  deploy: 'not needed: nothing here runs or deploys',
  scheduled: 'not needed: no checks apply here',
};
const PART_LABEL: Readonly<Record<Part, string>> = {
  pipeline: 'Pipeline', precommit: 'Pre-commit hooks', docker: 'Dockerfile', compose: 'Compose file', tests: 'Starter tests',
  'test-migration': 'Test migration', codeowners: 'Code owners', 'deploy-verify': 'Deploy check', docs: 'Docs',
};
const CAPABILITY_NAMES: readonly [keyof AuditReport['capabilities'], string][] = [
  ['branchProtection', 'merge rules'], ['environments', 'environments'], ['envRequiredReviewers', 'required deploy reviewers'],
  ['attestations', 'artifact attestations'], ['codeScanning', 'code scanning'], ['keylessSigningAllowed', 'keyless signing'],
];
/** The GitHub fact (AuditReport.githubIncomplete.unread) each capability comes from; the rest come from the repo's own facts. */
const CAPABILITY_FACT: Partial<Record<keyof AuditReport['capabilities'], GitHubFact>> = {
  branchProtection: 'branch-protection', environments: 'environments', envRequiredReviewers: 'environments', codeScanning: 'code-scanning',
};
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
  | { kind: 'rows'; rows: Row[] }
  /** One of pipegen's own fixed commands, under the block before it (depth: that item's depth, or -1 under text). */
  | { kind: 'command'; command: string; depth: number };
interface Section { title: string; blocks: Block[] }
interface Doc { title: string; intro: string[]; /** P55: the audited commit line. */ commit: string; verdict: string | null; /** PS37: the scheduled group's own status line (not part of the verdict). */ scheduled?: string; sections: Section[] }

/** How values are cleaned and amounts written for one target. */
interface Ctx {
  target: OutputTarget;
  /** A repo, GitHub or AI string (ruling U10). */
  v(s: string, max?: number): string;
  /** pipegen's own fixed table (the permissions): every step but redact (see safeOutput). */
  own(s: string, max?: number): string;
  usd(n: number): string;
  /** The capabilities, for the merge gate's note on a plan without a merge lock. */
  mergeLock: boolean;
  /** The check's service builds no image (buildsNoImage): signing is named "Release signing" (final review M4). */
  noImage(need: Pick<Need, 'service'>): boolean;
}

function ctxFor(target: OutputTarget, opts: RenderOptions, mergeLock: boolean, services: AuditReport['profile']['services'] = []): Ctx {
  const clean = makeSafeOutput(opts.knownValues, opts.found);
  return {
    target,
    mergeLock,
    noImage: (need) => buildsNoImage(need, { services }),
    v: (s, max = OUTPUT_CAP.name) => clean(s, { target, max }),
    own: (s, max = OUTPUT_CAP.text) => clean(s, { target, max, redact: false }),
    // Markdown: safeMarkdown puts U+200B and a backslash before the $, so GitHub math can't start
    usd: (n) => (target === 'markdown' ? safeMarkdown(money(n)) : money(n)),
  };
}

const text = (t: string): Block => ({ kind: 'text', text: t });
const item = (t: string, depth = 0, warn = false): Block => ({ kind: 'item', text: t, depth, warn });
/** Appends without spreading into a call: `xs` can be as long as the repo makes it. */
function append<T>(out: T[], xs: readonly T[]): void {
  for (const x of xs) out.push(x);
}
/**
 * A command block, or the command cleaned as ordinary text when it isn't exactly one pipegen builds (defence in depth:
 * the model never puts anything else there).
 */
function command(c: Ctx, cmd: string, depth: number): Block {
  return isOwnCommand(cmd) ? { kind: 'command', command: cmd, depth } : (depth < 0 ? text(c.v(cmd, OUTPUT_CAP.text)) : item(c.v(cmd, OUTPUT_CAP.text), depth + 1));
}

// ---------- layers and the verdict (ruling S14) ----------

interface LayerView { layer: Group; rows: Coverage[]; needed: boolean; gaps: boolean; serious: boolean; unknown: boolean; covered: number }

/**
 * A blocking floor need (every coverage row is a floor need) that is missing or partial, and that a tool or the
 * project's own script should cover: pipegen's own checks are gaps pipegen fills, never serious (ruling U16).
 */
const isSerious = (c: Coverage) => c.need.blocking === true && !isBuiltInNeed(c.need) && (c.status === 'missing' || c.status === 'partial');

function layerViews(r: AuditReport): LayerView[] {
  return GROUPS.map((layer) => {
    // a scheduled row (a merge-layer need) is counted in its own group only, so nothing is counted twice
    const rows = r.coverage.filter((c) => (layer === 'scheduled' ? isScheduled(c.need) : c.need.layer === layer && !isScheduled(c.need)));
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

/** A check's plain-English name (needLabel), or its cleaned id when pipegen doesn't know it, with the service. */
const checkLabel = (c: Ctx, need: Pick<Need, 'id' | 'service'>) =>
  `${needLabel(need.id, { noImage: c.noImage(need) }) ?? c.v(need.id)}${need.service === undefined ? '' : ` for ${c.v(need.service)}`}`;
const lowerFirst = (s: string) => (/^[A-Z][a-z]/.test(s) ? `${s[0]?.toLowerCase()}${s.slice(1)}` : s);

function row(c: Ctx, cov: Coverage, services: readonly string[] = []): Row {
  const by = cov.by === undefined ? null : c.v(cov.by, OUTPUT_CAP.path);
  const where = cov.where === undefined ? null : c.v(cov.where, OUTPUT_CAP.path);
  const label = services.length > 1 ? groupLabel(c, cov.need, services) : checkLabel(c, cov.need);
  return {
    serious: isSerious(cov), status: cov.status, check: `${label}${cov.need.blocking ? '' : ` (${WARNING_ONLY})`}`, why: c.v(cov.why, OUTPUT_CAP.text),
    found: by !== null && where !== null ? `${by} in ${where}` : by ?? where,
  };
}

/** "a", "a and b", "a, b and c". */
const andList = (xs: readonly string[]) => (xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1] as string}`);
/** A check's name for several services at once: "Lint for frontend and backend". */
const groupLabel = (c: Ctx, need: Need, services: readonly string[]) =>
  `${needLabel(need.id, { noImage: c.noImage(need) }) ?? c.v(need.id)} for ${andList(services.map((s) => c.v(s)))}`;

/**
 * DoD run (fastapi): per-service rows that say the same thing (the same check, status, why, finding and label) become
 * one row naming every service, at the first one's place, so several services don't read as every row printed twice.
 * `key` is what must match besides the check; a row without a service is never merged. Order is kept.
 */
function groupByService<T extends { need: Need }>(c: Ctx, items: readonly T[], key: (x: T) => string): { first: T; services: string[] }[] {
  const out: { first: T; services: string[] }[] = [];
  const at = new Map<string, { first: T; services: string[] }>();
  for (const x of items) {
    const svc = x.need.service;
    if (svc === undefined) {
      out.push({ first: x, services: [] });
      continue;
    }
    const k = `${x.need.id}\u0000${x.need.layer}\u0000${x.need.blocking ? 1 : 0}\u0000${c.noImage(x.need) ? 1 : 0}\u0000${key(x)}`;
    const g = at.get(k);
    if (g !== undefined) {
      g.services.push(svc);
      continue;
    }
    const fresh = { first: x, services: [svc] };
    at.set(k, fresh);
    out.push(fresh);
  }
  return out;
}

// ---------- sections ----------

/**
 * Hand checks 2026-10-29 (fix 1, ruling P55): what the quick on-disk check looks for and what it doesn't, from the
 * report's own `secretCheck` (pipegen's fixed text). Shown with the findings, and in its own section when there are none.
 */
function secretScopeItems(r: Pick<AuditReport, 'secretCheck'>, c: Ctx, depth: number): Block[] {
  const s = r.secretCheck ?? SECRET_CHECK;
  return [
    item(`This check looks for ${c.own(s.looksFor)}`, depth),
    item(`It doesn't look for ${c.own(s.doesNotLookFor)}`, depth),
    item(c.own(s.fullScans), depth),
  ];
}

/** P55: with nothing found, the check still says what it did and what it didn't (never a block that vanishes and reads as clean). */
function quickSecretSection(r: Pick<AuditReport, 'secretsInTree' | 'secretCheck'>, c: Ctx): Section | null {
  if (r.secretsInTree.length > 0) return null; // the findings and the same lines are in the warnings
  return {
    title: 'Quick secret check (files on disk)',
    blocks: [text('A quick check for a few secret formats, not a secret scan: it found none of the formats it looks for in the files on disk.'), ...secretScopeItems(r, c, 0)],
  };
}

function warningsSection(r: Pick<AuditReport, 'secretsInTree' | 'warnings' | 'secretCheck'>, c: Ctx): Section | null {
  const blocks: Block[] = [];
  if (r.secretsInTree.length > 0) {
    blocks.push(item('Secret-like text in the files on disk now, from a quick check for a few secret formats, not a secret scan (pipegen never shows the values):', 0, true));
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
    append(blocks, secretScopeItems(r, c, 1));
  }
  for (const w of r.warnings) {
    blocks.push(item(c.v(w.text, OUTPUT_CAP.text), 0, true));
    if (w.command !== undefined) blocks.push(command(c, w.command, 0));
  }
  return blocks.length === 0 ? null : { title: '⚠ Warnings', blocks };
}

function planSection(r: AuditReport, c: Ctx): Section {
  const blocks: Block[] = [];
  // the limits first (Review Focus 3: never "make the repo public")
  for (const l of r.limits) blocks.push(item(c.v(l, OUTPUT_CAP.text), 0, true));
  // DoD run 2026-10-29: what GitHub's rate limit kept pipegen from reading is said, never guessed
  const gap = r.githubIncomplete;
  const repoUnread = gap?.unread.includes('repo') === true;
  const unreadNames = CAPABILITY_NAMES.filter(([k]) => {
    const fact = CAPABILITY_FACT[k];
    return repoUnread || (gap !== null && fact !== undefined && gap.unread.includes(fact));
  }).map(([, name]) => name);
  if (r.limits.length === 0) blocks.push(text(unreadNames.length > 0 ? "pipegen couldn't check every limit (GitHub's rate limit)." : 'Nothing here limits the pipeline pipegen would build.'));
  const available = CAPABILITY_NAMES.filter(([k, name]) => r.capabilities[k] === true && !unreadNames.includes(name)).map(([, name]) => name);
  if (!repoUnread) blocks.push(text(`Available here: ${available.length === 0 ? 'none of the GitHub features pipegen uses' : available.join(', ')}.`));
  if (unreadNames.length > 0) blocks.push(text(`Couldn't check (GitHub's rate limit): ${unreadNames.join(', ')}.`));
  const p = r.profile;
  const owner = p.ownerType === 'Organization' ? 'an organisation' : 'a user account';
  const plan = p.plan === 'unknown' ? PLAN_UNKNOWN : c.v(p.plan);
  blocks.push(text(repoUnread
    ? "Repo: pipegen couldn't read whether it is public or private, who owns it, its GitHub plan or its default branch (GitHub's rate limit)."
    : `Repo: ${p.private ? 'private' : 'public'}, owned by ${owner}, GitHub plan: ${plan}.`));
  return { title: 'What your GitHub plan allows', blocks };
}

function layersSection(c: Ctx, views: LayerView[]): Section {
  const blocks: Block[] = [];
  for (const v of views) {
    if (v.layer === 'scheduled' && !v.needed) continue; // a group with no checks is left out, not counted
    blocks.push({ kind: 'sub', title: `${GROUP_TITLE[v.layer]}: ${layerStatus(v)}` });
    if (v.needed) {
      const groups = groupByService(c, v.rows, (cov) => `${cov.status}\u0000${cov.why}\u0000${cov.by ?? ''}\u0000${cov.where ?? ''}`);
      blocks.push({ kind: 'rows', rows: groups.map((g) => row(c, g.first, g.services)) });
    }
  }
  return { title: 'Checks by layer', blocks };
}

/** Services named in the terminal's skipped lines before "and N more" (Markdown and JSON list them all). */
const MAX_SKIPPED_SERVICES_TERMINAL = 10;

/**
 * Plan P Task 9: the checks that don't apply here, each with its why. The terminal groups checks that share a reason on
 * one line; Markdown lists every check (with its services) under its reason, and JSON carries every entry.
 */
function skippedSection(r: Pick<AuditReport, 'skipped'>, c: Ctx): Section | null {
  if (r.skipped.length === 0) return null;
  const blocks: Block[] = [];
  const label = (category: string) => needLabel(category) ?? c.v(category);
  const services = (g: SkippedGroup, all: boolean) => {
    const names = g.services.map((x) => c.v(x));
    const shown = all ? names : names.slice(0, MAX_SKIPPED_SERVICES_TERMINAL);
    const more = names.length - shown.length;
    return names.length === 0 ? '' : ` (for ${shown.join(', ')}${more > 0 ? ` and ${num(more)} more` : ''})`;
  };
  for (const g of r.skipped) {
    const why = c.v(g.why, OUTPUT_CAP.text);
    if (c.target === 'terminal') {
      blocks.push(item(`${g.categories.map(label).join(', ')}${services(g, false)}: ${why}`));
    } else {
      blocks.push(item(why));
      for (const category of g.categories) blocks.push(item(`${label(category)}${services(g, true)}`, 1));
    }
  }
  return { title: "Checks that don't apply here", blocks };
}

const SETTING_LABEL: Readonly<Record<WouldSet['setting'], string>> = {
  'sha-pinning': 'Require actions pinned to a commit', 'dependabot-alerts': 'Dependabot alerts', 'secret-scanning': 'Secret scanning',
};

/** Plan P Task 9: the GitHub settings `finish` would turn on after the setup pull request is merged (ST1-ST3). */
function wouldSetSection(r: Pick<AuditReport, 'wouldSet'>, c: Ctx): Section | null {
  if (r.wouldSet.length === 0) return null;
  const blocks = r.wouldSet.map((w) => item(`${SETTING_LABEL[w.setting] ?? c.v(w.setting)}: ${c.v(w.why, OUTPUT_CAP.text)}`));
  return { title: 'After the setup PR is merged, pipegen would turn on:', blocks };
}

function toolText(c: Ctx, w: WouldAddRow): string {
  const note = c.v(w.note, OUTPUT_CAP.text);
  const t: WouldAddTool = w.tool;
  if (t === null) return note; // the model's note says what happens without a tool
  if ('kind' in t) {
    // the repo's own tool: the version it would run at, then the chooser's reason
    if (t.kind === 'repo-tool') return `${ownToolText(c, t)}${note === '' ? '' : `; ${note}`}`;
    // pipegen's own check, or the service's own script; without a merge lock the gate can't be made required
    const gateNote = t.kind === 'built-in' && w.need.category === 'gate' && !c.mergeLock
      ? ". On this plan GitHub can't make it a required check, so it reports but can't block a merge"
      : '';
    return `${note}${gateNote}`;
  }
  let out = reviewedText(c, t);
  for (const a of w.also) if (a !== null && 'candidate' in a) out += `, plus ${reviewedText(c, a)}`;
  return `${out}, ${note}`;
}

const reviewedText = (c: Ctx, t: ReviewedTool) => `${c.v(t.candidate.name)} ${c.v(t.candidate.version)} (${c.v(t.candidate.repo)})`;
/** "your own `tsc` 7.0.2 (from your lockfile) would run here": a tool name that is plain words goes in backticks, any other value is cleaned plain. */
function ownToolText(c: Ctx, t: RepoToolStep): string {
  const name = c.v(t.tool);
  const plain = name === t.tool && /^[a-z][a-z0-9 -]{0,30}$/.test(name);
  const version = t.version === null ? '' : ` ${c.v(t.version)} ${t.fromRange === true ? '(version from package.json)' : '(from your lockfile)'}`;
  const when = t.version === null ? ', if installed, would run here' : ' would run here';
  return `your own ${plain ? `\`${name}\`` : name}${version}${when}`;
}

function aiBlocks(ai: AuditAi, reviewedUnavailable: boolean, c: Ctx): Block[] {
  const blocks: Block[] = [{ kind: 'sub', title: 'What the AI suggests (--ai)' }];
  if (ai.extraNeeds.length === 0) blocks.push(text('The AI suggests no extra checks.'));
  for (const n of ai.extraNeeds) {
    const when = LAYER_WHEN[n.layer] ?? c.v(n.layer);
    blocks.push(item(`the AI also suggests checking ${lowerFirst(checkLabel(c, n))}, ${when}: ${c.v(n.why, OUTPUT_CAP.text)}`));
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
  if (ai.local === true) {
    return `no cost counted: Ollama runs the model itself, not a paid API (${plural(calls, 'AI call', 'AI calls')}).`;
  }
  if (calls === 0 && !(ai.costUsd > 0)) {
    const cap = typeof ai.capUsd === 'number' && Number.isFinite(ai.capUsd) ? ` The limit you agreed to: ${c.usd(ai.capUsd)}.` : '';
    return `No AI usage was recorded. (A call that ended without reporting its usage, such as a timeout, isn't counted.)${cap}`;
  }
  const cost = ai.costUsd > 0 && ai.costUsd < 0.005 ? `less than ${c.usd(0.01)}` : `about ${c.usd(ai.costUsd)}`;
  const u = ai.usage;
  const cached = u.cacheReadTokens + u.cacheWriteTokens;
  const tokens = `${num(u.inputTokens)} input${cached > 0 ? ` (plus ${num(cached)} cached)` : ''} and ${num(u.outputTokens)} output tokens`;
  // final review M6: the limit the user agreed to on the consent screen (the full setup's cap below is another number)
  const cap = typeof ai.capUsd === 'number' && Number.isFinite(ai.capUsd) ? `; the limit you agreed to: ${c.usd(ai.capUsd)}` : '';
  return `${cost} at list price (${plural(calls, 'AI call', 'AI calls')}; ${tokens})${cap}.`;
}

function addSection(r: AuditReport, c: Ctx): Section {
  const blocks: Block[] = [];
  if (r.wouldAdd.length > 0) {
    if (r.wouldAddNote !== null) blocks.push(item(c.v(r.wouldAddNote, OUTPUT_CAP.text), 0, true)); // P51 (M5)
    blocks.push(text("For each check that isn't covered:"));
    // rows that say the same for several services are one line naming them all (DoD fastapi)
    for (const g of groupByService(c, r.wouldAdd, (w) => `${w.status}\u0000${isScheduled(w.need) ? 1 : 0}\u0000${toolText(c, w)}`)) {
      const w = g.first;
      const label = g.services.length > 1 ? groupLabel(c, w.need, g.services) : checkLabel(c, w.need);
      blocks.push(item(`${label}, ${isScheduled(w.need) ? 'on a schedule' : LAYER_WHEN[w.need.layer]} (now ${w.status}): ${toolText(c, w)}`));
    }
  }
  if (r.testsNote !== null) blocks.push(text(c.v(r.testsNote, OUTPUT_CAP.text)));
  if (r.wouldCreate.length > 0) {
    blocks.push(text('pipegen would also create:'));
    for (const w of r.wouldCreate) blocks.push(item(`${PART_LABEL[w.what] ?? c.v(w.what)}: ${c.v(w.why, OUTPUT_CAP.text)}`));
  }
  if (blocks.length === 0) blocks.push(text('Nothing: every check is already covered.'));
  if (r.ai !== undefined) append(blocks, aiBlocks(r.ai, r.reviewedUnavailable, c));
  return { title: 'What pipegen would add', blocks };
}

function costsSection(r: AuditReport, c: Ctx): Section {
  const e = r.estimates;
  const blocks: Block[] = [];
  blocks.push(item(`Setup: about ${num(e.setupMinutes)} GitHub Actions minutes, with a hard limit of ${num(e.setupMinutesCap)} (the setup stops there).`));
  // a capped activity count (ruling S12) makes the monthly figure a lower bound
  const atLeast = e.basis.some((b) => b.startsWith(ACTIVITY_CAPPED_PREFIX));
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

function bundleSection(r: Pick<AuditReport, 'aiBundle'>, c: Ctx): Section {
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
  blocks.push(text('These are counts only, never file contents. They were made without the secret scan; before anything is sent, '
    + 'a secret scan (betterleaks, or gitleaks as the fallback) checks every file and secret-looking values are hidden, so the '
    + 'real bundle can differ slightly.'));
  return { title: 'What the full setup would send to the AI', blocks };
}

function permissionsSection(r: AuditReport, c: Ctx): Section {
  const blocks = r.permissions.map((p) => item(`${c.own(p.permission, OUTPUT_CAP.name)} — ${c.own(p.why)}`));
  return { title: 'Permissions the full setup needs', blocks: blocks.length === 0 ? [text('None listed.')] : blocks };
}

function notesSection(r: Pick<AuditReport, 'notes'>, c: Ctx): Section | null {
  const notes = dedupe(r.notes.map((n) => c.v(n, OUTPUT_CAP.text)));
  return notes.length === 0 ? null : { title: 'Notes', blocks: notes.map((n) => item(n)) };
}

function nextSection(r: AuditReport, c: Ctx): Section {
  const blocks: Block[] = r.support.reasons.map((x) => item(c.v(x, OUTPUT_CAP.text)));
  blocks.push(text(c.v(r.support.nextStep, OUTPUT_CAP.text)));
  if (r.support.nextCommand !== null && r.support.nextCommand !== undefined) blocks.push(command(c, r.support.nextCommand, -1));
  return { title: 'Next step', blocks };
}

const dedupe = (xs: string[]) => [...new Set(xs)];

/** P55 (hand checks fix 10): the commit the audit read, so two runs (or a hand check) can be compared. */
function commitLine(r: Pick<AuditReport, 'commit'>, c: Ctx): string {
  const k = r.commit;
  if (k === null || k === undefined) return "Audited commit: pipegen couldn't read it from .git (it reads the files on disk as they are now).";
  return `Audited commit: ${c.v(k.short)}${k.branch === null ? ' (detached HEAD, no branch)' : ` on branch ${c.v(k.branch, OUTPUT_CAP.path)}`}.`;
}

function buildDoc(r: AuditReport, c: Ctx): Doc {
  const views = layerViews(r);
  const sched = views.find((v) => v.layer === 'scheduled');
  const intro = ['pipegen changed nothing in the repo or on GitHub.'];
  intro.push(r.ai === undefined ? 'Nothing was sent to an AI.' : 'You ran it with --ai: the AI part below says what the AI step found.');
  const sections = [
    warningsSection(r, c), quickSecretSection(r, c), planSection(r, c), layersSection(c, views), skippedSection(r, c), addSection(r, c), wouldSetSection(r, c),
    costsSection(r, c), bundleSection(r, c), permissionsSection(r, c), notesSection(r, c), { title: "What this audit can't see", blocks: CANT_SEE.map((l) => item(l)) }, nextSection(r, c),
  ].filter((s): s is Section => s !== null);
  return { title: `pipegen audit: ${c.v(`${r.profile.owner}/${r.profile.repo}`, OUTPUT_CAP.path)}`, intro, commit: commitLine(r, c), verdict: verdictOf(views.filter((v) => v.layer !== 'scheduled')),
    ...(sched === undefined || !sched.needed ? {} : { scheduled: `Scheduled and repo-file checks: ${layerStatus(sched)}.` }), sections };
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

function terminalBlocks(blocks: Block[], out: string[]): void {
  for (const b of blocks) {
    if (b.kind === 'text') append(out, wrap(b.text, '  '));
    else if (b.kind === 'item') append(out, wrap(b.text, `${'  '.repeat(b.depth + 1)}${b.warn ? '⚠ ' : '- '}`));
    else if (b.kind === 'sub') {
      out.push('');
      append(out, wrap(b.title, '  '));
    } else if (b.kind === 'command') {
      // U17: on a line of its own, never wrapped (a line over 100 characters is fine), so it pastes as one command
      out.push(`${'  '.repeat(Math.max(b.depth, 0) + 2)}${b.command}`);
    } else {
      for (const r of b.rows) {
        const lead = `    ${r.serious ? '⚠' : ' '} ${r.status.padEnd(STATUS_WIDTH)} `;
        const pad = ' '.repeat(lead.length);
        append(out, wrap(r.check, lead, pad));
        append(out, wrap(r.why, pad));
        if (r.found !== null) append(out, wrap(`Found: ${r.found}`, pad));
      }
    }
  }
}

/** The report for the terminal: plain text, no colours, lines wrapped at 100 characters. */
export function renderTerminal(r: AuditReport, opts: RenderOptions): string {
  return terminalDoc(buildDoc(r, ctxFor('terminal', opts, r.capabilities.branchProtection === true, r.profile.services)));
}

function terminalDoc(doc: Doc): string {
  const lines: string[] = [];
  append(lines, wrap(doc.title, ''));
  append(lines, wrap(doc.commit, ''));
  for (const l of doc.intro) append(lines, wrap(l, ''));
  if (doc.verdict !== null) {
    lines.push('');
    append(lines, wrap(`Verdict: ${doc.verdict}`, ''));
    if (doc.scheduled !== undefined) append(lines, wrap(doc.scheduled, ''));
  }
  for (const s of doc.sections) {
    lines.push('', s.title);
    terminalBlocks(s.blocks, lines);
  }
  return lines.join('\n');
}

// ---------- Markdown ----------

/** A fence longer than any backtick run in `s`, so the content can't close it. */
function fenceFor(s: string): string {
  let longest = 0;
  for (const m of s.matchAll(/`+/g)) longest = Math.max(longest, m[0].length);
  return '`'.repeat(Math.max(3, longest + 1));
}

function markdownBlocks(blocks: Block[], out: string[]): void {
  let last: Block['kind'] | null = null;
  for (const b of blocks) {
    // items run together as one list, and a command stays inside the item above it; anything else is its own paragraph
    const joins = (b.kind === 'item' && (last === 'item' || last === 'command')) || (b.kind === 'command' && last === 'item' && b.depth >= 0);
    if (last !== null && !joins) out.push('');
    if (b.kind === 'text') out.push(b.text);
    else if (b.kind === 'item') out.push(`${'  '.repeat(b.depth)}- ${b.warn ? '⚠ ' : ''}${b.text}`);
    else if (b.kind === 'sub') out.push(`### ${b.title}`);
    else if (b.kind === 'command') {
      // U17: pipegen's own fixed command (isOwnCommand checked when the block was made: constants and pipegen's own
      // version only, no repo data), so it goes unescaped in a fenced block: GitHub shows a copy button and copies it exactly
      const indent = b.depth < 0 ? '' : '  '.repeat(b.depth + 1);
      const fence = fenceFor(b.command);
      out.push(`${indent}${fence}sh`, `${indent}${b.command}`, `${indent}${fence}`);
    } else {
      out.push('| | Status | Check | Why | Found |', '|---|---|---|---|---|');
      for (const r of b.rows) out.push(`| ${r.serious ? '⚠' : ' '} | ${r.status} | ${r.check} | ${r.why} | ${r.found ?? '—'} |`);
    }
    last = b.kind;
  }
}

/** The report as a Markdown file (`--out`): every value through safeMarkdown, every excluded pattern listed. */
export function renderMarkdown(r: AuditReport, opts: RenderOptions): string {
  const doc = buildDoc(r, ctxFor('markdown', opts, r.capabilities.branchProtection === true, r.profile.services));
  const at = (opts.now ?? Date.now)();
  const date = Number.isFinite(at) ? `Audited on ${new Date(at).toISOString().slice(0, 10)}. ` : '';
  const lines = [`# ${doc.title}`, '', doc.commit, '', `${date}${doc.intro.join(' ')}`, '', `**Verdict:** ${doc.verdict ?? ''}`];
  if (doc.scheduled !== undefined) lines.push('', doc.scheduled);
  for (const s of doc.sections) {
    lines.push('', `## ${s.title}`, '');
    markdownBlocks(s.blocks, lines);
  }
  return `${lines.join('\n')}\n`;
}

// ---------- JSON (ruling S13) ----------

/** Keys whose strings are prose (why texts, notes, basis lines): the long cap. */
const PROSE_KEYS: ReadonlySet<string> = new Set(['why', 'note', 'notes', 'basis', 'reasons', 'text', 'limits', 'nextStep', 'testsNote', 'message', 'cantSee', 'looksFor', 'doesNotLookFor', 'fullScans']);
/** Keys that hold one of pipegen's own fixed commands: written as they are when isOwnCommand holds (U17). */
const COMMAND_KEYS: ReadonlySet<string> = new Set(['command', 'nextCommand']);
/** Keys whose strings are paths (or lists of paths): a larger cap than names. */
const PATH_KEYS: ReadonlySet<string> = new Set(['path', 'file', 'where', 'by', 'dockerfile', 'evidence', 'topFolders', 'excludedPatterns', 'terraformDirs', 'repo']);
const capFor = (key: string) => (PROSE_KEYS.has(key) ? OUTPUT_CAP.text : PATH_KEYS.has(key) ? OUTPUT_CAP.path : OUTPUT_CAP.name);

/** A wouldAdd tool as `{ kind, id, name, repo, version }` (only the fields it has). */
function slimTool(t: WouldAddTool): Record<string, string | boolean> | null {
  if (t === null) return null;
  if ('kind' in t) {
    if (t.kind === 'built-in') return { kind: 'built-in' };
    if (t.kind === 'repo-tool') return { kind: 'repo-tool', id: t.needId, name: t.tool, ...(t.version === null ? {} : { version: t.version }), ...(t.fromRange === true ? { fromRange: true } : {}) };
    return { kind: 'project-script', id: t.needId, name: t.script };
  }
  return { kind: 'reviewed', id: t.id, name: t.candidate.name, repo: t.candidate.repo, version: t.candidate.version };
}

type Clean = ReturnType<typeof makeSafeOutput>;

/**
 * Every string (keys too) through the helper; numbers, booleans and null kept; anything else dropped. JSON keeps empty
 * strings (no placeholder). Only the report's own top-level `permissions` table skips redact (pipegen's own wording,
 * "Secrets: read and write"); a `permissions` key anywhere deeper is cleaned like any other.
 */
function deepClean(v: unknown, key: string, depth: number, own: boolean, clean: Clean, ancestors: Set<object>): unknown {
  if (typeof v === 'string') {
    if (COMMAND_KEYS.has(key) && isOwnCommand(v)) return v;
    return clean(v, { target: 'terminal', max: capFor(key), redact: !own, placeholder: false });
  }
  if (typeof v === 'number' || typeof v === 'boolean' || v === null) return v;
  // `ancestors`: only a cycle is dropped; an object shared by two rows (a row's need) is written in both
  if (typeof v !== 'object' || ancestors.has(v)) return null;
  ancestors.add(v);
  try {
    if (Array.isArray(v)) {
      const arr: unknown[] = [];
      for (const x of v) arr.push(deepClean(x, key, depth + 1, own, clean, ancestors));
      return arr;
    }
    // no prototype, so a key cleaned to "__proto__" is a plain key; two keys that clean to the same text both stay
    const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [k, x] of Object.entries(v)) {
      if (x === undefined || typeof x === 'function' || typeof x === 'symbol' || typeof x === 'bigint') continue;
      let name = clean(k, { target: 'terminal' });
      for (let n = 2; Object.hasOwn(out, name); n++) name = `${clean(k, { target: 'terminal' })} (${n})`;
      out[name] = deepClean(x, k, depth + 1, own || (depth === 0 && k === 'permissions'), clean, ancestors);
    }
    return out;
  } finally {
    ancestors.delete(v);
  }
}

/**
 * The report as JSON (`--json`): JSON.stringify(deepClean(r), null, 2), with wouldAdd tools slimmed, plus `cantSee`
 * (CANT_SEE: the limits the human report always shows; final review M7).
 */
export function renderJson(r: AuditReport, opts: RenderOptions): string {
  // DoD run 2026-10-29: facts GitHub's rate limit kept pipegen from reading are null, never the model's placeholders
  const unread = r.githubIncomplete?.unread ?? [];
  const profile = unread.includes('repo') ? { ...r.profile, private: null, ownerType: null, plan: null, defaultBranch: null } : r.profile;
  // P50 (M5): an unread capability is null, never the model's placeholder
  const capabilities: Record<string, boolean | null> = { ...r.capabilities };
  for (const k of Object.keys(capabilities) as (keyof AuditReport['capabilities'])[]) {
    const fact = k === 'deploymentBranchPolicies' ? 'deployment-branch-policies' : CAPABILITY_FACT[k];
    if (unread.includes('repo') || (fact !== undefined && unread.includes(fact))) capabilities[k] = null;
  }
  const slim = { ...r, profile, capabilities, wouldAdd: r.wouldAdd.map((w) => ({ ...w, tool: slimTool(w.tool), also: w.also.map(slimTool) })), cantSee: CANT_SEE };
  return JSON.stringify(deepClean(slim, '', 0, false, makeSafeOutput(opts.knownValues, opts.found), new Set()), null, 2);
}

// ---------- the local-only report (GitHub not read; the `inspect` R10 rule) ----------

/** The one line that says GitHub wasn't read, and what is therefore left out (never guessed). */
export const GITHUB_NOT_READ = 'GitHub: not read (the error is on stderr). Without GitHub, pipegen can\'t tell which checks your workflows run on '
  + 'the right branches, what your GitHub plan allows, or what the full setup would cost, so this report shows only what it found on disk.';

function localDoc(l: LocalAudit, c: Ctx): Doc {
  const p = l.profile;
  const found: Block[] = [];
  found.push(text(p.services.length === 0 ? 'Services: none found.' : `Services (${num(p.services.length)}):`));
  for (const s of p.services) found.push(item(`${c.v(s.name)} (${c.v(s.language)}, in ${c.v(s.path, OUTPUT_CAP.path)})`));
  found.push(text(p.existingWorkflows.length === 0 ? 'Workflows: none found.' : `Workflows (${num(p.existingWorkflows.length)}):`));
  for (const w of p.existingWorkflows) found.push(item(c.v(w.path, OUTPUT_CAP.path)));
  const sections = [
    warningsSection(l, c), quickSecretSection(l, c), { title: 'What pipegen found in the repo', blocks: found }, bundleSection(l, c), notesSection(l, c),
  ].filter((s): s is Section => s !== null);
  return {
    title: `pipegen audit: ${c.v(`${p.owner}/${p.repo}`, OUTPUT_CAP.path)}`,
    commit: commitLine(l, c),
    intro: ['pipegen changed nothing in the repo or on GitHub.', 'Nothing was sent to an AI.', '', GITHUB_NOT_READ],
    verdict: null,
    sections,
  };
}

/** The local-only report for the terminal (GitHub couldn't be read): same cleaning as renderTerminal. */
export function renderLocalTerminal(l: LocalAudit, opts: RenderOptions): string {
  return terminalDoc(localDoc(l, ctxFor('terminal', opts, false)));
}

/** The local-only report as JSON (`--json`): `github: "not read"` and the parts read from disk, every string cleaned. */
export function renderLocalJson(l: LocalAudit, opts: RenderOptions): string {
  const doc = { github: 'not read', profile: l.profile, commit: l.commit ?? null, secretsInTree: l.secretsInTree, secretCheck: l.secretCheck ?? SECRET_CHECK, aiBundle: l.aiBundle, warnings: l.warnings, notes: l.notes };
  return JSON.stringify(deepClean(doc, '', 0, false, makeSafeOutput(opts.knownValues, opts.found), new Set()), null, 2);
}
