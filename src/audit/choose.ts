// Choosing what pipegen would add (Plan P Task 8): the catalogue's "choose X when ..." rules (catalogue §2, §3), applied
// to each missing check of the audit. Deterministic: the same repo facts and the same reviewed list always give the
// same pick, and every pick carries a one-line plain-English reason.
//
// What it never does:
// - pick a tool for another language (reviewedFor filters by the need's language);
// - pick a tool on the never-lists (NEVER_REPOS, NEVER_IMAGES: neverListed, neverImage), even if a list contains it;
// - invent an entry: a rule names a reviewed id, and an id the list doesn't have gives tool null (the row says
//   "suggestion only"), never a crash and never a different tool.
// A repo's own tool (its ESLint, its tsc, its Jest...) is a RepoToolStep at the lockfile version (DECISIONS #95); it
// needs no reviewed entry. Whether that tool actually runs in CI is the coverage mapper's call (Task 3, Task 4), not
// this file's: the chooser only says what pipegen would add for a row that is missing or partial.
//
// Also here: `skippedGroups` (the checks that don't apply, one line per reason) and `wouldSetSettings` (the GitHub
// settings `finish` would turn on).
import { codeSecurityAvailable } from '../github/availability.js';
import { needLanguage } from '../engine/discover.js';
import { skippedChecks, type SkippedCheck } from '../engine/needs.js';
import { neverImage, neverListed, nodeTypeChecker, repoToolStep, reviewedFor, type RepoToolStep, type WouldAddTool } from '../engine/reviewed.js';
import { emptyServiceQuality } from '../read/quality.js';
import type { Capabilities, Need, NeedCategory, RepoProfile, ReviewedTool, Service } from '../types.js';
import { PATH_SHOWN_MAX, safeText } from '../util/safe-text.js';
import type { Coverage } from './coverage.js';

export interface Choice {
  tool: WouldAddTool; also: WouldAddTool[]; note: string;
  /** Task 9: the pick is null only because the rule's reviewed entry is not in the list (so an unavailable list is the better reason). */
  unlisted?: true;
}

/** Every reviewed id a rule can name. Rules refer to ids only through this table, so the list can't drift from the rules. */
const T = {
  biome: 'biome', eslint: 'eslint', eslintTs: 'eslint-typescript', oxlintTypeaware: 'oxlint-typeaware', prettier: 'prettier',
  ruff: 'ruff', ruffFormat: 'ruff-format', mypy: 'mypy', vitestCoverage: 'vitest-coverage', c8: 'c8', coveragePy: 'coverage-py',
  knip: 'knip', creosote: 'creosote', vulture: 'vulture', jscpd: 'jscpd', hadolint: 'hadolint', actionlint: 'actionlint', zizmor: 'zizmor',
  poutine: 'poutine', pinact: 'pinact', osvScanner: 'osv-scanner', dependencyReviewAction: 'dependency-review-action', trivyLicence: 'trivy-licence',
  schemathesis: 'schemathesis', trivyConfig: 'trivy-config', kubeLinter: 'kube-linter', betterleaks: 'betterleaks', bullfrog: 'bullfrog',
  scorecardAction: 'scorecard-action',
} as const;
export const CHOOSER_IDS: readonly string[] = Object.freeze(Object.values(T));

const NO_ENTRY = 'it is not on the reviewed list yet, so pipegen would only mention it';

interface Ctx {
  need: Need; s: Service | undefined; p: RepoProfile; caps: Capabilities;
  /** The need's coverage row, when the caller has it (the audit does): a rule may read what the row found (P55). */
  row?: Coverage;
  q: Service['quality']; lang: ReturnType<typeof needLanguage>;
  /** The reviewed entries that cover this need and may be picked: right category and language, never on a never-list. */
  usable: ReviewedTool[];
}

// ---------- building a choice ----------

const none = (note: string): Choice => ({ tool: null, also: [], note });
const builtIn = (note: string): Choice => ({ tool: { kind: 'built-in' }, also: [], note });

/** A reviewed id from the usable entries, or null. */
const entry = (c: Ctx, id: string): ReviewedTool | null => c.usable.find((t) => t.id === id) ?? null;

/** Note text; a function gets the ids of the `also` tools that were actually found, so a note never names one the list lacks. */
type NoteText = string | ((found: ReadonlySet<string>) => string);
const text = (t: NoteText, found: ReadonlySet<string>): string => (typeof t === 'string' ? t : t(found));

/** The reviewed tool `id` with its reason; missing from the list → tool null and a note that says so. `also` ids that are missing are left out, and so are their names in the note (use a NoteText). */
function reviewed(c: Ctx, id: string, reason: NoteText, alsoIds: readonly string[] = [], extra: NoteText = ''): Choice {
  const tool = entry(c, id);
  if (tool === null) return { ...none(`${text(reason, new Set())}; ${NO_ENTRY}`), unlisted: true };
  const also = alsoIds.map((a) => entry(c, a)).filter((t): t is ReviewedTool => t !== null);
  const found = new Set(also.map((t) => t.id));
  return { tool, also, note: `${text(reason, found)}${text(extra, found)}` };
}

/** The repo's own tool at its lockfile version. */
function own(c: Ctx, tool: string, version: string | null, reason: string, pkg?: string): Choice {
  const step: RepoToolStep = { kind: 'repo-tool', needId: c.need.id, service: c.s?.name ?? c.need.service ?? '', tool, version };
  if (version !== null && pkg !== undefined && (c.q.fromRange as readonly string[]).includes(pkg)) step.fromRange = true;
  if (c.s !== undefined && c.s.path !== '' && c.s.path !== '.') step.workingDir = c.s.path;
  // a null version means the tool is configured but pipegen has no version for it: say why, rather than imply it would run.
  // pipegen reads no Python lockfile (uv.lock, poetry.lock) yet, so for Python it says that, not "no installed version was found" (hand checks, P55)
  const noVersion = c.lang === 'python' ? "; pipegen doesn't read Python lockfiles yet, so it can't say which version is installed" : ', but no installed version was found';
  return { tool: step, also: [], note: version === null ? `${reason}${noVersion}` : reason };
}

const major = (v: string | undefined): number | null => {
  const n = Number((v ?? '').split('.')[0]);
  return v !== undefined && Number.isInteger(n) ? n : null;
};

// ---------- node lint and format ----------

type NodeLint = { engine: 'eslint' | 'xo' | 'biome' | 'oxlint'; own: boolean };
/** The repo's own linter if it configured one (ESLint first, then XO, Biome, Oxlint), else the framework rule, else Biome. XO is an ESLint wrapper that lints and checks style, so nothing else is suggested next to it (P55). */
function nodeLint(q: Service['quality']): NodeLint {
  if (q.eslintConfig !== 'none') return { engine: 'eslint', own: true };
  if (q.configs.includes('xo')) return { engine: 'xo', own: true };
  if (q.configs.includes('biome')) return { engine: 'biome', own: true };
  if (q.configs.includes('oxlint')) return { engine: 'oxlint', own: true };
  return q.uiFrameworks.length > 0 ? { engine: 'eslint', own: false } : { engine: 'biome', own: false };
}
const isTypeScript = (q: Service['quality']) => q.tsconfig || q.versions.typescript !== undefined;
const PACKAGE_OF = { eslint: 'eslint', xo: 'xo', biome: '@biomejs/biome', oxlint: 'oxlint' } as const;
const FRAMEWORK_NAMES = { next: 'Next', nuxt: 'Nuxt', vue: 'Vue', svelte: 'Svelte', astro: 'Astro', 'react-native': 'React Native' } as const;

/** Task 9 (DECISIONS #104): ESLint's Vue, Svelte and Astro plugins are not set up by pipegen yet (v0.2), so those files are not linted. */
export const ESLINT_UI_NOTE = "pipegen can't set up ESLint's parsers for .vue, .svelte and .astro files yet (v0.2), so those files would not be linted";
const UI_FILE_FRAMEWORKS: readonly string[] = ['vue', 'nuxt', 'svelte', 'astro'];
const eslintUiNote = (q: Service['quality']): string => (q.uiFrameworks.some((f) => UI_FILE_FRAMEWORKS.includes(f)) ? `; ${ESLINT_UI_NOTE}` : '');

function lintRule(c: Ctx): Choice {
  const { q } = c;
  if (c.lang === 'python') {
    // hand checks (P55): Ruff configured ([tool.ruff], ruff.toml) is the repo's own linter too, and comes first
    if (q.configs.includes('ruff')) return own(c, 'ruff', null, 'Ruff is already configured');
    const configured = q.configs.find((x) => x === 'flake8' || x === 'pylint');
    return configured !== undefined ? own(c, configured, null, `${configured} is already configured`) : reviewed(c, T.ruff, 'Ruff: no Python linter configured');
  }
  if (c.lang !== 'node') return generic(c);
  const l = nodeLint(q);
  if (l.own) {
    const version = q.versions[PACKAGE_OF[l.engine]] ?? null;
    if (l.engine === 'eslint' && (major(version ?? undefined) ?? 0) >= 10 && q.eslintConfig === 'eslintrc') {
      return own(c, 'eslint', version, "the repo's ESLint config: error, ESLint 10 doesn't read .eslintrc; migrate it with ESLint's migration tool (@eslint/migrate-config)", 'eslint');
    }
    const names = { eslint: 'ESLint', xo: 'XO', biome: 'Biome', oxlint: 'Oxlint' } as const;
    return own(c, l.engine, version, `${names[l.engine]} is already configured${l.engine === 'eslint' ? eslintUiNote(q) : ''}`, PACKAGE_OF[l.engine]);
  }
  if (l.engine === 'biome') {
    return reviewed(c, T.biome, `Biome: no linter configured; ${isTypeScript(q) ? 'TypeScript' : 'JavaScript'} repo without a framework plugin`);
  }
  const framework = q.uiFrameworks.map((f) => FRAMEWORK_NAMES[f]).join(' and ');
  const why = `no linter configured; ${framework} needs ESLint plugins${eslintUiNote(q) === '' ? '' : ` (${ESLINT_UI_NOTE})`}`;
  if (!isTypeScript(q)) return reviewed(c, T.eslint, `ESLint: ${why}`);
  if ((major(q.versions.typescript) ?? 0) >= 7) {
    return reviewed(c, T.eslint, `ESLint with Oxlint's type-aware rules: ${why}, and typescript-eslint doesn't support TypeScript 7`, [T.oxlintTypeaware]);
  }
  return reviewed(c, T.eslintTs, `ESLint with typescript-eslint: ${why}`);
}

function formatRule(c: Ctx): Choice {
  const { q } = c;
  if (c.lang === 'python') {
    if (q.configs.includes('black')) return own(c, 'black', null, 'Black is already configured');
    // hand checks (P55): Ruff configured ([tool.ruff], ruff.toml) formats too (`ruff format`), so it is the repo's own formatter
    if (q.configs.includes('ruff')) return own(c, 'ruff format', null, 'Ruff is already configured, and `ruff format` formats with it');
    return reviewed(c, T.ruffFormat, 'Ruff format: no Python formatter configured');
  }
  if (c.lang !== 'node') return generic(c);
  if (q.configs.includes('prettier')) {
    return q.versions.prettier !== undefined ? own(c, 'prettier', q.versions.prettier, 'Prettier is already configured', 'prettier') : reviewed(c, T.prettier, 'Prettier: a Prettier config is already in the repo');
  }
  const l = nodeLint(q);
  if (l.engine === 'xo') return own(c, 'xo', q.versions.xo ?? null, 'XO is already configured, and it checks code style too', 'xo');
  if (l.engine === 'biome') {
    return l.own ? own(c, 'biome', q.versions['@biomejs/biome'] ?? null, 'Biome is already configured', '@biomejs/biome') : reviewed(c, T.biome, 'Biome: it lints here, so it formats too');
  }
  return reviewed(c, T.prettier, 'Prettier: ESLint lints here, and it does not format');
}

// ---------- type-check and coverage ----------

function typeCheckRule(c: Ctx): Choice {
  const { q } = c;
  if (c.lang === 'python') {
    const checker = q.configs.find((x) => x === 'mypy' || x === 'pyright' || x === 'basedpyright');
    return checker !== undefined ? own(c, checker, null, `${checker} is already configured`) : reviewed(c, T.mypy, 'mypy: no Python type checker configured');
  }
  if (c.lang !== 'node') return generic(c);
  // G4b: the pick is the pipeline's too (reviewed.ts nodeTypeChecker, repoToolStep), so the audit and the pipeline never name different tools
  const pick = nodeTypeChecker(q);
  const version = q.versions[pick.pkg];
  if (version === undefined) {
    return none(`${pick.tool}: ${pick.pkg} is not in the lockfile, so pipegen can only suggest it (add ${pick.pkg} as a dev dependency)`);
  }
  const reason = `${pick.tool} is in the ${q.fromRange.includes(pick.pkg) ? 'package.json' : 'lockfile'}`;
  const step = c.s === undefined ? null : repoToolStep(c.need, c.s);
  return step === null ? own(c, pick.tool, version, reason, pick.pkg) : { tool: step, also: [], note: reason };
}

const COVERAGE_NOTE = '`floor(current) - 1`; 60% of lines for repos with few tests; an existing minimum is kept';

function coverageRule(c: Ctx): Choice {
  const { q, s } = c;
  const withNote = (ch: Choice): Choice => ({ ...ch, note: `${ch.note}; minimum: ${COVERAGE_NOTE}` });
  if (c.lang === 'python') return withNote(reviewed(c, T.coveragePy, 'coverage.py: pytest and unittest both run under it'));
  if (c.lang !== 'node') return generic(c);
  const runner = q.versions.vitest !== undefined || s?.testFramework === 'vitest' ? 'vitest'
    : q.versions.jest !== undefined || s?.testFramework === 'jest' ? 'jest' : 'other';
  if (runner === 'vitest') return withNote(reviewed(c, T.vitestCoverage, 'Vitest coverage: Vitest is the test runner'));
  if (runner === 'jest') return withNote(own(c, 'jest', q.versions.jest ?? null, "Jest's own coverage (coverageThreshold): Jest is the test runner", 'jest'));
  return withNote(reviewed(c, T.c8, `c8: ${s?.testFramework === 'node:test' ? 'node:test' : 'the test runner'} has no coverage of its own`));
}

// ---------- the rest ----------

function deadCodeRule(c: Ctx): Choice {
  if (c.lang === 'node') {
    return reviewed(c, T.knip, 'Knip: finds unused files, exports and dependencies', [], c.q.configs.includes('knip') ? '; blocking because `knip.json` exists' : '; report-only on the first run');
  }
  if (c.lang === 'python') return reviewed(c, T.creosote, 'Creosote: finds unused dependencies', [T.vulture]);
  if (c.lang === 'go') return none('`go mod tidy -diff`, report only');
  return generic(c);
}

const RISKY_TRIGGERS: readonly string[] = ['pull_request_target', 'workflow_run', 'issue_comment'];

function dependencyReviewRule(c: Ctx): Choice {
  const available = codeSecurityAvailable(c.p, c.caps);
  return reviewed(c, T.osvScanner, `OSV-Scanner: checks new dependencies against known vulnerabilities${available ? ', plus GitHub dependency review' : ''}`, available ? [T.dependencyReviewAction] : []);
}

function licencesRule(c: Ctx): Choice {
  const config = c.p.repoFiles.licenceConfig;
  if (config === 'deny.toml') return none('cargo-deny: a deny.toml is already in the repo (suggestion only)');
  if (config === '.grant.yaml') return none('grant: a .grant.yaml is already in the repo (suggestion only)');
  if (config === '.fossa.yml') return none('keep FOSSA: a .fossa.yml is already in the repo, so pipegen adds no licence check');
  return reviewed(c, T.trivyLicence, 'Trivy licence scan: no licence tool configured');
}

function apiDastRule(c: Ctx): Choice {
  const spec = c.q.apiSpec;
  const where = spec === null ? 'the API spec' : spec.kind === 'file' ? safeText(spec.path, PATH_SHOWN_MAX) : `served by ${spec.by === 'fastapi' ? 'FastAPI' : 'NestJS'}`;
  return reviewed(c, T.schemathesis, `Schemathesis: tests the API from its spec (${where})`);
}

function updateConfigRule(c: Ctx): Choice {
  // hand checks (P55): the row says which tool it read and whether its wait is already long enough; never ask for a set wait
  const set = c.row?.cooldown === 'set';
  const tool = c.row?.by === 'dependabot' || c.row?.by === 'renovate' ? c.row.by : c.p.repoFiles.renovate !== null ? 'renovate' : c.p.repoFiles.dependabot !== null ? 'dependabot' : null;
  if (tool === 'renovate') return builtIn(set ? 'keep Renovate; its minimumReleaseAge already waits at least 7 days' : 'keep Renovate; set `minimumReleaseAge: "7 days"`');
  if (tool === 'dependabot') return builtIn(set ? 'keep your Dependabot config; its cooldown already waits at least 7 days' : 'keep your Dependabot config; set `cooldown.default-days: 7`');
  return builtIn('pipegen would write `.github/dependabot.yml`: weekly, grouped, `cooldown.default-days: 7`');
}

/** Categories without a choose rule keep the first reviewed entry for the need (PS35). */
function generic(c: Ctx): Choice {
  const first = c.usable[0];
  return first === undefined ? none('') : { tool: first, also: [], note: 'reviewed tool' };
}

type Rule = (c: Ctx) => Choice;
const RULES: Readonly<Record<string, Rule>> = {
  lint: lintRule, format: formatRule,
  // P55 (batch B): the pre-commit hook runs the repo's own XO (a repo with XO never gets Biome suggested next to it); other repos keep the first reviewed entry
  'format-lint': (c) => (c.lang === 'node' && c.q.eslintConfig === 'none' && c.q.configs.includes('xo') ? lintRule(c) : generic(c)), 'type-check': typeCheckRule, coverage: coverageRule, 'dead-code': deadCodeRule,
  duplication: (c) => reviewed(c, T.jscpd, 'jscpd: finds copy-pasted code', [], '; warning only; new copy-paste in the pull request only'),
  'dockerfile-lint': (c) => reviewed(c, T.hadolint, 'Hadolint: lints the Dockerfile', [], "; Trivy config's Dockerfile checks stay on"),
  'workflow-lint': (c) => {
    const risky = c.p.existingWorkflows.some((w) => w.triggers.some((t) => RISKY_TRIGGERS.includes(t)));
    return reviewed(
      c, T.actionlint,
      (found) => (found.has(T.zizmor) ? 'actionlint and zizmor: check the workflows for mistakes and risky patterns' : 'actionlint: checks the workflows for mistakes'),
      risky ? [T.zizmor, T.poutine] : [T.zizmor],
      (found) => (risky && found.has(T.poutine) ? '; poutine too, because a workflow runs on untrusted pull request input' : ''),
    );
  },
  'workflow-pin-check': (c) => reviewed(c, T.pinact, 'pinact: checks that every action is pinned to a commit', [], c.p.repoFiles.actionsLock ? "; an actions.lock exists, so pinact won't rewrite its pins" : ''),
  'dependency-review': dependencyReviewRule,
  licences: licencesRule,
  'api-dast': apiDastRule,
  iac: (c) => reviewed(
    c, T.trivyConfig,
    (found) => (c.p.repoFiles.kubernetes ? `Trivy config: scans Terraform and Kubernetes files${found.has(T.kubeLinter) ? ', plus kube-linter' : ''}` : 'Trivy config: scans Terraform files'),
    c.p.repoFiles.kubernetes ? [T.kubeLinter] : [],
  ),
  secrets: (c) => reviewed(c, T.betterleaks, 'Betterleaks: scans for committed secrets', [], c.p.repoFiles.secretsBaseline ? '; a .secrets.baseline exists, so detect-secrets also runs' : ''),
  'update-config': updateConfigRule,
  publishing: () => builtIn('trusted publishing (OIDC); no long-lived token'),
  egress: (c) => reviewed(c, T.bullfrog, 'Bullfrog: blocks unexpected network traffic in release jobs'),
  scorecard: (c) => reviewed(c, T.scorecardAction, 'OpenSSF Scorecard: scores the repo weekly'),
  fuzzing: () => none('pipegen builds fuzzing in v0.3'),
};

/**
 * What pipegen would add for `need`: the rule for its category, else the first reviewed entry that covers it.
 * Pure and deterministic. `s` is the need's service (absent for repo-wide needs); `row`, its coverage row when known.
 */
export function chooseTools(need: Need, s: Service | undefined, p: RepoProfile, caps: Capabilities, reviewedList: ReviewedTool[], row?: Coverage): Choice {
  const usable = reviewedFor(need, needLanguage(need, p), reviewedList, 'audit')
    .filter((t) => neverListed(t.candidate.repo) === null && (t.candidate.kind !== 'docker' || neverImage(t.candidate.repo) === null));
  const c: Ctx = { need, s, p, caps, q: s?.quality ?? emptyServiceQuality(), lang: needLanguage(need, p), usable, ...(row === undefined ? {} : { row }) };
  const rule = Object.hasOwn(RULES, need.category) ? (RULES[need.category] as Rule) : generic;
  return rule(c);
}

// ---------- skipped checks, one line per reason ----------

/** Checks left out for the same reason, on one line. */
export interface SkippedGroup { why: string; categories: NeedCategory[]; services: string[] }

/** The checks that don't apply to this repo, grouped by reason in first-seen order ("no services found" once, not 20 times). */
export function skippedGroups(p: RepoProfile, caps: Capabilities): SkippedGroup[] {
  const groups = new Map<string, SkippedGroup>();
  for (const k of skippedChecks(p, caps) as SkippedCheck[]) {
    const g = groups.get(k.why) ?? { why: k.why, categories: [], services: [] };
    groups.set(k.why, g);
    if (!g.categories.includes(k.category)) g.categories.push(k.category);
    if (k.service !== undefined && !g.services.includes(k.service)) g.services.push(k.service);
  }
  return [...groups.values()];
}

// ---------- the settings `finish` would turn on ----------

export interface WouldSet { setting: 'sha-pinning' | 'dependabot-alerts' | 'secret-scanning'; why: string }

const CANT_SEE = "pipegen can't see this setting with read access, so it can't say whether it is already on";

/** ST1-ST3 (DEC #27, #14). Set by `finish` after the merge. Private repos never get public wording. */
export function wouldSetSettings(p: RepoProfile, coverage: readonly Coverage[], skippedWorkflows = 0): WouldSet[] {
  const pin = coverage.find((c) => c.need.category === 'workflow-pin-check');
  const pinned = pin !== undefined && pin.status === 'covered';
  // PS36: the setting breaks every workflow whose actions are pinned by tag, so the why names that precondition and counts them
  const tagged = p.existingWorkflows.filter((w) => (w.tagPinned ?? 0) > 0).length;
  const total = p.existingWorkflows.length;
  // review I2: "none" only when every workflow was read and every uses: line was checked
  const complete = skippedWorkflows === 0 && !p.existingWorkflows.some((w) => w.usesUnchecked === true);
  const unread = 'pipegen could not read all your workflows, so it can\'t count them all';
  const today = tagged > 0
    ? `Today ${complete ? '' : 'at least '}${tagged} of your ${total} ${total === 1 ? 'workflow uses' : 'workflows use'} actions pinned by tag or branch, and ${tagged === 1 && total === 1 ? 'it would' : 'they would'} stop running${complete ? '' : ` (${unread})`}`
    : !complete ? `Today ${unread}`
      : total === 0 ? 'Today no workflow uses tag pins'
        : `Today none of your ${total} ${total === 1 ? 'workflow uses' : 'workflows use'} tag pins${pinned ? ' (the action pin check passes today)' : ''}`;
  const out: WouldSet[] = [
    {
      setting: 'sha-pinning',
      why: `Makes GitHub refuse any action that is not pinned to a commit. pipegen turns it on only after your other workflows pin their actions to a commit. ${today}; ${CANT_SEE}.`,
    },
    { setting: 'dependabot-alerts', why: `Tells you when a dependency has a known vulnerability; free on every repo. ${CANT_SEE}.` },
  ];
  out.push(p.private
    ? { setting: 'secret-scanning', why: `Needs GitHub Secret Protection (a paid add-on); pipegen can't turn it on without it.` }
    : { setting: 'secret-scanning', why: `Blocks pushes that contain a known secret format (push protection). ${CANT_SEE}.` });
  return out;
}
