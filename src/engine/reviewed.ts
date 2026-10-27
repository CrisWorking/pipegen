// The reviewed tool list (Plan B Task 8): data/reviewed-tools.yml is pipegen's trust root. Only tools on it ever run
// in a user's CI. Each entry is one exact tool, version, pin and step template, reviewed by a human.
// - loadReviewed checks every entry strictly (zod + cross-field rules) and fails closed: a pin that isn't exact, a
//   step that runs anything but the pinned tool, an input the AI could set that is also fixed, a Semgrep rules pack
//   from the registry (p/…, auto) or a checkout that keeps the job's credential in .git/config are all refused.
// - Until the owner reviews an entry it says `reviewedBy: PENDING`. A release build refuses the list while any entry
//   is PENDING (ruling S21): the bundled dist defines process.env.PIPEGEN_RELEASE (tsup `define`), and
//   NODE_ENV=production counts too. Tests and dev runs (src, no define) load PENDING entries so the list can be
//   built and reviewed. The marker rules live in review-marker.ts, shared with pinned-binaries.yml.
// - nearDuplicate is the typosquat check: any reviewed `owner/name` within Levenshtein distance 2 (lowercased, whole
//   name, any owner: ruling S31) that isn't the same repo → the reviewed entry it imitates. Discovery drops it.
// - packageExists asks npm or PyPI whether an exact version exists, with no credential and no redirect (rulings
//   S14, S15; shared http.ts).
// - Project scripts (`npm test`, `npm run lint`) are a built-in step kind, not reviewed entries: no third-party code,
//   so nothing to pin or review.
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { z } from 'zod';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { NEED_CATEGORIES, PROTECTED_PATHS_BASE, type Language, type Need, type ReviewedTool, type Service } from '../types.js';
import {
  advisoryVersion, ASSET_RE, COMMIT_SHA_RE, DIGEST_RE, IMAGE_TAG_RE, isFullSemver, isGitHubRepo, isNpmName, isPypiName, npmEscapedName, parseImageRef, pep503,
  SHA256_RE, SRI_SHA512_RE, TAG_RE,
} from './names.js';
import { NEED_ID_CATEGORY } from './need-ids.js';
import { fetchAllowed, HttpError } from './http.js';
import { COOLDOWN_DAYS } from './pin.js';
import { isReleaseBuild, listPending, PENDING, REVIEWER_RE, reviewMarkerProblems } from './review-marker.js';

/** A built-in step that runs the project's own script. Not a reviewed third-party entry, so it has no pin. */
export interface ProjectScriptStep { kind: 'project-script'; needId: string; service: string; script: 'test' | 'lint'; workingDir?: string }

/** Categories a reviewed entry may carry (ruling S23): every need category, plus three that aren't needs. */
export const TOOL_CATEGORIES = [...NEED_CATEGORIES, 'platform', 'egress', 'workflow-lint'] as const;
const LANGUAGES = ['node', 'python', 'go', 'java', 'dotnet', 'ruby', 'php', 'other', 'any'] as const satisfies readonly (Language | 'any')[];

export { PENDING } from './review-marker.js';

export class ReviewedListError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(safeText(message, 800), options);
    this.name = 'ReviewedListError';
  }
}

export class PackageCheckError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(safeText(message, 400), options);
    this.name = 'PackageCheckError';
  }
}

// ---------- schema ----------

export const ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const INPUT_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;
const ENV_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const FLAG_RE = /^-{1,2}[A-Za-z][A-Za-z0-9-]{0,63}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MS = 86_400_000;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
/** A repo-relative path or glob: no absolute path, no `..`, no backslash. */
const REL_GLOB_RE = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._*/-]{1,200}$/;
/** The Semgrep rules archive (ruling S22): a GitHub archive at a 40-character commit SHA. */
const RULES_URL_RE = /^https:\/\/github\.com\/[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}\/archive\/([0-9a-f]{40})\.tar\.gz$/;
export const RULES_URL_ENV = 'PIPEGEN_RULES_URL';
export const RULES_SHA256_ENV = 'PIPEGEN_RULES_SHA256';
/** The git tree SHA of the rules commit: the v0.2 renderer fetches the commit and checks HEAD^{tree} against it. */
export const RULES_TREE_ENV = 'PIPEGEN_RULES_TREE';
/**
 * Where the renderer puts the verified rules (in the scan container). Semgrep's default config is `auto` (the
 * registry), so every semgrep command must name this directory explicitly, and nothing else, as its config.
 */
export const SEMGREP_RULES_DIR = '/pipegen-rules';

/**
 * A value pipegen writes into a workflow: bounded, never a workflow expression, and printable (one line; only a
 * pinned config file's content may span lines).
 */
const value = (max: number, multiline: boolean) => z.string().max(max).refine(
  (s) => !(multiline ? /[\u0000-\u0008\u000b-\u001f\u007f]/ : /[\u0000-\u001f\u007f]/).test(s) && !s.includes('${{'),
  'control characters, line breaks or ${{ … }} are not allowed',
);
const safeValue = value(512, false);

const pinSchema = z.strictObject({
  sha: z.string().regex(COMMIT_SHA_RE).optional(),
  checksum: z.string().optional(),
  digest: z.string().regex(DIGEST_RE).optional(),
});

const candidateSchema = z.strictObject({
  id: z.string().regex(ID_RE),
  name: z.string().min(1).max(120).pipe(safeValue),
  kind: z.enum(['action', 'cli', 'docker']),
  repo: z.string().refine(isGitHubRepo, 'not a GitHub owner/name'),
  version: z.string().regex(TAG_RE),
  pin: pinSchema,
  source: z.literal('reviewed'),
  reviewed: z.literal(true),
  categories: z.array(z.string()),
});

const installSchema = z.strictObject({
  method: z.enum(['npm', 'pip', 'github-release', 'docker']),
  package: z.string().min(1).max(255),
  version: z.string().regex(TAG_RE),
  checksum: z.string().optional(),
  digest: z.string().optional(),
});

const stepSchema = z.strictObject({
  action: z.strictObject({ uses: z.string().max(300), with: z.record(z.string().regex(INPUT_RE), safeValue) }).optional(),
  cli: z.strictObject({
    install: installSchema,
    command: z.array(z.string().min(1).pipe(safeValue)).max(64),
    env: z.record(z.string().regex(ENV_RE), safeValue).optional(),
  }).optional(),
  output: z.strictObject({ path: z.union([z.literal(''), z.string().regex(REL_GLOB_RE)]), format: z.enum(['sarif', 'junit', 'zap-json', 'none']) }),
});

const fixedSchema = z.strictObject({
  with: z.record(z.string().regex(INPUT_RE), safeValue).optional(),
  args: z.array(z.string().min(1).pipe(safeValue)).max(64).optional(),
  env: z.record(z.string().regex(ENV_RE), safeValue).optional(),
  config: z.strictObject({
    content: value(65_536, true),
    passAs: z.union([z.strictObject({ flag: z.string().regex(FLAG_RE) }), z.strictObject({ input: z.string().regex(INPUT_RE) })]),
  }).optional(),
});

const entrySchema = z.strictObject({
  id: z.string().regex(ID_RE),
  categories: z.array(z.enum(TOOL_CATEGORIES)).min(1),
  languages: z.array(z.enum(LANGUAGES)).min(1),
  /** Server-recorded date of the pinned release (cooldown, ruling S26); file metadata, not returned. */
  releasedAt: z.string().regex(ISO_RE),
  candidate: candidateSchema,
  step: stepSchema,
  fixedInputs: fixedSchema,
  choices: z.record(z.string().regex(INPUT_RE), z.array(z.string().min(1).max(100).pipe(safeValue)).min(1).max(32)),
  configFiles: z.array(z.string().regex(REL_GLOB_RE)).max(32),
  reviewedBy: z.string().max(100).pipe(safeValue).refine((s) => REVIEWER_RE.test(s) && s.trim().length >= 2, 'reviewedBy must be PENDING or a printable name (letters, digits, spaces, . \' -; 2 to 80 characters)'),
  reviewedAt: z.string(),
  proofs: z.number().int().nonnegative(),
}).superRefine((e, ctx) => {
  for (const p of entryProblems(e)) ctx.addIssue({ code: 'custom', path: p.path, message: p.message });
});

const fileSchema = z.strictObject({
  /** When the list was last pinned (an ISO timestamp); every releasedAt must be at least the cooldown before it. */
  pinnedOn: z.string().regex(ISO_RE),
  tools: z.array(entrySchema).min(1).max(500),
}).superRefine((f, ctx) => {
  const pinnedOn = Date.parse(f.pinnedOn);
  const pinnedDay = f.pinnedOn.slice(0, 10);
  f.tools.forEach((t, i) => {
    if (t.reviewedAt !== PENDING && DATE_RE.test(t.reviewedAt) && t.reviewedAt < pinnedDay) {
      ctx.addIssue({ code: 'custom', path: ['tools', i, 'reviewedAt'], message: `reviewedAt is before pinnedOn (${pinnedDay}): the review must cover the pins as they are` });
    }
    if (!(pinnedOn - Date.parse(t.releasedAt) >= COOLDOWN_DAYS * DAY_MS)) {
      ctx.addIssue({ code: 'custom', path: ['tools', i, 'releasedAt'], message: `the release must be at least ${COOLDOWN_DAYS} days older than pinnedOn (cooldown, ruling S26)` });
    }
  });
});

type Entry = z.infer<typeof entrySchema>;

const unique = (xs: readonly string[]) => new Set(xs).size === xs.length;
const lower = (s: string) => s.toLowerCase();

/** Every cross-field rule of one entry (each a message and the path it is about). */
function entryProblems(e: Entry): { message: string; path: (string | number)[] }[] {
  const out: { message: string; path: (string | number)[] }[] = [];
  const bad = (message: string, ...path: (string | number)[]) => out.push({ message, path });
  const c = e.candidate;
  const repo = lower(c.repo);

  if (c.id !== e.id) bad('candidate.id must equal the entry id', 'candidate', 'id');
  if (c.categories.length !== e.categories.length || c.categories.some((x, i) => x !== e.categories[i])) bad('candidate.categories must equal the entry categories', 'candidate', 'categories');
  if (!unique(e.categories)) bad('a category is listed twice', 'categories');
  if (!unique(e.languages)) bad('a language is listed twice', 'languages');

  // reviewedBy and reviewedAt go together: both exactly PENDING, or a name and a real review date (the rule
  // pinned-binaries.yml uses too; the file-level check adds "not before pinnedOn")
  for (const p of reviewMarkerProblems(e.reviewedBy, e.reviewedAt, null)) bad(p.message, p.field);

  // ---- the exact pin, and a step that runs exactly the pinned tool ----
  const { sha, checksum, digest } = c.pin;
  const pinKeys = Object.keys(c.pin);
  const { action, cli } = e.step;
  if (c.kind === 'action') {
    if (sha === undefined || pinKeys.length !== 1) bad('an action is pinned by its 40-character commit SHA only', 'candidate', 'pin');
    if (action === undefined || cli !== undefined) bad('an action entry has a step.action template (and no step.cli)', 'step');
    if (action !== undefined && sha !== undefined) {
      const at = action.uses.lastIndexOf('@');
      const path = lower(action.uses.slice(0, at));
      if (at < 0 || action.uses.slice(at + 1) !== sha || !(path === repo || (path.startsWith(`${repo}/`) && /^[a-z0-9._/-]+$/.test(path.slice(repo.length + 1)) && !path.includes('..')))) {
        bad(`step.action.uses must be ${c.repo}[/path]@<the pinned SHA>`, 'step', 'action', 'uses');
      }
    }
  } else {
    if (cli === undefined || action !== undefined) bad('a cli or docker entry has a step.cli template (and no step.action)', 'step');
    if (cli !== undefined) {
      const inst = cli.install;
      if (inst.version !== c.version) bad('step.cli.install.version must equal candidate.version', 'step', 'cli', 'install', 'version');
      // the candidate pin is the one source of truth (resolvePin refuses an install hash that differs)
      if (inst.checksum !== undefined && inst.checksum !== checksum) bad('step.cli.install.checksum must equal candidate.pin.checksum', 'step', 'cli', 'install', 'checksum');
      if (inst.digest !== undefined && inst.digest !== digest) bad('step.cli.install.digest must equal candidate.pin.digest', 'step', 'cli', 'install', 'digest');
      if (c.kind === 'docker') {
        if (digest === undefined || pinKeys.length !== 1) bad('an image is pinned by its sha256 index digest only', 'candidate', 'pin');
        // the image grammar pinning uses (names.ts parseImageRef): Docker Hub or GHCR, lower case, no tag
        if (inst.method !== 'docker' || parseImageRef(inst.package) === null) bad('an image entry installs with method docker and an image name pipegen can pin (Docker Hub or GHCR, lower case, no tag)', 'step', 'cli', 'install');
        if (!IMAGE_TAG_RE.test(inst.version)) bad('an image entry names an image tag pipegen can look up', 'step', 'cli', 'install', 'version');
      } else {
        if (checksum === undefined || pinKeys.length !== 1) bad('a cli tool is pinned by its checksum only', 'candidate', 'pin');
        if (cli.command.length === 0) bad('a cli entry has a command', 'step', 'cli', 'command');
        const okHash = inst.method === 'npm' ? SRI_SHA512_RE : SHA256_RE;
        if (checksum !== undefined && !okHash.test(checksum)) bad(inst.method === 'npm' ? 'an npm pin is a sha512 integrity' : 'the checksum must be a sha256 (64 hex characters)', 'candidate', 'pin', 'checksum');
        if (inst.method === 'docker') bad('a cli entry is not installed as an image (use kind docker)', 'step', 'cli', 'install', 'method');
        if (inst.method === 'github-release' && !ASSET_RE.test(inst.package)) bad('a release install names its asset', 'step', 'cli', 'install', 'package');
        if (inst.method === 'npm' && (!isNpmName(inst.package) || !isFullSemver(inst.version))) bad('an npm install names a package and an exact version', 'step', 'cli', 'install');
        if (inst.method === 'pip' && (!isPypiName(inst.package) || advisoryVersion(inst.version, 'pep440') !== inst.version)) bad('a pip install names a package and an exact version', 'step', 'cli', 'install');
      }
    }
  }

  // ---- outputs: platform entries scan nothing ----
  const output = e.step.output;
  if ((output.format === 'none') !== (output.path === '')) bad("output.path is '' exactly when output.format is none", 'step', 'output');
  if (e.categories.includes('platform') && output.format !== 'none') bad("a platform entry has output { path: '', format: 'none' }", 'step', 'output');

  // ---- fixed inputs are set by the template; choices never cover them ----
  const fx = e.fixedInputs;
  const stepWith = action?.with ?? {};
  for (const [k, v] of Object.entries(fx.with ?? {})) {
    if (action === undefined) bad('fixedInputs.with is for actions', 'fixedInputs', 'with');
    else if (stepWith[k] !== v) bad(`the fixed input ${k} must be set to the same value in step.action.with`, 'fixedInputs', 'with', k);
  }
  for (const [k, v] of Object.entries(fx.env ?? {})) {
    if (cli?.env?.[k] !== v) bad(`the fixed env ${k} must be set to the same value in step.cli.env`, 'fixedInputs', 'env', k);
  }
  if (fx.args !== undefined) {
    if (cli === undefined) bad('fixedInputs.args is for cli and docker entries', 'fixedInputs', 'args');
    else if (!isSubsequence(fx.args, cli.command)) bad('every fixed arg must appear, in order, in step.cli.command', 'fixedInputs', 'args');
  }
  if (fx.config !== undefined) {
    const viaFlag = 'flag' in fx.config.passAs;
    if (c.kind === 'action' ? viaFlag : !viaFlag) bad('a pinned config is passed to an action as an input, and to a cli as a flag', 'fixedInputs', 'config', 'passAs');
  }
  // fixed keys: inputs and env set by the template, the config input, and every fixed flag (by name, without dashes)
  const flagName = (a: string) => a.replace(/^-+/, '').split('=')[0] as string;
  const fixedKeys = new Set([
    ...Object.keys(stepWith), ...Object.keys(fx.with ?? {}), ...Object.keys(fx.env ?? {}), ...Object.keys(cli?.env ?? {}),
    ...(fx.args ?? []).filter((a) => a.startsWith('-')).map(flagName),
    ...(fx.config === undefined ? [] : ['input' in fx.config.passAs ? fx.config.passAs.input : flagName(fx.config.passAs.flag)]),
  ]);
  for (const [k, vs] of Object.entries(e.choices)) {
    if (fixedKeys.has(k)) bad(`the AI may not choose ${k}: it is a fixed input`, 'choices', k);
    if (!unique(vs)) bad(`the choice ${k} lists a value twice`, 'choices', k);
  }

  // ---- tool-specific rules ----
  if (repo === 'actions/cache' || /^actions\/cache[@/]/i.test(action?.uses ?? '')) bad('pipegen uses no caches: no actions/cache entry (spec §19)', 'candidate', 'repo');
  if (repo === 'actions/checkout' && fx.with?.['persist-credentials'] !== 'false') {
    bad('the checkout entry must fix persist-credentials: "false" (the job credential stays out of .git/config)', 'fixedInputs', 'with');
  }
  // I3: the default git context hands the job's GitHub credential to the Dockerfile as a build secret
  if (repo === 'docker/build-push-action') {
    if (fx.with?.context !== '.') bad('the build-push entry must fix context: "." (the checked-out files, not a git context)', 'fixedInputs', 'with', 'context');
    if (fx.with?.['github-token'] !== '') bad('the build-push entry must fix github-token: "" (the job credential is never a build secret)', 'fixedInputs', 'with', 'github-token');
  }
  // S8: Bullfrog blocks only in block mode, and only while no later step has sudo
  if (repo === 'bullfrogsec/bullfrog') {
    const want: Record<string, string> = { 'egress-policy': 'block', 'dns-policy': 'allowed-domains-only', 'enable-sudo': 'false' };
    for (const [k, v] of Object.entries(want)) if (fx.with?.[k] !== v) bad(`the Bullfrog entry must fix ${k}: "${v}"`, 'fixedInputs', 'with', k);
    // nothing else: an api-token or a control-plane URL would let Bullfrog's control plane override the policy
    const allowed = new Set([...Object.keys(want), 'allowed-domains', 'allowed-ips']);
    for (const k of [...Object.keys(stepWith), ...Object.keys(fx.with ?? {}), ...Object.keys(e.choices)]) {
      if (!allowed.has(k)) bad(`the Bullfrog entry may not set ${k}: only ${[...allowed].join(', ')}`, 'step', 'action', 'with', k);
    }
  }
  // I1: without -silent, zap-baseline.py updates and installs add-ons from the internet at run time
  if (repo === 'zaproxy/zaproxy' || /(^|\/)zap(-[a-z]+)?$/.test(cli?.install.package ?? '')) {
    // zap-baseline.py keeps the LAST -z, so there must be exactly one, and its value must be -silent alone
    const silent = (args: readonly string[]) => {
      const at = args.flatMap((a, i) => (a === '-z' || a.startsWith('-z') ? [i] : []));
      return at.length === 1 && args[at[0] as number] === '-z' && args[(at[0] as number) + 1] === '-silent';
    };
    if (!silent(cli?.command ?? []) || !silent(fx.args ?? [])) bad('the ZAP entry must pass exactly one -z, with the value -silent (in the command and fixedInputs.args): no add-on downloads at run time', 'step', 'cli', 'command');
  }
  if (repo === 'semgrep/semgrep' || /(^|\/)semgrep$/.test(cli?.install.package ?? '')) out.push(...semgrepProblems(e));
  return out;
}

/** Ruling S22: Semgrep rules come from a pinned archive (40-hex commit SHA + sha256), never the registry or auto. */
function semgrepProblems(e: Entry): { message: string; path: (string | number)[] }[] {
  const out: { message: string; path: (string | number)[] }[] = [];
  const env = e.fixedInputs.env ?? {};
  const url = env[RULES_URL_ENV];
  if (url === undefined || !RULES_URL_RE.test(url)) out.push({ message: `semgrep needs fixedInputs.env.${RULES_URL_ENV}: a rules archive at a 40-character commit SHA`, path: ['fixedInputs', 'env'] });
  if (!SHA256_RE.test(env[RULES_SHA256_ENV] ?? '')) out.push({ message: `semgrep needs fixedInputs.env.${RULES_SHA256_ENV}: the archive's sha256`, path: ['fixedInputs', 'env'] });
  if (!COMMIT_SHA_RE.test(env[RULES_TREE_ENV] ?? '')) out.push({ message: `semgrep needs fixedInputs.env.${RULES_TREE_ENV}: the rules commit's tree SHA`, path: ['fixedInputs', 'env'] });
  const values = [
    ...(e.step.cli?.command ?? []), ...(e.fixedInputs.args ?? []), ...Object.values(e.step.cli?.env ?? {}), ...Object.values(env),
    ...Object.values(e.step.action?.with ?? {}), ...Object.values(e.choices).flat(),
  ];
  const registry = (v: string) => {
    const t = v.replace(/^--config=|^-[cf]=?/, '');
    return t === 'auto' || /^(?:p|r|s)\//.test(t) || /semgrep\.dev/i.test(t);
  };
  if (values.some(registry)) out.push({ message: 'semgrep must not use registry rule packs (p/…, r/…), semgrep.dev or --config auto: they change without review', path: ['step', 'cli', 'command'] });
  if ('SEMGREP_RULES' in (e.step.cli?.env ?? {})) out.push({ message: 'semgrep rules come only from the pinned archive (no SEMGREP_RULES)', path: ['step', 'cli', 'env'] });
  // semgrep's default config is auto: the command must name the verified rules dir, and only it (in the fixed args too)
  const command = e.step.cli?.command ?? [];
  const configs = semgrepConfigs(command);
  if (configs.length === 0 || configs.some((c) => c !== SEMGREP_RULES_DIR) || !semgrepConfigs(e.fixedInputs.args ?? []).includes(SEMGREP_RULES_DIR)) {
    out.push({ message: `semgrep must run with --config ${SEMGREP_RULES_DIR} (the verified rules) and no other config, in the command and fixedInputs.args; its default is auto`, path: ['step', 'cli', 'command'] });
  }
  // No --disable-nosem: a nosem comment is a suppression the gate already reports as a finding.
  return out;
}

/** Every config semgrep would load from these args: --config X, -c X, -f X, --config=X, and glued -cX, -fX, -c=X, -f=X. */
function semgrepConfigs(args: readonly string[]): string[] {
  const out: string[] = [];
  args.forEach((a, i) => {
    if (a === '--config' || a === '-c' || a === '-f') out.push(args[i + 1] ?? '');
    else if (a.startsWith('--config=')) out.push(a.slice('--config='.length));
    else if (/^-[cf]./.test(a)) out.push(a.slice(2).replace(/^=/, ''));
  });
  return out;
}

function isSubsequence(needle: readonly string[], hay: readonly string[]): boolean {
  let i = 0;
  for (const h of hay) if (i < needle.length && h === needle[i]) i++;
  return i === needle.length;
}

// ---------- loading ----------

/**
 * Reads and checks the reviewed tool list (default: pipegen's own data/reviewed-tools.yml). Every candidate is
 * exactly pinned and `reviewed: true`; every entry declares configFiles and fixedInputs. Throws ReviewedListError on
 * any problem, and, in a release build, while any entry is still PENDING review.
 */
export function loadReviewed(path: string = packageDataPath('reviewed-tools.yml')): ReviewedTool[] {
  let raw: unknown;
  try {
    raw = parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new ReviewedListError("pipegen's reviewed tool list could not be read.", { cause: e });
  }
  const parsed = fileSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const tools = (raw as { tools?: { id?: unknown }[] } | null)?.tools;
    const index = issue?.path[1];
    const id = issue?.path[0] === 'tools' && typeof index === 'number' && typeof tools?.[index]?.id === 'string' ? ` (entry ${tools[index].id})` : '';
    throw new ReviewedListError(`pipegen's reviewed tool list is invalid${id} at ${issue?.path.join('.') || 'the top'}: ${issue?.message ?? 'invalid'}`);
  }
  const entries = parsed.data.tools;
  const ids = entries.map((t) => t.id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup !== undefined) throw new ReviewedListError(`pipegen's reviewed tool list has the entry ${dup} more than once.`);

  if (isReleaseBuild()) {
    const pending = entries.filter((t) => t.reviewedBy === PENDING).map((t) => t.id);
    if (pending.length > 0) {
      throw new ReviewedListError(`This pipegen release refuses its reviewed tool list: ${pending.length} entries still wait for human review (${listPending(pending)}). Nothing unreviewed may run in your CI.`);
    }
  }
  return entries.map(toReviewedTool);
}

function toReviewedTool(e: Entry): ReviewedTool {
  const { releasedAt: _releasedAt, ...tool } = e;
  return tool as ReviewedTool;
}

// ---------- lookups ----------

/**
 * Reviewed entries for a need: its category (from NEED_ID_CATEGORY, which must agree with need.category, ruling S6)
 * is one of the entry's categories, and the entry is for this language or 'any'. Full runs (v0.2+) only use entries
 * with at least one passed proof; the audit (v0.1) uses human-reviewed, exactly pinned entries with none.
 */
export function reviewedFor(need: Need, language: Language, list: ReviewedTool[], mode: 'audit' | 'full'): ReviewedTool[] {
  const category = (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[need.id];
  if (category === undefined || category !== need.category) return [];
  return list.filter((t) => t.categories.includes(category)
    && (t.languages.includes(language) || t.languages.includes('any'))
    && (mode === 'audit' || t.proofs >= 1));
}

/** PROTECTED_PATHS_BASE, then every configFiles entry of the tools in use, each once, in order. */
export function effectiveProtectedPaths(inUse: ReviewedTool[]): string[] {
  return [...new Set([...PROTECTED_PATHS_BASE, ...inUse.flatMap((t) => t.configFiles)])];
}

/**
 * The typosquat check. Both names lowercased, the FULL `owner/name` compared: a reviewed repo within Levenshtein
 * distance 2 that isn't the same repo → that reviewed entry (any owner, ruling S31). The same repo (any letter
 * case) → null; so is anything further away. A name that isn't a plain ASCII GitHub `owner/name` (a look-alike
 * Unicode letter such as the Kelvin sign, which NFKC folds to K) is always refused: the result is the reviewed
 * entry it is closest to after NFKC folding (null only when the list is empty).
 */
export function nearDuplicate(repo: string, list: ReviewedTool[]): ReviewedTool | null {
  if (!isGitHubRepo(repo)) {
    const folded = lower((typeof repo === 'string' ? repo : '').normalize('NFKC'));
    let best: ReviewedTool | null = null;
    let bestDistance = Number.POSITIVE_INFINITY;
    for (const t of list) {
      const d = levenshtein(folded, lower(t.candidate.repo));
      if (d < bestDistance) [best, bestDistance] = [t, d];
    }
    return best;
  }
  const name = lower(repo);
  if (list.some((t) => lower(t.candidate.repo) === name)) return null;
  return list.find((t) => {
    const other = lower(t.candidate.repo);
    return Math.abs(other.length - name.length) <= 2 && levenshtein(name, other) <= 2;
  }) ?? null;
}

/** Levenshtein distance (inputs cut to 300 characters: a GitHub owner/name is at most 140). */
function levenshtein(x: string, y: string): number {
  const a = x.slice(0, 300);
  const b = y.slice(0, 300);
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min((prev[j - 1] as number) + (a[i - 1] === b[j - 1] ? 0 : 1), (prev[j] as number) + 1, (cur[j - 1] as number) + 1);
    }
    prev = cur;
  }
  return prev[b.length] as number;
}

/** The need ids the project's own scripts cover (by id: type-check and migration-check aren't `test`/`lint`). */
const PROJECT_SCRIPTS: Readonly<Record<string, 'test' | 'lint'>> = { 'unit-tests': 'test', 'full-tests': 'test', lint: 'lint', 'format-lint': 'lint' };

/**
 * The built-in step that runs the project's own `test` or `lint` script for a need, or null when the service has no
 * such script (or the need is for another service). `workingDir` is the raw Service.path (renderers validate it).
 */
export function projectScriptFor(need: Need, s: Service): ProjectScriptStep | null {
  const script = PROJECT_SCRIPTS[need.id];
  if (script === undefined || !s.scripts.includes(script)) return null;
  if (need.service !== undefined && need.service !== s.name) return null;
  const step: ProjectScriptStep = { kind: 'project-script', needId: need.id, service: s.name, script };
  if (s.path !== '' && s.path !== '.') step.workingDir = s.path;
  return step;
}

// ---------- package existence ----------

const PACKAGE_TIMEOUT_MS = 20_000;

/**
 * Whether this exact version of an npm or PyPI package exists (new packages must exist before pipegen adds them,
 * T13). 200 → true, 404 → false. A name or version that isn't valid for the registry → false, with no request.
 * Any other answer, a redirect or a network failure is a PackageCheckError: never a silent yes. No credential is
 * sent (ruling S15).
 */
export async function packageExists(registry: 'npm' | 'pypi', name: string, version: string, f: typeof fetch): Promise<boolean> {
  let url: string;
  if (registry === 'npm') {
    if (!isNpmName(name) || typeof version !== 'string' || !isFullSemver(version)) return false;
    url = `https://registry.npmjs.org/${npmEscapedName(name)}/${encodeURIComponent(version)}`;
  } else if (registry === 'pypi') {
    if (!isPypiName(name) || typeof version !== 'string' || version === '' || advisoryVersion(version, 'pep440') !== version) return false;
    url = `https://pypi.org/pypi/${encodeURIComponent(pep503(name))}/${encodeURIComponent(version)}/json`;
  } else {
    throw new PackageCheckError(`pipegen can't check packages on "${safeText(String(registry), 20)}".`);
  }
  const [where, Where] = registry === 'npm' ? ['the npm registry', 'The npm registry'] : ['PyPI', 'PyPI'];
  let res: Response;
  try {
    // shared http.ts: the registry's own host only, and no redirect at all (a redirect is an error, never a yes)
    res = await fetchAllowed(f, url, { method: 'GET', timeoutMs: PACKAGE_TIMEOUT_MS, hosts: [new URL(url).hostname], maxRedirects: 0, status: 'any' });
  } catch (e) {
    if (e instanceof HttpError && e.kind === 'redirect') {
      throw new PackageCheckError(`${Where} redirected the check of ${name} ${version}; pipegen follows no redirect there, so it couldn't tell whether it exists.`, { cause: e });
    }
    throw new PackageCheckError(`Couldn't reach ${where} to check ${name} ${version}.`, { cause: e });
  }
  await res.body?.cancel().catch(() => {});
  if (res.status === 200) return true;
  if (res.status === 404) return false;
  throw new PackageCheckError(`${Where} answered HTTP ${res.status} for ${name} ${version}; pipegen couldn't tell whether it exists.`);
}
