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
// - Plan P Task 5: NEVER_REPOS (catalogue §4's never-list) is refused anywhere in an entry, in any letter case, under a
//   known old name, by sub-path, as an image on any registry and as a look-alike (neverListed); discovery drops it too.
//   MUST_VERIFY repos record the signature check made when pinning (verifiedWith). The catalogue's tool locks: Trivy's
//   three hardening flags, no jscpd --semantic, betterleaks with the pinned --config only, Nuclei with -duc and the
//   pinned templates only, Scorecard without publish_results, dependency-review without PR comments, and no
//   eslint-config-prettier / eslint-plugin-prettier. Plugins (npm or pip, exact and hashed, at most 4).
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
import { isRealDate, isReleaseBuild, listPending, PENDING, REVIEWER_RE, reviewMarkerProblems } from './review-marker.js';
import { BETTERLEAKS_FORBIDDEN_FLAGS } from './tool-flags.js';

/** A built-in step that runs the project's own script. Not a reviewed third-party entry, so it has no pin. */
export interface ProjectScriptStep { kind: 'project-script'; needId: string; service: string; script: 'test' | 'lint'; workingDir?: string }

/** Categories a reviewed entry may carry (ruling S23): every need category, plus `platform`, which isn't a need (egress and workflow-lint became needs in Plan P Task 2). */
export const TOOL_CATEGORIES = [...NEED_CATEGORIES, 'platform'] as const;
const LANGUAGES = ['node', 'python', 'go', 'java', 'dotnet', 'ruby', 'php', 'other', 'any'] as const satisfies readonly (Language | 'any')[];

export { PENDING } from './review-marker.js';

export class ReviewedListError extends Error {
  /** Why, in a few words, without the "reviewed tool list" subject (for the audit's top warning, review M7); absent when the thrower gave none. */
  readonly reason?: string;
  constructor(message: string, options?: { cause?: unknown; reason?: string }) {
    super(safeText(message, 800), options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'ReviewedListError';
    if (options?.reason !== undefined) this.reason = safeText(options.reason, 600);
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

/** The Nuclei templates archive (catalogue §3 MG5, ruling PS30): an official nuclei-templates release tarball and its sha256. */
export const NUCLEI_TEMPLATES_URL_ENV = 'PIPEGEN_NUCLEI_TEMPLATES_URL';
export const NUCLEI_TEMPLATES_SHA256_ENV = 'PIPEGEN_NUCLEI_TEMPLATES_SHA256';
/** Where the renderer puts the verified templates; `-t` must name this directory, and nothing else (like Semgrep's rules, S22). */
export const NUCLEI_TEMPLATES_DIR = '/pipegen-nuclei-templates';
const NUCLEI_TEMPLATES_URL_RE = /^https:\/\/github\.com\/projectdiscovery\/nuclei-templates\/(?:archive\/refs\/tags\/v\d{1,4}\.\d{1,4}\.\d{1,4}\.tar\.gz|releases\/download\/v\d{1,4}\.\d{1,4}\.\d{1,4}\/[A-Za-z0-9._-]{1,100}\.tar\.gz)$/;

/** Trivy's hardening flags (catalogue §4, D10): no telemetry, no version-check call, and the checks in the verified binary only. */
export const TRIVY_REQUIRED_FLAGS = ['--disable-telemetry', '--skip-version-check', '--skip-check-update'] as const;
/** The most plugins one entry may install next to its tool. */
export const MAX_PLUGINS = 4;
/** The only OIDC issuer a recorded keyless signature may have: GitHub Actions. */
export const OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
/**
 * The exact certificate identity of a keyless signature (ruling PS24): a GitHub workflow URL at a tag, a branch or a
 * commit. Never a regex: none of `^ $ * ( ) [ ] | \ ? +` outside the ref, and no `..`.
 */
const IDENTITY_RE = /^https:\/\/github\.com\/[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}\/\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml@(?:refs\/(?:tags|heads)\/[A-Za-z0-9._/-]{1,128}|[0-9a-f]{40})$/;

/**
 * Catalogue §4's never-list ("Remove / never add"), lowercased `owner/name` (or `owner/*` for every repo of an owner)
 * → why. It also holds the old names GitHub still redirects to these repos (checked with the GitHub API on
 * 2026-10-27) and the same projects' own action repos. neverListed matches it.
 */
export const NEVER_REPOS: Readonly<Record<string, string>> = Object.freeze({
  'checkmarx/kics-github-action': 'KICS: its action tags were hijacked in 2026 (catalogue §4, §5)',
  'checkmarx/kics-action': 'KICS: the old name of checkmarx/kics-github-action, whose tags were hijacked in 2026 (catalogue §4, §5)',
  'checkmarx/kics': 'KICS: its Docker Hub tags were overwritten with a data-stealing binary in 2026 (catalogue §4, §5)',
  'aquasecurity/trivy-action': '76 of its 77 tags were force-pushed to malicious code in March 2026; Trivy runs only as the verified binary (catalogue §4, §5)',
  'aquasecurity/setup-trivy': 'all its tags were replaced with malicious code in March 2026; Trivy runs only as the verified binary (catalogue §4, §5)',
  'gitleaks/gitleaks-action': 'proprietary licence, needs a licence key and phones home (catalogue §4)',
  'zricethezav/gitleaks-action': 'the old name of gitleaks/gitleaks-action: proprietary licence, licence key, phones home (catalogue §4)',
  'reviewdog/*': 'reviewdog actions: reviewdog/action-setup was hijacked (CVE-2025-30154); pipegen uses plain run steps (catalogue §4, §5)',
  'slsa-framework/slsa-github-generator': 'not actively maintained; pipegen uses actions/attest (catalogue §4)',
  'tenable/terrascan': 'archived (catalogue §4)',
  'accurics/terrascan': 'the old name of tenable/terrascan, which is archived (catalogue §4)',
  'tenable/terrascan-action': 'Terrascan is archived (catalogue §4)',
  'accurics/terrascan-action': 'the old name of tenable/terrascan-action; Terrascan is archived (catalogue §4)',
  'aquasecurity/tfsec': 'superseded by Trivy (catalogue §4)',
  'tfsec/tfsec': 'the old name of aquasecurity/tfsec, which Trivy superseded (catalogue §4)',
  'liamg/tfsec': 'the old name of aquasecurity/tfsec, which Trivy superseded (catalogue §4)',
  'aquasecurity/tfsec-action': 'tfsec is superseded by Trivy (catalogue §4)',
  'aquasecurity/tfsec-sarif-action': 'tfsec is superseded by Trivy (catalogue §4)',
  'aquasecurity/tfsec-pr-commenter-action': 'tfsec is superseded by Trivy (catalogue §4)',
  'tfsec/tfsec-sarif-action': 'the old name of aquasecurity/tfsec-sarif-action; tfsec is superseded by Trivy (catalogue §4)',
  'tfsec/tfsec-pr-commenter-action': 'the old name of aquasecurity/tfsec-pr-commenter-action; tfsec is superseded by Trivy (catalogue §4)',
  'zizmorcore/zizmor-action': 'beta (the no-beta rule, DECISIONS #92); pipegen runs the pinned zizmor binary (catalogue §4)',
  'portswigger/dastardly-github-action': 'Dastardly: unmaintained action with a mutable :latest image (catalogue §4, ruling PS21)',
  'portswigger/dastardly': 'Dastardly: a mutable :latest image from an unmaintained product (catalogue §4, ruling PS21)',
});

/**
 * Repos whose releases pipegen pins only with a recorded signature or attestation check (verifiedWith): catalogue §4
 * ("+ cosign", "+ GitHub attestation", "+ sigstore") and DECISIONS #95 (jscpd as a signed binary, ruling PS27).
 */
export const MUST_VERIFY: ReadonlySet<string> = new Set([
  'betterleaks/betterleaks', 'aquasecurity/trivy', 'hadolint/hadolint', 'stackrox/kube-linter', 'securego/gosec', 'kucherenko/jscpd',
]);

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
    plugins: z.array(installSchema).max(16).optional(),
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

const verifiedWithSchema = z.strictObject({
  method: z.enum(['cosign-bundle', 'cosign-signature', 'github-attestation']),
  asset: z.string().regex(ASSET_RE),
  identity: z.string().max(400).regex(IDENTITY_RE, 'identity must be the exact certificate identity, https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref> (never a regex)')
    .refine((s) => !s.includes('..'), 'identity must not contain ..'),
  issuer: z.literal(OIDC_ISSUER),
  verifiedOn: z.string().refine(isRealDate, 'verifiedOn must be a real date (YYYY-MM-DD)'),
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
  /** The signature or attestation check made when pinning (Plan P Task 5); required for MUST_VERIFY repos. */
  verifiedWith: verifiedWithSchema.optional(),
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
    // PS24: the signature check must cover the pins as they are
    if (t.verifiedWith !== undefined && t.verifiedWith.verifiedOn < pinnedDay) {
      ctx.addIssue({ code: 'custom', path: ['tools', i, 'verifiedWith', 'verifiedOn'], message: `verifiedOn is before pinnedOn (${pinnedDay}): the signature check must cover the pins as they are` });
    }
  });
});

type Entry = z.infer<typeof entrySchema>;
type Install = z.infer<typeof installSchema>;

const unique = (xs: readonly string[]) => new Set(xs).size === xs.length;
const lower = (s: string) => s.toLowerCase();

/** Every cross-field rule of one entry (each a message and the path it is about). */
function entryProblems(e: Entry): { message: string; path: (string | number)[] }[] {
  const out: { message: string; path: (string | number)[] }[] = [];
  const bad = (message: string, ...path: (string | number)[]) => out.push({ message, path });
  const c = e.candidate;
  const repo = lower(c.repo);
  const { action, cli } = e.step;
  const fx = e.fixedInputs;

  // ---- Plan P Task 5: never-listed tools, anywhere in the entry (first, so the refusal names the reason) ----
  const refs: [string, (string | number)[]][] = [[c.repo, ['candidate', 'repo']], [c.name, ['candidate', 'name']]];
  if (action !== undefined) refs.push([action.uses, ['step', 'action', 'uses']]);
  if (cli !== undefined) refs.push([cli.install.package, ['step', 'cli', 'install', 'package']]);
  // download URLs, images and repo names in any value of the step, the fixed inputs or the choices
  for (const text of [...leaves(e.step), ...leaves(fx), ...leaves(e.choices)]) {
    for (const token of text.split(/[\s=,;"'`()[\]{}<>|]+/)) if (token.includes('/')) refs.push([token, ['step']]);
  }
  for (const [ref, path] of refs) {
    const hit = neverListed(ref);
    if (hit !== null) {
      bad(`pipegen never adds ${hit.key === hit.ref ? hit.key : `${hit.ref} (${hit.key})`}: ${hit.reason}`, ...path);
      break;
    }
  }
  // PS25 (catalogue §5, CVE-2025-54313): never eslint-config-prettier or eslint-plugin-prettier, as the tool, a plugin or in any value
  for (const text of [...leaves(e.step), ...leaves(fx), ...leaves(e.choices)]) {
    const m = BANNED_PACKAGE_RE.exec(text);
    if (m !== null) {
      bad(`pipegen never adds ${lower(m[0])}: its maintainer was phished and malicious versions were published (CVE-2025-54313, catalogue §5)`, 'step', 'cli');
      break;
    }
  }
  // MUST_VERIFY repos are pinned only with a recorded signature or attestation check
  if (MUST_VERIFY.has(repo) && e.verifiedWith === undefined) bad(`${c.repo} is pinned only with a signature or attestation check: verifiedWith is required (MUST_VERIFY)`, 'verifiedWith');
  if (e.verifiedWith !== undefined) {
    const tag = /@refs\/tags\/(.+)$/.exec(e.verifiedWith.identity)?.[1];
    if (tag !== undefined && tag.replace(/^v/, '') !== c.version.replace(/^v/, '')) {
      bad(`verifiedWith.identity is the signature of tag ${tag}, not of this entry's version ${c.version}`, 'verifiedWith', 'identity');
    }
  }

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
      if (cli.plugins !== undefined) out.push(...pluginProblems(c.kind, inst, cli.plugins));
    }
  }

  // ---- outputs: platform entries scan nothing ----
  const output = e.step.output;
  if ((output.format === 'none') !== (output.path === '')) bad("output.path is '' exactly when output.format is none", 'step', 'output');
  if (e.categories.includes('platform') && output.format !== 'none') bad("a platform entry has output { path: '', format: 'none' }", 'step', 'output');

  // ---- fixed inputs are set by the template; choices never cover them ----
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
  const fixedName = (a: string) => a.replace(/^-+/, '').split('=')[0] as string;
  const fixedKeys = new Set([
    ...Object.keys(stepWith), ...Object.keys(fx.with ?? {}), ...Object.keys(fx.env ?? {}), ...Object.keys(cli?.env ?? {}),
    ...(fx.args ?? []).filter((a) => a.startsWith('-')).map(fixedName),
    ...(fx.config === undefined ? [] : ['input' in fx.config.passAs ? fx.config.passAs.input : fixedName(fx.config.passAs.flag)]),
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

  // ---- Plan P Task 5: the catalogue's tool locks ----
  const command = cli?.command ?? [];
  const args = fx.args ?? [];
  // Trivy (catalogue §4, D10): no telemetry, no version-check call, checks from the verified binary only; trivy keeps
  // the last value of a flag, so `--flag=false` later in the command is refused too
  if (runsTool(e, 'aquasecurity/trivy', 'trivy')) {
    for (const flag of TRIVY_REQUIRED_FLAGS) {
      if (!command.includes(flag) || !args.includes(flag) || [...command, ...args].some((a) => lower(a).startsWith(`${flag}=`))) {
        bad(`trivy must run with ${flag} in the command and fixedInputs.args, and never ${flag}=… (catalogue §4: no telemetry or update calls)`, 'step', 'cli', 'command');
      }
    }
  }
  // jscpd (catalogue D6): --semantic can call any OpenAI-compatible API, so not anywhere in its step
  if (runsTool(e, 'kucherenko/jscpd', 'jscpd') && [...leaves(e.step), ...leaves(fx), ...leaves(e.choices)].some((t) => /semantic/i.test(t))) {
    bad('jscpd must never use --semantic (it can send code to an AI API; catalogue D6): not in the command, args, env, config or choices', 'step', 'cli', 'command');
  }
  if (runsTool(e, 'betterleaks/betterleaks', 'betterleaks')) out.push(...betterleaksProblems(e));
  if (runsTool(e, 'projectdiscovery/nuclei', 'nuclei')) out.push(...nucleiProblems(e));
  // catalogue §3 SD5 / MG1: no results upload from Scorecard, no PR comments (a write) from dependency-review
  const want = FIXED_ACTION_INPUTS[repo];
  for (const [k, v] of Object.entries(want ?? {})) {
    if (fx.with?.[k] !== v) bad(`the ${c.repo} entry must fix ${k}: "${v}"`, 'fixedInputs', 'with', k);
  }
  return out;
}

/** Action inputs some entries must fix (catalogue §3 SD5, MG1), by lowercased repo. */
const FIXED_ACTION_INPUTS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  'ossf/scorecard-action': { publish_results: 'false' },
  'actions/dependency-review-action': { 'comment-summary-in-pr': 'never' },
};

/** PS25: npm packages pipegen never adds (CVE-2025-54313). */
const BANNED_PACKAGE_RE = /eslint-(?:config|plugin)-prettier/i;

/** Every string in a value: strings, array items, and object keys and values (deep). */
function leaves(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) for (const x of v) leaves(x, out);
  else if (v !== null && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      out.push(k);
      leaves(x, out);
    }
  }
  return out;
}

/** A flag's name: without its leading dashes or `=value`, lower case (`--Validate=true` → `validate`). */
const flagName = (a: string) => lower(a.replace(/^-+/, '').split('=')[0] as string);

/**
 * Whether an entry runs this tool: its repo (any letter case), its install package or asset (`trivy`, `aquasec/trivy`,
 * `trivy_0.76.0_Linux-64bit.tar.gz`, `jscpd-linux-x64-gnu.tar.gz`), or a command word (`npx jscpd`, `/usr/bin/trivy`).
 */
function runsTool(e: Entry, repo: string, tool: string): boolean {
  if (lower(e.candidate.repo) === repo) return true;
  const cli = e.step.cli;
  if (cli === undefined) return false;
  const base = (s: string) => lower(s.split('/').pop() ?? '');
  const pkg = base(cli.install.package);
  if (pkg === tool || pkg.startsWith(`${tool}_`) || pkg.startsWith(`${tool}-`)) return true;
  return cli.command.some((w) => base(w) === tool);
}

/** Plugins: npm or pip packages next to an npm or pip tool, each exact and hashed, at most MAX_PLUGINS, never the tool itself. */
function pluginProblems(kind: string, inst: Install, plugins: readonly Install[]): { message: string; path: (string | number)[] }[] {
  const out: { message: string; path: (string | number)[] }[] = [];
  const at = (...p: (string | number)[]) => ['step', 'cli', 'plugins', ...p];
  if (kind !== 'cli' || (inst.method !== 'npm' && inst.method !== 'pip')) out.push({ message: 'only npm and pip entries take plugins', path: at() });
  if (plugins.length > MAX_PLUGINS) out.push({ message: `an entry installs at most ${MAX_PLUGINS} plugins`, path: at() });
  const norm = (method: string, name: string) => (method === 'pip' ? pep503(name) : lower(name));
  const own = norm(inst.method, inst.package);
  const seen = new Set<string>();
  plugins.forEach((p, i) => {
    if (p.method !== 'npm' && p.method !== 'pip') out.push({ message: 'a plugin is an npm or pip package', path: at(i, 'method') });
    else if (p.method !== inst.method) out.push({ message: `a plugin installs the way its tool does (${inst.method})`, path: at(i, 'method') });
    if (p.digest !== undefined) out.push({ message: 'a plugin is pinned by its checksum only (no digest)', path: at(i, 'digest') });
    if (p.method === 'npm') {
      if (!isNpmName(p.package) || !isFullSemver(p.version)) out.push({ message: 'an npm plugin names a package and an exact version', path: at(i) });
      if (!SRI_SHA512_RE.test(p.checksum ?? '')) out.push({ message: 'an npm plugin is pinned by its sha512 integrity', path: at(i, 'checksum') });
    } else if (p.method === 'pip') {
      if (!isPypiName(p.package) || advisoryVersion(p.version, 'pep440') !== p.version) out.push({ message: 'a pip plugin names a package and an exact version', path: at(i) });
      if (!SHA256_RE.test(p.checksum ?? '')) out.push({ message: 'a pip plugin is pinned by its sha256', path: at(i, 'checksum') });
    }
    const name = norm(p.method, p.package);
    if (name === own) out.push({ message: `a plugin is never the entry's own package (${inst.package})`, path: at(i, 'package') });
    if (seen.has(name)) out.push({ message: `the plugin ${p.package} is listed twice`, path: at(i, 'package') });
    seen.add(name);
  });
  return out;
}

/** betterleaks (catalogue §3 PC2, ruling PS34): pipegen's pinned --config only, and none of BETTERLEAKS_FORBIDDEN_FLAGS. */
function betterleaksProblems(e: Entry): { message: string; path: (string | number)[] }[] {
  const out: { message: string; path: (string | number)[] }[] = [];
  const fx = e.fixedInputs;
  const flags = [...(e.step.cli?.command ?? []), ...(fx.args ?? []), ...Object.values(e.choices).flat()].filter((a) => a.startsWith('-')).map(flagName);
  const names = [...flags, ...Object.keys(e.choices).map(flagName)];
  const envKeys = [...Object.keys(e.step.cli?.env ?? {}), ...Object.keys(fx.env ?? {})];
  for (const f of BETTERLEAKS_FORBIDDEN_FLAGS) {
    const name = flagName(f);
    if (names.includes(name) || envKeys.some((k) => lower(k).includes(name.replace(/-/g, '_')))) {
      out.push({ message: `betterleaks must never use ${f} (it sends candidate secrets out or loads the repo's config; catalogue §3)`, path: ['step', 'cli', 'command'] });
    }
  }
  const pinned = fx.config !== undefined && 'flag' in fx.config.passAs && fx.config.passAs.flag === '--config';
  const other = [...(e.step.cli?.command ?? []), ...(fx.args ?? [])].some((a) => a === '-c' || /^-c./.test(a) || flagName(a) === 'config')
    || envKeys.some((k) => /^(?:better|git)leaks_config/i.test(k));
  if (!pinned || other) out.push({ message: "betterleaks runs with pipegen's pinned --config (fixedInputs.config passed as --config) and no other config", path: ['fixedInputs', 'config'] });
  return out;
}

/**
 * Nuclei (catalogue §3 MG5, §5): -duc fixed; templates only from the pinned archive, with -t naming its directory only;
 * no upload to ProjectDiscovery's cloud (-dashboard, -cloud, -pd, PDCP_* settings) and no update at run time.
 */
function nucleiProblems(e: Entry): { message: string; path: (string | number)[] }[] {
  const out: { message: string; path: (string | number)[] }[] = [];
  const bad = (message: string, ...path: (string | number)[]) => out.push({ message, path });
  const fx = e.fixedInputs;
  const command = e.step.cli?.command ?? [];
  const args = fx.args ?? [];
  const env = fx.env ?? {};
  const all = [...command, ...args, ...Object.values(e.choices).flat()];
  const names = [...all.filter((a) => a.startsWith('-')).map(flagName), ...Object.keys(e.choices).map(flagName)];

  if (!command.includes('-duc') || !args.includes('-duc') || all.some((a) => a.includes('=') && ['duc', 'disable-update-check'].includes(flagName(a)))) {
    bad('nuclei must run with -duc (no update check) in the command and fixedInputs.args, and never -duc=…', 'step', 'cli', 'command');
  }
  if (names.some((n) => ['dashboard', 'cloud', 'pd', 'pdu', 'dashboard-upload', 'cloud-upload'].includes(n))) {
    bad('nuclei must never upload results: no -dashboard, -cloud or -pd (catalogue §3)', 'step', 'cli', 'command');
  }
  if ([...Object.keys(e.step.cli?.env ?? {}), ...Object.keys(env)].some((k) => /^pdcp_/i.test(k))) {
    bad('nuclei gets no PDCP_ settings (they turn on the ProjectDiscovery cloud upload)', 'step', 'cli', 'env');
  }
  if (names.some((n) => ['ut', 'update-templates', 'up', 'update', 'ud', 'update-template-dir'].includes(n))) {
    bad('nuclei must not update itself or its templates at run time (no -ut, -up or -ud)', 'step', 'cli', 'command');
  }
  // every template or workflow location is the verified directory, in the command and the fixed args
  const locations = (xs: readonly string[]) => {
    const found: string[] = [];
    xs.forEach((a, i) => {
      if (!a.startsWith('-')) return;
      const n = flagName(a);
      if (!['t', 'templates', 'w', 'workflows', 'tu', 'template-url', 'wu', 'workflow-url'].includes(n)) return;
      const v = a.includes('=') ? a.slice(a.indexOf('=') + 1) : xs[i + 1] ?? '';
      found.push(['t', 'templates'].includes(n) ? v : `${n}:${v}`); // anything but -t <dir> fails the check below
    });
    return found;
  };
  const inCommand = locations(command);
  const inChoices = Object.keys(e.choices).map(flagName).filter((n) => ['t', 'templates', 'w', 'workflows', 'tu', 'template-url', 'wu', 'workflow-url'].includes(n));
  if (inCommand.length === 0 || inCommand.some((v) => v !== NUCLEI_TEMPLATES_DIR) || !locations(args).includes(NUCLEI_TEMPLATES_DIR) || inChoices.length > 0) {
    bad(`nuclei templates come only from the pinned archive: -t ${NUCLEI_TEMPLATES_DIR} and nothing else, in the command and fixedInputs.args (no -tu, -w or -wu)`, 'step', 'cli', 'command');
  }
  if (!NUCLEI_TEMPLATES_URL_RE.test(env[NUCLEI_TEMPLATES_URL_ENV] ?? '')) {
    bad(`nuclei needs fixedInputs.env.${NUCLEI_TEMPLATES_URL_ENV}: an official projectdiscovery/nuclei-templates release tarball (a vX.Y.Z tag)`, 'fixedInputs', 'env');
  }
  if (!SHA256_RE.test(env[NUCLEI_TEMPLATES_SHA256_ENV] ?? '')) bad(`nuclei needs fixedInputs.env.${NUCLEI_TEMPLATES_SHA256_ENV}: the templates archive's sha256`, 'fixedInputs', 'env');
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
    throw new ReviewedListError("pipegen's reviewed tool list could not be read.", { cause: e, reason: 'it could not be read' });
  }
  const parsed = fileSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const tools = (raw as { tools?: { id?: unknown }[] } | null)?.tools;
    const index = issue?.path[1];
    const id = issue?.path[0] === 'tools' && typeof index === 'number' && typeof tools?.[index]?.id === 'string' ? ` (entry ${tools[index].id})` : '';
    const where = `${id} at ${issue?.path.join('.') || 'the top'}: ${issue?.message ?? 'invalid'}`;
    throw new ReviewedListError(`pipegen's reviewed tool list is invalid${where}`, { reason: `it is invalid${where}` });
  }
  const entries = parsed.data.tools;
  const ids = entries.map((t) => t.id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup !== undefined) throw new ReviewedListError(`pipegen's reviewed tool list has the entry ${dup} more than once.`, { reason: `it has the entry ${dup} more than once` });

  if (isReleaseBuild()) {
    const pending = entries.filter((t) => t.reviewedBy === PENDING).map((t) => t.id);
    if (pending.length > 0) {
      const reason = `${pending.length} entries still wait for human review (${listPending(pending)})`;
      throw new ReviewedListError(`This pipegen release refuses its reviewed tool list: ${reason}. Nothing unreviewed may run in your CI.`, { reason });
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

/**
 * The never-list check (Plan P Task 5): whether a reference names a NEVER_REPOS entry → that entry, its reason and the
 * `owner/name` read from the reference; else null. A reference is a repo (`owner/name`), a `uses:` value (any sub-path,
 * `@ref`), an image (`[registry/]owner/name[:tag][@digest]`, `docker://…`, any registry host) or a URL
 * (`https://github.com/owner/name/…`, raw.githubusercontent.com, api.github.com/repos/…). Letter case doesn't matter,
 * and look-alike letters fold first (NFKC). A look-alike is refused too: within Levenshtein distance 2 of a listed
 * `owner/name`, or an owner within distance 2 of a listed `owner/*`.
 */
export function neverListed(ref: unknown): { key: string; reason: string; ref: string } | null {
  const parts = ownerName(ref);
  if (parts === null) return null;
  const [owner, name] = parts;
  const full = name === undefined ? owner : `${owner}/${name}`;
  const found = (key: string) => ({ key, reason: NEVER_REPOS[key] as string, ref: full });
  if (name !== undefined && NEVER_REPOS[full] !== undefined) return found(full);
  if (NEVER_REPOS[`${owner}/*`] !== undefined) return found(`${owner}/*`);
  for (const key of Object.keys(NEVER_REPOS)) {
    const [keyOwner, keyName] = key.split('/') as [string, string];
    if (keyName === '*' ? levenshtein(owner, keyOwner) <= 2 : name !== undefined && Math.abs(full.length - key.length) <= 2 && levenshtein(full, key) <= 2) return found(key);
  }
  return null;
}

/** The `owner` and `name` a reference points at (see neverListed), lower case; null when there is no owner. */
function ownerName(ref: unknown): [string, string | undefined] | null {
  if (typeof ref !== 'string' || ref.length > 2048) return null;
  let s = lower(ref.normalize('NFKC').trim()).replace(/^docker:\/\//, '');
  let segs: string[];
  const url = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/?#]+)\/?([^?#]*)/.exec(s);
  if (url !== null) {
    segs = (url[2] ?? '').split('/');
    if (url[1] === 'api.github.com' && segs[0] === 'repos') segs.shift();
    if (segs[0] === 'v2') segs.shift(); // a registry API path (ghcr.io/v2/owner/name/…)
  } else {
    s = s.replace(/^git@[^:/]+:/, '');
    segs = s.split('/');
    // an image's registry host (docker.io, ghcr.io, quay.io, localhost:5000, …)
    if (segs.length > 2 && /[.:]|^localhost$/.test(segs[0] ?? '')) segs.shift();
  }
  segs = segs.filter((x) => x !== '' && x !== '.');
  const owner = segs[0]?.replace(/[@:#?].*$/, '');
  if (owner === undefined || owner === '') return null;
  const name = segs[1]?.replace(/[@:#?].*$/, '').replace(/\.git$/, '');
  return [owner, name === '' ? undefined : name];
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
