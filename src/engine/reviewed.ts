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
import { lastValue, parseArgv, type ParsedArgv } from './argv.js';
import { BETTERLEAKS_FORBIDDEN_FLAGS, BETTERLEAKS_FORBIDDEN_SUBCOMMANDS, BETTERLEAKS_SUBCOMMANDS } from './tool-flags.js';
import { BETTERLEAKS_GRAMMAR, NUCLEI_GRAMMAR, TRIVY_GRAMMAR } from './tool-grammar.js';

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
 * The exact certificate identity of a keyless signature (ruling PS24, fix round 1): the entry's own repo's workflow
 * at a tag. Never a regex, a branch or a commit: entryProblems also checks that owner/repo is the entry's repo and the
 * tag its version.
 */
const IDENTITY_RE = /^https:\/\/github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})\/\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml@refs\/tags\/([A-Za-z0-9._+-]{1,128})$/;
/** A cosign public key in the entry's own repo at its version tag (P10: kube-linter and gosec sign with a repo-held key). */
const KEY_URL_RE = /^https:\/\/raw\.githubusercontent\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})\/([A-Za-z0-9._+-]{1,128})\/((?:[A-Za-z0-9._-]{1,100}\/){0,8}[A-Za-z0-9._-]{1,100})$/;

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
 * Repo names refused under ANY owner (fix round 1): a fork or a copy shares the code and often the commit network of
 * the tool it copies. Every non-wildcard NEVER_REPOS name, plus `reviewdog`; a name that starts with one of them and
 * a `-` (`slsa-github-generator-go`, `tfsec-action`) is refused too. NEVER_NAME_ALLOW lists `owner/name` exceptions.
 */
const NEVER_NAMES: ReadonlyMap<string, string> = (() => {
  const m = new Map<string, string>([['reviewdog', 'reviewdog/*']]);
  // the first key with a name (the current repo, listed before its old names) is the one a hit reports
  for (const k of Object.keys(NEVER_REPOS)) if (!k.endsWith('/*') && !m.has(k.slice(k.indexOf('/') + 1))) m.set(k.slice(k.indexOf('/') + 1), k);
  return m;
})();
/** `owner/name` repos allowed although their name is in a never-list family (none needed today). */
export const NEVER_NAME_ALLOW: ReadonlySet<string> = new Set<string>();

/**
 * Images pipegen never runs (P11), by image name (the last part of the path), on any registry and under any
 * namespace: `aquasec/trivy`, `ghcr.io/aquasecurity/trivy` and `public.ecr.aws/aquasecurity/trivy` all end in
 * `trivy`. Kept apart from NEVER_REPOS so the reviewed binary's repo, aquasecurity/trivy, still loads. Docker Hub
 * checked on 2026-10-27: aquasec/trivy, aquasec/tfsec, aquasec/tfsec-ci, aquasec/tfsec-alpine, aquasec/tfsec-scratch,
 * tfsec/tfsec, liamg/tfsec, checkmarx/kics, tenable/terrascan and accurics/terrascan exist.
 */
export const NEVER_IMAGES: Readonly<Record<string, string>> = Object.freeze({
  trivy: 'Trivy runs only as the release binary checked by sha256 and cosign: its Docker Hub images 0.69.5 and 0.69.6 were malicious in March 2026 (catalogue §4, §5)',
  tfsec: 'tfsec is superseded by Trivy (catalogue §4)',
  'tfsec-ci': 'tfsec is superseded by Trivy (catalogue §4)',
  'tfsec-alpine': 'tfsec is superseded by Trivy (catalogue §4)',
  'tfsec-scratch': 'tfsec is superseded by Trivy (catalogue §4)',
  kics: 'KICS: its Docker Hub tags were overwritten with a data-stealing binary in 2026 (catalogue §4, §5)',
  dastardly: 'Dastardly: a mutable :latest image from an unmaintained product (catalogue §4, ruling PS21)',
  terrascan: 'Terrascan is archived (catalogue §4)',
});

/**
 * Tools whose releases pipegen pins only with a recorded signature or attestation check (verifiedWith), by their
 * repo: catalogue §4 ("+ cosign", "+ GitHub attestation", "+ sigstore"). The check goes by the tool, not the exact
 * repo (fix round 1): any entry whose repo has one of these names (under any owner) or that runs one of these tools
 * (runsTool) needs verifiedWith. jscpd is not on it (ruling P12): its releases are signed from a branch
 * (refs/heads/master), which verifiedWith's tag-only identity refuses; it is an advisory, warning-only check
 * (DECISIONS #93), pinned by the sha256 of the reviewed release asset, and its bundle is recorded as information only.
 */
export const MUST_VERIFY: ReadonlySet<string> = new Set([
  'betterleaks/betterleaks', 'aquasecurity/trivy', 'hadolint/hadolint', 'stackrox/kube-linter', 'securego/gosec',
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

/** A keyless signature or attestation check (PS24); its format and binding to the entry are checked in verifiedWithProblems. */
const keylessSchema = z.strictObject({
  method: z.enum(['cosign-bundle', 'cosign-signature', 'github-attestation']),
  asset: z.string().max(255),
  identity: z.string().max(400),
  issuer: z.literal(OIDC_ISSUER),
  verifiedOn: z.string().max(10),
});
/** A check with a cosign key held in the entry's own repo (P10: kube-linter, gosec). */
const keySchema = z.strictObject({
  kind: z.literal('cosign-key'),
  keyUrl: z.string().max(400),
  keySha256: z.string().max(64),
  verifiedOn: z.string().max(10),
});
const verifiedWithSchema = z.union([keylessSchema, keySchema]);

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
  // a pinnedOn in the future would let a release younger than the cooldown through
  if (!(pinnedOn <= Date.now())) ctx.addIssue({ code: 'custom', path: ['pinnedOn'], message: 'pinnedOn is in the future: the cooldown is measured from it' });
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
  // [reference, path, may be an image]
  const refs: [string, (string | number)[], boolean][] = [[c.repo, ['candidate', 'repo'], false], [c.name, ['candidate', 'name'], false]];
  if (action !== undefined) refs.push([action.uses, ['step', 'action', 'uses'], false]);
  if (cli !== undefined) refs.push([cli.install.package, ['step', 'cli', 'install', 'package'], cli.install.method === 'docker']);
  // download URLs, images and repo names in any value of the step (plugins included), the fixed inputs or the choices
  for (const text of [...leaves(e.step), ...leaves(fx), ...leaves(e.choices)]) {
    // a word may be an image unless it is a URL or a file path (`/usr/local/bin/trivy`, `./x`)
    for (const token of refTokens(text)) refs.push([token, ['step'], (!/^[a-z][a-z0-9+.-]*:\/\//i.test(token) || /^docker:\/\//i.test(token)) && !/^\.{0,2}\//.test(token)]);
  }
  for (const [ref, path, image] of refs) {
    const hit = neverListed(ref) ?? (image ? neverImage(ref) : null);
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
  // jscpd's AI mode by any tool name (a renamed jscpd binary is still jscpd): no --semantic* flag in any entry
  if (flagWords(e).some((n) => n.startsWith('semantic'))) bad(`no entry may pass --semantic (jscpd's AI mode: ${JSCPD_AI_WHY})`, 'step', 'cli', 'command');
  // MUST_VERIFY tools, by repo name under any owner or by what the entry runs, are pinned only with a recorded check
  const verify = mustVerifyRepo(e);
  if (verify !== null && e.verifiedWith === undefined) bad(`${c.repo} is ${verify}'s tool, which pipegen pins only with a signature or attestation check: verifiedWith is required (MUST_VERIFY)`, 'verifiedWith');
  if (e.verifiedWith !== undefined) out.push(...verifiedWithProblems(e));

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

  // ---- Plan P Task 5: the catalogue's tool locks (argv read with each tool's own grammar, fix round 1) ----
  if (runsTool(e, 'aquasecurity/trivy', 'trivy')) out.push(...trivyProblems(e));
  if (runsTool(e, 'kucherenko/jscpd', 'jscpd')) out.push(...jscpdProblems(e));
  if (runsTool(e, 'betterleaks/betterleaks', 'betterleaks')) out.push(...betterleaksProblems(e));
  if (runsTool(e, 'projectdiscovery/nuclei', 'nuclei')) out.push(...nucleiProblems(e));
  // catalogue §3 SD5 / MG1: no results upload from Scorecard, no PR comments (a write) from dependency-review
  const want = FIXED_ACTION_INPUTS[repo];
  for (const [k, v] of Object.entries(want ?? {})) {
    if (fx.with?.[k] !== v) bad(`the ${c.repo} entry must fix ${k}: "${v}"`, 'fixedInputs', 'with', k);
  }
  return out;
}

type Problem = { message: string; path: (string | number)[] };

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

/**
 * The words of a value that may name a repo or an image: split at spaces, quotes, brackets, `=`, `,` and `;`, each
 * with a `/`, and again at `:` (so `uses:owner/name` or `x:owner/name` glued in config text is read too).
 */
function refTokens(text: string): string[] {
  const out: string[] = [];
  for (const token of text.split(/[\s=,;"'`()[\]{}<>|]+/)) {
    if (!token.includes('/')) continue;
    out.push(token);
    if (token.includes(':')) out.push(...token.split(':').filter((p) => p.includes('/')));
  }
  return out;
}

/** A flag's name: without its leading dashes or `=value`, lower case (`--Validate=true` → `validate`). */
const flagName = (a: string) => lower(a.replace(/^-+/, '').split('=')[0] as string);

/** The flag names an entry passes anywhere: dash words of the command, the fixed args and the choice values, and the choice names. */
function flagWords(e: Entry): string[] {
  const words = [...(e.step.cli?.command ?? []), ...(e.fixedInputs.args ?? []), ...Object.values(e.choices).flat()];
  return [...words.filter((a) => a.startsWith('-')).map(flagName), ...Object.keys(e.choices).map(flagName)];
}

/** The last part of a path, lower case (`/usr/bin/trivy` → `trivy`). */
const basename = (s: string) => lower(s.split('/').pop() ?? '');

/**
 * Whether an entry runs this tool: its repo (any letter case), its install package or asset (`trivy`, `aquasec/trivy`,
 * `trivy_0.76.0_Linux-64bit.tar.gz`, `jscpd-linux-x64-gnu.tar.gz`, the npm scope `@jscpd/cli`), or a command word
 * (`npx jscpd`, `/usr/bin/trivy`).
 */
function runsTool(e: Entry, repo: string, tool: string): boolean {
  if (lower(e.candidate.repo) === repo) return true;
  const cli = e.step.cli;
  if (cli === undefined) return false;
  const pkg = basename(cli.install.package);
  if (pkg === tool || pkg.startsWith(`${tool}_`) || pkg.startsWith(`${tool}-`) || lower(cli.install.package).startsWith(`@${tool}/`)) return true;
  return cli.command.some((w) => basename(w) === tool);
}

/** The MUST_VERIFY repo whose tool this entry is: by its repo's name under any owner, or by what it runs; else null. */
function mustVerifyRepo(e: Entry): string | null {
  const name = lower(e.candidate.repo).split('/')[1];
  for (const r of MUST_VERIFY) {
    const tool = r.slice(r.indexOf('/') + 1);
    if (lower(e.candidate.repo) === r || name === tool || runsTool(e, r, tool)) return r;
  }
  return null;
}

/**
 * verifiedWith is bound to the entry (fix round 1): a keyless identity is the entry's own repo's workflow at the
 * entry's version tag (no branch, no commit, no other repo); a cosign key is a file in the entry's own repo at that
 * tag, with its sha256; the asset names no other version; verifiedOn is a real day, not before the release and not
 * in the future.
 */
function verifiedWithProblems(e: Entry): Problem[] {
  const out: Problem[] = [];
  const bad = (message: string, ...path: (string | number)[]) => out.push({ message, path: ['verifiedWith', ...path] });
  const v = e.verifiedWith;
  if (v === undefined) return out;
  const c = e.candidate;
  const repo = lower(c.repo);
  const isVersion = (tag: string) => tag === c.version || tag === `v${c.version}`;
  if (!isRealDate(v.verifiedOn)) bad('verifiedWith.verifiedOn must be a real date (YYYY-MM-DD)', 'verifiedOn');
  else if (v.verifiedOn > new Date().toISOString().slice(0, 10)) bad('verifiedWith.verifiedOn is in the future', 'verifiedOn');
  else if (v.verifiedOn < e.releasedAt.slice(0, 10)) bad(`verifiedWith.verifiedOn is before the release (${e.releasedAt.slice(0, 10)})`, 'verifiedOn');
  if ('kind' in v) {
    const m = KEY_URL_RE.exec(v.keyUrl);
    if (m === null || lower(`${m[1]}/${m[2]}`) !== repo || !isVersion(m[3] as string) || (m[4] as string).split('/').some((s) => s === '.' || s === '..')) {
      bad(`verifiedWith.keyUrl must be the key file in ${c.repo} at ${c.version}: https://raw.githubusercontent.com/${c.repo}/${c.version}/<path>`, 'keyUrl');
    }
    if (!SHA256_RE.test(v.keySha256)) bad("verifiedWith.keySha256 must be the key file's sha256 (64 hex characters)", 'keySha256');
    return out;
  }
  const m = IDENTITY_RE.exec(v.identity);
  if (m === null) bad(`verifiedWith.identity must be the exact certificate identity https://github.com/${c.repo}/.github/workflows/<file>@refs/tags/${c.version} (never a regex, a branch or a commit)`, 'identity');
  else if (lower(`${m[1]}/${m[2]}`) !== repo) bad(`verifiedWith.identity is a workflow of ${m[1]}/${m[2]}, not of ${c.repo}`, 'identity');
  else if (!isVersion(m[3] as string)) bad(`verifiedWith.identity is the signature of tag ${m[3]}, not of this entry's version ${c.version}`, 'identity');
  if (!ASSET_RE.test(v.asset)) bad('verifiedWith.asset names the signed file (a plain file name)', 'asset');
  for (const x of v.asset.match(/\d+\.\d+\.\d+/g) ?? []) {
    if (x !== c.version.replace(/^v/, '')) bad(`verifiedWith.asset is the file of version ${x}, not of this entry's ${c.version}`, 'asset');
  }
  return out;
}

/** Problems with a tool's choices: each names a flag the tool has and pipegen allows, and no value is a flag. */
function choiceProblems(tool: string, e: Entry, known: (name: string) => boolean, refused: (name: string) => string | null): Problem[] {
  const out: Problem[] = [];
  for (const [k, vs] of Object.entries(e.choices)) {
    const why = refused(k) ?? (known(k) ? null : `${tool} has no flag --${k} that pipegen may pass: a choice names a flag of the pinned version on the allowlist (ruling P13)`);
    if (why !== null) out.push({ message: why, path: ['choices', k] });
    for (const v of vs) if (v.startsWith('-')) out.push({ message: `a ${tool} choice value may not be a flag (${v})`, path: ['choices', k] });
  }
  return out;
}

/**
 * Ruling P13: the only flags (long names) pipegen may pass each tool at its pinned version, the smallest set its own
 * planned steps use (catalogue §3 PU11, MG2, MG4, PC2, MG5 and the Task 6 table). Any parsed flag outside its list is
 * refused, aliases and shorthands included (`-v`, `--help`, `-version`, `-tl`, …); the forbidden lists stay as a
 * second check. A flag added here needs a review of what it does at the pinned version.
 */
export const TRIVY_ALLOWED_FLAGS: ReadonlySet<string> = new Set([
  'disable-telemetry', 'skip-version-check', 'skip-check-update', 'format', 'output', 'exit-code', 'severity', 'scanners', 'ignore-unfixed',
]);
export const BETTERLEAKS_ALLOWED_FLAGS: ReadonlySet<string> = new Set(['report-format', 'report-path', 'no-banner', 'ignore-gitleaks-allow', 'redact', 'exit-code']);
export const NUCLEI_ALLOWED_FLAGS: ReadonlySet<string> = new Set([
  'disable-update-check', 'templates', 'severity', 'sarif-export', 'target', 'automatic-scan', 'tags', 'no-interactsh',
]);

/** P13: every parsed flag is on the tool's allowlist (skip: names another rule already refused with its own reason). */
function allowlistProblems(tool: string, parsed: readonly ParsedArgv[], allowed: ReadonlySet<string>, dash: string, skip: (name: string) => boolean = () => false): Problem[] {
  const out: Problem[] = [];
  for (const p of parsed) {
    for (const f of p.flags) {
      if (allowed.has(f.name) || skip(f.name)) continue;
      const shown = f.raw === `${dash}${f.name}` || f.raw.startsWith(`${dash}${f.name}=`) ? f.raw : `${f.raw} (${dash}${f.name})`;
      out.push({ message: `${tool} may use only ${[...allowed].map((n) => `${dash}${n}`).join(', ')} (allowlist, ruling P13), not ${shown}`, path: ['step', 'cli', 'command'] });
      return out;
    }
  }
  return out;
}

/** Keys pipegen's pinned trivy config may set, with their only value (P13): today, the in-memory cache. */
const TRIVY_CONFIG_ALLOWED: Readonly<Record<string, string>> = { 'cache.backend': 'memory' };

/**
 * Trivy's pinned config (P13): passed as --config (so the repo's trivy.yaml is never loaded), YAML (bounded: 64 KiB,
 * no aliases) whose every key is in TRIVY_CONFIG_ALLOWED with its value. The config can set every flag (db.repository,
 * server.addr, misconfiguration.checks-bundle-repository, …), so nothing else is allowed.
 */
function trivyConfigProblems(e: Entry): Problem[] {
  const bad = (message: string): Problem[] => [{ message, path: ['fixedInputs', 'config'] }];
  const cfg = e.fixedInputs.config;
  if (cfg === undefined || !('flag' in cfg.passAs) || cfg.passAs.flag !== '--config') return bad("trivy runs with pipegen's pinned config, passed as --config (else it loads the repo's trivy.yaml)");
  let doc: unknown;
  try {
    doc = parse(cfg.content, { maxAliasCount: 0, uniqueKeys: true });
  } catch {
    return bad("trivy's pinned config must be plain YAML (no aliases, no repeated keys)");
  }
  const leavesOf = (v: unknown, at: string, out: [string, unknown][]) => {
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) for (const [k, x] of Object.entries(v)) leavesOf(x, at === '' ? k : `${at}.${k}`, out);
    else out.push([at, v]);
    return out;
  };
  const found = leavesOf(doc, '', []);
  const allowed = Object.entries(TRIVY_CONFIG_ALLOWED).map(([k, v]) => `${k}: ${v}`).join(', ');
  for (const [k, v] of found) {
    if (TRIVY_CONFIG_ALLOWED[k] === undefined || TRIVY_CONFIG_ALLOWED[k] !== v) return bad(`trivy's pinned config may set only ${allowed}, not ${k || '(a non-mapping document)'}`);
  }
  return [];
}

/** Trivy flags pipegen never passes: other servers, registries, check or DB sources, modules, credentials, or a second config. */
const TRIVY_FORBIDDEN: ReadonlySet<string> = new Set([
  'server', 'token', 'token-header', 'custom-headers', 'cache-backend', 'cache-ttl', 'redis-ca', 'redis-cert', 'redis-key', 'redis-tls',
  'db-repository', 'java-db-repository', 'checks-bundle-repository', 'config-check', 'config-data', 'module-dir', 'enable-modules',
  'rekor-url', 'sbom-sources', 'vex', 'output-plugin-arg', 'password', 'password-stdin', 'username', 'registry-token',
  'download-db-only', 'download-java-db-only', 'generate-default-config', 'config', 'cacert', 'insecure', 'docker-host', 'podman-host',
]);

/**
 * Trivy (catalogue §4, D10): `trivy config|image|fs …`, read with v0.76.0's grammar (tool-grammar.ts). The three
 * hardening flags must be in effect (not swallowed as another flag's value, not after `--`, not set false later) and
 * be fixed args; no flag v0.76.0 doesn't have, none of TRIVY_FORBIDDEN, no TRIVY_* env (it sets any flag).
 */
function trivyProblems(e: Entry): Problem[] {
  const out: Problem[] = [];
  const bad = (message: string, ...path: (string | number)[]) => out.push({ message, path });
  const command = e.step.cli?.command ?? [];
  const sub = command[1] === 'filesystem' ? 'fs' : command[1];
  if (basename(command[0] ?? '') !== 'trivy' || (sub !== 'config' && sub !== 'image' && sub !== 'fs')) {
    bad('trivy runs as `trivy config|image|fs …` (the pinned binary, its subcommand first)', 'step', 'cli', 'command');
    return out;
  }
  const g = TRIVY_GRAMMAR[sub];
  const p = parseArgv(command.slice(2), g, 'pflag');
  if (p.errors.length > 0) bad(`trivy ${sub}: ${p.errors[0]} (pipegen reads the command with trivy v0.76.0's flags and refuses any it doesn't know)`, 'step', 'cli', 'command');
  const args = e.fixedInputs.args ?? [];
  const pa = parseArgv(args, g, 'pflag');
  if (pa.errors.length > 0) bad(`trivy ${sub} fixedInputs.args: ${pa.errors[0]}`, 'fixedInputs', 'args');
  for (const flag of TRIVY_REQUIRED_FLAGS) {
    if (lastValue(p, flag.slice(2)) !== 'true' || !args.includes(flag)) {
      bad(`trivy must run with ${flag} in effect, in the command and fixedInputs.args (not another flag's value, not after --, never ${flag}=false; catalogue §4)`, 'step', 'cli', 'command');
    }
  }
  for (const f of [...p.flags, ...pa.flags]) if (TRIVY_FORBIDDEN.has(f.name)) bad(`trivy must not use --${f.name} (another server, source, credential or config than pipegen's)`, 'step', 'cli', 'command');
  out.push(...allowlistProblems('trivy', [p, pa], TRIVY_ALLOWED_FLAGS, '--', (n) => TRIVY_FORBIDDEN.has(n)));
  out.push(...trivyConfigProblems(e));
  for (const k of [...Object.keys(e.step.cli?.env ?? {}), ...Object.keys(e.fixedInputs.env ?? {})]) {
    if (/^trivy_/i.test(k)) bad(`trivy gets no ${k}: a TRIVY_* variable sets a flag outside the command pipegen checks`, 'step', 'cli', 'env');
  }
  out.push(...choiceProblems('trivy', e, (k) => (g.value.has(k) || g.bool.has(k)) && TRIVY_ALLOWED_FLAGS.has(k),
    (k) => (TRIVY_FORBIDDEN.has(k) || (TRIVY_REQUIRED_FLAGS as readonly string[]).includes(`--${k}`) ? `the AI may not choose trivy's --${k}` : null)));
  return out;
}

const JSCPD_AI_WHY = 'it runs an embedding model that can send code to an AI API; jscpd 5.4.2 rust/crates/cpd/src/options.rs:178-222 and cli.rs:269-333, 534, 602, 613; catalogue D6';
/** jscpd 5.4.2 flags that run the embedding model or serve it: --compare, --mcp, --dashboard, and every --semantic*. */
const JSCPD_AI_FLAGS: ReadonlySet<string> = new Set(['compare', 'mcp', 'dashboard']);

/**
 * jscpd (catalogue D6): no semantic mode anywhere. Flags: --semantic* and the modes that run the model without it
 * (--compare, --mcp) or serve results (--dashboard). The pinned config must be JSON (jscpd reads it with serde_json)
 * and, decoded, has no `semantic` key (`semantic.enabled` turns the mode on) and none of those modes.
 */
function jscpdProblems(e: Entry): Problem[] {
  const out: Problem[] = [];
  const bad = (message: string, ...path: (string | number)[]) => out.push({ message, path });
  const ai = `jscpd must never use --semantic, --compare, --mcp or --dashboard (${JSCPD_AI_WHY})`;
  if (flagWords(e).some((n) => n.startsWith('semantic') || JSCPD_AI_FLAGS.has(n))) bad(ai, 'step', 'cli', 'command');
  else if ([...leaves(e.step), ...leaves(e.fixedInputs), ...leaves(e.choices)].some((t) => /semantic/i.test(t))) bad(ai, 'step', 'cli');
  const content = e.fixedInputs.config?.content;
  if (content !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      bad("jscpd's pinned config must be JSON (jscpd reads it with serde_json), so pipegen can check every key", 'fixedInputs', 'config');
      return out;
    }
    const keys: string[] = [];
    const walk = (v: unknown) => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (v !== null && typeof v === 'object') for (const [k, x] of Object.entries(v)) { keys.push(lower(k)); walk(x); }
    };
    walk(parsed);
    if (keys.some((k) => k.includes('semantic') || JSCPD_AI_FLAGS.has(k))) bad(`jscpd's pinned config must not turn on semantic mode (${JSCPD_AI_WHY})`, 'fixedInputs', 'config');
  }
  return out;
}

/**
 * betterleaks (catalogue §3 PC2, ruling PS34): `betterleaks git|dir|stdin …`, read with v1.9.0's grammar
 * (tool-grammar.ts): none of BETTERLEAKS_FORBIDDEN_FLAGS, no subcommand that validates or scans a remote service, no
 * flag v1.9.0 doesn't have, no env (it can carry a config), and pipegen's pinned --config as the only config.
 */
function betterleaksProblems(e: Entry): Problem[] {
  const out: Problem[] = [];
  const bad = (message: string, ...path: (string | number)[]) => out.push({ message, path });
  const fx = e.fixedInputs;
  const command = e.step.cli?.command ?? [];
  const forbidden = new Set<string>(BETTERLEAKS_FORBIDDEN_FLAGS);
  const pinnedMsg = "betterleaks runs with pipegen's pinned --config (fixedInputs.config passed as --config) and no other config";
  // the forbidden flags by name, in any spelling (one or two dashes, =value), wherever a flag can be
  const words = [...command, ...(fx.args ?? []), ...Object.values(e.choices).flat()].filter((a) => a.startsWith('-'));
  const named = [...words.map((a) => (/^--?[a-z]$/i.test(a.split('=')[0] as string) ? (a.split('=')[0] as string) : `--${flagName(a)}`)), ...Object.keys(e.choices).map((k) => `--${flagName(k)}`)];
  const hit = named.find((n) => forbidden.has(n) || n.startsWith('--validation'));
  if (hit !== undefined) bad(`betterleaks must never use ${hit} (it sends candidate secrets to provider APIs, prints them, or runs unreviewed features; betterleaks v1.9.0 cmd/root.go:89, 109-127)`, 'step', 'cli', 'command');
  const sub = command[1] ?? '';
  if (basename(command[0] ?? '') !== 'betterleaks') bad('betterleaks runs as `betterleaks git|dir|stdin …`', 'step', 'cli', 'command');
  else if ((BETTERLEAKS_FORBIDDEN_SUBCOMMANDS as readonly string[]).includes(lower(sub))) bad(`betterleaks must never run ${sub} (it calls provider APIs or a remote service with a token; v1.9.0 cmd/${lower(sub)}.go)`, 'step', 'cli', 'command');
  else if (!(BETTERLEAKS_SUBCOMMANDS as readonly string[]).includes(sub)) bad(`betterleaks runs only ${BETTERLEAKS_SUBCOMMANDS.join(', ')} (local scans), not ${sub || 'nothing'}`, 'step', 'cli', 'command');
  else {
    const g = BETTERLEAKS_GRAMMAR[sub as 'git' | 'dir' | 'stdin'];
    // cmd/rule_flags.go expands -dr and -ir before cobra parses
    const expand = (xs: readonly string[]) => xs.map((a) => a.replace(/^-dr(?==|$)/, '--disable-rule').replace(/^-ir(?==|$)/, '--isolate-rule'));
    const p = parseArgv(expand(command.slice(2)), g, 'pflag');
    const pa = parseArgv(expand(fx.args ?? []), g, 'pflag');
    // the forbidden flags as betterleaks reads them: `-vfsarif` is --verbose plus -f sarif (re-review A)
    const parsedHit = [...p.flags, ...pa.flags].find((f) => forbidden.has(`--${f.name}`) || f.name.startsWith('validation'));
    if (hit === undefined && parsedHit !== undefined) bad(`betterleaks must never use --${parsedHit.name} (given as ${parsedHit.raw}; it sends candidate secrets to provider APIs, prints them, or runs unreviewed features; betterleaks v1.9.0 cmd/root.go:89, 109-127)`, 'step', 'cli', 'command');
    if (hit === undefined && p.errors.length > 0) bad(`betterleaks ${sub}: ${p.errors[0]} (pipegen reads the command with betterleaks v1.9.0's flags and refuses any it doesn't know)`, 'step', 'cli', 'command');
    if (hit === undefined && pa.errors.length > 0) bad(`betterleaks ${sub} fixedInputs.args: ${pa.errors[0]}`, 'fixedInputs', 'args');
    if ([...p.flags, ...pa.flags].some((f) => f.name === 'config')) bad(pinnedMsg, 'step', 'cli', 'command');
    out.push(...allowlistProblems('betterleaks', [p, pa], BETTERLEAKS_ALLOWED_FLAGS, '--', (n) => n === 'config' || forbidden.has(`--${n}`) || n.startsWith('validation')));
    out.push(...choiceProblems('betterleaks', e, (k) => (g.value.has(k) || g.bool.has(k) || g.optional.has(k)) && BETTERLEAKS_ALLOWED_FLAGS.has(k),
      (k) => (k === 'config' ? pinnedMsg : forbidden.has(`--${k}`) || k.startsWith('validation') ? `betterleaks must never use --${k}` : null)));
  }
  const pinned = fx.config !== undefined && 'flag' in fx.config.passAs && fx.config.passAs.flag === '--config';
  if (!pinned || (fx.args ?? []).some((a) => a === '-c' || /^-c./.test(a) || flagName(a) === 'config')) bad(pinnedMsg, 'fixedInputs', 'config');
  for (const k of [...Object.keys(e.step.cli?.env ?? {}), ...Object.keys(fx.env ?? {})]) {
    bad(/config/i.test(k) ? `${pinnedMsg} (not ${k})` : `betterleaks gets no env (${k}): v1.9.0 reads its config and tokens from it`, 'step', 'cli', 'env');
  }
  return out;
}

/** Nuclei v3.11.1 flags pipegen never passes, by long name → why (cmd/nuclei/main.go at tag v3.11.1). */
const NUCLEI_UPLOAD = 'nuclei must never upload results or log in to ProjectDiscovery: no -cloud-upload (-cup), -dashboard (-pd), -dashboard-upload (-pdu), -team-id or -auth (catalogue §3)';
const NUCLEI_TEMPLATES = `nuclei templates come only from the pinned archive: -t ${NUCLEI_TEMPLATES_DIR} and nothing else, in the command and fixedInputs.args (no -w, -turl, -wurl, -config, -tp or -ai)`;
const NUCLEI_UPDATE = 'nuclei must not update itself or its templates at run time (no -up, -ut, -ud or -reset)';
const NUCLEI_FORBIDDEN: Readonly<Record<string, string>> = {
  'cloud-upload': NUCLEI_UPLOAD, dashboard: NUCLEI_UPLOAD, 'dashboard-upload': NUCLEI_UPLOAD, 'team-id': NUCLEI_UPLOAD, auth: NUCLEI_UPLOAD,
  prompt: NUCLEI_TEMPLATES, config: NUCLEI_TEMPLATES, profile: NUCLEI_TEMPLATES, workflows: NUCLEI_TEMPLATES, 'template-url': NUCLEI_TEMPLATES, 'workflow-url': NUCLEI_TEMPLATES,
  update: NUCLEI_UPDATE, 'update-templates': NUCLEI_UPDATE, 'update-template-dir': NUCLEI_UPDATE, reset: NUCLEI_UPDATE,
  'env-vars': 'nuclei must not pass the runner environment into templates (-ev)',
};

/**
 * Nuclei (catalogue §3 MG5, §5): `nuclei …` read with v3.11.1's grammar (goflags: parsing stops at the first word
 * that isn't a flag). -duc (-disable-update-check) in effect, in the command and the fixed args; templates only from
 * the pinned archive (-t naming its directory only); none of NUCLEI_FORBIDDEN; no flag v3.11.1 doesn't have; and
 * only pipegen's two template env variables (nuclei reads PDCP_*, ENABLE_CLOUD_UPLOAD, GITHUB_TEMPLATE_REPO,
 * AWS_TEMPLATE_BUCKET and more from its env: internal/runner/options.go:458-502, runner.go:1129-1130).
 */
function nucleiProblems(e: Entry): Problem[] {
  const out: Problem[] = [];
  const bad = (message: string, ...path: (string | number)[]) => out.push({ message, path });
  const fx = e.fixedInputs;
  const command = e.step.cli?.command ?? [];
  if (basename(command[0] ?? '') !== 'nuclei') {
    bad('nuclei runs as `nuclei …` (the pinned binary)', 'step', 'cli', 'command');
    return out;
  }
  const p = parseArgv(command.slice(1), NUCLEI_GRAMMAR, 'goflags');
  const a = parseArgv(fx.args ?? [], NUCLEI_GRAMMAR, 'goflags');
  const reasons = new Set<string>();
  for (const f of [...p.flags, ...a.flags]) {
    const why = NUCLEI_FORBIDDEN[f.name];
    if (why !== undefined) reasons.add(why);
  }
  for (const why of reasons) bad(why, 'step', 'cli', 'command');
  if (p.errors.length > 0) bad(`nuclei: ${p.errors[0]} (pipegen reads the command with nuclei v3.11.1's flags and refuses any it doesn't know)`, 'step', 'cli', 'command');
  if (a.errors.length > 0) bad(`nuclei fixedInputs.args: ${a.errors[0]}`, 'fixedInputs', 'args');
  if (lastValue(p, 'disable-update-check') !== 'true' || lastValue(a, 'disable-update-check') !== 'true') {
    bad('nuclei must run with -duc (no update check) in effect, in the command and fixedInputs.args (not another flag\'s value, not after a target, never -duc=false)', 'step', 'cli', 'command');
  }
  const dirs = (x: typeof p) => x.flags.filter((f) => f.name === 'templates').flatMap((f) => f.value.split(','));
  const inCommand = dirs(p);
  if (!reasons.has(NUCLEI_TEMPLATES) && (inCommand.length === 0 || inCommand.some((d) => d !== NUCLEI_TEMPLATES_DIR) || !dirs(a).includes(NUCLEI_TEMPLATES_DIR))) {
    bad(NUCLEI_TEMPLATES, 'step', 'cli', 'command');
  }
  const allowedEnv = new Set([NUCLEI_TEMPLATES_URL_ENV, NUCLEI_TEMPLATES_SHA256_ENV]);
  for (const k of new Set([...Object.keys(e.step.cli?.env ?? {}), ...Object.keys(fx.env ?? {})])) {
    if (!allowedEnv.has(k)) bad(`nuclei gets only ${NUCLEI_TEMPLATES_URL_ENV} and ${NUCLEI_TEMPLATES_SHA256_ENV} in its env, not ${k} (nuclei reads PDCP_*, ENABLE_CLOUD_UPLOAD and template sources from it)`, 'step', 'cli', 'env');
  }
  const env = fx.env ?? {};
  if (!NUCLEI_TEMPLATES_URL_RE.test(env[NUCLEI_TEMPLATES_URL_ENV] ?? '')) {
    bad(`nuclei needs fixedInputs.env.${NUCLEI_TEMPLATES_URL_ENV}: an official projectdiscovery/nuclei-templates release tarball (a vX.Y.Z tag)`, 'fixedInputs', 'env');
  }
  if (!SHA256_RE.test(env[NUCLEI_TEMPLATES_SHA256_ENV] ?? '')) bad(`nuclei needs fixedInputs.env.${NUCLEI_TEMPLATES_SHA256_ENV}: the templates archive's sha256`, 'fixedInputs', 'env');
  // the allowlist last, so a more specific refusal (-duc swallowed, templates) is the one reported first
  out.push(...allowlistProblems('nuclei', [p, a], NUCLEI_ALLOWED_FLAGS, '-', (n) => NUCLEI_FORBIDDEN[n] !== undefined));
  const long = (k: string) => NUCLEI_GRAMMAR.shorts[k] ?? k;
  out.push(...choiceProblems('nuclei', e, (k) => (NUCLEI_GRAMMAR.value.has(long(k)) || NUCLEI_GRAMMAR.bool.has(long(k))) && NUCLEI_ALLOWED_FLAGS.has(long(k)),
    (k) => NUCLEI_FORBIDDEN[long(k)] ?? (['templates', 'disable-update-check'].includes(long(k)) ? `the AI may not choose nuclei's -${k}` : null)));
  return out;
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

/** A never-list hit: the key it matched, why, and the `owner/name` (or image name) read from the reference. */
export type NeverHit = { key: string; reason: string; ref: string };

/**
 * The never-list check (Plan P Task 5, fix round 1): whether a reference names a NEVER_REPOS repo → the hit; else
 * null. A reference is a repo (`owner/name`), a `uses:` value (any sub-path, `@ref`), an npm `@scope/name`, an image
 * (`[registry/]owner/name[:tag][@digest]`, `docker://…`) or a URL (`https://github.com/owner/name/…`,
 * raw.githubusercontent.com, api.github.com/repos/…). It is read the way the server would: NFKC-folded, lower case,
 * percent-decoded (a broken escape is refused), dot segments resolved. Refused:
 * - a listed `owner/name`, or any repo of a listed `owner/*`;
 * - a never-list name under any owner, or that name followed by `-…` (NEVER_NAMES), unless NEVER_NAME_ALLOW has it;
 * - look-alikes: a full name within Levenshtein distance 2 of a listed one, an owner within 2 of a listed `owner/*`,
 *   or a name of 10 or more characters within 2 of a never-list name;
 * - a repo named by its numeric id (api.github.com/repositories/<id>): pipegen can't tell which repo that is.
 */
export function neverListed(ref: unknown): NeverHit | null {
  const parts = refParts(ref);
  if (parts === null) return null;
  if (parts === 'bad-escape') return { key: '(unreadable)', reason: "it has a broken %-escape, so pipegen can't tell which repo it names", ref: String(ref).slice(0, 100) };
  if (parts === 'repo-id') return { key: '(repo by id)', reason: "it names a GitHub repo by its numeric id, so pipegen can't tell which repo it is", ref: String(ref).slice(0, 100) };
  const [owner, name] = parts;
  const full = name === undefined ? owner : `${owner}/${name}`;
  const found = (key: string) => ({ key, reason: NEVER_REPOS[key] as string, ref: full });
  if (name !== undefined && NEVER_REPOS[full] !== undefined) return found(full);
  if (NEVER_REPOS[`${owner}/*`] !== undefined) return found(`${owner}/*`);
  if (name !== undefined && !NEVER_NAME_ALLOW.has(full)) {
    for (const [family, key] of NEVER_NAMES) if (name === family || name.startsWith(`${family}-`)) return found(key);
  }
  for (const key of Object.keys(NEVER_REPOS)) {
    const [keyOwner, keyName] = key.split('/') as [string, string];
    if (keyName === '*' ? levenshtein(owner, keyOwner) <= 2 : name !== undefined && Math.abs(full.length - key.length) <= 2 && levenshtein(full, key) <= 2) return found(key);
  }
  if (name !== undefined && !NEVER_NAME_ALLOW.has(full)) {
    for (const [family, key] of NEVER_NAMES) if (family.length >= 10 && Math.abs(name.length - family.length) <= 2 && levenshtein(name, family) <= 2) return found(key);
  }
  return null;
}

/**
 * The image check (P11): whether an image reference's name (the last part of its path, any registry, any namespace)
 * is in NEVER_IMAGES → the hit; else null. `aquasec/tfsec-ci:latest`, `ghcr.io/aquasecurity/trivy@sha256:…` and
 * `docker://checkmarx/kics` are all refused.
 */
export function neverImage(ref: unknown): NeverHit | null {
  if (typeof ref !== 'string' || ref.length > 2048) return null;
  const s = decodeRef(ref);
  if (s === null) return { key: '(unreadable)', reason: "it has a broken %-escape, so pipegen can't tell which image it names", ref: ref.slice(0, 100) };
  const path = s.replace(/^docker:\/\//, '').replace(/@sha256:[0-9a-f]*$/, '');
  const last = (path.split('/').pop() ?? '').replace(/[:@].*$/, '');
  const reason = NEVER_IMAGES[last];
  return reason === undefined ? null : { key: last, reason, ref: path.slice(0, 100) };
}

/** NFKC-folded, trimmed, lower case and percent-decoded (until stable); null when an escape is broken. */
function decodeRef(ref: string): string | null {
  let s = lower(ref.normalize('NFKC').trim());
  for (let i = 0; i < 3 && s.includes('%'); i++) {
    try {
      const d = decodeURIComponent(s);
      if (d === s) break;
      s = lower(d.normalize('NFKC'));
    } catch {
      return null;
    }
  }
  return s;
}

/** Path segments with `.` and `..` resolved (a `..` above the start is dropped, as a URL resolver does) and empty ones removed. */
function resolveDots(segs: readonly string[]): string[] {
  const out: string[] = [];
  for (const s of segs) {
    if (s === '' || s === '.') continue;
    if (s === '..') out.pop();
    else out.push(s);
  }
  return out;
}

/** The `owner` and `name` a reference points at (see neverListed), lower case; null when there is no owner. */
function refParts(ref: unknown): [string, string | undefined] | 'bad-escape' | 'repo-id' | null {
  if (typeof ref !== 'string' || ref.length > 2048) return null;
  const decoded = decodeRef(ref);
  if (decoded === null) return 'bad-escape';
  const s = decoded.replace(/^docker:\/\//, '');
  let segs: string[];
  const url = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/?#]+)([^?#]*)/.exec(s);
  if (url !== null) {
    const host = (url[1] ?? '').replace(/:\d+$/, '');
    segs = resolveDots((url[2] ?? '').split('/'));
    if (host === 'api.github.com' && segs[0] === 'repositories') return 'repo-id';
    if (host === 'api.github.com' && segs[0] === 'repos') segs.shift();
    if (segs[0] === 'v2') segs.shift(); // a registry API path (ghcr.io/v2/owner/name/…)
  } else {
    segs = resolveDots(s.replace(/^git@[^:/]+:/, '').split('/'));
    // an image's registry host (docker.io, ghcr.io, quay.io, localhost:5000, …) or a URL host without its scheme
    if (segs.length > 2 && /[.:]|^localhost$/.test(segs[0] ?? '')) segs.shift();
    if (segs[0] === 'repos') segs.shift();
    if (segs[0] === 'repositories' && /^\d+$/.test(segs[1] ?? '')) return 'repo-id';
  }
  const owner = segs[0]?.replace(/^@/, '').replace(/[@:#?].*$/, ''); // an npm @scope is its owner
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
