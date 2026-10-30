// The referee (Plan B Task 7 Part 2, sub-task 7a: the static checks). pipegen's last line of defence: it reads the
// finished files pipegen is about to propose and refuses anything unsafe. It PARSES, it does not trust: it judges the
// files themselves, never what the renderer meant to write, and treats every file as hostile (Plan G may also edit a
// user's own workflow). Every check fails closed.
// - Parsing (ruling S29): one YAML document, unique keys, no anchors, aliases, `<<` merge keys, tags or directives, so no
//   key can hide from the walkers below. Job-level `uses:` (reusable workflows) and step-level `uses:` are both walked.
// - Run-time slot values (an image digest, a local URL, a repo path) are checked by shape only (slots.ts `slotProblem`): the
//   referee can not know which image or URL is the right one, so Plan G binds the values it writes (final review minor 15).
// - Pins: every `uses:` is a reviewed entry (the platform actions, the draft's tools, pipegen's own gate and watcher), the
//   central `<owner>/pipelines/` repo at a 40-character SHA. A local `./` action is refused outright (fix round 2). The
//   comparison uses the whole `uses` path, sub-path included (S14). A tag or branch is `unpinned`; any other commit is `unknown-pin`.
// - Only reviewed tools, only as their template: an action step must carry exactly its entry's fixed inputs, its choices
//   inside their lists, and otherwise only RENDERER_INPUTS, each judged by its own checker and `whenWith` (S15). A run step
//   must BE a step the renderer makes for this draft (the draft's tools and the project scripts its needs call for): it is
//   recognised by content, never by its id. Anything else is `unreviewed` (or `template` when it reuses a rendered id).
// - Expressions: the renderer's own checkExpressions judges every step (one source of truth). Secrets (S9) only as
//   `${{ secrets.X }}` under the name X, X in the allowed set, and a declared app secret only on a step that runs the app.
// - Permissions (S17): `permissions: {}` at the top, and every job within JOB_PERMISSIONS by its exact id.
// - Caches: `cache-mode: none` on every job with steps; no actions/cache, no cache inputs; trivy only with its pinned
//   in-memory cache config (S3).
// - Order (S6 c): the renderer's own checkJobOrder runs over every parsed job; a run step not recognised by content counts
//   as repo code whatever its id says.
// - The gate's wiring (Plan C C0b): job `outputs` only in the forms of jobOutputsProblems (job-rules.ts); the gate step in mode gate only in
//   the job `gate`, with its `with` equal to gateStepInputs(draft) (the `job-list` literal = gateJobList(draft), every other input from the draft too;
//   final review fix round A) and `needs` covering every listed job (else `not-gate-readable`);
//   each scrub step equal to its scan step (tool, format, id; job-rules.ts scrubChainProblems); a checkout `ref` only in `base-scan`.
// - The gate's check name comes from GATE_CHECK_NAME; the blocking rule (B7) demotes a findings check whose tool writes no
//   SARIF; findSecretLike runs over every file (S18). The workflow linters (actionlint, zizmor) run through `deps.runLinters`
//   (default: linters.ts runLinters, 7b), which tests replace with a stub.
import { isDeepStrictEqual } from 'node:util';
import { isAlias, isMap, isScalar, isSeq, LineCounter, parseAllDocuments, visit, type Document, type Node as YamlNode, type Pair } from 'yaml';
import { findSecretLike } from '../ai/redact.js';
import { safeText } from '../util/safe-text.js';
import { GATE_CHECK_NAME, type CreatedFile, type OutputFormat, type PipegenInserted, type PipelineDraft, type ReviewedTool, type StepSpec } from '../types.js';
import { ArtifactNameError, slug } from './artifact-names.js';
import { FINDINGS_CATEGORIES, gateJobList, GateJobListError, jobIdFor, PIPEGEN_JOB_CATEGORIES, readableFormat, type JobListEntry } from './gate-job-list.js';
import { GATE_JSON_INPUTS, gateStepInputs, NIGHTLY_JSON_INPUTS, nightlyStepInputs } from './gate-inputs.js';
import { runLinters } from './linters.js';
import { COMMIT_SHA_RE } from './names.js';
import { NEED_ID_CATEGORY, toolCoversNeed } from './need-ids.js';
import { PLATFORM_ACTION_IDS, type PlatformActions } from './pin.js';
import { APP_RUNNING_CATEGORIES, TRIVY_LAUNCH_RE } from './render-cli.js';
import { EXPR, own, show } from './render-error.js';
import { ACTION_PATH_RE, checkExpressions, createdPathProblem, checkJobOrder, gateResultUploadProblems, IF_VALUES, isDangerousName, isReviewed, isScrubStep, isStageStep, jobOutputsProblems, SECRET_REF_RE, STEP_KEYS as STEP_KEY_LIST, WORKFLOW_PATH_RE, type RenderedStep, type ScanFact } from './job-rules.js';
import { containerRefusal, RenderError, renderProjectScript, renderStep, sameDedupeContent, type RenderContext } from './render-step.js';
import { centralWorkflowPath } from './central-path.js';
import { projectScriptFor } from './reviewed.js';
import { slotProblem, type SlotKind } from './slots.js';
import { ARGV_POLICIES, CACHE_LOCKS, GATE_OPTIONAL_UPLOADS, PLAIN_REL_RE, PLATFORM_USES, RENDERER_INPUTS, rendererInputProblems, SCRUB_SECRET, uploadIfNoFiles } from './tool-flags.js';

// ---------- the report ----------

/** What a check found. `'quality-bar'` is gone (F10): no static rule produces it. */
export type RefereeCheck = 'unpinned' | 'unknown-pin' | 'unreviewed' | 'permissions' | 'injection' | 'not-gate-readable' | 'cache' | 'template' | 'actionlint' | 'zizmor' | 'secret-value';
/**
 * `line` (1-based) when the finding has one (the linters, 7b): in an edited user workflow it decides between an issue and a
 * note. `repo`: which repository's file it is (7b knows it, one temp copy per repo); a finding is matched to its file by repo
 * and path, and one that can not be matched to exactly one file stays an issue.
 */
export interface RefereeIssue { file: string; check: RefereeCheck; message: string; line?: number; repo?: CreatedFile['repo'] }
/**
 * `ok` = no issue. `demoted`: the needs whose blocking was turned off (B7), by need key (`<needId>`, or
 * `<needId>--<service slug>` for a per-service need, as in the result artifact name), each with a note. `notes`: what the
 * caller should tell the user but that blocks nothing (demotions, steps that could not be rendered, linter findings on
 * a user's own lines).
 */
export interface RefereeReport { ok: boolean; issues: RefereeIssue[]; demoted: string[]; notes: string[] }

/** The pinned linters, as re-verifying closures (ruling S20): each call checks the binary's hash again right before it runs. */
export interface Linters { actionlint: () => Promise<string>; zizmor: () => Promise<string> }
/** The linter run (7b's runLinters): actionlint and zizmor over the workflow files, findings as issues. */
export type RunLinters = (files: CreatedFile[], linters: Linters, ghToken: string | null) => Promise<RefereeIssue[]>;
/** The injectable parts. `runLinters` defaults to the real one (linters.ts); a throwing runner is an issue. */
export interface RefereeDeps { runLinters?: RunLinters }

// ---------- the tables ----------

type Level = 'read' | 'write';
/**
 * The permissions a job may have beyond `contents: read`, by its EXACT job id (ruling S17). Every other job may have
 * `contents: read` only. Plan G names its jobs with these ids; a reusable-workflow caller may also have the union of the
 * called file's jobs (when that file is in `files`).
 */
export const JOB_PERMISSIONS: Readonly<Record<string, Readonly<Record<string, Level>>>> = Object.freeze({
  'pr-check': { 'pull-requests': 'read' },
  'pipegen-verify': { actions: 'read', packages: 'read', attestations: 'read' },
  'code-scanning': { 'security-events': 'write', actions: 'read' },
  gate: { actions: 'read', 'pull-requests': 'read' },
  'base-scan': { actions: 'read' },
  'baseline-check': { actions: 'read' },
  'image-publish': { packages: 'write' },
  sign: { 'id-token': 'write', packages: 'write', attestations: 'write' },
  nightly: { actions: 'read', issues: 'write' },
  watch: { issues: 'write', actions: 'read' },
  notify: { 'pull-requests': 'read', checks: 'read' },
  'merged-red': { 'pull-requests': 'read', checks: 'read' },
});
/** The environment `pipegen-verify` runs in when the plan has environments (design §19): only default-branch deploys pass. */
export const SIGNING_ENVIRONMENT = 'pipegen-signing';
/** pipegen's own secrets (gate fingerprint key, cosign key, Slack webhook) and the workflow token: allowed besides the draft's declared ones (S9). */
export const PIPEGEN_SECRETS: readonly string[] = ['PIPEGEN_FP_KEY', 'PIPEGEN_COSIGN_KEY', 'PIPEGEN_SLACK_WEBHOOK', 'GITHUB_TOKEN'];
/** Ruling B7: the checks the gate judges by their findings; their tool must write SARIF (DAST: ZAP's JSON too). Every other category is judged by job status. */
export { FINDINGS_CATEGORIES };   // defined in gate-job-list.ts (the job list needs the same set)

/**
 * What a step is, recognised by its content (the reviewed entry its `uses` and template match, or the rendered step its
 * run text equals), never by its id alone. `repo-code`: a step that runs or loads the repository's code (tests, project
 * scripts, the repo's npm ci); `central`: an action from the central pipelines repo; `unrecognised`: anything else.
 */
export type StepKind = 'checkout' | 'setup' | 'harden' | 'upload-artifact' | 'download-artifact' | 'upload-sarif' | 'attest' | 'docker-login' | 'setup-buildx' | 'build-push'
  | 'gate' | 'watcher' | 'tool' | 'scrub' | 'stage' | 'central' | 'repo-code' | 'unrecognised';
/** pipegen's own actions by reviewed-entry id (Plan C adds the gate entry, Plan H the watcher entry, under these ids). */
export const PIPEGEN_ACTION_IDS = { gate: 'pipegen-gate', watcher: 'pipegen-watcher' } as const;
/** The step kind of each reviewed action entry that is not an ordinary tool, by entry id. The gate entry is kind `gate`, except a recognised scrub step of it (isScrubStep: judgeUses). */
const ENTRY_KIND: Readonly<Record<string, StepKind>> = Object.freeze({
  ...Object.fromEntries(Object.entries({ checkout: 'checkout', 'setup-node': 'setup', 'setup-python': 'setup', 'upload-artifact': 'upload-artifact', 'download-artifact': 'download-artifact',
    'upload-sarif': 'upload-sarif', attest: 'attest', 'docker-login': 'docker-login', 'setup-buildx': 'setup-buildx', 'build-push': 'build-push' } satisfies Record<keyof PlatformActions, StepKind>)
    .map(([k, kind]) => [PLATFORM_ACTION_IDS[k as keyof PlatformActions], kind])),
  bullfrog: 'harden', [PIPEGEN_ACTION_IDS.gate]: 'gate', [PIPEGEN_ACTION_IDS.watcher]: 'watcher',
});
/**
 * The steps each job of the permission table may hold (7a fix round 1, ruling 1), by step kind. A job with power (any
 * permission beyond `contents: read`, an `environment:`, or a secret other than the declared app secrets) runs only what
 * that power is for: no repo-code step and no unrecognised step, ever. A privileged job whose id is not here is refused.
 * pipegen's own gate and watcher actions are allowed only in the rows that list them.
 * DOCUMENTED RESIDUAL: `image-publish` builds the repository's Dockerfile with the reviewed build-push step. That build is
 * the repo's code running with `packages: write`; it is allowed there and nowhere else, because publishing the image is the
 * job's purpose (the image is then signed and verified by digest).
 */
export const JOB_STEP_POLICY: Readonly<Record<string, readonly StepKind[]>> = Object.freeze({
  'pr-check': ['harden', 'checkout'],
  'pipegen-verify': ['harden', 'checkout', 'download-artifact', 'gate'],
  'code-scanning': ['harden', 'download-artifact', 'upload-sarif'],
  // no checkout: the gate never reads the workspace (Plan C ruling S21); it reads the event, the job outputs and the API
  // C5b: the gate's own uploads (result, baseline, clean-run marker) after the gate step, and no other upload (checkJobOrder, gateUploadProblems)
  gate: ['harden', 'download-artifact', 'gate', 'upload-artifact'],
  'base-scan': ['harden', 'checkout', 'setup', 'stage', 'tool', 'scrub', 'upload-artifact'],
  // no checkout: this job holds PIPEGEN_FP_KEY and reads only the API and artifacts (C3 review m9, like the gate job's S21)
  'baseline-check': ['harden', 'download-artifact', 'gate'],
  'image-publish': ['harden', 'checkout', 'setup-buildx', 'docker-login', 'build-push'],
  sign: ['harden', 'checkout', 'download-artifact', 'docker-login', 'attest'],
  // no checkout: the nightly job holds PIPEGEN_FP_KEY (it verifies the baseline) and reads only the API; the identity comes from GITHUB_REPOSITORY (C7 fix round 1)
  nightly: ['harden', 'download-artifact', 'gate'],
  watch: ['harden', 'checkout', 'watcher'],
  notify: ['harden', 'download-artifact'],
  'merged-red': ['harden', 'download-artifact'],
});
/** The only jobs that may run in the signing environment (its secrets sign and verify). */
const SIGNING_JOBS: ReadonlySet<string> = new Set(['sign', 'pipegen-verify']);
/** The triggers pipegen writes (ruling 7): `pull_request_target`, `workflow_run` and the rest are never in a file pipegen writes whole. */
const TRIGGERS: ReadonlySet<string> = new Set(['push', 'pull_request', 'merge_group', 'schedule', 'workflow_dispatch', 'workflow_call']);
/**
 * GitHub-hosted runner labels, as a plain string (ruling 6). A self-hosted runner keeps state between runs, which breaks the
 * no-cache rule (spec §19); self-hosted support would be a future, explicit opt-in.
 */
const HOSTED_RUNNERS: ReadonlySet<string> = new Set(['ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-24.04-arm', 'ubuntu-22.04-arm']);
/** GitHub's owner name rule (the same pattern as src/github/client.ts), checked again here: the central prefix is built from it. */
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
/**
 * Any status-function call (success(), always(), failure(), cancelled()): GitHub adds its implicit `success() && (…)` only when
 * an if holds none. Over-approximated on purpose (review-7a-r2): no \b, so `x-success(` matches; a name inside a string literal
 * matches too (refusing it is only stricter, and a quote stripper that lexes differently from GitHub's could hide a real call).
 * Non-ASCII is refused before this runs, so JS \s covers every whitespace GitHub's lexer skips.
 */
const STATUS_CALL_RE = /(?:success|always|failure|cancelled)\s*\(/i;

/** Parentheses never below zero and back to zero at the end, and every single-quoted string closed ('' is an escape). */
function balanced(e: string): boolean {
  let depth = 0;
  for (let i = 0; i < e.length; i++) {
    const c = e[i];
    if (c === "'") {
      let closed = false;
      for (i++; i < e.length; i++) if (e[i] === "'") { if (e[i + 1] === "'") i++; else { closed = true; break; } }
      if (!closed) return false;
    } else if (c === '(') depth++;
    else if (c === ')' && --depth < 0) return false;
  }
  return depth === 0;
}

/** Whether an expression holds `||` outside parentheses and quoted strings. */
function topLevelOr(e: string): boolean {
  let depth = 0;
  for (let i = 0; i < e.length; i++) {
    const c = e[i];
    if (c === "'") {
      for (i++; i < e.length; i++) if (e[i] === "'") { if (e[i + 1] === "'") i++; else break; }
    } else if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === '|' && e[i + 1] === '|' && depth === 0) return true;
  }
  return false;
}

/**
 * Ruling 1 (fix round 2), loosened after review-7a-r2: the `if:` of a user job pipegen gated with `needs:` may be absent, an
 * expression with no status-function call at all (GitHub runs it as `success() && (…)`, so it still respects the needs),
 * exactly `success()`, or `success() && <expr>` where <expr> holds no status call and no `||` at its top level. Anything else
 * can run the job although pipegen's job failed (`success() || …`, `!success()`, `always()`, `!cancelled()`).
 * Refused first: non-ASCII (U+0085 is whitespace to GitHub's .NET lexer but not to JS \s; U+017F folds to 'S' in .NET only),
 * more than one `${{ }}` or text outside it, whitespace included (read by GitHub as a truthy string; a value with no `${{` may be trimmed), any `{` or `}` left after the unwrap (GitHub
 * ends the expression at the first `}}`, so `${{ x }}}` is a truthy string template; expressions have no brace syntax, so braces
 * inside string literals are refused too, which is only stricter), an empty condition, and unbalanced
 * parentheses or quotes (GitHub refuses the workflow; the referee says so itself). A YAML boolean is not a string: refused.
 */
export function gatedIfAllowed(cond: unknown): boolean {
  if (cond === undefined) return true;
  if (typeof cond !== 'string' || !/^[\t\n\r\x20-\x7e]*$/.test(cond)) return false;
  let e = cond;
  if (cond.includes(EXPR)) {
    // the wrapper is judged on the untrimmed value: whitespace outside it is literal text, which GitHub reads as a (truthy) string template
    const wrapped = /^\$\{\{([\s\S]*)\}\}$/.exec(cond);
    if (wrapped === null) return false;
    e = (wrapped[1] as string).trim();
  } else e = cond.trim();
  if (e === '' || e.includes(EXPR) || /[{}]/.test(e) || !balanced(e)) return false;
  if (!STATUS_CALL_RE.test(e)) return true;
  if (/^success\(\s*\)$/i.test(e)) return true;
  const m = /^success\(\s*\)\s*&&([\s\S]+)$/i.exec(e);
  if (m === null) return false;
  const rest = m[1] as string;
  return rest.trim() !== '' && !STATUS_CALL_RE.test(rest) && !topLevelOr(rest);
}

const LEVEL: Readonly<Record<string, number>> = { none: 0, read: 1, write: 2 };
const JOB_ID_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,99}$/;
const STEP_KEYS: ReadonlySet<string> = new Set(STEP_KEY_LIST);
const TOP_KEYS: ReadonlySet<string> = new Set(['name', 'run-name', 'on', 'permissions', 'env', 'concurrency', 'jobs']);
const STEPS_JOB_KEYS: ReadonlySet<string> = new Set(['name', 'runs-on', 'needs', 'if', 'permissions', 'environment', 'concurrency', 'outputs', 'env', 'steps', 'timeout-minutes', 'services', 'cache-mode']);
const CALLER_JOB_KEYS: ReadonlySet<string> = new Set(['name', 'uses', 'with', 'secrets', 'needs', 'if', 'permissions']);
const ACTION_KEYS: ReadonlySet<string> = new Set(['name', 'description', 'author', 'inputs', 'outputs', 'runs', 'branding']);
const CACHE_INPUT_RE = /(?:^|[-_])cache(?:$|[-_])/i;
/** Any `secrets.X` reference inside an expression, however it is spaced. */
const SECRET_USE_RE = /\$\{\{[^}]*?\bsecrets\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/g;
const TRIVY_CONFIG = ARGV_POLICIES['trivy-config']?.config;

/** Sentinel targets the referee renders with: two sets, so the env values that differ are the run-time slots (B6). */
const SENTINELS = [
  { image: `ghcr.io/pipegen-referee/a@sha256:${'a'.repeat(64)}`, url: 'http://localhost:1', k8sDir: 'pipegen-referee-a' },
  { image: `ghcr.io/pipegen-referee/b@sha256:${'b'.repeat(64)}`, url: 'http://localhost:2', k8sDir: 'pipegen-referee-b' },
] as const;

type Add = (file: string, check: RefereeCheck, message: string, line?: number, repo?: CreatedFile['repo']) => void;
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const hasExpr = (v: unknown): boolean => (typeof v === 'string' ? v.includes(EXPR) : Array.isArray(v) ? v.some(hasExpr) : isObj(v) ? Object.entries(v).some(([k, x]) => k.includes(EXPR) || hasExpr(x)) : false);
const uniq = <T>(xs: Iterable<T>): T[] => [...new Set(xs)];

// ---------- parsing (S29) ----------

/** `scalars`: every string key and value as parsed (escapes decoded), for the secret-value check (S18). */
interface Parsed { doc: Document; js: Obj; lines: LineCounter; scalars: string[] }

/**
 * One YAML document as a map, or the problems that make pipegen refuse it. `strict` (a file pipegen wrote whole): no
 * anchor or alias at all. `user` (a user's own workflow pipegen edited): the user's anchors are theirs, so they resolve
 * (bounded); the parts pipegen inserted are checked for them separately. Both refuse `<<` merge keys, tags, directives,
 * duplicate keys, a key that is not text, more than one document and anything that is not a map.
 */
function parseYaml(text: string, mode: 'strict' | 'user'): { parsed: Parsed } | { problems: string[] } {
  const lines = new LineCounter();
  const problems: string[] = [];
  let docs: Document[];
  try {
    docs = parseAllDocuments(text, { uniqueKeys: true, lineCounter: lines, prettyErrors: false }) as unknown as Document[];
  } catch {
    return { problems: ['it is not YAML pipegen can read'] };
  }
  if (docs.length !== 1) return { problems: [`it holds ${docs.length} YAML documents; a workflow is exactly one`] };
  const doc = docs[0] as Document;
  for (const e of doc.errors) problems.push(e.code === 'DUPLICATE_KEY' ? 'a key is set twice (a later one could hide the first from a reader)' : `it is not valid YAML (${safeText(e.code, 40)})`);
  if (doc.warnings.length > 0) problems.push(`the YAML parser warns about it (${safeText(doc.warnings[0]?.code ?? '', 40)})`);
  const directives = doc.directives;
  if (directives?.yaml.explicit === true || Object.keys(directives?.tags ?? {}).some((h) => h !== '!!' && h !== '!')) problems.push('it has a YAML directive (%YAML or %TAG), which changes how values are read');
  const scalars: string[] = [];
  visit(doc, {
    Alias() { if (mode === 'strict') problems.push('it uses a YAML alias (*name), which can copy a key past a reader'); },
    // the S18 values are collected here, not in a Scalar visitor: one would replace this one for scalars, and their tags and
    // anchors would go unchecked (review-7a-r1 finding 2)
    Node(_, n) {
      if (isScalar(n) && typeof n.value === 'string') scalars.push(n.value);
      if (n.tag !== undefined) problems.push('it has a YAML tag (!!type), which changes what a value is');
      if (mode === 'strict' && n.anchor !== undefined) problems.push('it defines a YAML anchor (&name)');
    },
    Pair(_, p) {
      if (!isScalar(p.key) || typeof p.key.value !== 'string') problems.push('a key is not plain text');
      else if (p.key.value === '<<') problems.push('it has a << merge key, which can bring in keys a reader does not see');
    },
  });
  if (problems.length > 0) return { problems: uniq(problems) };
  let js: unknown;
  try {
    js = doc.toJS({ maxAliasCount: mode === 'strict' ? 0 : 100 });
  } catch {
    return { problems: ['its aliases can not be resolved within the limit'] };
  }
  if (!isObj(js)) return { problems: ['it is not a map of keys'] };
  return { parsed: { doc, js, lines, scalars } };
}

/** The lines (1-based) a node covers, from its first character to the end of its value. */
function linesOf(lc: LineCounter, from: number, to: number, into: Set<number>): void {
  const a = lc.linePos(from).line;
  const b = lc.linePos(Math.max(from, to - 1)).line;
  for (let l = a; l <= b; l++) into.add(l);
}

function jobPair(doc: Document, id: string): Pair<YamlNode, YamlNode> | undefined {
  const jobs = doc.get('jobs', true);
  if (!isMap(jobs)) return undefined;
  return jobs.items.find((p) => isScalar(p.key) && p.key.value === id) as Pair<YamlNode, YamlNode> | undefined;
}

/**
 * The lines of an edited user workflow on which a linter finding is an issue, for 7b and the referee: the jobs pipegen
 * added, the `needs:` of the user's jobs it touched and those jobs' `if:`, and the user's top-level `on`, `env`,
 * `defaults` and `permissions`, which apply to pipegen's jobs too (7a fix round 1, ruling 5). A finding elsewhere is on the
 * user's own lines (a note). Null for a file pipegen wrote whole (every line is judged) or one that can not be read
 * (judged whole too: fail closed).
 */
export function pipegenLines(file: CreatedFile): ReadonlySet<number> | null {
  const mark = file.inserted;
  if (mark === undefined) return null;
  const r = parseYaml(file.content, 'user');
  if (!('parsed' in r)) return null;
  const { doc, lines } = r.parsed;
  const out = new Set<number>();
  for (const id of mark.jobs) {
    const p = jobPair(doc, id);
    if (p?.key?.range && p.value?.range) linesOf(lines, p.key.range[0], p.value.range[1], out);
  }
  for (const n of mark.needs) {
    const p = jobPair(doc, n.job);
    for (const key of ['needs', 'if']) {
      const q = isMap(p?.value) ? (p.value.items.find((x) => isScalar(x.key) && x.key.value === key) as Pair<YamlNode, YamlNode> | undefined) : undefined;
      if (q?.key?.range && q.value?.range) linesOf(lines, q.key.range[0], q.value.range[1], out);
    }
  }
  if (isMap(doc.contents)) {
    for (const q of doc.contents.items as Pair<YamlNode, YamlNode>[]) {
      if (isScalar(q.key) && ['on', 'env', 'defaults', 'permissions'].includes(String(q.key.value)) && q.key.range && q.value?.range) linesOf(lines, q.key.range[0], q.value.range[1], out);
    }
  }
  return out;
}

// ---------- what the renderer makes for this draft ----------

interface Expected {
  step: RenderedStep;
  /** env keys whose values are run-time slots, with their kind (judged by slots.ts, not by equality) */
  slots: Map<string, SlotKind>;
  source: string; appRunning: boolean; blocking: boolean;
  /** the last run step of its spec: the tool's own run (before it come installs and checks); only this one makes the spec "present" (R2) */
  final: boolean;
  /** the tool reads the checked-out workspace (every scanner but the image and URL ones): its job needs the locked checkout first */
  readsWorkspace: boolean;
  /** the job id of the check this step is for (jobIdFor of its need and service), and the job it must run in: that same id, or `base-scan` for the base twin (C0b fix round 1, ruling 3) */
  need?: string; owner?: string;
}

/** A judged job, kept for the checks that need every file judged first (the gate's binding to the jobs it lists). */
interface JobRecord { file: string; id: string; judged: readonly Judged[]; outputs: unknown }
/** The key of a workflow file in every map of the referee. */
const fileKey = (f: CreatedFile): string => `${f.repo}:${f.path}`;

interface Expectations {
  runs: Expected[];
  runIds: Set<string>;
  /** `owner/repo[/path]@sha` (path lower case) → its reviewed action entry */
  actions: Map<string, ReviewedTool>;
  actionPaths: Set<string>;
  /** `<image>@sha256:<digest>` of the reviewed docker entries */
  images: Set<string>;
  declared: Set<string>;
  allowed: Set<string>;
  /** the sources (`spec:<i>`) of the cli specs that rendered, and those of them a parsed file holds a step of (the blocking rule, finding 3) */
  rendered: Set<string>;
  matched: Set<string>;
  /** source → the pins each of its `pipegen-npm-ci-…` steps carries */
  npmPins: Map<string, Map<string, string[]>>;
  byId: Map<string, ReviewedTool>;
  /** checks that need every file judged first (the gate's job list), run once after the last file */
  deferred: (() => void)[];
  /** every steps job judged, in every file */
  jobs: JobRecord[];
}

const coreOf = (s: RenderedStep): Obj => ({ id: s.id, uses: s.uses, with: s.with, run: s.run, shell: s.shell, env: s.env, 'working-directory': s['working-directory'] });
const usesKey = (uses: string): { path: string; ref: string } | null => {
  const at = uses.lastIndexOf('@');
  return at <= 0 ? null : { path: uses.slice(0, at).toLowerCase(), ref: uses.slice(at + 1) };
};
const sameCandidate = (a: ReviewedTool['candidate'], b: ReviewedTool['candidate']): boolean =>
  a.id === b.id && a.kind === b.kind && a.repo === b.repo && a.version === b.version && isDeepStrictEqual(a.pin, b.pin);
const pinLines = (json: string | undefined): string[] | null => {
  try {
    const list: unknown = JSON.parse(json ?? '[]');
    return Array.isArray(list) ? list.map((p) => JSON.stringify(p)) : null;
  } catch {
    return null;
  }
};

function slotKindOf(value: string, a: (typeof SENTINELS)[number]): SlotKind | undefined {
  if (value === a.image) return 'image-digest';
  if (value === a.url) return 'local-url';
  if (value === a.k8sDir) return 'repo-path';
  return undefined;
}

/**
 * Whether a cli tool reads the checked-out workspace: every one does, except those whose only run-time values are an image
 * or a URL (trivy-image, syft, nuclei) and a docker tool that mounts only a fresh work folder (zap). Unknown: it does.
 */
function readsWorkspace(entryId: string): boolean {
  const pol = own(ARGV_POLICIES, entryId);
  if (pol === undefined) return true;
  if (pol.method === 'docker' && pol.mount?.source === 'work') return false;
  const kinds = Object.values(pol.slots ?? {});
  return !(kinds.length > 0 && kinds.every((k) => k === 'image-digest' || k === 'local-url'));
}

/** The job id of a check (the gate's job list key), or undefined for a name that cannot make one. */
function keyOf(needId: string, service: string | undefined): string | undefined {
  try { return jobIdFor(needId, service); } catch (e) { if (e instanceof GateJobListError) return undefined; throw e; }
}

function expectations(draft: PipelineDraft, platform: PlatformActions, reviewed: readonly ReviewedTool[], add: Add, notes: string[]): Expectations {
  const byId = new Map(reviewed.map((t) => [t.id, t]));
  const actions = new Map<string, ReviewedTool>();
  const images = new Set<string>();
  for (const t of [...reviewed, ...Object.values(platform)]) {
    if (!isReviewed(t?.candidate)) continue;
    const uses = t.step.action?.uses;
    if (t.candidate.kind === 'action' && uses !== undefined) {
      const k = usesKey(uses);
      if (k !== null && k.ref === t.candidate.pin.sha) actions.set(`${k.path}@${k.ref}`, t);
    }
    const install = t.step.cli?.install;
    if (install?.method === 'docker' && t.candidate.pin.digest !== undefined) images.add(`${install.package}@${t.candidate.pin.digest}`);
  }
  const ex: Expectations = {
    runs: [], runIds: new Set(), actions, actionPaths: new Set([...actions.keys()].map((k) => k.slice(0, k.lastIndexOf('@')))), images,
    declared: new Set(), allowed: new Set(PIPEGEN_SECRETS), rendered: new Set(), matched: new Set(), npmPins: new Map(), byId, deferred: [], jobs: [],
  };
  const ctxs: RenderContext[] = SENTINELS.map((t) => ({ profile: draft.profile, targets: { ...t } }));
  const needOf = (needId: string, service: string | undefined) => draft.needs.find((n) => n.id === needId && n.service === service);
  const record = (source: string, results: RenderedStep[][], appRunning: boolean, blocking: boolean, readsWorkspace: boolean, need: string | undefined, owner: string | undefined): void => {
    const [a, b] = results as [RenderedStep[], RenderedStep[]];
    const pins = new Map<string, string[]>();
    const lastRun = a.map((s) => s.run !== undefined).lastIndexOf(true);
    a.forEach((s, i) => {
      if (s.id?.startsWith('pipegen-npm-ci-') === true) pins.set(s.id, pinLines(s.env?.PIPEGEN_NPM_EXPECT) ?? []);
      if (s.run === undefined) return;
      const other = b[i];
      const slots = new Map<string, SlotKind>();
      for (const [k, v] of Object.entries(s.env ?? {})) {
        if (other?.env?.[k] === v) continue;
        const kind = slotKindOf(v, SENTINELS[0]);
        if (kind !== undefined) slots.set(k, kind);
      }
      ex.runs.push({ step: s, slots, source, appRunning, blocking, readsWorkspace, final: i === lastRun, ...(need === undefined ? {} : { need }), ...(owner === undefined ? {} : { owner }) });
      if (s.id !== undefined) ex.runIds.add(s.id);
    });
    ex.npmPins.set(source, pins);
  };

  draft.steps.forEach((spec: StepSpec, i) => {
    const t = isObj(spec) && isObj(spec.tool) && typeof spec.tool.id === 'string' ? byId.get(spec.tool.id) : undefined;
    if (t === undefined || !isReviewed(spec.tool) || !isReviewed(t.candidate) || !sameCandidate(spec.tool, t.candidate)) {
      add(`draft.steps[${i}]`, 'unreviewed', `The step for ${show(spec?.needId)} runs ${show(spec?.tool?.id)}, which is not an entry of the reviewed list at its reviewed pin; pipegen never runs it, not even as a non-blocking job (it belongs in the suggestions).`);
      return;
    }
    if (!toolCoversNeed(t.categories, spec.needId)) {
      add(`draft.steps[${i}]`, 'unreviewed', `The step for ${show(spec.needId)} runs ${show(t.id)}, which does not cover the check ${show(spec.needId)} (its categories are ${t.categories.map((c) => show(c)).join(', ')}); a tool of another kind would leave the check undone, so it is not run.`);
      return;
    }
    if (t.candidate.kind === 'action') {   // actions are judged by their template (judgeAction), not by a re-render
      for (const n of spec.secrets ?? []) ex.declared.add(n);
      return;
    }
    const appRunning = t.categories.some((c) => APP_RUNNING_CATEGORIES.has(c));
    try {
      const blocking = needOf(spec.needId, spec.service)?.blocking ?? true;
      const need = keyOf(spec.needId, spec.service);
      record(`spec:${i}`, ctxs.map((c) => renderStep(spec, t, platform, c).steps), appRunning, blocking, readsWorkspace(t.id), need, need);
      // the target-branch variant (the base-scan job): the same spec, rendered into the base artifact folder
      record(`spec:${i}:base`, ctxs.map((c) => renderStep(spec, t, platform, { ...c, base: true }).steps), appRunning, blocking, readsWorkspace(t.id), need, 'base-scan');
      ex.rendered.add(`spec:${i}`);
      // only a spec that rendered declares its secrets (one that did not names no step, so nothing may carry them)
      for (const n of spec.secrets ?? []) ex.declared.add(n);
    } catch (e) {
      if (!(e instanceof RenderError)) throw e;
      notes.push(`The step for ${show(spec.needId)} (${t.id}) can not be rendered, so no step may claim to be it: ${safeText(e.message, 200)}`);
    }
  });
  for (const v of ex.declared) ex.allowed.add(v);
  // the project's own scripts its needs call for (ruling S10): the only other run steps pipegen makes
  for (const need of draft.needs) {
    for (const s of draft.profile.services) {
      const ps = projectScriptFor(need, s);
      if (ps === null) continue;
      try {
        const key = keyOf(need.id, need.service);
        record(`script:${need.id}:${s.name}`, ctxs.map((c) => renderProjectScript(ps, platform, c).steps), false, need.blocking, true, key, key);
      } catch (e) {
        if (!(e instanceof RenderError)) throw e;
      }
    }
  }
  return ex;
}

// ---------- judging one file ----------

interface FileCtx {
  file: CreatedFile; add: Add; ex: Expectations; draft: PipelineDraft;
  /** every parsed workflow and action file, by `<repo>:<path>` */
  others: Map<string, Parsed>;
}

const issueFor = (fc: FileCtx) => (check: RefereeCheck, message: string): void => fc.add(fc.file.path, check, message);

/** The event names of an `on:` value (a name, a list of names, or a map by name); null when it is none of those. */
function triggersOf(on: unknown): string[] | null {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.every((x) => typeof x === 'string') ? (on as string[]) : null;
  if (isObj(on)) return Object.keys(on);
  return null;
}

/**
 * The central `<owner>/pipelines/` prefix and the one commit pipegen recorded for it (ruling 2), or null: the owner must
 * pass GitHub's owner rule again here (an empty or odd owner never makes a prefix), and `draft.centralPin` must name that
 * repo at a 40-character commit. Without it every central `uses` is unknown-pin.
 */
function centralOf(draft: PipelineDraft): { prefix: string; sha: string; repo: string } | null {
  const owner = draft.profile.owner;
  const pin = draft.centralPin;
  if (typeof owner !== 'string' || !OWNER_RE.test(owner) || pin === undefined || !isObj(pin)) return null;
  if (typeof pin.repo !== 'string' || pin.repo.toLowerCase() !== `${owner.toLowerCase()}/pipelines` || typeof pin.sha !== 'string' || !COMMIT_SHA_RE.test(pin.sha)) return null;
  return { prefix: `${owner.toLowerCase()}/pipelines/`, sha: pin.sha, repo: pin.repo };
}
/** A `uses` path that looks like any owner's central pipelines repo. */
const CENTRAL_LIKE_RE = /^[^/]*\/pipelines\//;

/** The workflow's own top level (a file pipegen wrote whole). */
function judgeTop(fc: FileCtx, js: Obj): void {
  const bad = issueFor(fc);
  for (const k of Object.keys(js)) if (!TOP_KEYS.has(k)) bad('template', `The top-level key ${show(k)} is not one pipegen writes (defaults, for one, would change every run step).`);
  const p = js.permissions;
  if (!isObj(p) || Object.keys(p).length > 0) bad('permissions', 'The workflow must start from `permissions: {}`, so a job gets only what it declares.');
  for (const k of ['name', 'run-name', 'concurrency']) if (hasExpr(js[k])) bad('injection', `The workflow's ${k} holds an expression (\${{), which pipegen never writes there.`);
  const triggers = triggersOf(js.on);
  if (triggers === null || triggers.length === 0) bad('template', 'The workflow has no triggers pipegen can read.');
  else for (const t of triggers) if (!TRIGGERS.has(t)) bad('template', `The trigger ${show(t)} is not one pipegen writes (only ${[...TRIGGERS].join(', ')}).`);
  judgeEnv(fc, js.env, 'the workflow');
}

/** A workflow- or job-level env: plain values only (no expression, no secret) and no name that changes how code runs. */
function judgeEnv(fc: FileCtx, env: unknown, where: string): void {
  if (env === undefined) return;
  const bad = issueFor(fc);
  if (!isObj(env)) { bad('template', `The env of ${where} is not a map.`); return; }
  for (const [k, v] of Object.entries(env)) {
    if (isDangerousName(k)) bad('injection', `The env of ${where} sets ${show(k)}, which changes how code runs on the runner (every step and action of the job would see it).`);
    if (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'boolean') bad('template', `The env value ${show(k)} of ${where} is not plain text.`);
    if (hasExpr(v)) bad('injection', `The env value ${show(k)} of ${where} holds an expression; secrets and values reach only the steps that need them.`);
  }
}

function judgeJobs(fc: FileCtx, jobs: unknown, only?: readonly string[]): void {
  if (!isObj(jobs) || Object.keys(jobs).length === 0) { issueFor(fc)('template', 'The workflow has no jobs map.'); return; }
  for (const [id, j] of Object.entries(jobs)) if (only === undefined || only.includes(id)) judgeJob(fc, id, j);
}

/** The highest level of each permission a job with this id may have: `contents: read`, plus its row of JOB_PERMISSIONS. */
function ceilingOf(id: string): Record<string, number> {
  const allowed: Record<string, number> = { contents: LEVEL.read as number };
  for (const [k, v] of Object.entries(own(JOB_PERMISSIONS, id) ?? {})) allowed[k] = Math.max(allowed[k] ?? 0, LEVEL[v] as number);
  return allowed;
}

/**
 * Whether a job holds power (ruling 1): any permission beyond `contents: read`, an environment, or a secret that is not a declared app secret.
 * `secrets` are those the job's steps name, except the fingerprint key on a recognised scrub step (judgeStepPolicy, Plan C ruling B1 part 5).
 * DOCUMENTED RESIDUAL (C0a fix round 1): a job with a scrub step holds no repo code (checkJobOrder), but a reviewed native tool in it (gitleaks, trivy,
 * osv-scanner, ...) that hostile input turns into code execution could still read the key from the runner. The bullfrog harden step (no sudo,
 * egress limited to allowed domains) is the mitigation; the key's value is an HMAC key for fingerprints and baselines, not a deploy credential.
 */
function privileged(j: Obj, secrets: ReadonlySet<string>, ex: Expectations): boolean {
  const p = j.permissions;
  if (typeof p === 'string') return true;
  if (isObj(p) && Object.entries(p).some(([k, v]) => (k === 'contents' ? v !== 'read' && v !== 'none' : v !== 'none'))) return true;
  if (j.environment !== undefined) return true;
  return [...secrets].some((n) => !ex.declared.has(n) || PIPEGEN_SECRETS.includes(n));
}

function judgeJob(fc: FileCtx, id: string, j: unknown): void {
  const bad = issueFor(fc);
  const where = `the job ${show(id)}`;
  if (!JOB_ID_RE.test(id)) bad('template', `${where} has an id pipegen does not write.`);
  if (!isObj(j)) { bad('template', `${where} is not a map.`); return; }
  const caller = j.uses !== undefined;
  const keys = caller ? CALLER_JOB_KEYS : STEPS_JOB_KEYS;
  for (const k of Object.keys(j)) if (!keys.has(k)) bad('template', `${where} has the key ${show(k)}, which pipegen never writes on a job${k === 'container' || k === 'strategy' || k === 'continue-on-error' || k === 'defaults' ? ' (it changes what runs or whether a failure counts)' : ''}.`);
  // expressions: nowhere on a job except the forms below (a caller's explicit secrets) and the job outputs, which jobOutputsProblems judges (ruling B3)
  for (const k of ['name', 'runs-on', 'needs', 'environment', 'concurrency', 'timeout-minutes', 'with']) if (hasExpr(j[k])) bad('injection', `${where} has an expression (\${{) in ${k}, which pipegen does not write there.`);
  // a job that feeds the gate is never skipped on a condition (ruling 4); only the gate itself may run always(). Plan G's
  // pr-check form (`needs.pr-check.outputs.has-pr != 'true'`) comes with Plan G, through a checker shared with the renderer
  if (j.if !== undefined) {
    if (typeof j.if !== 'string' || !IF_VALUES.has(j.if)) bad('injection', `${where} has an if: pipegen does not write.`);
    else if (!(id === 'gate' && j.if === 'always()')) bad('template', `${where} has if: ${safeText(j.if, 20)}; a job that feeds the gate runs whenever its workflow does (a skipped job counts as passed).`);
  }
  if (j['timeout-minutes'] !== undefined && !(typeof j['timeout-minutes'] === 'number' && Number.isInteger(j['timeout-minutes']) && j['timeout-minutes'] >= 1 && j['timeout-minutes'] <= 360)) bad('template', `${where} has a timeout-minutes that is not 1 to 360.`);
  judgeEnv(fc, j.env, where);
  judgeGateName(fc, id, j);
  const calledPerms = caller ? judgeCaller(fc, id, j) : undefined;
  judgePermissions(fc, id, j, calledPerms);
  const envName = isObj(j.environment) ? j.environment.name : j.environment;
  // GitHub environment names are not case-sensitive (fix round 2, ruling 4): any spelling of the signing environment counts
  const signing = typeof envName === 'string' && envName.toLowerCase() === SIGNING_ENVIRONMENT;
  if (id === 'pipegen-verify' && fc.draft.capabilities.environments && envName !== SIGNING_ENVIRONMENT) {
    bad('permissions', `${where} must run in the environment ${SIGNING_ENVIRONMENT} (only deploys from the default branch pass it).`);
  }
  if (signing && !SIGNING_JOBS.has(id)) bad('permissions', `${where} runs in ${SIGNING_ENVIRONMENT} (in any spelling), whose secrets only the sign and pipegen-verify jobs may get.`);
  else if (signing && envName !== SIGNING_ENVIRONMENT) bad('permissions', `${where} must name the environment exactly ${SIGNING_ENVIRONMENT}.`);
  if (caller) return;
  if (typeof j['runs-on'] !== 'string' || !HOSTED_RUNNERS.has(j['runs-on'])) {
    bad('template', `${where} must run on a GitHub-hosted runner (${[...HOSTED_RUNNERS].join(', ')}); a self-hosted runner keeps state between runs.`);
  }
  if (j['cache-mode'] !== 'none') bad('cache', `${where} must have cache-mode: none (no cache of any kind may feed the gate, a build, a signature or a verification).`);
  judgeServices(fc, where, j.services);
  if (!Array.isArray(j.steps)) { bad('template', `${where} has no list of steps.`); judgeOutputs(fc, id, where, j, []); return; }
  const judged = judgeJobSteps(fc, where, j.steps, true, id);
  fc.ex.jobs.push({ file: fileKey(fc.file), id, judged, outputs: j.outputs });
  judgeOutputs(fc, id, where, j, judged);
  judgeStepPolicy(fc, id, where, j, judged);
  judgeGateSteps(fc, id, where, j, judged);
}

/** The job's `outputs`: only the forms of jobOutputsProblems (one rule for the renderer's jobOutputsFor and this judge), else `injection` (ruling B3). */
function judgeOutputs(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  for (const problem of jobOutputsProblems(id, j.outputs, judged.map((x) => x.step))) fc.add(fc.file.path, 'injection', `In ${where}: ${problem}`);
}

/**
 * The find-run step's layout, central-workflow and central-sha against the draft. The pin is the VALIDATED one (centralOf: `<owner>/pipelines` at a
 * 40-hex commit), never the raw `draft.centralPin`: a pin that is set but invalid is itself an issue (it makes every central `uses` unknown-pin),
 * and `inline` is not accepted for it. No pin at all: inline, and no central input.
 */
function judgeFindRunLayout(fc: FileCtx, where: string, withs: Obj): void {
  const bad = issueFor(fc);
  const pin = centralOf(fc.draft);
  if (pin === null && fc.draft.centralPin !== undefined) { bad('template', `${where}: the draft's central pin is not a valid central pin (<owner>/pipelines at a 40-character commit), so the find-run step's central layout can not be judged.`); return; }
  const want = pin === null ? 'inline' : 'central';
  if (withs.layout !== want) { bad('template', `${where}: the find-run step's layout must be ${want} for this pipeline (it is ${show(withs.layout)}); the gate it looks for runs ${want === 'central' ? 'in the central workflow' : 'inline in pipegen.yml'}.`); return; }
  if (pin === null) {
    if (withs['central-workflow'] !== undefined || withs['central-sha'] !== undefined) bad('template', `${where}: layout inline takes no central-workflow or central-sha.`);
    return;
  }
  // exactly the path the renderer derives (one helper), so an @, a .., another repository or another file is refused
  const path = centralWorkflowPath(pin.repo, fc.draft.profile.repo);
  if (withs['central-workflow'] !== path) bad('template', `${where}: the find-run step's central-workflow must be exactly ${show(path)}.`);
  if (withs['central-sha'] !== pin.sha) bad('template', `${where}: the find-run step's central-sha must be the commit pipegen recorded for the central repository.`);
}

/**
 * A nightly step (mode nightly) holds exactly nightlyStepInputs(draft) (final review fix round A, ruling 3): no missing, extra or other input. Its
 * `warn-first` list must be the warn-first checks of this draft's job list, so the nightly never opens a "switch to blocking" issue for another
 * check, and never misses one. Deferred: the job list counts only the steps the parsed files hold.
 */
function judgeNightlyInputs(fc: FileCtx, where: string, withs: Record<string, unknown>): void {
  const bad = issueFor(fc);
  fc.ex.deferred.push(() => {
    let want: Record<string, string>;
    try {
      want = nightlyStepInputs(fc.draft, { formatOf: reviewedFormatOf(fc.ex) });
    } catch (e) {
      if (!(e instanceof GateJobListError || e instanceof ArtifactNameError)) throw e;
      bad('template', `${where}: the nightly step's inputs for this pipeline can not be made (${safeText(e.message, 300)}).`);
      return;
    }
    for (const k of [...new Set([...Object.keys(want), ...Object.keys(withs)])]) {
      const name = show(safeText(k, 40));
      if (!Object.hasOwn(want, k)) bad('template', `${where}: the nightly step has the input ${name}, which this pipeline's draft does not give it.`);
      else if (!Object.hasOwn(withs, k)) bad('template', `${where}: the nightly step has no ${name} input, which this pipeline's draft gives it.`);
      else if (!sameInput(NIGHTLY_JSON_INPUTS, withs[k], want[k] as string, k)) bad('template', `${where}: the nightly step's ${name} input is not the value this pipeline's draft gives it.`);
    }
  });
}

/**
 * The job `gate` decides (C0b fix round 1, rulings 1 to 3). It runs the gate action exactly once, in mode `gate` (whatever the
 * draft holds: with no checks the gate still has to run), and has `if: always()` (a skipped required check counts as passed). The
 * gate action in mode `gate` runs in no other job. Its `job-list` literal must equal gateJobList(draft) with `needs` covering every
 * listed job, and each listed job must really hold the check it is listed for (judgeListedJobs). The list and job checks run after
 * every file is judged (the list counts only the steps a parsed file holds, and the scanner jobs may come after the gate in a file).
 */
function judgeGateSteps(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  const bad = issueFor(fc);
  const gateKind = judged.filter((x) => x.kind === 'gate');
  const gates = gateKind.filter((x) => x.step.with?.mode === 'gate');
  // C3: the gate action's mode baseline-check (it verifies the stored baseline's signature) runs in the job baseline-check, exactly
  // once and alone, and in no other job
  const baselineSteps = gateKind.filter((x) => x.step.with?.mode === 'baseline-check');
  if (id === 'baseline-check') {
    if (gateKind.length !== 1 || baselineSteps.length !== 1) {
      bad('permissions', `${where} must run the gate action exactly once, in mode baseline-check (it has ${gateKind.length} gate step${gateKind.length === 1 ? '' : 's'}${gateKind.length === 0 ? '' : `, modes ${gateKind.map((x) => show(String(x.step.with?.mode ?? 'none'))).join(', ')}`}); this job checks the stored baseline and decides nothing else.`);
    }
    return;
  }
  if (baselineSteps.length > 0) bad('permissions', `${where} runs the gate action in mode baseline-check, which only the job baseline-check does.`);
  // C8 fix round 1: a find-run step names where the gate runs, and that must be what the draft says: `central` exactly when pipegen recorded a central pin
  for (const x of gateKind.filter((k) => k.step.with?.mode === 'find-run')) judgeFindRunLayout(fc, where, x.step.with ?? {});
  // final review fix round A (ruling 3): a nightly step's inputs are nightlyStepInputs(draft) exactly (its warn-first list and recorded date come from the draft)
  for (const x of gateKind.filter((k) => k.step.with?.mode === 'nightly')) judgeNightlyInputs(fc, where, isObj(x.step.with) ? x.step.with : {});
  if (id !== 'gate') {
    if (gates.length > 0) bad('not-gate-readable', `${where} runs the gate action in mode gate, which only the job gate does (the required check ${GATE_CHECK_NAME} is its result).`);
    return;
  }
  if (j.if !== 'always()') bad('not-gate-readable', `${where} must have if: always(): without it a failing check skips the gate, and a skipped required check counts as passed.`);
  if (gateKind.length !== 1 || gates.length !== 1) {
    bad('not-gate-readable', `${where} must run the gate action exactly once, in mode gate (it has ${gateKind.length} gate step${gateKind.length === 1 ? '' : 's'}${gateKind.length === 0 ? '' : `, modes ${gateKind.map((x) => show(String(x.step.with?.mode ?? 'none'))).join(', ')}`}); otherwise the required check ${GATE_CHECK_NAME} decides nothing.`);
    return;
  }
  const g = gates[0] as Judged;
  // fix round 1 (ruling 1): the result upload right after the gate step, so the job can not succeed without the gate's result
  // fix round 2 (review-C5b-r1 r1-1): with the gate step found here, never searched again; and no id on it, so the job rules (which know the
  // gate step by content, without an id) and this judge can never disagree about which step it is
  if (g.step.id !== undefined) bad('not-gate-readable', `${where}: the gate step has an id, which pipegen never gives it; the job rules know the gate step by its content, so an id would make them miss it.`);
  for (const problem of gateResultUploadProblems(judged.map((x) => x.step), judged.indexOf(g))) bad('not-gate-readable', `${where}: ${problem}`);
  const needs = needsList(j.needs).filter((x): x is string => typeof x === 'string');
  if (g.step.with?.jobs === undefined) bad('not-gate-readable', `${where}: the gate step has no jobs input, so it would not see the results of the jobs it needs.`);
  const literal = g.step.with?.['job-list'];
  const withs: Record<string, unknown> = isObj(g.step.with) ? g.step.with : {};
  fc.ex.deferred.push(() => {
    let expected: JobListEntry[];
    let want: Record<string, string>;
    try {
      expected = gateJobList(fc.draft, { formatOf: reviewedFormatOf(fc.ex) });
      want = gateStepInputs(fc.draft, { formatOf: reviewedFormatOf(fc.ex) });
    } catch (e) {
      if (!(e instanceof GateJobListError || e instanceof ArtifactNameError)) throw e;
      bad('not-gate-readable', `${where}: the job list of this pipeline can not be made (${safeText(e.message, 300)}), so the gate has no list to read.`);
      return;
    }
    let actual: unknown;
    try { actual = typeof literal === 'string' ? JSON.parse(literal) : undefined; } catch { actual = undefined; }
    if (!isDeepStrictEqual(actual, JSON.parse(JSON.stringify(expected)))) {
      const listed = Array.isArray(actual) ? actual.map((x) => (isObj(x) ? String(x.job) : '?')) : [];
      const want = expected.map((e) => e.job);
      const diff = [...want.filter((x) => !listed.includes(x)).map((x) => `${x} is missing`), ...listed.filter((x) => !want.includes(x)).map((x) => `${x} is extra`)];
      bad('not-gate-readable', `${where}: the gate's job-list is not the list this pipeline needs (${safeText(diff.length > 0 ? diff.join(', ') : 'an entry differs', 200)}), so the gate would read other checks than the pipeline runs.`);
    }
    // final review fix round A (ruling 1): every other input equals gateStepInputs(draft) exactly, none missing, none extra (a skipped,
    // not-proven, service-roots, policy, protected-paths or recorded date the draft never gave would change what the gate decides)
    for (const k of [...new Set([...Object.keys(want), ...Object.keys(withs)])]) {
      if (k === 'job-list') continue;
      const name = show(safeText(k, 40));
      if (!Object.hasOwn(want, k)) bad('not-gate-readable', `${where}: the gate step has the input ${name}, which this pipeline's draft does not give it, so the gate would decide on a setting pipegen never recorded.`);
      else if (!Object.hasOwn(withs, k)) bad('not-gate-readable', `${where}: the gate step has no ${name} input, which this pipeline's draft gives it, so the gate would decide without it.`);
      else if (!sameInput(GATE_JSON_INPUTS, withs[k], want[k] as string, k)) bad('not-gate-readable', `${where}: the gate step's ${name} input is not the value this pipeline's draft gives it, so the gate would decide on another setting.`);
    }
    for (const e of expected) {
      if (!needs.includes(e.job)) bad('not-gate-readable', `${where} does not need the job ${show(e.job)} of its job list, so the gate would not wait for that check (needs must include every listed job).`);
    }
    judgeListedJobs(fc.ex, fc.draft, expected, fileKey(fc.file), bad);
  });
}

/** One step input against its value from gateStepInputs or nightlyStepInputs: JSON literals as parsed JSON (spacing does not count), the others as text. */
function sameInput(json: ReadonlySet<string>, have: unknown, want: string, name: string): boolean {
  if (typeof have !== 'string') return false;
  if (!json.has(name)) return have === want;
  try { return isDeepStrictEqual(JSON.parse(have), JSON.parse(want)); } catch { return false; }
}

/**
 * Each job the gate lists is the job that runs its check, and no other job of the gate's file does (C0b fix rounds 1 and 2): the
 * gate's `needs` and `toJSON(needs)` see only the file the gate is in, so everything here is judged over that file's jobs alone
 * (`file`), never over a job of the same id in another file. The steps pipegen rendered for the check (its tool run or project
 * script, not the shared checkout and installs) sit in `entry.job` only; their base twins only in `base-scan`; a check that is a
 * reviewed ACTION (dependency-review-action) has its action step in `entry.job` and in no other job, unless that job is the listed job
 * of another check of the same action; a findings job holds the scrub and the upload of its artifact and declares exactly the outputs
 * the gate reads (`<artifact>-sha256|-status|-error`). Without this the gate could wait on an empty job, so its `success` would say
 * nothing about the check, which runs (or fails) in a job nobody reads.
 */
function judgeListedJobs(ex: Expectations, draft: PipelineDraft, expected: readonly JobListEntry[], file: string, bad: (check: RefereeCheck, message: string) => void): void {
  const records = ex.jobs.filter((r) => r.file === file);
  const listed = new Set(expected.map((e) => e.job));
  const nb = (m: string): void => bad('not-gate-readable', m);
  // a rendered step of a listed check runs in its own job only
  for (const r of records) {
    for (const x of r.judged) {
      const m = x.match;
      if (m?.need === undefined || m.owner === undefined || !listed.has(m.need) || x.step.run === undefined || x.step.id?.startsWith('pipegen-') === true) continue;
      if (r.id !== m.owner) nb(`The step ${show(x.step.name)} belongs to the job ${show(m.owner)} (the check ${show(m.need)}${m.owner === 'base-scan' ? ', run on the base' : ''}) but sits in the job ${show(r.id)}: the gate reads the job ${show(m.owner)}, so this step's result would not count.`);
    }
  }
  const holds = (jobId: string): readonly Judged[] => records.filter((r) => r.id === jobId).flatMap((r) => r.judged);
  const outputsOf = (jobId: string): Record<string, unknown>[] => records.filter((r) => r.id === jobId).map((r) => (isObj(r.outputs) ? r.outputs : {}));
  const withOf = (x: Judged, k: string): unknown => x.step.with?.[k];
  // the reviewed action entries a listed check is made of (its specs whose tool is an action entry that rendered as reviewed)
  const actionsOf = (job: string): string[] => draft.steps.flatMap((spec, i) => {
    if (!isObj(spec) || !isReviewed(spec.tool) || keyOf(spec.needId, spec.service) !== job) return [];
    const t = ex.byId.get(spec.tool.id);
    return t !== undefined && t.candidate.kind === 'action' && sameCandidate(spec.tool, t.candidate) && reviewedFormatOf(ex)(spec, i) !== undefined ? [t.id] : [];
  });
  for (const e of expected) {
    // 1. the job holds the rendered tool or script of its check
    const sources = [...new Set(ex.runs.filter((r) => r.need === e.job && r.owner === e.job && !r.source.endsWith(':base') && r.step.id?.startsWith('pipegen-') !== true).map((r) => r.source))];
    for (const src of sources) {
      if (!holds(e.job).some((x) => x.match?.source === src)) nb(`The job ${show(e.job)} is in the gate's list for the check ${show(e.needId)}, but it holds no step of the check (the rendered ${src.startsWith('script:') ? 'project script' : 'tool run'}); the gate would wait on a job that does not run it.`);
    }
    // 1b. an action check: its action step is in the listed job and in no other job of the file
    for (const entryId of new Set(actionsOf(e.job))) {
      if (!holds(e.job).some((x) => x.entryId === entryId)) nb(`The job ${show(e.job)} is in the gate's list for the check ${show(e.needId)}, but it holds no step of the action check ${show(entryId)}; the gate would wait on a job that does not run it.`);
      // an action with a reserved kind (the harden step, the platform actions, the build) is also in other jobs (every job starts with the harden step), so only the other kinds are held to one job
      if (own(ENTRY_KIND, entryId) !== undefined) continue;
      for (const r of records) {
        if (r.id !== e.job && r.judged.some((x) => x.entryId === entryId) && !actionsOf(r.id).includes(entryId)) nb(`The action step of the check ${show(e.needId)} (${show(entryId)}) sits in the job ${show(r.id)}, but the gate reads the job ${show(e.job)}: that step's result would not count.`);
      }
    }
    if (e.artifact === undefined) continue;
    // 2. a findings job holds the scrub and the upload of its artifact, and declares its outputs; no other job touches that artifact
    for (const [artifact, home, label] of [[e.artifact, e.job, 'result'], [e.baseArtifact, 'base-scan', 'base result']] as const) {
      if (artifact === undefined) continue;
      const scrubs = records.flatMap((r) => r.judged.filter((x) => x.kind === 'scrub' && withOf(x, 'artifact') === artifact).map(() => r.id));
      const uploads = records.flatMap((r) => r.judged.filter((x) => x.kind === 'upload-artifact' && withOf(x, 'name') === artifact).map(() => r.id));
      for (const id of new Set([...scrubs, ...uploads])) if (id !== home) nb(`The scrub step of the ${label} ${show(artifact)} sits in the job ${show(id)}, but only the job ${show(home)} may hold the scrub and the upload of it.`);
      if (artifact === e.artifact) {
        if (!scrubs.includes(home)) nb(`The job ${show(home)} holds no scrub step of the ${label} ${show(artifact)}, so the gate would have nothing it can trust to read.`);
        if (!uploads.includes(home)) nb(`The job ${show(home)} does not upload the ${label} ${show(artifact)}, so the gate would have nothing to download.`);
      }
      if (scrubs.includes(home)) {
        for (const n of ['sha256', 'status', 'error']) {
          if (!outputsOf(home).some((o) => Object.hasOwn(o, `${artifact}-${n}`))) nb(`The job ${show(home)} must declare the output ${show(`${artifact}-${n}`)}: the gate reads the scrub's ${n} from the job's outputs (a missing one reads as no result).`);
        }
      }
    }
  }
}

/**
 * An artifact name is uploaded by one step per workflow file (the artifact namespace is per workflow run, so per file: a repo with a
 * pull_request file and a merge_group file has each pipeline's uploads in its own run). A second upload of one name fails at run time or hides the first.
 */
function judgeUploadsPerFile(ex: Expectations, add: Add): void {
  const seen = new Map<string, number>();
  for (const r of ex.jobs) {
    for (const x of r.judged) {
      const name = x.kind === 'upload-artifact' ? x.step.with?.name : undefined;
      if (typeof name === 'string') seen.set(`${r.file}\0${name}`, (seen.get(`${r.file}\0${name}`) ?? 0) + 1);
    }
  }
  for (const [k, n] of seen) {
    if (n > 1) { const [file, name] = k.split('\0') as [string, string]; add(file.slice(file.indexOf(':') + 1), 'not-gate-readable', `The artifact ${show(name)} is uploaded by more than one step (${n}) in this workflow file; one name has one upload, or a later one could replace the scrubbed result.`, undefined, file.slice(0, file.indexOf(':')) as CreatedFile['repo']); }
  }
}

/** The output format of a spec's reviewed tool, only for a spec that rendered and that a parsed file holds a step of (an action spec counts as reviewed): the one rule of the blocking rule and the job list. */
function reviewedFormatOf(ex: Expectations): (spec: StepSpec, index: number) => OutputFormat | undefined {
  return (s, si) => {
    if (!(isObj(s) && isReviewed(s.tool))) return undefined;
    const t = ex.byId.get(s.tool.id);
    if (t === undefined || !sameCandidate(s.tool, t.candidate)) return undefined;
    if (t.candidate.kind !== 'action' && !(ex.rendered.has(`spec:${si}`) && ex.matched.has(`spec:${si}`))) return undefined;
    return t.step.output.format;
  };
}

/**
 * Ruling 1: a job runs only what its power is for. A privileged job must have a row in JOB_STEP_POLICY and hold only the
 * step kinds of its row (never repo code, never an unrecognised step); a job whose id has a row is held to it either way.
 * pipegen's own gate and watcher actions run only in the rows that list them, and never after repo code.
 */
function judgeStepPolicy(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  const bad = issueFor(fc);
  // the fingerprint key on a recognised scrub step is that step's own power and gives the job none (ruling B1 part 5): a scanner job stays at contents: read; anywhere else the key still makes a job privileged
  // ... but only while the job holds no step that runs code pipegen did not render as harmless (checkJobOrder refuses that too): every step of a job can read the job's secrets
  const mixed = judged.some((x) => x.kind === 'repo-code' || x.kind === 'unrecognised' || x.kind === 'central');
  const secrets = new Set(judged.flatMap((x) => [...x.secrets].filter((n) => mixed || !(x.kind === 'scrub' && n === SCRUB_SECRET))));
  const row = own(JOB_STEP_POLICY, id);
  const power = privileged(j, secrets, fc.ex);
  if (power && row === undefined) bad('permissions', `${where} holds power (a permission beyond contents: read, an environment or pipegen's own secret) but is not one of pipegen's jobs (${Object.keys(JOB_STEP_POLICY).join(', ')}).`);
  if (row !== undefined) {
    judged.forEach((x, i) => {
      if (!row.includes(x.kind)) bad('permissions', `${where}, step ${i + 1}, is ${x.kind === 'repo-code' ? 'code from the repository' : x.kind === 'unrecognised' ? 'a step pipegen does not recognise' : `a ${x.kind} step`}; the job ${id} may run only ${row.join(', ')} steps.`);
    });
  } else {
    judged.forEach((x, i) => { if (x.kind === 'gate' || x.kind === 'watcher') bad('permissions', `${where}, step ${i + 1}: pipegen's ${x.kind} action runs only in its own job.`); });
  }
  const firstRepo = judged.findIndex((x) => x.kind === 'repo-code' || x.kind === 'unrecognised' || x.kind === 'central');
  if (firstRepo >= 0) judged.slice(firstRepo + 1).forEach((x) => { if (x.kind === 'gate' || x.kind === 'watcher') bad('injection', `In ${where}: pipegen's ${x.kind} action comes after a step that runs code pipegen did not render.`); });
}

/** No job takes the gate's check name; the gate job (id `gate`) has the name the required check expects (GATE_CHECK_NAME, never a literal). */
function judgeGateName(fc: FileCtx, id: string, j: Obj): void {
  const gateJob = GATE_CHECK_NAME.split(' / ')[1];
  const bad = issueFor(fc);
  if (j.name === GATE_CHECK_NAME) bad('not-gate-readable', `The job ${show(id)} is named like the gate's required check (${GATE_CHECK_NAME}); only the gate may report under that name.`);
  else if (id === 'gate' && j.name !== undefined && j.name !== gateJob) bad('not-gate-readable', `The gate job must be named ${show(gateJob)} so the required check is ${GATE_CHECK_NAME}.`);
  else if (id !== 'gate' && j.name === gateJob) bad('not-gate-readable', `The job ${show(id)} is named ${show(gateJob)}, like the gate; a check under the gate's name could pass for it.`);
}

/**
 * A reusable-workflow caller: its `uses` pin, its inputs, its explicit secrets. The called workflow must be a file pipegen is
 * writing (local, or the central repo at the commit pipegen recorded, ruling 2), so it is judged too; pipegen's own secrets
 * reach it only then. Returns the called file's job permissions.
 */
function judgeCaller(fc: FileCtx, id: string, j: Obj): Obj[] | undefined {
  const bad = issueFor(fc);
  const where = `the job ${show(id)}`;
  const uses = j.uses;
  let called: Parsed | undefined;
  if (typeof uses !== 'string') bad('unpinned', `${where} calls a workflow that is not named by text.`);
  else if (uses.startsWith('./')) {
    const rel = uses.slice(2);
    called = WORKFLOW_PATH_RE.test(rel) && PLAIN_REL_RE.test(rel) ? fc.others.get(`${fc.file.repo}:${rel}`) : undefined;
    if (called === undefined) bad('unknown-pin', `${where} calls ${show(uses)}, which is not a workflow file pipegen is writing.`);
  } else {
    const k = usesKey(uses);
    const central = centralOf(fc.draft);
    if (k === null || !COMMIT_SHA_RE.test(k.ref)) bad('unpinned', `${where} calls ${show(uses)}, which is not pinned to a 40-character commit.`);
    else if (central === null || !k.path.startsWith(central.prefix)) bad('unknown-pin', `${where} calls ${show(uses)}, which is neither the central pipelines repo (at the commit pipegen recorded) nor a reviewed workflow.`);
    else if (k.ref !== central.sha) bad('unknown-pin', `${where} calls the central repo at a commit pipegen did not record.`);
    else {
      const rel = k.path.slice(central.prefix.length);
      called = WORKFLOW_PATH_RE.test(rel) ? fc.others.get(`central:${rel}`) : undefined;
      if (called === undefined) bad('unknown-pin', `${where} calls ${show(uses)}, which is not among the central files pipegen is writing, so it can not be judged.`);
    }
  }
  if (j.secrets === 'inherit') bad('permissions', `${where} passes every secret (secrets: inherit); pipegen maps each secret by name.`);
  else if (j.secrets !== undefined) {
    if (!isObj(j.secrets)) bad('template', `${where} has secrets that are not a map.`);
    else for (const [k, v] of Object.entries(j.secrets)) {
      const m = typeof v === 'string' ? SECRET_REF_RE.exec(v) : null;
      if (m === null || m[1] !== k) bad('injection', `${where} passes the secret ${show(k)} as something other than \${{ secrets.${safeText(k, 40)} }}.`);
      else if (!fc.ex.allowed.has(k)) bad('permissions', `${where} passes the secret ${show(k)}, which no step of this pipeline declared.`);
      else if (called === undefined && PIPEGEN_SECRETS.includes(k)) bad('permissions', `${where} passes pipegen's secret ${show(k)} to a workflow pipegen can not judge.`);
    }
  }
  if (called === undefined || !isObj(called.js.jobs)) return undefined;
  return Object.values(called.js.jobs).map((cj) => (isObj(cj) && isObj(cj.permissions) ? cj.permissions : {}));
}

function judgePermissions(fc: FileCtx, id: string, j: Obj, called: Obj[] | undefined): void {
  const bad = issueFor(fc);
  const where = `the job ${show(id)}`;
  const p = j.permissions;
  if (p === undefined || p === null) { bad('permissions', `${where} declares no permissions (it would get the repository's defaults).`); return; }
  if (typeof p === 'string') { bad('permissions', `${where} has permissions ${show(p)}; pipegen lists each permission (never read-all or write-all).`); return; }
  if (!isObj(p)) { bad('permissions', `${where} has permissions that are not a map.`); return; }
  const allowed = ceilingOf(id);
  for (const c of called ?? []) for (const [k, v] of Object.entries(c)) if (typeof v === 'string' && own(LEVEL, v) !== undefined) allowed[k] = Math.max(allowed[k] ?? 0, LEVEL[v] as number);
  for (const [k, v] of Object.entries(p)) {
    const level = typeof v === 'string' ? own(LEVEL, v) : undefined;
    if (level === undefined) bad('permissions', `${where} sets ${show(k)} to ${show(v)}, which is not read, write or none.`);
    else if (level > (own(allowed, k) ?? 0)) bad('permissions', `${where} asks for ${safeText(k, 40)}: ${safeText(String(v), 10)}, more than a job with this id may have.`);
  }
}

function judgeServices(fc: FileCtx, where: string, services: unknown): void {
  if (services === undefined) return;
  const bad = issueFor(fc);
  if (!isObj(services)) { bad('template', `The services of ${where} are not a map.`); return; }
  for (const [name, s] of Object.entries(services)) {
    if (!isObj(s)) { bad('template', `The service ${show(name)} of ${where} is not a map.`); continue; }
    for (const k of Object.keys(s)) if (!['image', 'ports', 'env'].includes(k)) bad('template', `The service ${show(name)} of ${where} has ${show(k)}; pipegen sets only its image, ports and env.`);
    if (hasExpr(s)) bad('injection', `The service ${show(name)} of ${where} holds an expression.`);
    judgeEnv(fc, s.env, `the service ${show(name)}`);
    const image = typeof s.image === 'string' ? s.image : '';
    if (!/@sha256:[0-9a-f]{64}$/.test(image)) bad('unpinned', `The service ${show(name)} of ${where} runs an image that is not pinned by digest.`);
    else if (!fc.ex.images.has(image)) bad('unknown-pin', `The service ${show(name)} of ${where} runs an image that is not a reviewed image at its reviewed digest.`);
  }
}

// ---------- steps ----------

interface Judged {
  step: RenderedStep; match?: Expected; kind: StepKind;
  /** the reviewed entry id of an action step (its `uses` path and pin matched that entry): what binds an action check to its job */
  entryId?: string;
  /** the id may be trusted by the order rule (the step is recognised by content) */
  harmlessId: boolean;
  /** the secrets the step names */
  secrets: Set<string>;
  readsWorkspace: boolean;
}

/**
 * A job's steps, judged where they run: each step (judgeList), then the order rule, the merged npm ci pins and, for a job
 * (`job`), the locked checkout before the first scanner that reads the workspace (ruling 4).
 */
function judgeJobSteps(fc: FileCtx, where: string, steps: unknown[], job: boolean, jobId?: string): Judged[] {
  const judged = judgeList(fc, where, steps);
  // the order rule, on what was parsed: a run step not recognised by content is repo code, whatever id it claims
  const forOrder = judged.map((x) => (x.harmlessId ? x.step : { ...x.step, id: undefined }));
  // the scan steps pipegen rendered (recognised by content, so their ids can be trusted), with their reviewed tool and result format: the scrub steps must equal them
  const scans = new Map<string, ScanFact>();
  for (const x of judged) {
    const m = x.match === undefined || !x.match.final || x.kind !== 'tool' || !x.harmlessId || x.step.id === undefined ? null : /^spec:(\d+)(?::base)?$/.exec(x.match.source);
    const spec = m === null ? undefined : fc.draft.steps[Number(m[1])];
    const format = spec === undefined || !isObj(spec) || !isObj(spec.tool) ? undefined : fc.ex.byId.get(spec.tool.id)?.step.output.format;
    if (spec !== undefined && x.step.id !== undefined && (format === 'sarif' || format === 'zap-json')) scans.set(x.step.id, { tool: spec.tool.id, format });
  }
  for (const problem of checkJobOrder(forOrder, { ...(jobId === undefined ? {} : { id: jobId }), scans })) fc.add(fc.file.path, 'injection', `In ${where}: ${problem}`);
  // a merged repo `npm ci` (dedupeJobSteps) carries exactly the pins of the tools of this job that need it
  const sources = new Set(judged.flatMap((x) => (x.match === undefined ? [] : [x.match.source])));
  for (const x of judged) {
    const id = x.step.id;
    if (x.match === undefined || id === undefined || !id.startsWith('pipegen-npm-ci-')) continue;
    const want = new Set([...sources].flatMap((src) => fc.ex.npmPins.get(src)?.get(id) ?? []));
    const got = pinLines(x.step.env?.PIPEGEN_NPM_EXPECT);
    if (got === null || !isDeepStrictEqual(new Set(got), want)) fc.add(fc.file.path, 'template', `In ${where}: the dependency install ${show(id)} does not check exactly the pins of the tools of its job.`);
  }
  if (job) {
    // the stage step (C1c) reads the checkout too: it copies it for the secrets scan
    const reader = judged.findIndex((x) => (x.kind === 'tool' && x.readsWorkspace) || x.kind === 'stage');
    if (reader >= 0) {
      const co = judged.findIndex((x) => x.kind === 'checkout');
      const ok = co >= 0 && co < reader && judged.slice(0, co).every((x) => x.kind === 'harden' || x.kind === 'setup') && judged[co]?.step.if === undefined;
      if (!ok) fc.add(fc.file.path, 'template', `In ${where}: a scanner reads the workspace, so the job must check the repository out first (the locked checkout, right after any harden or setup step, with no condition); otherwise it scans nothing and passes.`);
    }
  }
  return judged;
}

/**
 * Steps in order. A `./` local action is refused outright in v0.2 (fix round 2, ruling 3): GitHub runs it from the job's
 * checked-out workspace, which on a pull request is the author's code (and in a central reusable workflow, the caller's
 * repository), never from the files pipegen judged. A future opt-in would have to treat it as repo code.
 */
function judgeList(fc: FileCtx, where: string, steps: unknown[]): Judged[] {
  return steps.map((raw, i) => {
    const at = `${where}, step ${i + 1}`;
    if (isObj(raw) && typeof raw.uses === 'string' && raw.uses.startsWith('./')) {
      fc.add(fc.file.path, 'unreviewed', `In ${at}: ${show(raw.uses)} is a local action. GitHub runs it from the checked-out workspace, which on a pull request is the author's code, not the file pipegen judged; pipegen does not run local actions.`);
      return { step: { name: '' }, kind: 'unrecognised', harmlessId: false, secrets: new Set<string>(), readsWorkspace: false };
    }
    return judgeStep(fc, at, raw);
  });
}

function judgeStep(fc: FileCtx, where: string, raw: unknown): Judged {
  const bad = issueFor(fc);
  const at = (m: string): string => `In ${where}: ${m}`;
  const none = (step: RenderedStep): Judged => ({ step, kind: 'unrecognised', harmlessId: false, secrets: new Set(), readsWorkspace: false });
  if (!isObj(raw)) { bad('template', at('the step is not a map.')); return none({ name: '' }); }
  for (const k of Object.keys(raw)) if (!STEP_KEYS.has(k)) bad('template', at(`the key ${show(k)} is not one pipegen writes on a step.`));
  for (const k of ['id', 'name', 'if', 'uses', 'run', 'shell', 'working-directory']) if (raw[k] !== undefined && typeof raw[k] !== 'string') bad('template', at(`${k} is not text.`));
  for (const k of ['with', 'env']) if (raw[k] !== undefined && !isObj(raw[k])) bad('template', at(`${k} is not a map.`));
  const step = raw as unknown as RenderedStep;
  try {
    checkExpressions(step);
  } catch (e) {
    if (!(e instanceof RenderError)) throw e;
    bad('injection', at(e.message));
  }
  const isUses = typeof raw.uses === 'string';
  const isRun = typeof raw.run === 'string';
  if (isUses === isRun) { bad('template', at('a step must have exactly one of uses and run.')); return none(step); }
  const withs = isObj(raw.with) ? raw.with : {};
  const env = isObj(raw.env) ? raw.env : {};
  // caches: no cache action, no cache input beyond the reviewed locks at their locked value
  for (const [k, v] of Object.entries(withs)) {
    if (CACHE_INPUT_RE.test(k) && own(CACHE_LOCKS, k) !== v) bad('cache', at(`the input ${show(k)} turns on a cache; pipegen uses none.`));
  }
  if (isUses && /^actions\/cache(?:\/|@)/i.test(raw.uses as string)) bad('cache', at('actions/cache restores files a previous run left; pipegen uses no cache.'));
  let appRunning = false;
  let kind: StepKind = 'unrecognised';
  let match: Expected | undefined;
  let harmlessId = true;
  let reads = false;
  let entryId: string | undefined;
  if (isUses) {
    ({ appRunning, kind, entryId } = judgeUses(fc, at, raw.uses as string, withs, env, raw));
    if (raw.shell !== undefined) bad('template', at('an action step takes no shell.'));
  } else {
    const r = matchRun(fc.ex, step);
    if (r === 'near') { bad('template', at(`the step ${show(raw.id)} differs from what pipegen renders for it (an input, its pinned config or its command was changed).`)); harmlessId = false; }
    else if (r === null) { bad('unreviewed', at(`the run step ${show(raw.name ?? raw.id ?? '')} is not a step pipegen renders for this pipeline (a reviewed tool or a project script), so it is not run.`)); harmlessId = false; }
    else {
      match = r;
      if (r.final) fc.ex.matched.add(r.source);
      appRunning = r.appRunning;
      const id = r.step.id ?? '';
      kind = r.source.startsWith('script:') || appRunning ? 'repo-code' : /^(?:checker-run|tool-run|tool-install|tool-pull)-/.test(id) ? 'tool' : 'repo-code';
      reads = kind === 'tool' && r.readsWorkspace;
    }
    // trivy keeps a cache between runs unless it runs with pipegen's pinned config (cache.backend: memory, ruling S3), whether
    // or not the step was recognised
    if (TRIVY_LAUNCH_RE.test(raw.run as string)) {
      const cfg = typeof env.PIPEGEN_CONFIG === 'string' ? env.PIPEGEN_CONFIG : '';
      const flag = TRIVY_CONFIG === undefined ? null : `${TRIVY_CONFIG.flag} "$cfg/${TRIVY_CONFIG.fileName}"`;
      if (TRIVY_CONFIG === undefined || cfg !== TRIVY_CONFIG.content || !/backend:\s*memory/.test(cfg) || flag === null || !(raw.run as string).includes(flag)) {
        bad('cache', at('trivy runs without its pinned config (cache.backend: memory), so it could keep a cache between runs.'));
      }
    }
    if (/--cache-dir\b|TRIVY_CACHE/.test(raw.run as string)) bad('cache', at('the step points a tool at a cache folder.'));
  }
  // ruling 4: a step that feeds the gate is never skipped on success and its failure always counts: no continue-on-error,
  // and `if:` only success(), or always() on an upload or a scrub (so a failed job still hands its result to the gate)
  // fix round 1 (ruling 2): except on the gate's baseline and clean-run marker uploads, whose failure is never a gate failure; their job and
  // place (job gate, after the gate step) are the shared order rule's (gateUploadProblems)
  const optionalGateUpload = kind === 'upload-artifact' && typeof withs.name === 'string' && GATE_OPTIONAL_UPLOADS.has(withs.name);
  if (raw['continue-on-error'] !== undefined && raw['continue-on-error'] !== false && !(optionalGateUpload && raw['continue-on-error'] === true)) bad('template', at('continue-on-error would let a failed step pass; pipegen sets it only on the gate\'s baseline and clean-run marker uploads.'));
  if (raw.if !== undefined && raw.if !== 'success()' && !(raw.if === 'always()' && (kind === 'upload-artifact' || kind === 'upload-sarif' || kind === 'scrub'))) {
    bad('template', at(`if: ${safeText(String(raw.if), 20)} could skip this step while the job passes (only success(), or always() on an upload or a scrub).`));
  }
  const secrets = judgeSecrets(fc, at, withs, env, kind, appRunning);
  return { step, ...(match === undefined ? {} : { match }), kind, harmlessId, secrets, readsWorkspace: reads, ...(entryId === undefined ? {} : { entryId }) };
}

/** Which rendered run step this one is: equal to one in every field that runs (name aside), the slots judged by slots.ts. */
function matchRun(ex: Expectations, s: RenderedStep): Expected | 'near' | null {
  const core = coreOf(s);
  for (const e of ex.runs) {
    if (e.slots.size === 0) {
      if (isDeepStrictEqual(core, coreOf(e.step))) return e;
      continue;
    }
    const env = s.env ?? {};
    const masked = Object.fromEntries(Object.entries(env).filter(([k]) => !e.slots.has(k)));
    const want = Object.fromEntries(Object.entries(e.step.env ?? {}).filter(([k]) => !e.slots.has(k)));
    if (!isDeepStrictEqual({ ...core, env: masked }, { ...coreOf(e.step), env: want })) continue;
    if ([...e.slots].every(([k, kind]) => typeof env[k] === 'string' && slotProblem(kind, env[k]) === null)) return e;
  }
  // the repo `npm ci` of a folder: the same step for every tool that asks for it, with the pins merged (dedupeJobSteps)
  if (s.id?.startsWith('pipegen-npm-ci-') === true) {
    const strip = (x: RenderedStep): RenderedStep => ({ ...(coreOf(x) as unknown as RenderedStep), name: '' });
    const e = ex.runs.find((r) => r.step.id === s.id && sameDedupeContent(strip(r.step), strip(s)));
    if (e !== undefined) return e;
  }
  return s.id !== undefined && ex.runIds.has(s.id) ? 'near' : null;
}

/** A `uses:` step: its pin, and as a reviewed action its template. Returns its kind and whether it runs the app (a declared secret may reach it). */
function judgeUses(fc: FileCtx, at: (m: string) => string, uses: string, withs: Obj, env: Obj, raw: Obj): { appRunning: boolean; kind: StepKind; entryId?: string } {
  const bad = issueFor(fc);
  const other = { appRunning: false, kind: 'unrecognised' as StepKind };
  if (uses.startsWith('docker://')) {
    const image = uses.slice('docker://'.length);
    if (!/@sha256:[0-9a-f]{64}$/.test(image)) bad('unpinned', at(`${show(uses)} runs an image by tag; whoever controls the tag controls what runs.`));
    else if (!fc.ex.images.has(image)) bad('unknown-pin', at(`${show(uses)} is not a reviewed image at its reviewed digest.`));
    else bad('template', at('pipegen runs a reviewed image with its own docker step, never as a docker:// action.'));
    return other;
  }
  const k = usesKey(uses);
  if (k === null || !COMMIT_SHA_RE.test(k.ref)) { bad('unpinned', at(`${show(uses)} is not pinned to a 40-character commit.`)); return other; }
  const central = centralOf(fc.draft);
  if (central !== null && k.path.startsWith(central.prefix)) {
    // ruling 2: the central repo only at the commit pipegen recorded, and with every other check (no plain env, no folder)
    if (k.ref !== central.sha) bad('unknown-pin', at(`${show(uses)} is the central repo at a commit pipegen did not record.`));
    // fix round 2, ruling 4: the action file must be a central file pipegen is writing (so it is judged), and the step takes
    // only the inputs that file declares
    const head = uses.slice(0, central.prefix.length);
    const rel = head.toLowerCase() === central.prefix ? uses.slice(central.prefix.length, uses.lastIndexOf('@')) : '';
    const action = PLAIN_REL_RE.test(rel) ? ['action.yml', 'action.yaml'].map((n) => fc.others.get(`central:${rel}/${n}`)).find((x) => x !== undefined) : undefined;
    if (action === undefined) bad('unknown-pin', at(`${show(uses)} is not a central action file pipegen is writing, so what it runs can not be judged.`));
    else {
      const inputs = isObj(action.js.inputs) ? action.js.inputs : {};
      for (const name of Object.keys(withs)) if (!Object.hasOwn(inputs, name)) bad('template', at(`the central action ${show(rel)} declares no input ${show(name)}.`));
    }
    for (const [name, v] of Object.entries(env)) {
      const m = typeof v === 'string' ? SECRET_REF_RE.exec(v) : null;
      if (m === null || m[1] !== name) bad('template', at(`a central action step's env may only map a secret under its own name (${show(name)}).`));
    }
    if (raw['working-directory'] !== undefined) bad('template', at('an action step takes no working-directory.'));
    return { appRunning: false, kind: 'central' };
  }
  if (CENTRAL_LIKE_RE.test(k.path) && !fc.ex.actionPaths.has(k.path)) {
    bad('unknown-pin', at(`${show(uses)} looks like a central pipelines repo, but pipegen recorded no central commit for this repository's owner.`));
    return other;
  }
  const t = fc.ex.actions.get(`${k.path}@${k.ref}`);
  if (t === undefined) {
    if (fc.ex.actionPaths.has(k.path)) bad('unknown-pin', at(`${show(uses)} is a reviewed action at another commit than its reviewed pin.`));
    else {
      bad('unknown-pin', at(`${show(uses)} is not a reviewed action (the whole path counts, sub-path included).`));
      bad('unreviewed', at(`${show(uses)} is not on the reviewed list, so pipegen never runs it.`));
    }
    return other;
  }
  const refusal = containerRefusal(t, k.path);
  if (refusal !== null) bad('unpinned', at(`container action: ${refusal}.`));
  judgeTemplate(fc, at, t, k.path, withs);
  for (const [name, v] of Object.entries(env)) {
    const m = typeof v === 'string' ? SECRET_REF_RE.exec(v) : null;
    if (m === null || m[1] !== name) bad('template', at(`an action step's env may only map a secret under its own name (${show(name)}).`));
  }
  if (raw['working-directory'] !== undefined) bad('template', at('an action step takes no working-directory.'));
  const appRunning = t.categories.some((c) => APP_RUNNING_CATEGORIES.has(c));
  // the gate action in scrub mode under a scrub id is kind scrub; in any other mode (or under another id) it is the gate (ruling B1 part 4)
  // C1c: in stage mode under a stage id it is kind stage (the stage folder of a secrets scan)
  const kind = t.id === PIPEGEN_ACTION_IDS.gate && isScrubStep(raw as unknown as RenderedStep) ? 'scrub'
    : t.id === PIPEGEN_ACTION_IDS.gate && isStageStep(raw as unknown as RenderedStep) ? 'stage'
      : own(ENTRY_KIND, t.id) ?? (appRunning ? 'repo-code' : 'tool');
  return { appRunning, kind, entryId: t.id };
}

/** The template rule (S15): every fixed input at its value, every choice present and inside its list, nothing else but a renderer-filled input that passes its checker and condition. */
function judgeTemplate(fc: FileCtx, at: (m: string) => string, t: ReviewedTool, path: string, withs: Obj): void {
  const bad = issueFor(fc);
  const fixed = t.fixedInputs.with ?? {};
  const all = Object.fromEntries(Object.entries(withs).map(([k, v]) => [k, typeof v === 'string' ? v : String(v)]));
  for (const [k, v] of Object.entries(fixed)) {
    // C5b: an upload's `if-no-files-found` is `error`, except `ignore` on the gate's two optional files (the baseline and the marker)
    const want = path === PLATFORM_USES['upload-artifact'] && k === 'if-no-files-found' ? uploadIfNoFiles(withs.name) : v;
    if (withs[k] !== want) bad('template', at(`${t.id} must have ${safeText(k, 40)}: ${show(want)} (a reviewed fixed input${want === v ? '' : ', for this artifact'}).`));
  }
  // the gate action does one thing per mode and has no default: a step without a mode would run whatever the action's own default is
  if (t.id === PIPEGEN_ACTION_IDS.gate && withs.mode === undefined) bad('template', at(`${t.id} must set its mode (scrub, stage, gate, find-run, nightly or baseline-check); the action has no reviewed default.`));
  for (const [k, values] of Object.entries(t.choices)) {
    const v = withs[k];
    if (v === undefined) bad('template', at(`${t.id} must set its choice ${show(k)} (left out, the action's own default would run, which nobody reviewed).`));
    else if (typeof v !== 'string' || !values.includes(v)) bad('template', at(`${t.id}'s ${safeText(k, 40)} must be one of ${values.join(', ')}.`));
  }
  for (const [k, v] of Object.entries(withs)) {
    if (Object.hasOwn(fixed, k) || Object.hasOwn(t.choices, k)) continue;
    const table = own(RENDERER_INPUTS, path);
    if (table === undefined || own(table, k) === undefined) { bad('template', at(`${t.id} takes no input ${show(k)} from pipegen.`)); continue; }
    const problems = rendererInputProblems(path, { [k]: typeof v === 'string' ? v : String(v) }, all);
    if (problems.length > 0) bad('template', at(problems.map((p) => safeText(p, 160)).join(' ')));
  }
}

/**
 * S9: every secret a step names is in the allowed set; a declared app secret reaches only a step that runs the app;
 * pipegen's own only a reviewed action that does not run the repo's code (never a run step, a central or unknown action).
 * Returns the names, for the job's privilege.
 */
function judgeSecrets(fc: FileCtx, at: (m: string) => string, withs: Obj, env: Obj, kind: StepKind, appRunning: boolean): Set<string> {
  const bad = issueFor(fc);
  const names = new Set<string>();
  for (const v of [...Object.values(withs), ...Object.values(env)]) {
    if (typeof v !== 'string') continue;
    for (const m of v.matchAll(SECRET_USE_RE)) names.add(m[1] as string);
  }
  const ownOk = !appRunning && !['tool', 'scrub', 'stage', 'repo-code', 'unrecognised', 'central'].includes(kind);
  // a recognised scrub step names the fingerprint key and nothing else of pipegen's (ruling B1 part 6)
  const scrubOk = (n: string): boolean => kind === 'scrub' && !appRunning && n === SCRUB_SECRET;
  for (const n of names) {
    if (!fc.ex.allowed.has(n)) { bad('permissions', at(`the secret ${show(n)} is neither declared by a step of this pipeline nor one of pipegen's own.`)); continue; }
    if (fc.ex.declared.has(n) && !PIPEGEN_SECRETS.includes(n)) {
      if (!appRunning) bad('injection', at(`the declared secret ${show(n)} reaches a step that does not run the app (a scanner, linter, upload or setup step never gets one).`));
    } else if (!ownOk && !scrubOk(n)) bad('injection', at(`pipegen's own secret ${show(n)} reaches a step that runs code pipegen did not review as harmless.`));
  }
  return names;
}

// ---------- an edited user workflow (the marker, types.ts PipegenInserted) ----------

/** Needs as a list, whatever form they were written in. */
const needsList = (v: unknown): unknown[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);


function judgeEdited(fc: FileCtx, parsed: Parsed, mark: PipegenInserted): void {
  const bad = issueFor(fc);
  const existing = fc.draft.profile.existingWorkflows.find((w) => w.path === fc.file.path);
  if (fc.file.repo !== 'app' || existing === undefined || !WORKFLOW_PATH_RE.test(fc.file.path)) {
    bad('template', 'The file is marked as an edited user workflow, but it is not one of the repository\'s existing workflows.');
    return;
  }
  if (!Array.isArray(mark.jobs) || mark.jobs.length === 0 || !Array.isArray(mark.needs) || typeof mark.original !== 'string') { bad('template', 'The edit mark is incomplete.'); return; }
  const orig = parseYaml(mark.original, 'user');
  if (!('parsed' in orig)) { bad('template', `The user's original workflow can not be read (${orig.problems.join('; ')}), so pipegen can not show its edit is only the inserted job.`); return; }
  const jobs = parsed.js.jobs;
  const origJobs = orig.parsed.js.jobs;
  if (!isObj(jobs) || !isObj(origJobs)) { bad('template', 'The workflow has no jobs map.'); return; }
  judgeUserTop(fc, parsed.js, mark);
  // pipegen's own parts: present, new, and free of anchors and aliases
  for (const id of mark.jobs) {
    if (!Object.hasOwn(jobs, id)) bad('template', `The job ${show(id)} pipegen inserted is not in the file.`);
    if (Object.hasOwn(origJobs, id)) bad('template', `The job ${show(id)} is the user's own, not one pipegen inserted.`);
    const p = jobPair(parsed.doc, id);
    if (p !== undefined && hasAnchorOrAlias(p.value)) bad('injection', `The job ${show(id)} pipegen inserted uses a YAML anchor or alias.`);
  }
  for (const id of Object.keys(jobs)) if (!Object.hasOwn(origJobs, id) && !mark.jobs.includes(id)) bad('template', `The job ${show(id)} is new, but not marked as inserted by pipegen.`);
  // the file without pipegen's parts must be the original exactly
  const rest: Obj = structuredClone(parsed.js);
  const restJobs = rest.jobs as Obj;
  for (const id of mark.jobs) delete restJobs[id];
  for (const n of mark.needs) {
    const j = isObj(n) && typeof n.job === 'string' ? restJobs[n.job] : undefined;
    const added: unknown[] = isObj(n) && Array.isArray(n.added) ? n.added : [];
    if (!isObj(j) || !isObj(origJobs[n.job])) { bad('template', `The needs pipegen added are on ${show(n?.job)}, which is not a job of the user's workflow.`); continue; }
    const p = jobPair(parsed.doc, n.job);
    const needsNode = isMap(p?.value) ? p.value.get('needs', true) : undefined;
    if (hasAnchorOrAlias(needsNode)) bad('injection', `The needs of ${show(n.job)} use a YAML anchor or alias.`);
    // a gated job that can run although a job it needs failed is not gated (ruling 5; fix round 2, ruling 1)
    if (!gatedIfAllowed(j.if)) bad('template', `The job ${show(n.job)} has an if: other than success() or success() && <condition without a status function or a top-level ||>, so it could run even when pipegen's check fails; it would not really be gated.`);
    const list = needsList(j.needs);
    for (const a of added) {
      if (typeof a !== 'string' || !mark.jobs.includes(a)) bad('template', `The need ${show(a)} added to ${show(n.job)} is not a job pipegen inserted.`);
      if (!list.includes(a)) bad('template', `The job ${show(n.job)} does not need ${show(a)}, which the edit says pipegen added.`);
    }
    const kept = list.filter((x) => !added.includes(x));
    const before = (origJobs[n.job] as Obj).needs;
    if (before === undefined && kept.length === 0) delete j.needs;
    else if (typeof before === 'string' && kept.length === 1) j.needs = kept[0];
    else j.needs = kept;
  }
  if (!isDeepStrictEqual(rest, orig.parsed.js)) bad('template', 'The edit changes the user\'s workflow beyond the job and needs pipegen inserted.');
  judgeJobs(fc, jobs, mark.jobs);
}

/**
 * Ruling 5: the parts of the user's own file that apply to pipegen's jobs too. Any of these refuses the insert, so Plan G
 * writes a file of its own instead: a trigger that runs with the target's power on outside code (pull_request_target, or
 * workflow_run in a file that checks code out), a workflow env with a dangerous name or an expression, `defaults` other than
 * `run.shell` bash or sh, and top-level permissions beyond what the inserted jobs may have.
 */
function judgeUserTop(fc: FileCtx, js: Obj, mark: PipegenInserted): void {
  const bad = issueFor(fc);
  const triggers = triggersOf(js.on) ?? [];
  if (triggers.includes('pull_request_target')) bad('injection', 'The user\'s workflow runs on pull_request_target (with secrets and a write token for outside pull requests); pipegen will not insert its job there. Plan G writes a separate file.');
  if (triggers.includes('workflow_run')) bad('injection', 'The user\'s workflow runs on workflow_run (with the target\'s power, after another run that may have run outside code); pipegen will not insert its job there. Plan G writes a separate file.');
  judgeEnv(fc, js.env, 'the user\'s workflow');
  const d = js.defaults;
  if (d !== undefined) {
    const run = isObj(d) ? d.run : undefined;
    const ok = isObj(d) && Object.keys(d).every((k) => k === 'run') && isObj(run) && Object.keys(run).every((k) => k === 'shell') && (run.shell === undefined || run.shell === 'bash' || run.shell === 'sh');
    if (!ok) bad('injection', 'The user\'s workflow has defaults that would change pipegen\'s steps (only defaults.run.shell bash or sh is accepted).');
  }
  const p = js.permissions;
  if (p !== undefined) {
    const ceiling: Record<string, number> = {};
    for (const id of mark.jobs) for (const [k, v] of Object.entries(ceilingOf(id))) ceiling[k] = Math.max(ceiling[k] ?? 0, v);
    if (!isObj(p)) bad('permissions', `The user's workflow sets permissions ${show(p)} for every job, more than pipegen's inserted jobs may have.`);
    else for (const [k, v] of Object.entries(p)) {
      const level = typeof v === 'string' ? own(LEVEL, v) : undefined;
      if (level === undefined || level > (own(ceiling, k) ?? 0)) bad('permissions', `The user's workflow sets ${safeText(k, 40)}: ${safeText(String(v), 10)} at the top, more than pipegen's inserted jobs may have.`);
    }
  }
}

function hasAnchorOrAlias(node: unknown): boolean {
  if (node === undefined || node === null) return false;
  let found = false;
  visit(node as YamlNode, {
    Alias() { found = true; return visit.BREAK; },
    Node(_, n) { if (n.anchor !== undefined) { found = true; return visit.BREAK; } return undefined; },
  });
  return found;
}

// ---------- a composite action file ----------

function judgeAction(fc: FileCtx, js: Obj): void {
  const bad = issueFor(fc);
  for (const k of Object.keys(js)) if (!ACTION_KEYS.has(k)) bad('template', `The action key ${show(k)} is not one pipegen writes.`);
  const runs = js.runs;
  if (!isObj(runs) || runs.using !== 'composite' || !Array.isArray(runs.steps)) { bad('template', 'A local action pipegen writes is a composite action with a list of steps.'); return; }
  judgeJobSteps(fc, 'the action', runs.steps, false);
}

// ---------- the blocking rule (B7) ----------

/**
 * Every blocking need (outside pipegen's own jobs and the pre-commit layer) has a reviewed tool step or a project script,
 * else `not-gate-readable` (ruling 7). A findings check (B7) whose tool writes no SARIF the gate reads is demoted with a note.
 */
function blockingRule(draft: PipelineDraft, ex: Expectations, add: Add, notes: string[]): string[] {
  const demoted: string[] = [];
  const formatOf = reviewedFormatOf(ex);
  draft.needs.forEach((need, i) => {
    if (!need.blocking) return;
    const category = Object.hasOwn(NEED_ID_CATEGORY, need.id) ? (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[need.id] : undefined;
    // a spec counts only if it rendered and one of its rendered run steps is in a parsed file (an action spec has none: it counts as reviewed); the job list counts the same way
    const formats = draft.steps.flatMap((s, si) => {
      const f = isObj(s) && s.needId === need.id && s.service === need.service ? formatOf(s, si) : undefined;
      return f === undefined ? [] : [f];
    });
    const script = draft.profile.services.some((s) => projectScriptFor(need, s) !== null);
    if (formats.length === 0 && !script && need.layer !== 'pre-commit' && !(category !== undefined && PIPEGEN_JOB_CATEGORIES.has(category))) {
      add(`draft.needs[${i}]`, 'not-gate-readable', `The blocking check ${show(need.id)}${need.service === undefined ? '' : ` for ${show(need.service)}`} has no reviewed tool step and no project script, so the gate would have nothing to read.`);
      return;
    }
    // the category comes from the need id, never from the tool
    if (category !== undefined && !FINDINGS_CATEGORIES.has(category)) return;
    if (category !== undefined && formats.every((f) => readableFormat(category, f))) return;
    let key = need.id;
    if (need.service !== undefined) {
      try { key = `${need.id}--${slug(need.service)}`; } catch (e) { if (!(e instanceof ArtifactNameError)) throw e; }
    }
    if (demoted.includes(key)) return;
    demoted.push(key);
    notes.push(category === undefined
      ? `The check ${show(need.id)} is not one pipegen knows how the gate reads, so it runs as a warning only (non-blocking).`
      : `The check ${show(need.id)}${need.service === undefined ? '' : ` for ${show(need.service)}`} is judged by its findings, but its tool writes no SARIF the gate can read, so it runs as a warning only (non-blocking).`);
  });
  return demoted;
}

// ---------- the referee ----------

const fileKind = (f: CreatedFile): 'workflow' | 'action' | null => (WORKFLOW_PATH_RE.test(f.path) ? 'workflow' : ACTION_PATH_RE.test(f.path) ? 'action' : null);

/**
 * Judges the files pipegen is about to propose. `platform` from platformActions, `reviewed` from loadReviewed, `linters` from
 * ensureLinters and `ghToken` the read-only token zizmor's online audits use (7b); `deps.runLinters` runs the linters (default:
 * the real runLinters). Never throws for anything in the files.
 */
export async function referee(files: CreatedFile[], draft: PipelineDraft, platform: PlatformActions, reviewed: ReviewedTool[], linters: Linters, ghToken: string | null, deps: RefereeDeps = {}): Promise<RefereeReport> {
  const issues: RefereeIssue[] = [];
  const notes: string[] = [];
  const add: Add = (file, check, message, line, repo) => { issues.push({ file: safeText(file, 200), check, message, ...(line === undefined ? {} : { line }), ...(repo === undefined ? {} : { repo }) }); };

  // S18: no secret value in any file (rule names only, never the value)
  for (const f of files) {
    const hits = findSecretLike(f.content);
    if (hits.length > 0) add(f.path, 'secret-value', `The file holds text that looks like a secret value (${hits.join(', ')}); pipegen never writes one into a file.`);
  }

  const ex = expectations(draft, platform, reviewed, add, notes);
  const parsed = new Map<string, Parsed>();
  const lintable: CreatedFile[] = [];
  for (const f of files) {
    // every created path is judged or refused (final review r1, R1): a path that is not plain and normalized, or that is in
    // .github/ (any letter case) without being exactly a workflow or action file, would otherwise be skipped yet may land in .github/workflows/
    const pathProblem = createdPathProblem(f.path);
    if (pathProblem !== null) { add(f.path, 'template', `The file path is refused: ${pathProblem}; pipegen writes only plain, normalized paths.`); continue; }
    const kind = fileKind(f);
    if (kind === null && /^\.github\//i.test(f.path)) {
      add(f.path, 'template', 'The file path is in .github/ but is not a workflow (.github/workflows/<name>.yml) or a composite action (.github/actions/<folder>/action.yml) pipegen can judge, so it is not written.');
      continue;
    }
    if (kind === null) {
      if (f.inserted !== undefined) add(f.path, 'template', 'Only a workflow file can carry the mark of an edited user workflow.');
      continue;
    }
    lintable.push(f);
    const r = parseYaml(f.content, f.inserted === undefined ? 'strict' : 'user');
    if ('problems' in r) {
      for (const p of r.problems) add(f.path, 'injection', `pipegen refuses this file: ${p}.`);
      continue;
    }
    parsed.set(`${f.repo}:${f.path}`, r.parsed);
    // S18 on the parsed values too: an escape (`"\x41…"`) or a folded scalar can hide a value from the raw-text scan
    const raw = findSecretLike(f.content);
    // each value on its own, with a `"` read as a line break: a JSON document held in a value (an npm closure lock) is
    // scanned string by string, as the raw scan sees it, so one URL and the next package name never make a "connection string"
    const hits = uniq(r.parsed.scalars.flatMap((v) => findSecretLike(v.replace(/"/g, '\n')))).filter((h) => !raw.includes(h));
    if (hits.length > 0) add(f.path, 'secret-value', `A value in the file, once parsed, looks like a secret (${hits.join(', ')}); pipegen never writes one into a file.`);
  }
  for (const f of files) {
    const p = parsed.get(`${f.repo}:${f.path}`);
    if (p === undefined) continue;
    const fc: FileCtx = { file: f, add, ex, draft, others: parsed };
    if (fileKind(f) === 'action') judgeAction(fc, p.js);
    else if (f.inserted !== undefined) judgeEdited(fc, p, f.inserted);
    else {
      judgeTop(fc, p.js);
      judgeJobs(fc, p.js.jobs);
    }
  }

  for (const check of ex.deferred) check();
  judgeUploadsPerFile(ex, add);
  const demoted = blockingRule(draft, ex, add, notes);

  // the workflow linters (7b): an issue on pipegen's lines, a note on a user's own
  if (lintable.length > 0) {
    let found: RefereeIssue[];
    try {
      found = await (deps.runLinters ?? runLinters)(lintable, linters, ghToken);
    } catch (e) {
      found = [{ file: lintable[0]?.path ?? '', check: 'actionlint', message: `The workflow linters could not run (${safeText(e instanceof Error ? e.message : String(e), 160)}).` }];
    }
    for (const i of found) {
      // matched by repo and path (ruling 7): a finding that does not name exactly one file is judged as pipegen's own
      const hit = lintable.filter((x) => x.path === i.file && (i.repo === undefined || x.repo === i.repo));
      const f = hit.length === 1 ? hit[0] : undefined;
      const lines = f === undefined ? null : pipegenLines(f);
      if (lines !== null && i.line !== undefined && !lines.has(i.line)) notes.push(`${safeText(i.file, 200)}:${i.line}: ${safeText(i.message, 300)} (on the user's own lines, not pipegen's)`);
      else add(i.file, i.check, i.message, i.line, i.repo);
    }
  }
  return { ok: issues.length === 0, issues, demoted, notes };
}
