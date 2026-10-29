// The referee (Plan B Task 7 Part 2, sub-task 7a: the static checks). pipegen's last line of defence: it reads the
// finished files pipegen is about to propose and refuses anything unsafe. It PARSES, it does not trust: it judges the
// files themselves, never what the renderer meant to write, and treats every file as hostile (Plan G may also edit a
// user's own workflow). Every check fails closed.
// - Parsing (ruling S29): one YAML document, unique keys, no anchors, aliases, `<<` merge keys, tags or directives, so no
//   key can hide from the walkers below. Job-level `uses:` (reusable workflows) and step-level `uses:` are both walked.
// - Pins: every `uses:` is a reviewed entry (the platform actions, the draft's tools, pipegen's own gate and watcher), the
//   central `<owner>/pipelines/` repo at a 40-character SHA, or a local file that is in `files`. The comparison uses the
//   whole `uses` path, sub-path included (S14). A tag or branch is `unpinned`; any other commit is `unknown-pin`.
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
// - The gate's check name comes from GATE_CHECK_NAME; the blocking rule (B7) demotes a findings check whose tool writes no
//   SARIF; findSecretLike runs over every file (S18). The workflow linters (actionlint, zizmor) are 7b's: they are called
//   through `deps.runLinters`, and without one the referee reports that they did not run.
import { isDeepStrictEqual } from 'node:util';
import { isAlias, isMap, isScalar, isSeq, LineCounter, parseAllDocuments, visit, type Document, type Node as YamlNode, type Pair } from 'yaml';
import { findSecretLike } from '../ai/redact.js';
import { safeText } from '../util/safe-text.js';
import { GATE_CHECK_NAME, type CreatedFile, type PipegenInserted, type PipelineDraft, type ReviewedTool, type StepSpec } from '../types.js';
import { ArtifactNameError, slug } from './artifact-names.js';
import { COMMIT_SHA_RE } from './names.js';
import { NEED_ID_CATEGORY } from './need-ids.js';
import type { PlatformActions } from './pin.js';
import { APP_RUNNING_CATEGORIES } from './render-cli.js';
import { EXPR, own, show } from './render-error.js';
import {
  checkExpressions, checkJobOrder, containerRefusal, IF_VALUES, isDangerousName, RenderError, renderProjectScript, renderStep, sameDedupeContent,
  SECRET_REF_RE, type RenderContext, type RenderedStep,
} from './render-step.js';
import { projectScriptFor } from './reviewed.js';
import { slotProblem, type SlotKind } from './slots.js';
import { ARGV_POLICIES, PLAIN_REL_RE, RENDERER_INPUTS, rendererInputProblems } from './tool-flags.js';

// ---------- the report ----------

/** What a check found. `'quality-bar'` is gone (F10): no static rule produces it. */
export type RefereeCheck = 'unpinned' | 'unknown-pin' | 'unreviewed' | 'permissions' | 'injection' | 'not-gate-readable' | 'cache' | 'template' | 'actionlint' | 'zizmor' | 'secret-value';
/** `line` (1-based) when the finding has one (the linters, 7b): in an edited user workflow it decides between an issue and a note. */
export interface RefereeIssue { file: string; check: RefereeCheck; message: string; line?: number }
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
/** The injectable parts. 7b sets `runLinters` to the real one; without it the referee reports that the linters did not run. */
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
export const FINDINGS_CATEGORIES: ReadonlySet<string> = new Set(['secrets', 'sast', 'deps', 'iac', 'image-scan', 'dast', 'licences', 'dockerfile-lint']);

const LEVEL: Readonly<Record<string, number>> = { none: 0, read: 1, write: 2 };
const WORKFLOW_PATH_RE = /^\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml$/;
const ACTION_PATH_RE = /^\.github\/actions\/[A-Za-z0-9._/-]{1,200}\/action\.ya?ml$/;
const JOB_ID_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,99}$/;
const RUNS_ON_RE = /^[A-Za-z0-9._-]{1,64}$/;
const STEP_KEYS: ReadonlySet<string> = new Set(['id', 'name', 'if', 'uses', 'with', 'run', 'shell', 'env', 'working-directory', 'continue-on-error', 'timeout-minutes']);
const TOP_KEYS: ReadonlySet<string> = new Set(['name', 'run-name', 'on', 'permissions', 'env', 'concurrency', 'jobs']);
const STEPS_JOB_KEYS: ReadonlySet<string> = new Set(['name', 'runs-on', 'needs', 'if', 'permissions', 'environment', 'concurrency', 'outputs', 'env', 'steps', 'timeout-minutes', 'services', 'cache-mode']);
const CALLER_JOB_KEYS: ReadonlySet<string> = new Set(['name', 'uses', 'with', 'secrets', 'needs', 'if', 'permissions']);
const ACTION_KEYS: ReadonlySet<string> = new Set(['name', 'description', 'author', 'inputs', 'outputs', 'runs', 'branding']);
/** Cache inputs the reviewed locks set, with the only value they may have (everything else that names a cache is refused). */
const CACHE_LOCKS: Readonly<Record<string, string>> = { 'package-manager-cache': 'false', 'no-cache': 'true', 'cache-binary': 'false' };
const CACHE_INPUT_RE = /(?:^|[-_])cache(?:$|[-_])/i;
/** Any `secrets.X` reference inside an expression, however it is spaced. */
const SECRET_USE_RE = /\$\{\{[^}]*?\bsecrets\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/g;
/** The line a rendered trivy run step starts trivy with (render-cli.ts launch). */
const TRIVY_LAUNCH_RE = /"\$\{pg_env\[@\]\}" "\$bin\/trivy"/;
const TRIVY_CONFIG = ARGV_POLICIES['trivy-config']?.config;
/** Run-step `if:` values that never skip a tool on success (a blocking tool must run whenever its job runs). */
const RUNS_ALWAYS: ReadonlySet<string> = new Set(['always()', 'success()', '!cancelled()']);

/** Sentinel targets the referee renders with: two sets, so the env values that differ are the run-time slots (B6). */
const SENTINELS = [
  { image: `ghcr.io/pipegen-referee/a@sha256:${'a'.repeat(64)}`, url: 'http://localhost:1', k8sDir: 'pipegen-referee-a' },
  { image: `ghcr.io/pipegen-referee/b@sha256:${'b'.repeat(64)}`, url: 'http://localhost:2', k8sDir: 'pipegen-referee-b' },
] as const;

type Add = (file: string, check: RefereeCheck, message: string, line?: number) => void;
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const isReviewed = (c: unknown): boolean => isObj(c) && c.source === 'reviewed' && c.reviewed === true;
const hasExpr = (v: unknown): boolean => (typeof v === 'string' ? v.includes(EXPR) : Array.isArray(v) ? v.some(hasExpr) : isObj(v) ? Object.entries(v).some(([k, x]) => k.includes(EXPR) || hasExpr(x)) : false);
const uniq = <T>(xs: Iterable<T>): T[] => [...new Set(xs)];

// ---------- parsing (S29) ----------

interface Parsed { doc: Document; js: Obj; lines: LineCounter }

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
  visit(doc, {
    Alias() { if (mode === 'strict') problems.push('it uses a YAML alias (*name), which can copy a key past a reader'); },
    Node(_, n) {
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
  return { parsed: { doc, js, lines } };
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
 * The lines pipegen inserted into an edited user workflow (the jobs it added and the `needs:` entries of the user's jobs
 * it touched), for 7b to tell a linter finding on pipegen's lines (an issue) from one on the user's own (a note). Null for
 * a file pipegen wrote whole (every line is judged) or one that can not be read (judged whole too: fail closed).
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
    const needs = isMap(p?.value) ? (p.value.items.find((q) => isScalar(q.key) && q.key.value === 'needs') as Pair<YamlNode, YamlNode> | undefined) : undefined;
    if (needs?.key?.range && needs.value?.range) linesOf(lines, needs.key.range[0], needs.value.range[1], out);
  }
  return out;
}

// ---------- what the renderer makes for this draft ----------

interface Expected {
  step: RenderedStep;
  /** env keys whose values are run-time slots, with their kind (judged by slots.ts, not by equality) */
  slots: Map<string, SlotKind>;
  source: string; appRunning: boolean; blocking: boolean;
}

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
  /** source → the pins each of its `pipegen-npm-ci-…` steps carries */
  npmPins: Map<string, Map<string, string[]>>;
  byId: Map<string, ReviewedTool>;
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
    declared: new Set(), allowed: new Set(PIPEGEN_SECRETS), npmPins: new Map(), byId,
  };
  const ctxs: RenderContext[] = SENTINELS.map((t) => ({ profile: draft.profile, targets: { ...t } }));
  const needOf = (needId: string, service: string | undefined) => draft.needs.find((n) => n.id === needId && n.service === service);
  const record = (source: string, results: RenderedStep[][], appRunning: boolean, blocking: boolean): void => {
    const [a, b] = results as [RenderedStep[], RenderedStep[]];
    const pins = new Map<string, string[]>();
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
      ex.runs.push({ step: s, slots, source, appRunning, blocking });
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
    for (const n of spec.secrets ?? []) ex.declared.add(n);
    if (t.candidate.kind === 'action') return;   // actions are judged by their template (judgeAction), not by a re-render
    const appRunning = t.categories.some((c) => APP_RUNNING_CATEGORIES.has(c));
    try {
      record(`spec:${i}`, ctxs.map((c) => renderStep(spec, t, platform, c).steps), appRunning, needOf(spec.needId, spec.service)?.blocking ?? true);
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
        record(`script:${need.id}:${s.name}`, ctxs.map((c) => renderProjectScript(ps, platform, c).steps), false, need.blocking);
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

/** The workflow's own top level (a file pipegen wrote whole). */
function judgeTop(fc: FileCtx, js: Obj): void {
  const bad = issueFor(fc);
  for (const k of Object.keys(js)) if (!TOP_KEYS.has(k)) bad('template', `The top-level key ${show(k)} is not one pipegen writes (defaults, for one, would change every run step).`);
  const p = js.permissions;
  if (!isObj(p) || Object.keys(p).length > 0) bad('permissions', 'The workflow must start from `permissions: {}`, so a job gets only what it declares.');
  for (const k of ['name', 'run-name', 'concurrency']) if (hasExpr(js[k])) bad('injection', `The workflow's ${k} holds an expression (\${{), which pipegen never writes there.`);
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

function judgeJob(fc: FileCtx, id: string, j: unknown): void {
  const bad = issueFor(fc);
  const where = `the job ${show(id)}`;
  if (!JOB_ID_RE.test(id)) bad('template', `${where} has an id pipegen does not write.`);
  if (!isObj(j)) { bad('template', `${where} is not a map.`); return; }
  const caller = j.uses !== undefined;
  const keys = caller ? CALLER_JOB_KEYS : STEPS_JOB_KEYS;
  for (const k of Object.keys(j)) if (!keys.has(k)) bad('template', `${where} has the key ${show(k)}, which pipegen never writes on a job${k === 'container' || k === 'strategy' || k === 'continue-on-error' || k === 'defaults' ? ' (it changes what runs or whether a failure counts)' : ''}.`);
  // expressions: nowhere on a job except the forms below (if from the fixed set; a caller's explicit secrets)
  for (const k of ['name', 'runs-on', 'needs', 'environment', 'concurrency', 'outputs', 'timeout-minutes', 'with']) if (hasExpr(j[k])) bad('injection', `${where} has an expression (\${{) in ${k}, which pipegen does not write there.`);
  if (j.if !== undefined && (typeof j.if !== 'string' || !IF_VALUES.has(j.if))) bad('injection', `${where} has an if: pipegen does not write (only always(), success(), failure(), !cancelled()).`);
  judgeEnv(fc, j.env, where);
  judgeGateName(fc, id, j);
  const calledPerms = caller ? judgeCaller(fc, id, j) : undefined;
  judgePermissions(fc, id, j, calledPerms);
  if (id === 'pipegen-verify' && fc.draft.capabilities.environments) {
    const env = isObj(j.environment) ? j.environment.name : j.environment;
    if (env !== SIGNING_ENVIRONMENT) bad('permissions', `${where} must run in the environment ${SIGNING_ENVIRONMENT} (only deploys from the default branch pass it).`);
  }
  if (caller) return;
  if (typeof j['runs-on'] === 'string' ? !RUNS_ON_RE.test(j['runs-on']) : !(Array.isArray(j['runs-on']) && j['runs-on'].length > 0 && j['runs-on'].every((r) => typeof r === 'string' && RUNS_ON_RE.test(r)))) {
    bad('template', `${where} has a runs-on pipegen does not write.`);
  }
  if (j['cache-mode'] !== 'none') bad('cache', `${where} must have cache-mode: none (no cache of any kind may feed the gate, a build, a signature or a verification).`);
  judgeServices(fc, where, j.services);
  if (!Array.isArray(j.steps)) { bad('template', `${where} has no list of steps.`); return; }
  judgeSteps(fc, where, j.steps);
}

/** No job takes the gate's check name; the gate job (id `gate`) has the name the required check expects (GATE_CHECK_NAME, never a literal). */
function judgeGateName(fc: FileCtx, id: string, j: Obj): void {
  const gateJob = GATE_CHECK_NAME.split(' / ')[1];
  const bad = issueFor(fc);
  if (j.name === GATE_CHECK_NAME) bad('not-gate-readable', `The job ${show(id)} is named like the gate's required check (${GATE_CHECK_NAME}); only the gate may report under that name.`);
  else if (id === 'gate' && j.name !== undefined && j.name !== gateJob) bad('not-gate-readable', `The gate job must be named ${show(gateJob)} so the required check is ${GATE_CHECK_NAME}.`);
  else if (id !== 'gate' && j.name === gateJob) bad('not-gate-readable', `The job ${show(id)} is named ${show(gateJob)}, like the gate; a check under the gate's name could pass for it.`);
}

/** A reusable-workflow caller: its `uses` pin, its inputs, its explicit secrets. Returns the called file's job permissions when that file is in `files`. */
function judgeCaller(fc: FileCtx, id: string, j: Obj): Obj[] | undefined {
  const bad = issueFor(fc);
  const where = `the job ${show(id)}`;
  const uses = j.uses;
  if (j.secrets === 'inherit') bad('permissions', `${where} passes every secret (secrets: inherit); pipegen maps each secret by name.`);
  else if (j.secrets !== undefined) {
    if (!isObj(j.secrets)) bad('template', `${where} has secrets that are not a map.`);
    else for (const [k, v] of Object.entries(j.secrets)) {
      const m = typeof v === 'string' ? SECRET_REF_RE.exec(v) : null;
      if (m === null || m[1] !== k) bad('injection', `${where} passes the secret ${show(k)} as something other than \${{ secrets.${safeText(k, 40)} }}.`);
      else if (!fc.ex.allowed.has(k)) bad('permissions', `${where} passes the secret ${show(k)}, which no step of this pipeline declared.`);
    }
  }
  if (typeof uses !== 'string') { bad('unpinned', `${where} calls a workflow that is not named by text.`); return undefined; }
  let called: Parsed | undefined;
  if (uses.startsWith('./')) {
    const rel = uses.slice(2);
    called = WORKFLOW_PATH_RE.test(rel) && PLAIN_REL_RE.test(rel) ? fc.others.get(`${fc.file.repo}:${rel}`) : undefined;
    if (called === undefined) bad('unknown-pin', `${where} calls ${show(uses)}, which is not a workflow file pipegen is writing.`);
  } else {
    const k = usesKey(uses);
    if (k === null || !COMMIT_SHA_RE.test(k.ref)) bad('unpinned', `${where} calls ${show(uses)}, which is not pinned to a 40-character commit.`);
    else {
      const central = `${fc.draft.profile.owner.toLowerCase()}/pipelines/`;
      if (!k.path.startsWith(central)) bad('unknown-pin', `${where} calls ${show(uses)}, which is neither the central pipelines repo nor a reviewed workflow.`);
      else called = fc.others.get(`central:${k.path.slice(central.length)}`);
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
  const allowed: Record<string, number> = { contents: LEVEL.read as number };
  for (const [k, v] of Object.entries(own(JOB_PERMISSIONS, id) ?? {})) allowed[k] = Math.max(allowed[k] ?? 0, LEVEL[v] as number);
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

interface Judged { step: RenderedStep; match?: Expected; harmlessId: boolean }

function judgeSteps(fc: FileCtx, where: string, steps: unknown[]): void {
  const judged = steps.map((s, i) => judgeStep(fc, `${where}, step ${i + 1}`, s));
  // the order rule, on what was parsed: a run step not recognised by content is repo code, whatever id it claims
  const forOrder = judged.map((x) => (x.harmlessId ? x.step : { ...x.step, id: undefined }));
  for (const problem of checkJobOrder(forOrder)) fc.add(fc.file.path, 'injection', `In ${where}: ${problem}`);
  // a merged repo `npm ci` (dedupeJobSteps) carries exactly the pins of the tools of this job that need it
  const sources = new Set(judged.flatMap((x) => (x.match === undefined ? [] : [x.match.source])));
  for (const x of judged) {
    const id = x.step.id;
    if (x.match === undefined || id === undefined || !id.startsWith('pipegen-npm-ci-')) continue;
    const want = new Set([...sources].flatMap((src) => fc.ex.npmPins.get(src)?.get(id) ?? []));
    const got = pinLines(x.step.env?.PIPEGEN_NPM_EXPECT);
    if (got === null || !isDeepStrictEqual(new Set(got), want)) fc.add(fc.file.path, 'template', `In ${where}: the dependency install ${show(id)} does not check exactly the pins of the tools of its job.`);
  }
}

function judgeStep(fc: FileCtx, where: string, raw: unknown): Judged {
  const bad = issueFor(fc);
  const at = (m: string): string => `In ${where}: ${m}`;
  if (!isObj(raw)) { bad('template', at('the step is not a map.')); return { step: { name: '' }, harmlessId: false }; }
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
  if (isUses === isRun) { bad('template', at('a step must have exactly one of uses and run.')); return { step, harmlessId: false }; }
  const withs = isObj(raw.with) ? raw.with : {};
  const env = isObj(raw.env) ? raw.env : {};
  // caches: no cache action, no cache input beyond the reviewed locks at their locked value
  for (const [k, v] of Object.entries(withs)) {
    if (CACHE_INPUT_RE.test(k) && own(CACHE_LOCKS, k) !== v) bad('cache', at(`the input ${show(k)} turns on a cache; pipegen uses none.`));
  }
  if (isUses && /^actions\/cache(?:\/|@)/i.test(raw.uses as string)) bad('cache', at('actions/cache restores files a previous run left; pipegen uses no cache.'));
  let appRunning = false;
  let match: Expected | undefined;
  let harmlessId = true;
  if (isUses) appRunning = judgeUses(fc, at, raw.uses as string, withs, env, raw);
  else {
    const r = matchRun(fc.ex, step);
    if (r === 'near') { bad('template', at(`the step ${show(raw.id)} differs from what pipegen renders for it (an input, its pinned config or its command was changed).`)); harmlessId = false; }
    else if (r === null) { bad('unreviewed', at(`the run step ${show(raw.name ?? raw.id ?? '')} is not a step pipegen renders for this pipeline (a reviewed tool or a project script), so it is not run.`)); harmlessId = false; }
    else {
      match = r;
      appRunning = r.appRunning;
      // a blocking tool must run whenever its job does, and its failure must count
      if (r.blocking && (raw['continue-on-error'] === true || (typeof raw.if === 'string' && !RUNS_ALWAYS.has(raw.if)))) bad('template', at('a step of a blocking check may not be skipped on success or have its failure ignored.'));
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
  judgeSecrets(fc, at, withs, env, isUses, appRunning);
  return { step, ...(match === undefined ? {} : { match }), harmlessId };
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

/** A `uses:` step: its pin, and as a reviewed action its template. Returns whether it runs the app (a declared secret may reach it). */
function judgeUses(fc: FileCtx, at: (m: string) => string, uses: string, withs: Obj, env: Obj, raw: Obj): boolean {
  const bad = issueFor(fc);
  if (uses.startsWith('docker://')) {
    const image = uses.slice('docker://'.length);
    if (!/@sha256:[0-9a-f]{64}$/.test(image)) bad('unpinned', at(`${show(uses)} runs an image by tag; whoever controls the tag controls what runs.`));
    else if (!fc.ex.images.has(image)) bad('unknown-pin', at(`${show(uses)} is not a reviewed image at its reviewed digest.`));
    else bad('template', at('pipegen runs a reviewed image with its own docker step, never as a docker:// action.'));
    return false;
  }
  if (uses.startsWith('./')) {
    const rel = uses.slice(2).replace(/\/$/, '');
    const found = PLAIN_REL_RE.test(rel) && ['action.yml', 'action.yaml'].some((n) => fc.others.has(`${fc.file.repo}:${rel}/${n}`));
    if (!found) bad('unknown-pin', at(`${show(uses)} is a local action that is not among the files pipegen is writing.`));
    return false;
  }
  const k = usesKey(uses);
  if (k === null || !COMMIT_SHA_RE.test(k.ref)) { bad('unpinned', at(`${show(uses)} is not pinned to a 40-character commit.`)); return false; }
  const central = `${fc.draft.profile.owner.toLowerCase()}/pipelines/`;
  if (k.path.startsWith(central)) return false;
  const t = fc.ex.actions.get(`${k.path}@${k.ref}`);
  if (t === undefined) {
    if (fc.ex.actionPaths.has(k.path)) bad('unknown-pin', at(`${show(uses)} is a reviewed action at another commit than its reviewed pin.`));
    else {
      bad('unknown-pin', at(`${show(uses)} is not a reviewed action (the whole path counts, sub-path included).`));
      bad('unreviewed', at(`${show(uses)} is not on the reviewed list, so pipegen never runs it.`));
    }
    return false;
  }
  const refusal = containerRefusal(t, k.path);
  if (refusal !== null) bad('unpinned', at(`container action: ${refusal}.`));
  judgeTemplate(fc, at, t, k.path, withs);
  for (const [name, v] of Object.entries(env)) {
    const m = typeof v === 'string' ? SECRET_REF_RE.exec(v) : null;
    if (m === null || m[1] !== name) bad('template', at(`an action step's env may only map a secret under its own name (${show(name)}).`));
  }
  if (raw['working-directory'] !== undefined) bad('template', at('an action step takes no working-directory.'));
  return t.categories.some((c) => APP_RUNNING_CATEGORIES.has(c));
}

/** The template rule (S15): every fixed input at its value, every choice present and inside its list, nothing else but a renderer-filled input that passes its checker and condition. */
function judgeTemplate(fc: FileCtx, at: (m: string) => string, t: ReviewedTool, path: string, withs: Obj): void {
  const bad = issueFor(fc);
  const fixed = t.fixedInputs.with ?? {};
  const all = Object.fromEntries(Object.entries(withs).map(([k, v]) => [k, typeof v === 'string' ? v : String(v)]));
  for (const [k, v] of Object.entries(fixed)) if (withs[k] !== v) bad('template', at(`${t.id} must have ${safeText(k, 40)}: ${show(v)} (a reviewed fixed input).`));
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

/** S9: every secret a step names is in the allowed set; a declared app secret reaches only a step that runs the app; pipegen's own only an action that does not. */
function judgeSecrets(fc: FileCtx, at: (m: string) => string, withs: Obj, env: Obj, isUses: boolean, appRunning: boolean): void {
  const bad = issueFor(fc);
  const names = new Set<string>();
  for (const v of [...Object.values(withs), ...Object.values(env)]) {
    if (typeof v !== 'string') continue;
    for (const m of v.matchAll(SECRET_USE_RE)) names.add(m[1] as string);
  }
  for (const n of names) {
    if (!fc.ex.allowed.has(n)) { bad('permissions', at(`the secret ${show(n)} is neither declared by a step of this pipeline nor one of pipegen's own.`)); continue; }
    if (fc.ex.declared.has(n) && !PIPEGEN_SECRETS.includes(n)) {
      if (!appRunning) bad('injection', at(`the declared secret ${show(n)} reaches a step that does not run the app (a scanner, linter, upload or setup step never gets one).`));
    } else if (!isUses || appRunning) bad('injection', at(`pipegen's own secret ${show(n)} reaches a step that runs code from the repository.`));
  }
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
  judgeSteps(fc, 'the action', runs.steps);
}

// ---------- the blocking rule (B7) ----------

function blockingRule(draft: PipelineDraft, ex: Expectations, notes: string[]): string[] {
  const demoted: string[] = [];
  for (const need of draft.needs) {
    if (!need.blocking) continue;
    const category = Object.hasOwn(NEED_ID_CATEGORY, need.id) ? (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[need.id] : undefined;
    // the category comes from the need id, never from the tool
    if (category !== undefined && !FINDINGS_CATEGORIES.has(category)) continue;
    const formats = draft.steps
      .filter((s) => isObj(s) && s.needId === need.id && s.service === need.service && isReviewed(s.tool))
      .flatMap((s) => {
        const t = ex.byId.get(s.tool.id);
        return t === undefined || !sameCandidate(s.tool, t.candidate) ? [] : [t.step.output.format];
      });
    const readable = (f: string): boolean => f === 'sarif' || (category === 'dast' && f === 'zap-json');
    if (category !== undefined && formats.every(readable)) continue;
    let key = need.id;
    if (need.service !== undefined) {
      try { key = `${need.id}--${slug(need.service)}`; } catch (e) { if (!(e instanceof ArtifactNameError)) throw e; }
    }
    if (demoted.includes(key)) continue;
    demoted.push(key);
    notes.push(category === undefined
      ? `The check ${show(need.id)} is not one pipegen knows how the gate reads, so it runs as a warning only (non-blocking).`
      : `The check ${show(need.id)}${need.service === undefined ? '' : ` for ${show(need.service)}`} is judged by its findings, but its tool writes no SARIF the gate can read, so it runs as a warning only (non-blocking).`);
  }
  return demoted;
}

// ---------- the referee ----------

const fileKind = (f: CreatedFile): 'workflow' | 'action' | null => (WORKFLOW_PATH_RE.test(f.path) ? 'workflow' : ACTION_PATH_RE.test(f.path) ? 'action' : null);

/**
 * Judges the files pipegen is about to propose. `platform` from platformActions, `reviewed` from loadReviewed, `linters` from
 * ensureLinters and `ghToken` the read-only token zizmor's online audits use (7b); `deps.runLinters` runs the linters (7b
 * wires the real one; without it the referee reports that they did not run). Never throws for anything in the files.
 */
export async function referee(files: CreatedFile[], draft: PipelineDraft, platform: PlatformActions, reviewed: ReviewedTool[], linters: Linters, ghToken: string | null, deps: RefereeDeps = {}): Promise<RefereeReport> {
  const issues: RefereeIssue[] = [];
  const notes: string[] = [];
  const add: Add = (file, check, message, line) => { issues.push({ file: safeText(file, 200), check, message, ...(line === undefined ? {} : { line }) }); };

  // S18: no secret value in any file (rule names only, never the value)
  for (const f of files) {
    const hits = findSecretLike(f.content);
    if (hits.length > 0) add(f.path, 'secret-value', `The file holds text that looks like a secret value (${hits.join(', ')}); pipegen never writes one into a file.`);
  }

  const ex = expectations(draft, platform, reviewed, add, notes);
  const parsed = new Map<string, Parsed>();
  const lintable: CreatedFile[] = [];
  for (const f of files) {
    const kind = fileKind(f);
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

  const demoted = blockingRule(draft, ex, notes);

  // the workflow linters (7b): an issue on pipegen's lines, a note on a user's own
  if (lintable.length > 0) {
    if (deps.runLinters === undefined) {
      add(lintable[0]?.path ?? '', 'actionlint', 'The workflow linters (actionlint and zizmor) were not run, so the files are not cleared.');
    } else {
      let found: RefereeIssue[];
      try {
        found = await deps.runLinters(lintable, linters, ghToken);
      } catch (e) {
        found = [{ file: lintable[0]?.path ?? '', check: 'actionlint', message: `The workflow linters could not run (${safeText(e instanceof Error ? e.message : String(e), 160)}).` }];
      }
      for (const i of found) {
        const f = lintable.find((x) => x.path === i.file);
        const lines = f === undefined ? null : pipegenLines(f);
        if (lines !== null && i.line !== undefined && !lines.has(i.line)) notes.push(`${safeText(i.file, 200)}:${i.line}: ${safeText(i.message, 300)} (on the user's own lines, not pipegen's)`);
        else add(i.file, i.check, i.message, i.line);
      }
    }
  }
  return { ok: issues.length === 0, issues, demoted, notes };
}
