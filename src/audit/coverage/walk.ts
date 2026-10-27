// Coverage mapper (see ../coverage.ts for the rules): reading files safely and walking workflows, jobs, steps, local
// actions and called workflows. The only async, I/O-bound part.
import { lstat, realpath } from 'node:fs/promises';
import { join, posix, sep } from 'node:path';
import { linkedLevel, parseYamlLimited, readTextLimitedWithReason, regexSafe } from '../../read/limits.js';
import { asObj } from '../../read/manifest.js';
import { JOB_ID_RE, MAX_WORKFLOWS, WORKFLOW_FILE } from '../../read/workflows.js';
import { codeSecurityAvailable } from '../../github/availability.js';
import { safeText } from '../../util/safe-text.js';
import { MAX_FILTER_PATTERNS, MAX_HITS, MAX_JOBS, MAX_LOCAL_FILES, MAX_SCAN_BYTES, MAX_STEPS, MAX_STEP_VISITS } from './bounds.js';
import { MAY_NOT_RUN, OPAQUE_WHY } from './decide.js';
import { allowedToFail, cut, defaultsDir, firstSet, list, strs, validRef, workingDir } from './helpers.js';
import { resolveScripts } from './scripts.js';
import {
  ALL_GATE, NO_GATE, OLD_PREFIX, actionReason, actionSkipped, condition, foundOf, gateOf, gated, lowerInputs, orGate, refVerdict, requiredInputsHeld,
  type EnvGate, type Inputs, type RepoId,
} from './settings.js';
import { preCommitAllFiles, scanImage, scanShell, shellMode } from './shell.js';
import { PART_RE, PRE_COMMIT_ID, type ToolSignature } from './signatures.js';
import { tokenize } from './tokenize.js';
import type { Compiled, Ctx, Fit, Found, Hit, Obj, Reason } from './types.js';

// ---------- reading files safely (ruling S2) ----------

type Read<T> = { ok: T } | { fail: 'missing' | 'unreadable' | 'outside' };

export class Reader {
  private cache = new Map<string, Promise<Read<string>>>();
  private rootReal: Promise<string | null>;
  constructor(private dir: string) {
    this.rootReal = realpath(dir).catch(() => null);
  }

  /**
   * Text of `rel` (repo-relative), only when no level of the path is a symbolic link, its real path stays inside the
   * repo, and it passes the read limits. Each distinct file is read once.
   */
  text(rel: string): Promise<Read<string>> {
    let r = this.cache.get(rel);
    if (!r) {
      r = this.cache.size >= MAX_WORKFLOWS + MAX_LOCAL_FILES + 2 ? Promise.resolve({ fail: 'unreadable' as const }) : this.load(rel);
      this.cache.set(rel, r);
    }
    return r;
  }

  async yaml(rel: string): Promise<Read<Obj>> {
    const r = await this.text(rel);
    if (!('ok' in r)) return r;
    try {
      return { ok: asObj(parseYamlLimited(r.ok)) };
    } catch {
      return { fail: 'unreadable' };
    }
  }

  private async load(rel: string): Promise<Read<string>> {
    if (!regexSafe(rel) || safeText(rel) !== rel || rel.startsWith('/') || rel.split('/').some((x) => x === '..' || x === '')) return { fail: 'unreadable' };
    if ((await linkedLevel(this.dir, rel)) !== null) return { fail: 'unreadable' };
    const abs = join(this.dir, rel);
    if ((await lstat(abs).catch(() => null)) === null) return { fail: 'missing' };
    const [root, real] = await Promise.all([this.rootReal, realpath(abs).catch(() => null)]);
    if (root === null || real === null) return { fail: 'unreadable' };
    if (!real.startsWith(root + sep)) return { fail: 'outside' };
    const read = await readTextLimitedWithReason(abs);
    return 'text' in read ? { ok: read.text } : { fail: 'unreadable' };
  }
}

/** A local `uses: ./…` value as a repo-relative path ('.' = root), or 'outside' when it leaves the repo. */
function localPath(uses: string): string | 'outside' | null {
  if (!regexSafe(uses) || uses.includes('\\') || uses.includes('\0')) return null;
  const rel = posix.normalize(uses).replace(/\/+$/, '');
  if (rel === '' || rel === '.') return '.';
  if (rel === '..' || rel.startsWith('../') || posix.isAbsolute(rel)) return 'outside';
  return rel;
}

// ---------- walking workflows (rulings S3, S26, U3) ----------

interface StepCtx {
  fit: Fit;
  where: string;
  /** Where `run:` steps start: defaults.run.working-directory of the job or workflow, else the root. */
  runDir: string | null;
  /** defaults.run.shell of the job or workflow (a step's own `shell:` wins). */
  shell: unknown;
  continueOnError: boolean;
  conditional: boolean;
  /** The step (or the local action step that led here) sets more `with:` inputs than pipegen reads. */
  inputsUnread: boolean;
  depth: number;
  /** Task 5: env vars seen in the job that change what tox, nox or pre-commit run. */
  gate: EnvGate;
  /** Plan P Task 3 (PB5): a step of a local composite action other than its first one: other steps ran before it. */
  laterStep?: boolean;
}

function spend(ctx: Ctx): boolean {
  if (ctx.budget.visits >= MAX_STEP_VISITS) {
    ctx.budget.truncated = true;
    return false;
  }
  ctx.budget.visits++;
  return true;
}

/** Something pipegen can't see inside. It runs from the repo root, so it may cover any service. */
function opaque(ctx: Ctx, why: string, by: string | undefined, c: { fit: Fit; where: string }): void {
  if (ctx.hits.length >= MAX_HITS) {
    ctx.budget.truncated = true;
    return;
  }
  ctx.hits.push({ opaque: true, categories: [], ...(by === undefined ? {} : { by }), subject: '', dir: '.', reason: null, fit: c.fit, where: c.where, why });
}

function addFound(ctx: Ctx, found: Found[], c: StepCtx): void {
  if (ctx.hits.length + found.length > MAX_HITS) {
    ctx.budget.truncated = true;
    return;
  }
  for (const f of found) {
    let reason: Reason | null = c.continueOnError ? 'continue' : (f.reason ?? (c.inputsUnread ? 'inputs' : null));
    // Plan P Task 3: an `if:` says the run may not happen at all, which matters more than a reason it can't block (a
    // check that doesn't block, such as scorecard or the copy-paste check, only cares whether it runs)
    if (c.conditional && (reason === null || !MAY_NOT_RUN.has(reason))) reason = 'condition';
    ctx.hits.push({
      opaque: false, categories: f.categories, by: f.by, subject: f.subject, dir: f.dir, reason,
      ...(f.partialWhy === undefined ? {} : { partialWhy: f.partialWhy }), fit: c.fit, where: c.where, ...(f.hookRun === true ? { hookRun: true } : {}),
      ...(c.laterStep === true ? { laterStep: true } : {}),
    });
  }
}

/** Signatures listing exactly this `uses:` path (owner/name[/sub], case-insensitive, @ref ignored); `x*` is a prefix. */
function actionMatches(sigs: Compiled, uses: string): ToolSignature[] {
  const at = uses.indexOf('@');
  const parts = (at < 0 ? uses : uses.slice(0, at)).toLowerCase().split('/');
  if (parts.length < 2 || !parts.every((x) => PART_RE.test(x))) return [];
  const out: ToolSignature[] = [];
  for (const a of sigs.actions) {
    if (a.parts.length !== parts.length || out.includes(a.tool)) continue;
    const last = a.parts.length - 1;
    if (a.parts.every((x, i) => (i === last && a.prefixLast ? (parts[i] as string).startsWith(x) : parts[i] === x))) out.push(a.tool);
  }
  return out;
}

const repoId = (ctx: Ctx): RepoId => ({ owner: ctx.p.owner, repo: ctx.p.repo });

/** Plan P Task 3: signatures listing exactly this called workflow (owner/repo/.github/workflows/<file>, letter case and @ref ignored). */
function reusableMatches(sigs: Compiled, uses: string): ToolSignature[] {
  const at = uses.indexOf('@');
  return sigs.reusable.get((at < 0 ? uses : uses.slice(0, at)).toLowerCase()) ?? [];
}
/** Plan P Task 3 (PS19): a called workflow's ref is pinned: a commit SHA or a vX[.Y[.Z]] tag. */
const pinnedRef = (uses: string) => {
  const at = uses.indexOf('@');
  const ref = at < 0 ? '' : uses.slice(at + 1);
  return /^[0-9a-f]{40}$/.test(ref) || /^v\d{1,6}(?:\.\d{1,6}){0,2}$/.test(ref);
};

/**
 * What the matching tools of an action step (or a called workflow, `reusable`) find, given its `with:` inputs. The
 * reason, first that applies: the repo can't use the action (availability, Plan P Task 3); a soft or crowded input,
 * a check that never fails or fails only when told to (actionReason); a version pipegen can't place (actionRef; for a
 * called workflow any ref but a SHA or a tag); inputs that don't set the action up for the check (requireInputs).
 */
function actionFinds(ctx: Ctx, tools: readonly ToolSignature[], uses: string, w: Inputs, reusable: boolean): Found[] {
  return tools.filter((t) => !actionSkipped(t, w)).map((t) => {
    const verdict = refVerdict(t, uses);
    const available = t.availability === undefined || (t.availability === 'public' ? !ctx.p.private : codeSecurityAvailable(ctx.p, ctx.caps));
    const required = requiredInputsHeld(t, w);
    const ref = verdict === 'unknown' || (reusable && !pinnedRef(uses));
    const reason: Reason | null = !available ? 'unavailable' : actionReason(t, w) ?? (ref ? 'ref' : !required ? 'needs-inputs' : null);
    const f = foundOf(t, '.', reason);
    if (reason === 'unavailable' && t.unavailableWhy !== undefined) f.partialWhy = t.unavailableWhy;
    if (reason === 'needs-inputs' && t.requireInputs !== undefined) f.partialWhy = t.requireInputs.why;
    if (reason === 'ref' && verdict === 'unknown' && t.actionRef !== undefined) f.partialWhy = t.actionRef.unknownWhy;
    if (verdict === 'old' && t.actionRef !== undefined) {
      return { ...f, categories: t.categories.map((c) => `${OLD_PREFIX}${c}`), reason: null, partialWhy: t.actionRef.oldWhy };
    }
    if (t.id === PRE_COMMIT_ID && preCommitActionAllFiles(w)) f.hookRun = true;
    return f;
  });
}

/** Task 5: pre-commit/action runs `pre-commit run … ${extra_args}`, `--all-files` by default (https://github.com/pre-commit/action/blob/main/action.yml). */
function preCommitActionAllFiles(w: Inputs): boolean {
  if (w.crowded.has('extra_args')) return false;
  const all = w.byName.get('extra_args') ?? [];
  if (all.length === 0) return true;
  return all.every((v) => {
    if (v === null || v === undefined) return true; // `extra_args:` with no value: the default
    if (typeof v !== 'string' || !regexSafe(v) || v.includes('${{')) return false;
    const toks = tokenize(v);
    return toks.every((t) => t.op === null) && preCommitAllFiles(toks.map((t) => t.w));
  });
}

async function walkStep(ctx: Ctx, step: Obj, c: StepCtx): Promise<void> {
  if (!spend(ctx)) return;
  const cond = condition(step.if, repoId(ctx));
  if (cond === 'never') return;
  const withInputs = lowerInputs(asObj(step.with));
  const sc: StepCtx = {
    ...c, continueOnError: c.continueOnError || allowedToFail(step['continue-on-error']), conditional: c.conditional || cond === 'partial',
    inputsUnread: c.inputsUnread || withInputs.unread, gate: gateOf(typeof step.run === 'string' ? [step.run] : [], [step.env], c.gate),
  };
  if (typeof step.uses === 'string' && regexSafe(step.uses)) {
    const uses = step.uses.trim();
    if (uses === '.' || uses.startsWith('./')) {
      await followAction(ctx, uses, sc);
    } else if (uses.startsWith('docker://')) {
      addFound(ctx, scanImage(uses, withInputs, ctx.sigs), sc);
    } else {
      const tools = actionMatches(ctx.sigs, uses);
      addFound(ctx, gated(actionFinds(ctx, tools, uses, withInputs, false), sc.gate), sc);
      const owner = uses.split('/')[0]?.toLowerCase();
      if (tools.length === 0 && owner !== undefined && owner === ctx.p.owner.toLowerCase()) opaque(ctx, OPAQUE_WHY.ownerAction, validRef(uses), sc);
    }
  }
  if (typeof step.run === 'string') {
    const base = firstSet(workingDir(step['working-directory']), c.runDir);
    const found = await resolveScripts(ctx, scanShell(step.run, base, ctx.sigs, ctx.budget, shellMode(step.shell ?? c.shell)));
    addFound(ctx, gated(found, sc.gate), sc);
  }
}

/** A local action (`uses: ./dir`): a composite one is followed one level; anything else can't be seen into. */
async function followAction(ctx: Ctx, uses: string, c: StepCtx): Promise<void> {
  const by = validRef(uses);
  if (c.depth > 0) return opaque(ctx, OPAQUE_WHY.secondLevel, by, c);
  const rel = localPath(uses);
  if (rel === 'outside') return opaque(ctx, OPAQUE_WHY.outside, by, c);
  if (rel === null) return opaque(ctx, OPAQUE_WHY.unreadable, by, c);
  let file = '';
  let doc: Read<Obj> = { fail: 'missing' };
  for (const name of ['action.yml', 'action.yaml']) {
    file = rel === '.' ? name : `${rel}/${name}`;
    doc = await readLocal(ctx, file);
    if (!('fail' in doc) || doc.fail !== 'missing') break;
  }
  if ('fail' in doc) return opaque(ctx, doc.fail === 'outside' ? OPAQUE_WHY.outside : OPAQUE_WHY.unreadable, by, c);
  const runs = asObj(doc.ok.runs);
  if (runs.using !== 'composite') return opaque(ctx, OPAQUE_WHY.localCode, by, c);
  const where = cut(`${c.where} → ${file}`);
  // A composite action's run steps start at the repo root (plus their own working-directory and shell), not at the
  // job's defaults.
  for (const [k, step] of list(runs.steps).slice(0, MAX_STEPS).entries()) {
    await walkStep(ctx, asObj(step), { ...c, where, runDir: '.', shell: undefined, depth: 1, ...(k > 0 ? { laterStep: true } : {}) });
  }
  if (list(runs.steps).length > MAX_STEPS) ctx.budget.truncated = true;
}

/**
 * Fix round 3 (N6): the env gate a local composite action (`uses: ./dir`) adds to the job that uses it: its steps' run
 * text and `env:`. Worked out once per action path per mapCoverage call (one read, one parse, its text counted
 * against the scan-byte budget). A missing action (the runner fails the step) or one that isn't composite (its own code,
 * already opaque) adds nothing. Fix round 4 (N9): an action pipegen can't fully read could set anything through
 * GITHUB_ENV, as the runner does read it, so its gate is all on (rows lean partial): one reached through a symbolic link
 * or outside the repo, unreadable, past MAX_LOCAL_FILES, past the scan budget (which also makes would-be-missing rows
 * unknown), or a composite one with more than MAX_STEPS steps or a step that uses another local action (pipegen
 * doesn't follow that one).
 */
function compositeGate(ctx: Ctx, uses: string): Promise<EnvGate> {
  if (!(uses === '.' || uses.startsWith('./'))) return Promise.resolve(NO_GATE);
  const rel = localPath(uses);
  if (rel === null || rel === 'outside') return Promise.resolve(ALL_GATE);
  let gate = ctx.compositeGates.get(rel);
  if (gate === undefined) {
    gate = (async () => {
      for (const name of ['action.yml', 'action.yaml']) {
        const file = rel === '.' ? name : `${rel}/${name}`;
        const doc = await readLocal(ctx, file);
        if ('fail' in doc && doc.fail === 'missing') continue;
        if ('fail' in doc) return ALL_GATE;
        const text = await ctx.read.text(file);
        ctx.budget.bytes += 'ok' in text ? text.ok.length : 0;
        if (ctx.budget.bytes > MAX_SCAN_BYTES) {
          ctx.budget.truncated = true;
          return ALL_GATE;
        }
        const runs = asObj(doc.ok.runs);
        if (runs.using !== 'composite') return NO_GATE;
        if (list(runs.steps).length > MAX_STEPS) return ALL_GATE;
        const steps = list(runs.steps).map(asObj);
        if (steps.some((st) => typeof st.uses === 'string' && (st.uses.trim() === '.' || st.uses.trim().startsWith('./')))) return ALL_GATE;
        return gateOf(steps.flatMap((st) => (typeof st.run === 'string' ? [st.run] : [])), steps.map((st) => st.env));
      }
      return NO_GATE;
    })();
    ctx.compositeGates.set(rel, gate);
  }
  return gate;
}

/** A local workflow or action file, counted against MAX_LOCAL_FILES. */
async function readLocal(ctx: Ctx, rel: string): Promise<Read<Obj>> {
  if (!ctx.localFiles.has(rel)) {
    if (ctx.localFiles.size >= MAX_LOCAL_FILES) {
      ctx.budget.truncated = true;
      return { fail: 'unreadable' };
    }
    ctx.localFiles.add(rel);
  }
  return ctx.read.yaml(rel);
}

const defaultsShell = (doc: Obj): unknown => asObj(asObj(doc.defaults).run).shell;

const mentionsWindows = (texts: string[]) => texts.some((t) => regexSafe(t) && t.toLowerCase().includes('windows'));
/**
 * Whether a job may run on a Windows runner, where a step without `shell:` runs in pwsh: `runs-on` (a string, a list
 * or `{ labels }`) names windows, or it is an expression and the job's matrix names windows somewhere.
 */
function onWindows(job: Obj): boolean {
  const ro = job['runs-on'];
  const labels = [...strs(ro), ...strs(asObj(ro).labels), ...strs(asObj(ro).group)];
  if (mentionsWindows(labels)) return true;
  if (!labels.some((t) => t.includes('${{'))) return false;
  const matrix = asObj(asObj(job.strategy).matrix);
  const values = Object.values(matrix).slice(0, MAX_FILTER_PATTERNS).flatMap((v) =>
    [...strs(v), ...list(v).slice(0, MAX_FILTER_PATTERNS).flatMap((e) => Object.values(asObj(e)).flatMap(strs))]);
  return mentionsWindows(values);
}

/** Plan P Task 3 (PB5): the hits of one job's first step, [start, first). */
interface JobRange { start: number; first: number }

/**
 * Walks a workflow's jobs. `jobs` collects each job's hit range for the egress rule; the top-level call (no `jobs`)
 * checks that rule once its jobs, and the jobs of the local workflows they call, are walked.
 */
export async function walkWorkflow(ctx: Ctx, doc: Obj, path: string, fit: Fit, depth: number, prefix: string, conditional: boolean, jobs?: JobRange[]): Promise<void> {
  const own = jobs ?? [];
  const from = ctx.hits.length;
  const wfDir = defaultsDir(doc);
  const wfShell = defaultsShell(doc);
  const entries = Object.entries(asObj(doc.jobs));
  if (entries.length > MAX_JOBS) ctx.budget.truncated = true;
  for (const [i, [id, raw]] of entries.slice(0, MAX_JOBS).entries()) {
    const job = asObj(raw);
    const cond = condition(job.if, repoId(ctx));
    if (cond === 'never') continue;
    const label = regexSafe(id) && JOB_ID_RE.test(id) ? id : `#${i + 1}`;
    const where = cut(`${prefix}${path} (job ${label})`);
    const jobConditional = conditional || cond === 'partial';
    const start = ctx.hits.length;
    if (typeof job.uses === 'string' && regexSafe(job.uses)) {
      const before = own.length;
      await callWorkflow(ctx, job.uses.trim(), { fit, where, runDir: '.', shell: undefined, continueOnError: false, conditional: jobConditional, inputsUnread: false, depth, gate: NO_GATE },
        asObj(job.with), own);
      // a called workflow pipegen followed added its own jobs; anything else is one job (with no egress step of its own)
      if (own.length === before) own.push({ start, first: start });
      continue;
    }
    const steps = list(job.steps);
    if (steps.length > MAX_STEPS) ctx.budget.truncated = true;
    const kept = steps.slice(0, MAX_STEPS).map(asObj);
    // fix round 2 (N4): a local composite action the job uses runs in the same job, so its steps' env and run text
    // (`echo SKIP=… >> $GITHUB_ENV`) count for the whole job too
    // each distinct `uses:` once per job; each action read once per call (compositeGate caches it)
    let compositeGates = NO_GATE;
    for (const uses of new Set(kept.flatMap((st) => (typeof st.uses === 'string' && regexSafe(st.uses) ? [st.uses.trim()] : [])))) {
      compositeGates = orGate(compositeGates, await compositeGate(ctx, uses));
    }
    const c: StepCtx = {
      fit, where, runDir: firstSet(defaultsDir(job), wfDir), shell: defaultsShell(job) ?? wfShell ?? (onWindows(job) ? 'pwsh' : undefined),
      continueOnError: allowedToFail(job['continue-on-error']), conditional: jobConditional, inputsUnread: false, depth,
      gate: gateOf(kept.flatMap((st) => (typeof st.run === 'string' ? [st.run] : [])), [doc.env, job.env, ...kept.map((st) => st.env)], compositeGates),
    };
    let first = start;
    for (const [k, step] of kept.entries()) {
      await walkStep(ctx, step, c);
      if (k === 0) first = ctx.hits.length;
    }
    own.push({ start, first });
  }
  if (jobs === undefined) egressInEveryJob(ctx, from, own);
}

const isEgress = (h: Hit) => !h.opaque && h.categories.includes('egress');
/**
 * Plan P Task 3 (ruling PB5): egress control counts only when it is the first step of every job of the workflow that
 * has it (the jobs of the local workflows it calls included; a job calling a remote workflow has none; in a local
 * composite action, only its own first step). Otherwise each
 * of the workflow's egress runs that would count gets the reason 'some-jobs' (partial). Egress signatures count for
 * egress only, so the reason changes nothing else. One pass over the workflow's hits.
 */
function egressInEveryJob(ctx: Ctx, from: number, ranges: readonly JobRange[]): void {
  let any = false;
  for (let i = from; i < ctx.hits.length && !any; i++) any = isEgress(ctx.hits[i] as Hit);
  if (!any) return;
  const guarded = (r: JobRange) => {
    for (let i = r.start; i < r.first; i++) {
      const h = ctx.hits[i] as Hit;
      if (isEgress(h) && h.reason === null && h.laterStep !== true) return true;
    }
    return false;
  };
  if (ranges.every(guarded)) return;
  for (let i = from; i < ctx.hits.length; i++) {
    const h = ctx.hits[i] as Hit;
    if (isEgress(h) && h.reason === null) ctx.hits[i] = { ...h, reason: 'some-jobs' };
  }
}

/**
 * A job-level `uses:`: a local reusable workflow is followed one level; a remote one listed in a signature's
 * reusableWorkflows (Plan P Task 3) counts like that action, with the job's `with:` inputs; any other remote one can't
 * be seen into.
 */
async function callWorkflow(ctx: Ctx, uses: string, c: StepCtx, withObj: Obj, jobs: JobRange[]): Promise<void> {
  if (!spend(ctx)) return;
  const by = validRef(uses);
  if (!uses.startsWith('./')) {
    const tools = reusableMatches(ctx.sigs, uses);
    if (tools.length === 0) return opaque(ctx, OPAQUE_WHY.remoteWorkflow, by, c);
    const w = lowerInputs(withObj);
    return addFound(ctx, actionFinds(ctx, tools, uses, w, true), { ...c, inputsUnread: c.inputsUnread || w.unread });
  }
  if (c.depth > 0) return opaque(ctx, OPAQUE_WHY.secondLevel, by, c);
  const rel = localPath(uses);
  if (rel === 'outside') return opaque(ctx, OPAQUE_WHY.outside, by, c);
  if (rel === null || !WORKFLOW_FILE.test(rel)) return opaque(ctx, OPAQUE_WHY.unreadable, by, c);
  const doc = await readLocal(ctx, rel);
  if ('fail' in doc) return opaque(ctx, doc.fail === 'outside' ? OPAQUE_WHY.outside : OPAQUE_WHY.unreadable, by, c);
  // The called workflow runs on the caller's event (and only when the calling job's `if:` holds).
  await walkWorkflow(ctx, doc.ok, rel, c.fit, 1, `${c.where} → `, c.conditional, jobs);
}
