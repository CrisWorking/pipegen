// Coverage mapper (see ../coverage.ts for the rules): reading files safely and walking workflows, jobs, steps, local
// actions and called workflows. The only async, I/O-bound part.
import { lstat, opendir, realpath } from 'node:fs/promises';
import { join, posix, sep } from 'node:path';
import { linkedLevel, parseYamlLimited, readTextLimitedWithReason, regexSafe } from '../../read/limits.js';
import { asObj } from '../../read/manifest.js';
import { JOB_ID_RE, MAX_WORKFLOWS, WORKFLOW_FILE } from '../../read/workflows.js';
import { codeSecurityAvailable } from '../../github/availability.js';
import { neverListed, plainNeverReason } from '../../engine/never-list.js';
import { safeText } from '../../util/safe-text.js';
import { MAX_FILTER_PATTERNS, MAX_HITS, MAX_JOBS, MAX_LOCAL_FILES, MAX_SCAN_BYTES, MAX_STEPS, MAX_STEP_VISITS } from './bounds.js';
import { MAY_NOT_RUN, OPAQUE_WHY } from './decide.js';
import { allowedToFail, cut, defaultsDir, firstSet, list, strs, validRef, workingDir } from './helpers.js';
import { resolveScripts } from './scripts.js';
import {
  ALL_GATE, NO_GATE, OLD_PREFIX, OPAQUE_GATE, actionReason, actionSkipped, condition, foundOf, gateOf, gated, lowerInputs, orGate, refVerdict, requiredInputsHeld,
  configWhy, type EnvGate, type Inputs, type RepoId,
} from './settings.js';
import { imageName, preCommitAllFiles, scanImage, scanShell, shellMode } from './shell.js';
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

  /**
   * Fix round 1 (P8): whether `rel` exists (a file, a folder or a link: the tool would find it there), without reading
   * it. Worked out once per path; past MAX_CONFIG_CHECKS paths the answer is true (rows lean partial).
   */
  exists(rel: string): Promise<boolean> {
    let r = this.seen.get(rel);
    if (r === undefined) {
      const ok = regexSafe(rel) && !rel.startsWith('/') && !rel.split('/').some((x) => x === '..' || x === '');
      r = !ok || this.seen.size >= MAX_CONFIG_CHECKS ? Promise.resolve(true) : lstat(join(this.dir, rel)).then(() => true, () => false);
      this.seen.set(rel, r);
    }
    return r;
  }
  private seen = new Map<string, Promise<boolean>>();

  /**
   * Fix round 2: whether `dir` holds a file named `name` in any letter case (a macOS or Windows runner). Each folder is
   * listed once; past MAX_CONFIG_CHECKS folders, or with more than MAX_LISTED entries, the answer is true.
   */
  async existsFold(dir: string, name: string): Promise<boolean> {
    let r = this.listed.get(dir);
    if (r === undefined) {
      const ok = dir === '.' || (regexSafe(dir) && !dir.startsWith('/') && !dir.split('/').some((x) => x === '..' || x === ''));
      r = !ok || this.listed.size >= MAX_CONFIG_CHECKS ? Promise.resolve(null)
        : opendirNames(join(this.dir, dir)).catch(() => new Set<string>());
      this.listed.set(dir, r);
    }
    const names = await r;
    return names === null || names.has(name.toLowerCase());
  }
  private listed = new Map<string, Promise<ReadonlySet<string> | null>>();

  /**
   * `rel` as a YAML map. Each distinct file is parsed once (a composite action used by 20,000 steps is the same 100 KB
   * of text each time, and its parsed form is only ever read, never changed).
   */
  yaml(rel: string): Promise<Read<Obj>> {
    let r = this.parsed.get(rel);
    if (r === undefined) {
      r = this.parse(rel);
      this.parsed.set(rel, r);
    }
    return r;
  }
  private parsed = new Map<string, Promise<Read<Obj>>>();

  private async parse(rel: string): Promise<Read<Obj>> {
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
    const read = await readTextLimitedWithReason(abs, this.dir);
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
  /** Fix round 1 (P8, concern 2): the top-level workflow releases (deploys or publishes); egress counts only there. */
  release: boolean;
  /** Fix round 2: the job may run on macOS or Windows, where config file names match in any letter case. */
  foldCase?: boolean;
  /** Fix round 1: the job's runner, when `runs-on` is one literal label (lowercased), and whether it runs in a container. */
  runner: string | null;
  container: boolean;
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
  for (const found1 of found) {
    // fix round 1 (P8, concern 2): egress control in a workflow that doesn't release never counts
    const f = !c.release && found1.categories.includes('egress') ? { ...found1, categories: found1.categories.filter((x) => x !== 'egress') } : found1;
    if (f.categories.length === 0) continue;
    // ruling P33: a never-listed action keeps its own reason, whatever else holds for the step
    let reason: Reason | null = f.reason === 'never-listed' ? f.reason : c.continueOnError ? 'continue' : (f.reason ?? (c.inputsUnread ? 'inputs' : null));
    // Plan P Task 3: an `if:` says the run may not happen at all, which matters more than a reason it can't block (a
    // check that doesn't block, such as scorecard or the copy-paste check, only cares whether it runs)
    if (c.conditional && (reason === null || !MAY_NOT_RUN.has(reason))) reason = 'condition';
    ctx.hits.push({
      opaque: false, categories: f.categories, by: f.by, subject: f.subject, dir: f.dir, reason,
      ...(f.partialWhy === undefined ? {} : { partialWhy: f.partialWhy }), fit: c.fit, where: c.where, ...(f.hookRun === true ? { hookRun: true } : {}),
      ...(c.laterStep === true ? { laterStep: true } : {}), ...(f.configFiles === undefined ? {} : { configFiles: f.configFiles }),
      ...(f.configFiles !== undefined && c.foldCase === true ? { foldCase: true } : {}),
      ...(f.jobEnv === undefined ? {} : { jobEnv: f.jobEnv }),
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
 * Before all of these (ruling P33, final review I1): an action on pipegen's own never-list (neverListed, the loader's
 * rule: any letter case, a fork's name family under any owner, a look-alike) is partial with that reason, never covered.
 */
function actionFinds(ctx: Ctx, tools: readonly ToolSignature[], uses: string, w: Inputs, reusable: boolean, c: StepCtx): Found[] {
  const never = neverListed(uses);
  return tools.filter((t) => !actionSkipped(t, w)).map((t) => {
    if (never !== null) {
      const f = foundOf(t, '.', 'never-listed');
      return { ...f, partialWhy: `${f.subject} runs, but this action is on pipegen's never-use list (${plainNeverReason(never)}); pin a reviewed alternative.` };
    }
    const verdict = refVerdict(t, uses);
    const available = t.availability === undefined || (t.availability === 'public' ? !ctx.p.private : codeSecurityAvailable(ctx.p, ctx.caps));
    // fix round 1: an action that works only on some GitHub-hosted runners, outside a container
    const runnerOk = t.runners === undefined || (!c.container && c.runner !== null && t.runners.includes(c.runner));
    const required = requiredInputsHeld(t, w);
    const ref = verdict === 'unknown' || (reusable && !pinnedRef(uses));
    const reason: Reason | null = !available ? 'unavailable' : !runnerOk ? 'runner' : actionReason(t, w) ?? (ref ? 'ref' : !required ? 'needs-inputs' : null);
    const f = foundOf(t, '.', reason);
    if (reason === 'unavailable' && t.unavailableWhy !== undefined) f.partialWhy = t.unavailableWhy;
    if (reason === 'runner') {
      f.partialWhy = `${f.subject} runs, but ${c.container ? 'in a container job' : c.runner === null ? "on a runner pipegen can't place" : `on ${c.runner}`}, where it doesn't block traffic.`;
    }
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
    inputsUnread: c.inputsUnread || withInputs.unread, gate: gateOf(typeof step.run === 'string' ? [step.run] : [], [step.env], c.gate, ctx.sigs.softEnv, ctx.sigs.configFiles),
  };
  if (typeof step.uses === 'string' && regexSafe(step.uses)) {
    const uses = step.uses.trim();
    if (uses === '.' || uses.startsWith('./')) {
      await followAction(ctx, uses, sc);
    } else if (uses.startsWith('docker://')) {
      addFound(ctx, scanImage(uses, withInputs, ctx.sigs), sc);
    } else {
      const tools = actionMatches(ctx.sigs, uses);
      addFound(ctx, gated(actionFinds(ctx, tools, uses, withInputs, false, sc), sc.gate), sc);
      const owner = uses.split('/')[0]?.toLowerCase();
      if (tools.length === 0 && owner !== undefined && owner === ctx.p.owner.toLowerCase()) opaque(ctx, OPAQUE_WHY.ownerAction, validRef(uses), sc);
    }
  }
  if (typeof step.run === 'string') {
    const base = firstSet(workingDir(step['working-directory']), c.runDir);
    // P52 (d): a no-exec shell runs nothing; a `shell:` spec pipegen doesn't know makes the step opaque (unknown)
    const mode = shellMode(step.shell ?? c.shell);
    if (mode === null) return opaque(ctx, OPAQUE_WHY.unknownShell, undefined, sc);
    const found = mode === 'noexec' ? [] : await resolveScripts(ctx, scanShell(step.run, base, ctx.sigs, ctx.budget, mode));
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
  // fix round 2 (ruling P9): a step pipegen can't see into may set any variable through GITHUB_ENV
  if (!(uses === '.' || uses.startsWith('./'))) return Promise.resolve(opaqueStep(ctx, uses) ? OPAQUE_GATE : NO_GATE);
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
        if (runs.using !== 'composite') return OPAQUE_GATE; // its own code (fix round 2: may set any variable)
        if (list(runs.steps).length > MAX_STEPS) return ALL_GATE;
        const steps = list(runs.steps).map(asObj);
        if (steps.some((st) => typeof st.uses === 'string' && (st.uses.trim() === '.' || st.uses.trim().startsWith('./')))) return ALL_GATE;
        if (steps.some((st) => typeof st.uses === 'string' && regexSafe(st.uses) && opaqueStep(ctx, st.uses.trim()))) return OPAQUE_GATE;
        return gateOf(steps.flatMap((st) => (typeof st.run === 'string' ? [st.run] : [])), steps.map((st) => st.env), NO_GATE, ctx.sigs.softEnv, ctx.sigs.configFiles);
      }
      return NO_GATE;
    })();
    ctx.compositeGates.set(rel, gate);
  }
  return gate;
}

/**
 * Fix round 2 (ruling P9): a remote `uses:` step pipegen can't see into: a `docker://` image no signature names, or an
 * action from the repo owner's own account that no signature lists (walkStep reads it as opaque too).
 */
function opaqueStep(ctx: Ctx, uses: string): boolean {
  // an image a signature names runs that tool (scanImage reads it); any other image runs code pipegen can't see
  if (uses.startsWith('docker://')) return !ctx.sigs.byFirstWord.has(imageName(uses.slice('docker://'.length)));
  const owner = uses.split('/')[0]?.toLowerCase();
  return owner !== undefined && owner === ctx.p.owner.toLowerCase() && actionMatches(ctx.sigs, uses).length === 0;
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

const mentions = (texts: string[], words: readonly string[]) => texts.some((t) => regexSafe(t) && words.some((w) => t.toLowerCase().includes(w)));
/**
 * Whether a job may run on a runner whose name mentions one of `words`: `runs-on` (a string, a list or `{ labels }`)
 * names it, or it is an expression and the job's matrix names it somewhere.
 */
function mayRunOn(job: Obj, words: readonly string[]): boolean {
  const ro = job['runs-on'];
  const labels = [...strs(ro), ...strs(asObj(ro).labels), ...strs(asObj(ro).group)];
  if (mentions(labels, words)) return true;
  if (!labels.some((t) => t.includes('${{'))) return false;
  const matrix = asObj(asObj(job.strategy).matrix);
  const values = Object.values(matrix).slice(0, MAX_FILTER_PATTERNS).flatMap((v) =>
    [...strs(v), ...list(v).slice(0, MAX_FILTER_PATTERNS).flatMap((e) => Object.values(asObj(e)).flatMap(strs))]);
  return mentions(values, words);
}
/** Whether a job may run on a Windows runner, where a step without `shell:` runs in pwsh. */
const onWindows = (job: Obj) => mayRunOn(job, ['windows']);
/** Fix round 2: a macOS or Windows runner, whose file system ignores letter case (a `Trivy.yaml` is trivy.yaml there). */
const foldsCase = (job: Obj) => mayRunOn(job, ['windows', 'macos']);

/** Fix round 1: `runs-on` as one literal label (a string, or a list of one), lowercased; null for anything else. */
function literalRunner(job: Obj): string | null {
  const ro = job['runs-on'];
  const labels = typeof ro === 'string' ? [ro] : Array.isArray(ro) ? ro : [];
  const only = labels.length === 1 ? labels[0] : undefined;
  return typeof only === 'string' && regexSafe(only) && /^[A-Za-z0-9.-]{1,64}$/.test(only.trim()) ? only.trim().toLowerCase() : null;
}

/**
 * Walks a workflow's jobs. Fix round 1 (P8, concern 2): in a release workflow (`release`, passed on to the local
 * workflows it calls) each job's first-step hit range goes to ctx.releaseJobs, for releaseEgress.
 */
export async function walkWorkflow(ctx: Ctx, doc: Obj, path: string, fit: Fit, depth: number, prefix: string, conditional: boolean, release: boolean): Promise<void> {
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
      const before = ctx.releaseJobs.length;
      await callWorkflow(ctx, job.uses.trim(), {
        fit, where, runDir: '.', shell: undefined, continueOnError: false, conditional: jobConditional, inputsUnread: false, depth, gate: NO_GATE, release,
        runner: null, container: false,
      }, asObj(job.with));
      // a called workflow pipegen followed added its own jobs; anything else is one job (with no egress step of its own)
      if (release && ctx.releaseJobs.length === before) ctx.releaseJobs.push({ start, first: start, where });
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
      gate: gateOf(kept.flatMap((st) => (typeof st.run === 'string' ? [st.run] : [])), [doc.env, job.env, ...kept.map((st) => st.env)], compositeGates, ctx.sigs.softEnv, ctx.sigs.configFiles),
      release, runner: literalRunner(job), container: job.container !== undefined && job.container !== null, ...(foldsCase(job) ? { foldCase: true } : {}),
    };
    let first = start;
    for (const [k, step] of kept.entries()) {
      await walkStep(ctx, step, c);
      if (k === 0) first = ctx.hits.length;
    }
    if (release) ctx.releaseJobs.push({ start, first, where });
  }
}

/** Fix round 1 (P8): config files looked for per mapCoverage call; past it every run with configFiles leans partial. */
const MAX_CONFIG_CHECKS = 2_000;
/** Fix round 2: entries read per listed folder (case-folding runners); a bigger folder leans partial (null). */
const MAX_LISTED = 5_000;
/** The lowercased entry names of a folder, or null past MAX_LISTED entries. */
async function opendirNames(abs: string): Promise<ReadonlySet<string> | null> {
  const d = await opendir(abs);
  const out = new Set<string>();
  try {
    for await (const e of d) {
      if (out.size >= MAX_LISTED) return null;
      out.add(e.name.toLowerCase());
    }
  } finally {
    await d.close().catch(() => undefined);
  }
  return out;
}

/**
 * Fix round 1 (P8): a run of a tool that loads a config file by itself (configFiles) is partial ('config') when such a
 * file sits in the run's folder or at the repo root: pipegen never reads it, and it can turn the check or the failure
 * off. A run whose folder can't be known leans partial too. One existence check per distinct (folder, file).
 */
export async function configFilesPass(ctx: Ctx): Promise<void> {
  for (let i = 0; i < ctx.hits.length; i++) {
    const h = ctx.hits[i] as Hit;
    if (h.configFiles === undefined || (h.reason !== null && MAY_NOT_RUN.has(h.reason))) continue;
    let found: string | null = null;
    for (const file of h.configFiles) {
      const places = h.dir === null ? [] : h.dir === '.' ? [file] : [`${h.dir}/${file}`, file];
      const folders = h.dir === null ? [] : h.dir === '.' ? ['.'] : [h.dir, '.'];
      const there = h.foldCase === true
        ? (await Promise.all(folders.map((d) => ctx.read.existsFold(d, file)))).some(Boolean)
        : (await Promise.all(places.map((x) => ctx.read.exists(x)))).some(Boolean);
      if (h.dir === null || there) {
        found = file;
        break;
      }
    }
    if (found !== null) ctx.hits[i] = { ...h, reason: 'config', partialWhy: configWhy(h.subject, `a ${found} file`) };
  }
}

/**
 * Fix round 2 (ruling P9, re-review N4c/N4d): signs in a workflow's own text that it releases although pipegen's
 * readers don't say `deploys` or `publishes`: a job that grants `id-token`, `packages` or `contents` write (or
 * write-all, also at the workflow level), a step that pushes an image with docker/build-push-action (`push:` set and
 * not false), or a job that hands secrets to a called workflow (`secrets:`). Its local calls (`uses: ./…`) are listed
 * for the one-level rule. Bounded by MAX_JOBS and MAX_STEPS.
 */
export function releaseSigns(doc: Obj): { grants: boolean; pushes: boolean; passesSecrets: boolean; calls: string[] } {
  const writes = (perm: unknown): boolean => {
    if (typeof perm === 'string') return perm.trim().toLowerCase() === 'write-all';
    const o = asObj(perm);
    return ['id-token', 'packages', 'contents'].some((k) => typeof o[k] === 'string' && (o[k] as string).trim().toLowerCase() === 'write');
  };
  let grants = writes(doc.permissions);
  let pushes = false;
  let passesSecrets = false;
  const calls: string[] = [];
  for (const raw of Object.values(asObj(doc.jobs)).slice(0, MAX_JOBS)) {
    const job = asObj(raw);
    grants ||= writes(job.permissions);
    if (job.secrets !== undefined && job.secrets !== null) passesSecrets = true;
    if (typeof job.uses === 'string' && regexSafe(job.uses) && job.uses.trim().startsWith('./')) {
      const rel = localPath(job.uses.trim());
      if (rel !== null && rel !== 'outside') calls.push(rel);
    }
    for (const st of list(job.steps).slice(0, MAX_STEPS).map(asObj)) {
      if (typeof st.uses !== 'string' || !st.uses.trim().toLowerCase().startsWith('docker/build-push-action')) continue;
      const push = asObj(st.with).push;
      if (push !== undefined && push !== null && push !== false && !(typeof push === 'string' && ['', 'false'].includes(push.trim().toLowerCase()))) pushes = true;
    }
  }
  return { grants, pushes, passesSecrets, calls };
}

const isEgress = (h: Hit) => !h.opaque && h.categories.includes('egress');
/**
 * Plan P Task 3 (ruling PB5), fix round 1 (P8, concern 2): egress control counts only when it is the first step of
 * every job of every release workflow (the jobs of the local workflows they call included; a job calling a remote
 * workflow has none; in a local composite action, only its own first step), and every release workflow was read in
 * full. Otherwise each egress run that would count gets the reason 'some-jobs' (partial), naming the first release job
 * without it. Egress hits come from release workflows only (addFound), and egress signatures count for egress only, so
 * the reason changes nothing else. One pass over the hits and one over the release jobs, after every workflow is walked.
 */
export function releaseEgress(ctx: Ctx): void {
  let any = false;
  for (let i = 0; i < ctx.hits.length && !any; i++) any = isEgress(ctx.hits[i] as Hit);
  if (!any) return;
  const guarded = (r: { start: number; first: number }) => {
    for (let i = r.start; i < r.first; i++) {
      const h = ctx.hits[i] as Hit;
      if (isEgress(h) && h.reason === null && h.laterStep !== true) return true;
    }
    return false;
  };
  const open = ctx.releaseJobs.find((r) => !guarded(r));
  if (open === undefined && !ctx.releaseUnread && !ctx.budget.truncated) return;
  const why = open !== undefined
    ? `Egress control runs in some release jobs only: ${open.where} doesn't start with it, so its steps can reach any site.`
    : "Egress control runs in the release jobs pipegen could read, but some release workflows couldn't be read in full, so pipegen can't tell about the rest.";
  for (let i = 0; i < ctx.hits.length; i++) {
    const h = ctx.hits[i] as Hit;
    if (isEgress(h) && h.reason === null) ctx.hits[i] = { ...h, reason: 'some-jobs', partialWhy: why };
  }
}

/**
 * A job-level `uses:`: a local reusable workflow is followed one level; a remote one listed in a signature's
 * reusableWorkflows (Plan P Task 3) counts like that action, with the job's `with:` inputs; any other remote one can't
 * be seen into.
 */
async function callWorkflow(ctx: Ctx, uses: string, c: StepCtx, withObj: Obj): Promise<void> {
  if (!spend(ctx)) return;
  const by = validRef(uses);
  if (!uses.startsWith('./')) {
    const tools = reusableMatches(ctx.sigs, uses);
    if (tools.length === 0) return opaque(ctx, OPAQUE_WHY.remoteWorkflow, by, c);
    const w = lowerInputs(withObj);
    return addFound(ctx, actionFinds(ctx, tools, uses, w, true, c), { ...c, inputsUnread: c.inputsUnread || w.unread });
  }
  if (c.depth > 0) return opaque(ctx, OPAQUE_WHY.secondLevel, by, c);
  const rel = localPath(uses);
  if (rel === 'outside') return opaque(ctx, OPAQUE_WHY.outside, by, c);
  if (rel === null || !WORKFLOW_FILE.test(rel)) return opaque(ctx, OPAQUE_WHY.unreadable, by, c);
  const doc = await readLocal(ctx, rel);
  if ('fail' in doc) return opaque(ctx, doc.fail === 'outside' ? OPAQUE_WHY.outside : OPAQUE_WHY.unreadable, by, c);
  // The called workflow runs on the caller's event (and only when the calling job's `if:` holds).
  await walkWorkflow(ctx, doc.ok, rel, c.fit, 1, `${c.where} → `, c.conditional, c.release);
}
