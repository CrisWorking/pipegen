// PL-E3: Plan G's layout rules (G1: rulings B1, B2 referee side; carries C3, C5a, C7s, BP-6), moved out of referee.ts unchanged. They judge a
// file's role (caller, push file, nightly, called workflow), its triggers, where the gate may sit and a job's `if:`. This module imports no
// value from referee.ts (the types only, erased at build), so referee.ts -> layout-rules.ts is the one direction.
import { isDeepStrictEqual } from 'node:util';
import { activeSafeText as safeText } from '../util/known-values.js';
import { GATE_CHECK_NAME, type CreatedFile, type PipelineDraft } from '../types.js';
import { COMMIT_SHA_RE } from './names.js';
import { show } from './render-error.js';
import { isObj, type Obj, type Parsed } from './yaml-parse.js';
import { centralWorkflowFile, centralWorkflowPath } from './central-path.js';
import { PLAIN_REL_RE } from './tool-flags.js';
import { RenderError } from './render-step.js';
import { triggersOf } from './referee-shared.js';
import {
  CALLER_TRIGGERS, CALLER_WORKFLOW, DEPLOY_PUSH_IF, defaultPushTrigger, featurePushTrigger, IF_VALUES, LOCAL_MERGE_WORKFLOW, NIGHTLY_IF, NIGHTLY_WORKFLOW, PR_CHECK_IF, PR_CHECK_JOB,
  PR_REVIEW_TRIGGER, PUSH_WORKFLOW, REQUIRED_JOB, REQUIRED_NAME, requiredWorkflowForm, SCORECARD_IF, SCORECARD_JOB, WORKFLOW_CONCURRENCY, WORKFLOW_PATH_RE,
} from './job-rules.js';
import type { Expectations, RefereeCheck } from './referee.js';

// ---------- Plan G's layout (G1: rulings B1, B2 referee side; carries C3, C5a, C7s, BP-6) ----------
// Each form is the job-rules.ts constant or builder the renderer uses, compared by equality. A file's role comes from its path and its exact
// triggers, never from what it claims to be: pipegen.yml (the caller: push on the default branch only), the push file (every other branch, no
// gate) and the rest.

/** The source name of the pr-check lookup step among the expected run steps. */
export const PR_CHECK_SOURCE = 'pr-check';
/** G4-R1: the sources of the DAST hand-off step (run job), the archive start (run job) and the raw result's hash check (scrub job). */
export const DAST_HANDOFF_SOURCE = 'dast-handoff';
export const DAST_APP_SOURCE = 'dast-app';
export const DAST_CHECK_SOURCE = 'dast-check';
/** G15a round 4 (b3): the nightly DAST scan's own steps (run job) and the hash check of its raw result (scrub job): nightly file only. */
export const NIGHTLY_DAST_SOURCE = 'nightly-dast';
export const NIGHTLY_DAST_CHECK_SOURCE = 'nightly-dast-check';
/**
 * G15a round 6: the nightly ZAP AF active scan's own steps (its pull and run, in zap-active-run--<svc>), its hand-off (there) and the hash
 * check of its raw result (in zap-active--<svc>): nightly file only. The app start and the archive check are the merge pair's own sources,
 * allowed in the AF run job of the nightly file too (the same steps).
 */
export const NIGHTLY_ZAP_SOURCE = 'nightly-zap';
export const NIGHTLY_ZAP_CHECK_SOURCE = 'nightly-zap-check';
export const ZAP_HANDOFF_SOURCE = 'zap-handoff';
/** G4 (C9r1): the source name of the pre-push head fetch step of the secrets job. */
export const RANGE_FETCH_SOURCE = 'range-fetch';
/** The gate job's own name (the second half of GATE_CHECK_NAME). */
export const GATE_JOB_NAME = GATE_CHECK_NAME.split(' / ')[1] as string;
/** How deep the layout rules follow reusable-workflow calls; a deeper chain is read as holding what they look for (fail closed). */
export const MAX_CALL_DEPTH = 10;

/** The merge caller job of pipegen.yml: the first half of GATE_CHECK_NAME (job `pipegen`, name `pipegen`). */
export const MERGE_CALLER_ID = GATE_CHECK_NAME.split(' / ')[0] as string;
export const isCallerFile = (fc: FileCtx): boolean => fc.file.repo === 'app' && fc.file.path === CALLER_WORKFLOW;
/** G8: the project's central org required workflow (`<name>--required.yml`). */
export const isRequiredFile = (fc: FileCtx): boolean => fc.file.repo === 'central' && typeof fc.draft.profile.repo === 'string' && fc.file.path === centralWorkflowFile(fc.draft.profile.repo, 'required');
/** G17 row 6: the org required workflow's file name form (any project name, any letter case, .yml or .yaml). */
export const REQUIRED_NAME_RE = /--required\.ya?ml$/i;
/** G17 row 5: the files of the B2 layout that may hold or call the gate (judged as written whole, never as a user's edited workflow). */
export function gateLayoutFile(fc: FileCtx): boolean {
  if (fc.file.inserted !== undefined) return false;
  if (fc.file.repo === 'app') return fc.file.path === CALLER_WORKFLOW || fc.file.path === LOCAL_MERGE_WORKFLOW;
  return isRequiredFile(fc) || (typeof fc.draft.profile.repo === 'string' && fc.file.path === centralWorkflowFile(fc.draft.profile.repo, 'merge'));
}
/** Whether a push trigger's value is exactly CALLER_WORKFLOW's form for this draft's default branch (a default branch with no exact form: never). */
export function isDefaultOnlyPush(v: unknown, defaultBranch: string): boolean {
  try { return isDeepStrictEqual(v, defaultPushTrigger(defaultBranch)); } catch (e) { if (e instanceof RenderError) return false; throw e; }
}
export function isFeaturePush(v: unknown, defaultBranch: string): boolean {
  try { return isDeepStrictEqual(v, featurePushTrigger(defaultBranch)); } catch (e) { if (e instanceof RenderError) return false; throw e; }
}
/** Whether a workflow's push may run on a branch other than the default, or on a tag: any push trigger but the exact default-only form (unreadable triggers: yes). */
export function pushOffDefault(on: unknown, triggers: readonly string[] | null, defaultBranch: string): boolean {
  if (triggers === null) return true;
  return triggers.includes('push') && !(isObj(on) && isDefaultOnlyPush(on.push, defaultBranch));
}
/** The exact per-ref concurrency, at the top of one of the two app callers, in a file nothing calls (a called workflow sharing its caller's group deadlocks). */
export function concurrencyFormOk(fc: FileCtx, js: Obj, triggers: readonly string[]): boolean {
  return fc.file.repo === 'app' && (fc.file.path === CALLER_WORKFLOW || fc.file.path === PUSH_WORKFLOW) && !triggers.includes('workflow_call')
    && isDeepStrictEqual(js.concurrency, { ...WORKFLOW_CONCURRENCY });
}
/** pull_request_review exactly in its form, and only in CALLER_WORKFLOW (B1, B2). */
export function prReviewFormOk(fc: FileCtx, js: Obj): boolean {
  return isCallerFile(fc) && isObj(js.on) && isDeepStrictEqual(js.on.pull_request_review, { types: [...PR_REVIEW_TRIGGER.types] });
}
/**
 * The push file (ruling B2), the one file a pr-check skip may sit in: the app's PUSH_WORKFLOW whose only trigger is exactly the
 * every-branch-but-the-default push, or the central `<project>--push.yml` whose only trigger is workflow_call. Neither may hold or call the
 * gate (prCheckIfProblem checks that too).
 */
export function isPushFile(fc: FileCtx): boolean {
  const on = fc.js.on;
  if (fc.file.repo === 'app' && fc.file.path === PUSH_WORKFLOW) return isObj(on) && Object.keys(on).length === 1 && isFeaturePush(on.push, fc.draft.profile.defaultBranch);
  if (fc.file.repo === 'central' && typeof fc.draft.profile.repo === 'string' && fc.file.path === centralWorkflowFile(fc.draft.profile.repo, 'push')) {
    const t = triggersOf(on);
    return t !== null && t.length === 1 && t[0] === 'workflow_call';
  }
  return false;
}

/**
 * Controller ruling G1-R-sec: the push caller, the one workflow allowed to call a push file. The app's PUSH_WORKFLOW whose only trigger is the
 * every-branch-but-the-default push and that holds or calls no gate (C5a refuses one there anyway).
 */
export function isPushCaller(fc: FileCtx): boolean {
  const on = fc.js.on;
  return fc.file.repo === 'app' && fc.file.path === PUSH_WORKFLOW && isObj(on) && Object.keys(on).length === 1 && isFeaturePush(on.push, fc.draft.profile.defaultBranch)
    && !reaches(fc, fc.file.repo, fc.js.jobs, holdsGate);
}
/**
 * Whether a caller job's `uses` names a push file (the central `<project>--push.yml`, or the app's PUSH_WORKFLOW), by the path alone: whether
 * pipegen writes that file or not, so a call can not slip past while the file is missing (judgeCaller refuses that call on its own).
 */
export function callsPushFile(fc: FileCtx, repo: CreatedFile['repo'], uses: unknown): boolean {
  if (typeof uses !== 'string') return false;
  const project = fc.draft.profile.repo;
  const centralPush = typeof project === 'string' ? centralWorkflowFile(project, 'push').toLowerCase() : null;
  if (uses.startsWith('./')) {
    const rel = uses.slice(2).toLowerCase();
    return (repo === 'app' && rel === PUSH_WORKFLOW.toLowerCase()) || (repo === 'central' && rel === centralPush);
  }
  const k = usesKey(uses);
  if (k === null || centralPush === null) return false;
  // any owner's pipelines repo, at any commit: the call is refused whatever the pin (the pin itself is judgeCaller's)
  const m = /^[^/]+\/pipelines\/(.+)$/.exec(k.path);
  return m !== null && m[1] === centralPush;
}

/** The workflow file a caller job's `uses` names, when pipegen is writing it (the same resolution as judgeCaller, without issues: those are its). */
export function calledFileOf(fc: FileCtx, repo: CreatedFile['repo'], uses: unknown): { parsed: Parsed; repo: CreatedFile['repo']; key: string } | undefined {
  if (typeof uses !== 'string') return undefined;
  if (uses.startsWith('./')) {
    const rel = uses.slice(2);
    const key = `${repo}:${rel}`;
    const parsed = WORKFLOW_PATH_RE.test(rel) && PLAIN_REL_RE.test(rel) ? fc.others.get(key) : undefined;
    return parsed === undefined ? undefined : { parsed, repo, key };
  }
  const k = usesKey(uses);
  const central = centralOf(fc.draft);
  if (k === null || central === null || !k.path.startsWith(central.prefix) || k.ref !== central.sha) return undefined;
  const rel = k.path.slice(central.prefix.length);
  const key = `central:${rel}`;
  const parsed = WORKFLOW_PATH_RE.test(rel) ? fc.others.get(key) : undefined;
  return parsed === undefined ? undefined : { parsed, repo: 'central', key };
}
export const stepsOf = (j: Obj): Obj[] => (Array.isArray(j.steps) ? j.steps.filter(isObj) : []);
/** A job or check name as GitHub might match it (G1-R2 m1): trimmed, lower case, spaces collapsed, no space around a slash, slashes collapsed. */
export const normName = (v: unknown): string | undefined => (typeof v === 'string' ? v.trim().toLowerCase().replace(/\s*\/+\s*/g, '/').replace(/\s+/g, ' ') : undefined);
export const GATE_NAMES: ReadonlySet<string> = new Set([normName(GATE_JOB_NAME) as string, normName(GATE_CHECK_NAME) as string]);
/** Whether a name reads as the gate's job or check name once normalized. */
export const gateNameLike = (v: unknown): boolean => { const n = normName(v); return n !== undefined && GATE_NAMES.has(n); };
/** The gate, by any sign: the job id gate (any case), a job named like the gate's check (normalized), or a step in gate mode (whatever action it names). */
export const holdsGate = (id: string, j: Obj): boolean => id.toLowerCase() === 'gate' || gateNameLike(j.name) || stepsOf(j).some((s) => isObj(s.with) && s.with.mode === 'gate');
/** What a scheduled run never holds (C7s): baseline-check and find-run read the event's repository payload, which schedule has not; and the gate (B2). */
export const SCHEDULE_FORBIDDEN_MODES: ReadonlySet<string> = new Set(['baseline-check', 'find-run', 'gate']);
export const scheduleForbidden = (id: string, j: Obj): boolean => id === 'baseline-check' || id === 'gate' || stepsOf(j).some((s) => isObj(s.with) && SCHEDULE_FORBIDDEN_MODES.has(String(s.with.mode)));
/**
 * Whether jobs (and the workflows their caller jobs call, transitively) hold what `hit` looks for. A call that can not be resolved is judgeCaller's
 * issue. G1-R2 m3: a call past MAX_CALL_DEPTH is not followed and never counts as a hit (it would make a job a gate holder); `walk.tooDeep` marks
 * it, and judgeLayoutJobs refuses such a chain on its own.
 */
export function reaches(fc: FileCtx, repo: CreatedFile['repo'], jobs: unknown, hit: (id: string, j: Obj) => boolean, depth = 0, seen: Set<string> = new Set(), walk?: { tooDeep: boolean }): boolean {
  if (!isObj(jobs)) return false;
  for (const [id, j] of Object.entries(jobs)) {
    if (!isObj(j)) continue;
    if (hit(id, j)) return true;
    const c = j.uses === undefined ? undefined : calledFileOf(fc, repo, j.uses);
    if (c === undefined || seen.has(c.key)) continue;
    if (depth >= MAX_CALL_DEPTH) { if (walk !== undefined) walk.tooDeep = true; continue; }
    seen.add(c.key);
    if (reaches(fc, c.repo, c.parsed.js.jobs, hit, depth + 1, seen, walk)) return true;
  }
  return false;
}

/**
 * G1-R2 I1 (ruling B2): each file of the layout runs on its own triggers and nothing else. pipegen.yml: push (default-only, C3), pull_request
 * (bare) and pull_request_review (its form), any of them, no other (workflow_call, workflow_dispatch, merge_group or schedule would let an event
 * that is not a push to the default branch reach its deploy jobs as `push`, or run the gate without a pull request). pipegen-push.yml: exactly
 * the feature push. pipegen-nightly.yml: schedule only (cron entries). A called workflow (any central file, the local merge file, or any file
 * with workflow_call): workflow_call only. Other app workflows are not part of the layout and keep the general trigger list.
 */
export function judgeTriggerSet(fc: FileCtx, js: Obj, triggers: readonly string[] | null): void {
  if (triggers === null) return;   // judgeTop refuses unreadable triggers
  const bad = (m: string): void => fc.add(fc.file.path, 'template', m, undefined, fc.file.repo);
  const on = js.on;
  const app = fc.file.repo === 'app';
  if (app && fc.file.path === CALLER_WORKFLOW) {
    const ok = triggers.every((t) => CALLER_TRIGGERS.includes(t)) && (isObj(on) ? !Object.hasOwn(on, 'pull_request') || on.pull_request === null : triggers.every((t) => t === 'pull_request'));
    if (!ok) bad(`${CALLER_WORKFLOW} runs only on push [<default>], pull_request (with no filter) and pull_request_review [${PR_REVIEW_TRIGGER.types.join(', ')}], nothing else: another trigger could reach its deploy jobs as a push that is not to the default branch, or run the gate without a pull request.`);
    return;
  }
  if (app && fc.file.path === PUSH_WORKFLOW) {
    if (!(isObj(on) && Object.keys(on).length === 1 && isFeaturePush(on.push, fc.draft.profile.defaultBranch))) bad(`${PUSH_WORKFLOW} runs only on the push to every branch but the default (branches-ignore: [<default>]), nothing else.`);
    return;
  }
  if (app && fc.file.path === NIGHTLY_WORKFLOW) {
    const crons = isObj(on) ? on.schedule : undefined;
    const ok = isObj(on) && Object.keys(on).length === 1 && Array.isArray(crons) && crons.length > 0 && crons.every((c) => isObj(c) && Object.keys(c).length === 1 && typeof c.cron === 'string');
    if (!ok) bad(`${NIGHTLY_WORKFLOW} runs only on schedule (its cron entries), nothing else.`);
    return;
  }
  if (isRequiredFile(fc)) {
    // G8: the org required workflow, in its one form (requiredWorkflow, src/layers/locks.ts): pull_request (bare) only, one job that calls the
    // project's central merge workflow at the recorded commit; GitHub runs it from the central repo, so it holds nothing else
    // (review m1) the whole file deep-equals requiredWorkflowForm built from pipegen.yml's merge caller judged in the same call
    const pin = centralOf(fc.draft);
    const want = pin === null ? null : `${centralWorkflowPath(pin.repo, fc.draft.profile.repo)}@${pin.sha}`;
    const callerJobs = fc.others.get(`app:${CALLER_WORKFLOW}`)?.js.jobs;
    const caller = isObj(callerJobs) ? callerJobs[MERGE_CALLER_ID] : undefined;
    const ok = want !== null && isObj(caller) && caller.uses === want && isDeepStrictEqual(js, requiredWorkflowForm(want, { permissions: caller.permissions, secrets: caller.secrets }));
    if (!ok) bad(`The org required workflow runs only on pull_request (with no filter) and holds one job, ${REQUIRED_JOB} named ${REQUIRED_NAME}, that calls the project's central merge workflow at the recorded commit with exactly the permissions and secrets of the merge caller in ${CALLER_WORKFLOW} (judged in the same call), nothing else.`);
    return;
  }
  if (!app || fc.file.path === LOCAL_MERGE_WORKFLOW || triggers.includes('workflow_call')) {
    if (!(triggers.length === 1 && triggers[0] === 'workflow_call')) bad('A called workflow runs only on workflow_call (a central file, the local merge file, or any file with workflow_call): another trigger would run its jobs outside the caller that grants their permissions and passes their secrets.');
  }
}

/** A file pipegen writes whole: C3 (pipegen.yml's push trigger), then the job rules of the layout. */
export function judgeLayout(fc: FileCtx, js: Obj, triggers: readonly string[] | null): void {
  const defaultBranch = fc.draft.profile.defaultBranch;
  if (isCallerFile(fc) && (triggers ?? []).includes('push') && !(isObj(js.on) && isDefaultOnlyPush(js.on.push, defaultBranch))) {
    fc.add(fc.file.path, 'template', `${CALLER_WORKFLOW}'s push trigger must be exactly branches: [${safeText(String(defaultBranch), 100)}] (the default branch, written as a plain name), with no tags, no other branch, no pattern and no path filter (C3): a tag or another branch named like the default would start a run whose head looks trusted.`, undefined, fc.file.repo);
  }
  judgeLayoutJobs(fc, js.on, triggers, js.jobs);
}

/**
 * C5a: a workflow whose push may run on another branch than the default (or a tag) holds no gate job, no job named like the gate and calls no
 * workflow that holds one: a push has no pull request, so its gate result would mean nothing (the gate action refuses to pass there too).
 * C7s (and B2): a workflow with schedule holds no baseline-check, find-run or gate, and calls none. `only`: the jobs pipegen inserted in a user's file.
 */
export function judgeLayoutJobs(fc: FileCtx, on: unknown, triggers: readonly string[] | null, jobs: unknown, only?: readonly string[]): void {
  const picked = !isObj(jobs) ? {} : only === undefined ? jobs : Object.fromEntries(Object.entries(jobs).filter(([id]) => only.includes(id)));
  // controller ruling G1-R-sec: the push file's jobs carry the pr-check skip, so only the push caller (no gate, no pull request) may call it; called
  // from a workflow that holds or calls the gate, or runs on pull requests, the skip would hide scanners the gate reads (a skipped job counts as passed)
  if (!isPushCaller(fc)) {
    for (const [id, j] of Object.entries(picked)) {
      if (isObj(j) && callsPushFile(fc, fc.file.repo, j.uses)) {
        fc.add(fc.file.path, 'not-gate-readable', `The job ${show(id)} calls the push workflow, but only the push caller (${PUSH_WORKFLOW}, whose only trigger is the push to every branch but the default and which holds or calls no gate) may call the push workflow: its jobs skip when the branch has a pull request, which in any other run could hide a check the gate reads (G1-R-sec).`, undefined, fc.file.repo);
      }
    }
  }
  // G17 row 5 (open question 4): the gate is held only in the B2 layout: pipegen.yml (inline or through its merge caller), the local merge
  // file, the project's central merge workflow and the org required workflow that calls it. Any other workflow (ci.yml with workflow_dispatch,
  // a central file, a user's edited workflow) holding or calling the gate is refused; the gate's own run-time refusal stays the second net
  if (!gateLayoutFile(fc) && reaches(fc, fc.file.repo, picked, holdsGate)) {
    fc.add(fc.file.path, 'not-gate-readable', `The workflow holds the gate (or a job named like it, ${GATE_CHECK_NAME}) or calls a workflow that does, outside pipegen's layout: only ${CALLER_WORKFLOW}, ${LOCAL_MERGE_WORKFLOW}, the central <project>--merge.yml and the org required workflow run the gate, on their own triggers.`, undefined, fc.file.repo);
  }
  if (pushOffDefault(on, triggers, fc.draft.profile.defaultBranch) && reaches(fc, fc.file.repo, picked, holdsGate)) {
    fc.add(fc.file.path, 'not-gate-readable', `The workflow runs on pushes to a branch other than the default (or to tags), so it may hold no gate job, no job named like the gate (${GATE_CHECK_NAME}) and call no workflow that holds one (C5a): a push has no pull request, so a gate there decides nothing that can be trusted. The gate runs from ${CALLER_WORKFLOW}, whose push runs on the default branch only, and on pull requests.`, undefined, fc.file.repo);
  }
  // G1-R2 m3: a chain of calls deeper than GitHub runs (or than pipegen follows) is refused outright
  const walk = { tooDeep: false };
  reaches(fc, fc.file.repo, picked, () => false, 0, new Set(), walk);
  if (walk.tooDeep) fc.add(fc.file.path, 'template', `The workflow calls a chain of reusable workflows deeper than ${MAX_CALL_DEPTH} levels, which pipegen does not follow or write.`, undefined, fc.file.repo);
  // G1-R2 m2: triggers pipegen can not read count as schedule (fail closed, as in the push rule)
  if ((triggers === null || triggers.includes('schedule')) && reaches(fc, fc.file.repo, picked, scheduleForbidden)) {
    fc.add(fc.file.path, 'template', 'The workflow runs on schedule, whose event carries no repository payload, so it holds no baseline-check or find-run step, no gate (mode gate), no job baseline-check or gate, and calls no workflow that holds one (C7s); the nightly job is the one gate mode a scheduled run has.', undefined, fc.file.repo);
  }
}

/**
 * A job's `if:` (ruling 4, and G1's two forms). A job that feeds the gate is never skipped on a condition (a skipped job counts as passed);
 * only the gate itself runs always(). Two exact forms besides, each only where it can hide no gate-feeding job: the pr-check skip on a
 * push-layer job of the push file, and the deploy condition on a deploy job of pipegen.yml that needs the gate. Anything else: refused.
 */
export function judgeJobIf(fc: FileCtx, id: string, j: Obj, where: string): void {
  const bad = issueFor(fc);
  // G15a round 3 (PF-3): the weekly condition, exactly, on the job scorecard of the nightly file only; that job never runs without it
  const scorecardJob = id === SCORECARD_JOB && isNightlyFile(fc);
  if (scorecardJob && j.if !== SCORECARD_IF) { bad('template', `${where} is the weekly Scorecard job: it runs only on its own cron entry (if: ${SCORECARD_IF}), never on every nightly run.`); return; }
  if (j.if === SCORECARD_IF) { if (!scorecardJob) bad('template', `${where}: the weekly condition (if: ${SCORECARD_IF}) is written only on the job ${SCORECARD_JOB} of the nightly file.`); return; }
  // G15a-R7 spec 2: the nightly condition, on a steps job of the nightly file only (never the scorecard job, above, or a caller job)
  if (j.if === NIGHTLY_IF) { if (!isNightlyFile(fc) || j.uses !== undefined) bad('template', `${where}: the nightly condition (if: ${NIGHTLY_IF}) is written only on a job of the nightly file.`); return; }
  if (j.if === undefined) return;
  if (j.if === PR_CHECK_IF) { const p = prCheckIfProblem(fc, id, j); if (p !== null) bad('template', `${where}: ${p}`); return; }
  if (j.if === DEPLOY_PUSH_IF) { const p = deployIfProblem(fc, id, j); if (p !== null) bad('template', `${where}: ${p}`); return; }
  if (typeof j.if !== 'string' || !IF_VALUES.has(j.if)) bad('injection', `${where} has an if: pipegen does not write.`);
  else if (!(id === 'gate' && j.if === 'always()')) bad('template', `${where} has if: ${safeText(j.if, 20)}; a job that feeds the gate runs whenever its workflow does (a skipped job counts as passed).`);
}

/** The nightly file: the app's pipegen-nightly.yml, or the project's central nightly workflow (called by it only). */
export function isNightlyFile(fc: FileCtx): boolean {
  if (fc.file.repo === 'app') return fc.file.path === NIGHTLY_WORKFLOW;
  return fc.file.repo === 'central' && typeof fc.draft.profile.repo === 'string' && fc.file.path === centralWorkflowFile(fc.draft.profile.repo, 'nightly');
}

export function prCheckIfProblem(fc: FileCtx, id: string, j: Obj): string | null {
  const what = `the pr-check skip (if: ${PR_CHECK_IF}) is written only on a push-layer job of the push file`;
  if (j.uses !== undefined || id === PR_CHECK_JOB) return `${what}, never on the job ${PR_CHECK_JOB} itself or on a caller job.`;
  if (!isPushFile(fc)) return `${what} (${PUSH_WORKFLOW} whose only trigger is the push to every branch but the default, or the central <project>--push.yml), never in another file.`;
  if (reaches(fc, fc.file.repo, fc.js.jobs, holdsGate)) return `${what}, and this file holds or calls the gate: the skip could hide a job the gate reads (a skipped job counts as passed).`;
  const jobs = isObj(fc.js.jobs) ? fc.js.jobs : {};
  if (!needsList(j.needs).includes(PR_CHECK_JOB) || !isObj(jobs[PR_CHECK_JOB])) return `${what}, on a job that needs the job ${PR_CHECK_JOB} of the same file.`;
  return null;
}

export function deployIfProblem(fc: FileCtx, id: string, j: Obj): string | null {
  const what = `the deploy condition (if: ${DEPLOY_PUSH_IF}) is written only on a deploy job of ${CALLER_WORKFLOW}`;
  if (!isCallerFile(fc)) return `${what}, never in another file.`;
  if (!(isObj(fc.js.on) && isDefaultOnlyPush(fc.js.on.push, fc.draft.profile.defaultBranch))) return `${what}, whose push trigger is exactly branches: [<default>] (here it is not), so the job runs on a push to the default branch only.`;
  const jobs = isObj(fc.js.jobs) ? fc.js.jobs : {};
  const holders = Object.entries(jobs).filter(([hid, hj]) => isObj(hj) && reaches(fc, fc.file.repo, { [hid]: hj }, holdsGate)).map(([hid]) => hid);
  if (holders.includes(id)) return `${what}, never on the gate or the job that calls it (the required check would be skipped on every pull request).`;
  if (!needsList(j.needs).some((n) => typeof n === 'string' && holders.includes(n))) return `${what}, on a job that needs the job holding the gate (${holders.length === 0 ? 'none in this file' : holders.join(', ')}), so it deploys only what passed it.`;
  return null;
}

// ---------- shared with referee.ts (they moved here so this module imports no value from it) ----------
export const usesKey = (uses: string): { path: string; ref: string } | null => {
  const at = uses.lastIndexOf('@');
  return at <= 0 ? null : { path: uses.slice(0, at).toLowerCase(), ref: uses.slice(at + 1) };
};

/**
 * The central `<owner>/pipelines/` prefix and the one commit pipegen recorded for it (ruling 2), or null: the owner must
 * pass GitHub's owner rule again here (an empty or odd owner never makes a prefix), and `draft.centralPin` must name that
 * repo at a 40-character commit. Without it every central `uses` is unknown-pin.
 */
export function centralOf(draft: PipelineDraft): { prefix: string; sha: string; repo: string } | null {
  const owner = draft.profile.owner;
  const pin = draft.centralPin;
  if (typeof owner !== 'string' || !OWNER_RE.test(owner) || pin === undefined || !isObj(pin)) return null;
  if (typeof pin.repo !== 'string' || pin.repo.toLowerCase() !== `${owner.toLowerCase()}/pipelines` || typeof pin.sha !== 'string' || !COMMIT_SHA_RE.test(pin.sha)) return null;
  return { prefix: `${owner.toLowerCase()}/pipelines/`, sha: pin.sha, repo: pin.repo };
}
/** Needs as a list, whatever form they were written in. */
export const needsList = (v: unknown): unknown[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
export const issueFor = (fc: FileCtx) => (check: RefereeCheck, message: string): void => fc.add(fc.file.path, check, message);
export interface FileCtx {
  file: CreatedFile; add: Add; ex: Expectations; draft: PipelineDraft;
  /** the file's own parsed top level (its triggers and jobs: the layout rules of G1 read them) */
  js: Obj;
  /** every parsed workflow and action file, by `<repo>:<path>` */
  others: Map<string, Parsed>;
  /** how many times the name PIPEGEN_DB_PASSWORD sits inside runtime-env steps recognised by content (D4): the only place it may be */
  dbPwOk: number;
  /** G17A-R1 sec M2: every file of the batch, and the app's workflow texts (RefereeDeps.workflowTexts) */
  batch?: readonly CreatedFile[];
  workflowTexts?: ReadonlyMap<string, string>;
}
export type Add = (file: string, check: RefereeCheck, message: string, line?: number, repo?: CreatedFile['repo']) => void;
