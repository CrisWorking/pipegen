// v0.2 Plan G Task 4 (sub-task G7; rulings B3 a, c, e, S11, S15; carries G40, B-T1a, E-b3, G1→G7, G2→G7, G4→G7, G5→G7): the deploy layer.
// Verify first: a deploy runs only after pipegen's `pipegen-verify` job has proved that the deployed commit passed the gate in the trusted
// push run of pipegen.yml (the gate action's find-run mode), that the commit is still the head of the default branch, and that the image
// that run published (its digest artifact, read by the run's id) carries pipegen's signature. pipegen doesn't change what or how the user
// deploys: it only adds the job and a `needs:` entry to the user's deploy jobs, byte for byte, and records the edit (the referee holds it).
//
// - planVerifyInserts: per deploy workflow of the profile. A push deploy whose push runs on the default branch only gets the job; any other
//   trigger (workflow_run included, B3 e: the referee refuses an edit there), a push to other branches or tags, a shape pipegen can not edit
//   without touching the user's bytes, or a deploy job that could run when the check fails, is a DeployGap (listed in PIPEGEN.md as
//   unprotected). S15: the deploy detector is applied per job; when it can tell no deploy job apart, every job waits (shown in the preview).
//   Every edit is a not-proven note (E-b3: no user workflow runs beside real keys, so the proof never runs it).
// - insertVerify / renewVerifyJob: the byte-level edit (and the re-pin's: the inserted job's literals, central-sha and attest's signer
//   digest, move only by rendering the job again into the same place; review G12 m7).
// - releaseJobs: image-publish (the reviewed build-push with push, the digest hand-off; one image per repository in v0.2), for assemble's
//   `deploy` option. Its jobs need the gate (assemble adds `if: DEPLOY_PUSH_IF` and `needs: [pipegen]`), and the sign job needs it.
// - environmentPlan: what `finish` applies: the user's deploy environments (approval reviewers only with the capability and the approval
//   flag, B-T1a: only environments a deploy job really uses) and pipegen-signing whenever the repository has environments; existing ones
//   are read first (created false, their previous settings kept for uninstall).
// - generateCosignKeys: the key pair made by the pinned cosign in a memory-backed folder only (never on disk), removed after.
import { statfsSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import type { Octokit } from '@octokit/rest';
import { Document, isMap, isScalar, isSeq, parseDocument, type Node as YamlNode, type Pair } from 'yaml';
import { callsWorkflow, plainUbuntu, readsContents, strongReason, weakReason } from '../engine/deploy-gating.js';
import { BUILD_PUSH_STEP_ID, HEAD_CHECK_STEP_ID, imageDigestArtifact, publishedImageRepo, PUBLISH_TAG, renderPublishDigestStep } from '../engine/deploy-steps.js';
import type { RateClock } from '../engine/github-rate.js';
import { CALLER_WORKFLOW, isDangerousName, LOCAL_MERGE_WORKFLOW, NIGHTLY_WORKFLOW, PUSH_WORKFLOW, type RenderedStep } from '../engine/job-rules.js';
import { publishedImageServices } from '../engine/needs.js';
import type { PlatformActions } from '../engine/pin.js';
import { gatedIfAllowed, SIGNING_ENVIRONMENT, triggersOf } from '../engine/referee.js';
import { RenderError } from '../engine/render-error.js';
import { renderJobPrelude, renderPlatformStep, stepsToYaml } from '../engine/render-step.js';
import { parseYaml } from '../engine/yaml-parse.js';
import { clockOf } from '../github/client.js';
import { makeCosignKeyPair, type CosignExec, type CosignResolver } from '../deliver/cosign-keys.js';
import { readEnv } from '../deliver/deliver.js';
import { DeliverError } from '../deliver/git-data.js';
import { jobDeploys } from '../read/workflows.js';
import type { Capabilities, CreatedFile, EnvSettings, ExistingWorkflow, NotProven, PipegenInserted, PipelineDraft, RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { AssembleError, egressStepFor, JOB_MINUTES, JOB_RUNNER, packageSets, type Job } from './jobs.js';

// ---------- types ----------

/** How a deploy workflow is started: push, workflow_run, or anything else (any trigger that is not push or workflow_run makes it `other`). */
export type DeployTrigger = 'push' | 'workflow_run' | 'other';
/** A deploy workflow pipegen does not protect, with why: listed in PIPEGEN.md as unprotected (G9 renders it). */
export interface DeployGap { path: string; triggers: string[]; why: string }
/** One insertion into the user's file: the bytes pipegen added at an offset of the original (offsets of the original, ascending). */
export interface Insertion { at: number; text: string }
/** An edited deploy workflow. `inserted` is the referee's mark (CreatedFile.inserted); `insertions` the exact bytes (Review Focus 2). */
export interface VerifyInsert { path: string; text: string; inserted: PipegenInserted; insertions: Insertion[]; file: CreatedFile }
/** What planVerifyInserts gives deliver: the edited files, the gaps, the not-proven notes (E-b3), the preview lines (S15) and notes. */
export interface VerifyPlan { inserts: VerifyInsert[]; gaps: DeployGap[]; notProven: NotProven[]; preview: string[]; notes: string[] }
/** One environment `finish` applies (plan Task 4 "Environments"). */
export interface EnvironmentPlan { name: string; created: boolean; previous?: EnvSettings; branchPolicy: 'default-only'; reviewers: boolean }

/** The verify job's id: the referee's permission and step tables are keyed by it (assemble.ts VERIFY_JOB_ID). */
const VERIFY_JOB = 'pipegen-verify';
/** pipegen's own workflows: never a user's deploy workflow to edit. */
const OWN_WORKFLOWS: ReadonlySet<string> = new Set([CALLER_WORKFLOW, PUSH_WORKFLOW, NIGHTLY_WORKFLOW, LOCAL_MERGE_WORKFLOW]);
/** The permissions a user's workflow may set at the top without refusing the insert (the referee's judgeUserTop: the verify job's ceiling). */
const VERIFY_CEILING: Readonly<Record<string, number>> = Object.freeze({ contents: 1, actions: 1, packages: 1, attestations: 1 });
const LEVEL: Readonly<Record<string, number>> = Object.freeze({ none: 0, read: 1, write: 2 });

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
const show = (s: unknown): string => JSON.stringify(safeText(String(s), 100));
const fail = (m: string): never => { throw new AssembleError(m); };
/** Not an edit pipegen can make without touching the user's bytes: becomes a gap. */
class EditRefused extends Error {}
const refuse = (m: string): never => { throw new EditRefused(m); };

// ---------- triggers ----------

/** 'push' when push is the only trigger, 'workflow_run' when that is the only one, else 'other' (plan Task 4). */
export function deployTriggers(wf: Pick<ExistingWorkflow, 'triggers'>): DeployTrigger {
  const t = Array.isArray(wf.triggers) ? [...new Set(wf.triggers)] : [];
  if (t.length === 1 && t[0] === 'push') return 'push';
  if (t.length === 1 && t[0] === 'workflow_run') return 'workflow_run';
  return 'other';
}

/** Why a push trigger is not "the default branch only" (a filter of exactly that branch, no tags), or null. */
function pushBranchProblem(on: unknown, defaultBranch: string): string | null {
  const fix = `; pipegen's check passes only on the default branch, so limit its push to \`branches: [${safeText(defaultBranch, 100)}]\``;
  const push = isObj(on) ? on.push : undefined;
  if (!isObj(push)) return `its push runs on every branch and tag${fix}`;
  if (push['branches-ignore'] !== undefined || push.tags !== undefined || push['tags-ignore'] !== undefined) return `its push also runs on tags or on other branches${fix}`;
  const b = push.branches;
  const list = typeof b === 'string' ? [b] : Array.isArray(b) ? b : null;
  if (list === null || list.length === 0) return `its push runs on every branch${fix}`;
  if (!list.every((x) => x === defaultBranch)) return `its push runs on other branches too${fix}`;
  return null;
}

// ---------- the byte-level edit ----------

const lineStart = (text: string, at: number): number => text.lastIndexOf('\n', at - 1) + 1;
/** The column of `at` when only spaces come before it on its line, else null. */
function spacesBefore(text: string, at: number): number | null {
  const from = lineStart(text, at);
  return /^ *$/.test(text.slice(from, at)) ? at - from : null;
}
const indentLines = (text: string, n: number): string => text.split('\n').map((l) => (l === '' ? l : `${' '.repeat(n)}${l}`)).join('\n');

/** The verify job as YAML, keyed by its id, at indent 0, without a trailing newline (steps written by stepsToYaml, like pipegen's own files). */
export function verifyJobYaml(verify: Job): string {
  const doc = new Document();
  const { steps: _s, ...rest } = verify;
  doc.contents = doc.createNode({ [VERIFY_JOB]: rest });
  doc.setIn([VERIFY_JOB, 'steps'], stepsToYaml(verify.steps));
  return doc.toString({ lineWidth: 0 }).replace(/\n+$/, '');
}

interface JobsNode { map: ReturnType<typeof jobsMapOf>; doc: ReturnType<typeof parseDocument> }
/** The block `jobs:` map of a workflow's text, or a refusal (a flow map, no jobs, an anchor or alias at the top of it). */
function jobsMapOf(doc: ReturnType<typeof parseDocument>) {
  const jobs = doc.get('jobs', true);
  if (!isMap(jobs) || jobs.flow === true || jobs.items.length === 0) return refuse('its jobs are not a block map pipegen can add a job to');
  return jobs;
}
function parsedDoc(text: string): JobsNode {
  const doc = parseDocument(text, { uniqueKeys: true });
  if (doc.errors.length > 0) refuse('it is not YAML pipegen can read');
  return { doc, map: jobsMapOf(doc) };
}
const pairOf = (map: { items: Pair[] }, key: string): Pair<YamlNode, YamlNode> | undefined => map.items.find((p) => isScalar(p.key) && p.key.value === key) as Pair<YamlNode, YamlNode> | undefined;

/** The file's line ending: CRLF when the file uses it, so every line pipegen adds ends the same way (G7-R1 minor). */
const eolOf = (text: string): string => (text.includes('\r\n') ? '\r\n' : '\n');
/** The head check the verify job holds (the same step goes first into every gated job that has steps), or a refusal. */
function headCheckOf(verify: Job): RenderedStep {
  const h = verify.steps.find((s) => s.id === HEAD_CHECK_STEP_ID);
  return h === undefined ? refuse(`the ${VERIFY_JOB} job has no head check`) : h;
}
/** One step as a block list item at indent 0, without a trailing newline (stepsToYaml, like the verify job's steps). */
function stepItemYaml(step: RenderedStep): string {
  const doc = new Document();
  doc.contents = stepsToYaml([step]);
  return doc.toString({ lineWidth: 0 }).replace(/\n+$/, '');
}
/** The parsed form of a step (what a reader of the edited file sees), to compare a job's first step with. */
const stepJs = (step: RenderedStep): unknown => (parseDocument(stepItemYaml(step)).toJS() as unknown[])[0];

/** Insertion order at one offset (spec review I1): needs first, then the head-check step, then the job (so a job that ends with its needs keeps them). */
const NEEDS = 0;
const STEP = 1;
const JOB = 2;

/**
 * Adds the verify job and a `needs: pipegen-verify` entry to each of `deployJobs`, puts pipegen's head check (the verify job's own, exactly)
 * as the FIRST step of each of them that has steps (G7-R1 sec I1: it runs inside the deploy job, after any approval wait and on every
 * re-run), and changes nothing else (Review Focus 2): the job goes at the end of the block `jobs:` map, at the indentation of the user's
 * job keys; a need goes into a one-line flow list before its `]`, as a new item of a block list at that list's indentation, around a single
 * job id written plain (`needs: build` becomes `needs: [build, pipegen-verify]`), or as a new first line `needs: [pipegen-verify]` of a job
 * that has none; the head check goes before the first item of the job's block `steps:` list, at its indentation. At one offset the needs go
 * in before the job (spec review I1). Lines end like the file's (CRLF stays CRLF). Then the result is checked the way the referee checks it:
 * the file without pipegen's job, needs and head checks is the original exactly (parsed), and the job is the verify job exactly; anything
 * else throws (a gap).
 */
export function insertVerify(original: string, deployJobs: readonly string[], verify: Job, needsOnly: readonly string[] = []): { text: string; inserted: PipegenInserted; insertions: Insertion[] } {
  if (needsOnly.some((id) => !deployJobs.includes(id))) refuse('a job that waits without the head check must be one it gates');
  if (deployJobs.length === 0) refuse('no job to gate');
  const { map } = parsedDoc(original);
  if (pairOf(map, VERIFY_JOB) !== undefined) refuse(`it already has a job named ${VERIFY_JOB}; rename that job, then run pipegen again`);
  const eol = eolOf(original);
  const nl = (t: string): string => t.replace(/\r?\n/g, eol);
  const head = headCheckOf(verify);
  const ranked: (Insertion & { rank: number })[] = [];
  const add = (at: number, text: string, rank: number): void => { ranked.push({ at, text: nl(text), rank }); };
  const first = map.items[0]?.key as YamlNode | undefined;
  const keyAt = first?.range?.[0];
  const indent = keyAt === undefined ? null : spacesBefore(original, keyAt);
  const end = map.range?.[1];
  if (indent === null || end === undefined) return refuse('its job names do not each start their own line');
  const headJobs: string[] = [];
  for (const id of [...new Set(deployJobs)]) {
    const p = pairOf(map, id);
    if (p === undefined || !isMap(p.value) || p.value.flow === true || p.value.items.length === 0) refuse(`its job ${show(id)} is written in { } on one line; write it as an indented block, then run pipegen again`);
    const job = (p as Pair<YamlNode, YamlNode>).value as unknown as { items: Pair[] };
    const needs = pairOf(job, 'needs');
    if (needs === undefined) {
      const k = job.items[0]?.key as YamlNode | undefined;
      const at = k?.range?.[0];
      const col = at === undefined ? null : spacesBefore(original, at);
      if (at === undefined || col === null) return refuse(`the keys of its job ${show(id)} do not each start their own line`);
      add(lineStart(original, at), `${' '.repeat(col)}needs: [${VERIFY_JOB}]\n`, NEEDS);
    } else {
      const v = needs.value;
      const r = v?.range;
      if (v === null || v === undefined || r === undefined || r === null) return refuse(`the needs of its job ${show(id)} are empty; list the jobs it waits for, or remove the needs line`);
      if (v.anchor !== undefined || (isScalar(v) && v.type !== 'PLAIN')) refuse(`the needs of its job ${show(id)} use a YAML anchor or a quoted job name; write the job names plainly`);
      if (isScalar(v)) {
        if (typeof v.value !== 'string' || original.slice(r[0], r[1]) !== v.value) refuse(`the needs of its job ${show(id)} are not one plain job name`);
        add(r[0], '[', NEEDS);
        add(r[1], `, ${VERIFY_JOB}]`, NEEDS);
      } else if (isSeq(v) && v.flow === true) {
        if (/\r?\n/.test(original.slice(r[0], r[1]))) refuse(`its job ${show(id)} lists its needs over several lines inside [ ]; write them on one line, or as a - list, then run pipegen again`);
        const close = original.lastIndexOf(']', r[1] - 1);
        if (close < r[0]) return refuse(`the needs of its job ${show(id)} do not end with ]`);
        add(close, v.items.length === 0 ? VERIFY_JOB : `, ${VERIFY_JOB}`, NEEDS);
      } else if (isSeq(v) && v.items.length > 0) {
        const item = v.items[0] as YamlNode;
        const dash = item.range === undefined || item.range === null ? -1 : original.lastIndexOf('-', item.range[0] - 1);
        const col = dash < 0 ? null : spacesBefore(original, dash);
        if (col === null) return refuse(`the needs list of its job ${show(id)} does not start each item on its own line`);
        const lead = r[1] > 0 && original[r[1] - 1] !== '\n' ? '\n' : '';
        add(r[1], `${lead}${' '.repeat(col)}- ${VERIFY_JOB}\n`, NEEDS);
      } else refuse(`the needs of its job ${show(id)} are not a list of job names`);
    }
    // G7-R1 sec I1: the head check, first, in every gated job that has steps (a call of another workflow has none)
    // G7-R3: a WEAK job that can not take the step (needsOnly) waits with needs only
    if (pairOf(job, 'uses') !== undefined || needsOnly.includes(id)) continue;
    const steps = pairOf(job, 'steps');
    const sv = steps?.value;
    if (steps === undefined || !isSeq(sv) || sv.flow === true || sv.items.length === 0) refuse(`its job ${show(id)} has no block list of steps to start with pipegen's head check; write its steps as a - list, then run pipegen again`);
    const item0 = (sv as unknown as { items: YamlNode[] }).items[0] as YamlNode;
    const dash = item0.range === undefined || item0.range === null ? -1 : original.lastIndexOf('-', item0.range[0] - 1);
    const col = dash < 0 ? null : spacesBefore(original, dash);
    if (col === null) return refuse(`the steps of its job ${show(id)} do not start each item on its own line`);
    add(lineStart(original, dash), `${indentLines(stepItemYaml(head), col)}\n`, STEP);
    headJobs.push(id);
  }
  // the job: at the end of the jobs map (its value end is the start of the line after the last job, or the end of the text), after the needs
  const lead = end > 0 && original[end - 1] !== '\n' ? '\n' : '';
  add(end, `${lead}${indentLines(verifyJobYaml(verify), indent)}\n`, JOB);
  ranked.sort((a, b) => a.at - b.at || a.rank - b.rank);
  let text = '';
  let from = 0;
  for (const i of ranked) { text += original.slice(from, i.at) + i.text; from = i.at; }
  text += original.slice(from);
  const inserted: PipegenInserted = { original, jobs: [VERIFY_JOB], needs: [...new Set(deployJobs)].map((job) => ({ job, added: [VERIFY_JOB] })), headCheck: headJobs, ...(needsOnly.length > 0 ? { needsOnly: [...new Set(needsOnly)] } : {}) };
  checkEdit(text, inserted, verify);
  return { text, inserted, insertions: ranked.map(({ at, text: t }) => ({ at, text: t })) };
}

/**
 * The referee's check of an edited workflow (judgeEdited), done before the file leaves: the edit parses in the user mode, its verify job is
 * exactly `verify`, every job the mark gates still needs it (sec M4), every job of `headCheck` starts with the verify job's head check
 * exactly, and without pipegen's job, needs and head checks it is the original exactly.
 */
function checkEdit(text: string, mark: PipegenInserted, verify: Job): void {
  const now = parseYaml(text, 'user');
  const was = parseYaml(mark.original, 'user');
  if (!('parsed' in now) || !('parsed' in was)) return refuse('with pipegen\'s job added the file would not be valid YAML');
  const jobs = now.parsed.js.jobs as Obj;
  if (!isDeepStrictEqual(jobs[VERIFY_JOB], parseDocument(verifyJobYaml(verify)).toJS()[VERIFY_JOB])) refuse(`the ${VERIFY_JOB} job in the file is not the one pipegen writes`);
  const rest = structuredClone(now.parsed.js);
  const restJobs = rest.jobs as Obj;
  delete restJobs[VERIFY_JOB];
  const origJobs = was.parsed.js.jobs as Obj;
  for (const n of mark.needs) {
    const j = restJobs[n.job];
    if (!isObj(j)) return refuse(`the job ${show(n.job)} is no longer in the file`);
    const list = Array.isArray(j.needs) ? j.needs : j.needs === undefined ? [] : [j.needs];
    for (const a of n.added) if (!list.includes(a)) refuse(`the job ${show(n.job)} no longer waits for ${a}; add ${a} back to its needs`);
    const kept = list.filter((x) => !n.added.includes(x as string));
    const before = (origJobs[n.job] as Obj).needs;
    if (before === undefined && kept.length === 0) delete j.needs;
    else if (typeof before === 'string' && kept.length === 1) j.needs = kept[0];
    else j.needs = kept;
  }
  const want = stepJs(headCheckOf(verify));
  for (const id of mark.headCheck ?? []) {
    const j = restJobs[id];
    const steps = isObj(j) && Array.isArray(j.steps) ? j.steps : [];
    if (!isDeepStrictEqual(steps[0], want)) refuse(`the job ${show(id)} does not start with pipegen's head check; put it back as the job's first step`);
    steps.shift();
  }
  if (!isDeepStrictEqual(rest, was.parsed.js)) refuse('pipegen could not add its job without changing the rest of the file');
}

/**
 * The re-pin (review G12 m7): the inserted verify job's literals (find-run's central-sha, attest's --signer-digest, the key-env hash) live in
 * the user's file, where swapPins can not move them. They move only by rendering the job again from the new draft into exactly the bytes of
 * the old one: the job's text is replaced, nothing else changes, and the result is checked like a fresh insert against `original`.
 */
export function renewVerifyJob(text: string, mark: PipegenInserted, verify: Job): string {
  const { map } = parsedDoc(text);
  const p = pairOf(map, VERIFY_JOB);
  const from = p?.key?.range?.[0];
  const to = p?.value?.range?.[1];
  const col = from === undefined ? null : spacesBefore(text, from);
  if (p === undefined || from === undefined || to === undefined || col === null) return refuse(`the file holds no ${VERIFY_JOB} job pipegen can renew`);
  const start = lineStart(text, from);
  const tail = text.slice(start, to).endsWith('\n') ? eolOf(text) : '';
  const out = `${text.slice(0, start)}${indentLines(verifyJobYaml(verify), col).replace(/\n/g, eolOf(text))}${tail}${text.slice(to)}`;
  checkEdit(out, mark, verify);
  return out;
}

// ---------- the plan per deploy workflow ----------

/**
 * Why the parts of a user's workflow that apply to pipegen's job too refuse the insert (the referee's judgeUserTop, asked first so the
 * workflow is a gap and not a refused delivery), or null.
 */
function userTopProblem(js: Obj): string | null {
  const env = js.env;
  if (env !== undefined && (!isObj(env) || Object.entries(env).some(([k, v]) => isDangerousName(k) || (typeof v === 'string' && v.includes('${{'))))) return 'its workflow-wide env would reach pipegen\'s job (a name that changes how tools run, or an expression)';
  const d = js.defaults;
  if (d !== undefined) {
    const run = isObj(d) ? d.run : undefined;
    const ok = isObj(d) && Object.keys(d).every((k) => k === 'run') && isObj(run) && Object.keys(run).every((k) => k === 'shell') && (run.shell === undefined || run.shell === 'bash' || run.shell === 'sh');
    if (!ok) return 'its defaults would change how pipegen\'s steps run';
  }
  const p = js.permissions;
  if (p !== undefined) {
    if (!isObj(p)) return 'it sets one permission level for every job (read-all or write-all), more than pipegen\'s job may have';
    for (const [k, v] of Object.entries(p)) {
      const level = typeof v === 'string' && Object.hasOwn(LEVEL, v) ? LEVEL[v] as number : undefined;
      if (level === undefined || level > (Object.hasOwn(VERIFY_CEILING, k) ? VERIFY_CEILING[k] as number : 0)) return 'its workflow-wide permissions are more than pipegen\'s job may have';
    }
  }
  return null;
}

/** The jobs an insert started with the head check. */
const headCheckJobs = (mark: PipegenInserted): string[] => mark.headCheck ?? [];
/** G7-R-sec1: every step's if: of a job runs only when the steps before it passed (the job-level rule, gatedIfAllowed, per step). */
const stepsGated = (job: unknown): boolean => isObj(job) && (!Array.isArray(job.steps) || job.steps.every((st) => !isObj(st) || gatedIfAllowed(st.if)));

/**
 * The verify inserts of a draft's deploy workflows (see the file header). `texts`: each workflow's text as read (path → text); `verify`: the
 * verify job (assemble's AssembledFiles.verify; null when the deploy part is skipped, and then nothing is inserted and nothing is a gap).
 */
export function planVerifyInserts(draft: PipelineDraft, texts: ReadonlyMap<string, string>, verify: Job | null): VerifyPlan {
  const out: VerifyPlan = { inserts: [], gaps: [], notProven: [], preview: [], notes: [] };
  if (verify === null) return out;
  const def = draft.profile.defaultBranch;
  for (const wf of draft.profile.existingWorkflows) {
    if (wf.deploys !== true || OWN_WORKFLOWS.has(wf.path)) continue;
    const gap = (why: string, triggers: string[] = Array.isArray(wf.triggers) ? [...wf.triggers] : []): void => { out.gaps.push({ path: wf.path, triggers, why }); };
    const text = texts.get(wf.path);
    if (typeof text !== 'string') { gap('pipegen could not read this workflow, so it adds no check before its deploy'); continue; }
    const parsed = parseYaml(text, 'user');
    if (!('parsed' in parsed)) { gap(`pipegen can not edit it safely (${safeText(parsed.problems.join('; '), 200)})`); continue; }
    const js = parsed.parsed.js;
    const triggers = triggersOf(js.on);
    if (triggers === null) { gap('its triggers can not be read; write `on:` as a name, a list or a map of events'); continue; }
    const kind = deployTriggers({ triggers });
    if (kind === 'workflow_run') { gap('it deploys after another workflow run (workflow_run), which runs with full rights on what that run produced, so pipegen adds no check to it; to have the check, deploy from a push to the default branch', triggers); continue; }
    if (kind === 'other') { gap(`it is started by ${triggers.filter((t) => t !== 'push').map((t) => safeText(t, 40)).join(', ') || 'no push'}, not only by a push, so pipegen adds no check to it; to have the check, start it only on a push to the default branch`, triggers); continue; }
    const branch = pushBranchProblem(js.on, def);
    if (branch !== null) { gap(branch, triggers); continue; }
    const top = userTopProblem(js);
    if (top !== null) { gap(`pipegen can not add its job: ${top}`, triggers); continue; }
    const jobs = isObj(js.jobs) ? js.jobs : {};
    const ids = Object.keys(jobs);
    // S15, G7-R1 sec I2, G7-R3: why each job waits (src/engine/deploy-gating.ts). When the detector tells no job apart, every job waits (a
    // STRONG reason: pipegen could not tell). The workflow-level gap rules apply to STRONG jobs only; a WEAK job (only its runner or vars)
    // never makes the workflow a gap
    const found = ids.filter((id) => jobDeploys(jobs[id]));
    const strong = new Map<string, string>();
    const weak = new Map<string, string>();
    for (const id of ids) {
      const sr = found.length === 0 ? 'pipegen could not tell which job deploys, so every job waits' : strongReason(jobs[id], js.permissions);
      if (sr !== null) { strong.set(id, sr); continue; }
      const wr = weakReason(jobs[id]);
      if (wr !== null) weak.set(id, wr);
    }
    const why = (id: string): string => `${show(id)} (${strong.get(id) ?? weak.get(id) ?? ''})`;
    const strongIds = [...strong.keys()];
    const ungated = strongIds.filter((id) => !gatedIfAllowed(isObj(jobs[id]) ? (jobs[id] as Obj).if : undefined));
    if (ungated.length > 0) { gap(`its job ${ungated.map(why).join(', ')} has an if: that could run it even when pipegen's check fails (always(), failure(), or a top-level ||); change it to success() && <your condition>`, triggers); continue; }
    // G7-R-sec1: a later step whose if: can run when an earlier step failed (always(), failure(), cancelled(), a top-level ||) would still
    // deploy after pipegen's head check failed, so such a job is not protected: the workflow is a gap
    const stepIfs = strongIds.filter((id) => !callsWorkflow(jobs[id]) && !stepsGated(jobs[id]));
    if (stepIfs.length > 0) { gap(`a step of its job ${stepIfs.map(why).join(', ')} has an if: that could run it after pipegen's head check failed (always(), failure(), cancelled(), or a top-level ||); change it to success() && <your condition>`, triggers); continue; }
    const noContents = strongIds.filter((id) => !callsWorkflow(jobs[id]) && !readsContents(jobs[id], js.permissions));
    if (noContents.length > 0) { gap(`its job ${noContents.map(why).join(', ')} sets permissions without contents: read, which pipegen's head check in that job needs to read the branch; add contents: read to that job's permissions`, triggers); continue; }
    // G7-R3 1: a WEAK job whose own if: defeats needs is left out (said so); else it waits, with the head check only when it can take it
    const weakOut = [...weak.keys()].filter((id) => !gatedIfAllowed(isObj(jobs[id]) ? (jobs[id] as Obj).if : undefined));
    const weakIn = [...weak.keys()].filter((id) => !weakOut.includes(id));
    const needsOnly = weakIn.filter((id) => !(plainUbuntu(jobs[id]) && stepsGated(jobs[id]) && readsContents(jobs[id], js.permissions)));
    const deployJobs = ids.filter((id) => strong.has(id) || weakIn.includes(id));
    const left = ids.filter((id) => !strong.has(id) && !weak.has(id));
    let edit: ReturnType<typeof insertVerify>;
    try { edit = insertVerify(text, deployJobs, verify, needsOnly); } catch (e) {
      if (!(e instanceof EditRefused || e instanceof RenderError)) throw e;
      gap(`pipegen can not add its check without changing the rest of the file: ${safeText(e.message, 200)}`, triggers);
      continue;
    }
    const file: CreatedFile = { path: wf.path, content: edit.text, part: 'deploy-verify', reason: `Adds the ${VERIFY_JOB} job, which proves the commit passed the gate (and, for an image, that pipegen signed it) before ${deployJobs.length === 1 ? 'the deploy job runs' : 'the deploy jobs run'}, and starts each of them with pipegen's head check, except a job that calls another workflow, or one pipegen gates only for its runner or vars and can not start with the check (see the notes).`, repo: 'app', inserted: edit.inserted };
    out.inserts.push({ path: wf.path, text: edit.text, inserted: edit.inserted, insertions: edit.insertions, file });
    out.preview.push(`${wf.path}: pipegen adds the job ${VERIFY_JOB}, and ${deployJobs.map(show).join(', ')} ${deployJobs.length === 1 ? 'waits' : 'wait'} for it${found.length === 0 ? ' (pipegen could not tell which job deploys, so every job waits)' : ''}.`);
    // G7-R3: each gated job's reason (why pipegen counts it as a deploy)
    if (found.length > 0) for (const id of deployJobs) out.preview.push(`${wf.path}: ${show(id)} counts as a deploy job: ${strong.get(id) ?? weak.get(id) ?? ''}.`);
    for (const id of weakOut) {
      const line = `${wf.path}: ${show(id)} may deploy (${weak.get(id) ?? ''}), but its if: could run it even when pipegen's check fails, so pipegen leaves it out; change its if: to success() && <your condition> to have it wait for ${VERIFY_JOB}.`;
      out.preview.push(line);
      out.notes.push(line);
    }
    for (const id of needsOnly) {
      const line = `${wf.path}: ${show(id)} waits for ${VERIFY_JOB} but gets no head check (${weak.get(id) ?? ''}; it is not on GitHub's ubuntu runner, or has a step that runs after a failure, or no contents: read), so it waits for the check; an older commit can still run after an approval wait or a re-run of this job alone. Re-run all jobs (never this job alone) after a newer commit.`;
      out.preview.push(line);
      out.notes.push(line);
    }
    for (const id of left) {
      const line = `${wf.path}: ${show(id)} does not wait for ${VERIFY_JOB}: it shows no deploy, uses no secret but the workflow token, has only read permissions, no environment, calls no other workflow, runs on a GitHub-hosted runner, and reads no configuration variable.`;
      out.preview.push(line);
      out.notes.push(line);
    }
    for (const id of deployJobs.filter((x) => callsWorkflow(jobs[x]))) {
      // G7-R2 3 (sec M1): what is not checked for such a job; the BINDING carry to G13 puts the head check into a local called workflow's jobs
      out.notes.push(`${wf.path}: the job ${show(id)} calls another workflow, so pipegen can not start it with its head check: only ${VERIFY_JOB} checks that the commit is still the head of the default branch, before the job starts. So an older commit can still deploy when the called workflow waits for an approval and a newer commit ships first, or when someone re-runs this job (or "re-run failed jobs") on an older run. Approve deploys in order, re-run all jobs (never this job alone) after a newer commit, or move the deploy into a job with steps.`);
    }
    // G7-R2 1c: the head check runs on the job's own runner or container: anything but GitHub's ubuntu runner may lack bash, curl or jq (it
    // fails closed and says which tool; the job stays gated)
    for (const id of headCheckJobs(edit.inserted).filter((x) => !plainUbuntu(jobs[x]))) {
      const line = `${wf.path}: ${show(id)} runs pipegen's head check on its own runner or container: the check needs bash, curl and jq on this runner (on its PATH under /usr/local/bin, /usr/bin or /bin), or every deploy of that job stops with a message naming the missing tool.`;
      out.preview.push(line);
      out.notes.push(line);
    }
    // G7-R2 4 (sec M3): a push filtered by paths: a newer commit may start no deploy, and the older one's head check then refuses it
    const push = isObj(js.on) && isObj(js.on.push) ? js.on.push : {};
    if (push.paths !== undefined || push['paths-ignore'] !== undefined) {
      out.preview.push(`${wf.path}: its push only for some paths starts a deploy, so a newer commit that changes none of them deploys nothing while it stops an older one.`);
      out.notes.push(`${wf.path}: its push starts a deploy only for some paths. pipegen's head check refuses an older commit once a newer commit is on the default branch, and a newer commit that starts no deploy (it changes none of those paths) ships nothing. When that happens, push again or re-run all jobs on the newest commit.`);
    }
    out.notProven.push({ part: 'deploy-verify', reason: `pipegen's edit of ${wf.path} (the ${VERIFY_JOB} job, its needs and the head checks) is not proven: the proof never runs a user's workflow beside real keys, so only the referee checked it.`, missingSecrets: [] });
  }
  if (out.inserts.length > 0) {
    out.notes.push(`The ${VERIFY_JOB} job outputs the verified image digest (needs.${VERIFY_JOB}.outputs.digest): a signature protects only a deploy that uses that digest.`);
    // G7-R1 sec I1 (for G9's PIPEGEN.md): what the head check in the deploy job covers, and how to re-run and queue deploys
    out.notes.push(`Each deploy job starts with pipegen's head check, except a job that calls another workflow, or one pipegen gates only for its runner or vars and can not start with the check (see the notes), so a deploy that waited for an approval, or a re-run of an older run, stops once a newer commit is on the default branch. When a deploy fails, use "Re-run all jobs": "Re-run failed jobs" reuses ${VERIFY_JOB}'s earlier result. To keep two deploys from overlapping, give each deploy job a concurrency group, for example \`concurrency: { group: deploy-production, cancel-in-progress: false }\`.`);
  }
  return out;
}

// ---------- the release jobs ----------

/**
 * The deploy layer's own jobs for pipegen.yml (assemble's `deploy` option): image-publish when the plan publishes an image
 * (publishedImageServices; one per repository in v0.2), else none. It runs repo code (the Dockerfile, inside BuildKit) with packages: write
 * (the referee's documented residual), logs in to ghcr.io with the job's token, builds and pushes the root service's Dockerfile with the
 * reviewed build-push (no cache), then writes and uploads the pushed digest (the sign job and the verify job read it). No secret of the app.
 */
export function releaseJobs(draft: PipelineDraft, deps: { platform: PlatformActions }): Record<string, Job> {
  if (draft.skipped.some((s) => s.part === 'deploy')) return {};
  const services = publishedImageServices(draft.profile, draft.capabilities);
  if (services.length === 0) return {};
  if (services.length > 1) fail(`pipegen publishes one image per repository in v0.2, and this plan would publish ${services.length} (${services.map(show).join(', ')}).`);
  const name = services[0] as string;
  const svc = draft.profile.services.find((s) => s.name === name);
  if (svc === undefined || typeof svc.dockerfile !== 'string') return fail(`The service ${show(name)} has no Dockerfile to publish.`);
  let repo: string;
  try { repo = publishedImageRepo(draft.profile.owner, draft.profile.repo, name); } catch (e) { if (e instanceof RenderError) return fail(e.message); throw e; }
  const planned = draft.signing?.images ?? [];
  if (planned.some((i) => i.service === name && i.repo !== repo)) fail(`The signing plan signs ${show(planned.find((i) => i.service === name)?.repo)}, but pipegen publishes the image of ${show(name)} as ${show(repo)}.`);
  const artifact = imageDigestArtifact(name);
  let steps;
  try {
    steps = [
      egressStepFor(['dockerhub', 'ghcr', ...packageSets([svc])], { userSecret: false, dockerNetworks: true, job: 'image-publish' }),
      ...renderJobPrelude({}, deps.platform).steps,
      renderPlatformStep('docker-login', deps.platform, { username: '${{ github.actor }}', password: '${{ secrets.GITHUB_TOKEN }}' }, { registry: 'ghcr.io' }),
      { id: BUILD_PUSH_STEP_ID, ...renderPlatformStep('build-push', deps.platform, { file: svc.dockerfile, tags: `${repo}:${PUBLISH_TAG}` }, { push: 'true' }) },
      renderPublishDigestStep(name),
      { ...renderPlatformStep('upload-artifact', deps.platform, { name: artifact, path: `\${{ runner.temp }}/pipegen-out/${artifact}` }), name: `Upload the image digest of ${name}` },
    ];
  } catch (e) { if (e instanceof RenderError) return fail(e.message); throw e; }
  return { 'image-publish': { name: 'pipegen image publish', 'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, permissions: { contents: 'read', packages: 'write' }, 'cache-mode': 'none', steps } };
}

// ---------- environments ----------

/** The environment names a workflow's jobs deploy to (a plain name or `{ name }`; a name with an expression is not one pipegen can plan). */
function environmentNames(text: string): { names: string[]; dynamic: boolean } {
  const r = parseYaml(text, 'user');
  if (!('parsed' in r) || !isObj(r.parsed.js.jobs)) return { names: [], dynamic: false };
  const names = new Set<string>();
  let dynamic = false;
  for (const j of Object.values(r.parsed.js.jobs)) {
    if (!isObj(j)) continue;
    const e = isObj(j.environment) ? j.environment.name : j.environment;
    if (typeof e !== 'string' || e === '') continue;
    if (e.includes('${{') || !/^[A-Za-z0-9._ -]{1,255}$/.test(e)) { dynamic = true; continue; }
    names.add(e);
  }
  return { names: [...names], dynamic };
}

/**
 * The environments `finish` applies (plan Task 4 "Environments", B-T1a, S11), each read first: an existing one is `created: false` with its
 * settings as GitHub reports them (uninstall restores them), a missing one `created: true`. The user's deploy environments are the ones
 * their deploy jobs already name (pipegen never adds an environment to a user's job, so it creates none they don't use: no empty
 * environments, B-T1a); required reviewers only when the plan can have them AND the approval flag is set. pipegen-signing whenever the
 * repository has environments (verify-first runs in it; key-env holds the key there), never with reviewers (pipegen's jobs never wait for a
 * person, G41). Every one is limited to the default branch. No environments at all on a repository without them (private Free).
 */
export async function environmentPlan(gh: Octokit, p: RepoProfile, caps: Capabilities, requireApproval: boolean, opts: { texts: ReadonlyMap<string, string>; inserted: readonly string[]; clock?: RateClock; notes?: string[] }): Promise<EnvironmentPlan[]> {
  if (caps.environments !== true) return [];
  const names = new Set<string>();
  // G7-R1 minor: only the environments of workflows pipegen protects (its verify job inserted) are limited to the default branch; the others
  // (a deploy from another branch, a gap) are left as they are, with a note
  const others = new Map<string, string>();
  let dynamic = false;
  const inserted = new Set(opts.inserted);
  for (const wf of p.existingWorkflows) {
    if (wf.deploys !== true || OWN_WORKFLOWS.has(wf.path)) continue;
    const t = opts.texts.get(wf.path);
    if (typeof t !== 'string') continue;
    const e = environmentNames(t);
    for (const n of e.names) {
      if (n.toLowerCase() === SIGNING_ENVIRONMENT) continue;
      if (inserted.has(wf.path)) names.add(n);
      else if (!others.has(n)) others.set(n, wf.path);
    }
    if (inserted.has(wf.path)) dynamic ||= e.dynamic;
  }
  for (const [n, path] of [...others].sort(([a], [b]) => a.localeCompare(b))) {
    opts.notes?.push(names.has(n)
      ? `The environment ${show(n)} is also used by ${path}, which pipegen does not protect; pipegen limits ${show(n)} to the default branch, so a deploy of ${path} from another branch stops. Give that deploy its own environment if it needs one.`
      : `The environment ${show(n)} is used only by ${path}, which pipegen does not protect, so pipegen leaves it as it is (not limited to the default branch, no approval rule).`);
  }
  if (dynamic) opts.notes?.push('A deploy job names its environment with an expression, so pipegen can not tell which environment to protect; set its approval rules yourself.');
  if (requireApproval && names.size === 0) opts.notes?.push('pipegen asks for a deploy approval only on an environment your deploy jobs use; add `environment: <name>` to your deploy job to have one.');
  const clock = opts.clock ?? clockOf(gh);
  const app = { owner: p.owner, repo: p.repo };
  const reviewers = caps.envRequiredReviewers === true && requireApproval === true;
  const out: EnvironmentPlan[] = [];
  for (const name of [...[...names].sort(), SIGNING_ENVIRONMENT]) {
    const cur = await readEnv(gh, app, clock, name);
    const own = name === SIGNING_ENVIRONMENT;
    const base = { name, branchPolicy: 'default-only' as const, reviewers: own ? false : reviewers };
    out.push(cur === null ? { ...base, created: true } : { ...base, created: false, previous: { ...cur.settings, branch_policies: cur.policies.map((x) => ({ name: x.name, type: x.type })) } });
  }
  return out;
}

// ---------- the cosign key pair ----------

/** The filesystem types whose files live in memory only (Linux statfs f_type): tmpfs and ramfs. */
const MEMORY_FS: ReadonlySet<number> = new Set([0x01021994, 0x858458f6]);
/** The memory-backed folder pipegen makes keys in: /dev/shm when it is a tmpfs (Linux), else none. */
export const MEMORY_DIR = '/dev/shm';
export const isMemoryFolder = (dir: string): boolean => {
  try { return MEMORY_FS.has(Number(statfsSync(dir).type)); } catch { return false; }
};

/**
 * A new encrypted cosign key pair (key-env, B3 c), made only in memory: the pinned cosign (resolved right before the exec, S24) writes it into
 * a fresh 0700 folder of a memory-backed filesystem, the texts are read back and checked, and the folder is removed whatever happens
 * (makeCosignKeyPair). A folder that is not memory-backed is refused, so the key never reaches a disk. `finish` makes every pair it stores
 * with this (G13, carry 28; test "finish: the cosign key is made in memory; no key file on a disk-backed folder"), and so does the full
 * run for the pair deliver stores (key-env).
 */
export async function generateCosignKeys(cosignBin: CosignResolver, deps: { exec?: CosignExec; base?: string; isMemory?: (dir: string) => boolean } = {}): Promise<{ privateKey: string; publicKey: string; password: string }> {
  const base = deps.base ?? MEMORY_DIR;
  if (!(deps.isMemory ?? isMemoryFolder)(base)) throw new DeliverError(`pipegen makes the signing key only in memory (a tmpfs folder such as ${MEMORY_DIR}), so it never touches a disk, and ${show(base)} is not one on this machine. Run this step on Linux, where ${MEMORY_DIR} is in memory (WSL or a Linux container works too), or, on a public repository, use keyless signing, which needs no key.`);
  const pair = await makeCosignKeyPair(cosignBin, deps.exec, base);
  return { privateKey: pair.key, publicKey: pair.pub, password: pair.password };
}
