// v0.2 Plan G G13: the pure parts of `pipegen run` (src/cli/run.ts), each tested on its own with the real modules: the strictness levels
// (DECISIONS #96, ruling G13-R0 5), the draft from the debate (F-6), the signing plan (only services that publish an image, carry 10), the
// code owners (carry 39), the PR wait (ruling G13-R0 4), the estimate inputs (carries 41-43), PIPEGEN.md's inputs (carries 31-34) and the
// proof layout closure (carry 36). Nothing here reads the network, the disk or the clock.
import { parseDocument } from 'yaml';
import type { DebateResult } from '../debate/debate.js';
import type { Choice } from '../debate/builder.js';
import { publishedImageRepo } from '../engine/deploy-steps.js';
import { CALLER_WORKFLOW, NIGHTLY_WORKFLOW } from '../engine/job-rules.js';
import { floorNeeds, jobCategories, MINIMUM_CATEGORIES, publishedImageServices } from '../engine/needs.js';
import type { Estimates, JobCategories } from '../estimate/estimate.js';
import { signingMode, type SigningMode } from '../github/signing-mode.js';
import { signingPlan } from '../layers/central.js';
import { isAiNote } from '../deliver/docs.js';
import type { DeployGap, VerifyPlan } from '../layers/deploy.js';
import type { AssembledJobs, Job, JobsPlan } from '../layers/jobs.js';
import type { LockPlan } from '../layers/locks.js';
import type { PrecommitResult } from '../layers/precommit.js';
import { PROOF_SIGNING_MODE } from '../proof/harness.js';
import { ADVISORY_TOOLS } from '../debate/builder.js';
import type { Capabilities, CreatedFile, Need, PipelineDoc, PipelineDraft, RepoProfile, StepSpec } from '../types.js';

// ---------- strictness (DECISIONS #96, ruling G13-R0 5) ----------

export const STRICTNESS_LEVELS = Object.freeze(['starter', 'standard', 'strict'] as const);
export type Strictness = typeof STRICTNESS_LEVELS[number];
export const DEFAULT_STRICTNESS: Strictness = 'standard';
/** The name PIPEGEN.md prints (doc.estimates.strictness). */
export const STRICTNESS_NAME: Readonly<Record<Strictness, NonNullable<PipelineDoc['estimates']['strictness']>>> = Object.freeze({ starter: 'Starter', standard: 'Standard', strict: 'Strict' });

/** `--strictness <level>`: one of the three, or a plain refusal naming them. Absent: Standard. */
export function parseStrictness(value: string | undefined): Strictness {
  if (value === undefined) return DEFAULT_STRICTNESS;
  const v = value.trim().toLowerCase();
  if ((STRICTNESS_LEVELS as readonly string[]).includes(v)) return v as Strictness;
  throw new Error(`Unknown strictness "${value.slice(0, 40)}". Use starter, standard or strict.`);
}

/**
 * The one frozen table of the levels (ruling G13-R0 5; G13-R1 spec M2 and I2), mapped onto the merge checks' `draft.warnFirst` and, for
 * Strict only, their `blocking` (strictNeeds): which merge (gate) checks start in warn mode (from `today`, for 14 days until the nightly
 * asks to switch them to blocking). Only `layer === 'merge'` needs are gate checks; a pre-commit, push, deploy or nightly need is never in
 * warnFirst (warn mode means nothing for a commit hook).
 * - Starter: the fixed minimum (MINIMUM_CATEGORIES) and the floor checks (`floor: true`, which the gate never lets warn: POLICY_FLOOR)
 *   block; every other blocking merge check starts in warn mode.
 * - Standard (default): the minimum, the floor and the type checks (floorNeeds: the checks the service types call for) block; the other
 *   blocking merge checks (the ones the AI added) start in warn mode.
 * - Strict: every merge check blocks, with no warn period; strictNeeds also makes the non-blocking merge checks blocking.
 */
export function warnFirstFor(needs: readonly Need[], level: Strictness, typeNeedIds: ReadonlySet<string>, today: string): Record<string, { since: string }> {
  const out: Record<string, { since: string }> = {};
  if (level === 'strict') return out;
  const minimum: ReadonlySet<string> = new Set(MINIMUM_CATEGORIES);
  for (const n of needs) {
    if (n.layer !== 'merge' || !n.blocking || n.floor || minimum.has(n.category)) continue;
    if (level === 'standard' && typeNeedIds.has(n.id)) continue;
    out[n.id] = { since: today };
  }
  return out;
}

/**
 * Strict (spec M2): every merge check pipegen adds blocks, `blocking: false` ones too, when the debate gave it a tool it can run (a step for
 * its need and service, and not in the plan's uncovered list) that may block: an advisory tool (ADVISORY_TOOLS, ruling S9: jscpd,
 * nuclei, scorecard-action) only ever warns, so its check stays non-blocking. A blocking check with no such tool would stop assemble ("It
 * never guesses a tool"), so Strict never turns a check it can't run into a stop. The other levels and layers are unchanged. Pure.
 */
export function strictNeeds(needs: readonly Need[], level: Strictness, covered: { steps: readonly Pick<StepSpec, 'needId' | 'service' | 'tool'>[]; uncovered: readonly { needId: string; service?: string }[] }): Need[] {
  if (level !== 'strict') return [...needs];
  const runs = (n: Need): boolean => covered.steps.some((s) => s.needId === n.id && s.service === n.service && !ADVISORY_TOOLS.has(s.tool.id)) && !covered.uncovered.some((u) => u.needId === n.id && u.service === n.service);
  return needs.map((n) => (n.layer === 'merge' && !n.blocking && runs(n) ? { ...n, blocking: true } : n));
}

// ---------- the draft from the debate (F-6) ----------

/** What the run's draft takes from the debate: needs, steps (each choice, a decided dispute's winner by key), suggestions, the approval rule. */
export interface DebateDraft { draft: PipelineDraft; plan: JobsPlan; byCode: DebateResult['byCode']; choices: Choice[] }

/** A deploy job or environment really exists (B-T1a): only then is a deploy approval applied. */
export const deploysExist = (p: RepoProfile): boolean => p.existingWorkflows.some((w) => w.deploys);

/**
 * The draft from DebateResult (plan l. 865-868): `needs`, the steps of `choices` (a decided dispute's winner replaces its key's choice),
 * `suggestions`, `requireDeployApproval` (applied only when a deploy exists), and the jobs plan (`needs`, `candidates`, `uncovered`) assemble
 * renders from. `byCode` (needs a built-in job covers) passes through. Pure.
 */
export function draftFromDebate(base: PipelineDraft, d: DebateResult, winners: ReadonlyMap<string, Choice> = new Map()): DebateDraft {
  const choices = d.choices.map((c) => winners.get(c.key) ?? c);
  const draft: PipelineDraft = {
    ...base,
    needs: [...d.needs],
    steps: choices.map((c) => c.chosen),
    suggestions: d.suggestions.map((s) => ({ name: s.name, repo: s.repo, why: s.why })),
    requireDeployApproval: d.requireDeployApproval && deploysExist(base.profile),
  };
  return { draft, plan: { needs: draft.needs, candidates: d.candidates, uncovered: d.uncovered }, byCode: d.byCode, choices };
}

// ---------- signing (carry 10) ----------

/**
 * The signing plan from the probed repository (never the draft): signingMode(p, caps), and only the images of services that publish one
 * (publishedImageServices), each at publishedImageRepo. No image: no plan (a plan for no-image services is refused by the referee).
 */
export function signingFor(p: RepoProfile, caps: Capabilities, cosignPubSha256?: string): PipelineDraft['signing'] {
  const mode: SigningMode = signingMode(p, caps);
  const images = publishedImageServices(p, caps).map((service) => ({ service, repo: publishedImageRepo(p.owner, p.repo, service) }));
  if (mode === 'none' || images.length === 0) return undefined;
  return signingPlan(p, caps, mode, images, mode === 'key-env' ? cosignPubSha256 : undefined);
}

// ---------- code owners (carry 39, S9, G8-R2 I1) ----------

export type OwnersPick = { owners: string[]; writers: number; note?: string } | { stop: string };
const BOT_RE = /\[bot\]$|^dependabot$|^github-actions$/i;

/**
 * The code owners: users who can write to the app AND the central repo, bots left out. The default is the token's login (when it qualifies)
 * plus the other qualifying writers, so with two or more writers there are at least two owners. Fewer than two qualify: no code-owner rule
 * (owners empty) and a note (DECISIONS #75 gap), never a bypass. No human writer of the app, or of the central repo (spec M7): stop with a
 * plain reason.
 */
export function pickOwners(writers: { app: readonly string[]; central: readonly string[] }, login: string | null): OwnersPick {
  const central = new Set(writers.central.map((w) => w.toLowerCase()));
  const humans = writers.app.filter((w) => !BOT_RE.test(w));
  if (humans.length === 0) return { stop: 'pipegen found no person with write access to this repository (only bots, or nobody), so it can\'t pick code owners or lock merging safely. Give at least one person write access, then run `npx pipegen run` again.' };
  // spec M7 (G8-R2 I1): the central list too, before anything costs money (planLocks would refuse it only at stage 15)
  if (!writers.central.some((w) => !BOT_RE.test(w))) return { stop: 'pipegen found no person with write access to the central repository (pipelines): only bots, or nobody, so it can\'t pick code owners or lock merging safely. Give at least one person write access to pipelines, then run `npx pipegen run` again.' };
  const both = [...new Set(humans.filter((w) => central.has(w.toLowerCase())))];
  if (both.length < 2) return { owners: [], writers: humans.length, note: 'Fewer than two people can write to both this repository and the central repository, so pipegen sets no code-owner rule and writes no CODEOWNERS block: a single writer can approve their own changes to the pipeline files.' };
  const first = login !== null ? both.find((w) => w.toLowerCase() === login.toLowerCase()) : undefined;
  const ordered = first === undefined ? both : [first, ...both.filter((w) => w !== first)];
  return { owners: ordered.map((w) => `@${w}`), writers: humans.length };
}

// ---------- estimates (carries 41-43, ruling G13-R0 3, 4) ----------

/** Whether an organisation required workflow could apply (private, organisation, Team or Enterprise): the merge layer runs twice per PR. */
export const requiredWorkflowApplies = (p: Pick<RepoProfile, 'private' | 'ownerType' | 'plan'>): boolean => p.private && p.ownerType === 'Organization' && (p.plan === 'team' || p.plan === 'enterprise');

/** The merge layer counted twice where an org required workflow could apply (carry 41). */
function withRequired(j: JobCategories, p: RepoProfile): JobCategories {
  return requiredWorkflowApplies(p) ? { ...j, merge: [...j.merge, ...j.merge] } : j;
}

/**
 * The consent estimate's jobs (ruling G13-R0 3, an upper bound before anything is assembled): one job per check and service of the floor
 * needs (jobCategories never groups jobs), the merge layer twice where an org required workflow could apply. The warning-only no-image
 * signing need (blocking false, no job) is left out (carry 8).
 */
export function consentJobs(p: RepoProfile, caps: Capabilities): JobCategories {
  const floor = floorNeeds(p, caps).filter((n) => !((n.category === 'signing' || n.category === 'attestation') && !n.blocking));
  return withRequired(jobCategories(floor), p);
}

/** The jobs as assembled (carry 43): one per written job, each named by its need's category, the merge layer twice as above. */
export function assembledJobs(jobs: Pick<AssembledJobs, 'push' | 'merge' | 'nightly'>, needs: readonly Need[], p: RepoProfile): JobCategories {
  const cat = (id: string): string => needs.find((n) => id === n.id || id.startsWith(`${n.id}--`))?.category ?? id;
  return withRequired({ 'pre-commit': [], push: Object.keys(jobs.push).map(cat), merge: Object.keys(jobs.merge).map(cat), deploy: [], nightly: Object.keys(jobs.nightly).map(cat) }, p);
}

/** Ruling G13-R0 4: the PR wait, the longest chain through `needs` of the merge-layer jobs, each at its timeout (an upper bound). */
export function prWaitMinutes(merge: Readonly<Record<string, Pick<Job, 'timeout-minutes' | 'needs'>>>): number {
  const memo = new Map<string, number>();
  const visit = (id: string, seen: ReadonlySet<string>): number => {
    const known = memo.get(id);
    if (known !== undefined) return known;
    const j = merge[id];
    if (j === undefined || seen.has(id)) return 0;
    const next = new Set(seen).add(id);
    const before = Math.max(0, ...(j.needs ?? []).map((n) => visit(n, next)));
    const total = before + j['timeout-minutes'];
    memo.set(id, total);
    return total;
  };
  return Math.max(0, ...Object.keys(merge).map((id) => visit(id, new Set())));
}

// ---------- PIPEGEN.md's inputs (carries 31-34, B7) ----------

/** The creators' own AI note, never a doc field (carry 34, D-m5). G17-F1 (sec I2): docs.ts's one filter (format characters, NFKC, spaces). */
export { isAiNote };

export interface DocInputs {
  transcript: readonly string[];
  verify: Pick<VerifyPlan, 'gaps' | 'notes' | 'preview'>;
  locks: Pick<LockPlan, 'notes'> & { gateRequired: boolean };
  precommit: Pick<PrecommitResult, 'setupCommand' | 'notes' | 'inPlace'>;
  jobs: { notes: readonly string[]; uncoveredMinimum: AssembledJobs['uncoveredMinimum'] };
  assembledNotes: readonly string[];
  testNotes: readonly string[];
  credits: readonly NonNullable<PipelineDoc['credits']>[number][];
  estimates: Pick<Estimates, 'monthlyMinutes' | 'includedMinutes'>;
  prWaitMinutes: number;
  strictness: Strictness;
  /** PL-D6: shown under the title of PIPEGEN.md; the builder prints them only when plain. */
  version?: string; date?: string;
}

/** draft.doc, filled completely (carry 31): every note list in one generic list, the AI note dropped, the transcript as the debate gave it. */
export function docFor(i: DocInputs): PipelineDoc {
  const notes = [...i.jobs.notes, ...i.assembledNotes, ...i.precommit.notes, ...i.verify.notes, ...i.verify.preview].filter((n) => !isAiNote(n));
  return {
    transcript: [...i.transcript],
    deployGaps: i.verify.gaps.map((g: DeployGap) => ({ path: g.path, triggers: [...g.triggers], why: g.why })),
    lockNotes: [...i.locks.notes],
    estimates: { monthlyMinutes: i.estimates.monthlyMinutes, includedMinutes: i.estimates.includedMinutes, prWaitMinutes: i.prWaitMinutes, strictness: STRICTNESS_NAME[i.strictness] },
    setupCommand: i.precommit.setupCommand,
    ...(i.locks.gateRequired ? {} : { gateRequired: false }),
    testNotes: i.testNotes.filter((n) => !isAiNote(n)),
    uncoveredMinimum: i.jobs.uncoveredMinimum.map((u) => ({ category: u.category, why: u.why, ...(u.service === undefined ? {} : { service: u.service }) })),
    notes: [...new Set(notes)],
    credits: i.credits.map((c) => ({ text: c.text, kind: c.kind })),
    ...(i.version === undefined ? {} : { version: i.version }),
    ...(i.date === undefined ? {} : { date: i.date }),
    ...(i.precommit.inPlace === undefined || i.precommit.inPlace.length === 0 ? {} : { hooksInPlace: i.precommit.inPlace.map((h) => ({ path: h.path, runs: [...h.runs] })) }),
  };
}

// ---------- the proof layout (carry 36) ----------

/**
 * The proof copy of the assembled files (PROOF_TRIGGERS: push and pull_request only): the nightly files dropped (schedule) and the caller's
 * pull_request_review trigger removed. checkProofWorkflows is never widened; anything else in the files is assemble's (mode none). Pure.
 */
export function proofLayout(files: readonly CreatedFile[]): CreatedFile[] {
  const out: CreatedFile[] = [];
  for (const f of files) {
    if (f.path === NIGHTLY_WORKFLOW || /--nightly\.ya?ml$/.test(f.path)) continue;
    if (f.repo === 'app' && f.path === CALLER_WORKFLOW) {
      const doc = parseDocument(f.content);
      if (doc.hasIn(['on', 'pull_request_review'])) doc.deleteIn(['on', 'pull_request_review']);
      out.push({ ...f, content: doc.toString({ lineWidth: 0 }) });
      continue;
    }
    out.push(f);
  }
  return out;
}

/** The ProofAssemble closure G14 calls: the draft at `centralSha`, assembled with PROOF_SIGNING_MODE, in the proof layout. */
export function proofAssembler(draft: PipelineDraft, assembleIn: (d: PipelineDraft, mode: typeof PROOF_SIGNING_MODE) => { files: CreatedFile[] }): (mode: typeof PROOF_SIGNING_MODE, centralSha: string | undefined) => CreatedFile[] {
  return (mode, centralSha) => {
    if (mode !== PROOF_SIGNING_MODE) throw new Error('The proof is assembled with signing mode none only.');
    const pinned: PipelineDraft = centralSha === undefined || draft.centralPin === undefined ? draft : { ...draft, centralPin: { repo: draft.centralPin.repo, sha: centralSha } };
    const { signing: _signing, ...unsigned } = pinned;
    return proofLayout(assembleIn(unsigned, mode).files);
  };
}
