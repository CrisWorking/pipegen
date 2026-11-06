// The builder (v0.2 Plan F, F2; plan Task 1, builder half). For every need key the AI may see, the builder AI picks one REVIEWED
// tool from the candidates offered for that key and says why ("X instead of Y, because Z"). Unreviewed finds that passed the
// quality bar can only become suggestions: mention-only, never a step (spec §6, §19). This is where AI output becomes a pipeline
// step, so (threats T1, T4, T22):
// - What is offered is decided by code (rulings B2, S9, S20). A candidate is offered for a key only when the reviewed list has an
//   entry with its id that reviewedFor(…, 'full') gives for the need (category, language, at least one proof), that entry is
//   reviewed, and, for a blocking key, it is not an advisory-only tool. Needs pipegen's own jobs, the project's own scripts or the
//   repo's own tools (a TypeScript service's tsc, G4b) cover, and needs whose check has no reviewed entry at all, never reach the AI
//   (`byCode`); a need with nothing offered is
//   `uncovered`, never guessed and never filled from the audit list. A key the AI may not see (ruling B1) is decided by code.
// - Every id the AI returns is an enum in the schema and is checked again by code against what was offered for THAT key
//   (Review Focus 1, ruling S3). An id that wasn't offered refuses the whole answer; the AI is asked once more with pipegen's
//   own problem lines; a second bad answer is a BuilderError. Nothing of a refused answer is used.
// - The step is built by code from the reviewed entry (ruling S2): the tool is the entry's own candidate (never the map's
//   Candidate object), the output is the template's, and needId, service and workingDir come from the need. The AI fills only
//   the entry's open choices (aiChoiceNames, minus the ones code fills) and the tuning enums. A coverage minimum is filled by
//   code (Plan D I4), and a choice that would narrow a scanner is never the AI's (DECISIONS #108; report ruling F2-R2).
//   validateSpec must pass; its problems go into the one repair round; tuning still wrong after it is dropped.
// - Prompts (ruling S6): the bundle only through bundleText (first call and its repair), the enum-only profile summary, and the
//   offered needs and tools built from enums and reviewed-list data, all scrubbed with promptText. A need's `why` (AI text from
//   planNeeds or the judge) never goes in: pipegen's own needWhy does. Every request sets maxOutputTokens and timeoutMs.
// - reason and suggestion why go through cleanForDoc (Plan F F1): the reason is built by code from enum ids plus the cleaned
//   "because", so it is fit for PIPEGEN.md as it is (ruling S5: never escaped again).
import { z } from 'zod';
import { AiError, count } from '../ai/errors.js';
import { BUILDER_INSTRUCTIONS, BUILDER_NEEDS_TAG, BUILDER_SUGGESTIONS_TAG, BUILDER_SYSTEM, builderRepairText } from '../ai/prompts/builder.js';
import { completeValidated } from '../ai/provider.js';
import { bundleText, type CodeBundle } from '../ai/redact.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import { aiChoiceNames } from '../create/coverage.js';
import { needLanguage, toSuggestions } from '../engine/discover.js';
import { PIPEGEN_JOB_CATEGORIES } from '../engine/gate-job-list.js';
import { isReviewed, NARROWING_CHOICES } from '../engine/job-rules.js';
import { NEED_ID_CATEGORY, toolCoversNeed } from '../engine/need-ids.js';
import { needWhy, NO_HOOKS_CI_MANAGERS, promptProfile, promptText, WORKFLOW_LINT_TOOL, workflowLintTools } from '../engine/needs.js';
import type { QualityBar } from '../engine/quality-bar.js';
import { validateSpec } from '../engine/render-step.js';
import { projectScriptFor, repoToolFor, repoToolProblem, reviewedFor } from '../engine/reviewed.js';
import { COVERAGE_MINIMUMS } from '../engine/tool-flags.js';
import { LANGUAGE_FOLDERS, SEMGREP_RULE_FOLDERS, TUNING_OPTIONS, tuningEnums } from '../engine/tuning.js';
import { safeMarkdown, safeText } from '../util/safe-text.js';
import {
  NEED_CATEGORIES, type AiProvider, type AiRequest, type AiUsage, type Candidate, type Capabilities, type Need, type PipelineDraft, type RepoProfile,
  type ReviewedCandidate, type ReviewedTool, type StepChoices, type StepSpec, type TuningPicks,
} from '../types.js';
import { cleanForDoc } from './clean.js';
import { needRefs, type NeedRef } from './need-ref.js';

// ---------- limits ----------

/** The most output (thinking included) one builder request may produce. */
export const BUILDER_MAX_OUTPUT_TOKENS = 32_000;
/** How long one builder request may take. */
export const BUILDER_TIMEOUT_MS = 180_000;
/** Tools that may only warn (Plan C minor 7, ruling S9): offered only for needs with `blocking: false`. */
export const ADVISORY_TOOLS: ReadonlySet<string> = new Set(['nuclei', 'jscpd', 'scorecard-action']);
/** The most unreviewed tools offered to the AI as possible suggestions. */
export const MAX_OFFERED_SUGGESTIONS = 20;
/** The cap of a suggestion's `why` (ruling S4). */
export const SUGGESTION_WHY_MAX = 200;
/** The cap of a suggestion's name (discover.ts toSuggestions keeps at most 64 characters). */
export const SUGGESTION_NAME_MAX = 64;
/** The cap of the cleaned "because" in a reason. */
export const BECAUSE_MAX = 300;
/** The most characters of AI text the schema accepts per free-text field (the cleaner cuts further). Shared with the judge (F3). */
export const AI_TEXT_MAX = 2_000;
/** The most problem lines one repair request carries. Shared with the judge (F3). */
export const MAX_REPAIR_PROBLEMS = 40;
/** The most other tools a reason names after "instead of". */
const MAX_REASON_ALTERNATIVES = 3;

// ---------- types ----------

/** One pick: the step for one need key (every layer of its (need id, service) pair, ruling B1). */
export interface Choice {
  /** The need key (needKeyOf): `<need id>` or `<need id>--<service slug>`. */
  key: string;
  needId: string;
  /** Built by code from the reviewed entry; only `choices` holds AI picks. */
  chosen: StepSpec;
  /** Ruling S22: offered reviewed candidates only, the chosen one first, then the AI's order, no repeats. Plan G builds the fix loop's next tool from ranked[1…]. */
  ranked: ReviewedCandidate[];
  /** "X instead of Y, because Z": X and Y are reviewed ids, Z is cleanForDoc text. Fit for PIPEGEN.md as it is (never escaped again). */
  reason: string;
  /** Who picked: the AI, or pipegen's code for a key the AI may not see (ruling B1). */
  by: 'ai' | 'pipegen';
}

/**
 * A mention-only tool (PipelineDraft.suggestions): name and repo from the candidate record, only `why` from the AI. Never run. `name`
 * (GitHub discovery text) and `why` are cleanForDoc text (suggestionName; final review m1): doc-final, written into PIPEGEN.md as they
 * are, never through safeMarkdown. `repo` passed isGitHubRepo.
 */
export type Suggestion = PipelineDraft['suggestions'][number];

/**
 * A suggestion's name for PIPEGEN.md (final review m1): the discovery name when cleanForDoc leaves it as it is, else the repository's
 * own name, cleaned (so a name with a link, HTML, an @ or a cut mark is never half kept).
 */
export function suggestionName(name: string, repo: string): string {
  const n = String(name);
  if (cleanForDoc(n, SUGGESTION_NAME_MAX) === n) return n;
  return cleanForDoc(String(repo).slice(String(repo).indexOf('/') + 1), SUGGESTION_NAME_MAX);
}

/** Why code, not the AI, covers a need (ruling S20). */
export type ByCodeKind = 'pipegen-job' | 'project-script' | 'repo-tool' | 'pipegen-egress' | 'no-reviewed-tool';
/**
 * A need code covers. `pipegen-egress` (review F2 I2, ruling F2-R12): the egress allow list of release jobs is never an AI pick; Plan G
 * renders it with Plan E's egress step and the reviewed domain sets per job. `repo-tool` (G4b, ruling G4-R3, DECISIONS #95): the repo's own
 * tool at its lockfile version (a TypeScript service's tsc, repoToolFor), never an AI pick. `no-reviewed-tool` is listed here only for a
 * non-blocking need; a blocking one is `uncovered` (review m2).
 */
export interface ByCode { key: string; needId: string; service?: string; kind: ByCodeKind; blocking: boolean }
/**
 * A need nothing covers (ruling S20): never guessed, never filled in audit mode. `none-offered`: reviewed tools exist for its check, but
 * none was offered for this key; `no-reviewed-tool`: the reviewed list has no tool for its check at all (blocking needs only, review m2);
 * `no-repo-tool` (G4b): a repo built-in is meant to cover it (a Node service's type-check), but the repository has none pipegen can run
 * (repoToolProblem says why, in plain words).
 */
export interface Uncovered { key: string; needId: string; service?: string; blocking: boolean; reason: 'none-offered' | 'no-reviewed-tool' | 'no-repo-tool' }

/** What the builder needs besides the needs and the AI (ruling B2; `caps` for the profile summary, see the F2 report). */
export interface BuilderDeps {
  reviewed: readonly ReviewedTool[];
  bar: QualityBar;
  now: Date;
  caps: Capabilities;
  /** Values the user typed: scrubbed from every prompt part, and a key or tuning value holding one is never offered. */
  knownValues?: readonly string[];
}

/** One reviewed tool offered for one key, with what the AI may set on it. */
export interface Offer {
  entry: ReviewedTool;
  /** Choice name → the values the AI may pick (two or more). */
  aiChoices: Readonly<Record<string, readonly string[]>>;
  /** Choice name → the value code fills (a coverage minimum, a choice narrowed to one value). */
  codeChoices: Readonly<Record<string, string>>;
  /** Tuning option → the values offered for this key (empty options left out; each value unchanged by promptText; never code's own). */
  tuning: Readonly<Record<string, readonly string[]>>;
  /** Tuning option → the values code always fills (F2-R13: Semgrep's other rule sets the service needs). The AI can only add to them. */
  codeTuning: Readonly<Record<string, readonly string[]>>;
}

/** An unreviewed tool the AI may name as a suggestion, under an opaque id (`s1`, …). */
export interface SuggestionOffer { id: string; suggestion: Suggestion; categories: string[] }

/** Everything code decides before the AI is asked (exported for the judge and the debate, F3/F4). */
export interface BuilderOffers {
  refs: NeedRef[];
  /** Need key → the offered tools, in the candidates map's order. Only keys with at least one. */
  offers: Map<string, Offer[]>;
  /** The keys the AI is asked about (the schema's need enum), in need order. */
  aiKeys: string[];
  /** Keys with offers that the AI may not see (ruling B1): decided by code. */
  codeKeys: string[];
  byCode: ByCode[];
  uncovered: Uncovered[];
  suggestions: SuggestionOffer[];
}

/** `calls`: the AI requests made (0 with no key for the AI, else 1, or 2 with the repair; completeValidated's schema retry not counted), for the debate's call bound (F4, ruling S10). */
export interface BuildResult { choices: Choice[]; suggestions: Suggestion[]; byCode: ByCode[]; uncovered: Uncovered[]; usage: AiUsage; calls: number }

/** The AI's answer, as the schema gives it. */
export interface BuilderAnswer {
  choices: { key: string; candidateId: string; ranked: string[]; because: string; choices: Record<string, string | null>; tuning: Record<string, string[] | null> }[];
  suggestions: { id: string | null; why: string }[];
}

/** The builder AI gave a bad answer twice (ruling S3), or a step it picked can't be built. The run stops (Plan G); nothing is used. */
export class BuilderError extends Error {
  constructor(message: string, readonly problems: readonly string[], readonly usage?: AiUsage) {
    super(message);
    this.name = 'BuilderError';
  }
}

// ---------- what may be offered ----------

/**
 * Choices that would narrow a scanner if the AI picked them (DECISIONS #108: no ignore-unfixed, no severity above the gate's
 * high floor; image-build never pushes in a check). Only these values stay; one left → code fills it; none → the tool is not offered.
 */
const NARROWED: Readonly<Record<string, (v: string) => boolean>> = Object.fromEntries(
  Object.entries(NARROWING_CHOICES).map(([name, narrows]) => [name, (v: string) => !narrows(v)]),   // G2: the renderer's own table (job-rules.ts), one source
);

/** The Semgrep rule folders of the services a key is for (review F2 I1): node → javascript (+ typescript with a tsconfig), python → python, … */
function ruleFolders(ref: NeedRef, p: RepoProfile): Set<string> {
  const svc = serviceOf(ref, p);
  const scope = svc === null ? [] : svc === undefined ? p.services : [svc];
  const out = new Set<string>();
  for (const s of scope) {
    for (const lang of [s.language, ...(s.alsoLanguages ?? [])]) {
      for (const f of Object.hasOwn(LANGUAGE_FOLDERS, lang) ? (LANGUAGE_FOLDERS[lang] as readonly string[]) : []) out.add(f);
      if (lang === 'node' && s.quality?.tsconfig === true) out.add('typescript');
    }
  }
  return out;
}

/** What code fills for an entry on a key: choices and tuning values the AI can't change or remove. */
interface KeyFilled { code: Record<string, string>; tuning: Record<string, string[]> }

/**
 * Semgrep's rule sets for a key (review F2 I1, ruling F2-R13: scan more, never less). `rules` is always code's: the main folder of
 * the service's own language (node → javascript, python → python; for a repo-wide key, the first listed main folder of its
 * services). Every other folder the services need (typescript with a tsconfig, the folder's other languages, the other services'
 * languages) is a code-filled `extra-rules` set. The AI may only add more sets from the offered enum. null: the entry has none of
 * the main folders, so it is not offered.
 */
function semgrepRules(e: ReviewedTool, ref: NeedRef, p: RepoProfile): KeyFilled | null {
  const listed = Array.isArray(e.choices.rules) ? e.choices.rules : [];
  const svc = serviceOf(ref, p);
  const scope = svc === null ? [] : svc === undefined ? p.services : [svc];
  const mains = new Set(scope.map((s) => (Object.hasOwn(LANGUAGE_FOLDERS, s.language) ? LANGUAGE_FOLDERS[s.language]?.[0] : undefined)));
  const base = listed.find((v) => mains.has(v));
  if (base === undefined) return null;
  const extras = [...ruleFolders(ref, p)].filter((f) => f !== base && SEMGREP_RULE_FOLDERS.includes(f));
  return { code: { rules: base }, tuning: extras.length > 0 ? { 'extra-rules': extras } : {} };
}

/** Entries whose choices and tuning code fills per key (by entry id). */
const KEY_FILLED: Readonly<Record<string, (e: ReviewedTool, ref: NeedRef, p: RepoProfile) => KeyFilled | null>> = { semgrep: semgrepRules };

/** Tools of these categories are never offered: their inputs are pipegen's own (egress, review F2 I2). Shared with the judge (F3). */
export const NEVER_OFFERED_CATEGORIES: ReadonlySet<string> = new Set(['egress']);

const sameList = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

interface ChoicePlan { ai: Record<string, string[]>; code: Record<string, string>; codeTuning: Record<string, string[]> }

/** The AI's and code's choices of an entry for a key, or null when it can't be offered (a coverage minimum it can't fill, a choice with no safe value). */
function choicePlan(e: ReviewedTool, ref: NeedRef, p: RepoProfile): ChoicePlan | null {
  if (e.categories.some((c) => NEVER_OFFERED_CATEGORIES.has(c))) return null;
  const ai: Record<string, string[]> = {};
  const code: Record<string, string> = {};
  const aiNames = new Set(aiChoiceNames(e.id, e.choices));
  const filled = Object.hasOwn(KEY_FILLED, e.id) ? (KEY_FILLED[e.id] as (x: ReviewedTool, r: NeedRef, q: RepoProfile) => KeyFilled | null)(e, ref, p) : { code: {}, tuning: {} };
  if (filled === null) return null;
  for (const [name, raw] of Object.entries(e.choices)) {
    const values = Array.isArray(raw) ? raw.filter((v): v is string => typeof v === 'string') : [];
    if (Object.hasOwn(filled.code, name)) {
      const v = filled.code[name] as string;
      if (!values.includes(v)) return null;
      code[name] = v;
      continue;
    }
    // Plan D I4: a coverage minimum is code's, never the AI's: the CODE_FILLED_CHOICES entry, and any choice whose values are exactly the minimums (coverage.py's fail-under)
    if (!aiNames.has(name) || sameList(values, COVERAGE_MINIMUMS)) {
      if (!values.includes(COVERAGE_MINIMUMS[0])) return null;
      code[name] = COVERAGE_MINIMUMS[0];
      continue;
    }
    const keep = Object.hasOwn(NARROWED, name) ? values.filter(NARROWED[name] as (v: string) => boolean) : values;
    if (keep.length === 0) return null;
    if (keep.length === 1) code[name] = keep[0] as string;
    else ai[name] = keep;
  }
  return { ai, code, codeTuning: filled.tuning };
}

/** The service a key is for, or undefined (repo-wide); null when the need names a service the profile doesn't have. */
function serviceOf(ref: NeedRef, p: RepoProfile) {
  if (ref.service === undefined) return undefined;
  return p.services.find((s) => s.name === ref.service) ?? null;
}

const workingDirOf = (path: string): string | undefined => (path === '' || path === '.' ? undefined : path);

/** The tuning max of an option id (the largest over the tools that have it). Shared with the debate (F4). */
export const tuningMax = (id: string): number => Math.max(1, ...TUNING_OPTIONS.filter((o) => o.id === id).map((o) => o.max));

/**
 * The tuning enums of an entry for a key: per option, the union over every value of the entry's choices (ruling S2: semgrep's
 * extra-rules over every `rules` value; validateSpec checks the pick against the chosen one later), keeping only values that
 * promptText leaves unchanged. Options with no value are left out.
 */
function tuningOffer(ref: NeedRef, e: ReviewedTool, plan: ChoicePlan, p: RepoProfile, kv: readonly string[]): Record<string, string[]> {
  const svc = serviceOf(ref, p);
  const where = { ...(ref.service === undefined ? {} : { service: ref.service }), ...(svc && workingDirOf(svc.path) !== undefined ? { workingDir: svc.path } : {}) };
  const variants: StepChoices[] = [{ ...plan.code }];
  for (const [name, values] of Object.entries(plan.ai)) for (const v of values) variants.push({ ...plan.code, [name]: v });
  const out: Record<string, string[]> = {};
  for (const choices of variants) {
    for (const [opt, values] of Object.entries(tuningEnums(e, { choices, ...where }, { profile: p }))) {
      const list = out[opt] ?? [];
      // code's own sets are not the AI's to offer (it can't remove them; giving one back is harmless)
      for (const v of values) if (!list.includes(v) && !(plan.codeTuning[opt] ?? []).includes(v) && promptText(v, kv) === v) list.push(v);
      out[opt] = list;
    }
  }
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v.length > 0));
}

/** What the AI (or the judge's counter, F4) picked for one tool: choice values and tuning values, null for none. */
export interface Picks { choices?: Readonly<Record<string, string | null>>; tuning?: Readonly<Record<string, readonly string[] | null>> }

/** An enum value or id as a problem line shows it (cut, terminal-safe). Shared with the judge (F3). */
export const shown = (v: unknown) => safeText(String(v), 60);

/**
 * The fence on picks (review F2 I3; ruling S2, F2-R2): the problems of `picks` for one key and one offered tool. A choice value must be
 * one the tool offers the AI for this key; a choice code fills may only be given back with code's own value; a choice the tool
 * doesn't have is ignored. A tuning value must be one offered for this key. Used by builderAnswerProblems, the build of the answer and
 * specFor, so there is one fence. Problem lines hold pipegen's words, field paths and the (cut) values.
 */
export function offeredPickProblems(key: string, offer: Offer, picks: Picks): { choices: string[]; tuning: string[] } {
  const choices: string[] = [];
  const raw = picks.choices !== null && typeof picks.choices === 'object' ? picks.choices : {};
  for (const [name, v] of Object.entries(raw)) {
    if (v === null || v === undefined) continue;
    const aiValues = Object.hasOwn(offer.aiChoices, name) ? offer.aiChoices[name] : undefined;
    const codeValue = Object.hasOwn(offer.codeChoices, name) ? offer.codeChoices[name] : undefined;
    if (aiValues === undefined && codeValue === undefined) continue;   // a name the tool doesn't have: never read
    if (aiValues !== undefined ? !aiValues.includes(v) : v !== codeValue) choices.push(`${key}: choices.${shown(name)}: ${shown(v)} is not one of the values offered for this tool`);
  }
  const tuning: string[] = [];
  const rawT = picks.tuning !== null && typeof picks.tuning === 'object' ? picks.tuning : {};
  for (const [opt, values] of Object.entries(rawT)) {
    if (values === null || values === undefined) continue;
    if (!Array.isArray(values)) { tuning.push(`${key}: choices.tuning.${shown(opt)}: must be a list of values`); continue; }
    if (values.length === 0) continue;
    const offered = Object.hasOwn(offer.tuning, opt) ? offer.tuning[opt] : undefined;
    const filled = Object.hasOwn(offer.codeTuning, opt) ? offer.codeTuning[opt] : undefined;
    const allowed = offered === undefined && filled === undefined ? undefined : [...(offered ?? []), ...(filled ?? [])];
    if (allowed === undefined) { tuning.push(`${key}: choices.tuning.${shown(opt)}: this tool has no tuning option with that name for this need`); continue; }
    values.forEach((v, i) => { if (!allowed.includes(v)) tuning.push(`${key}: choices.tuning.${shown(opt)}[${i}]: ${JSON.stringify(shown(v))} is not one of the values offered`); });
  }
  return { choices, tuning };
}

/**
 * The StepSpec for one key and one offered tool, built by code (ruling S2): the entry's own candidate and output template, the
 * need's id, service and service folder, code's choices, and the AI's picks where given (else each choice's first allowed value).
 * Exported for the debate (F4) and Plan G's fix loop (the next ranked tool with template defaults, ruling S22).
 */
export function specFor(ref: NeedRef, offer: Offer, p: RepoProfile, picks?: Picks): StepSpec {
  // the one fence (review F2 I3): a pick outside what was offered for this key and tool is refused, never rendered
  const bad = offeredPickProblems(ref.key, offer, picks ?? {});
  if (bad.choices.length > 0 || bad.tuning.length > 0) throw new BuilderError('pipegen refused a pick that was not offered for this need.', [...bad.choices, ...bad.tuning]);
  const choices: StepChoices = {};
  for (const [name, values] of Object.entries(offer.aiChoices)) {
    const v = picks?.choices !== undefined && Object.hasOwn(picks.choices, name) ? picks.choices[name] : null;
    choices[name] = typeof v === 'string' ? v : (values[0] as string);
  }
  for (const [name, v] of Object.entries(offer.codeChoices)) choices[name] = v;
  // code's own tuning first (F2-R13: never removed), then the AI's additions (a code value given back is not repeated)
  const tuning: TuningPicks = {};
  for (const [opt, v] of Object.entries(offer.codeTuning)) if (v.length > 0) tuning[opt] = [...v];
  for (const [opt, v] of Object.entries(picks?.tuning ?? {})) {
    if (!Array.isArray(v) || v.length === 0) continue;
    const filled = Object.hasOwn(offer.codeTuning, opt) ? (offer.codeTuning[opt] as readonly string[]) : [];
    tuning[opt] = [...(tuning[opt] ?? []), ...v.filter((x) => !filled.includes(x))];
  }
  if (Object.keys(tuning).length > 0) choices.tuning = tuning;
  const svc = serviceOf(ref, p);
  const wd = svc ? workingDirOf(svc.path) : undefined;
  return {
    needId: ref.id,
    ...(ref.service === undefined ? {} : { service: ref.service }),
    tool: structuredClone(offer.entry.candidate),
    choices,
    output: structuredClone(offer.entry.step.output),
    ...(wd === undefined ? {} : { workingDir: wd }),
  };
}

/** The tools offered for one key (ruling B2), in the map's order, each once. */
function offersFor(ref: NeedRef, cands: readonly Candidate[], p: RepoProfile, deps: OfferDeps, kv: readonly string[]): Offer[] {
  if (serviceOf(ref, p) === null) return [];
  const need = ref.needs[0] as Need;
  // full mode only (proofs >= 1): never the audit list (ruling S20)
  const listed = new Map(reviewedFor(need, needLanguage(need, p), [...deps.reviewed], 'full').map((t) => [t.id, t]));
  const out: Offer[] = [];
  const seen = new Set<string>();
  for (const c of Array.isArray(cands) ? cands : []) {
    // the map's Candidate only names the tool; it must say it is reviewed, and the entry decides everything else
    if (c === null || typeof c !== 'object' || c.reviewed !== true || c.source !== 'reviewed' || typeof c.id !== 'string' || seen.has(c.id)) continue;
    const e = listed.get(c.id);
    if (e === undefined || !isReviewed(e.candidate) || e.candidate.id !== e.id || !toolCoversNeed(e.categories, ref.id)) continue;
    if (ref.blocking && ADVISORY_TOOLS.has(e.id)) continue;   // ruling S9: an advisory tool never covers a blocking need
    // GJ (Plan J fix wave I1, DECISIONS #122): workflow lint is zizmor (plus poutine on a risky trigger), never actionlint; without zizmor
    // on the list nothing is offered (the check is only a suggestion)
    if (categoryOf(ref.id) === 'workflow-lint' && (!workflowLintTools(p).includes(e.id) || !workflowLintAvailable(deps.reviewed))) continue;
    // GJ: a pre-commit or husky repository's hooks are not lefthook's: hooks-ci offers no reviewed tool there (a plain note instead)
    if (categoryOf(ref.id) === 'hooks-ci' && p.precommit !== null && NO_HOOKS_CI_MANAGERS.has(p.precommit)) continue;
    const plan = choicePlan(e, ref, p);
    if (plan === null) continue;
    seen.add(c.id);
    const offer: Offer = { entry: e, aiChoices: plan.ai, codeChoices: plan.code, tuning: tuningOffer(ref, e, plan, p, kv), codeTuning: plan.codeTuning };
    // the code-filled parts must already be valid, so any later problem is the AI's pick
    if (validateSpec(specFor(ref, offer, p), e, { profile: p }).length > 0) continue;
    out.push(offer);
  }
  return out;
}

const categoryOf = (id: string): string | undefined => (Object.hasOwn(NEED_ID_CATEGORY, id) ? (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[id] : undefined);
const where = (ref: NeedRef) => ({ key: ref.key, needId: ref.id, ...(ref.service === undefined ? {} : { service: ref.service }) });

/** What deciding the offered tools needs (the judge passes only these, ruling B2). */
export type OfferDeps = Pick<BuilderDeps, 'reviewed' | 'knownValues'>;

/**
 * GJ-R1 (review spec M4): whether workflow lint's main tool zizmor is on the reviewed list (a reviewed entry). The one predicate the offers
 * (keyOffers) and the jobs (assembleJobs) share: without it the check is only a suggestion; with it but not offered, the check is uncovered.
 */
export const workflowLintAvailable = (reviewed: readonly ReviewedTool[]): boolean => reviewed.some((t) => t?.id === WORKFLOW_LINT_TOOL && isReviewed(t.candidate));

/** builderOffers without the suggestions: what the builder and the judge (F3) both offer per key. */
export type KeyOffers = Omit<BuilderOffers, 'suggestions'>;

/**
 * The offered reviewed tools per need key, the keys the AI sees, the needs code covers (`byCode`) and the uncovered ones: one
 * function for the builder and the judge (F3: a counter candidate must be one of these for its key). Throws NeedKeyError
 * (need-ref.ts) on a key collision.
 */
export function keyOffers(needs: readonly Need[], candidates: ReadonlyMap<string, readonly Candidate[]>, p: RepoProfile, deps: OfferDeps): KeyOffers {
  const kv = deps.knownValues ?? [];
  const refs = needRefs(needs, p, kv);
  const result: KeyOffers = { refs, offers: new Map(), aiKeys: [], codeKeys: [], byCode: [], uncovered: [] };
  for (const ref of refs) {
    const category = categoryOf(ref.id);
    const svc = serviceOf(ref, p);
    const byCode = (kind: ByCodeKind) => result.byCode.push({ ...where(ref), kind, blocking: ref.blocking });
    if (category !== undefined && PIPEGEN_JOB_CATEGORIES.has(category)) { byCode('pipegen-job'); continue; }
    if (category !== undefined && NEVER_OFFERED_CATEGORIES.has(category)) { byCode('pipegen-egress'); continue; }
    if (svc && projectScriptFor(ref.needs[0] as Need, svc) !== null) { byCode('project-script'); continue; }
    // G4b: the repo's own tool (DECISIONS #95) decides before any reviewed entry; one it can not run is uncovered, never another tool
    if (svc && repoToolFor(ref.needs[0] as Need, svc) !== null) { byCode('repo-tool'); continue; }
    if (svc && repoToolProblem(ref.needs[0] as Need, svc) !== null) { result.uncovered.push({ ...where(ref), blocking: ref.blocking, reason: 'no-repo-tool' }); continue; }
    if (!deps.reviewed.some((t) => toolCoversNeed(t.categories, ref.id))) {
      if (ref.blocking) result.uncovered.push({ ...where(ref), blocking: true, reason: 'no-reviewed-tool' });
      else byCode('no-reviewed-tool');
      continue;
    }
    let offers = offersFor(ref, candidates.get(ref.key) ?? [], p, deps, kv);
    // GJ-R1 (review sec M1): workflow lint without its main tool zizmor offered is uncovered (pipegen stops), never poutine in its place
    if (category === 'workflow-lint' && !offers.some((o) => o.entry.id === WORKFLOW_LINT_TOOL)) offers = [];
    if (offers.length === 0) { result.uncovered.push({ ...where(ref), blocking: ref.blocking, reason: 'none-offered' }); continue; }
    result.offers.set(ref.key, offers);
    (ref.offered ? result.aiKeys : result.codeKeys).push(ref.key);
  }
  return result;
}

/**
 * What code decides before the AI is asked: the need keys (needRefs; refuses two services with one name), per key the offered
 * reviewed tools, the keys the AI sees, the needs code covers (`byCode`), the uncovered ones, and the suggestions the AI may name.
 * Throws NeedKeyError (need-ref.ts) on a key collision.
 */
export function builderOffers(needs: readonly Need[], candidates: ReadonlyMap<string, readonly Candidate[]>, p: RepoProfile, deps: BuilderDeps): BuilderOffers {
  const kv = deps.knownValues ?? [];
  const result: BuilderOffers = { ...keyOffers(needs, candidates, p, deps), suggestions: [] };
  const refs = result.refs;

  // ruling S4: the suggestions are toSuggestions' (unreviewed discovery candidates that pass the bar, deduped by repo), never a reviewed tool's id or repo
  const reviewedIds = new Set(deps.reviewed.map((t) => t.id));
  const reviewedRepos = new Set(deps.reviewed.map((t) => t.candidate.repo.toLowerCase()));
  const pool: Candidate[] = [];
  for (const ref of refs) {
    for (const c of candidates.get(ref.key) ?? []) {
      if (c === null || typeof c !== 'object' || c.reviewed !== false || reviewedIds.has(c.id) || typeof c.repo !== 'string' || reviewedRepos.has(c.repo.toLowerCase())) continue;
      pool.push(c);
    }
  }
  const allowed = toSuggestions(pool, new Map(), deps.bar, deps.now).filter((s) => promptText(s.repo, kv) === s.repo).slice(0, MAX_OFFERED_SUGGESTIONS);
  result.suggestions = allowed.map((s, i) => {
    const categories = [...new Set(pool.filter((c) => c.repo.toLowerCase() === s.repo.toLowerCase()).flatMap((c) => (Array.isArray(c.categories) ? c.categories : [])))]
      .filter((x): x is string => (NEED_CATEGORIES as readonly string[]).includes(x));
    return { id: `s${i + 1}`, suggestion: s, categories };
  });
  return result;
}

// ---------- the request ----------

/** A schema enum of the given values, each once. Shared with the judge (F3). */
export const enumOf = (xs: readonly string[]) => z.enum([...new Set(xs)] as [string, ...string[]]);
/** A nullable enum, or null only when nothing may be named. */
export const nullableEnum = (xs: readonly string[]) => (xs.length > 0 ? enumOf(xs).nullable() : z.null());

/** The answer's schema: need keys, candidate ids, choice values, tuning values and suggestion ids are enums of what was offered. */
function builderSchema(o: BuilderOffers): AiSchema<BuilderAnswer> {
  const ids: string[] = [];
  const choiceValues = new Map<string, string[]>();
  const tuningValues = new Map<string, string[]>();
  const add = (m: Map<string, string[]>, k: string, vs: readonly string[]) => { const l = m.get(k) ?? []; for (const v of vs) if (!l.includes(v)) l.push(v); m.set(k, l); };
  for (const key of o.aiKeys) {
    for (const offer of o.offers.get(key) ?? []) {
      if (!ids.includes(offer.entry.id)) ids.push(offer.entry.id);
      for (const [n, vs] of Object.entries(offer.aiChoices)) add(choiceValues, n, vs);
      for (const [n, vs] of Object.entries(offer.tuning)) add(tuningValues, n, vs);
    }
  }
  const sugIds = o.suggestions.map((s) => s.id);
  return aiSchema<BuilderAnswer>(z.strictObject({
    choices: z.array(z.strictObject({
      key: enumOf(o.aiKeys),
      candidateId: enumOf(ids),
      ranked: z.array(enumOf(ids)).max(ids.length),
      because: z.string().max(AI_TEXT_MAX),
      choices: z.strictObject(Object.fromEntries([...choiceValues].map(([n, vs]) => [n, enumOf(vs).nullable()]))),
      tuning: z.strictObject(Object.fromEntries([...tuningValues].map(([n, vs]) => [n, z.array(enumOf(vs)).max(tuningMax(n)).nullable()]))),
    })).max(o.aiKeys.length),
    suggestions: z.array(z.strictObject({ id: sugIds.length > 0 ? enumOf(sugIds) : z.null(), why: z.string().max(AI_TEXT_MAX) })).max(sugIds.length),
  }) as unknown as z.ZodType<BuilderAnswer>);
}

/** The offered needs and tools as the AI sees them: enums, reviewed-list data and pipegen's own texts only. */
function needsBlock(o: BuilderOffers): string {
  const refs = new Map(o.refs.map((r) => [r.key, r]));
  const summary = (opt: string, tool: string) => TUNING_OPTIONS.find((t) => t.id === opt && t.tool === tool)?.summary ?? '';
  const items = o.aiKeys.map((key) => {
    const ref = refs.get(key) as NeedRef;
    return {
      key, check: ref.id, service: ref.service ?? null, layers: ref.layers, blocking: ref.blocking,
      why: needWhy(ref.id) ?? '',   // pipegen's own text, never Need.why (AI text from planNeeds or the judge)
      tools: (o.offers.get(key) ?? []).map((of) => ({
        id: of.entry.id, name: of.entry.candidate.name, kind: of.entry.candidate.kind,
        choices: of.aiChoices,
        tuning: Object.fromEntries(Object.entries(of.tuning).map(([opt, values]) => [opt, { values, max: tuningMax(opt), does: summary(opt, of.entry.id) }])),
      })),
    };
  });
  const sugs = o.suggestions.map((s) => ({ id: s.id, repo: s.suggestion.repo, checks: s.categories }));
  // one value per line (redact() replaces a line over 4 KB whole)
  return `<${BUILDER_NEEDS_TAG}>\n${JSON.stringify(items, null, 1)}\n</${BUILDER_NEEDS_TAG}>\n\n<${BUILDER_SUGGESTIONS_TAG}>\n${JSON.stringify(sugs, null, 1)}\n</${BUILDER_SUGGESTIONS_TAG}>`;
}

function builderRequest(code: string, p: RepoProfile, o: BuilderOffers, deps: BuilderDeps): { req: AiRequest; schema: AiSchema<BuilderAnswer> } {
  const kv = deps.knownValues ?? [];
  const schema = builderSchema(o);
  return {
    schema,
    req: {
      system: BUILDER_SYSTEM,
      user: `${code}\n${promptProfile(p, deps.caps, kv)}\n\n${promptText(needsBlock(o), kv)}\n\n${BUILDER_INSTRUCTIONS}`,
      schemaName: 'builder',
      jsonSchema: schema.jsonSchema,
      timeoutMs: BUILDER_TIMEOUT_MS,
      maxOutputTokens: BUILDER_MAX_OUTPUT_TOKENS,
    },
  };
}

/**
 * The repair request (ruling S3, S2): the first request (for the builder, bundle included) plus pipegen's own problem lines, cut and
 * scrubbed, in the caller's repair text. One function for the builder and the judge (F3), so the scrub can't drift between them.
 */
export function repairRequest(req: AiRequest, problems: readonly string[], kv: readonly string[], text: (lines: readonly string[]) => string): AiRequest {
  const lines = problems.slice(0, MAX_REPAIR_PROBLEMS).map((x) => safeText(x, 300));
  return { ...req, user: `${req.user}${promptText(text(lines), kv)}` };
}

// ---------- checking the answer ----------

/**
 * pipegen's own problem lines for the ids and choice values of an answer (ruling S3): a key that wasn't offered, answered twice
 * or not at all; a candidate or ranked id not offered for THAT key; a choice value the chosen tool doesn't allow (or a value for a
 * choice code fills); a suggestion id that wasn't offered. Empty = every id is one that was offered. Never uses the AI's text.
 */
export function builderAnswerProblems(answer: BuilderAnswer, o: BuilderOffers): string[] {
  const out: string[] = [];
  const aiKeys = new Set(o.aiKeys);
  const answered = new Set<string>();
  for (const item of Array.isArray(answer?.choices) ? answer.choices : []) {
    const key = typeof item?.key === 'string' ? item.key : '';
    if (!aiKeys.has(key)) { out.push(`${shown(key)}: this need was not offered`); continue; }
    if (answered.has(key)) { out.push(`${key}: answered more than once`); continue; }
    answered.add(key);
    const offers = o.offers.get(key) ?? [];
    const offer = offers.find((x) => x.entry.id === item.candidateId);
    if (offer === undefined) { out.push(`${key}: ${shown(item.candidateId)} was not offered for this need`); continue; }
    for (const id of Array.isArray(item.ranked) ? item.ranked : []) {
      if (!offers.some((x) => x.entry.id === id)) out.push(`${key}: ranked: ${shown(id)} was not offered for this need`);
    }
    out.push(...offeredPickProblems(key, offer, { choices: item.choices }).choices);   // the one fence (also in specFor)
  }
  for (const key of o.aiKeys) if (!answered.has(key)) out.push(`${key}: no choice was given for this need`);
  const sugIds = new Set(o.suggestions.map((s) => s.id));
  for (const s of Array.isArray(answer?.suggestions) ? answer.suggestions : []) {
    if (typeof s?.id !== 'string' || !sugIds.has(s.id)) out.push(`suggestions: ${shown(s?.id)} was not offered`);
  }
  return out;
}

const isTuningProblem = (key: string) => (x: string) => x.startsWith(`${key}: choices.tuning`);

/** The Choices of an answer whose ids are all fine, or the spec problems (validateSpec, prefixed with the key). `final`: tuning still wrong → dropped. */
function choicesFrom(answer: BuilderAnswer, o: BuilderOffers, p: RepoProfile, final: boolean): { choices: Map<string, Choice>; problems: string[] } {
  const refs = new Map(o.refs.map((r) => [r.key, r]));
  const choices = new Map<string, Choice>();
  const problems: string[] = [];
  for (const item of answer.choices) {
    const ref = refs.get(item.key) as NeedRef;
    const offers = o.offers.get(item.key) as Offer[];
    const offer = offers.find((x) => x.entry.id === item.candidateId) as Offer;
    const ctx = { profile: p };
    // the fence first (specFor refuses anything outside it), then validateSpec against this call's own enums
    let bad = offeredPickProblems(item.key, offer, { tuning: item.tuning }).tuning;
    let spec: StepSpec | undefined;
    if (bad.length === 0) {
      spec = specFor(ref, offer, p, { choices: item.choices, tuning: item.tuning });
      bad = validateSpec(spec, offer.entry, ctx).map((x) => `${item.key}: ${x}`);
    }
    if (bad.length > 0 && final && bad.every(isTuningProblem(item.key))) {
      // ruling S2: tuning still wrong after the repair → the tuning section is dropped (the AI does less: no added rules, no skip)
      spec = specFor(ref, offer, p, { choices: item.choices });
      bad = validateSpec(spec, offer.entry, ctx).map((x) => `${item.key}: ${x}`);
    }
    if (bad.length > 0 || spec === undefined) { problems.push(...bad); continue; }
    const ranked: ReviewedCandidate[] = [structuredClone(offer.entry.candidate)];
    for (const id of item.ranked) {
      if (ranked.some((c) => c.id === id)) continue;
      const other = offers.find((x) => x.entry.id === id);
      if (other !== undefined) ranked.push(structuredClone(other.entry.candidate));
    }
    choices.set(item.key, {
      key: item.key, needId: ref.id, chosen: spec, ranked, by: 'ai',
      reason: reasonOf(offer.entry.id, ranked.slice(1).map((c) => c.id), cleanForDoc(item.because, BECAUSE_MAX)),
    });
  }
  return { choices, problems };
}

/** "X instead of Y, because Z" from reviewed ids and already-cleaned text; fit for PIPEGEN.md as it is (else the whole line is cleaned). */
function reasonOf(chosen: string, others: readonly string[], because: string): string {
  const alt = others.slice(0, MAX_REASON_ALTERNATIVES);
  const line = `${chosen}${alt.length > 0 ? ` instead of ${alt.join(' or ')}` : ''}, because ${because}`;
  return safeMarkdown(line) === line ? line : cleanForDoc(line);
}

// ---------- the call ----------

/** No usage yet. Shared with the judge (F3). */
export const ZERO_USAGE: AiUsage = Object.freeze({ inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 });
/** a + b, field by field (b missing → a). Shared with the judge (F3). */
export const addUsage = (a: AiUsage, b: AiUsage | undefined): AiUsage => (b === undefined ? a : {
  inputTokens: count(a.inputTokens) + count(b.inputTokens), outputTokens: count(a.outputTokens) + count(b.outputTokens),
  cacheReadTokens: count(a.cacheReadTokens) + count(b.cacheReadTokens), cacheWriteTokens: count(a.cacheWriteTokens) + count(b.cacheWriteTokens),
});
/** Whether any tokens were counted. Shared with the debate (F4). */
export const billed = (u: AiUsage) => u.inputTokens + u.outputTokens + count(u.cacheReadTokens) + count(u.cacheWriteTokens) > 0;

/**
 * An AiError with the usage of the earlier calls (`before`) added: same kind and message, the original kept as `cause` so its stack
 * survives (review F4 m3). Anything else, or nothing billed before, is returned as it is. Shared with the judge (F3) and the debate (F4).
 */
export function withUsageBefore(e: unknown, before: AiUsage): unknown {
  if (!(e instanceof AiError) || !billed(before)) return e;
  const out = new AiError(e.kind, e.message, addUsage(before, e.usage));
  out.cause = e;
  return out;
}

/** completeValidated; an AiError passes through (same kind and message) with the usage of the earlier calls added. Shared with the judge (F3). */
export async function ask<T>(ai: AiProvider, req: AiRequest, schema: AiSchema<T>, before: AiUsage): Promise<{ data: T; usage: AiUsage }> {
  try {
    return await completeValidated(ai, req, schema.zod);
  } catch (e) {
    throw withUsageBefore(e, before);
  }
}

/** The code-decided Choice of a key the AI may not see (ruling B1): the first offered tool, its template defaults, no tuning. */
function codeChoice(ref: NeedRef, offers: readonly Offer[], p: RepoProfile): Choice {
  const first = offers[0] as Offer;
  return {
    key: ref.key, needId: ref.id, chosen: specFor(ref, first, p), by: 'pipegen',
    ranked: offers.map((x) => structuredClone(x.entry.candidate)),
    reason: reasonOf(first.entry.id, [], 'pipegen picked the first reviewed tool for this check without asking the AI'),
  };
}

/**
 * The builder (plan Task 1; rulings B1, B2, S2-S4, S6, S9, S20, S22). `candidates` is keyed by need key (needKeyOf). One AI
 * request (plus completeValidated's one schema retry) and at most one repair; both carry the bundle. Returns one Choice per key
 * that has an offered reviewed tool (AI-picked, or code-picked for a key the AI may not see), the suggestions the AI named, the
 * needs code covers and the uncovered ones. Throws SecretScanRequiredError for an unscanned bundle and NeedKeyError for a key
 * collision before any request, BuilderError after a second bad answer, and passes AiError (cost-cap included) through with usage.
 */
export async function buildChoices(needs: readonly Need[], candidates: ReadonlyMap<string, readonly Candidate[]>, p: RepoProfile, bundle: CodeBundle, ai: AiProvider, deps: BuilderDeps): Promise<BuildResult> {
  const code = bundleText(bundle); // first: throws SecretScanRequiredError before anything else happens
  const kv = deps.knownValues ?? [];
  const o = builderOffers(needs, candidates, p, deps);
  let usage: AiUsage = { ...ZERO_USAGE };
  let picked = new Map<string, Choice>();
  let suggestions: Suggestion[] = [];
  let calls = 0;

  if (o.aiKeys.length > 0) {
    const { req, schema } = builderRequest(code, p, o, deps);
    let problems: string[] = [];
    let done = false;
    for (let round = 0; round < 2 && !done; round++) {
      calls++;
      const r = await ask(ai, round === 0 ? req : repairRequest(req, problems, kv, builderRepairText), schema, usage);
      usage = addUsage(usage, r.usage);
      const idProblems = builderAnswerProblems(r.data, o);
      if (idProblems.length > 0) { problems = idProblems; continue; }   // the whole answer is refused (ruling S3)
      const built = choicesFrom(r.data, o, p, round === 1);
      if (built.problems.length > 0) { problems = built.problems; continue; }
      picked = built.choices;
      const seen = new Set<string>();
      for (const s of r.data.suggestions) {
        const offer = o.suggestions.find((x) => x.id === s.id);
        if (offer === undefined || seen.has(offer.id)) continue;
        seen.add(offer.id);
        suggestions.push({ name: suggestionName(offer.suggestion.name, offer.suggestion.repo), repo: offer.suggestion.repo, why: cleanForDoc(s.why, SUGGESTION_WHY_MAX) });
      }
      done = true;
    }
    if (!done) throw new BuilderError('The builder AI answered twice with picks pipegen can not use, so pipegen stopped. Nothing it picked was used.', problems, usage);
  } else {
    // no key for the AI: no request; the suggestions keep pipegen's own text from toSuggestions
    suggestions = o.suggestions.map((s) => ({ ...s.suggestion, name: suggestionName(s.suggestion.name, s.suggestion.repo), why: cleanForDoc(s.suggestion.why, SUGGESTION_WHY_MAX) }));
  }

  const choices: Choice[] = [];
  for (const ref of o.refs) {
    const ai = picked.get(ref.key);
    if (ai !== undefined) choices.push(ai);
    else if (o.codeKeys.includes(ref.key)) choices.push(codeChoice(ref, o.offers.get(ref.key) as Offer[], p));
  }
  return { choices, suggestions, byCode: o.byCode, uncovered: o.uncovered, usage, calls };
}
