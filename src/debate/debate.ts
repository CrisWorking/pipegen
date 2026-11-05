// The debate (v0.2 Plan F, F4; plan Task 3). The builder (F2) proposes, the judge (F3) objects, the builder accepts or rebuts,
// the judge withdraws or keeps: at most MAX_ROUNDS rounds, no developer vote, no questions (spec §10). Objections still kept after
// the last round become disputes (the builder's option against the judge's), one per need key, settled later by proof runs and
// scoring (F6). Its answers decide which reviewed tool runs in the user's CI, so (threats T1, T4, T22; spec §10, §19):
// - Objections come only from the judge's critique (ruling S7). Later rounds answer over an enum of the open objection ids: the
//   builder `accept`s or `rebut`s, the judge `withdraw`s or `keep`s. No round schema has a field for a new objection, a tool, a
//   check, a need's blocking, deploy approval or gate settings. An id code didn't ask about, or one answered twice, refuses the
//   whole answer: the builder's then counts as "rebut all", the judge's as "keep all" (more disputes, never fewer checks).
// - Every step is built by code through F2's specFor (one fence): an accepted counter carries the builder's picks for that tool,
//   checked by specFor and validateSpec, else the template's first values; a judge option always takes the template's first
//   values (no AI value). The offers are recomputed with the final needs, so an added layer re-checks every pick (F3 carry): a
//   tool no longer offered becomes the first offered one, and a key with nothing offered is `uncovered`, never the old tool.
// - A kept added check is added (adding a check only adds coverage), never a dispute (ruling S7). Nothing removes a need or
//   changes its blocking.
// - Deploy approval = the rule OR the judge (ruling S8): the judge can only turn it on.
// - At most MAX_DEBATE_CALLS AI requests (ruling S10), only the builder's first call and its repair carry the code bundle; an
//   AiError (cost-cap included) passes through with the usage so far, so no unjudged choices are returned.
// - Every line, argument and reason returned is cleanForDoc text (F1), fit for PIPEGEN.md as it is. Lines name checks in plain
//   words ("the sast check for web"), never by need key or planted item id (F5-R4).
import { z } from 'zod';
import {
  ROUND_BUILDER_INSTRUCTIONS, ROUND_BUILDER_SYSTEM, ROUND_JUDGE_INSTRUCTIONS, ROUND_JUDGE_SYSTEM, ROUND_OBJECTIONS_TAG,
} from '../ai/prompts/debate.js';
import { untrustedAiText } from '../ai/prompts/untrusted.js';
import { knownValueScrubber, type CodeBundle } from '../ai/redact.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import { needLanguage } from '../engine/discover.js';
import { needWhy, promptProfile, promptText } from '../engine/needs.js';
import { validateSpec } from '../engine/render-step.js';
import { reviewedFor } from '../engine/reviewed.js';
import type { Variant } from '../proof/snapshot.js';
import type { AiProvider, AiRequest, AiUsage, Candidate, Capabilities, Need, RepoProfile, ReviewedCandidate, StepSpec } from '../types.js';
import {
  AI_TEXT_MAX, BuilderError, SUGGESTION_WHY_MAX, ZERO_USAGE, addUsage, ask, buildChoices, enumOf, keyOffers, specFor, tuningMax, withUsageBefore,
  type BuilderDeps, type ByCode, type Choice, type KeyOffers, type Offer, type Picks, type Suggestion, type Uncovered,
} from './builder.js';
import { CLEAN_DOC_MAX, CLEAN_DOC_PLACEHOLDER, cleanForDoc, stripForDoc } from './clean.js';
import { counterOffers, critique, type Objection } from './judge.js';
import { needKeyOf, type NeedRef } from './need-ref.js';

// ---------- limits ----------

/** At most this many rounds (spec §10): a round = the builder answers the open objections, then the judge answers the rebutted ones. */
export const MAX_ROUNDS = 3;
/**
 * The most AI requests one debate makes (ruling S10): the builder 1 + its repair 1, the judge's critique 1 + its re-ask 1, then per
 * round the builder 1 + the judge 1, never past this total (when the first two steps needed their re-asks, the last judge round is
 * not asked and the open objections stay kept). completeValidated's one schema retry per request is not counted here.
 */
export const MAX_DEBATE_CALLS = 9;
/** Of those, the most that carry the code bundle: only the builder's first call and its repair (ruling S6). */
export const MAX_BUNDLE_CALLS = 2;
/** The most output (thinking included) one round request may produce. */
export const ROUND_MAX_OUTPUT_TOKENS = 16_000;
/** How long one round request may take. */
export const ROUND_TIMEOUT_MS = 180_000;
/** The cap of a cleaned rebuttal or verdict argument. */
export const ARGUMENT_MAX = 300;
/** The cap of one cleaned transcript line. */
export const TRANSCRIPT_LINE_MAX = 600;

// ---------- types ----------

/** What the debate needs besides the plan and the AI (ruling B2; `caps` stays positional, as the plan has it). */
export type DebateDeps = Omit<BuilderDeps, 'caps'>;

/** One option of a dispute: proven on its own Plan E variant (F6). */
export interface DisputeOption {
  /** 'pipegen' when pipegen replaced the builder's tool (no longer offered once an added check is in place), else 'builder'. */
  label: 'builder' | 'pipegen' | 'judge';
  /** `dispute-dN-a` for the key's current pick; `dispute-dN-b`, or `dispute-dN-<j>-b` when the dispute has more than one judge option (ruling S11). */
  variant: Variant;
  /** Built by code (specFor). The builder's is the current choice; a judge option takes the template's first values. */
  choice: Choice;
  /** cleanForDoc text: the builder's rebuttal, or the judge's claim. */
  argument: string;
  /** The kept objections this option stands for, in objection order (the builder's: all of the dispute's). */
  objectionIds: string[];
}

/** Objections kept after the last round on one need key (ruling B1), merged: the builder's option first, then each distinct judge option. */
export interface Dispute {
  /** `d1`, `d2`, … in need key order (ruling S11). */
  id: string;
  key: string;
  needId: string;
  options: DisputeOption[];
}

export interface DebateResult {
  /**
   * One per need key with an offered reviewed tool, in need key order. For a key in a dispute this is the builder's option until
   * the dispute is decided (F6 replaces it with the winner).
   */
  choices: Choice[];
  /** The needs with the judge's kept or accepted additions after them (floor: false). Nothing removed, nothing changed. */
  needs: Need[];
  /** Mention-only (PipelineDraft.suggestions), deduped by repo in any letter case. */
  suggestions: Suggestion[];
  disputes: Dispute[];
  /** Plain-English lines for PIPEGEN.md, each cleanForDoc text. */
  transcript: string[];
  /** rule OR judge (ruling S8). */
  requireDeployApproval: boolean;
  /** Recomputed with the final needs (F2's keyOffers). */
  byCode: ByCode[];
  uncovered: Uncovered[];
  /** Rounds in which the builder was asked (0 when the judge had nothing to debate). */
  rounds: number;
  /** AI requests made (at most MAX_DEBATE_CALLS). */
  calls: number;
  usage: AiUsage;
}

/** The builder's round answer, as the schema gives it. */
export interface BuilderReplies {
  answers: { objection: string; answer: 'accept' | 'rebut'; argument: string; choices: Record<string, string | null>; tuning: Record<string, string[] | null> }[];
}
/** The judge's round answer, as the schema gives it. */
export interface JudgeVerdicts { verdicts: { objection: string; verdict: 'withdraw' | 'keep'; argument: string }[] }

/** One read builder reply: `picks` only with an accept (checked later by specFor's fence); `argument` cleaned, null when none was given. */
export interface Reply { answer: 'accept' | 'rebut'; argument: string | null; picks: Picks | null }
/** One read judge verdict; `argument` cleaned, null when none was given. */
export interface Verdict { verdict: 'withdraw' | 'keep'; argument: string | null }

// ---------- reading a round answer ----------

const REBUT: Reply = Object.freeze({ answer: 'rebut', argument: null, picks: null });
const KEEP: Verdict = Object.freeze({ verdict: 'keep', argument: null });
const argumentOf = (v: unknown): string | null => (typeof v === 'string' ? cleanForDoc(v, ARGUMENT_MAX) : null);
const objectOf = <T>(v: unknown): Readonly<Record<string, T>> => (v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, T>) : {});

/**
 * Reads the builder's round answer over the open ids (ruling S7). An id that is not open, or one answered twice, refuses the whole
 * answer: every open objection then counts as rebutted with no argument. An open id with no answer counts as rebutted.
 */
export function readBuilderReplies(a: BuilderReplies, open: readonly string[]): { refused: boolean; replies: Map<string, Reply> } {
  const want = new Set(open);
  const got = new Map<string, Reply>();
  let refused = !Array.isArray(a?.answers);
  for (const x of Array.isArray(a?.answers) ? a.answers : []) {
    const id = typeof x?.objection === 'string' ? x.objection : '';
    if (!want.has(id) || got.has(id)) { refused = true; break; }
    const accept = x.answer === 'accept';
    got.set(id, { answer: accept ? 'accept' : 'rebut', argument: argumentOf(x.argument), picks: accept ? { choices: objectOf(x.choices), tuning: objectOf(x.tuning) } : null });
  }
  return { refused, replies: new Map(open.map((id) => [id, refused ? REBUT : got.get(id) ?? REBUT])) };
}

/**
 * Reads the judge's round answer over the rebutted ids (ruling S7). An id that was not asked about, or one answered twice, refuses the
 * whole answer: every one is then kept. A rebutted id with no verdict is kept.
 */
export function readJudgeVerdicts(a: JudgeVerdicts, asked: readonly string[]): { refused: boolean; verdicts: Map<string, Verdict> } {
  const want = new Set(asked);
  const got = new Map<string, Verdict>();
  let refused = !Array.isArray(a?.verdicts);
  for (const x of Array.isArray(a?.verdicts) ? a.verdicts : []) {
    const id = typeof x?.objection === 'string' ? x.objection : '';
    if (!want.has(id) || got.has(id)) { refused = true; break; }
    got.set(id, { verdict: x.verdict === 'withdraw' ? 'withdraw' : 'keep', argument: argumentOf(x.argument) });
  }
  return { refused, verdicts: new Map(asked.map((id) => [id, refused ? KEEP : got.get(id) ?? KEEP])) };
}

/** The builder's suggestions, each repo once in any letter case (ruling S4; the builder already dedupes, this is the fence). */
export function dedupeSuggestions(list: readonly Suggestion[]): Suggestion[] {
  const seen = new Set<string>();
  const out: Suggestion[] = [];
  for (const s of list) {
    const k = String(s.repo).toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

// ---------- state ----------

/** One debated objection. `open` after the loop = kept. */
interface Tracked {
  o: Objection;
  status: 'open' | 'accepted' | 'withdrawn' | 'settled';
  /** The builder's last rebuttal (cleaned). */
  rebuttal: string | null;
  /** The judge's last "keep" argument (cleaned). */
  reply: string | null;
}

/**
 * The current pick of a key: the builder's own Choice (`original`), or a tool to build later with the final offers. `prior`: the
 * builder's ranked order, kept across a switch (ruling S22).
 */
interface Pick { tool: string; picks: Picks | null; reason: string; by: 'ai' | 'pipegen'; original: Choice | null; prior: readonly ReviewedCandidate[] }

/** "the sast check in merge for web": enum values and checked service names only. */
const checkLabel = (id: string, service?: string | null, layer?: string): string => `the ${id} check${layer === undefined ? '' : ` in ${layer}`}${service ? ` for ${service}` : ''}`;
const shownText = (v: string | null) => v ?? CLEAN_DOC_PLACEHOLDER;
/** A step of the builder or the judge; an AiError passes through with the debate's usage so far added (F2's withUsageBefore, cause kept). */
async function passAi<T>(before: AiUsage, f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e) {
    throw withUsageBefore(e, before);
  }
}

/** The shortest cleaned form of a typed value that is scrubbed too (a shorter one would blank ordinary words). */
const MIN_CLEANED_FORM = 4;

/**
 * Defence in depth for returned text (ruling F4-R12 m2; Plan G's vault check stays the gate): every value the user typed, in its
 * own forms (knownValueScrubber) and in its cleaned form (cleanForDoc turns `_` and some marks into blanks, so a claim already
 * holds that form), becomes the vault's placeholder, and the text is cleaned again. Text holding none is returned as it is.
 */
function returnedTextScrubber(knownValues: readonly string[]): (text: string, max: number) => string {
  const forms = [...new Set(knownValues.flatMap((v) => {
    const cleaned = stripForDoc(v);
    return cleaned !== v && cleaned.trim().length >= MIN_CLEANED_FORM ? [v, cleaned] : [v];
  }))].filter((v) => v.trim() !== '');
  if (forms.length === 0) return (text) => text;
  const scrub = knownValueScrubber(forms);
  return (text, max) => { const t = scrub(text); return t === text ? text : cleanForDoc(t, max); };
}

/** A key-sorted copy, so two specs with the same choices compare equal (ruling S11's dedupe by candidate id and choices). */
function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical((v as Record<string, unknown>)[k])]));
  return v;
}
const signatureOf = (s: StepSpec) => JSON.stringify([s.tool.id, canonical(s.choices)]);

/** The spec of `offer` with the builder's picks, checked by specFor's fence and validateSpec; any problem → the template's first values (ruling S7). */
function checkedSpec(ref: NeedRef, offer: Offer, p: RepoProfile, picks: Picks | null): StepSpec {
  if (picks !== null) {
    try {
      const spec = specFor(ref, offer, p, picks);
      if (validateSpec(spec, offer.entry, { profile: p }).length === 0) return spec;
    } catch (e) {
      if (!(e instanceof BuilderError)) throw e;
    }
  }
  return specFor(ref, offer, p);
}

/** The AI's picks a built spec holds for an offer (its open choices and the tuning beyond code's), to rebuild it once the key changed. */
function picksOf(spec: StepSpec, offer: Offer): Picks {
  const choices: Record<string, string | null> = {};
  for (const name of Object.keys(offer.aiChoices)) choices[name] = typeof spec.choices[name] === 'string' ? (spec.choices[name] as string) : null;
  const tuning: Record<string, string[] | null> = {};
  for (const [opt, values] of Object.entries(spec.choices.tuning ?? {})) {
    const code = Object.hasOwn(offer.codeTuning, opt) ? (offer.codeTuning[opt] as readonly string[]) : [];
    const extra = Array.isArray(values) ? values.filter((v) => !code.includes(v)) : [];
    tuning[opt] = extra.length > 0 ? extra : null;
  }
  return { choices, tuning };
}

/**
 * ranked (ruling S22): the chosen tool first, then `before`'s order (the builder's), offered tools only, no repeats. `all`: then the
 * other offers too, in offer order (a pick code made, like F2's code-decided keys, or a key the builder never ranked).
 */
function rankedOf(chosen: Offer, offers: readonly Offer[], before: readonly ReviewedCandidate[], all: boolean): ReviewedCandidate[] {
  const ids = [chosen.entry.id, ...before.map((c) => c.id), ...(all ? offers.map((o) => o.entry.id) : [])];
  const out: ReviewedCandidate[] = [];
  for (const id of ids) {
    const o = offers.find((x) => x.entry.id === id);
    if (o !== undefined && !out.some((c) => c.id === id)) out.push(structuredClone(o.entry.candidate));
  }
  return out;
}

/** A reason line from reviewed ids and pipegen's words, plus at most one already-cleaned AI text at its end. */
const reasonLine = (text: string) => cleanForDoc(text, CLEAN_DOC_MAX);

// ---------- the round requests ----------

interface RoundCtx {
  p: RepoProfile;
  caps: Capabilities;
  kv: readonly string[];
  refs: ReadonlyMap<string, NeedRef>;
  current: ReadonlyMap<string, Pick>;
  counterOf: (t: Tracked) => Offer | undefined;
}

/** The facts of one objection as a round shows them: enums, reviewed ids and pipegen's own texts only. */
function objectionFacts(t: Tracked, c: RoundCtx) {
  const o = t.o;
  const add = o.counter.addNeed;
  const ref = c.refs.get(o.key);
  return {
    id: o.id, key: o.key, check: o.needId, service: ref?.service ?? add?.service ?? null, layers: ref?.layers ?? (add ? [add.layer] : []),
    blocking: ref?.blocking ?? add?.blocking ?? true, severity: o.severity,
    why: needWhy(o.needId) ?? '',   // pipegen's own text, never Need.why
    currentTool: c.current.get(o.key)?.tool ?? null,
    counterTool: c.counterOf(t)?.entry.id ?? null,
    addCheck: add ? { check: add.id, layer: add.layer, service: add.service ?? null } : null,
  };
}

function builderRoundRequest(open: readonly Tracked[], c: RoundCtx): { req: AiRequest; schema: AiSchema<BuilderReplies> } {
  const choiceValues = new Map<string, string[]>();
  const tuningValues = new Map<string, string[]>();
  const add = (m: Map<string, string[]>, k: string, vs: readonly string[]) => { const l = m.get(k) ?? []; for (const v of vs) if (!l.includes(v)) l.push(v); m.set(k, l); };
  const items = open.map((t) => {
    const offer = c.counterOf(t);
    for (const [n, vs] of Object.entries(offer?.aiChoices ?? {})) add(choiceValues, n, vs);
    for (const [n, vs] of Object.entries(offer?.tuning ?? {})) add(tuningValues, n, vs);
    return {
      ...objectionFacts(t, c),
      counterChoices: offer?.aiChoices ?? {},
      counterTuning: Object.fromEntries(Object.entries(offer?.tuning ?? {}).map(([opt, values]) => [opt, { values, max: tuningMax(opt) }])),
    };
  });
  const ids = open.map((t) => t.o.id);
  const schema = aiSchema<BuilderReplies>(z.strictObject({
    answers: z.array(z.strictObject({
      objection: enumOf(ids),
      answer: z.enum(['accept', 'rebut']),
      argument: z.string().max(AI_TEXT_MAX),
      choices: z.strictObject(Object.fromEntries([...choiceValues].map(([n, vs]) => [n, enumOf(vs).nullable()]))),
      tuning: z.strictObject(Object.fromEntries([...tuningValues].map(([n, vs]) => [n, z.array(enumOf(vs)).max(tuningMax(n)).nullable()]))),
    })).max(ids.length),
  }) as unknown as z.ZodType<BuilderReplies>);
  const words = open.map((t) => [
    `The judge's claim for ${t.o.id}:\n${untrustedAiText(t.o.claim, 'judge', c.kv)}`,
    ...(t.reply === null ? [] : [`The judge's last reply for ${t.o.id}:\n${untrustedAiText(t.reply, 'judge', c.kv)}`]),
  ].join('\n\n')).join('\n\n');
  return { schema, req: roundRequest('debate-builder', ROUND_BUILDER_SYSTEM, items, words, ROUND_BUILDER_INSTRUCTIONS, schema, c) };
}

function judgeRoundRequest(rebutted: readonly Tracked[], c: RoundCtx): { req: AiRequest; schema: AiSchema<JudgeVerdicts> } {
  const ids = rebutted.map((t) => t.o.id);
  const schema = aiSchema<JudgeVerdicts>(z.strictObject({
    verdicts: z.array(z.strictObject({ objection: enumOf(ids), verdict: z.enum(['withdraw', 'keep']), argument: z.string().max(AI_TEXT_MAX) })).max(ids.length),
  }) as unknown as z.ZodType<JudgeVerdicts>);
  const words = rebutted.map((t) => [
    `Your claim for ${t.o.id}:\n${untrustedAiText(t.o.claim, 'judge', c.kv)}`,
    `The builder's rebuttal for ${t.o.id}:\n${untrustedAiText(shownText(t.rebuttal), 'builder', c.kv)}`,
  ].join('\n\n')).join('\n\n');
  return { schema, req: roundRequest('debate-judge', ROUND_JUDGE_SYSTEM, rebutted.map((t) => objectionFacts(t, c)), words, ROUND_JUDGE_INSTRUCTIONS, schema, c) };
}

/** A round request (ruling S6): the enum-only profile, the facts block scrubbed, the other AI's words only in untrusted blocks, no bundle. */
function roundRequest(name: string, system: string, items: unknown[], words: string, instructions: string, schema: AiSchema<unknown>, c: RoundCtx): AiRequest {
  const block = `<${ROUND_OBJECTIONS_TAG}>\n${JSON.stringify(items, null, 1)}\n</${ROUND_OBJECTIONS_TAG}>`;
  return {
    system,
    user: `${promptProfile(c.p, c.caps, c.kv)}\n\n${promptText(block, c.kv)}\n\n${words}\n\n${instructions}`,
    schemaName: name,
    jsonSchema: schema.jsonSchema,
    timeoutMs: ROUND_TIMEOUT_MS,
    maxOutputTokens: ROUND_MAX_OUTPUT_TOKENS,
  };
}

// ---------- the debate ----------

/**
 * The debate (plan Task 3; rulings B1, S7, S8, S10, S11; carries F1, F2, F3, F5-R4). `candidates` is keyed by need key (the map
 * the builder gets); `rule` is the plan's deploy approval rule (deployApprovalRule). Throws what the builder and the judge throw
 * (NeedKeyError, SecretScanRequiredError, BuilderError, JudgeError) and passes every AiError (cost-cap included) through with the
 * usage so far; nothing of an interrupted debate is returned.
 */
export async function debate(
  needs: readonly Need[], candidates: ReadonlyMap<string, readonly Candidate[]>, p: RepoProfile, caps: Capabilities, bundle: CodeBundle,
  ai: AiProvider, rule: { requireDeployApproval: boolean }, deps: DebateDeps,
): Promise<DebateResult> {
  const kv = deps.knownValues ?? [];
  const odeps = { reviewed: deps.reviewed, knownValues: kv };
  const transcript: string[] = [];
  const scrubbed = returnedTextScrubber(kv);
  const say = (text: string) => { transcript.push(cleanForDoc(scrubbed(text, TRANSCRIPT_LINE_MAX), TRANSCRIPT_LINE_MAX)); };
  let usage: AiUsage = { ...ZERO_USAGE };
  let calls = 0;

  // 1. the builder (the only requests with the code bundle)
  const built = await passAi(usage, () => buildChoices(needs, candidates, p, bundle, ai, { ...deps, caps }));
  usage = addUsage(usage, built.usage);
  calls += built.calls;
  const plan: KeyOffers = keyOffers(needs, candidates, p, odeps);
  const refs = new Map(plan.refs.map((r) => [r.key, r]));
  const current = new Map<string, Pick>();
  for (const c of built.choices) {
    current.set(c.key, { tool: c.chosen.tool.id, picks: null, reason: c.reason, by: c.by, original: c, prior: c.ranked });
    const ref = refs.get(c.key);
    if (c.by === 'ai' && ref !== undefined) say(`The builder picked for ${checkLabel(ref.id, ref.service)}: ${c.reason}`);
  }

  // 2. the judge's critique: the only place objections come from (ruling S7)
  const crit = await passAi(usage, () => critique(built.choices, needs, candidates, p, caps, ai, odeps));
  usage = addUsage(usage, crit.usage);
  calls += crit.calls;
  const requireDeployApproval = rule.requireDeployApproval === true || crit.requireDeployApproval === true;   // ruling S8: on only
  // the needs the critique checked its counters with (the plan plus every addition it kept)
  const critNeeds = [...needs, ...crit.objections.flatMap((o) => (o.counter.addNeed === undefined ? [] : [o.counter.addNeed]))];
  const offerCache = new Map<string, Offer[]>();
  const counterOf = (t: Tracked): Offer | undefined => {
    const id = t.o.counter.candidateId;
    if (id === undefined) return undefined;
    if (!offerCache.has(t.o.key)) offerCache.set(t.o.key, counterOffers(t.o.key, critNeeds, p, odeps, plan));
    return (offerCache.get(t.o.key) as Offer[]).find((x) => x.entry.id === id);
  };
  const labelOf = (o: Objection) => {
    const add = o.counter.addNeed;
    if (add !== undefined) return checkLabel(add.id, add.service, add.layer);
    const ref = refs.get(o.key);
    return checkLabel(o.needId, ref?.service);
  };

  const tracked: Tracked[] = [];
  if (crit.objections.length === 0) say('The judge had no objection to the builder\'s picks.');
  for (const o of crit.objections) {
    const add = o.counter.addNeed;
    const counter = o.counter.candidateId;
    const cur = current.get(o.key)?.tool;
    if (add !== undefined) {
      say(`The judge asked (${o.id}, ${o.severity}) to add ${labelOf(o)}${counter === undefined ? '' : ` with ${counter}`}: ${o.claim}`);
    } else if (counter === undefined) {
      say(`The judge objected (${o.id}, ${o.severity}) to ${cur ?? 'the pick'} for ${labelOf(o)} without naming another reviewed tool, so pipegen keeps the builder's pick: ${o.claim}`);
      continue;
    } else if (counter === cur) {
      say(`The judge objected (${o.id}, ${o.severity}) to ${labelOf(o)} but proposed the tool the builder already picked, so nothing changes: ${o.claim}`);
      continue;
    } else {
      say(`The judge objected (${o.id}, ${o.severity}) to ${cur ?? 'the pick'} for ${labelOf(o)} and proposed ${counter}: ${o.claim}`);
    }
    tracked.push({ o, status: 'open', rebuttal: null, reply: null });
  }
  for (const note of crit.notes) say(note);
  if (crit.requireDeployApproval) say(`The judge asks that deploys wait for a person to approve them: ${shownText(crit.deployApprovalReason)}`);
  if (rule.requireDeployApproval === true) say('pipegen\'s own rule makes deploys wait for a person to approve them.');

  // 3. the rounds: accept or rebut, then withdraw or keep (no new objections, ruling S7)
  const ctx: RoundCtx = { p, caps, kv, refs, current, counterOf };
  const budgetLine = `pipegen makes at most ${MAX_DEBATE_CALLS} AI calls in a debate, so the judge was not asked again; the open objections stay kept.`;
  let rounds = 0;
  for (let round = 1; round <= MAX_ROUNDS; round++) {
    const open = tracked.filter((t) => t.status === 'open');
    if (open.length === 0) break;
    if (calls + 1 > MAX_DEBATE_CALLS) { say(budgetLine); break; }
    rounds = round;
    const b = builderRoundRequest(open, ctx);
    calls++;
    const br = await ask(ai, b.req, b.schema, usage);
    usage = addUsage(usage, br.usage);
    const read = readBuilderReplies(br.data, open.map((t) => t.o.id));
    if (read.refused) say(`Round ${round}: pipegen refused the builder's answer (an objection it was not asked about, or one answered twice), so every open objection counts as rebutted.`);
    const switched = new Set<string>();
    const rebutted: Tracked[] = [];
    for (const t of open) {
      const rep = read.replies.get(t.o.id) as Reply;
      const counter = t.o.counter.candidateId;
      const add = t.o.counter.addNeed;
      if (rep.answer === 'accept' && add !== undefined && counter !== undefined && switched.has(t.o.key)) {
        // ruling F4-R12 I1: an accepted addition is always added; the one-switch rule limits only its tool switch
        t.status = 'accepted';
        say(`Round ${round}: the builder accepted ${t.o.id}, so pipegen adds ${labelOf(t.o)}; it keeps the tool another objection switched this check to in this round, not ${counter}.`);
        continue;
      }
      if (rep.answer === 'accept' && counter !== undefined && switched.has(t.o.key)) {
        // one switch per key per round: a second accept on the same key in the same round counts as a rebuttal
        t.rebuttal = 'The builder accepted another objection on this check in the same round.';
        rebutted.push(t);
        say(`Round ${round}: the builder accepted another objection on ${labelOf(t.o)} in this round, so ${t.o.id} counts as rebutted.`);
        continue;
      }
      if (rep.answer === 'accept') {
        t.status = 'accepted';
        if (counter !== undefined) {
          const before = current.get(t.o.key);
          current.set(t.o.key, {
            tool: counter, picks: rep.picks, by: 'ai', original: null, prior: before?.prior ?? [],
            reason: reasonLine(before === undefined ? `${counter}, because the judge asked for it: ${t.o.claim}` : `${counter} instead of ${before.tool}, because the judge objected: ${t.o.claim}`),
          });
          switched.add(t.o.key);
        }
        say(`Round ${round}: the builder accepted ${t.o.id}${add === undefined ? '' : `, so pipegen adds ${labelOf(t.o)}`}${counter === undefined ? '' : `${add === undefined ? ' and' : ';'} it now uses ${counter}${add === undefined ? ` for ${labelOf(t.o)}` : ''}`}.`);
        continue;
      }
      t.rebuttal = rep.argument;
      rebutted.push(t);
      say(`Round ${round}: the builder rebutted ${t.o.id}: ${shownText(rep.argument)}`);
    }
    // a counter that is now the key's tool is settled (an added check still needs the judge's word)
    const asked = rebutted.filter((t) => {
      if (t.o.counter.addNeed !== undefined || t.o.counter.candidateId !== current.get(t.o.key)?.tool) return true;
      t.status = 'settled';
      say(`Round ${round}: ${t.o.id} is settled: ${labelOf(t.o)} now uses ${t.o.counter.candidateId}.`);
      return false;
    });
    if (asked.length === 0) continue;
    if (calls + 1 > MAX_DEBATE_CALLS) { say(budgetLine); break; }
    const j = judgeRoundRequest(asked, ctx);
    calls++;
    const jr = await ask(ai, j.req, j.schema, usage);
    usage = addUsage(usage, jr.usage);
    const verdicts = readJudgeVerdicts(jr.data, asked.map((t) => t.o.id));
    if (verdicts.refused) say(`Round ${round}: pipegen refused the judge's answer (an objection it was not asked about, or one answered twice), so every rebutted objection stays kept.`);
    for (const t of asked) {
      const v = verdicts.verdicts.get(t.o.id) as Verdict;
      if (v.verdict === 'withdraw') {
        t.status = 'withdrawn';
        say(`Round ${round}: the judge withdrew ${t.o.id}: ${shownText(v.argument)}`);
      } else {
        t.reply = v.argument;
        say(`Round ${round}: the judge kept ${t.o.id}: ${shownText(v.argument)}`);
      }
    }
  }
  const kept = tracked.filter((t) => t.status === 'open');

  // 4. the final needs: the plan plus every accepted or kept addition (ruling S7: a kept addition is added, never a dispute)
  const existing = new Set(built.choices.map((c) => c.key));
  const addedFrom = tracked.filter((t) => t.o.counter.addNeed !== undefined && (t.status === 'accepted' || t.status === 'open'));
  const added = addedFrom.map((t) => t.o.counter.addNeed as Need);
  for (const t of addedFrom) {
    say(`pipegen adds ${labelOf(t.o)}: ${t.status === 'accepted' ? 'the builder accepted it' : 'the judge kept it, and adding a check only adds coverage'}.`);
    // a kept addition with a counter on a new key: the judge's tool with the template's first values (an existing key: a dispute option below)
    const counter = t.o.counter.candidateId;
    if (t.status === 'open' && counter !== undefined && !existing.has(t.o.key) && !current.has(t.o.key)) {
      current.set(t.o.key, { tool: counter, picks: null, by: 'ai', original: null, prior: [], reason: reasonLine(`${counter}, because the judge asked for it: ${t.o.claim}`) });
    }
  }
  const finalNeeds = [...needs, ...added];
  const finalCands = new Map(candidates);
  for (const n of added) {
    const k = needKeyOf(n);
    if (!finalCands.has(k)) finalCands.set(k, reviewedFor(n, needLanguage(n, p), [...deps.reviewed], 'full').map((t) => structuredClone(t.candidate)));
  }
  // the offers with the final needs: an added layer can make a key blocking and drop a tool (F3 carry)
  const fin = keyOffers(finalNeeds, finalCands, p, odeps);
  const touched = new Set(added.map(needKeyOf));

  // 5. the choices, built by code with the final offers (F2 carry: only through specFor)
  const choices: Choice[] = [];
  for (const ref of fin.refs) {
    const offers = fin.offers.get(ref.key);
    const pick = current.get(ref.key);
    if (offers === undefined) {
      if (pick !== undefined && touched.has(ref.key)) say(`No reviewed tool is offered for ${checkLabel(ref.id, ref.service)} once the added check is in place, so pipegen reports it as not covered.`);
      continue;
    }
    if (pick === undefined) {
      const first = offers[0] as Offer;
      choices.push({
        key: ref.key, needId: ref.id, chosen: specFor(ref, first, p), ranked: rankedOf(first, offers, [], true), by: 'pipegen',
        reason: reasonLine(`${first.entry.id}, because pipegen picked the first reviewed tool for the check the judge added`),
      });
      continue;
    }
    if (pick.original !== null && !touched.has(ref.key)) { choices.push(pick.original); continue; }
    const offer = offers.find((o) => o.entry.id === pick.tool);
    if (offer === undefined) {
      const first = offers[0] as Offer;
      say(`pipegen switched ${checkLabel(ref.id, ref.service)} to ${first.entry.id}: ${pick.tool} is no longer offered once the added check is in place.`);
      choices.push({
        key: ref.key, needId: ref.id, chosen: specFor(ref, first, p), ranked: rankedOf(first, offers, pick.prior, true), by: 'pipegen',
        reason: reasonLine(`${first.entry.id} instead of ${pick.tool}, because ${pick.tool} is no longer offered once the added check is in place`),
      });
      continue;
    }
    const picks = pick.picks ?? (pick.original === null ? null : picksOf(pick.original.chosen, offer));
    choices.push({
      key: ref.key, needId: ref.id, chosen: checkedSpec(ref, offer, p, picks), ranked: rankedOf(offer, offers, pick.prior, pick.by === 'pipegen' || pick.prior.length === 0), by: pick.by,
      reason: pick.reason,
    });
  }

  // 6. the disputes: kept objections with a counter, merged per key, options deduped (ruling S11)
  const disputes: Dispute[] = [];
  for (const ref of fin.refs) {
    const list = kept.filter((t) => t.o.key === ref.key && t.o.counter.candidateId !== undefined && (t.o.counter.addNeed === undefined || existing.has(ref.key)));
    if (list.length === 0) continue;
    const mine = choices.find((c) => c.key === ref.key);
    const offers = fin.offers.get(ref.key) ?? [];
    if (mine === undefined) continue;   // uncovered: reported above
    const theirs: { choice: Choice; ids: string[]; argument: string }[] = [];
    for (const t of list) {
      const id = t.o.counter.candidateId as string;
      const offer = offers.find((o) => o.entry.id === id);
      if (offer === undefined) { say(`The judge's option ${id} for ${labelOf(t.o)} is no longer offered once the added checks are in place, so it is dropped.`); continue; }
      if (id === mine.chosen.tool.id) { say(`${t.o.id} is settled: ${labelOf(t.o)} already uses ${id}.`); continue; }
      const spec = specFor(ref, offer, p);   // the template's first values: never an AI value
      const same = theirs.find((x) => signatureOf(x.choice.chosen) === signatureOf(spec));
      if (same !== undefined) { same.ids.push(t.o.id); continue; }
      theirs.push({
        ids: [t.o.id], argument: t.o.claim,
        choice: { key: ref.key, needId: ref.id, chosen: spec, ranked: rankedOf(offer, offers, [], true), by: 'ai', reason: reasonLine(`${id}, because the judge objected: ${t.o.claim}`) },
      });
    }
    if (theirs.length === 0) continue;
    const id = `d${disputes.length + 1}`;
    const all = list.filter((t) => theirs.some((x) => x.ids.includes(t.o.id)));
    const rebuttal = all.find((t) => t.rebuttal !== null)?.rebuttal ?? null;
    disputes.push({
      id, key: ref.key, needId: ref.id,
      options: [
        { label: mine.by === 'pipegen' ? 'pipegen' : 'builder', variant: `dispute-${id}-a`, choice: mine, argument: shownText(rebuttal), objectionIds: all.map((t) => t.o.id) },
        ...theirs.map((x, j): DisputeOption => ({ label: 'judge', variant: theirs.length === 1 ? `dispute-${id}-b` : `dispute-${id}-${j + 1}-b`, choice: x.choice, argument: x.argument, objectionIds: x.ids })),
      ],
    });
    say(`Dispute ${id} on ${checkLabel(ref.id, ref.service)}: ${mine.chosen.tool.id} (the builder's pick) against ${theirs.map((x) => x.choice.chosen.tool.id).join(' and ')} (the judge's); proof runs against planted problems decide, not a vote.`);
  }

  // ruling F4-R12 m2: no typed value in any returned text (the transcript is scrubbed in `say`)
  const scrubChoice = (c: Choice): Choice => { const reason = scrubbed(c.reason, CLEAN_DOC_MAX); return reason === c.reason ? c : { ...c, reason }; };
  return {
    choices: choices.map(scrubChoice), needs: finalNeeds,
    suggestions: dedupeSuggestions(built.suggestions).map((s) => { const why = scrubbed(s.why, SUGGESTION_WHY_MAX); return why === s.why ? s : { ...s, why }; }),
    disputes: disputes.map((d) => ({ ...d, options: d.options.map((o) => ({ ...o, argument: scrubbed(o.argument, ARGUMENT_MAX), choice: scrubChoice(o.choice) })) })),
    transcript, requireDeployApproval,
    byCode: fin.byCode, uncovered: fin.uncovered, rounds, calls, usage,
  };
}
