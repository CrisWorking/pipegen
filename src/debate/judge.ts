// The judge (v0.2 Plan F, F3; plan Task 2). A second AI, "a security engineer for a small company that can be taken down fast",
// attacks the builder's picks: gaps per layer, weak tools, missing blocking coverage, loose permissions, anything that ignores the
// capabilities. It may name a counter candidate, add a need and turn deploy approval on. Its answer can steer which tool runs in
// the user's CI, so (threats T1, T4, T22; spec §10, §19):
// - What the judge may name is decided by code (rulings B1, B2, S7, S9). It objects only to keys the AI may see that have a
//   builder choice. A counter candidate must be one of the tools the builder was offered for THAT key (keyOffers: reviewed, full
//   mode, never advisory-only on a blocking key, never an egress tool). An added need goes through pipegen's own addition rule
//   (acceptAddedNeed, the same rule as planNeeds); its candidates are the reviewed list's full-mode entries for it (reviewedFor,
//   no discovery, no network), offered through the same keyOffers. Every id is an enum in the schema and is checked again here.
// - An id that wasn't offered refuses the whole answer (ruling S3): one re-ask with pipegen's own problem lines, then JudgeError.
//   Nothing of a refused answer is used. A refused addition (acceptAddedNeed) is a note, not a refused answer.
// - The schema has no field that removes a need, lowers blocking, or sets gate settings, secrets or folders (ruling S9, Plan C
//   r1-4). An added need's blocking follows pipegen's table only. Deploy approval can only be turned on, and only with a reason
//   that is not empty after cleanForDoc (ruling S8); it is kept when the judge agrees.
// - Prompts (ruling S6): the enum-only profile summary, the capabilities, the builder's picks and the reviewed tools per check
//   (enums and reviewed-list data, scrubbed with promptText), and the builder's reasons, each only inside the untrusted block
//   (untrustedAiText). No code bundle, no Need.why, no planted item. Every request sets maxOutputTokens and timeoutMs.
// - claims and the approval reason go through cleanForDoc (Plan F F1), so they are fit for PIPEGEN.md as they are (ruling S5).
import { z } from 'zod';
import {
  JUDGE_CAPABILITIES_TAG, JUDGE_CHOICES_TAG, JUDGE_COVERED_TAG, JUDGE_INSTRUCTIONS, JUDGE_SYSTEM, JUDGE_TOOLS_TAG, judgeRepairText,
} from '../ai/prompts/judge.js';
import { untrustedAiText } from '../ai/prompts/untrusted.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import { needLanguage } from '../engine/discover.js';
import { isReviewed } from '../engine/job-rules.js';
import { toolCoversNeed } from '../engine/need-ids.js';
import {
  LAYERS, NEED_IDS, acceptAddedNeed, addedNeedContext, needKey, needWhy, promptProfile, promptServiceNames, promptText, refusedAdditionsNote,
  type AddedNeed, type AddedNeedRefusal,
} from '../engine/needs.js';
import { reviewedFor } from '../engine/reviewed.js';
import {
  NEED_CATEGORIES, type AiProvider, type AiRequest, type AiUsage, type Candidate, type Capabilities, type Need, type RepoProfile, type ReviewedTool,
} from '../types.js';
import {
  AI_TEXT_MAX, NEVER_OFFERED_CATEGORIES, ZERO_USAGE, addUsage, ask, keyOffers, nullableEnum, repairRequest, shown, type Choice, type KeyOffers, type Offer,
} from './builder.js';
import { CLEAN_DOC_PLACEHOLDER, cleanForDoc } from './clean.js';
import { needKeyOf, type NeedRef } from './need-ref.js';

// ---------- limits ----------

/** The most output (thinking included) one judge request may produce. */
export const JUDGE_MAX_OUTPUT_TOKENS = 16_000;
/** How long one judge request may take. */
export const JUDGE_TIMEOUT_MS = 180_000;
/** The most objections read from one answer (ruling S7); the rest are not read. */
export const MAX_OBJECTIONS = 20;
/** The most added needs read from one answer (ruling S7), counted among the objections read. */
export const MAX_ADDED_NEEDS = 8;
/** The cap of a cleaned claim. */
export const CLAIM_MAX = 300;
/** The cap of the cleaned deploy approval reason. */
export const APPROVAL_REASON_MAX = 300;

// ---------- types ----------

/** What the judge needs besides the plan and the AI (ruling B2). */
export interface JudgeDeps {
  reviewed: readonly ReviewedTool[];
  /** Values the user typed: scrubbed from every prompt part; a key or service name holding one is never offered. */
  knownValues?: readonly string[];
}

/** One objection the judge keeps (plan Task 2; ruling B1: by need key). */
export interface Objection {
  /** `o1`, `o2`, … in the order read (the debate's later rounds answer over these ids, ruling S7). */
  id: string;
  /** The need key the objection is about; for an added need, that need's key. */
  key: string;
  needId: string;
  /** cleanForDoc text: fit for PIPEGEN.md as it is. */
  claim: string;
  /** candidateId: a reviewed id offered for `key`. addNeed: a need pipegen's addition rule accepted (floor: false), never in the plan yet. */
  counter: { candidateId?: string; addNeed?: Need };
  severity: 'must' | 'should';
}

export interface Critique {
  agreed: boolean;
  /** Empty when `agreed`. */
  objections: Objection[];
  /** true = the judge asks to turn deploy approval on (with a reason). It can never turn it off: the debate ORs it with the rule (F4). */
  requireDeployApproval: boolean;
  /** The cleaned reason when `requireDeployApproval`, else null. */
  deployApprovalReason: string | null;
  /** pipegen's own notes: refused or repeated additions, objections not read. Enum values and checked names only. */
  notes: string[];
  usage: AiUsage;
}

/** The judge's answer, as the schema gives it. */
export interface JudgeAnswer {
  agreed: boolean;
  objections: {
    key: string | null;
    addNeed: { id: string; layer: string; category: string; service: string | null } | null;
    counterCandidateId: string | null;
    severity: 'must' | 'should';
    claim: string;
  }[];
  requireDeployApproval: boolean;
  deployApprovalReason: string;
}

/** What code decides before the judge is asked. */
export interface JudgeOffers {
  /** The plan's offers per key (keyOffers, the builder's own). */
  keys: KeyOffers;
  /** The keys the judge may object to: keys the AI may see that have a builder choice whose tool was offered for them, in need order. */
  judgeKeys: string[];
  /** The builder's choice per judge key. */
  choices: Map<string, Choice>;
  /** The schema's counter enum: reviewed ids of full-mode entries (code checks each per key). */
  counterIds: string[];
  /** The schema's service enum for an added need (promptServiceNames, as planNeeds). */
  services: string[];
}

/** The judge AI gave a bad answer twice (ruling S3). The run stops (Plan G); nothing is used. */
export class JudgeError extends Error {
  constructor(message: string, readonly problems: readonly string[], readonly usage?: AiUsage) {
    super(message);
    this.name = 'JudgeError';
  }
}

// ---------- what may be named ----------

/**
 * The keys, choices and enums of one critique. A choice is shown to the judge only for a key the AI may see (ruling B1) and only
 * when its tool is one offered for that key; the first choice per key counts. Throws NeedKeyError on a key collision.
 */
export function judgeOffers(choices: readonly Choice[], needs: readonly Need[], candidates: ReadonlyMap<string, readonly Candidate[]>, p: RepoProfile, deps: JudgeDeps): JudgeOffers {
  const kv = deps.knownValues ?? [];
  const keys = keyOffers(needs, candidates, p, deps);
  const byKey = new Map<string, Choice>();
  for (const c of choices) {
    if (!keys.aiKeys.includes(c.key) || byKey.has(c.key)) continue;
    if (!(keys.offers.get(c.key) ?? []).some((o) => o.entry.id === c.chosen.tool.id)) continue;
    byKey.set(c.key, c);
  }
  // a superset of every key's offers (code checks each pick per key): full-mode reviewed entries that cover some check, never an
  // egress tool (its inputs are pipegen's own, review F2 I2), each id unchanged by the scrub
  const counterIds = deps.reviewed
    .filter((t) => t.proofs >= 1 && isReviewed(t.candidate) && t.candidate.id === t.id && promptText(t.id, kv) === t.id
      && !t.categories.some((c) => NEVER_OFFERED_CATEGORIES.has(c)) && NEED_IDS.some((id) => toolCoversNeed(t.categories, id)))
    .map((t) => t.id);
  return { keys, judgeKeys: keys.aiKeys.filter((k) => byKey.has(k)), choices: byKey, counterIds: [...new Set(counterIds)], services: promptServiceNames(p, kv) };
}

/**
 * The tools a counter may name for `key` once the needs are `current`: the plan plus the additions kept from the same answer (ruling
 * F3-R9, review F3 m1). A key no addition touched keeps the plan's own offers. A key an addition extends or creates is offered again
 * through keyOffers over every need it now has, so its strictest blocking counts (an added blocking layer drops advisory-only tools),
 * from a pool of: the plan's offers when the key is already in the plan (never more than the plan offered), else the reviewed list's
 * own full-mode entries for it (ruling S7: reviewedFor, never the discovery map, no network). None when the AI may not see the key.
 */
export function counterOffers(key: string, current: readonly Need[], p: RepoProfile, deps: JudgeDeps, plan: KeyOffers): Offer[] {
  const same = current.filter((n) => needKeyOf(n) === key);
  const inPlan = plan.refs.find((r) => r.key === key);
  const planOffers = inPlan !== undefined && plan.aiKeys.includes(key) ? plan.offers.get(key) ?? [] : [];
  const planNeeds = new Set((inPlan?.needs ?? []).map(needKey));
  if (inPlan !== undefined && same.every((n) => planNeeds.has(needKey(n)))) return planOffers;
  const first = same[0];
  if (first === undefined) return [];
  const pool: Candidate[] = inPlan !== undefined
    ? planOffers.map((o) => structuredClone(o.entry.candidate))
    : reviewedFor(first, needLanguage(first, p), [...deps.reviewed], 'full').map((t) => structuredClone(t.candidate));
  const fresh = keyOffers(same, new Map([[key, pool]]), p, deps);
  return fresh.aiKeys.includes(key) ? fresh.offers.get(key) ?? [] : [];
}

/** The tools a counter may name for an added need, with `current` the needs before it (counterOffers over `current` plus it). */
export function addedNeedOffers(added: Need, current: readonly Need[], p: RepoProfile, deps: JudgeDeps, plan: KeyOffers): Offer[] {
  return counterOffers(needKeyOf(added), [...current, added], p, deps, plan);
}

const addedItem = (a: { id: string; layer: string; service: string | null }) => `${a.id} in ${a.layer}${a.service === null ? '' : ` for ${a.service}`}`;

/**
 * Reads one answer (rulings S3, S7, F3-R9): pipegen's problem lines (any → the whole answer is refused), the objections kept and the
 * notes. `agreed: true` → no objection is read. At most MAX_OBJECTIONS objections and, among them, MAX_ADDED_NEEDS additions are read.
 * Two passes: first the keys and the additions (acceptAddedNeed, repeats dropped), then every counter against its key's offers with
 * ALL the answer's kept additions in place (counterOffers), so an addition can't make an earlier or later counter unsafe.
 * Problem lines hold pipegen's words, enum values and checked names only, never the AI's text.
 */
export function readJudgeAnswer(a: JudgeAnswer, j: JudgeOffers, needs: readonly Need[], p: RepoProfile, caps: Capabilities, deps: JudgeDeps): { problems: string[]; objections: Objection[]; notes: string[] } {
  if (a.agreed === true) return { problems: [], objections: [], notes: [] };
  const problems: string[] = [];
  const kept: (Omit<Objection, 'id'> & { asked: string | null })[] = [];
  const notes: string[] = [];
  const all = Array.isArray(a.objections) ? a.objections : [];
  const read = all.slice(0, MAX_OBJECTIONS);
  if (all.length > read.length) notes.push(`pipegen read only the first ${MAX_OBJECTIONS} of ${all.length} objections.`);

  const refs = new Map<string, NeedRef>(j.keys.refs.map((r) => [r.key, r]));
  const ctx = addedNeedContext(p, caps, deps.knownValues ?? []);
  const refused = new Map<AddedNeedRefusal, string[]>();
  const already: string[] = [];
  const current = [...needs];
  const seen = new Set(needs.map(needKey));
  let adds = 0;
  let addsAsked = 0;
  // pass 1: keys and additions
  for (const [i, o] of read.entries()) {
    const counter = typeof o?.counterCandidateId === 'string' ? o.counterCandidateId : null;
    const key = typeof o?.key === 'string' ? o.key : null;
    const add = o?.addNeed !== null && typeof o?.addNeed === 'object' ? o.addNeed : null;
    const severity = o?.severity === 'should' ? 'should' : 'must';
    const claim = cleanForDoc(typeof o?.claim === 'string' ? o.claim : '', CLAIM_MAX);
    if ((key === null) === (add === null)) { problems.push(`objection ${i + 1}: give either a key or addNeed, never both and never neither`); continue; }

    if (key !== null) {
      if (!j.judgeKeys.includes(key)) { problems.push(`${shown(key)}: this need was not offered`); continue; }
      kept.push({ key, needId: (refs.get(key) as NeedRef).id, claim, severity, counter: counter === null ? {} : { candidateId: counter }, asked: null });
      continue;
    }

    const asked = add as NonNullable<typeof add>;
    addsAsked++;
    if (adds >= MAX_ADDED_NEEDS) continue;   // not read
    adds++;
    // pipegen's own addition rule (the planNeeds rule). The judge gives no why and no blocking: the need's why is pipegen's own
    // text, and its blocking follows pipegen's table only (ruling S9: no AI field lowers blocking).
    const res = acceptAddedNeed({ id: asked.id, layer: asked.layer, category: asked.category, service: asked.service, why: '', blocking: true } as AddedNeed, ctx);
    if (!res.ok) { refused.set(res.reason, [...(refused.get(res.reason) ?? []), res.item]); continue; }
    const item = addedItem(asked);
    if (seen.has(needKey(res.need))) { already.push(item); continue; }
    seen.add(needKey(res.need));
    current.push(res.need);
    kept.push({ key: needKeyOf(res.need), needId: res.need.id, claim, severity, counter: { addNeed: res.need, ...(counter === null ? {} : { candidateId: counter }) }, asked: item });
  }
  // pass 2: every counter against its key's offers with all the kept additions in place
  const offersOf = new Map<string, Offer[]>();
  for (const o of kept) {
    const counter = o.counter.candidateId;
    if (counter === undefined) continue;
    if (!offersOf.has(o.key)) offersOf.set(o.key, counterOffers(o.key, current, p, deps, j.keys));
    if ((offersOf.get(o.key) as Offer[]).some((x) => x.entry.id === counter)) continue;
    problems.push(o.asked === null ? `${o.key}: ${shown(counter)} was not offered for this need` : `${o.asked}: ${shown(counter)} was not offered for this added check`);
  }
  if (addsAsked > adds) notes.push(`pipegen read only the first ${MAX_ADDED_NEEDS} of ${addsAsked} added checks.`);
  for (const [reason, items] of refused) notes.push(refusedAdditionsNote(reason, [...new Set(items)]));
  for (const item of [...new Set(already)]) notes.push(`The judge asked to add ${item}, which pipegen already plans; pipegen left it out.`);
  return { problems, objections: kept.map(({ asked: _asked, ...o }, n) => ({ id: `o${n + 1}`, ...o })), notes };
}

/** Ruling S8: on only when the judge says on AND gives a reason that is not empty after cleanForDoc. */
function approvalOf(a: JudgeAnswer): { requireDeployApproval: boolean; deployApprovalReason: string | null } {
  if (a.requireDeployApproval !== true) return { requireDeployApproval: false, deployApprovalReason: null };
  const reason = cleanForDoc(typeof a.deployApprovalReason === 'string' ? a.deployApprovalReason : '', APPROVAL_REASON_MAX);
  if (reason === CLEAN_DOC_PLACEHOLDER) return { requireDeployApproval: false, deployApprovalReason: null };
  return { requireDeployApproval: true, deployApprovalReason: reason };
}

// ---------- the request ----------


/** The answer's schema (ruling S9): keys, counter ids, added need ids, layers, categories and services are enums; nothing else. */
function judgeSchema(j: JudgeOffers): AiSchema<JudgeAnswer> {
  return aiSchema<JudgeAnswer>(z.strictObject({
    agreed: z.boolean(),
    objections: z.array(z.strictObject({
      key: nullableEnum(j.judgeKeys),
      addNeed: z.strictObject({ id: z.enum(NEED_IDS), layer: z.enum(LAYERS), category: z.enum(NEED_CATEGORIES), service: nullableEnum(j.services) }).nullable(),
      counterCandidateId: nullableEnum(j.counterIds),
      severity: z.enum(['must', 'should']),
      claim: z.string().max(AI_TEXT_MAX),
    })),
    requireDeployApproval: z.boolean(),
    deployApprovalReason: z.string().max(AI_TEXT_MAX),
  }) as unknown as z.ZodType<JudgeAnswer>);
}

/** The seven capability flags (types.ts Capabilities); the compile-time check below fails when the type gains or loses one. */
const CAPABILITY_FLAGS = ['branchProtection', 'environments', 'envRequiredReviewers', 'deploymentBranchPolicies', 'attestations', 'codeScanning', 'keylessSigningAllowed'] as const;
type MissingFlag = Exclude<keyof Capabilities, (typeof CAPABILITY_FLAGS)[number]>;
const ALL_FLAGS_LISTED: [MissingFlag] extends [never] ? true : never = true;
void ALL_FLAGS_LISTED;

/** Only the named flags, each true only for a real `true` (review F3 m4): nothing else the object holds reaches the prompt. */
const capabilityFlags = (caps: Capabilities): Record<string, boolean> => Object.fromEntries(CAPABILITY_FLAGS.map((f) => [f, caps[f] === true]));

/** The picks and the reviewed tools as the judge sees them: enums, reviewed-list data and pipegen's own texts only. */
function judgeBlocks(j: JudgeOffers, caps: Capabilities, reviewed: readonly ReviewedTool[]): string {
  const refs = new Map(j.keys.refs.map((r) => [r.key, r]));
  const choices = j.judgeKeys.map((key) => {
    const ref = refs.get(key) as NeedRef;
    const c = j.choices.get(key) as Choice;
    const offers = j.keys.offers.get(key) ?? [];
    const offer = offers.find((o) => o.entry.id === c.chosen.tool.id) as Offer;
    // only values offered for this key: never a value of another origin
    const picked: Record<string, string> = {};
    for (const [name, values] of Object.entries({ ...offer.aiChoices, ...Object.fromEntries(Object.entries(offer.codeChoices).map(([n, v]) => [n, [v]])) })) {
      const v = c.chosen.choices[name];
      if (typeof v === 'string' && values.includes(v)) picked[name] = v;
    }
    const tuning: Record<string, string[]> = {};
    for (const [opt, values] of Object.entries(c.chosen.choices.tuning ?? {})) {
      const allowed = [...(offer.tuning[opt] ?? []), ...(offer.codeTuning[opt] ?? [])];
      const keep = Array.isArray(values) ? values.filter((v) => allowed.includes(v)) : [];
      if (keep.length > 0) tuning[opt] = keep;
    }
    return {
      key, check: ref.id, service: ref.service ?? null, layers: ref.layers, blocking: ref.blocking,
      why: needWhy(ref.id) ?? '',   // pipegen's own text, never Need.why
      tool: offer.entry.id, choices: picked, tuning,
      otherOfferedTools: offers.filter((o) => o !== offer).map((o) => o.entry.id),
    };
  });
  const covered = [
    ...j.keys.byCode.map((b) => ({ key: b.key, by: b.kind })),
    ...j.keys.uncovered.map((u) => ({ key: u.key, by: `nothing (${u.reason})` })),
  ].filter((x) => refs.get(x.key)?.offered === true).map((x) => {
    const ref = refs.get(x.key) as NeedRef;
    return { key: x.key, check: ref.id, service: ref.service ?? null, layers: ref.layers, blocking: ref.blocking, coveredBy: x.by };
  });
  // the tools a counter may name, per check id: full-mode reviewed entries (the counter enum), with the languages they read
  // A list of { check, tools } items, never an object keyed by check id: redact's generic rule reads a `"secrets": [` line as a
  // secret and hides the whole list (review F3 m2); as a value after "check" the id is plain data.
  const listed = new Set(j.counterIds);
  const tools: { check: string; tools: { id: string; languages: string[] }[] }[] = [];
  for (const id of NEED_IDS) {
    const ts = reviewed.filter((t) => listed.has(t.id) && toolCoversNeed(t.categories, id)).map((t) => ({ id: t.id, languages: [...t.languages] }));
    if (ts.length > 0) tools.push({ check: id, tools: ts });
  }
  return [
    `<${JUDGE_CAPABILITIES_TAG}>\n${JSON.stringify(capabilityFlags(caps), null, 1)}\n</${JUDGE_CAPABILITIES_TAG}>`,
    `<${JUDGE_CHOICES_TAG}>\n${JSON.stringify(choices, null, 1)}\n</${JUDGE_CHOICES_TAG}>`,
    `<${JUDGE_COVERED_TAG}>\n${JSON.stringify(covered, null, 1)}\n</${JUDGE_COVERED_TAG}>`,
    `<${JUDGE_TOOLS_TAG}>\n${JSON.stringify(tools, null, 1)}\n</${JUDGE_TOOLS_TAG}>`,
  ].join('\n\n');
}

/** The builder's reasons, each inside its own untrusted block (ruling S6), named by its key outside the block. */
function reasonBlocks(j: JudgeOffers, kv: readonly string[]): string {
  return j.judgeKeys.map((key) => `The builder's reason for ${key}:\n${untrustedAiText((j.choices.get(key) as Choice).reason, 'builder', kv)}`).join('\n\n');
}

function judgeRequest(j: JudgeOffers, p: RepoProfile, caps: Capabilities, deps: JudgeDeps): { req: AiRequest; schema: AiSchema<JudgeAnswer> } {
  const kv = deps.knownValues ?? [];
  const schema = judgeSchema(j);
  return {
    schema,
    req: {
      system: JUDGE_SYSTEM,
      user: `${promptProfile(p, caps, kv)}\n\n${promptText(judgeBlocks(j, caps, deps.reviewed), kv)}\n\n${reasonBlocks(j, kv)}\n\n${JUDGE_INSTRUCTIONS}`,
      schemaName: 'judge',
      jsonSchema: schema.jsonSchema,
      timeoutMs: JUDGE_TIMEOUT_MS,
      maxOutputTokens: JUDGE_MAX_OUTPUT_TOKENS,
    },
  };
}


// ---------- the call ----------

/**
 * The judge (plan Task 2; rulings B1, B2, S3, S6-S9). `choices` are the builder's, `candidates` is keyed by need key (the map the
 * builder got). One AI request (plus completeValidated's one schema retry) and at most one repair; no code bundle. Returns the
 * objections kept (none when the judge agrees), whether it asks to turn deploy approval on (with the cleaned reason), pipegen's
 * notes and the usage. Throws NeedKeyError for a key collision before any request, JudgeError after a second bad answer, and
 * passes AiError (cost-cap included) through with usage.
 */
export async function critique(choices: readonly Choice[], needs: readonly Need[], candidates: ReadonlyMap<string, readonly Candidate[]>, p: RepoProfile, caps: Capabilities, ai: AiProvider, deps: JudgeDeps): Promise<Critique> {
  const kv = deps.knownValues ?? [];
  const j = judgeOffers(choices, needs, candidates, p, deps);
  const { req, schema } = judgeRequest(j, p, caps, deps);
  let usage: AiUsage = { ...ZERO_USAGE };
  let problems: string[] = [];
  for (let round = 0; round < 2; round++) {
    const r = await ask(ai, round === 0 ? req : repairRequest(req, problems, kv, judgeRepairText), schema, usage);
    usage = addUsage(usage, r.usage);
    const read = readJudgeAnswer(r.data, j, needs, p, caps, deps);
    if (read.problems.length > 0) { problems = read.problems; continue; }   // the whole answer is refused (ruling S3)
    return { agreed: r.data.agreed === true, objections: read.objections, ...approvalOf(r.data), notes: read.notes, usage };
  }
  throw new JudgeError('The judge AI answered twice with picks pipegen can not use, so pipegen stopped. Nothing it said was used.', problems, usage);
}
