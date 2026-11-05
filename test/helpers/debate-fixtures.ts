// Shared fixtures for the debate tests (v0.2 Plan F, F3 onwards): the real reviewed list with one proof per entry (ruling F-P2),
// a python service `api` and a TypeScript node service `web`, a need list, the candidates map as discover gives it, a scripted
// fake AI and the builder's choices built by code (builderOffers + specFor, no AI call).
import { builderOffers, specFor, type BuilderDeps, type Choice } from '../../src/debate/builder.js';
import { needKeyOf } from '../../src/debate/need-ref.js';
import { needLanguage } from '../../src/engine/discover.js';
import { needWhy } from '../../src/engine/needs.js';
import { loadQualityBar } from '../../src/engine/quality-bar.js';
import { loadReviewed, reviewedFor } from '../../src/engine/reviewed.js';
import { emptyRepoFiles, emptyServiceQuality } from '../../src/read/quality.js';
import {
  DEFAULT_MODEL, type AiProvider, type AiRequest, type AiUsage, type Candidate, type Capabilities, type Layer, type Need, type RepoProfile, type ReviewedTool, type Service,
} from '../../src/types.js';

export const NOW = new Date('2026-11-05T00:00:00Z');
/** The real reviewed list; every entry gets one proof, as after a bootstrap proof (ruling F-P2). */
export const REVIEWED: ReviewedTool[] = loadReviewed().map((t) => ({ ...t, proofs: 1 }));
export const BAR = loadQualityBar();
const CAP_NAMES = ['branchProtection', 'environments', 'deploymentBranchPolicies', 'envRequiredReviewers', 'attestations', 'codeScanning', 'keylessSigningAllowed'] as const;
export const CAPS = Object.fromEntries(CAP_NAMES.map((n) => [n, true])) as unknown as Capabilities;

export const svc = (over: Partial<Service> = {}): Service => ({
  name: 'app', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: [], frameworks: [], quality: emptyServiceQuality(), ...over,
});
export const API = svc({ name: 'api', path: 'api', language: 'python', packageManager: 'pip', envVars: ['API_TOKEN'] });
export const WEB = svc({ name: 'web', path: 'web', scripts: ['test', 'start'], frameworks: ['express'], quality: { ...emptyServiceQuality(), tsconfig: true } });
export const profile = (over: Partial<RepoProfile> = {}): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free',
  monorepo: 'folders', services: [API, WEB], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
  generatedDirs: ['web/dist'], ...over,
});
export const P = profile();

const FLOOR_IDS = ['secrets', 'sast', 'deps', 'unit-tests', 'full-tests', 'gate'];
export const need = (id: string, layer: Layer, service: string | undefined, blocking = true, why = needWhy(id) ?? ''): Need => ({
  id, layer, category: id, ...(service === undefined ? {} : { service }), why, blocking, floor: FLOOR_IDS.includes(id),
});
export const NEEDS: Need[] = [
  need('secrets', 'push', undefined),
  need('secrets', 'merge', undefined),
  need('sast', 'push', 'api'),
  need('sast', 'merge', 'api'),
  need('sast', 'merge', 'web'),
  need('coverage', 'merge', 'web', false),
  need('dast', 'merge', 'web'),
  need('unit-tests', 'merge', 'web'),
  need('gate', 'merge', undefined),
];

/** A reviewed candidate the way discover hands it over (a copy of the entry's candidate). */
export const asCandidate = (t: ReviewedTool): Candidate => ({ ...t.candidate, pin: { ...t.candidate.pin }, categories: [...t.candidate.categories], source: 'reviewed', reviewed: true });
const STATS = (repo: string) => ({
  repo, stars: 5000, archived: false, lastReleaseAt: '2026-10-01T00:00:00Z', scorecard: 8, scorecardAt: '2026-10-01T00:00:00Z', verifiedPublisher: true, license: 'MIT', advisories: 0,
});
export const discovered = (id: string, repo: string, category: string, over: Partial<Candidate> = {}): Candidate => ({
  id, name: id, kind: 'cli', repo, version: '1.0.0', pin: {}, source: 'discovery', reviewed: false, categories: [category], stats: STATS(repo), ...over,
});

/** The candidates map for a need list: every key gets the reviewed tools reviewedFor offers it (full mode), as discover does. */
export function candidatesFor(needs: readonly Need[], p: RepoProfile = P, extra: Record<string, Candidate[]> = {}, reviewed: readonly ReviewedTool[] = REVIEWED): Map<string, Candidate[]> {
  const m = new Map<string, Candidate[]>();
  for (const n of needs) {
    const key = needKeyOf(n);
    if (m.has(key)) continue;
    m.set(key, reviewedFor(n, needLanguage(n, p), [...reviewed], 'full').map(asCandidate));
  }
  for (const [k, v] of Object.entries(extra)) m.set(k, [...(m.get(k) ?? []), ...v]);
  return m;
}

export const builderDeps = (over: Partial<BuilderDeps> = {}): BuilderDeps => ({ reviewed: REVIEWED, bar: BAR, now: NOW, caps: CAPS, ...over });
export const usageOf = (input: number, output: number) => Object.fromEntries([['inputTokens', input], ['outputTokens', output]]) as unknown as AiUsage;

/**
 * The builder's choices for a need list, built by code without an AI call: for every key the AI may see, the tool `picks[key]`
 * (else the first offered one) with its template defaults, every other offered tool ranked after it, and `reasons[key]` (else a
 * plain reason) as the reason. Keys code decides get by 'pipegen'.
 */
export function choicesFor(needs: readonly Need[], p: RepoProfile = P, picks: Record<string, string> = {}, reasons: Record<string, string> = {}, deps: BuilderDeps = builderDeps(), candidates = candidatesFor(needs, p)): Choice[] {
  const o = builderOffers(needs, candidates, p, deps);
  const out: Choice[] = [];
  for (const ref of o.refs) {
    const offers = o.offers.get(ref.key);
    if (offers === undefined) continue;
    const chosen = offers.find((x) => x.entry.id === picks[ref.key]) ?? offers[0]!;
    out.push({
      key: ref.key, needId: ref.id, chosen: specFor(ref, chosen, p), by: o.aiKeys.includes(ref.key) ? 'ai' : 'pipegen',
      ranked: [chosen, ...offers.filter((x) => x !== chosen)].map((x) => structuredClone(x.entry.candidate)),
      reason: reasons[ref.key] ?? `${chosen.entry.id}, because it fits this project`,
    });
  }
  return out;
}

/** A fake provider: each call answers with the next script function (given the request), and records every request. */
export function scripted(...script: ((req: AiRequest) => unknown)[]) {
  const calls: AiRequest[] = [];
  const ai: AiProvider = {
    name: 'claude', model: DEFAULT_MODEL,
    complete: async (req: AiRequest) => {
      calls.push(req);
      const f = script[Math.min(calls.length - 1, script.length - 1)]!;
      const data = f(req);
      if (data instanceof Error) throw data;
      return { data, usage: usageOf(100, 10) };
    },
  };
  return { ai, calls };
}

/** Every property name anywhere in a JSON schema. */
export function propertyNames(node: unknown, out: string[] = []): string[] {
  if (node === null || typeof node !== 'object') return out;
  const n = node as Record<string, unknown>;
  if (n.properties !== undefined && typeof n.properties === 'object') out.push(...Object.keys(n.properties as object));
  for (const v of Object.values(n)) {
    if (Array.isArray(v)) v.forEach((x) => propertyNames(x, out));
    else propertyNames(v, out);
  }
  return out;
}

/** The PIPEGEN.md judge's options for a test doc. */
export const DOC_OPTS = { owner: 'acme', repo: 'app', containsKnownValue: () => false };
