// Live tool discovery (Plan B Task 2). For a need with no reviewed tool, pipegen looks for well-known tools and shows
// the good ones as MENTION-ONLY suggestions: listed in the audit report, never run, never turned into a step.
//
// - Tool names never come from repo text. The AI prompt holds only the need id, its category, the language and the
//   package manager, all enum values (src/ai/prompts/candidates.ts); never the code bundle, README or manifests
//   (brief; ruling F6). Search keywords come from CATEGORY_KEYWORDS (a fixed table), the language qualifier from a
//   fixed table too. The repo being audited, the AI's answers and search results are all untrusted.
// - Sources, in order, merged and deduped by repo (any letter case): reviewed tools for the need (reviewedFor with
//   the run's mode, ruling S17; ordered by proofs in memory), memory entries (reviewed tool ids only; an id no longer
//   on the reviewed list is ignored), the AI (up to MAX_AI_CANDIDATES), GitHub search (actions, then CLIs in the
//   language) and npm search (Node lint, format and test tools; a hit counts only with a GitHub repo link, S36).
// - Every unreviewed candidate is checked in order: a valid GitHub owner/name (S14), not a look-alike of ANY
//   reviewed tool (nearDuplicate on the full list, S17/S31), the repo exists under that exact name. suggestTools
//   then reads its stats (fetchStats) and applies the quality bar. Anything that fails is dropped with one note.
// - Bounds: MAX_CANDIDATES per need (brief), MAX_DISCOVERY_NEEDS per run, MAX_CHECKED_PER_NEED stats lookups and
//   MAX_SUGGESTIONS_PER_NEED suggestions per need, one shared rate budget (the caller's newRateBudget(), S16) and a
//   wall-clock bound (DISCOVERY_DEADLINE_MS, on the injected clock).
// - Only `deps.gh` (Octokit, api.github.com) carries the user's credential; `deps.fetch` (npm search) never gets an
//   auth header (S15). AI usage goes to deps.onUsage, also when the call fails (S4). AI text is cleaned (links
//   removed, safeText) before anyone sees it; toSuggestions passes name and why through safeText again.
import type { Octokit } from '@octokit/rest';
import { z } from 'zod';
import { CANDIDATES_SYSTEM, candidatesUser } from '../ai/prompts/candidates.js';
import { AiError, completeValidated } from '../ai/provider.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import { safeText } from '../util/safe-text.js';
import type {
  AiProvider, AiUsage, Candidate, InstallSpec, Language, Need, NeedCategory, PackageManager, PipelineDraft, RepoProfile, ReviewedTool,
} from '../types.js';
import { BUDGET_SPENT_MESSAGE, GitHubRateLimitError, withRateLimit, type RateClock } from './github-rate.js';
import type { MemoryStore } from './memory.js';
import { githubRepoFromUrl, isFullSemver, isGitHubRepo, isNpmName, repoSegments } from './names.js';
import { cleanAiText, NEED_ID_CATEGORY } from './needs.js';
import { checkQualityBar, type QualityBar } from './quality-bar.js';
import { nearDuplicate, reviewedFor } from './reviewed.js';
import { fetchStats, StatsError } from './stats.js';

/** Candidates returned per need (brief). */
export const MAX_CANDIDATES = 10;
/** AI answers read per need (brief: up to 6). */
export const MAX_AI_CANDIDATES = 6;
/** Results taken from each search (brief: top 5). */
export const SEARCH_RESULTS = 5;
/** Needs discovery runs for in one run (distinct need id + language). */
export const MAX_DISCOVERY_NEEDS = 5;
/** Candidates per need whose stats are read (each costs several GitHub calls). */
export const MAX_CHECKED_PER_NEED = 5;
/** Suggestions kept per need. */
export const MAX_SUGGESTIONS_PER_NEED = 3;
/** The whole discovery in one run stops after this long (injected clock). */
export const DISCOVERY_DEADLINE_MS = 120_000;

const CANDIDATES_TIMEOUT_MS = 60_000;
const NPM_SEARCH_URL = 'https://registry.npmjs.org/-/v1/search';
const REQUEST_TIMEOUT_MS = 20_000;
const MAX_BODY_CHARS = 2_000_000;
const KINDS = ['action', 'cli', 'docker'] as const satisfies readonly Candidate['kind'][];
const LANGUAGES = ['node', 'python', 'go', 'java', 'dotnet', 'ruby', 'php', 'other'] as const satisfies readonly Language[];
const PACKAGE_MANAGERS = ['npm', 'pnpm', 'yarn', 'bun', 'pip', 'poetry', 'uv', 'other'] as const satisfies readonly PackageManager[];
/** A tool's display name as the AI or a search gives it; anything else falls back to the repo's name. */
const TOOL_NAME_RE = /^[A-Za-z0-9@][A-Za-z0-9 ._@/+-]{0,63}$/;

/**
 * Search keywords per need category: a fixed table in code, never repo text. A category that isn't here (pipegen's
 * own gate, hooks, image build, signing, attestation, deploy checks) is never searched for or asked about.
 */
export const CATEGORY_KEYWORDS: Readonly<Partial<Record<NeedCategory, string>>> = Object.freeze({
  secrets: 'secret scanner',
  sast: 'static analysis security',
  deps: 'dependency vulnerability scanner',
  'unit-tests': 'test runner',
  'full-tests': 'test runner',
  lint: 'linter',
  'format-lint': 'code formatter',
  iac: 'terraform security scanner',
  'image-scan': 'container vulnerability scanner',
  dast: 'web application security scanner',
  sbom: 'sbom generator',
});

/** GitHub search's `language:` value per pipegen language; `other` → no CLI search. */
const SEARCH_LANGUAGE: Readonly<Record<Language, string | null>> = {
  node: 'javascript', python: 'python', go: 'go', java: 'java', dotnet: 'csharp', ruby: 'ruby', php: 'php', other: null,
};
/** Node-side tool categories that npm search covers (brief: lint, test, format). */
const NPM_CATEGORIES: ReadonlySet<string> = new Set(['lint', 'format-lint', 'unit-tests', 'full-tests']);

const FALLBACK_WHY = 'Found by pipegen\'s discovery; pipegen has not reviewed it.';
const searchWhy = (where: string, category: string) => `Found by ${where} for ${category} checks (most used first); pipegen has not reviewed it.`;

export interface DiscoverDeps extends RateClock {
  ai: AiProvider; gh: Octokit; memory: MemoryStore; fetch: typeof fetch;
  /** The FULL reviewed list: the typosquat check always uses all of it (ruling S17). */
  reviewed: ReviewedTool[];
  /** Which reviewed tools count for the need (reviewedFor): the audit takes every reviewed entry, full runs proven ones. */
  mode: 'audit' | 'full';
  /** Plain-English notes (deduped, already cleaned): every dropped candidate, every search that failed. */
  notes?: string[];
  /** Gets what each AI call cost, also when it fails (ruling S4). */
  onUsage?: (u: AiUsage) => void;
  /** discover fills it: candidate repo → why text (cleaned), for toSuggestions. */
  why?: Map<string, string>;
}
export interface SuggestDeps extends DiscoverDeps { bar: QualityBar }

/** A candidate before its checks: where it came from and what it would need for stats. */
interface Raw { repo: unknown; name: string; kind: Candidate['kind']; why: string; install?: InstallSpec; version?: string }
interface Gathered { candidates: Candidate[]; installs: Map<Candidate, InstallSpec>; why: Map<string, string> }

type AiCandidates = { candidates: { needId: string; category: string; language: string; kind: Candidate['kind']; name: string; repo: string; why: string }[] };

function noter(list: string[] | undefined): (text: string) => void {
  return (text) => {
    const t = safeText(text, 400);
    if (list !== undefined && !list.includes(t)) list.push(t);
  };
}

const categoryOf = (n: Need): NeedCategory | undefined => {
  const c = Object.hasOwn(NEED_ID_CATEGORY, n.id) ? NEED_ID_CATEGORY[n.id as keyof typeof NEED_ID_CATEGORY] : undefined;
  return c !== undefined && c === n.category ? c : undefined;
};

/** One value every listed thing shares, else 'other' (also when the list is empty or a value isn't in `allowed`). */
function shared<T extends string>(values: (T | undefined)[], allowed: readonly T[]): T | 'other' {
  const set = new Set(values);
  const only = set.size === 1 ? [...set][0] : undefined;
  return only !== undefined && allowed.includes(only) ? only : 'other';
}

/** Ruling S18: a need's language is its service's; a repo-wide need's is the one every service shares, else 'other'. */
export function needLanguage(need: Need, p: RepoProfile): Language {
  const services = need.service === undefined ? p.services : p.services.filter((s) => s.name === need.service).slice(0, 1);
  return shared(services.map((s) => s.language), LANGUAGES);
}

/** The package manager the same way (an enum for the prompt). */
function needPackageManager(need: Need, p: RepoProfile): PackageManager {
  const services = need.service === undefined ? p.services : p.services.filter((s) => s.name === need.service).slice(0, 1);
  return shared(services.map((s) => s.packageManager), PACKAGE_MANAGERS);
}

/** The AI's answer schema: need id, category and language fixed to the asked need (one-value enums), kind an enum. */
function candidatesSchema(needId: string, category: NeedCategory, language: Language): AiSchema<AiCandidates> {
  return aiSchema<AiCandidates>(z.strictObject({
    candidates: z.array(z.strictObject({
      needId: z.enum([needId] as [string]),
      category: z.enum([category] as [string]),
      language: z.enum([language] as [string]),
      kind: z.enum(KINDS),
      name: z.string(),
      repo: z.string(),
      why: z.string(),
    })),
  }));
}

/** The name shown for a candidate: the given one when it looks like a tool name, else the repo's name. */
function displayName(given: unknown, repo: string): string {
  return typeof given === 'string' && TOOL_NAME_RE.test(given) ? given : repo.slice(repo.indexOf('/') + 1);
}

/** Is a failure GitHub's rate limit (or the run's spent wait budget)? Then no more GitHub work is worth trying. */
function isRateStop(e: unknown): boolean {
  return e instanceof GitHubRateLimitError
    || (e instanceof StatsError && (e.message === BUDGET_SPENT_MESSAGE || e.cause instanceof GitHubRateLimitError));
}

/** The sources, merged and checked: reviewed and memory candidates first, then checked discovery candidates. */
async function gather(need: Need, p: RepoProfile, deps: DiscoverDeps): Promise<Gathered> {
  const note = noter(deps.notes);
  const result: Gathered = { candidates: [], installs: new Map(), why: new Map() };
  const category = categoryOf(need);
  if (category === undefined) {
    note(`pipegen can't look for tools for the need "${safeText(String(need.id), 40)}": it isn't a need pipegen knows.`);
    return result;
  }
  const language = needLanguage(need, p);
  const out = result.candidates;
  const seen = new Set<string>();
  const add = (c: Candidate) => {
    seen.add(c.repo.toLowerCase());
    out.push(c);
  };

  // 1. Reviewed tools for the need (this run's mode), the ones memory has proven most first.
  const remembered = deps.memory.lookup(category, language);
  const proofs = new Map<string, number>();
  for (const e of remembered) proofs.set(e.toolId, Math.max(proofs.get(e.toolId) ?? 0, e.proofs));
  const reviewed = reviewedFor(need, language, deps.reviewed, deps.mode)
    .map((t, i) => ({ t, i }))
    .sort((a, b) => (proofs.get(b.t.id) ?? 0) - (proofs.get(a.t.id) ?? 0) || a.i - b.i)
    .map((x) => x.t);
  for (const t of reviewed) {
    if (!seen.has(t.candidate.repo.toLowerCase())) add({ ...t.candidate, pin: { ...t.candidate.pin }, categories: [...t.candidate.categories], source: 'reviewed', reviewed: true });
  }

  // 2. Memory: reviewed tool ids only, re-read from the reviewed list (memory stores no step, no repo, no name).
  const byId = new Map(deps.reviewed.map((t) => [t.id, t]));
  for (const e of remembered) {
    const t = byId.get(e.toolId);
    if (t === undefined) {
      note('pipegen ignored a tool it remembered that is no longer on its reviewed list.');
      continue;
    }
    if (!t.categories.includes(category) || !(t.languages.includes(language) || t.languages.includes('any'))) continue;
    if (!seen.has(t.candidate.repo.toLowerCase())) add({ ...t.candidate, pin: { ...t.candidate.pin }, categories: [...t.candidate.categories], source: 'memory', reviewed: true });
  }

  const keywords = CATEGORY_KEYWORDS[category];
  if (out.length >= MAX_CANDIDATES || keywords === undefined) {
    out.splice(MAX_CANDIDATES);
    return result;
  }

  // 3-5. The AI (enum fields only), GitHub search and npm search (fixed keywords).
  const raw: Raw[] = [
    ...(await askAi(need.id, category, language, needPackageManager(need, p), deps, note)),
    ...(await searchGitHub(keywords, category, language, deps, note)),
    ...(language === 'node' && NPM_CATEGORIES.has(category) ? await searchNpm(keywords, category, deps, note) : []),
  ];

  // Checks, in order: a valid repo name, not a look-alike of any reviewed tool, the repo exists under that name.
  let rateLimited = false;
  for (const r of raw) {
    if (out.length >= MAX_CANDIDATES) break;
    if (!isGitHubRepo(r.repo)) {
      note('pipegen left out a suggested tool: it is not a valid GitHub repo (owner/name).');
      continue;
    }
    const repo = r.repo;
    if (seen.has(repo.toLowerCase())) continue;
    seen.add(repo.toLowerCase());
    const twin = nearDuplicate(repo, deps.reviewed);
    if (twin !== null) {
      note(`pipegen left out ${repo}: its name is very close to the reviewed tool ${twin.candidate.repo}, so it may be a look-alike.`);
      continue;
    }
    if (rateLimited) {
      note('pipegen left out some suggested tools: GitHub\'s rate limit stopped it checking that they exist.');
      continue;
    }
    const found = await repoExists(repo, deps);
    if (found === 'rate-limited') {
      rateLimited = true;
      note('pipegen left out some suggested tools: GitHub\'s rate limit stopped it checking that they exist.');
      continue;
    }
    if (found === 'missing') { note(`pipegen left out ${repo}: that GitHub repo doesn't exist (or isn't public).`); continue; }
    if (found === 'moved') { note(`pipegen left out ${repo}: the repo has moved to another name, and pipegen checks the exact name only.`); continue; }
    if (found === 'unknown') { note(`pipegen left out ${repo}: it couldn't check that the repo exists.`); continue; }
    const c: Candidate = {
      id: repo.toLowerCase(), name: displayName(r.name, repo), kind: r.kind, repo, version: r.version ?? '', pin: {},
      source: 'discovery', reviewed: false, categories: [category],
    };
    add(c);
    if (r.install !== undefined) result.installs.set(c, r.install);
    result.why.set(repo, r.why);
  }
  return result;
}

/** GET /repos/{o}/{r}: the repo exists under exactly this name (a renamed or transferred repo doesn't count). */
async function repoExists(repo: string, deps: DiscoverDeps): Promise<'ok' | 'missing' | 'moved' | 'unknown' | 'rate-limited'> {
  const { owner, name } = repoSegments(repo);
  try {
    const res = await withRateLimit(() => deps.gh.rest.repos.get({ owner, repo: name }), deps);
    const full = (res.data as { full_name?: unknown } | null)?.full_name;
    return typeof full === 'string' && full.toLowerCase() === repo.toLowerCase() ? 'ok' : 'moved';
  } catch (e) {
    if (e instanceof GitHubRateLimitError) return 'rate-limited';
    return (e as { status?: unknown } | null)?.status === 404 ? 'missing' : 'unknown';
  }
}

/** The AI's candidates (prompt: enum fields only). AiError passes through after its usage is reported. */
async function askAi(needId: string, category: NeedCategory, language: Language, packageManager: PackageManager, deps: DiscoverDeps, note: (t: string) => void): Promise<Raw[]> {
  const schema = candidatesSchema(needId, category, language);
  let data: AiCandidates;
  try {
    const r = await completeValidated(deps.ai, {
      system: CANDIDATES_SYSTEM,
      user: candidatesUser({ needId, category, language, packageManager }, MAX_AI_CANDIDATES),
      schemaName: 'candidates',
      jsonSchema: schema.jsonSchema,
      timeoutMs: CANDIDATES_TIMEOUT_MS,
    }, schema.zod);
    deps.onUsage?.(r.usage);
    data = r.data;
  } catch (e) {
    if (e instanceof AiError && e.usage !== undefined) deps.onUsage?.(e.usage);
    throw e;
  }
  if (data.candidates.length > MAX_AI_CANDIDATES) note(`pipegen read only the first ${MAX_AI_CANDIDATES} of the ${data.candidates.length} tools the AI suggested.`);
  return data.candidates.slice(0, MAX_AI_CANDIDATES).map((a) => ({
    repo: a.repo, name: a.name, kind: a.kind, why: cleanAiText(a.why) || FALLBACK_WHY,
  }));
}

const searchSchema = z.object({ items: z.array(z.object({ full_name: z.string(), name: z.string().optional(), archived: z.boolean().optional() })) });

/** GitHub search, sorted by stars: actions (topic:github-action), then CLIs in the need's language. Never fails the run. */
async function searchGitHub(keywords: string, category: string, language: Language, deps: DiscoverDeps, note: (t: string) => void): Promise<Raw[]> {
  const queries: { q: string; kind: Candidate['kind'] }[] = [{ q: `${keywords} topic:github-action`, kind: 'action' }];
  const lang = SEARCH_LANGUAGE[language];
  if (lang !== null) queries.push({ q: `${keywords} language:${lang}`, kind: 'cli' });
  const out: Raw[] = [];
  for (const { q, kind } of queries) {
    let items: z.infer<typeof searchSchema>['items'];
    try {
      const res = await withRateLimit(() => deps.gh.rest.search.repos({ q, sort: 'stars', order: 'desc', per_page: SEARCH_RESULTS }), deps);
      const parsed = searchSchema.safeParse(res.data);
      if (!parsed.success) {
        note('GitHub search gave an unexpected answer, so pipegen continued without its results.');
        continue;
      }
      items = parsed.data.items;
    } catch (e) {
      if (e instanceof GitHubRateLimitError) {
        note('GitHub search hit its rate limit, so pipegen continued without search results.');
        break; // the next search would hit it too
      }
      note('GitHub search failed, so pipegen continued without its results.');
      continue;
    }
    for (const item of items.slice(0, SEARCH_RESULTS)) {
      if (item.archived === true) continue;
      out.push({ repo: item.full_name, name: item.name ?? '', kind, why: searchWhy('GitHub search', category) });
    }
  }
  return out;
}

const npmSearchSchema = z.object({
  objects: z.array(z.object({
    package: z.object({ name: z.unknown(), version: z.unknown().optional(), links: z.object({ repository: z.unknown().optional() }).nullish() }),
  })),
});

/** npm search (no credential, ruling S15). A hit is kept only when it links to a GitHub repo (ruling S36). */
async function searchNpm(keywords: string, category: string, deps: DiscoverDeps, note: (t: string) => void): Promise<Raw[]> {
  let body: unknown;
  try {
    const url = `${NPM_SEARCH_URL}?text=${encodeURIComponent(keywords)}&size=${SEARCH_RESULTS}`;
    const res = await deps.fetch(url, { method: 'GET', redirect: 'error', headers: { accept: 'application/json' }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BODY_CHARS) throw new Error('answer too large');
    body = JSON.parse(text);
  } catch {
    note('npm search failed, so pipegen continued without its results.');
    return [];
  }
  const parsed = npmSearchSchema.safeParse(body);
  if (!parsed.success) {
    note('npm search gave an unexpected answer, so pipegen continued without its results.');
    return [];
  }
  const out: Raw[] = [];
  for (const { package: pkg } of parsed.data.objects.slice(0, SEARCH_RESULTS)) {
    if (!isNpmName(pkg.name)) {
      note('pipegen left out an npm package whose name it can\'t use.');
      continue;
    }
    const repo = githubRepoFromUrl(pkg.links?.repository);
    if (repo === null) {
      note(`pipegen left out the npm package ${pkg.name}: it doesn't link to a GitHub repo, so pipegen can't check it.`);
      continue;
    }
    const version = typeof pkg.version === 'string' && isFullSemver(pkg.version) ? pkg.version : '';
    out.push({ repo, name: pkg.name, kind: 'cli', version, why: searchWhy('npm search', category), install: { method: 'npm', package: pkg.name, version } });
  }
  return out;
}

/**
 * Candidates for one need (unverified for quality: suggestTools reads stats and applies the bar), at most
 * MAX_CANDIDATES, deduped by repo. Reviewed tools first, then memory, then discovery candidates that passed the
 * name, typosquat and existence checks. AiError passes through (after deps.onUsage).
 */
export async function discover(need: Need, p: RepoProfile, deps: DiscoverDeps): Promise<Candidate[]> {
  const g = await gather(need, p, deps);
  if (deps.why !== undefined) for (const [repo, why] of g.why) deps.why.set(repo, why);
  return g.candidates;
}

/**
 * The mention-only list (PipelineDraft.suggestions): unreviewed discovery candidates only (the caller passes the
 * ones that passed the quality bar), each once, as exactly { name, repo, why }. Never a step. name and why go
 * through safeText; the report's Markdown output uses safeMarkdown on top (Plan G/U).
 */
export function toSuggestions(cands: Candidate[], why: Map<string, string>): PipelineDraft['suggestions'] {
  const out: PipelineDraft['suggestions'] = [];
  const seen = new Set<string>();
  for (const c of cands) {
    if (c.reviewed !== false || c.source !== 'discovery' || !isGitHubRepo(c.repo)) continue;
    const key = c.repo.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const name = safeText(String(c.name ?? ''), 64) || c.repo.slice(c.repo.indexOf('/') + 1);
    out.push({ name, repo: c.repo, why: safeText(why.get(c.repo) ?? '', 200) || FALLBACK_WHY });
  }
  return out;
}

/**
 * The audit chain (Plan U, `audit --ai`): for each need with no reviewed tool (one discovery per need id and
 * language, at most MAX_DISCOVERY_NEEDS), discover → fetchStats → checkQualityBar → toSuggestions. A StatsError drops
 * that candidate with a note and never fails the run; GitHub's rate limit (or the run's spent wait budget) and the
 * wall-clock bound stop the search and keep what passed so far. AiError passes through.
 */
export async function suggestTools(needs: Need[], p: RepoProfile, deps: SuggestDeps): Promise<PipelineDraft['suggestions']> {
  const note = noter(deps.notes);
  const now = deps.now ?? Date.now;
  const deadline = now() + DISCOVERY_DEADLINE_MS;
  const timeUp = () => {
    if (now() <= deadline) return false;
    note(`pipegen stopped looking for tool suggestions: it ran out of time (${Math.round(DISCOVERY_DEADLINE_MS / 60_000)} minutes).`);
    return true;
  };

  const picked: Need[] = [];
  const keys = new Set<string>();
  let skipped = 0;
  for (const n of needs) {
    const category = categoryOf(n);
    if (category === undefined || CATEGORY_KEYWORDS[category] === undefined) continue;
    const language = needLanguage(n, p);
    if (reviewedFor(n, language, deps.reviewed, deps.mode).length > 0) continue;
    const key = `${n.id}|${language}`;
    if (keys.has(key)) continue;
    keys.add(key);
    if (picked.length < MAX_DISCOVERY_NEEDS) picked.push(n);
    else skipped++;
  }
  if (skipped > 0) note(`pipegen looked for tool suggestions for the first ${MAX_DISCOVERY_NEEDS} needs with no reviewed tool, and skipped ${skipped} more.`);

  const stats = { gh: deps.gh, fetch: deps.fetch, budget: deps.budget, sleep: deps.sleep, now: deps.now };
  const why = new Map<string, string>();
  const passed: Candidate[] = [];
  const judged = new Set<string>(); // repos already checked for an earlier need
  search: for (const need of picked) {
    if (timeUp()) break;
    const g = await gather(need, p, deps);
    let checked = 0;
    let kept = 0;
    for (const c of g.candidates) {
      if (c.reviewed || c.source !== 'discovery') continue;
      if (kept >= MAX_SUGGESTIONS_PER_NEED || checked >= MAX_CHECKED_PER_NEED) break;
      const key = c.repo.toLowerCase();
      if (judged.has(key)) continue;
      if (timeUp()) break search;
      judged.add(key);
      checked++;
      let s;
      try {
        s = await fetchStats(c, stats, g.installs.get(c));
      } catch (e) {
        if (!(e instanceof StatsError || e instanceof GitHubRateLimitError)) throw e;
        note(`pipegen didn't suggest ${c.repo}: ${e.message}`);
        if (isRateStop(e)) {
          note('pipegen stopped looking for tool suggestions: GitHub\'s rate limit was reached.');
          break search;
        }
        continue;
      }
      const verdict = checkQualityBar(s, deps.bar, new Date(now()));
      if (!verdict.pass) {
        note(`pipegen didn't suggest ${c.repo}: it doesn't meet the quality bar (${verdict.reasons.join(' ')})`);
        continue;
      }
      kept++;
      passed.push({ ...c, stats: s });
      why.set(c.repo, g.why.get(c.repo) ?? FALLBACK_WHY);
    }
  }
  return toSuggestions(passed, why);
}
