// Live tool discovery (Plan B Task 2). For a need with no reviewed tool, pipegen looks for well-known tools and shows
// the good ones as MENTION-ONLY suggestions: listed in the audit report, never run, never turned into a step.
// suggestTools is the supported path (Plan U, `audit --ai`); discover and toSuggestions are its parts.
//
// - Tool names never come from repo text. The AI prompt holds only the need id, its category, the language and the
//   package manager, all enum values (src/ai/prompts/candidates.ts); never the code bundle, README or manifests
//   (brief; ruling F6; controller ruling in fix round 1). Search keywords come from CATEGORY_KEYWORDS (a fixed
//   table), the language qualifier from a fixed table too. The repo being audited, the AI's answers and search
//   results are all untrusted. A suggestion is shown under its checked repo's name (npm: its checked package name),
//   never a name the AI or a search gave.
// - Sources, in order, merged and deduped by repo (any letter case): reviewed tools for the need (reviewedForNeed:
//   reviewedFor with the run's mode, ruling S17, the ones memory has proven most first; memory holds reviewed tool
//   ids only, an id no longer on the reviewed list is ignored, and in full mode only entries with a proof count),
//   the AI (up to MAX_AI_CANDIDATES), GitHub search (actions, then CLIs in the language) and npm search (Node lint,
//   format and test tools; a hit counts only with a GitHub repo link, S36).
// - Every unreviewed candidate is checked in order: a valid GitHub owner/name (S14), not a repo already on the
//   reviewed list (for another check), not a look-alike of ANY reviewed tool (nearDuplicate on the full list,
//   S17/S31), the repo exists under that exact name. suggestTools then confirms that an "action" really is one
//   (action.yml at the repo root; else it is checked as a CLI), reads its stats (fetchStats) and applies the quality
//   bar. Anything that fails is dropped with one note.
// - Bounds: MAX_CANDIDATES per need (brief), MAX_DISCOVERY_NEEDS per run, MAX_CHECKED_PER_NEED stats lookups and
//   MAX_SUGGESTIONS_PER_NEED suggestions per need, one shared rate budget (the caller's newRateBudget(), S16) and a
//   wall-clock bound (DISCOVERY_DEADLINE_MS, on the injected clock). GitHub's rate limit (or the spent budget) stops
//   the whole run, so no later need makes a billed AI call for nothing.
// - Only `deps.gh` (Octokit, api.github.com) carries the user's credential; `deps.fetch` (npm search) never gets an
//   auth header (S15) and goes through the shared http.ts (no redirect, a bounded read). AI usage goes to deps.onUsage, also when the call fails (S4). AI text is cleaned (links
//   removed, safeText) before anyone sees it; toSuggestions passes name and why through safeText again.
import type { Octokit } from '@octokit/rest';
import { z } from 'zod';
import { CANDIDATES_SYSTEM, candidatesUser } from '../ai/prompts/candidates.js';
import { AiError, completeValidated, type AiErrorKind } from '../ai/provider.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import { safeText } from '../util/safe-text.js';
import type {
  AiProvider, AiUsage, Candidate, InstallSpec, Language, Need, NeedCategory, PackageManager, PipelineDraft, RepoProfile, ReviewedTool,
} from '../types.js';
import { CANDIDATES_MAX_OUTPUT_TOKENS, MAX_DISCOVERY_NEEDS } from './discovery-limits.js';
import { GitHubRateLimitError, isRateStop, withRateLimit, type RateClock } from './github-rate.js';
import { fetchAllowed, readJson } from './http.js';
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
export { MAX_DISCOVERY_NEEDS } from './discovery-limits.js';
/** Candidates per need whose stats are read (each costs several GitHub calls). */
export const MAX_CHECKED_PER_NEED = 5;
/** Suggestions kept per need. */
export const MAX_SUGGESTIONS_PER_NEED = 3;
/** The whole discovery in one run stops after this long (injected clock). */
export const DISCOVERY_DEADLINE_MS = 120_000;

const CANDIDATES_TIMEOUT_MS = 60_000;
const NPM_SEARCH_URL = 'https://registry.npmjs.org/-/v1/search';
const REQUEST_TIMEOUT_MS = 20_000;
/** Cap on the npm search answer (bytes, enforced while it streams). */
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const KINDS = ['action', 'cli', 'docker'] as const satisfies readonly Candidate['kind'][];
const LANGUAGES = ['node', 'python', 'go', 'java', 'dotnet', 'ruby', 'php', 'other'] as const satisfies readonly Language[];
const PACKAGE_MANAGERS = ['npm', 'pnpm', 'yarn', 'bun', 'pip', 'poetry', 'uv', 'other'] as const satisfies readonly PackageManager[];
/** The files that make a repo a GitHub Action (at its root). */
const ACTION_FILES: ReadonlySet<string> = new Set(['action.yml', 'action.yaml']);
/**
 * AI failures after which suggestTools asks the AI nothing more in this run: the provider rejected the request
 * itself (an HTTP error such as a bad key or a spent quota), isn't set up, or the next call could pass the agreed AI
 * cost cap (Plan U ruling U13). Other failures (refusal, invalid, truncated, timeout) only skip the AI for that need.
 */
const STOP_AI_KINDS: ReadonlySet<AiErrorKind> = new Set<AiErrorKind>(['http', 'missing', 'cost-cap']);
/** The one note a cost-cap stop gives (review M2). */
export const COST_CAP_STOP_NOTE = 'pipegen stopped asking the AI for tool suggestions before the AI cost limit you agreed to; the search went on without the AI.';

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
const RATE_STOP_NOTE = 'pipegen stopped looking for tool suggestions: GitHub\'s rate limit was reached.';

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

/** A candidate before its checks. `name` only for npm hits (a checked package name); everything else shows its repo's name. */
interface Raw { repo: unknown; name?: string; kind: Candidate['kind']; why: string; install?: InstallSpec; version?: string }
interface Gathered {
  candidates: Candidate[]; installs: Map<Candidate, InstallSpec>; why: Map<string, string>;
  /** GitHub's rate limit stopped the existence checks, or the run's wait budget is spent: no more GitHub work is worth trying. */
  rateLimited: boolean;
  /** The AI call failed (only when gather was told to go on without it). */
  aiError?: AiError;
}
interface GatherOptions { useAi: boolean; continueWithoutAi: boolean }

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

/** A repo's own name (the part after the slash): what a discovered candidate is shown as. */
const repoName = (repo: string) => repo.slice(repo.indexOf('/') + 1);

/**
 * The reviewed tools that cover a need, the rule both discover and suggestTools use: reviewedFor with the run's mode
 * (S17), ordered so the ones memory has proven most first (an entry with no proof adds nothing to the order).
 * Memory holds reviewed tool ids only, and an id no longer on the reviewed list is ignored with a note. Memory only
 * orders: it never adds a tool reviewedFor doesn't give, so in full mode a tool still needs a proof on the reviewed
 * list itself (fix round 1, M1).
 */
function reviewedForNeed(need: Need, category: NeedCategory, language: Language, deps: DiscoverDeps, note: (t: string) => void): ReviewedTool[] {
  const known = new Set(deps.reviewed.map((t) => t.id));
  const proofs = new Map<string, number>();
  for (const e of deps.memory.lookup(category, language)) {
    if (!known.has(e.toolId)) {
      note('pipegen ignored a tool it remembered that is no longer on its reviewed list.');
      continue;
    }
    proofs.set(e.toolId, Math.max(proofs.get(e.toolId) ?? 0, e.proofs));
  }
  return reviewedFor(need, language, deps.reviewed, deps.mode)
    .map((t, i) => ({ t, i }))
    .sort((a, b) => (proofs.get(b.t.id) ?? 0) - (proofs.get(a.t.id) ?? 0) || a.i - b.i)
    .map((x) => x.t);
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

/** The sources, merged and checked: reviewed candidates first, then checked discovery candidates. */
async function gather(need: Need, p: RepoProfile, deps: DiscoverDeps, opts: GatherOptions): Promise<Gathered> {
  const note = noter(deps.notes);
  const result: Gathered = { candidates: [], installs: new Map(), why: new Map(), rateLimited: false };
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

  // 1-2. Reviewed tools for the need (this run's mode), the ones memory has proven most first.
  for (const t of reviewedForNeed(need, category, language, deps, note)) {
    if (!seen.has(t.candidate.repo.toLowerCase())) add({ ...t.candidate, pin: { ...t.candidate.pin }, categories: [...t.candidate.categories], source: 'reviewed', reviewed: true });
  }

  const keywords = CATEGORY_KEYWORDS[category];
  if (out.length >= MAX_CANDIDATES || keywords === undefined) {
    out.splice(MAX_CANDIDATES);
    return result;
  }

  // 3. The AI (enum fields only).
  const raw: Raw[] = [];
  if (opts.useAi) {
    try {
      raw.push(...(await askAi(need.id, category, language, needPackageManager(need, p), deps, note)));
    } catch (e) {
      if (!(opts.continueWithoutAi && e instanceof AiError)) throw e;
      result.aiError = e;
    }
  }
  // 4-5. GitHub search and npm search (fixed keywords).
  const gh = await searchGitHub(keywords, category, language, deps, note);
  raw.push(...gh.raw);
  if (gh.budgetSpent) result.rateLimited = true;
  if (language === 'node' && NPM_CATEGORIES.has(category)) raw.push(...(await searchNpm(keywords, category, deps, note)));

  // Checks, in order: a valid repo name, not already reviewed, not a look-alike of any reviewed tool, the repo exists.
  const reviewedRepos = new Map(deps.reviewed.map((t) => [t.candidate.repo.toLowerCase(), t]));
  const unchecked = 'pipegen left out some suggested tools: GitHub\'s rate limit stopped it checking that they exist.';
  for (const r of raw) {
    if (out.length >= MAX_CANDIDATES) break;
    if (!isGitHubRepo(r.repo)) {
      note('pipegen left out a suggested tool: it is not a valid GitHub repo (owner/name).');
      continue;
    }
    const repo = r.repo;
    if (seen.has(repo.toLowerCase())) continue;
    seen.add(repo.toLowerCase());
    if (reviewedRepos.has(repo.toLowerCase())) {
      note(`pipegen left out ${repo}: it is on pipegen's reviewed list for other checks, not this one.`);
      continue;
    }
    const twin = nearDuplicate(repo, deps.reviewed);
    if (twin !== null) {
      note(`pipegen left out ${repo}: its name is very close to the reviewed tool ${twin.candidate.repo}, so it may be a look-alike.`);
      continue;
    }
    if (result.rateLimited) {
      note(unchecked);
      continue;
    }
    const found = await repoExists(repo, deps);
    if (found === 'rate-limited') {
      result.rateLimited = true;
      note(unchecked);
      continue;
    }
    if (found === 'missing') { note(`pipegen left out ${repo}: that GitHub repo doesn't exist (or isn't public).`); continue; }
    if (found === 'moved') { note(`pipegen left out ${repo}: the repo has moved to another name, and pipegen checks the exact name only.`); continue; }
    if (found === 'unknown') { note(`pipegen left out ${repo}: it couldn't check that the repo exists.`); continue; }
    const c: Candidate = {
      id: repo.toLowerCase(), name: r.name ?? repoName(repo), kind: r.kind, repo, version: r.version ?? '', pin: {},
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

/**
 * Is the repo a GitHub Action: an action.yml or action.yaml file at the root of its default branch (one listing of
 * the root, through the rate-limit helper). Discovery candidates carry no version, so the stats use the latest
 * release; the default branch is the one place to look without guessing a ref. Anything that isn't a clear yes is a no.
 */
async function isAction(repo: string, deps: DiscoverDeps): Promise<'yes' | 'no' | 'unknown' | 'rate-limited'> {
  const { owner, name } = repoSegments(repo);
  try {
    const res = await withRateLimit(() => deps.gh.rest.repos.getContent({ owner, repo: name, path: '' }), deps);
    const list = Array.isArray(res.data) ? (res.data as { name?: unknown; type?: unknown }[]) : [];
    return list.some((f) => f.type === 'file' && typeof f.name === 'string' && ACTION_FILES.has(f.name)) ? 'yes' : 'no';
  } catch (e) {
    if (e instanceof GitHubRateLimitError) return 'rate-limited';
    return (e as { status?: unknown } | null)?.status === 404 ? 'no' : 'unknown';
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
      maxOutputTokens: CANDIDATES_MAX_OUTPUT_TOKENS,
    }, schema.zod);
    deps.onUsage?.(r.usage);
    data = r.data;
  } catch (e) {
    if (e instanceof AiError && e.usage !== undefined) deps.onUsage?.(e.usage);
    throw e;
  }
  if (data.candidates.length > MAX_AI_CANDIDATES) note(`pipegen read only the first ${MAX_AI_CANDIDATES} of the ${data.candidates.length} tools the AI suggested.`);
  // The AI's `name` is never used: a suggestion is shown under its checked repo's name, so the AI can't present an
  // unknown repo under a reviewed tool's name.
  return data.candidates.slice(0, MAX_AI_CANDIDATES).map((a) => ({ repo: a.repo, kind: a.kind, why: cleanAiText(a.why) || FALLBACK_WHY }));
}

const searchSchema = z.object({ items: z.array(z.object({ full_name: z.string(), archived: z.boolean().optional() })) });

/**
 * GitHub search, sorted by stars: actions (topic:github-action), then CLIs in the need's language. Never fails the
 * run. `budgetSpent`: the run's wait budget ran out here (search has its own rate limit, which only skips search).
 */
async function searchGitHub(keywords: string, category: string, language: Language, deps: DiscoverDeps, note: (t: string) => void): Promise<{ raw: Raw[]; budgetSpent: boolean }> {
  const queries: { q: string; kind: Candidate['kind'] }[] = [{ q: `${keywords} topic:github-action`, kind: 'action' }];
  const lang = SEARCH_LANGUAGE[language];
  if (lang !== null) queries.push({ q: `${keywords} language:${lang}`, kind: 'cli' });
  const raw: Raw[] = [];
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
        return { raw, budgetSpent: e.budgetSpent }; // the next search would hit it too
      }
      note('GitHub search failed, so pipegen continued without its results.');
      continue;
    }
    for (const item of items.slice(0, SEARCH_RESULTS)) {
      if (item.archived === true) continue;
      raw.push({ repo: item.full_name, kind, why: searchWhy('GitHub search', category) });
    }
  }
  return { raw, budgetSpent: false };
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
    // shared http.ts: registry.npmjs.org only, no redirect at all, the answer read up to MAX_BODY_BYTES as it streams
    const url = `${NPM_SEARCH_URL}?text=${encodeURIComponent(keywords)}&size=${SEARCH_RESULTS}`;
    const res = await fetchAllowed(deps.fetch, url, { method: 'GET', timeoutMs: REQUEST_TIMEOUT_MS, hosts: [new URL(NPM_SEARCH_URL).hostname], maxRedirects: 0 });
    body = await readJson(res, MAX_BODY_BYTES, 'the npm search answer');
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
 * MAX_CANDIDATES, deduped by repo. Reviewed tools first (the ones memory has proven most first), then discovery
 * candidates that passed the name, reviewed-list, typosquat and existence checks. AiError passes through (after
 * deps.onUsage).
 */
export async function discover(need: Need, p: RepoProfile, deps: DiscoverDeps): Promise<Candidate[]> {
  const g = await gather(need, p, deps, { useAi: true, continueWithoutAi: false });
  if (deps.why !== undefined) for (const [repo, why] of g.why) deps.why.set(repo, why);
  return g.candidates;
}

/**
 * The mention-only list (PipelineDraft.suggestions): unreviewed discovery candidates whose stats (read for that
 * same repo) pass the quality bar at `now`, each once, as exactly { name, repo, why }. A candidate without stats,
 * or whose stats fail the bar, is skipped. Never a step. name and why go through safeText; the report's Markdown
 * output uses safeMarkdown on top (Plan G/U). suggestTools is the supported way to get here.
 */
export function toSuggestions(cands: Candidate[], why: Map<string, string>, bar: QualityBar, now: Date): PipelineDraft['suggestions'] {
  const out: PipelineDraft['suggestions'] = [];
  const seen = new Set<string>();
  for (const c of cands) {
    if (c.reviewed !== false || c.source !== 'discovery' || !isGitHubRepo(c.repo)) continue;
    if (c.stats === undefined || c.stats.repo.toLowerCase() !== c.repo.toLowerCase() || !checkQualityBar(c.stats, bar, now).pass) continue;
    const key = c.repo.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const name = safeText(String(c.name ?? ''), 64) || repoName(c.repo);
    out.push({ name, repo: c.repo, why: safeText(why.get(c.repo) ?? '', 200) || FALLBACK_WHY });
  }
  return out;
}

/**
 * The audit chain (Plan U, `audit --ai`), the supported path: for each need no reviewed tool covers (the same rule
 * discover uses; one discovery per need id and language, at most MAX_DISCOVERY_NEEDS), discover → (action check) →
 * fetchStats → checkQualityBar → toSuggestions.
 * - A StatsError drops that candidate with a note and never fails the run.
 * - GitHub's rate limit or the run's spent wait budget (in existence checks, search or stats) and the wall-clock
 *   bound stop the whole search; what passed so far is kept.
 * - An AI failure for one need is noted and that need goes on with search results only; an http or missing-provider
 *   failure stops asking the AI for the rest of the run (STOP_AI_KINDS). Usage is still reported (S4).
 */
export async function suggestTools(needs: Need[], p: RepoProfile, deps: SuggestDeps): Promise<PipelineDraft['suggestions']> {
  const note = noter(deps.notes);
  const now = deps.now ?? Date.now;
  const started = now();
  const deadline = started + DISCOVERY_DEADLINE_MS;
  const at = new Date(started); // the quality bar is judged at one moment for the whole run
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
    if (reviewedForNeed(n, category, language, deps, note).length > 0) continue;
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
  let useAi = true;
  search: for (const need of picked) {
    if (timeUp()) break;
    const g = await gather(need, p, deps, { useAi, continueWithoutAi: true });
    if (g.aiError?.kind === 'cost-cap') {
      useAi = false;
      note(COST_CAP_STOP_NOTE); // one note for the stop, not one per need
    } else if (g.aiError !== undefined) {
      note(`The AI couldn't suggest tools for the ${need.id} need (${g.aiError.message}); pipegen went on with search results for it.`);
      if (STOP_AI_KINDS.has(g.aiError.kind)) {
        useAi = false;
        note(`pipegen stopped asking the AI for tool suggestions (${g.aiError.message}) and continued without the AI.`);
      }
    }
    if (g.rateLimited) {
      note(RATE_STOP_NOTE);
      break;
    }
    let checked = 0;
    let kept = 0;
    for (const found of g.candidates) {
      if (found.reviewed || found.source !== 'discovery') continue;
      if (kept >= MAX_SUGGESTIONS_PER_NEED || checked >= MAX_CHECKED_PER_NEED) break;
      const key = found.repo.toLowerCase();
      if (judged.has(key)) continue;
      if (timeUp()) break search;
      judged.add(key);
      checked++;
      let c = found;
      if (c.kind === 'action') {
        // Advisories for an action come from GitHub's Actions database, which says nothing about other repos: a repo
        // that only claims to be an action is checked as a CLI (no advisory lookup → unchecked → the bar refuses).
        const action = await isAction(c.repo, deps);
        if (action === 'rate-limited') {
          note(RATE_STOP_NOTE);
          break search;
        }
        if (action !== 'yes') {
          note(action === 'no'
            ? `${c.repo} is not a GitHub Action (no action.yml at the root of its default branch), so pipegen checked it as a command-line tool.`
            : `pipegen couldn't confirm that ${c.repo} is a GitHub Action, so it checked it as a command-line tool.`);
          c = { ...c, kind: 'cli' };
        }
      }
      let s;
      // the stats' own notes (why advisories are unknown) go into the run's notes, deduped (final review M3)
      const statsNotes: string[] = [];
      try {
        s = await fetchStats(c, { ...stats, notes: statsNotes }, g.installs.get(found));
      } catch (e) {
        for (const n of statsNotes) note(n);
        if (!(e instanceof StatsError || e instanceof GitHubRateLimitError)) throw e;
        note(`pipegen didn't suggest ${c.repo}: ${e.message}`);
        if (isRateStop(e)) {
          note(RATE_STOP_NOTE);
          break search;
        }
        continue;
      }
      for (const n of statsNotes) note(n);
      const verdict = checkQualityBar(s, deps.bar, at);
      if (!verdict.pass) {
        note(`pipegen didn't suggest ${c.repo}: it doesn't meet the quality bar (${verdict.reasons.join(' ')})`);
        continue;
      }
      kept++;
      passed.push({ ...c, stats: s });
      why.set(c.repo, g.why.get(c.repo) ?? FALLBACK_WHY);
    }
  }
  return toSuggestions(passed, why, deps.bar, at);
}
