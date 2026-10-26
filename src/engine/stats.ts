// Live stats for one tool (Plan B Task 3), the facts the quality bar checks: GitHub repo (stars, archived,
// licence), last release, OpenSSF Scorecard, verified publisher and known advisories for the version in question.
// - Every name is checked before any request (ruling S14): a bad repo or package name is refused with a StatsError
//   and nothing is sent. Versions and tags that come back from GitHub are checked the same way before use.
// - Only `deps.gh` (Octokit, api.github.com) carries the user's credential. `deps.fetch` (Scorecard, OSV) is called
//   with no auth header (ruling S15).
// - Advisories (ruling S12): a version that can't be resolved or checked gives `advisories: null`, never 0, so the
//   quality bar fails closed. The reason is added to `deps.notes`.
// - GitHub calls go through the shared rate-limit helper (ruling S16).
import type { Octokit } from '@octokit/rest';
import { z } from 'zod';
import { safeText } from '../util/safe-text.js';
import type { Candidate, InstallSpec, ToolStats } from '../types.js';
import { GitHubRateLimitError, withRateLimit, type RateClock } from './github-rate.js';
import { advisoryVersion, COMMIT_SHA_RE, isGitHubRepo, isNpmName, isPypiName, repoSegments } from './names.js';

export interface StatsDeps extends RateClock {
  gh: Octokit;
  fetch: typeof fetch;
  /** Why advisories couldn't be checked, in plain English (already cleaned for display). */
  notes?: string[];
}

export class StatsError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'StatsError';
  }
}

const SCORECARD_BASE = 'https://api.scorecard.dev/projects/github.com/';
const OSV_QUERY = 'https://api.osv.dev/v1/query';
const REQUEST_TIMEOUT_MS = 20_000;
const MAX_BODY_CHARS = 4_000_000;
/** Pages of 100 tags searched for the tag of a pinned commit. */
const TAG_PAGES = 3;
const SPDX_RE = /^[A-Za-z0-9.+-]{1,64}$/;

const repoSchema = z.object({
  stargazers_count: z.number().int().nonnegative(),
  archived: z.boolean(),
  license: z.object({ spdx_id: z.string().nullish() }).nullish(),
  owner: z.object({ type: z.string() }),
});
const releaseSchema = z.object({ tag_name: z.string(), published_at: z.string().nullish() });
const tagsSchema = z.array(z.object({ name: z.string(), commit: z.object({ sha: z.string() }) }));
const commitSchema = z.object({ committer: z.object({ date: z.string() }) });
const scorecardSchema = z.object({ score: z.number().min(0).max(10) });
const osvSchema = z.object({ vulns: z.array(z.unknown()).optional() });
const advisoriesSchema = z.array(z.object({ withdrawn_at: z.string().nullish() }));

type Tag = z.infer<typeof tagsSchema>[number];
/** Where known advisories for this tool are looked up. */
type Target =
  | { db: 'github-actions' }
  | { db: 'osv'; ecosystem: 'npm' | 'PyPI'; package: string }
  | { db: 'none'; what: string };

const isNotFound = (e: unknown) => (e as { status?: unknown } | null)?.status === 404;

function isoDate(s: string | null | undefined): string | null {
  if (typeof s !== 'string') return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

/** Install method first (npm and pip packages are in OSV), then the kind: actions are in GitHub's advisory database. */
function targetFor(c: Candidate, install?: InstallSpec): Target {
  if (install?.method === 'npm') {
    if (!isNpmName(install.package)) throw new StatsError(`"${safeText(String(install.package), 80)}" isn't an npm package name pipegen can look up.`);
    return { db: 'osv', ecosystem: 'npm', package: install.package };
  }
  if (install?.method === 'pip') {
    if (!isPypiName(install.package)) throw new StatsError(`"${safeText(String(install.package), 80)}" isn't a PyPI package name pipegen can look up.`);
    return { db: 'osv', ecosystem: 'PyPI', package: install.package };
  }
  if (c.kind === 'action') return { db: 'github-actions' };
  return { db: 'none', what: c.kind === 'docker' || install?.method === 'docker' ? 'container images' : 'release binaries' };
}

/** Fetches the facts the quality bar checks. Throws StatsError (or GitHubRateLimitError) when they can't be read. */
export async function fetchStats(c: Candidate, deps: StatsDeps, install?: InstallSpec): Promise<ToolStats> {
  if (!isGitHubRepo(c.repo)) throw new StatsError(`"${safeText(String(c.repo), 120)}" isn't a GitHub repo (owner/name) pipegen can look up.`);
  const target = targetFor(c, install);
  const repo = c.repo;
  const { owner, name, path } = repoSegments(repo);
  const note = (text: string) => deps.notes?.push(safeText(text, 300));

  /** One GitHub call through the rate-limit helper; 404 → null when allowed; other failures → StatsError. */
  async function github<T>(what: string, call: () => Promise<{ data: unknown }>, schema: z.ZodType<T>, on404?: 'null'): Promise<T | null> {
    let data: unknown;
    try {
      data = (await withRateLimit(call, deps)).data;
    } catch (e) {
      if (e instanceof GitHubRateLimitError) throw e;
      if (on404 && isNotFound(e)) return null;
      throw new StatsError(`Couldn't read ${what} for ${repo} from GitHub.`, { cause: e });
    }
    const parsed = schema.safeParse(data);
    if (!parsed.success) throw new StatsError(`GitHub gave an unexpected answer for ${what} of ${repo}.`);
    return parsed.data;
  }

  const tagPages: Tag[][] = [];
  async function tagPage(i: number): Promise<Tag[]> {
    while (tagPages.length <= i) {
      const prev = tagPages[tagPages.length - 1];
      if (prev !== undefined && prev.length < 100) return [];
      const page = tagPages.length + 1;
      tagPages.push((await github('the tags', () => deps.gh.rest.repos.listTags({ owner, repo: name, per_page: 100, page }), tagsSchema)) ?? []);
    }
    return tagPages[i] ?? [];
  }

  const info = await github('the repo', () => deps.gh.rest.repos.get({ owner, repo: name }), repoSchema, 'null');
  if (info === null) throw new StatsError(`The GitHub repo ${repo} doesn't exist (or isn't public).`);
  const spdx = info.license?.spdx_id ?? null;
  const license = spdx !== null && SPDX_RE.test(spdx) ? spdx : null;

  const latest = await github('the latest release', () => deps.gh.rest.repos.getLatestRelease({ owner, repo: name }), releaseSchema, 'null');
  const lastReleaseAt = isoDate(latest?.published_at) ?? (await latestTagDate());

  const scorecard = await fetchScorecard();
  const verifiedPublisher = info.owner.type === 'Organization' && (await isVerifiedOrg());
  const advisories = await countAdvisories();

  return { repo, stars: info.stargazers_count, archived: info.archived, lastReleaseAt, scorecard, verifiedPublisher, license, advisories };

  /** No published release: the commit date of the first tag GitHub lists. No tags → null. */
  async function latestTagDate(): Promise<string | null> {
    const first = (await tagPage(0))[0];
    if (first === undefined || !COMMIT_SHA_RE.test(first.commit.sha)) return null;
    const commit = await github('the latest tag', () => deps.gh.rest.git.getCommit({ owner, repo: name, commit_sha: first.commit.sha }), commitSchema);
    return isoDate(commit?.committer.date);
  }

  /** OpenSSF Scorecard score out of 10; 404 (not scored) → null. Any other failure is an error, never a guess. */
  async function fetchScorecard(): Promise<number | null> {
    let res: Response;
    let body: unknown;
    try {
      res = await deps.fetch(SCORECARD_BASE + path, { method: 'GET', headers: { accept: 'application/json' }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      body = await readJson(res);
    } catch (e) {
      throw new StatsError(`Couldn't read the OpenSSF Scorecard score of ${repo}.`, { cause: e });
    }
    const parsed = scorecardSchema.safeParse(body);
    if (!parsed.success) throw new StatsError(`OpenSSF Scorecard gave an unexpected answer for ${repo}.`);
    return parsed.data.score;
  }

  /** Ruling S34: an Organization GitHub has verified. Display only (no rule uses it), so a failed lookup is false. */
  async function isVerifiedOrg(): Promise<boolean> {
    try {
      const org = await withRateLimit(() => deps.gh.rest.orgs.get({ org: owner }), deps);
      return (org.data as { is_verified?: unknown }).is_verified === true;
    } catch {
      return false;
    }
  }

  /** Known advisories for the version in question; null (with a note) whenever that can't be checked. */
  async function countAdvisories(): Promise<number | null> {
    if (target.db === 'none') {
      note(`pipegen can't look up known vulnerabilities for ${target.what} yet, so ${repo} counts as unchecked.`);
      return null;
    }
    const version = await versionToCheck(target.db === 'osv' && target.ecosystem === 'PyPI' ? 'pep440' : 'semver');
    if (version === null) return null;
    const failed = () => {
      note(`pipegen couldn't check ${repo} for known vulnerabilities (the advisory lookup failed), so it counts as unchecked.`);
      return null;
    };
    if (target.db === 'github-actions') {
      try {
        const res = await withRateLimit(() => deps.gh.rest.securityAdvisories.listGlobalAdvisories({ ecosystem: 'actions', affects: `${repo}@${version}`, per_page: 100 }), deps);
        const parsed = advisoriesSchema.safeParse(res.data);
        return parsed.success ? parsed.data.filter((a) => a.withdrawn_at == null).length : failed();
      } catch {
        return failed();
      }
    }
    try {
      const res = await deps.fetch(OSV_QUERY, {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({ version, package: { name: target.package, ecosystem: target.ecosystem } }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!res.ok) return failed();
      const parsed = osvSchema.safeParse(await readJson(res));
      return parsed.success ? (parsed.data.vulns ?? []).length : failed();
    } catch {
      return failed();
    }
  }

  /**
   * The version advisories are checked for (ruling S19): the install spec's or candidate's version; else the tag of
   * the pinned commit (advisory databases take versions, not SHAs); else the latest release's tag. null + a note
   * when there is none or it isn't a version.
   */
  async function versionToCheck(shape: 'semver' | 'pep440'): Promise<string | null> {
    const unchecked = `so pipegen couldn't check it for known vulnerabilities.`;
    const explicit = install?.version || c.version;
    if (typeof explicit === 'string' && explicit !== '') {
      const v = advisoryVersion(explicit, shape);
      if (v === null) note(`The version "${safeText(explicit, 40)}" of ${repo} isn't a version pipegen can look up, ${unchecked}`);
      return v;
    }
    const sha = c.pin.sha;
    if (sha !== undefined && sha !== '') {
      if (!COMMIT_SHA_RE.test(sha)) {
        note(`The pinned commit of ${repo} isn't a full commit SHA, ${unchecked}`);
        return null;
      }
      const tag = await tagOfCommit(sha, shape);
      if (tag === undefined) note(`No release tag points at the pinned commit of ${repo}, ${unchecked}`);
      else if (tag === null) note(`The tag on the pinned commit of ${repo} isn't a version pipegen can look up, ${unchecked}`);
      return tag ?? null;
    }
    if (latest === null) {
      note(`${repo} has no published release to check for known vulnerabilities.`);
      return null;
    }
    const v = advisoryVersion(latest.tag_name, shape);
    if (v === null) note(`The latest release tag of ${repo} isn't a version pipegen can look up, ${unchecked}`);
    return v;
  }

  /** The most specific version among the tags on `sha` (v4.2.2 over v4); null when tags exist but none is a version, undefined when none. */
  async function tagOfCommit(sha: string, shape: 'semver' | 'pep440'): Promise<string | null | undefined> {
    const onCommit: Tag[] = [];
    for (let i = 0; i < TAG_PAGES; i++) {
      const page = await tagPage(i);
      onCommit.push(...page.filter((t) => t.commit.sha.toLowerCase() === sha));
      if (page.length < 100) break;
    }
    if (onCommit.length === 0) return undefined;
    let best: string | null = null;
    for (const t of onCommit) {
      const v = advisoryVersion(t.name, shape);
      if (v !== null && (best === null || v.split('.').length > best.split('.').length)) best = v;
    }
    return best;
  }
}

/** The JSON body of a response, refusing very large bodies. */
async function readJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (text.length > MAX_BODY_CHARS) throw new Error('answer too large');
  return JSON.parse(text);
}
