// Live stats for one tool (Plan B Task 3), the facts the quality bar checks: GitHub repo (stars, archived,
// licence), last release, OpenSSF Scorecard score and date, verified publisher and known advisories for the version
// in question.
// - Every name is checked before any request (ruling S14): a bad repo or package name is refused with a StatsError
//   and nothing is sent. Versions and tags that come back from GitHub are checked the same way before use.
// - The exact repo only: a repo GitHub reports under another name (renamed or transferred) is refused.
// - An npm or PyPI package only borrows the repo's stats when a link the repo owner controls proves it is published
//   from that repo: registry provenance for that version naming the repo, or the repo's root manifest naming the
//   package (and not marked private) while the registry's own metadata points back at the repo. A provenance naming
//   another repo, or from a publisher that isn't GitHub, is a refusal.
// - Only `deps.gh` (Octokit, api.github.com) carries the user's credential. `deps.fetch` (Scorecard, OSV, npm,
//   PyPI) is called with no auth header (ruling S15), through the shared http.ts: redirects only within the URL's
//   own host (a POST follows none), every answer read up to MAX_BODY_BYTES while it streams.
// - Advisories (ruling S12): a version that can't be resolved or checked gives `advisories: null`, never 0, so the
//   quality bar fails closed. The reason is added to `deps.notes`. With a pinned commit, the versions checked are
//   the full version tags on that commit, and the highest count is kept.
// - GitHub calls go through the shared rate-limit helper (ruling S16); a spent wait budget is a StatsError whose cause
//   is the GitHubRateLimitError (isRateStop in github-rate.ts recognises it).
import type { Octokit } from '@octokit/rest';
import { parse as parseToml } from 'smol-toml';
import { z } from 'zod';
import { safeText } from '../util/safe-text.js';
import type { Candidate, InstallSpec, ToolStats } from '../types.js';
import { BUDGET_SPENT_MESSAGE, GitHubRateLimitError, isRateStop, withRateLimit, type RateClock } from './github-rate.js';
import { fetchAllowed, readJson } from './http.js';
import {
  advisoryVersion, COMMIT_SHA_RE, compareSemver, githubRepoFromUrl, isFullSemver, isGitHubRepo, isNpmName, isPypiName, npmEscapedName, pep503,
  repoSegments,
} from './names.js';

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
const NPM_REGISTRY = 'https://registry.npmjs.org/';
const NPM_ATTESTATIONS = `${NPM_REGISTRY}-/npm/v1/attestations/`;
const PYPI = 'https://pypi.org';
const REQUEST_TIMEOUT_MS = 20_000;
/** Cap on any answer read from Scorecard, OSV, npm or PyPI (bytes, enforced while it streams). */
const MAX_BODY_BYTES = 4 * 1024 * 1024;
/** Cap on one provenance payload (base64 text). */
const MAX_PAYLOAD_CHARS = 4_000_000;
const MAX_MANIFEST_CHARS = 1_500_000;
/** Pages of 100 tags searched (tags on a pinned commit, the highest version tag). */
const TAG_PAGES = 3;
/** At most this many versions on one commit are looked up; more → advisories unknown. */
const MAX_VERSIONS = 5;
/** PyPI release files checked for a provenance; a release with more gives no provenance proof (unknown). */
const MAX_PYPI_FILES = 3;
const PRIVATE_CLASSIFIER = 'Private :: Do Not Upload';
const SPDX_RE = /^[A-Za-z0-9.+-]{1,64}$/;
const PYPI_FILE_RE = /^[A-Za-z0-9._+-]{1,255}$/;
/** Stands for a provenance whose repo can't be read: never equal to a checked repo, so it counts as another repo. */
const UNREADABLE_REPO = '<unreadable>';

const repoSchema = z.object({
  full_name: z.string(),
  stargazers_count: z.number().int().nonnegative(),
  archived: z.boolean(),
  license: z.object({ spdx_id: z.string().nullish() }).nullish(),
  owner: z.object({ type: z.string() }),
});
const releaseSchema = z.object({ tag_name: z.string(), published_at: z.string().nullish() });
const tagsSchema = z.array(z.object({ name: z.string(), commit: z.object({ sha: z.string() }) }));
const commitSchema = z.object({ committer: z.object({ date: z.string() }) });
const contentSchema = z.object({ type: z.literal('file'), encoding: z.literal('base64'), content: z.string().max(MAX_MANIFEST_CHARS) });
const scorecardSchema = z.object({ score: z.number().min(0).max(10), date: z.string().nullish() });
const osvSchema = z.object({ vulns: z.array(z.unknown()).optional() });
const advisoriesSchema = z.array(z.object({ withdrawn_at: z.string().nullish() }));
const npmAttestationsSchema = z.object({
  attestations: z.array(z.object({ predicateType: z.string(), bundle: z.object({ dsseEnvelope: z.object({ payload: z.string() }) }) })),
});
const npmVersionSchema = z.object({ version: z.string().nullish(), repository: z.union([z.string(), z.object({ url: z.unknown() })]).nullish() });
const pypiReleaseSchema = z.object({
  info: z.object({ version: z.string().nullish(), home_page: z.unknown(), project_urls: z.record(z.string(), z.unknown()).nullish() }).nullish(),
  urls: z.array(z.object({ filename: z.string() })).nullish(),
});
const pypiProvenanceSchema = z.object({ attestation_bundles: z.array(z.object({ publisher: z.object({ kind: z.string(), repository: z.string().nullish() }) })) });

type Tag = z.infer<typeof tagsSchema>[number];
type Shape = 'semver' | 'pep440';
/** Where known advisories for this tool are looked up. */
type Target =
  | { db: 'github-actions' }
  | { db: 'osv'; ecosystem: 'npm' | 'PyPI'; package: string }
  | { db: 'none'; what: string };
/** What registry provenance says about the repo a package was built from. */
type Provenance = 'this-repo' | 'other-repo' | 'none';

const isNotFound = (e: unknown) => (e as { status?: unknown } | null)?.status === 404;
const budgetSpent = (e: unknown) => e instanceof GitHubRateLimitError && e.budgetSpent;
const isFull = (v: string, shape: Shape) => shape === 'pep440' || isFullSemver(v);

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
  const shape: Shape = target.db === 'osv' && target.ecosystem === 'PyPI' ? 'pep440' : 'semver';
  const label = install?.version || c.version;
  const note = (text: string) => deps.notes?.push(safeText(text, 300));
  const stopped = (e: unknown) => new StatsError(BUDGET_SPENT_MESSAGE, { cause: e });

  /** One GitHub call through the rate-limit helper; 404 → null when allowed; other failures → StatsError. */
  async function github<T>(what: string, call: () => Promise<{ data: unknown }>, schema: z.ZodType<T>, on404?: 'null'): Promise<T | null> {
    let data: unknown;
    try {
      data = (await withRateLimit(call, deps)).data;
    } catch (e) {
      if (budgetSpent(e)) throw stopped(e);
      if (e instanceof GitHubRateLimitError) throw e;
      if (on404 && isNotFound(e)) return null;
      throw new StatsError(`Couldn't read ${what} for ${repo} from GitHub.`, { cause: e });
    }
    const parsed = schema.safeParse(data);
    if (!parsed.success) throw new StatsError(`GitHub gave an unexpected answer for ${what} of ${repo}.`);
    return parsed.data;
  }

  /**
   * GET or POST with deps.fetch through the shared http.ts (never an auth header; redirects only within the URL's
   * own host, a POST follows none; the body read up to MAX_BODY_BYTES). A non-2xx answer → its status and no body;
   * null on any failure.
   */
  async function getJson(url: string, init: { method?: 'GET' | 'POST'; accept?: string; body?: string } = {}): Promise<{ status: number; body: unknown } | null> {
    try {
      const res = await fetchAllowed(deps.fetch, url, {
        method: init.method ?? 'GET', timeoutMs: REQUEST_TIMEOUT_MS, hosts: [new URL(url).hostname], headers: { accept: init.accept ?? 'application/json' },
        body: init.body, status: 'any',
      });
      if (!res.ok) {
        await res.body?.cancel().catch(() => {});
        return { status: res.status, body: undefined };
      }
      return { status: res.status, body: await readJson(res, MAX_BODY_BYTES, url) };
    } catch {
      return null;
    }
  }

  /** The package's PyPI name in URLs: PEP 503-normalised, then encoded. */
  const pypiPath = (pkg: string) => encodeURIComponent(pep503(pkg));
  /** The registry's metadata for the package, fetched once (see registryMetadata). */
  let metadata: Promise<unknown> | undefined;

  const tagPages: Tag[][] = [];
  /** Every tag in the first TAG_PAGES pages (fetched once). */
  async function allTags(): Promise<Tag[]> {
    while (tagPages.length < TAG_PAGES) {
      const prev = tagPages[tagPages.length - 1];
      if (prev !== undefined && prev.length < 100) break;
      const page = tagPages.length + 1;
      tagPages.push((await github('the tags', () => deps.gh.rest.repos.listTags({ owner, repo: name, per_page: 100, page }), tagsSchema)) ?? []);
    }
    return tagPages.flat();
  }

  const info = await github('the repo', () => deps.gh.rest.repos.get({ owner, repo: name }), repoSchema, 'null');
  if (info === null) throw new StatsError(`The GitHub repo ${repo} doesn't exist (or isn't public).`);
  // GitHub follows a renamed or transferred repo silently; pipegen checks the exact name only.
  if (info.full_name.toLowerCase() !== repo.toLowerCase()) {
    throw new StatsError(`The repository moved to ${safeText(info.full_name, 120)}; pipegen checks the exact name only.`);
  }
  if (target.db === 'osv') await confirmPublishedFromRepo(target);

  const spdx = info.license?.spdx_id ?? null;
  const license = spdx !== null && SPDX_RE.test(spdx) ? spdx : null;

  const latest = await github('the latest release', () => deps.gh.rest.repos.getLatestRelease({ owner, repo: name }), releaseSchema, 'null');
  const lastReleaseAt = isoDate(latest?.published_at) ?? (await highestTagDate());

  const { scorecard, scorecardAt } = await fetchScorecard();
  const verifiedPublisher = info.owner.type === 'Organization' && (await isVerifiedOrg());
  const advisories = await countAdvisories();

  return { repo, stars: info.stargazers_count, archived: info.archived, lastReleaseAt, scorecard, scorecardAt, verifiedPublisher, license, advisories };

  /**
   * Ruling I1 (and round 2): the package must be shown to come from this repo by something the repo owner controls.
   * Registry provenance for this exact version naming the repo; else the repo's root manifest naming the package
   * (not marked private) AND the registry's metadata for the package pointing back at the repo. A provenance naming
   * another repo, or neither proof, is a refusal.
   */
  async function confirmPublishedFromRepo(t: { ecosystem: 'npm' | 'PyPI'; package: string }): Promise<void> {
    const provenance = await provenanceOf(t);
    if (provenance === 'this-repo') return;
    if (provenance === 'none' && (await rootManifestNames(t)) && (await registryPointsBack(t))) return;
    throw new StatsError(`Couldn't confirm that ${t.package} is published from ${repo}.`);
  }

  /**
   * The registry's metadata for the package: the exact version when the label is one, else the latest
   * (fetched once). npm: the version document; PyPI: the release JSON (links and files).
   */
  function registryMetadata(t: { ecosystem: 'npm' | 'PyPI'; package: string }): Promise<unknown> {
    const version = exactVersion();
    const url = t.ecosystem === 'npm'
      ? `${NPM_REGISTRY}${npmEscapedName(t.package)}/${version === null ? 'latest' : encodeURIComponent(version)}`
      : `${PYPI}/pypi/${pypiPath(t.package)}/${version === null ? '' : `${encodeURIComponent(version)}/`}json`;
    metadata ??= getJson(url).then((r) => r?.body);
    return metadata;
  }

  /** The registry's own metadata names this repo: npm `repository`; PyPI `home_page` or any `project_urls` link. */
  async function registryPointsBack(t: { ecosystem: 'npm' | 'PyPI'; package: string }): Promise<boolean> {
    const body = await registryMetadata(t);
    const same = (link: unknown) => githubRepoFromUrl(link)?.toLowerCase() === repo.toLowerCase();
    if (t.ecosystem === 'npm') {
      const parsed = npmVersionSchema.safeParse(body);
      const r = parsed.success ? parsed.data.repository : null;
      return same(typeof r === 'string' ? r : r?.url);
    }
    const parsed = pypiReleaseSchema.safeParse(body);
    const info = parsed.success ? parsed.data.info : null;
    return [info?.home_page, ...Object.values(info?.project_urls ?? {})].some(same);
  }

  /** The registry's latest version of the package (npm `/latest`, PyPI's project JSON), checked; null when unreadable. */
  async function registryLatestVersion(t: { ecosystem: 'npm' | 'PyPI'; package: string }): Promise<string | null> {
    const body = await registryMetadata(t); // no version label → the latest document
    const raw = t.ecosystem === 'npm' ? npmVersionSchema.safeParse(body).data?.version : pypiReleaseSchema.safeParse(body).data?.info?.version;
    if (typeof raw !== 'string') return null;
    const v = advisoryVersion(raw, shape);
    return v !== null && v === raw && isFull(v, shape) ? v : null;
  }

  /** The full version label (install spec's or candidate's), for the registry's per-version provenance. */
  function exactVersion(): string | null {
    if (typeof label !== 'string' || label === '') return null;
    const v = advisoryVersion(label, shape);
    return v !== null && isFull(v, shape) ? v : null;
  }

  /** The repos registry provenance names: 'other-repo' if any is not this repo, 'this-repo' if one is, else 'none'. */
  function judge(repos: string[]): Provenance {
    const named = repos.map((r) => r.toLowerCase());
    if (named.some((r) => r !== repo.toLowerCase())) return 'other-repo';
    return named.length > 0 ? 'this-repo' : 'none';
  }

  async function provenanceOf(t: { ecosystem: 'npm' | 'PyPI'; package: string }): Promise<Provenance> {
    const version = exactVersion();
    if (version === null) return 'none';
    if (t.ecosystem === 'npm') {
      const res = await getJson(`${NPM_ATTESTATIONS}${npmEscapedName(t.package)}@${encodeURIComponent(version)}`);
      const parsed = npmAttestationsSchema.safeParse(res?.body);
      if (!parsed.success) return 'none';
      return judge(parsed.data.attestations.filter((a) => a.predicateType.startsWith('https://slsa.dev/provenance/')).map((a) => slsaRepo(a.bundle.dsseEnvelope.payload)));
    }
    const release = pypiReleaseSchema.safeParse(await registryMetadata(t));
    if (!release.success) return 'none';
    const files = (release.data.urls ?? []).map((u) => u.filename);
    // more files than are checked, or a name pipegen won't put in a URL: the provenance is unknown, never partial
    if (files.length > MAX_PYPI_FILES || files.some((f) => !PYPI_FILE_RE.test(f))) return 'none';
    const repos: string[] = [];
    for (const f of files) {
      const url = `${PYPI}/integrity/${pypiPath(t.package)}/${encodeURIComponent(version)}/${encodeURIComponent(f)}/provenance`;
      const prov = pypiProvenanceSchema.safeParse((await getJson(url, { accept: 'application/vnd.pypi.integrity.v1+json' }))?.body);
      if (!prov.success) continue;
      for (const b of prov.data.attestation_bundles) {
        // a publisher that isn't GitHub (or a repo that can't be read) counts as another repo
        const named = b.publisher.kind === 'GitHub' && typeof b.publisher.repository === 'string' && isGitHubRepo(b.publisher.repository);
        repos.push(named ? (b.publisher.repository as string) : UNREADABLE_REPO);
      }
    }
    return judge(repos);
  }

  /** The repo's root package.json / pyproject.toml names the package (PyPI names compared PEP 503-normalised) and isn't marked private. */
  async function rootManifestNames(t: { ecosystem: 'npm' | 'PyPI'; package: string }): Promise<boolean> {
    const file = t.ecosystem === 'npm' ? 'package.json' : 'pyproject.toml';
    const content = await github(`the root ${file}`, () => deps.gh.rest.repos.getContent({ owner, repo: name, path: file }), contentSchema, 'null')
      .catch((e: unknown) => {
        // rate limits still stop the run; any other failure to read the manifest is simply no proof
        if (isRateStop(e)) throw e;
        return null;
      });
    if (content === null) return false;
    try {
      const text = Buffer.from(content.content, 'base64').toString('utf8');
      // a manifest marked private says the package is NOT published from here
      if (t.ecosystem === 'npm') {
        const pkg = JSON.parse(text) as { name?: unknown; private?: unknown };
        return pkg.private !== true && pkg.name === t.package;
      }
      type PyMeta = { name?: unknown; classifiers?: unknown };
      const toml = parseToml(text) as { project?: PyMeta; tool?: { poetry?: PyMeta } };
      const sections = [toml.project, toml.tool?.poetry].filter((m): m is PyMeta => m !== undefined && m !== null);
      const isPrivate = sections.some((m) => Array.isArray(m.classifiers) && m.classifiers.some((c) => typeof c === 'string' && c.trim() === PRIVATE_CLASSIFIER));
      return !isPrivate && sections.some((m) => typeof m.name === 'string' && pep503(m.name) === pep503(t.package));
    } catch {
      return false;
    }
  }

  /** No published release: the commit date of the highest full semver tag (not the first one listed). None → null. */
  async function highestTagDate(): Promise<string | null> {
    let best: { v: string; sha: string } | null = null;
    for (const t of await allTags()) {
      const v = advisoryVersion(t.name, 'semver');
      if (v === null || !isFullSemver(v) || !COMMIT_SHA_RE.test(t.commit.sha)) continue;
      if (best === null || compareSemver(v, best.v) > 0) best = { v, sha: t.commit.sha };
    }
    if (best === null) return null;
    const sha = best.sha;
    const commit = await github('the latest tag', () => deps.gh.rest.git.getCommit({ owner, repo: name, commit_sha: sha }), commitSchema);
    return isoDate(commit?.committer.date);
  }

  /** OpenSSF Scorecard score out of 10 and its date; 404 (not scored) → nulls. Any other failure is an error, never a guess. */
  async function fetchScorecard(): Promise<{ scorecard: number | null; scorecardAt: string | null }> {
    let body: unknown;
    try {
      const url = SCORECARD_BASE + path;
      const res = await fetchAllowed(deps.fetch, url, { method: 'GET', timeoutMs: REQUEST_TIMEOUT_MS, hosts: [new URL(url).hostname], notFound: 'null' });
      if (res === null) return { scorecard: null, scorecardAt: null };
      body = await readJson(res, MAX_BODY_BYTES, 'the OpenSSF Scorecard answer');
    } catch (e) {
      throw new StatsError(`Couldn't read the OpenSSF Scorecard score of ${repo}.`, { cause: e });
    }
    const parsed = scorecardSchema.safeParse(body);
    if (!parsed.success) throw new StatsError(`OpenSSF Scorecard gave an unexpected answer for ${repo}.`);
    return { scorecard: parsed.data.score, scorecardAt: isoDate(parsed.data.date) };
  }

  /** Ruling S34: an Organization GitHub has verified. Display only (no rule uses it), so a failed lookup is false. */
  async function isVerifiedOrg(): Promise<boolean> {
    try {
      const org = await withRateLimit(() => deps.gh.rest.orgs.get({ org: owner }), deps);
      return (org.data as { is_verified?: unknown }).is_verified === true;
    } catch (e) {
      if (budgetSpent(e)) throw stopped(e);
      return false;
    }
  }

  /** Known advisories for the version(s) in question (the highest count); null (with a note) whenever that can't be checked. */
  async function countAdvisories(): Promise<number | null> {
    if (target.db === 'none') {
      note(`pipegen can't look up known vulnerabilities for ${target.what} yet, so ${repo} counts as unchecked.`);
      return null;
    }
    const versions = await versionsToCheck();
    if (versions === null) return null;
    let highest = 0;
    for (const v of versions) {
      const n = await advisoriesFor(v);
      if (n === null) {
        note(`pipegen couldn't check ${repo} for known vulnerabilities (the advisory lookup failed), so it counts as unchecked.`);
        return null;
      }
      highest = Math.max(highest, n);
    }
    return highest;
  }

  async function advisoriesFor(version: string): Promise<number | null> {
    if (target.db === 'github-actions') {
      try {
        const res = await withRateLimit(() => deps.gh.rest.securityAdvisories.listGlobalAdvisories({ ecosystem: 'actions', affects: `${repo}@${version}`, per_page: 100 }), deps);
        const parsed = advisoriesSchema.safeParse(res.data);
        return parsed.success ? parsed.data.filter((a) => a.withdrawn_at == null).length : null;
      } catch (e) {
        if (budgetSpent(e)) throw stopped(e);
        return null;
      }
    }
    if (target.db !== 'osv') return null;
    const res = await getJson(OSV_QUERY, { method: 'POST', body: JSON.stringify({ version, package: { name: target.package, ecosystem: target.ecosystem } }) });
    const parsed = osvSchema.safeParse(res?.body);
    return res !== null && res.status < 300 && parsed.success ? (parsed.data.vulns ?? []).length : null;
  }

  /**
   * Ruling I2: the versions advisories are checked for.
   * - Pinned commit: the full version tags on that commit (advisory databases take versions, not SHAs). A label
   *   (install spec's or candidate's version) must be one of the tags there, or a partial label (4, 4.2) fitting a
   *   full one; else null.
   * - No pinned commit: the label; else, for an npm or PyPI package, the registry's latest version (final review M4:
 *   never the GitHub release tag, which can differ from the package's version); else (an action) the latest
 *   release's tag (ruling S19). It must be a full x.y.z version.
   * null + a note when there is none.
   */
  async function versionsToCheck(): Promise<string[] | null> {
    const unchecked = `so pipegen couldn't check it for known vulnerabilities.`;
    let labelV: string | null = null;
    if (typeof label === 'string' && label !== '') {
      labelV = advisoryVersion(label, shape);
      if (labelV === null) {
        note(`The version "${safeText(label, 40)}" of ${repo} isn't a version pipegen can look up, ${unchecked}`);
        return null;
      }
    }
    const sha = c.pin.sha;
    if (sha !== undefined && sha !== '') {
      if (!COMMIT_SHA_RE.test(sha)) {
        note(`The pinned commit of ${repo} isn't a full commit SHA, ${unchecked}`);
        return null;
      }
      const onCommit = (await allTags()).filter((t) => t.commit.sha.toLowerCase() === sha);
      if (onCommit.length === 0) {
        note(`No release tag points at the pinned commit of ${repo}, ${unchecked}`);
        return null;
      }
      const versions = [...new Set(onCommit.map((t) => advisoryVersion(t.name, shape)).filter((v): v is string => v !== null))];
      const full = versions.filter((v) => isFull(v, shape));
      if (labelV !== null && !versions.includes(labelV) && !(!isFull(labelV, shape) && full.some((v) => v.startsWith(`${labelV}.`)))) {
        note(`The version "${safeText(label, 40)}" of ${repo} doesn't match the version tags on the pinned commit, ${unchecked}`);
        return null;
      }
      if (full.length === 0) {
        note(`No full version tag (like v1.2.3) points at the pinned commit of ${repo}, ${unchecked}`);
        return null;
      }
      // every full version on the commit (the label's among them) is looked up, or none: never a silent subset
      if (full.length > MAX_VERSIONS) {
        note(`The pinned commit of ${repo} has more than ${MAX_VERSIONS} versions tagged, ${unchecked}`);
        return null;
      }
      return full;
    }
    let v = labelV;
    if (v === null && target.db === 'osv') {
      // final review M4: a package's version is the registry's, never the GitHub release tag (they can differ)
      v = await registryLatestVersion(target);
      if (v === null) {
        note(`The registry gives no latest version of ${target.package} that pipegen can look up, ${unchecked}`);
        return null;
      }
    }
    if (v === null) {
      if (latest === null) {
        note(`${repo} has no published release to check for known vulnerabilities.`);
        return null;
      }
      v = advisoryVersion(latest.tag_name, shape);
      if (v === null) {
        note(`The latest release tag of ${repo} isn't a version pipegen can look up, ${unchecked}`);
        return null;
      }
    }
    if (!isFull(v, shape)) {
      note(`The version "${safeText(v, 40)}" of ${repo} isn't a full version (like 1.2.3), ${unchecked}`);
      return null;
    }
    return [v];
  }
}

/** The repo an SLSA provenance statement (base64 DSSE payload) was built from, as `owner/name`; UNREADABLE_REPO when it can't be read (fails closed). */
function slsaRepo(payload: string): string {
  try {
    if (payload.length > MAX_PAYLOAD_CHARS) return UNREADABLE_REPO;
    const stmt = JSON.parse(Buffer.from(payload, 'base64').toString('utf8')) as {
      predicate?: { buildDefinition?: { externalParameters?: { workflow?: { repository?: unknown } } }; invocation?: { configSource?: { uri?: unknown } } };
    };
    const url = stmt.predicate?.buildDefinition?.externalParameters?.workflow?.repository ?? stmt.predicate?.invocation?.configSource?.uri;
    if (typeof url !== 'string') return UNREADABLE_REPO;
    return githubRepoFromUrl(url) ?? UNREADABLE_REPO;
  } catch {
    return UNREADABLE_REPO;
  }
}
