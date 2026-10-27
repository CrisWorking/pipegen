// Exact pinning (Plan B Task 4). Every tool is pinned to something that can't change under it:
// - a GitHub Action → the 40-character commit SHA its tag points to, read from the upstream repo's own tag refs
//   (annotated tags dereferenced to the commit). A SHA from the AI or from repo text is never used (ruling S32);
// - a GitHub release binary → the version plus the sha256 of the linux amd64 asset, from the release's own
//   checksums file; else the sha256 digest GitHub itself records for the asset (marked `checksumSource:
//   github-asset-digest`, with whether the release is immutable); else downloaded and hashed by pipegen (marked
//   `checksumSource: computed`, ruling S20);
// - an npm package → the exact version plus `dist.integrity` (sha512);
// - a pip package → the exact version plus the sha256 of the py3-none-any wheel, else the sdist (ruling S20);
// - a container image → the digest of its multi-platform index (OCI index or Docker manifest list, ruling S20).
//
// A moved tag is an alert, never an update. A reviewed pin (a candidate with `source: 'reviewed'` AND `reviewed:
// true`, which only the reviewed list gives) is verified, never replaced: when its tag now points somewhere else,
// `deps.alert(new PinMovedWarning(...))` is called and the stored pin is returned. The new SHA or digest is never
// adopted (the tj-actions and Trivy attacks rewrote version tags; SHA-pinned users stayed safe). Any other pin a
// candidate carries (memory, discovery, the AI, `reviewed: false`) is never trusted: it gets a fresh pin, with the
// cooldown and the human-review note (final review I1; memory stores reviewed tool ids only, never pins).
//
// Cooldown (ruling S26): a new pin is only made for a release published at least 7 days ago, by a date the server
// records (GitHub release and asset dates, npm publish time, PyPI upload time, Docker Hub push time). Dates set
// by whoever made the commit or the image (commit, tag or image `created` dates) are never used. A date that can't
// be read, or is in the future, refuses the pin (fail closed). Pre-releases are never newly pinned, and a release
// whose target_commitish is another commit than its tag's means the tag moved: refused. Every new pin adds a note
// asking for human review (reviewed-tools Step 6). A stored pin whose tag now leads somewhere odd (not a commit,
// not an image index, an index with no readable digest) is still a moved tag: alert, stored pin kept; a deleted
// tag is a note, stored pin kept.
//
// Requests: every name is checked before any request and each path segment is encoded (ruling S14). Only
// `deps.gh` (api.github.com) carries the user's credential (ruling S15). `deps.fetch` never gets it; the one
// header it gets is the anonymous pull token a registry hands out, sent back to that same registry only. Fetches
// go through the shared http.ts (fetchAllowed, readBody): redirects followed by hand, to allow-listed https hosts
// only, with size-bounded bodies. GitHub calls go through
// the shared rate-limit helper with the run's budget (ruling S16): a rate limit is the GitHubRateLimitError itself, a
// spent budget a PinError whose cause is that error; isRateStop (github-rate.ts) recognises both.
import { createHash } from 'node:crypto';
import type { Octokit } from '@octokit/rest';
import { z } from 'zod';
import { safeText } from '../util/safe-text.js';
import type { Candidate, InstallSpec, ReviewedTool } from '../types.js';
import { BUDGET_SPENT_MESSAGE, GitHubRateLimitError, withRateLimit, type RateClock } from './github-rate.js';
import { fetchAllowed, HttpError, readBody, readJson } from './http.js';
import {
  advisoryVersion, ASSET_RE, COMMIT_SHA_RE, DIGEST_RE, isFullSemver, isGitHubRepo, isNpmName, isPypiName, npmEscapedName, parseImageRef, pep503,
  IMAGE_TAG_RE, repoSegments, SHA256_RE, SRI_SHA512_RE, TAG_RE, type ImageRef, type ImageRegistry,
} from './names.js';

/** A new pin needs a release at least this old (spec §6 cooldown, T27, T40). */
export const COOLDOWN_DAYS = 7;
/** Default cap on a release asset pipegen downloads to hash. */
export const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024;

export interface PinDeps extends RateClock {
  gh: Octokit;
  fetch: typeof fetch;
  /** A loud warning: the CLI prints it in red and adds it to PIPEGEN.md and the run report. */
  alert: (w: PinMovedWarning) => void;
  /**
   * Plain-English notes for the reviewer (already cleaned). Required, so these markers can't be lost: a computed
   * checksum (`checksumSource: computed`), a deleted tag, and one "needs human review" note per new pin.
   */
  notes: string[];
  /** Cap on a downloaded release asset (default MAX_DOWNLOAD_BYTES). */
  maxDownloadBytes?: number;
}

export class PinError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(safeText(message, 400), options);
    this.name = 'PinError';
  }
}

/** A tag that now points somewhere other than the reviewed pin. The fields stay raw; `message` is cleaned for display. */
export class PinMovedWarning {
  readonly message: string;
  constructor(
    readonly repo: string, readonly tag: string, readonly storedSha: string, readonly liveSha: string,
    what: 'commit' | 'image' = 'commit',
  ) {
    this.message = `Possible supply-chain attack: tag ${safeText(tag, 130)} of ${safeText(repo, 260)} moved. pipegen keeps the reviewed ${what} ${safeText(storedSha, 80)}.`;
  }
}

/** No 'cache': pipegen uses no caches (spec §19). */
export type PlatformActions = Record<'checkout' | 'setup-node' | 'setup-python' | 'upload-artifact' | 'download-artifact' | 'docker-login' | 'setup-buildx' | 'build-push' | 'upload-sarif' | 'attest', Candidate>;

/** PlatformActions key → ReviewedTool.id (the ids are set by Plan B Task 8's reviewed list). */
export const PLATFORM_ACTION_IDS: Record<keyof PlatformActions, string> = {
  checkout: 'actions-checkout',
  'setup-node': 'actions-setup-node',
  'setup-python': 'actions-setup-python',
  'upload-artifact': 'actions-upload-artifact',
  'download-artifact': 'actions-download-artifact',
  'docker-login': 'docker-login-action',
  'setup-buildx': 'docker-setup-buildx-action',
  'build-push': 'docker-build-push-action',
  'upload-sarif': 'codeql-upload-sarif',
  attest: 'actions-attest',
};

const DAY_MS = 86_400_000;
const REQUEST_TIMEOUT_MS = 20_000;
const DOWNLOAD_TIMEOUT_MS = 300_000;
const MAX_JSON_BYTES = 4 * 1024 * 1024;
/** npm's full package document (publish times) can be large for long-lived packages. */
const MAX_PACKUMENT_BYTES = 64 * 1024 * 1024;
const MAX_CHECKSUMS_BYTES = 1024 * 1024;
/** At most this many checksums files are read for one asset (they must all agree). */
const MAX_CHECKSUM_FILES = 4;
/** Nested annotated tags followed before giving up. */
const MAX_TAG_DEPTH = 3;
/** Where GitHub serves release downloads (github.com redirects to its asset hosts). */
const DOWNLOAD_HOSTS = ['github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com', 'github-releases.githubusercontent.com'];

const NPM = 'https://registry.npmjs.org/';
const PYPI = 'https://pypi.org/pypi/';
const DOCKER_HUB_API = 'https://hub.docker.com/v2/repositories/';
const INDEX_TYPES = ['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'];
/** The registries pipegen can pin from, with their anonymous token service. */
const REGISTRIES = {
  'docker.io': { api: 'https://registry-1.docker.io/v2/', token: 'https://auth.docker.io/token', service: 'registry.docker.io' },
  'ghcr.io': { api: 'https://ghcr.io/v2/', token: 'https://ghcr.io/token', service: 'ghcr.io' },
} as const satisfies Record<ImageRegistry, unknown>;

const REGISTRY_TOKEN_RE = /^[A-Za-z0-9._~+/=-]{1,8192}$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})$/;
/** A linux amd64 release asset (Go and Rust naming). */
const LINUX_AMD64_RE = /linux[_-](?:amd64|x86_64)|x86_64-unknown-linux/i;
/** Files beside a release archive that are never the tool itself. */
const SIDE_FILE_RE = /\.(?:sha256|sha256sum|sha512|sha512sum|md5|sig|asc|pem|cert|crt|bundle|sbom|spdx|json|jsonl|txt|deb|rpm|apk|msi|zst)$/i;
/** A checksums file covering several assets: checksums.txt, tool_1.0_checksums.txt, SHA256SUMS. */
const COMBINED_SUMS_RE = /(?:^|[._-])(?:checksums|sha256sums?)(?:\.txt)?$/i;

const refSchema = z.object({ ref: z.string(), object: z.object({ type: z.string(), sha: z.string() }) });
const tagObjectSchema = z.object({ object: z.object({ type: z.string(), sha: z.string() }) });
const assetSchema = z.object({ name: z.string(), size: z.number().int().nonnegative(), updated_at: z.string().nullish(), digest: z.string().nullish() });
const releaseSchema = z.object({
  tag_name: z.string(), published_at: z.string().nullish(), draft: z.boolean().optional(), prerelease: z.boolean().optional(),
  target_commitish: z.string().nullish(), assets: z.array(assetSchema).optional(), immutable: z.boolean().optional(),
});
const npmVersionSchema = z.object({ name: z.string(), version: z.string(), dist: z.object({ integrity: z.string() }) });
const npmTimesSchema = z.object({ time: z.record(z.string(), z.unknown()) });
const pypiSchema = z.object({
  info: z.object({ version: z.string() }),
  urls: z.array(z.object({
    filename: z.string(), packagetype: z.string(), digests: z.object({ sha256: z.string() }),
    upload_time_iso_8601: z.string().nullish(), yanked: z.boolean().optional(),
  })),
});
const tokenSchema = z.object({ token: z.string().optional(), access_token: z.string().optional() });
const hubTagSchema = z.object({ digest: z.string().nullish(), tag_last_pushed: z.string().nullish() });

type Asset = z.infer<typeof assetSchema>;
type Release = z.infer<typeof releaseSchema>;
/** Where a tag leads: a commit, nowhere (the tag is gone), or something that isn't a commit (tree, blob, too-deep chain). */
type TagTarget = { kind: 'commit'; sha: string } | { kind: 'missing' } | { kind: 'not-commit' };
/** Stands in for the live value in a PinMovedWarning when the tag no longer leads to a commit or an image index. */
const NOT_A_COMMIT = '<not a commit>';
const NOT_AN_INDEX = '<not an index>';

/** A pin pipegen keeps as is: only one from the reviewed list (both markers). Everything else is pinned afresh. */
const isStored = (c: Candidate) => c.source === 'reviewed' && c.reviewed === true;
const isNotFound = (e: unknown) => (e as { status?: unknown } | null)?.status === 404;

function checkTag(tag: unknown, what: string): string {
  if (typeof tag !== 'string' || tag === '') throw new PinError(`${what} has no version tag to pin.`);
  if (!TAG_RE.test(tag)) throw new PinError(`"${safeText(tag, 80)}" isn't a tag pipegen can look up for ${what}.`);
  return tag;
}

function checkRepo(repo: unknown): string {
  if (!isGitHubRepo(repo)) throw new PinError(`"${safeText(String(repo), 120)}" isn't a GitHub repo (owner/name) pipegen can pin.`);
  return repo;
}

/** A date the server recorded, as ms; null when it isn't a plain ISO 8601 timestamp. */
function readDate(s: unknown): number | null {
  if (typeof s !== 'string' || !ISO_DATE_RE.test(s)) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

/**
 * Resolves the exact pin for a candidate. `install` says how a `kind: 'cli'` tool is installed (ruling B2): npm,
 * pip or docker; none (or github-release) → a GitHub release binary. Images need `install` with the image name.
 * A reviewed pin (`source: 'reviewed'` and `reviewed: true`) is verified, never replaced; every other candidate
 * (discovery, memory, `reviewed: false`) gets a new pin, whatever pin it carries (cooldown applies).
 * Throws PinError (or GitHubRateLimitError) when the pin can't be made safely.
 */
export async function resolvePin(c: Candidate, deps: PinDeps, install?: InstallSpec): Promise<Candidate> {
  const now = () => (deps.now ?? Date.now)();
  const note = (text: string) => { deps.notes.push(safeText(text, 400)); };
  /** Every new pin is flagged for a human: nothing pipegen pins by itself runs until it is reviewed. */
  const reviewNote = (what: string, value: string) => note(`New pin for ${what} → ${value}: needs human review before release (reviewed-tools Step 6).`);
  const maxDownload = deps.maxDownloadBytes ?? MAX_DOWNLOAD_BYTES;

  // a hash in the install spec must be the candidate's own pin (one source of truth for what runs)
  for (const field of ['checksum', 'digest'] as const) {
    const fromSpec = install?.[field];
    if (fromSpec !== undefined && fromSpec !== c.pin[field]) {
      throw new PinError(`The stored hash for ${safeText(String(install?.package), 120)} and its pin disagree.`);
    }
  }
  if (c.kind === 'action') return pinAction();
  if (c.kind === 'docker' || install?.method === 'docker') return pinImage();
  if (c.kind !== 'cli') throw new PinError(`pipegen can't pin a tool of kind "${safeText(String(c.kind), 40)}".`);
  if (install?.method === 'npm') return pinNpm(install);
  if (install?.method === 'pip') return pinPip(install);
  if (install === undefined || install.method === 'github-release') return pinRelease();
  throw new PinError(`pipegen can't pin a tool installed with "${safeText(String(install.method), 40)}".`);

  // ---------- GitHub Actions ----------

  async function pinAction(): Promise<Candidate> {
    const repo = checkRepo(c.repo);
    const gh = github(repo);
    const stored = c.pin.sha;
    if (isStored(c) && stored !== undefined) {
      if (!COMMIT_SHA_RE.test(stored)) throw new PinError(`The stored pin of ${repo} isn't a full commit SHA.`);
      const tag = checkTag(c.version, repo);
      const live = await gh.tagCommit(tag);
      if (live.kind === 'missing') {
        note(`The tag ${tag} of ${repo} no longer exists; pipegen keeps the reviewed commit ${stored}.`);
      } else if (live.kind === 'not-commit') {
        deps.alert(new PinMovedWarning(repo, tag, stored, NOT_A_COMMIT));
      } else if (live.sha !== stored) {
        deps.alert(new PinMovedWarning(repo, tag, stored, live.sha));
      }
      return c; // the stored, reviewed pin: never replaced
    }
    // A new pin. The cooldown can't see a tag force-moved onto new code under an old release; target_commitish
    // catches some of those cases, and the human review of every new pin (B8 Step 6) is the control.
    // a new pin: the tag comes from c.version or the latest release, the SHA only from the upstream refs
    const wanted = c.version === '' ? null : checkTag(c.version, repo);
    const release = wanted === null ? await gh.latestRelease() : null;
    const tag = wanted ?? checkTag(release?.tag_name, repo);
    const target = await gh.tagCommit(tag);
    if (target.kind === 'missing') throw new PinError(`The tag ${tag} doesn't exist in ${repo}.`);
    if (target.kind === 'not-commit') throw new PinError(`The tag ${tag} of ${repo} doesn't lead to a commit.`);
    const sha = target.sha;
    checkAge(`${repo} ${tag}`, releaseDates(release ?? (await gh.releaseByTag(tag)), tag, `${repo} ${tag}`, sha));
    reviewNote(`${repo} ${tag}`, sha);
    return { ...c, version: tag, pin: { sha } };
  }

  /**
   * The release's own date: it must be published (not a draft, not a pre-release) for exactly this tag; a missing
   * release → age unknown. With the tag's commit known, a release made from another commit means the tag moved.
   */
  function releaseDates(release: Release | null, tag: string, what: string, sha?: string): unknown[] {
    if (release === null || release.tag_name !== tag || release.draft === true) {
      throw new PinError(`Couldn't establish the age of ${what}: it has no published GitHub release, and pipegen doesn't trust commit dates. Not pinned.`);
    }
    if (release.prerelease === true) throw new PinError(`${what} is a pre-release; pipegen doesn't pin pre-releases.`);
    const made = release.target_commitish;
    if (sha !== undefined && typeof made === 'string' && /^[0-9a-fA-F]{40}$/.test(made) && made.toLowerCase() !== sha) {
      throw new PinError(`The tag ${tag} was moved after its release was published. pipegen won't pin ${what}.`);
    }
    return [release.published_at];
  }

  // ---------- GitHub release binaries ----------

  async function pinRelease(): Promise<Candidate> {
    const repo = checkRepo(c.repo);
    const label = install?.version || c.version;
    const wanted = label === '' ? null : checkTag(label, repo);
    const assetName = install?.package || null;
    if (assetName !== null && !ASSET_RE.test(assetName)) throw new PinError(`"${safeText(assetName, 80)}" isn't a release asset name pipegen can download.`);
    if (isStored(c) && c.pin.checksum !== undefined) {
      if (!SHA256_RE.test(c.pin.checksum)) throw new PinError(`The stored checksum of ${repo} isn't a sha256.`);
      if (wanted === null) throw new PinError(`The stored pin of ${repo} has no version.`);
      return c; // a stored binary hash: the install step checks it, and it is never replaced
    }
    const gh = github(repo);
    const release = wanted === null ? await gh.latestRelease() : await gh.releaseByTag(wanted);
    if (release === null) throw new PinError(`${repo} has no published release ${wanted ?? ''} to pin.`);
    const tag = checkTag(release.tag_name, repo);
    const what = `${repo} ${tag}`;
    const dates = releaseDates(release, wanted ?? tag, what);
    const assets = (release.assets ?? []).filter((a) => ASSET_RE.test(a.name));
    const chosen = pickAsset(assets, assetName, what);
    dates.push(chosen.updated_at);
    const base = `https://github.com/${repoSegments(repo).path}/releases/download/${encodeURIComponent(tag)}/`;
    const sums = checksumFiles(assets, chosen.name);
    if (sums.length > MAX_CHECKSUM_FILES) throw new PinError(`${what} has more than ${MAX_CHECKSUM_FILES} checksums files; pipegen won't read only some of them.`);
    let checksum: string;
    if (sums.length > 0) {
      const found = new Set<string>();
      for (const s of sums) {
        if (s.size > MAX_CHECKSUMS_BYTES) throw new PinError(`The checksums file ${s.name} of ${what} is too large.`);
        dates.push(s.updated_at);
        const text = new TextDecoder().decode(await download(base + encodeURIComponent(s.name), MAX_CHECKSUMS_BYTES));
        const hash = hashFor(text, chosen.name, s.name !== chosen.name && s.name.startsWith(chosen.name));
        if (hash !== null) found.add(hash);
      }
      if (found.size === 0) throw new PinError(`The checksums file of ${what} doesn't list ${chosen.name}.`);
      if (found.size > 1) throw new PinError(`The checksums files of ${what} disagree about ${chosen.name}.`);
      // GitHub's own record of the asset, when it has one, must say the same
      if (typeof chosen.digest === 'string' && DIGEST_RE.test(chosen.digest) && chosen.digest !== `sha256:${[...found][0] as string}`) {
        throw new PinError(`The checksums file of ${what} and GitHub's record of ${chosen.name} disagree.`);
      }
      checkAge(what, dates);
      checksum = [...found][0] as string;
    } else if (typeof chosen.digest === 'string' && DIGEST_RE.test(chosen.digest)) {
      // no checksums file: GitHub's own record of the asset's sha256 (computed by GitHub when it was uploaded)
      checkAge(what, dates);
      checksum = chosen.digest.slice('sha256:'.length);
      note(`checksumSource: github-asset-digest. ${what} has no checksums file, so pipegen took the sha256 GitHub records for ${chosen.name} (immutable release: ${release.immutable === true ? 'yes' : 'no'}); a reviewer must confirm it.`);
    } else {
      if (chosen.size > maxDownload) throw new PinError(`${chosen.name} of ${what} is too large to download (${chosen.size} bytes).`);
      checkAge(what, dates); // before downloading anything
      const hash = createHash('sha256');
      await download(base + encodeURIComponent(chosen.name), maxDownload, (b) => hash.update(b));
      checksum = hash.digest('hex');
      note(`checksumSource: computed. ${what} has no checksums file, so pipegen downloaded ${chosen.name} and computed its sha256 itself; a reviewer must confirm it.`);
    }
    reviewNote(what, checksum);
    return { ...c, version: tag, pin: { checksum } };
  }

  // ---------- npm ----------

  async function pinNpm(spec: InstallSpec): Promise<Candidate> {
    if (!isNpmName(spec.package)) throw new PinError(`"${safeText(String(spec.package), 80)}" isn't an npm package name pipegen can pin.`);
    const pkg = spec.package;
    const version = spec.version || c.version;
    if (typeof version !== 'string' || !isFullSemver(version)) throw new PinError(`npm package ${pkg} needs an exact version (like 1.2.3), not "${safeText(String(version), 40)}".`);
    if (isStored(c) && c.pin.checksum !== undefined) {
      if (!SRI_SHA512_RE.test(c.pin.checksum)) throw new PinError(`The stored integrity of ${pkg} isn't a sha512.`);
      return c;
    }
    const what = `${pkg}@${version}`;
    const doc = npmVersionSchema.safeParse(await getJson(`npm's record of ${what}`, `${NPM}${npmEscapedName(pkg)}/${encodeURIComponent(version)}`, MAX_JSON_BYTES));
    if (!doc.success || doc.data.name !== pkg || doc.data.version !== version) throw new PinError(`npm gave an unexpected answer for ${what}.`);
    const integrity = doc.data.dist.integrity;
    if (!SRI_SHA512_RE.test(integrity)) throw new PinError(`npm has no sha512 integrity for ${what}.`);
    const times = npmTimesSchema.safeParse(await getJson(`npm's publish times of ${pkg}`, `${NPM}${npmEscapedName(pkg)}`, MAX_PACKUMENT_BYTES));
    checkAge(what, [times.success ? times.data.time[version] : undefined]);
    reviewNote(what, integrity);
    return { ...c, version, pin: { checksum: integrity } };
  }

  // ---------- pip ----------

  async function pinPip(spec: InstallSpec): Promise<Candidate> {
    if (!isPypiName(spec.package)) throw new PinError(`"${safeText(String(spec.package), 80)}" isn't a PyPI package name pipegen can pin.`);
    const pkg = spec.package;
    const version = spec.version || c.version;
    if (typeof version !== 'string' || version === '' || advisoryVersion(version, 'pep440') !== version) {
      throw new PinError(`PyPI package ${pkg} needs an exact version (like 1.2.3), not "${safeText(String(version), 40)}".`);
    }
    if (isStored(c) && c.pin.checksum !== undefined) {
      if (!SHA256_RE.test(c.pin.checksum)) throw new PinError(`The stored checksum of ${pkg} isn't a sha256.`);
      return c;
    }
    const what = `${pkg} ${version}`;
    const doc = pypiSchema.safeParse(await getJson(`PyPI's record of ${what}`, `${PYPI}${encodeURIComponent(pep503(pkg))}/${encodeURIComponent(version)}/json`, MAX_JSON_BYTES));
    if (!doc.success || doc.data.info.version !== version) throw new PinError(`PyPI gave an unexpected answer for ${what}.`);
    const wheels = doc.data.urls.filter((f) => f.packagetype === 'bdist_wheel' && isPy3AnyWheel(f.filename));
    const sdists = doc.data.urls.filter((f) => f.packagetype === 'sdist');
    const pool = wheels.length > 0 ? wheels : sdists;
    if (pool.length !== 1) {
      throw new PinError(pool.length === 0 ? `${what} has no py3-none-any wheel or sdist to pin.` : `${what} has several files of the same kind; pipegen won't guess which one to pin.`);
    }
    const file = pool[0] as (typeof pool)[number];
    if (file.yanked === true) throw new PinError(`${file.filename} of ${what} was yanked.`);
    const hex = file.digests.sha256;
    if (!SHA256_RE.test(hex)) throw new PinError(`PyPI has no readable sha256 for ${what}.`);
    checkAge(what, [file.upload_time_iso_8601]);
    reviewNote(what, hex);
    return { ...c, version, pin: { checksum: hex } };
  }

  // ---------- container images ----------

  async function pinImage(): Promise<Candidate> {
    if (install?.method !== 'docker') throw new PinError(`An image needs an install spec with its name to be pinned.`);
    const image = parseImage(install.package);
    const tag = install.version || c.version;
    if (typeof tag !== 'string' || !IMAGE_TAG_RE.test(tag)) throw new PinError(`"${safeText(String(tag), 80)}" isn't an image tag pipegen can look up for ${image.display}.`);
    const stored = isStored(c) ? c.pin.digest : undefined;
    if (stored !== undefined && !DIGEST_RE.test(stored)) throw new PinError(`The stored digest of ${image.display} isn't a sha256 digest.`);
    // GHCR has no anonymous, server-recorded push date, so a new GHCR pin can't pass the cooldown
    if (stored === undefined && image.registry === 'ghcr.io') {
      throw new PinError(`Couldn't establish the age of ${image.display}:${tag}: GHCR gives no server-recorded push date without a login. Not pinned.`);
    }
    const reg = REGISTRIES[image.registry];
    const tokenUrl = `${reg.token}?${new URLSearchParams({ service: reg.service, scope: `repository:${image.path}:pull` })}`;
    const tokens = tokenSchema.safeParse(await getJson(`a pull token for ${image.display}`, tokenUrl, MAX_JSON_BYTES));
    const token = tokens.success ? (tokens.data.token ?? tokens.data.access_token) : undefined;
    if (token === undefined || !REGISTRY_TOKEN_RE.test(token)) throw new PinError(`The registry gave no usable anonymous pull token for ${image.display}.`);
    const res = await asPinError(() => fetchAllowed(deps.fetch, `${reg.api}${image.path.split('/').map(encodeURIComponent).join('/')}/manifests/${encodeURIComponent(tag)}`, {
      method: 'HEAD', timeoutMs: REQUEST_TIMEOUT_MS, hosts: [new URL(reg.api).hostname], notFound: 'null',
      // the registry's own anonymous token, sent only to that registry; never the user's credential
      headers: { accept: INDEX_TYPES.join(', '), authorization: `Bearer ${token}` },
    }));
    if (res === null) {
      if (stored === undefined) throw new PinError(`The tag ${tag} of ${image.display} doesn't exist.`);
      note(`The tag ${tag} of ${image.display} no longer exists; pipegen keeps the reviewed image ${stored}.`);
      return c;
    }
    await res.body?.cancel().catch(() => {});
    const type = (res.headers.get('content-type') ?? '').split(';')[0]?.trim() ?? '';
    if (!INDEX_TYPES.includes(type)) {
      if (stored === undefined) throw new PinError(`${image.display}:${tag} isn't a multi-platform image index; pipegen pins the index digest only.`);
      deps.alert(new PinMovedWarning(image.display, tag, stored, NOT_AN_INDEX, 'image'));
      return c; // the stored, reviewed digest: never replaced
    }
    const digest = res.headers.get('docker-content-digest') ?? '';
    if (!DIGEST_RE.test(digest)) {
      if (stored === undefined) throw new PinError(`The registry gave no readable digest for ${image.display}:${tag}.`);
      // the tag no longer leads to a readable index digest: odd, so it is treated like a moved tag (alert, keep)
      deps.alert(new PinMovedWarning(image.display, tag, stored, NOT_AN_INDEX, 'image'));
      return c; // the stored, reviewed digest: never replaced
    }
    if (stored !== undefined) {
      if (digest !== stored) deps.alert(new PinMovedWarning(image.display, tag, stored, digest, 'image'));
      return c; // the stored, reviewed digest: never replaced
    }
    // Docker Hub records when the tag was pushed; the date must belong to this very digest
    const [ns, name] = image.path.split('/') as [string, string];
    const hub = hubTagSchema.safeParse(await getJson(`Docker Hub's record of ${image.display}:${tag}`, `${DOCKER_HUB_API}${encodeURIComponent(ns)}/${encodeURIComponent(name)}/tags/${encodeURIComponent(tag)}`, MAX_JSON_BYTES));
    if (!hub.success || hub.data.digest !== digest) throw new PinError(`Couldn't establish the age of ${image.display}:${tag}: Docker Hub's record doesn't match the digest. Not pinned.`);
    checkAge(`${image.display}:${tag}`, [hub.data.tag_last_pushed]);
    reviewNote(`${image.display}:${tag}`, digest);
    return { ...c, version: tag, pin: { digest } };
  }

  // ---------- shared ----------

  /** Refuses the pin unless every date is readable, not in the future, and at least COOLDOWN_DAYS old. */
  function checkAge(what: string, dates: unknown[]): void {
    const nowMs = now();
    let newest = Number.NEGATIVE_INFINITY;
    for (const d of dates) {
      const t = readDate(d);
      if (t === null) throw new PinError(`Couldn't establish the age of ${what} (no readable release date). Not pinned.`);
      if (t > nowMs) throw new PinError(`${what} has a release date in the future, which pipegen can't trust. Not pinned.`);
      newest = Math.max(newest, t);
    }
    if (dates.length === 0) throw new PinError(`Couldn't establish the age of ${what}. Not pinned.`);
    if (nowMs - newest < COOLDOWN_DAYS * DAY_MS) {
      throw new PinError(`${what} changed less than ${COOLDOWN_DAYS} days ago (${new Date(newest).toISOString()}); pipegen waits ${COOLDOWN_DAYS} days before pinning a new release.`);
    }
  }

  /** GitHub calls for one checked repo, through the rate-limit helper. */
  function github(repo: string) {
    const { owner, name } = repoSegments(repo);
    async function call<T>(what: string, fn: () => Promise<{ data: unknown }>, schema: z.ZodType<T>): Promise<T | null> {
      let data: unknown;
      try {
        data = (await withRateLimit(fn, deps)).data;
      } catch (e) {
        if (e instanceof GitHubRateLimitError && e.budgetSpent) throw new PinError(BUDGET_SPENT_MESSAGE, { cause: e });
        if (e instanceof GitHubRateLimitError) throw e;
        if (isNotFound(e)) return null;
        throw new PinError(`Couldn't read ${what} of ${repo} from GitHub.`, { cause: e });
      }
      const parsed = schema.safeParse(data);
      if (!parsed.success) throw new PinError(`GitHub gave an unexpected answer for ${what} of ${repo}.`);
      return parsed.data;
    }
    return {
      latestRelease: async (): Promise<Release> => {
        const r = await call('the latest release', () => deps.gh.rest.repos.getLatestRelease({ owner, repo: name }), releaseSchema);
        if (r === null) throw new PinError(`${repo} has no published release to pin.`);
        return r;
      },
      releaseByTag: (tag: string) => call(`the release ${tag}`, () => deps.gh.rest.repos.getReleaseByTag({ owner, repo: name, tag }), releaseSchema),
      /** Where a tag leads, from the repo's own refs (annotated tags dereferenced, at most MAX_TAG_DEPTH deep). */
      tagCommit: async (tag: string): Promise<TagTarget> => {
        const r = await call(`the tag ${tag}`, () => deps.gh.request('GET /repos/{owner}/{repo}/git/ref/tags/{tag}', { owner, repo: name, tag }), refSchema);
        if (r === null) return { kind: 'missing' };
        if (r.ref !== `refs/tags/${tag}`) throw new PinError(`GitHub answered with another ref for the tag ${tag} of ${repo}.`);
        let obj = r.object;
        for (let depth = 0; obj.type === 'tag'; depth++) {
          if (depth >= MAX_TAG_DEPTH || !COMMIT_SHA_RE.test(obj.sha)) return { kind: 'not-commit' };
          const sha = obj.sha;
          const t = await call(`the tag ${tag}`, () => deps.gh.rest.git.getTag({ owner, repo: name, tag_sha: sha }), tagObjectSchema);
          if (t === null) return { kind: 'not-commit' };
          obj = t.object;
        }
        if (obj.type !== 'commit' || !COMMIT_SHA_RE.test(obj.sha)) return { kind: 'not-commit' };
        return { kind: 'commit', sha: obj.sha };
      },
    };
  }

  /** A JSON document from the URL's own host (redirects only within that host), size-bounded. */
  async function getJson(what: string, url: string, maxBytes: number): Promise<unknown> {
    return asPinError(async () => readJson(await fetchAllowed(deps.fetch, url, { method: 'GET', timeoutMs: REQUEST_TIMEOUT_MS, hosts: [new URL(url).hostname] }), maxBytes, what));
  }

  function download(url: string, maxBytes: number, onChunk?: (b: Uint8Array) => void): Promise<Uint8Array> {
    return downloadRelease(deps.fetch, url, maxBytes, onChunk);
  }
}

/**
 * A GitHub release download (github.com and its release-asset hosts, https, no credential), size-bounded; with
 * `onChunk` the bytes are streamed to it instead of returned. Shared by pinning and ensurePinnedBinary (Task 7).
 */
export async function downloadRelease(fetchFn: typeof fetch, url: string, maxBytes: number, onChunk?: (b: Uint8Array) => void): Promise<Uint8Array> {
  return asPinError(async () => {
    const res = await fetchAllowed(fetchFn, url, { method: 'GET', timeoutMs: DOWNLOAD_TIMEOUT_MS, hosts: DOWNLOAD_HOSTS, headers: { accept: 'application/octet-stream' } });
    const chunks: Uint8Array[] = [];
    await readBody(res, maxBytes, onChunk ?? ((b) => chunks.push(b)), decodeURIComponent(new URL(url).pathname.split('/').pop() ?? 'the download'));
    return Buffer.concat(chunks);
  });
}

/** Runs shared-HTTP work (http.ts), turning its HttpError into a PinError with the same message. */
async function asPinError<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (e) {
    if (e instanceof HttpError) throw new PinError(e.message, { cause: e });
    throw e;
  }
}

/** The linux amd64 asset: the one the install spec names, else the only archive whose name says linux amd64. */
function pickAsset(assets: Asset[], wanted: string | null, what: string): Asset {
  if (wanted !== null) {
    const named = assets.find((a) => a.name === wanted);
    if (named === undefined) throw new PinError(`${what} has no asset named ${wanted}.`);
    return named;
  }
  const matches = assets.filter((a) => LINUX_AMD64_RE.test(a.name) && !SIDE_FILE_RE.test(a.name));
  if (matches.length === 0) throw new PinError(`${what} has no linux amd64 asset to pin.`);
  if (matches.length > 1) throw new PinError(`${what} has several linux amd64 assets; the install spec must name one.`);
  return matches[0] as Asset;
}

/** The checksums files for an asset: `<asset>.sha256` (or .sha256sum) and combined files like checksums.txt. */
function checksumFiles(assets: Asset[], asset: string): Asset[] {
  const own = new Set([`${asset}.sha256`, `${asset}.sha256sum`, `${asset}.sha256.txt`]);
  const owned = assets.filter((a) => own.has(a.name));
  const combined = assets.filter((a) => !own.has(a.name) && COMBINED_SUMS_RE.test(a.name) && !/512|sha1|md5/i.test(a.name));
  return [...owned, ...combined];
}

/** The sha256 a checksums file gives for `asset` (`<hex>  [*]<name>` lines; a per-asset file may hold the hex alone). */
function hashFor(text: string, asset: string, perAsset: boolean): string | null {
  const hashes = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '') continue;
    const m = /^([0-9A-Fa-f]{64})(?:\s+\*?(?:\.\/)?(\S+))?$/.exec(line);
    if (m === null) continue;
    const name = m[2];
    if (name === asset || (name === undefined && perAsset)) hashes.add((m[1] as string).toLowerCase());
  }
  if (hashes.size > 1) throw new PinError(`A checksums file lists ${asset} more than once with different hashes.`);
  return hashes.size === 1 ? ([...hashes][0] as string) : null;
}

/** A wheel tagged for any Python 3, any ABI, any platform (py3-none-any, py2.py3-none-any). */
function isPy3AnyWheel(filename: string): boolean {
  if (!filename.endsWith('.whl')) return false;
  const parts = filename.slice(0, -4).split('-');
  if (parts.length < 5) return false;
  const [py, abi, platform] = parts.slice(-3) as [string, string, string];
  return py.split('.').includes('py3') && abi === 'none' && platform === 'any';
}

/** `[registry/]path` → a checked image on Docker Hub or GHCR (the one grammar: names.ts parseImageRef). */
function parseImage(ref: unknown): ImageRef {
  const image = parseImageRef(ref);
  if (image === null) throw new PinError(`"${safeText(String(ref), 120)}" isn't an image name pipegen can pin (Docker Hub or GHCR, lower case, no tag).`);
  return image;
}

/**
 * The platform actions from the REVIEWED list, found by PLATFORM_ACTION_IDS. Each stored pin is re-verified
 * against its tag: a moved tag raises a PinMovedWarning and the stored SHA is kept.
 */
export async function platformActions(reviewed: ReviewedTool[], deps: PinDeps): Promise<PlatformActions> {
  const out: Partial<PlatformActions> = {};
  for (const [key, id] of Object.entries(PLATFORM_ACTION_IDS) as [keyof PlatformActions, string][]) {
    const matches = reviewed.filter((t) => t.id === id);
    if (matches.length !== 1) throw new PinError(matches.length === 0 ? `The reviewed list has no ${id} entry.` : `The reviewed list has more than one ${id} entry.`);
    const c = (matches[0] as ReviewedTool).candidate;
    if (c.kind !== 'action' || c.source !== 'reviewed' || c.reviewed !== true || c.pin.sha === undefined) {
      throw new PinError(`The reviewed entry ${id} isn't a reviewed action with a pinned commit.`);
    }
    out[key] = await resolvePin(c, deps);
  }
  return out as PlatformActions;
}
