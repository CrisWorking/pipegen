// Patterns for tool identifiers that come from the network or the AI (Plan B ruling S14). Every one is checked
// before it is used in a request, and path segments are still encoded with encodeURIComponent after the check.

/** GitHub `owner/name`: owner as GitHub allows it (max 39), name of letters, digits, `.`, `_`, `-` (never `.` or `..`). */
const GITHUB_REPO_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
/** npm package name, as the registry accepts new names: lower case, optional @scope/, max 214. */
const NPM_NAME_RE = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/;
/** PyPI project name (PEP 508). */
const PYPI_NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
/** Semver-shaped (major, major.minor or major.minor.patch, optional pre-release and build), no leading `v`. */
const SEMVER_RE = /^\d{1,9}(?:\.\d{1,9}){0,2}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
/** PEP 440 public version, normalised form: [N!]N(.N)*[{a|b|rc}N][.postN][.devN]. */
const PEP440_RE = /^(?:\d{1,9}!)?\d{1,9}(?:\.\d{1,9})*(?:(?:a|b|rc)\d{1,9})?(?:\.post\d{1,9})?(?:\.dev\d{1,9})?$/;
/** A full git commit SHA. */
export const COMMIT_SHA_RE = /^[0-9a-f]{40}$/;
/** A git tag pipegen will look up: no `/`, no leading `-` or `.`, nothing a URL treats specially. */
export const TAG_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/;
/** A GitHub release asset name pipegen will download (a plain file name). */
export const ASSET_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$/;
/** A sha256 as lower-case hex. */
export const SHA256_RE = /^[0-9a-f]{64}$/;
/** A sha256 image digest. */
export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
/** An npm `dist.integrity` sha512 (SRI form). */
export const SRI_SHA512_RE = /^sha512-[A-Za-z0-9+/]{86}==$/;

/** An image tag (the registry's tag grammar). */
export const IMAGE_TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;

/** The registries pipegen can pin images from. */
export type ImageRegistry = 'docker.io' | 'ghcr.io';
/** A checked image name: its registry, its path there (Docker Hub official images get `library/`), and how it is shown. */
export interface ImageRef { registry: ImageRegistry; path: string; display: string }
const IMAGE_COMPONENT_RE = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
const DOCKER_HUB_ALIASES: ReadonlySet<string> = new Set(['docker.io', 'index.docker.io', 'registry-1.docker.io']);

/**
 * The one image-name grammar (pinning and the reviewed list both use it): `[registry/]path`, lower case, no tag or
 * digest. The registry is Docker Hub (docker.io, index.docker.io, registry-1.docker.io, or none) with exactly
 * `namespace/name` (`name` alone → `library/name`), or GHCR (ghcr.io) with two or more parts. Anything else → null.
 */
export function parseImageRef(ref: unknown): ImageRef | null {
  if (typeof ref !== 'string' || ref.length > 255) return null;
  const parts = ref.split('/');
  let registry: ImageRegistry = 'docker.io';
  const first = parts[0] ?? '';
  if (parts.length > 1 && (first.includes('.') || first.includes(':') || first === 'localhost')) {
    if (DOCKER_HUB_ALIASES.has(first)) registry = 'docker.io';
    else if (first === 'ghcr.io') registry = 'ghcr.io';
    else return null;
    parts.shift();
  }
  if (parts.length === 0 || !parts.every((p) => IMAGE_COMPONENT_RE.test(p))) return null;
  if (registry === 'docker.io' && parts.length === 1) parts.unshift('library');
  if (parts.length < 2 || (registry === 'docker.io' && parts.length !== 2)) return null;
  const path = parts.join('/');
  return { registry, path, display: `${registry}/${path}` };
}

export function isGitHubRepo(s: unknown): s is string {
  if (typeof s !== 'string' || !GITHUB_REPO_RE.test(s)) return false;
  const name = s.slice(s.indexOf('/') + 1);
  return name !== '.' && name !== '..';
}

/** `owner/name` → its two path segments, each encoded for a URL. Only call on a checked repo. */
export function repoSegments(repo: string): { owner: string; name: string; path: string } {
  const [owner, name] = repo.split('/') as [string, string];
  return { owner, name, path: `${encodeURIComponent(owner)}/${encodeURIComponent(name)}` };
}

export const isNpmName = (s: unknown): s is string => typeof s === 'string' && s.length <= 214 && NPM_NAME_RE.test(s);
export const isPypiName = (s: unknown): s is string => typeof s === 'string' && s.length <= 100 && PYPI_NAME_RE.test(s);

/**
 * `owner/name` from a link to a GitHub repo, or null: npm shorthand (`o/r`, `github:o/r`), `git@github.com:o/r.git`,
 * and https/git/ssh URLs on github.com (a `.git` suffix, a deeper path, `@ref`, `#` or `?` after the name allowed).
 */
export function githubRepoFromUrl(s: unknown): string | null {
  if (typeof s !== 'string' || s.length > 500) return null;
  const t = s.trim();
  const m = /^(?:github:)?([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?$/.exec(t)
    ?? /^git@github\.com:([^/]+)\/([^/#?@]+?)(?:\.git)?\/?$/i.exec(t)
    ?? /^(?:git\+)?(?:https?|git|ssh):\/\/(?:[^@/]+@)?(?:www\.)?github\.com\/([^/#?@]+)\/([^/#?@]+?)(?:\.git)?(?:[/#?@].*)?$/i.exec(t);
  if (!m) return null;
  const repo = `${m[1]}/${m[2]}`;
  return isGitHubRepo(repo) ? repo : null;
}

/** A checked npm name as the registry's URLs take it: `@scope%2fname` for scoped names, each part encoded. */
export function npmEscapedName(name: string): string {
  const slash = name.indexOf('/');
  return slash < 0 ? encodeURIComponent(name) : `@${encodeURIComponent(name.slice(1, slash))}%2f${encodeURIComponent(name.slice(slash + 1))}`;
}

/** PEP 503 normalised PyPI name: lower case, each run of `-`, `_` and `.` made one `-`. */
export const pep503 = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '-');

const FULL_SEMVER_RE = /^(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/** A full x.y.z semver version (pre-release and build allowed), no leading `v`. A partial one (4, 4.2) is not. */
export const isFullSemver = (v: string) => FULL_SEMVER_RE.test(v);

/** Semver precedence of two full versions (see isFullSemver): negative when a < b. A release is above its pre-releases. */
export function compareSemver(a: string, b: string): number {
  const pa = FULL_SEMVER_RE.exec(a);
  const pb = FULL_SEMVER_RE.exec(b);
  if (!pa || !pb) throw new Error('compareSemver: not a full semver version');
  for (let i = 1; i <= 3; i++) {
    const d = Number(pa[i]) - Number(pb[i]);
    if (d !== 0) return d;
  }
  const [preA, preB] = [pa[4], pb[4]];
  if (preA === undefined || preB === undefined) return (preA === undefined ? 1 : 0) - (preB === undefined ? 1 : 0);
  const ia = preA.split('.');
  const ib = preB.split('.');
  for (let i = 0; i < Math.min(ia.length, ib.length); i++) {
    const [x, y] = [ia[i] as string, ib[i] as string];
    const [nx, ny] = [/^\d+$/.test(x), /^\d+$/.test(y)];
    if (nx && ny && Number(x) !== Number(y)) return Number(x) - Number(y);
    if (nx !== ny) return nx ? -1 : 1; // numeric identifiers sort below alphanumeric ones
    if (x !== y) return x < y ? -1 : 1;
  }
  return ia.length - ib.length;
}

/**
 * The version an advisory database expects, from a version or tag: one leading `v` dropped, then the semver shape
 * (npm, GitHub Actions) or the PEP 440 shape (PyPI). Anything else → null.
 */
export function advisoryVersion(v: string, shape: 'semver' | 'pep440'): string | null {
  if (typeof v !== 'string' || v.length > 64) return null;
  const bare = /^[vV]\d/.test(v) ? v.slice(1) : v;
  return (shape === 'pep440' ? PEP440_RE : SEMVER_RE).test(bare) ? bare : null;
}
