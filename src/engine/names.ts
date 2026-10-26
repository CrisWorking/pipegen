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
