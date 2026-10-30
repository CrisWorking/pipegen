// The lockfile kinds of Trivy's licence scan (Plan C final review fix round A, ruling 2; G11, ruling S9), in a leaf module: it imports
// only types.ts, so the gate bundles it (its schema in tool-flags.ts reads it) without the reviewed-list loader.
//
// A REVIEWED TABLE. Source: the docs of the pinned Trivy, v0.76.0 (data/reviewed-tools.yml, trivy-licence), read at the tag on 2026-10-30:
//   https://github.com/aquasecurity/trivy/blob/v0.76.0/docs/guide/coverage/language/nodejs.md   (sha256 717fd0a2…caa70a)
//     npm: "Trivy retrieves dependency license information from the lock file (starting with v2)"; Yarn: it "analyzes the .yarn directory
//     (for Yarn 2+) or the node_modules directory (for Yarn Classic)"; pnpm and Bun: "you need to install dependencies to node_modules beforehand".
//   https://github.com/aquasecurity/trivy/blob/v0.76.0/docs/guide/coverage/language/python.md   (sha256 2dc1127d…68b968)
//     pip: "requirements.txt files don't contain information about licenses", so Trivy reads `site-packages`; "License detection is not
//     supported for Pipenv / Poetry / uv / pylock".
//   https://github.com/aquasecurity/trivy/blob/v0.76.0/docs/guide/coverage/language/golang.md   (sha256 d4bff366…f456e0)
//     "To identify licenses, you need to download modules to local cache beforehand".
// and the G11 measurement with that binary (pipegen-internal reviews/dod/2026-10-29/g11-licences.md): without installed packages
// pnpm-lock.yaml, bun.lock, uv.lock, requirements.txt and go.mod gave 0 licences; uv.lock gave none even installed.
// `licences`: 'lockfile' = the lockfile itself carries the licences; 'installed' = only once the packages are installed next to it (pipegen
// v0.2 renders no install step before the licence scan: Plan G's G11 carry-forward); 'never' = Trivy has no licence data for it at all.
// A new Trivy pin re-reads these pages: change this table only with them.
import type { PackageManager, Service } from '../types.js';

/** A lockfile kind: the package manager the reader found (Service.packageManager), or `go` (a go.mod; the service's language or alsoLanguages). */
export type LockfileKind = PackageManager | 'go';
export type LicenceSupport = 'lockfile' | 'installed' | 'never';

/** What Trivy v0.76.0's licence scan reads, per lockfile kind (the source is in the header). */
export const TRIVY_LICENCE_LOCKFILES: Readonly<Record<LockfileKind, { file: string; licences: LicenceSupport }>> = Object.freeze({
  npm: { file: 'package-lock.json', licences: 'lockfile' },
  yarn: { file: 'yarn.lock', licences: 'installed' },
  pnpm: { file: 'pnpm-lock.yaml', licences: 'installed' },
  bun: { file: 'bun.lock', licences: 'installed' },
  pip: { file: 'requirements.txt', licences: 'installed' },
  poetry: { file: 'poetry.lock', licences: 'never' },
  uv: { file: 'uv.lock', licences: 'never' },
  go: { file: 'go.mod', licences: 'installed' },
  other: { file: '(a lockfile pipegen does not know)', licences: 'never' },
});
export const LOCKFILE_KINDS = Object.keys(TRIVY_LICENCE_LOCKFILES) as LockfileKind[];
export const isLockfileKind = (k: unknown): k is LockfileKind => typeof k === 'string' && Object.hasOwn(TRIVY_LICENCE_LOCKFILES, k);

/** One service's entry of the gate's `licence-lockfiles` input: its slug, and each lockfile kind found with whether Trivy reads it. */
export interface LicenceLockfiles { service: string; lockfiles: { kind: LockfileKind; read: boolean }[] }

/**
 * Whether the licence scan as pipegen renders it reads this kind: today only a kind whose lockfile itself carries the licences (no install
 * step is rendered before the scan). A kind Trivy never reads is never read.
 */
export const licenceRead = (kind: LockfileKind): boolean => TRIVY_LICENCE_LOCKFILES[kind].licences === 'lockfile';

/**
 * licenceRead for one service's lockfile (final review r1-3): npm's package-lock.json carries licences only from lockfileVersion 2 (the nodejs
 * page above: "from the lock file (starting with v2)"; v1 falls back to node_modules, which is not installed), so npm counts as read only
 * when the reader proved a version of 2 or more. An unknown version is not read (never "covered" on a guess).
 */
export const licenceReadFor = (kind: LockfileKind, service: Pick<Service, 'npmLockfileVersion'>): boolean =>
  licenceRead(kind) && (kind !== 'npm' || (service.npmLockfileVersion !== undefined && service.npmLockfileVersion >= 2));
