import { readFileSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_LEVELS = 20;

/**
 * Absolute path of one of pipegen's own data files (`data/<rel>`), for every loader (gitleaks config, quality bar,
 * reviewed tools, pinned binaries, bundled memory).
 * Found by walking up from this module (src/util/ in dev, dist/cli/main.js once bundled, wherever the package is
 * installed) to the nearest package.json whose name is "pipegen"; package.json `files` ships data/ next to dist/.
 * Fails closed: throws when `rel` leaves data/, when there is no such package.json, or when the file isn't there.
 */
export function packageDataPath(rel: string): string {
  const clean = normalize(rel);
  if (rel === '' || isAbsolute(rel) || clean === '.' || clean === '..' || clean.startsWith(`..${sep}`)) {
    throw new Error(`pipegen data files live in data/: "${rel}" is not a path inside it.`);
  }
  const dir = packageRoot();
  if (dir === null) throw new Error(`pipegen's data file (data/${clean}) could not be found: no pipegen package.json above this module.`);
  const file = join(dir, 'data', clean);
  if (statSync(file, { throwIfNoEntry: false })?.isFile()) return file;
  throw new Error(`pipegen's data file (data/${clean}) is missing from the pipegen package.`);
}

/** A plain release version (1.2.3, or 1.2.3-rc.1): safe to put in a command people copy. */
export const PLAIN_VERSION_RE = /^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.-]{1,40})?$/;

/**
 * The running pipegen's version, from its own package.json (found like packageDataPath finds data/), or null when
 * it can't be read or isn't a plain version. Plan U ruling S30: warnings print `pipegen@<this>`, never a placeholder.
 */
export function packageVersion(): string | null {
  const dir = packageRoot();
  if (dir === null) return null;
  const version = readPackage(join(dir, 'package.json'))?.version;
  return typeof version === 'string' && PLAIN_VERSION_RE.test(version) ? version : null;
}

/** The nearest folder above this module whose package.json is pipegen's (src/util/ in dev, dist/cli/ once bundled). */
function packageRoot(): string | null {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let level = 0; level < MAX_LEVELS; level++) {
    if (readPackage(join(dir, 'package.json'))?.name === 'pipegen') return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function readPackage(path: string): { name?: unknown; version?: unknown } | undefined {
  try {
    if (!statSync(path, { throwIfNoEntry: false })?.isFile()) return undefined;
    const pkg: unknown = JSON.parse(readFileSync(path, 'utf8'));
    return typeof pkg === 'object' && pkg !== null ? pkg as { name?: unknown; version?: unknown } : undefined;
  } catch {
    return undefined;
  }
}
