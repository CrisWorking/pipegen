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
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let level = 0; level < MAX_LEVELS; level++) {
    if (packageName(join(dir, 'package.json')) === 'pipegen') {
      const file = join(dir, 'data', clean);
      if (statSync(file, { throwIfNoEntry: false })?.isFile()) return file;
      throw new Error(`pipegen's data file (data/${clean}) is missing from the pipegen package.`);
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(`pipegen's data file (data/${clean}) could not be found: no pipegen package.json above this module.`);
}

function packageName(path: string): unknown {
  try {
    if (!statSync(path, { throwIfNoEntry: false })?.isFile()) return undefined;
    return (JSON.parse(readFileSync(path, 'utf8')) as { name?: unknown }).name;
  } catch {
    return undefined;
  }
}
