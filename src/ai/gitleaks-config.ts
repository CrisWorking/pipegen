import { readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_LEVELS = 20;

/**
 * Absolute path of pipegen's own gitleaks config (data/gitleaks-bundle.toml), always passed to gitleaks
 * with --config so a repo's .gitleaks.toml is never used.
 * Found by walking up from this module (src/ai/ in dev, dist/cli/main.js once bundled, wherever the package
 * is installed) to the nearest package.json whose name is "pipegen"; package.json `files` ships data/ next
 * to dist/. Fails closed: throws when there is no such package.json or the config file is not there.
 */
export function gitleaksConfigPath(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let level = 0; level < MAX_LEVELS; level++) {
    if (packageName(join(dir, 'package.json')) === 'pipegen') {
      const config = join(dir, 'data', 'gitleaks-bundle.toml');
      if (statSync(config, { throwIfNoEntry: false })?.isFile()) return config;
      throw new Error("pipegen's gitleaks config (data/gitleaks-bundle.toml) is missing from the pipegen package.");
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("pipegen's gitleaks config could not be found: no pipegen package.json above this module.");
}

function packageName(path: string): unknown {
  try {
    if (!statSync(path, { throwIfNoEntry: false })?.isFile()) return undefined;
    return (JSON.parse(readFileSync(path, 'utf8')) as { name?: unknown }).name;
  } catch {
    return undefined;
  }
}
