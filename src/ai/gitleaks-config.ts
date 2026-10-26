import { fileURLToPath } from 'node:url';

/**
 * Absolute path of pipegen's own gitleaks config (data/gitleaks-bundle.toml), always passed to gitleaks
 * with --config so a repo's .gitleaks.toml is never used.
 * Resolved from this module's URL: it lives in src/ai/ in dev and is bundled into dist/cli/main.js in
 * the build, both two folders below the package root, and package.json `files` ships data/ next to dist/.
 * A test builds this module at that depth and checks the path.
 */
export function gitleaksConfigPath(): string {
  return fileURLToPath(new URL('../../data/gitleaks-bundle.toml', import.meta.url));
}
