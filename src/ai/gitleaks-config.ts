import { packageDataPath } from '../util/package-data.js';

/**
 * Absolute path of pipegen's own gitleaks config (data/gitleaks-bundle.toml), always passed to gitleaks
 * with --config so a repo's .gitleaks.toml is never used.
 * Found through packageDataPath (the pipegen package's data/ folder). Fails closed: throws when there is no
 * pipegen package.json above this module or the config file is not there.
 */
export function gitleaksConfigPath(): string {
  return packageDataPath('gitleaks-bundle.toml');
}
