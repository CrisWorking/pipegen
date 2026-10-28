import { packageDataPath } from '../util/package-data.js';

/**
 * Absolute path of pipegen's own secret-scan config (data/gitleaks-bundle.toml), always passed to the scanner
 * with --config so a repo's own config (.gitleaks.toml) is never used.
 * Found through packageDataPath (the pipegen package's data/ folder). Fails closed: throws when there is no
 * pipegen package.json above this module or the config file is not there.
 */
export function secretScanConfigPath(): string {
  return packageDataPath('gitleaks-bundle.toml');
}
