// The required local secret scan before `audit --ai` sends code to an AI (Plan P Task 7): which scanner runs, with
// which config and which fixed argv. betterleaks 1.9.0 is the default; gitleaks 8.30.1 is the fallback, chosen with
// PIPEGEN_SECRET_SCANNER=gitleaks. Both are pinned binaries (data/pinned-binaries.yml, ensurePinnedBinary).
import { BETTERLEAKS_FORBIDDEN_FLAGS } from '../engine/tool-flags.js';
import { packageDataPath } from '../util/package-data.js';

/** The secret scanner could not run or gave an unusable result (not a finding): no bundle is returned. */
export class SecretScanError extends Error {}

export type SecretScannerName = 'betterleaks' | 'gitleaks';
/** The pinned secret scanner bundleCode runs (ensurePinnedBinary's absolute path) and its pinned version. */
export interface SecretScanner { name: SecretScannerName; path: string; version: string }

/** The environment variable that picks the scanner: 'betterleaks' (the default, when unset) or 'gitleaks'. */
export const SECRET_SCANNER_ENV = 'PIPEGEN_SECRET_SCANNER';

/**
 * The scanner `env` asks for: betterleaks when PIPEGEN_SECRET_SCANNER is unset, gitleaks when it is exactly
 * `gitleaks`. Any other value (an empty one, another case, another tool) throws SecretScanError, so a typo never
 * silently picks a scanner; the message doesn't repeat the value.
 */
export function chooseSecretScanner(env: Record<string, string | undefined>): SecretScannerName {
  const v = env[SECRET_SCANNER_ENV];
  if (v === undefined || v === 'betterleaks') return 'betterleaks';
  if (v === 'gitleaks') return 'gitleaks';
  throw new SecretScanError(`${SECRET_SCANNER_ENV} must be betterleaks (the default) or gitleaks.`);
}

/**
 * Absolute path of pipegen's own secret-scan config (data/gitleaks-bundle.toml), always passed to the scanner with
 * --config, so a repo's own config (.betterleaks.toml, .gitleaks.toml) is never used. Both scanners take it:
 * betterleaks 1.9.0 compiles it under RE2 with `[extend] useDefault` and runs pipegen's own rules (live probe, Task 7).
 * Found through packageDataPath (the pipegen package's data/ folder). Fails closed: throws when there is no pipegen
 * package.json above this module or the config file is not there.
 */
export function secretScanConfigPath(): string {
  return packageDataPath('gitleaks-bundle.toml');
}

/** Exit codes of both scanners with `--exit-code 1` (live probe): nothing found, and found. Any other is an error. */
export const SECRET_SCAN_EXIT = { clean: 0, found: 1 } as const;

// The fixed local argv (the live probe of the pinned binaries, Task 7). Only the scanned folder, the config and the
// report path change; everything else is these constants.
// - No --redact: unlike the CI entries in reviewed-tools.yml (ruling P21), this pass needs the raw Secret and Match
//   values to remove them from the bundle. The report is written only into the private 0700 temp folder the scan
//   runs in, never to stdout (never `--report-path -`) and never with -v/--verbose, and the folder is deleted after.
// - --exit-code 1 fixed; --ignore-gitleaks-allow, so an inline allow comment can't hide a line (the bundle's allow
//   comments are neutralised too).
// - betterleaks: never --validation/--validate (it sends candidate secrets to provider APIs), --analyze,
//   --unsafe-auto-load-config or any other of BETTERLEAKS_FORBIDDEN_FLAGS (the list the reviewed-list loader uses,
//   ruling PS34), and only the local `dir` scan.
const COMMON = ['--report-format', 'json'] as const;
const FIXED = ['--no-banner', '--ignore-gitleaks-allow', '--exit-code', '1'] as const;

/** The argv for one scan of the private temp folder `dir` with `config`, writing the JSON report to `reportPath` in it. */
export function secretScanArgv(name: SecretScannerName, dir: string, config: string, reportPath: string): string[] {
  const head = name === 'betterleaks' ? ['dir', dir] : ['detect', '--no-git', '--source', dir];
  const argv = [...head, '--config', config, ...COMMON, '--report-path', reportPath, ...FIXED];
  if (name === 'betterleaks') {
    const forbidden = new Set<string>(BETTERLEAKS_FORBIDDEN_FLAGS);
    if (argv.some((a) => forbidden.has(a.split('=')[0] as string))) throw new SecretScanError('pipegen refused a betterleaks flag it never passes.');
  }
  return argv;
}
