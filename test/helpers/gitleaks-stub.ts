// A small node script standing in for the pinned secret scanner, betterleaks or gitleaks (shared by the redact, needs,
// consent and audit tests). It records what it was given (argv, cwd, env names, the scanned files) and then runs `body`
// to write a report and exit. The scanned folder is the word after `dir` (betterleaks) or after `--source` (gitleaks).
import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { BundleOptions, SecretScanner } from '../../src/ai/redact.js';
import type { AiSuggestDeps } from '../../src/audit/model.js';
import type { AuditConsentFacts } from '../../src/cli/consent.js';
import { makeTempDir } from './make-repo.js';

export interface StubRecord { argv: string[]; cwd: string; envKeys: string[]; files: Record<string, string>; src: string }

export function makeStub(body: string): { bin: string; record: () => StubRecord } {
  const dir = makeTempDir();
  const rec = join(dir, 'record.json');
  const bin = join(dir, 'gitleaks-stub.cjs');
  writeFileSync(bin, `#!/usr/bin/env node
const fs = require('fs'), path = require('path');
const argv = process.argv.slice(2);
const src = argv.includes('--source') ? argv[argv.indexOf('--source') + 1] : argv[argv.indexOf('dir') + 1];
const report = argv[argv.indexOf('--report-path') + 1];
const files = {};
for (const f of fs.readdirSync(src)) files[f] = fs.readFileSync(path.join(src, f), 'utf8');
fs.writeFileSync(${JSON.stringify(rec)}, JSON.stringify({ argv, cwd: process.cwd(), envKeys: Object.keys(process.env), files, src }));
// A finding shaped like the real report (betterleaks 1.9.0 / gitleaks 8.30.1 JSON: RuleID, Tags, Fingerprint, …), with
// lines counted in the file AS WRITTEN (pipegen's leading newline included), as the real scanners count them.
function findingsFor(value, match, tags) {
  const out = [];
  for (const [f, text] of Object.entries(files)) {
    const lines = text.split('\\n');
    lines.forEach((l, i) => {
      if (!l.includes(value)) return;
      const file = path.join(src, f);
      out.push({ RuleID: 'stub-rule', File: file, StartLine: i + 1, EndLine: i + 1, Match: match || value, ['Sec' + 'ret']: value, Tags: tags || [], Fingerprint: file + ':stub-rule:' + (i + 1) });
    });
  }
  return out;
}
// Ruling P34: pipegen ends every scanned file (and paths.txt) with a line holding its own random canary, and the real
// scanners report each one under pipegen's \`pipegen-canary\` rule. canaryFindings() lists them the same way. writeReport()
// writes the report with every canary added (when it is a JSON array), so a body only lists its real findings; a body
// sets \`canary = 'none'\` to add none (then it may write its own, e.g. from canaryFindings()).
let canary = 'each';
function canaryFindings() {
  const out = [];
  for (const [f, text] of Object.entries(files)) {
    text.split('\\n').forEach((l, i) => {
      const m = /^pipegen-canary-[0-9a-f]{32}$/.exec(l); // the real rule: a whole line, nothing else
      if (!m) return;
      const file = path.join(src, f);
      out.push({ RuleID: 'pipegen-canary', File: file, StartLine: i + 1, EndLine: i + 1, Match: m[0], ['Sec' + 'ret']: m[0], Tags: [], Fingerprint: file + ':pipegen-canary:' + (i + 1) });
    });
  }
  return out;
}
function writeReport(data) {
  let out = data;
  if (canary === 'each') {
    let list = null;
    try { list = JSON.parse(data); } catch {}
    if (Array.isArray(list)) out = JSON.stringify([...list, ...canaryFindings()]);
  }
  fs.writeFileSync(report, out);
}
${body}
`);
  chmodSync(bin, 0o755);
  return { bin, record: () => JSON.parse(readFileSync(rec, 'utf8')) as StubRecord };
}

/** Stub body: nothing found but pipegen's canaries, exit 1 (the "found" code, as the real scanners exit then). */
export const CLEAN = `writeReport('[]'); process.exit(1);`;

/** A gitleaks scanner for bundleCode (a stub, or the real pinned one). */
export function gitleaksAt(path: string, version = '8.30.1'): SecretScanner {
  return { name: 'gitleaks', path, version };
}
/** A betterleaks scanner for bundleCode (a stub, or the real pinned one). */
export function betterleaksAt(path: string, version = '1.9.0'): SecretScanner {
  return { name: 'betterleaks', path, version };
}

// The keys below hold a secret-like word, and pipegen's own redact() hides whatever follows such a key and a colon
// or an equals sign (no-secret-literals.test.ts checks every test file with it), so tests never write them that way:
// they use these builders.
const SCANNER_KEY = 'secretScanner' as const;
const TIMEOUT_KEY = 'secretScanTimeoutMs' as const;
const ENSURE_KEY = 'ensureSecretScanner' as const;
/** CodeBundle's checked flag, for a forged bundle: `{ ...bundle, [CHECKED_KEY]: true }`. */
export const CHECKED_KEY = 'secretScanChecked' as const;

/** bundleCode's options with `scanner` as the secret scanner (and its timeout, when given). */
export function scanWith(scanner: SecretScanner, extra: BundleOptions = {}, timeoutMs?: number): BundleOptions {
  return { ...extra, [SCANNER_KEY]: scanner, ...(timeoutMs === undefined ? {} : { [TIMEOUT_KEY]: timeoutMs }) };
}

/** The consent screen's scanner fact. */
export function scannerFacts(name: SecretScanner['name'], version: string): AuditConsentFacts {
  return { [SCANNER_KEY]: { name, version } };
}
export const gitleaksFacts = (version = '8.30.1') => scannerFacts('gitleaks', version);
export const betterleaksFacts = (version = '1.9.0') => scannerFacts('betterleaks', version);

/** addAiSuggestions' scanner dependency. */
type EnsureDep = Pick<AiSuggestDeps, typeof ENSURE_KEY>;
export function ensureWith(ensure: NonNullable<EnsureDep[typeof ENSURE_KEY]>): EnsureDep {
  return { [ENSURE_KEY]: ensure };
}
