// A small node script standing in for the pinned gitleaks binary (shared by the redact and needs tests).
// It records what it was given (argv, cwd, env names, the scanned files) and then runs `body` to write a report and exit.
import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { makeTempDir } from './make-repo.js';

export interface StubRecord { argv: string[]; cwd: string; envKeys: string[]; files: Record<string, string>; src: string }

export function makeStub(body: string): { bin: string; record: () => StubRecord } {
  const dir = makeTempDir();
  const rec = join(dir, 'record.json');
  const bin = join(dir, 'gitleaks-stub.cjs');
  writeFileSync(bin, `#!/usr/bin/env node
const fs = require('fs'), path = require('path');
const argv = process.argv.slice(2);
const src = argv[argv.indexOf('--source') + 1];
const report = argv[argv.indexOf('--report-path') + 1];
const files = {};
for (const f of fs.readdirSync(src)) files[f] = fs.readFileSync(path.join(src, f), 'utf8');
fs.writeFileSync(${JSON.stringify(rec)}, JSON.stringify({ argv, cwd: process.cwd(), envKeys: Object.keys(process.env), files, src }));
function findingsFor(value, match) {
  const out = [];
  for (const [f, text] of Object.entries(files)) {
    const lines = text.split('\\n');
    lines.forEach((l, i) => { if (l.includes(value)) out.push({ File: path.join(src, f), StartLine: i + 1, EndLine: i + 1, Match: match || value, ['Sec' + 'ret']: value }); });
  }
  return out;
}
${body}
`);
  chmodSync(bin, 0o755);
  return { bin, record: () => JSON.parse(readFileSync(rec, 'utf8')) as StubRecord };
}

/** Stub body: an empty report, exit 0 (gitleaks found nothing). */
export const CLEAN = `fs.writeFileSync(report, '[]'); process.exit(0);`;
