// Plan E E0a, scans 4 and 5: the excerpt's multi-line secret classes, closed by a fuzz test instead of examples: every multi-line shape
// Plan A redact hides (an indented value after `key:`, a YAML literal block, a TOML/INI secret section, a .env value over lines, a JSON
// value list), plus a connection string split over lines and PEM private-key blocks of 1-300 body
// lines (RSA, EC, DSA, OPENSSH, PKCS#8, ENCRYPTED; Proc-Type/DEK-Info headers and blank lines) get random CSI, OSC and C1 sequences, stray
// ESC bytes and LS/PS/CR at random places, the BEGIN and END markers included; normal log lines go around them, and some logs are cut so
// the cut falls inside the block. No 16-character base64 run of the key body may reach the excerpt. The secret scan (step 7) only removes
// lines, so unscannedExcerpt (steps 1-6) is what is checked; no scanner process runs here.
// Fixed seed. PIPEGEN_E0A_FUZZ_CASES and PIPEGEN_E0A_FUZZ_SEED change the count and the seed for a one-off longer run.
import { writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { redact } from '../src/ai/redact.js';
import { unscannedExcerpt } from '../src/proof/excerpt.js';

const CASES = Number(process.env.PIPEGEN_E0A_FUZZ_CASES ?? 5000);
const SEED = Number(process.env.PIPEGEN_E0A_FUZZ_SEED ?? 0xe0a1);

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
// the key kinds and markers are built at runtime: no secret-looking literal is committed (test/no-secret-literals.test.ts)
const KINDS = ['RSA', 'EC', 'DSA', 'OPENSSH', '', 'ENCRYPTED'].map((k) => `${k === '' ? '' : `${k} `}PRIVATE KEY`);
const marker = (kind: string, end: boolean) => `-----${end ? 'END' : 'BEGIN'} ${kind}-----`;
const TS = '2026-11-03T10:00:00.1234567Z ';
const NORMAL = [
  'npm ERR! code ELIFECYCLE', 'Error: Process completed with exit code 1.', '    at Object.<anonymous> (src/app.test.js:12:5)', 'ok 12 - parses config',
  '##[group]Run npm test', '##[endgroup]', 'warning: deprecated option', 'FAIL src/key.test.js', '  ● loads the signing key', 'Expected: 200', '',
  'Received: 500', 'Tests: 3 failed, 41 passed', 'error: the key could not be read', 'done in 4.2s',
];

interface Case { shape: string; log: string; bare: string; runs: string[]; maxLogChars?: number }

// secret-bearing names, built at runtime (test/no-secret-literals.test.ts)
const VALUE_NAMES = [['pass', 'word'], ['client', '_sec', 'ret'], ['api', '_key'], ['to', 'ken'], ['db_pass', 'word'], ['sec', 'ret']].map((p) => p.join(''));
const SECTIONS = [['sec', 'rets'], ['database.pass', 'word'], ['au', 'th'], ['creden', 'tials'], ['aws.creden', 'tials']].map((p) => p.join(''));
const ENV_NAMES = [['DB_PASS', 'WORD'], ['API_TO', 'KEN'], ['CLIENT_SEC', 'RET'], ['PRIVATE', '_KEY']].map((p) => p.join(''));
const SHAPES = ['pem', 'yaml-block', 'yaml-literal', 'toml-section', 'env-multiline', 'json-block', 'conn-across-lines'] as const;

function makeCase(rnd: () => number): Case {
  const int = (n: number) => Math.floor(rnd() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)] as T;
  const b64 = (n: number) => Array.from({ length: n }, () => B64[int(64)]).join('');
  const alnum = (n: number) => b64(n).replace(/[+/]/g, 'x');
  const shape = pick(SHAPES);
  const runs: string[] = [];
  const blockLines: string[] = [];
  const ind = ' '.repeat(pick([0, 2, 4]));
  if (shape === 'pem') {
    const kind = pick(KINDS);
    const n = 1 + int(300);
    for (let i = 0; i < n; i++) runs.push(i === n - 1 ? b64(4 + int(61)) + pick(['', '=', '==']) : b64(64));
    blockLines.push(marker(kind, false));
    if (/^(RSA|EC|DSA) /.test(kind) && rnd() < 0.4) blockLines.push('Proc-Type: 4,ENCRYPTED', `DEK-Info: AES-128-CBC,${b64(16).replace(/[^0-9A-F]/g, 'A')}`, '');
    for (const l of runs) {
      blockLines.push(l);
      if (rnd() < 0.03) blockLines.push(pick(['', ' ', '\t']));
    }
    blockLines.push(marker(kind, true));
  } else {
    const n = 1 + int(20);
    for (let i = 0; i < n; i++) runs.push(alnum(20 + int(21)));
    if (shape === 'yaml-block' || shape === 'yaml-literal') {
      blockLines.push(`${ind}${pick(VALUE_NAMES)}:${shape === 'yaml-literal' ? ` ${pick(['|', '>', '|-', '>-'])}` : ''}`);
      for (const r of runs) blockLines.push(`${ind}  ${shape === 'yaml-block' && rnd() < 0.3 ? '- ' : ''}${r}`);
    } else if (shape === 'toml-section') {
      blockLines.push(`[${pick(SECTIONS)}]`);
      runs.forEach((r, i) => blockLines.push(`key${i} = "${r}"`));
      blockLines.push('[other]');
    } else if (shape === 'env-multiline') {
      blockLines.push(`${pick(ENV_NAMES)}="${runs[0]}`, ...runs.slice(1), '"');
    } else if (shape === 'json-block') {
      blockLines.push(`${ind}"${pick(VALUE_NAMES)}":`, ...runs.map((r) => `${ind}  "${r}"`));
    } else {
      // a connection string broken across lines: user and password on one line, host on the next
      blockLines.push(`url=postgres://app:${runs[0]}`, `@db.internal:5432/app`);
      runs.splice(1);
    }
  }
  const cleanBlock = [...blockLines];
  // insertions anywhere in the block, the first and last lines (markers, key lines) more often
  const params = () => Array.from({ length: int(5) }, () => pick([...'0123456789;'])).join('');
  const final = () => String.fromCharCode(0x40 + int(0x3f));
  const pieces = [
    () => `\u001b[${params()}${rnd() < 0.2 ? pick([...' !"#$%&()*+,-./']) : ''}${final()}`,
    () => `\u001b]${pick(['0;', '8;;'])}${b64(int(10))}${pick(['\u0007', '\u001b\\', ''])}`,
    () => `\u009b${params()}${final()}`,
    () => `\u009d${b64(int(10))}${pick(['\u009c', '\u0007', ''])}`,
    () => String.fromCharCode(0x80 + int(0x20)),
    () => '\u001b',
    () => `\u001b${pick(['(', ')', '#', ''])}${final()}`,
    () => '\u2028',
    () => '\u2029',
    () => '\r',
  ];
  for (let k = int(9); k > 0; k--) {
    const at = rnd() < 0.4 ? pick([0, blockLines.length - 1]) : int(blockLines.length);
    const line = blockLines[at] as string;
    const pos = int(line.length + 1);
    blockLines[at] = line.slice(0, pos) + pick(pieces)() + line.slice(pos);
  }
  const around = (m: number) => Array.from({ length: m }, () => pick(NORMAL));
  const before = around(int(20));
  const after = around(int(20));
  if (rnd() < 0.7) before.push('Error: signing failed');
  if (rnd() < 0.7) after.unshift('Error: key rejected');
  const stamp = rnd() < 0.5;
  const all = [...before, ...blockLines, ...after].map((l) => (stamp ? TS + l : l));
  const log = all.join('\n');
  // the clean block, whole, without timestamps: what the coverage check gives redact
  const bare = [...before, ...cleanBlock, ...after].join('\n');
  if (rnd() < 0.3 && blockLines.length > 1) {
    // cut inside the block: the tail starts on a line after a random point of a random block line after the first
    const line = before.length + 1 + int(blockLines.length - 1);
    const pos = all.slice(0, line).reduce((n, l) => n + l.length + 1, 0) + Math.floor(rnd() * ((all[line] as string).length + 1));
    if (log.length - pos > 0) return { shape, log, bare, runs, maxLogChars: log.length - pos };
  }
  return { shape, log, bare, runs };
}

/** The 16-character runs of the case's runs that are in `excerpt`. */
function leaked(excerpt: string, runs: readonly string[]): string[] {
  const windows = new Set<string>();
  for (const l of runs) for (let i = 0; i + 16 <= l.length; i++) windows.add(l.slice(i, i + 16));
  const out: string[] = [];
  for (const run of excerpt.match(/[A-Za-z0-9+/]{16,}/g) ?? []) {
    for (let i = 0; i + 16 <= run.length; i++) if (windows.has(run.slice(i, i + 16))) out.push(run.slice(i, i + 16));
  }
  return out;
}

describe('excerpt fuzz (E0a, scans 4 and 5)', () => {
  it(`excerpt fuzz: no 16-character run of a secret in any of redact's multi-line shapes reaches the excerpt (${CASES} cases, seed ${SEED})`, () => {
    const rnd = mulberry32(SEED);
    const scrub = (t: string) => t;
    const stats = new Map<string, { cases: number; checked: number; notCoveredClean: number; cuts: number }>();
    for (let c = 0; c < CASES; c++) {
      const kase = makeCase(rnd);
      const st = stats.get(kase.shape) ?? { cases: 0, checked: 0, notCoveredClean: 0, cuts: 0 };
      stats.set(kase.shape, st);
      st.cases++;
      if (kase.maxLogChars !== undefined) st.cuts++;
      // a case redact itself does not hide in the clean text (no inserted character, no timestamps, whole) is Plan A's gap, not the
      // excerpt's: counted, not checked. Window-independent: the excerpt's windows move when it hides a line
      if (leaked(redact(kase.bare), kase.runs).length > 0) {
        st.notCoveredClean++;
        continue;
      }
      st.checked++;
      const out = unscannedExcerpt(kase.log, scrub, kase.maxLogChars === undefined ? {} : { maxLogChars: kase.maxLogChars }).join('\n');
      const hits = leaked(out, kase.runs);
      if (hits.length > 0) {
        expect.fail(`case ${c} (${kase.shape}, seed ${SEED}) leaked ${hits.length} run(s); log ${JSON.stringify(kase.log.slice(0, 700))} cut ${kase.maxLogChars}; excerpt ${JSON.stringify(out.slice(0, 500))}`);
      }
    }
    const report = [...stats].map(([k, v]) => `${k}: ${v.cases} cases, ${v.checked} checked, ${v.notCoveredClean} not covered by redact even clean, ${v.cuts} cut`).join('\n');
    if (process.env.PIPEGEN_E0A_FUZZ_REPORT !== undefined) writeFileSync(process.env.PIPEGEN_E0A_FUZZ_REPORT, `${report}\n`);
    // the shapes redact covers must be checked in every case
    for (const shape of ['pem', 'yaml-block', 'yaml-literal', 'toml-section']) {
      const st = stats.get(shape);
      expect(st, report).toBeDefined();
      expect((st as { checked: number }).checked, report).toBe((st as { cases: number }).cases);
    }
  }, 900_000);
});
