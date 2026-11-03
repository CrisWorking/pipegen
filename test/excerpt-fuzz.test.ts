// Plan E E0a, scans 4 and 5: the excerpt's multi-line secret classes, closed by a fuzz test instead of examples: every multi-line shape
// Plan A redact hides (an indented value after `key:`, a YAML literal block, a TOML/INI secret section, a .env value over lines, a JSON
// value list), plus a connection string split over lines and PEM private-key blocks of 1-300 body
// lines (RSA, EC, DSA, OPENSSH, PKCS#8, ENCRYPTED; Proc-Type/DEK-Info headers and blank lines) get random CSI, OSC and C1 sequences, stray
// ESC bytes, LS/PS/CR, C0 controls, DEL and zero-width/bidi invisibles at random places, the BEGIN and END markers included; normal log lines go around them, and some logs are cut so
// the cut falls inside the block. No 16-character base64 run of the key body may reach the excerpt. The secret scan (step 7) only removes
// lines, so unscannedExcerpt (steps 1-6) is what is checked; no scanner process runs here.
// Fixed seed. PIPEGEN_E0A_FUZZ_CASES and PIPEGEN_E0A_FUZZ_SEED change the count and the seed for a one-off longer run.
import { writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { redact } from '../src/ai/redact.js';
import { SecretVault } from '../src/create/secrets.js';
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

/** The insertion alphabet: CSI, OSC and C1 sequences (some unterminated), stray ESC, ESC-other, LS/PS/CR, C0 controls, DEL, invisibles. */
function insertionPieces(rnd: () => number): (() => string)[] {
  const int = (n: number) => Math.floor(rnd() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)] as T;
  const b64 = (n: number) => Array.from({ length: n }, () => B64[int(64)]).join('');
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
    // scan 6: C0 controls (not LF, which ends a line), DEL, and the zero-width, bidi and other invisible characters
    () => String.fromCharCode(pick([...Array.from({ length: 10 }, (_, k) => k), ...Array.from({ length: 21 }, (_, k) => 11 + k), 0x7f])),
    () => pick(['\u200b', '\u200c', '\u200d', '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2060', '\u2066', '\u2067', '\u2068', '\u2069', '\ufeff', '\u00ad', '\u180e', '\ufe0f']),
  ];
  return pieces;
}

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
  // fix round 1 (I5): a foreign log line inside the block (parallel job output), where redact's own rule still covers it
  if ((shape === 'pem' || shape === 'toml-section') && blockLines.length > 2 && rnd() < 0.3) blockLines.splice(1 + int(blockLines.length - 2), 0, pick(NORMAL.filter((l) => l !== '')));
  const cleanBlock = [...blockLines];
  // insertions anywhere in the block, the first and last lines (markers, key lines) more often
  const pieces = insertionPieces(rnd);
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

describe('excerpt fuzz (E0a, scans 4 and 5, fix round 1)', () => {
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
    for (const shape of ['pem', 'yaml-block', 'yaml-literal', 'toml-section', 'json-block']) {
      const st = stats.get(shape);
      expect(st, report).toBeDefined();
      expect((st as { checked: number }).checked, report).toBe((st as { cases: number }).cases);
    }
  }, 900_000);
});

// ---------- vault mode (fix round 1, I5) ----------

const VALUE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+/=-';
// built at runtime (test/no-secret-literals.test.ts)
const CONN_PREFIX = ['url=postgres:', '//app:'].join('');
const VALUE_PREFIXES = [['Error: auth failed for '], ['using key '], ['Authori', 'zation', ': Bas', 'ic '], ['  tok', 'en', ': '], ['']].map((p) => p.join(''));

interface VaultCase { log: string; value: string; windows: string[]; form: string; maxLogChars?: number }

/**
 * A typed value (8-40 characters, sometimes Stripe-shaped) placed in one of the forms knownForms covers (as typed, base64, the base64 of
 * `user:value`, hex in either case, URL-encoded, JSON-escaped, in a connection string), whole or split over two lines at a random point,
 * with the insertion alphabet in and around it; plain filler around, and one error line 4-7 lines away so a window edge can fall
 * between the pieces. `windows`: what must never show (8 characters of the value; 12 of an encoded form, its edges aside).
 */
function makeVaultCase(rnd: () => number): VaultCase {
  const int = (n: number) => Math.floor(rnd() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)] as T;
  const value = (rnd() < 0.3 ? 'sk' + '_test_' : '') + Array.from({ length: 8 + int(33) }, () => VALUE_CHARS[int(VALUE_CHARS.length)]).join('');
  const b64 = (t: string) => Buffer.from(t, 'utf8').toString('base64');
  const hex = Buffer.from(value, 'utf8').toString('hex');
  const forms: [string, string][] = [
    ['raw', value], ['base64', b64(value)], ['basic', b64(`user:${value}`)], ['hex', hex], ['HEX', hex.toUpperCase()],
    ['url', encodeURIComponent(value)], ['json', JSON.stringify(value).slice(1, -1)], ['conn', value],
  ];
  const [form, text] = pick(forms);
  const prefix = form === 'conn' ? CONN_PREFIX : pick(VALUE_PREFIXES);
  const suffix = form === 'conn' ? '@db.internal:5432/app' : pick(['', ' rejected', '"', ' (401)']);
  let lines = [`${prefix}${text}${suffix}`];
  if (rnd() < 0.5) {
    const at = prefix.length + 1 + int(text.length - 1);
    const whole = lines[0] as string;
    lines = [whole.slice(0, at), `${pick(['', '', '    ', '\t'])}${whole.slice(at)}`];
  }
  const pieces = insertionPieces(rnd);
  for (let k = int(4); k > 0; k--) {
    const i = int(lines.length);
    const l = lines[i] as string;
    const pos = int(l.length + 1);
    lines[i] = l.slice(0, pos) + pick(pieces)() + l.slice(pos);
  }
  const filler = (n: number, tag: string) => Array.from({ length: n }, (_, i) => `${tag} step ${i} ok`);
  const d = 4 + int(4);
  const errorFirst = rnd() < 0.5;
  const before = errorFirst ? [...filler(int(10), 'a'), 'Error: request failed', ...filler(d - 1, 'b')] : filler(int(10), 'a');
  const after = errorFirst ? filler(int(10), 'c') : [...filler(d - 1, 'c'), 'Error: request failed', ...filler(int(10), 'd')];
  const stamp = rnd() < 0.5;
  const all = [...before, ...lines, ...after].map((l) => (stamp ? TS + l : l));
  const log = all.join('\n');
  const windows = form === 'raw' || form === 'url' || form === 'json' || form === 'conn'
    ? Array.from({ length: Math.max(0, value.length - 7) }, (_, i) => value.slice(i, i + 8))
    : Array.from({ length: Math.max(0, text.length - 15) }, (_, i) => text.slice(i + 2, i + 14));
  let maxLogChars: number | undefined;
  if (rnd() < 0.15) {
    // a cut just before or inside the value's lines
    const line = before.length + int(lines.length);
    const pos = all.slice(0, line).reduce((n, l) => n + l.length + 1, 0) + int((all[line] as string).length + 1);
    if (log.length - pos > 0) maxLogChars = log.length - pos;
  }
  return { log, value, windows, form, ...(maxLogChars === undefined ? {} : { maxLogChars }) };
}

describe('excerpt fuzz, vault mode (E0a fix round 1)', () => {
  it(`excerpt fuzz: no 8 characters of a vault value (12 of an encoded form) reach the excerpt, through the real vault scrubber (${CASES} cases, seed ${SEED + 1})`, () => {
    const rnd = mulberry32(SEED + 1);
    const byForm = new Map<string, number>();
    for (let c = 0; c < CASES; c++) {
      const kase = makeVaultCase(rnd);
      byForm.set(kase.form, (byForm.get(kase.form) ?? 0) + 1);
      const v = new SecretVault();
      v.set('K_VALUE', kase.value);
      const out = unscannedExcerpt(kase.log, v.scrubber(), kase.maxLogChars === undefined ? {} : { maxLogChars: kase.maxLogChars }).join('\n');
      v.wipe();
      const hits = kase.windows.filter((w) => out.includes(w));
      if (hits.length > 0) expect.fail(`vault case ${c} (${kase.form}, seed ${SEED + 1}) leaked ${JSON.stringify(hits.slice(0, 3))}; log ${JSON.stringify(kase.log.slice(-900))} cut ${kase.maxLogChars}; excerpt ${JSON.stringify(out.slice(0, 600))}`);
    }
    if (process.env.PIPEGEN_E0A_FUZZ_REPORT !== undefined) writeFileSync(`${process.env.PIPEGEN_E0A_FUZZ_REPORT}.vault`, `${[...byForm].map(([k, n]) => `${k}: ${n}`).join('\n')}\n`);
    expect(byForm.size).toBe(8);
  }, 900_000);
});

// ---------- wide vault mode (fix round 2, review-E0a-r1.md) ----------

const PUNCT = '_-+/=.~!@#$%^*:;,?';
const PREFIXES: ((i: number) => string)[] = [(i) => `#7 0.${300 + i} `, () => 'api-1  | ', () => 'app:build: '];

interface WideCase { log: string; value: string; windows: string[]; form: string; pieces: number; prefixed: boolean; inserted: number }

/**
 * The reviewer's shapes: values of 8-48 characters with punctuation (12 %), as typed, URL-encoded, JSON-escaped, in a Basic auth header
 * (split into 1-3 pieces over lines), or as the base64 or hex of a longer text that holds the value at any byte offset, wrapped at
 * 32/60/64/76 columns; a per-line prefix (buildkit, docker compose, turbo) on 40 % of logs; insertions in half of them; the error line
 * 0-8 lines away. `windows`: 8 characters of the value, or 12 of its encoded core (its edges aside).
 */
function makeWideCase(rnd: () => number): WideCase {
  const int = (n: number) => Math.floor(rnd() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)] as T;
  const value = Array.from({ length: 8 + int(41) }, () => (rnd() < 0.12 ? PUNCT[int(PUNCT.length)] : VALUE_CHARS[int(62)])).join('');
  const form = pick(['raw', 'url', 'json', 'basic', 'b64blob', 'hexblob'] as const);
  let lines: string[];
  let windows: string[];
  let pieces = 1;
  if (form === 'b64blob' || form === 'hexblob') {
    const before = Array.from({ length: int(40) }, () => VALUE_CHARS[int(62)]).join('');
    const blob = Buffer.from(`${before}${value}${'x'.repeat(int(30))}`, 'utf8');
    const off = Buffer.byteLength(before);
    const n = Buffer.byteLength(value);
    const enc = form === 'b64blob' ? blob.toString('base64') : blob.toString('hex');
    const core = form === 'b64blob' ? enc.slice(Math.ceil((8 * off) / 6) + 1, Math.floor((8 * (off + n)) / 6) - 1) : enc.slice(2 * off + 2, 2 * (off + n) - 2);
    lines = enc.match(new RegExp(`.{1,${pick([32, 60, 64, 76])}}`, 'g')) as string[];
    pieces = lines.length;
    windows = Array.from({ length: Math.max(0, core.length - 11) }, (_, i) => core.slice(i, i + 12));
  } else {
    const text = form === 'url' ? encodeURIComponent(value) : form === 'json' ? JSON.stringify(value).slice(1, -1) : value;
    const head = form === 'basic' ? ['Authori', 'zation: Bas', 'ic '].join('') : pick(VALUE_PREFIXES);
    const whole = form === 'basic' ? `${head}${Buffer.from(`user:${value}`).toString('base64')}` : `${head}${text} rejected`;
    pieces = 1 + int(3);
    const cuts = Array.from({ length: pieces - 1 }, () => head.length + 1 + int(Math.max(1, whole.length - head.length - 2))).sort((a, b) => a - b);
    lines = [];
    let at = 0;
    for (const c of [...cuts, whole.length]) { lines.push(whole.slice(at, Math.max(at, c))); at = Math.max(at, c); }
    const basicCore = Buffer.from(`user:${value}`).toString('base64');
    windows = form === 'basic' ? Array.from({ length: Math.max(0, basicCore.length - 21) }, (_, i) => basicCore.slice(i + 8, i + 20))
      : Array.from({ length: Math.max(0, value.length - 7) }, (_, i) => value.slice(i, i + 8));
  }
  let inserted = 0;
  if (rnd() < 0.5) {
    const ins = insertionPieces(rnd);
    for (let k = 1 + int(3); k > 0; k--, inserted++) {
      const i = int(lines.length);
      const l = lines[i] as string;
      const pos = int(l.length + 1);
      lines[i] = l.slice(0, pos) + pick(ins)() + l.slice(pos);
    }
  }
  const prefixed = rnd() < 0.4;
  const prefix = pick(PREFIXES);
  const filler = (n: number, tag: string) => Array.from({ length: n }, (_, i) => `${tag} step ${i} ok`);
  const d = int(9);
  const errorFirst = rnd() < 0.5;
  const before = errorFirst ? [...filler(int(8), 'a'), 'Error: request failed', ...filler(d, 'b')] : filler(int(8), 'a');
  const after = errorFirst ? filler(int(8), 'c') : [...filler(d, 'c'), 'Error: request failed', ...filler(int(8), 'd')];
  const all = [...before, ...lines, ...after].map((l, i) => (prefixed ? prefix(i) + l : l));
  return { log: all.join('\n'), value, windows, form, pieces, prefixed, inserted };
}

describe('excerpt fuzz, wide vault mode (E0a fix round 2)', () => {
  it(`excerpt fuzz: no structural split leaks (prefixes, 3 pieces, wrapped blobs, punctuation); split + insertion leaks are counted (${CASES} cases, seed ${SEED + 2})`, () => {
    const rnd = mulberry32(SEED + 2);
    const counts = new Map<string, { cases: number; leaks: number }>();
    for (let c = 0; c < CASES; c++) {
      const kase = makeWideCase(rnd);
      const cls = `${kase.form}/${kase.pieces > 2 ? '3+' : kase.pieces} pieces/${kase.prefixed ? 'prefixed' : 'plain'}/${kase.inserted > 0 ? 'inserted' : 'clean'}`;
      const st = counts.get(cls) ?? { cases: 0, leaks: 0 };
      counts.set(cls, st);
      st.cases++;
      const v = new SecretVault();
      v.set('K_VALUE', kase.value);
      const out = unscannedExcerpt(kase.log, v.scrubber()).join('\n');
      v.wipe();
      const hits = kase.windows.filter((w) => out.includes(w));
      if (hits.length === 0) continue;
      st.leaks++;
      // structure alone (no inserted character) must never leak; with insertions the leaks are recorded limits (ruling E0a-R5)
      if (kase.inserted === 0) expect.fail(`wide case ${c} (${cls}, seed ${SEED + 2}) leaked ${JSON.stringify(hits.slice(0, 3))}; log ${JSON.stringify(kase.log.slice(-900))}; excerpt ${JSON.stringify(out.slice(0, 600))}`);
    }
    if (process.env.PIPEGEN_E0A_FUZZ_REPORT !== undefined) {
      writeFileSync(`${process.env.PIPEGEN_E0A_FUZZ_REPORT}.wide`, `${[...counts].sort().map(([k, s]) => `${k}: ${s.cases} cases, ${s.leaks} leaked`).join('\n')}\n`);
    }
    expect(counts.size).toBeGreaterThan(20);
  }, 900_000);
});
