// Plan E E0a, scan 4: the excerpt's private-key class, closed by a fuzz test instead of examples. PEM private-key blocks of 1-300 body
// lines (RSA, EC, DSA, OPENSSH, PKCS#8, ENCRYPTED; Proc-Type/DEK-Info headers and blank lines) get random CSI, OSC and C1 sequences, stray
// ESC bytes and LS/PS/CR at random places, the BEGIN and END markers included; normal log lines go around them, and some logs are cut so
// the cut falls inside the block. No 16-character base64 run of the key body may reach the excerpt. The secret scan (step 7) only removes
// lines, so unscannedExcerpt (steps 1-6) is what is checked; no scanner process runs here.
// Fixed seed. PIPEGEN_E0A_FUZZ_CASES and PIPEGEN_E0A_FUZZ_SEED change the count and the seed for a one-off longer run.
import { describe, expect, it } from 'vitest';
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

interface Case { log: string; body: string[]; maxLogChars?: number }

function makeCase(rnd: () => number): Case {
  const int = (n: number) => Math.floor(rnd() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)] as T;
  const b64 = (n: number) => Array.from({ length: n }, () => B64[int(64)]).join('');
  const kind = pick(KINDS);
  const n = 1 + int(300);
  const body: string[] = [];
  for (let i = 0; i < n; i++) body.push(i === n - 1 ? b64(4 + int(61)) + pick(['', '=', '==']) : b64(64));
  const blockLines: string[] = [marker(kind, false)];
  if (/^(RSA|EC|DSA) /.test(kind) && rnd() < 0.4) blockLines.push('Proc-Type: 4,ENCRYPTED', `DEK-Info: AES-128-CBC,${b64(16).replace(/[^0-9A-F]/g, 'A')}`, '');
  for (const l of body) {
    blockLines.push(l);
    if (rnd() < 0.03) blockLines.push(pick(['', ' ', '\t']));
  }
  blockLines.push(marker(kind, true));
  // insertions anywhere in the block, the markers more often
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
  if (rnd() < 0.3) {
    // cut inside the block: the tail starts on a line after a random point of a random block line after the BEGIN line
    const line = before.length + 1 + int(blockLines.length - 1);
    const start = all.slice(0, line).reduce((s, l) => s + l.length + 1, 0);
    const pos = start + int((all[line] as string).length + 1);
    if (log.length - pos > 0) return { log, body, maxLogChars: log.length - pos };
  }
  return { log, body };
}

/** The 16-character base64 runs of the key body that are in `excerpt`. */
function leaked(excerpt: string, body: string[]): string[] {
  const windows = new Set<string>();
  for (const l of body) for (let i = 0; i + 16 <= l.length; i++) windows.add(l.slice(i, i + 16));
  const out: string[] = [];
  for (const run of excerpt.match(/[A-Za-z0-9+/]{16,}/g) ?? []) {
    for (let i = 0; i + 16 <= run.length; i++) if (windows.has(run.slice(i, i + 16))) out.push(run.slice(i, i + 16));
  }
  return out;
}

describe('excerpt fuzz (E0a, scan 4)', () => {
  it(`excerpt fuzz: no 16-character base64 run of a private key body reaches the excerpt (${CASES} cases, seed ${SEED})`, () => {
    const rnd = mulberry32(SEED);
    const scrub = (t: string) => t;
    let cuts = 0;
    for (let c = 0; c < CASES; c++) {
      const kase = makeCase(rnd);
      if (kase.maxLogChars !== undefined) cuts++;
      const out = unscannedExcerpt(kase.log, scrub, kase.maxLogChars === undefined ? {} : { maxLogChars: kase.maxLogChars }).join('\n');
      const hits = leaked(out, kase.body);
      if (hits.length > 0) {
        expect.fail(`case ${c} (seed ${SEED}) leaked ${hits.length} run(s); log ${JSON.stringify(kase.log.slice(0, 600))} cut ${kase.maxLogChars}; excerpt ${JSON.stringify(out.slice(0, 600))}`);
      }
    }
    expect(cuts).toBeGreaterThan(CASES / 5);
  }, 600_000);
});
