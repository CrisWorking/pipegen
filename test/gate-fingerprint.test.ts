// Plan C Task C1b: fingerprints (gate/src/fingerprint.ts). Rulings: preflight-scan B5 (for secrets, an HMAC over the bytes of the
// scanned region, read from the workspace), S10 (for everything else, a hash of tool, rule, path and message, never the line),
// S11 (key id). Real fixtures from C1a; the workspace the secret regions point into is rebuilt in a temp dir from fake values.
import { createHash, createHmac } from 'node:crypto';
import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { fingerprintAll, fingerprintFinding, isQuotingFinding, keyId, keyProblem, maskSecretShapes, normaliseMessage, readRegion, REGION_MAX_BYTES } from '../gate/src/fingerprint.js';
import { parseSarif, parseSarifText, type ParsedFinding } from '../gate/src/sarif.js';
import { parseZapJsonText } from '../gate/src/zap.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';

type Obj = Record<string, unknown>;
const DIR = join(import.meta.dirname, 'fixtures', 'sarif');
const WS = '/home/runner/work/fixture/fixture';
const KEY = ['fp', 'test', 'a'.repeat(40)].join('-');
const OTHER_KEY = ['fp', 'test', 'b'.repeat(40)].join('-');
const read = (name: string) => readFileSync(join(DIR, name));
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const hmac = (key: string, data: string | Buffer) => createHmac('sha256', key).update(data).digest('hex');
const SEC = 'sec' + 'ret:';
const NOKEY = 'sec' + 'ret-nokey:';
const SF = ('sec' + 'ret') as 'secret';   // the finding's flag, spelled so no secret-like `name: value` sits in a committed test file
const PW = 'Possible hardcoded pass' + 'word: ';
const QP = 'quoted:';
const QPN = 'quoted-nokey:';
afterEach(cleanupRepos);

// the planted repo of the fixtures: src/config.js holds two fake tokens on the columns the real betterleaks and gitleaks reported
const LEAK_ONE = fake.githubClassic();
const LEAK_TWO = 'gh' + 'p_' + 'b'.repeat(36);
function plantedWorkspace(): string {
  const ws = makeTempDir();
  mkdirSync(join(ws, 'src'));
  writeFileSync(join(ws, 'src', 'config.js'), `export const first = "${LEAK_ONE}";\nexport const second = "${LEAK_TWO}";\n`);
  return ws;
}

const PLANTED: [string, string][] = [
  ['betterleaks.sarif', 'betterleaks'], ['gitleaks.sarif', 'gitleaks'], ['semgrep.sarif', 'semgrep'], ['osv-scanner.sarif', 'osv-scanner'], ['trivy-config.sarif', 'trivy-config'],
  ['trivy-image.sarif', 'trivy-image'], ['trivy-licence.sarif', 'trivy-licence'], ['hadolint.sarif', 'hadolint'], ['kube-linter.sarif', 'kube-linter'], ['nuclei.sarif', 'nuclei'],
  ['ruff.sarif', 'ruff'], ['gosec.sarif', 'gosec'], ['bandit.sarif', 'bandit'],
];
const PLAIN_TOOLS = PLANTED.filter(([, t]) => t !== 'betterleaks' && t !== 'gitleaks' && t !== 'trivy-image');
const parsed = (file: string, tool: string) => {
  const out = parseSarifText(read(file), tool, { workspace: WS });
  expect(out.toolError).toBeUndefined();
  return out.findings;
};

describe('parser additions for C1b: the region, the raw uri of an unmapped finding and the secret flag', () => {
  it('betterleaks and gitleaks keep the whole region and say secret; others say not secret', () => {
    const [first] = parsed('betterleaks.sarif', 'betterleaks');
    expect(first).toMatchObject({ [SF]: true, line: 1, startColumn: 23, endLine: 1, endColumn: 62, uriUnmapped: false });
    expect(parsed('semgrep.sarif', 'semgrep').every((f) => !f.secret)).toBe(true);
  });
  it('an unmapped finding keeps a hash of its raw uri, never the uri (so two unmapped files do not collapse); a mapped one has none', () => {
    const out = parseSarifText(JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Semgrep OSS' } }, results: [
      { ruleId: 'r', level: 'error', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri: '../a.js' }, region: { startLine: 1 } } }] },
      { ruleId: 'r', level: 'error', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'ok.js' }, region: { startLine: 1 } } }] }] }] }), 'semgrep', { workspace: WS });
    expect(out.findings.map((f) => [f.uriUnmapped, f.uriId])).toEqual([[true, sha('../a.js').slice(0, 32)], [false, undefined]]);
    expect(JSON.stringify(out)).not.toContain('../a.js');
  });
  it('the trivy-image findings (no repo path) keep the hash of the raw uri too', () => {
    expect(parsed('trivy-image.sarif', 'trivy-image').every((f) => f.uriUnmapped && f.uriId?.length === 32)).toBe(true);
  });
});

describe('fingerprint: non-secrets (S10)', () => {
  function shifted(file: string, by: number): Buffer {
    const doc = JSON.parse(read(file).toString()) as { runs: { results: Obj[] }[] };
    for (const run of doc.runs) for (const r of run.results) {
      for (const loc of (r.locations ?? []) as Obj[]) {
        const region = ((loc.physicalLocation ?? {}) as Obj).region as Obj | undefined;
        if (region === undefined) continue;
        const old = [region.startLine, region.endLine].filter((n): n is number => typeof n === 'number');
        for (const k of ['startLine', 'endLine']) if (typeof region[k] === 'number') region[k] = (region[k] as number) + by;
        const msg = r.message as Obj;
        msg.text = (msg.text as string).replace(/(?<![\w.])\d+(?!\w)/g, (m) => (old.includes(Number(m)) ? String(Number(m) + by) : m));
      }
    }
    return Buffer.from(JSON.stringify(doc));
  }
  for (const [file, tool] of PLAIN_TOOLS) {
    it(`fingerprint: line shift keeps it (${tool}, real fixture and the same file shifted by 7 lines)`, () => {
      const a = parseSarifText(read(file), tool, { workspace: WS }).findings;
      const b = parseSarifText(shifted(file, 7), tool, { workspace: WS }).findings;
      expect(a.length).toBeGreaterThan(0);
      if (a.some((f) => f.line !== undefined)) expect(b.map((f) => f.line)).not.toEqual(a.map((f) => f.line));   // the pair really differs
      expect(fingerprintAll(b, {}).map((f) => f.fingerprint)).toEqual(fingerprintAll(a, {}).map((f) => f.fingerprint));
    });
  }

  it('the fingerprint is sha256(tool \\0 ruleId \\0 uri \\0 message) of the finding, hex, and never holds the line', () => {
    const [f] = parsed('hadolint.sarif', 'hadolint');
    const out = fingerprintFinding(f, {});
    expect(out.by).toBe('hash');
    expect(out.fingerprint).toBe(sha(['hadolint', f.ruleId, f.file, normaliseMessage(f.message, [f.line ?? 0])].join('\0')));
    expect(out.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it('the tool\'s own partialFingerprints are ignored (S10): osv-scanner primaryLocationLineHash, gitleaks commit data', () => {
    const doc = JSON.parse(read('osv-scanner.sarif').toString()) as { runs: { results: Obj[] }[] };
    const before = fingerprintAll(parseSarif(doc, 'osv-scanner', { workspace: WS }).findings, {});
    for (const r of doc.runs[0].results) r.partialFingerprints = { primaryLocationLineHash: 'f'.repeat(64), other: 'x' };
    expect(fingerprintAll(parseSarif(doc, 'osv-scanner', { workspace: WS }).findings, {})).toEqual(before);
  });

  it('a different rule, file or message gives a different fingerprint (and a case or whitespace change in the message does not matter)', () => {
    const [f] = parsed('hadolint.sarif', 'hadolint');
    const base = fingerprintFinding(f, {}).fingerprint;
    expect(fingerprintFinding({ ...f, ruleId: 'DL9999' }, {}).fingerprint).not.toBe(base);
    expect(fingerprintFinding({ ...f, file: 'other/Dockerfile' }, {}).fingerprint).not.toBe(base);
    expect(fingerprintFinding({ ...f, message: `${f.message} and more` }, {}).fingerprint).not.toBe(base);
    expect(fingerprintFinding({ ...f, message: `  ${f.message.replace(/ /g, '   ')}\n` }, {}).fingerprint).toBe(base);
  });

  it('normaliseMessage: whitespace collapsed, the finding\'s own line numbers removed as whole tokens only', () => {
    expect(normaliseMessage('error at line 12:  bad\n thing (12)', [12])).toBe('error at line : bad thing ()');
    expect(normaliseMessage('version 1.12.3 and 112 and a12 and 12', [12])).toBe('version 1.12.3 and 112 and a12 and');
    expect(normaliseMessage('lines 3 to 9, 30', [3, 9])).toBe('lines to , 30');
  });

  it('two unmapped findings with different raw uris get different fingerprints; one raw uri twice gets one', () => {
    const base: ParsedFinding = { tool: 'semgrep', ruleId: 'r', severity: 'high', message: 'm', uriUnmapped: true, [SF]: false };
    const a = fingerprintFinding({ ...base, uriId: 'a'.repeat(32) }, {}).fingerprint;
    expect(fingerprintFinding({ ...base, uriId: 'b'.repeat(32) }, {}).fingerprint).not.toBe(a);
    expect(fingerprintFinding({ ...base, uriId: 'a'.repeat(32), line: 40 }, {}).fingerprint).toBe(a);
  });

  it('fingerprint: image finding ignores image name and digest, keeps the package and installed version', () => {
    const digest = `sha256:${'d'.repeat(64)}`;
    const [f] = parsed('trivy-image.sarif', 'trivy-image');
    const base = fingerprintFinding(f, {}).fingerprint;
    const other = { ...f, uriId: 'c'.repeat(32), message: f.message.replace('Package: busybox', `Package: busybox@${digest}`) };
    expect(fingerprintFinding(other, {}).fingerprint).toBe(base);
    expect(fingerprintFinding({ ...f, uriId: 'd'.repeat(32) }, {}).fingerprint).toBe(base);
    expect(fingerprintFinding({ ...f, message: f.message.replace('1.30.1-r2', '1.30.1-r9') }, {}).fingerprint).not.toBe(base);
    expect(fingerprintFinding({ ...f, message: f.message.replace('busybox', 'musl') }, {}).fingerprint).not.toBe(base);
    expect(fingerprintFinding({ ...f, ruleId: 'CVE-1999-0001' }, {}).fingerprint).not.toBe(base);
  });

  it('every finding of the real trivy-image run keeps its fingerprint when the image is renamed (only the secret one, which has no readable file, may differ)', () => {
    const doc = JSON.parse(read('trivy-image.sarif').toString()) as { runs: { results: { locations: { physicalLocation: { artifactLocation: Obj } }[] }[] }[] };
    const a = fingerprintAll(parseSarif(doc, 'trivy-image').findings, {});
    for (const r of doc.runs[0].results) r.locations[0].physicalLocation.artifactLocation.uri = 'docker.io/library/app:2.0';
    const b = fingerprintAll(parseSarif(doc, 'trivy-image').findings, {});
    expect(b.filter((f) => !f.secret).map((f) => f.fingerprint)).toEqual(a.filter((f) => !f.secret).map((f) => f.fingerprint));
  });

  it('zap: pluginid, method and url path only: host, port, query and fragment do not matter; evidence is never read', () => {
    const report = (uri: string, method = 'GET'): string => JSON.stringify({ '@programName': 'ZAP', site: [{ alerts: [{ pluginid: '40012', name: 'XSS', riskcode: '2', instances: [{ uri, method, evidence: 'ev-' + uri }] }] }] });
    const fp = (text: string): string => fingerprintAll(parseZapJsonText(text, 'zap-baseline').findings, {})[0].fingerprint;
    const base = fp(report('http://app.example:8080/a/b?x=1#f'));
    expect(fp(report('https://127.0.0.1:3000/a/b?y=2'))).toBe(base);
    expect(base).toBe(sha(['40012', 'GET', '/a/b'].join('\0')));
    expect(fp(report('http://app.example:8080/a/c'))).not.toBe(base);
    expect(fp(report('http://app.example:8080/a/b', 'POST'))).not.toBe(base);
  });
});

describe('fingerprint: secrets with a key (B5)', () => {
  it('fingerprint: HMAC(key, tool \\0 ruleId \\0 bytes of the workspace region) with the --redact SARIF (real betterleaks and gitleaks fixtures)', () => {
    const ws = plantedWorkspace();
    for (const [file, tool] of [['betterleaks.sarif', 'betterleaks'], ['gitleaks.sarif', 'gitleaks']] as const) {
      const findings = parseSarifText(read(file), tool, { workspace: WS }).findings;
      expect(findings.map((f) => f.line)).toEqual([1, 2]);
      const out = fingerprintAll(findings, { fpKey: KEY, workspace: ws });
      expect(out.map((f) => f.fpBy), tool).toEqual(['region', 'region']);
      const ruleId = `${SEC}github-pat`;
      expect(out[0].fingerprint, tool).toBe(`${SEC}${hmac(KEY, Buffer.from(`${tool}\0${ruleId}\0${LEAK_ONE}`))}`);
      expect(out[1].fingerprint, tool).toBe(`${SEC}${hmac(KEY, Buffer.from(`${tool}\0${ruleId}\0${LEAK_TWO}`))}`);
    }
  });

  it('the column arithmetic per tool: betterleaks columns are exact; gitleaks is one too high from line 2 on (a multi-line region too); both count bytes, not UTF-16 units', () => {
    const ws = makeTempDir();
    const needle = LEAK_ONE;
    writeFileSync(join(ws, 'f.txt'), `x\não = "${needle}"; // é\nlast\n`);
    const region = (tool: string, over: Partial<ParsedFinding>) => readRegion(ws, { tool, ruleId: 'r', severity: 'critical', file: 'f.txt', message: '', uriUnmapped: false, [SF]: true, line: 2, endLine: 2, ...over });
    // line 2 is "ão = "ghp_...";": the a-tilde is two bytes, so the token starts at byte 8 (1-based)
    const b = region('betterleaks', { startColumn: 8, endColumn: 47 });
    expect(b.ok && b.bytes.toString()).toBe(needle);
    const g = region('gitleaks', { startColumn: 9, endColumn: 48 });
    expect(g.ok && g.bytes.toString()).toBe(needle);
    // multi-line: from line 2 column 1 to line 3 column 4 (inclusive), joined with the newline between
    const multiB = region('betterleaks', { startColumn: 1, endLine: 3, endColumn: 4 });
    expect(multiB.ok && multiB.bytes.toString()).toBe(`ão = "${needle}"; // é\nlast`);
    const multiG = region('gitleaks', { startColumn: 2, endLine: 3, endColumn: 5 });
    expect(multiG.ok && multiG.bytes.toString()).toBe(`ão = "${needle}"; // é\nlast`);
  });

  it('fingerprint: two different secrets in same file → different fingerprints [Review Focus 10]', () => {
    const ws = plantedWorkspace();
    const out = fingerprintAll(parseSarifText(read('gitleaks.sarif'), 'gitleaks', { workspace: WS }).findings, { fpKey: KEY, workspace: ws });
    expect(out[0].fingerprint).not.toBe(out[1].fingerprint);
    // same rule, same file, same line shape: only the secret differs
    expect(out[0]).toMatchObject({ ruleId: out[1].ruleId, file: out[1].file });
  });

  it('the same secret moved to another line keeps its fingerprint (the region bytes, not the line, are hashed)', () => {
    const ws = makeTempDir();
    writeFileSync(join(ws, 'a.txt'), `k = "${LEAK_ONE}"\n`);
    writeFileSync(join(ws, 'b.txt'), `\n\n# moved\nk = "${LEAK_ONE}"\n`);
    const at = (file: string, line: number) => fingerprintFinding({ tool: 'betterleaks', ruleId: `${SEC}github-pat`, severity: 'critical', file, line, endLine: line, startColumn: 6, endColumn: 45, message: '', uriUnmapped: false, [SF]: true }, { fpKey: KEY, workspace: ws });
    expect(at('a.txt', 1).fingerprint).toBe(at('b.txt', 4).fingerprint);
    expect(at('a.txt', 1).by).toBe('region');
  });

  it('fingerprint: same secret with a different key → different fingerprint', () => {
    const ws = plantedWorkspace();
    const f = parseSarifText(read('betterleaks.sarif'), 'betterleaks', { workspace: WS }).findings;
    const a = fingerprintAll(f, { fpKey: KEY, workspace: ws });
    const b = fingerprintAll(f, { fpKey: OTHER_KEY, workspace: ws });
    expect(a.map((x) => x.fingerprint)).not.toEqual(b.map((x) => x.fingerprint));
    expect(a.every((x) => x.fingerprint.startsWith(SEC) && new RegExp(`^${SEC}[0-9a-f]{64}$`).test(x.fingerprint))).toBe(true);
  });

  it('a secret fingerprint never holds the secret, the key or the region text', () => {
    const ws = plantedWorkspace();
    const out = fingerprintAll(parseSarifText(read('gitleaks.sarif'), 'gitleaks', { workspace: WS }).findings, { fpKey: KEY, workspace: ws });
    const text = JSON.stringify(out);
    for (const s of [KEY, LEAK_ONE, LEAK_TWO]) expect(text).not.toContain(s);
  });

  it('key id (S11): 16 hex characters from HMAC(key, "pipegen-key-id"), never the key; two keys, two ids', () => {
    expect(keyId(KEY)).toBe(hmac(KEY, 'pipegen-key-id').slice(0, 16));
    expect(keyId(KEY)).toMatch(/^[0-9a-f]{16}$/);
    expect(keyId(OTHER_KEY)).not.toBe(keyId(KEY));
    expect(KEY).not.toContain(keyId(KEY));
  });
});

describe('fingerprint: the region cannot be read → the line form, flagged (B5)', () => {
  const finding = (over: Partial<ParsedFinding> = {}): ParsedFinding => ({ tool: 'betterleaks', ruleId: `${SEC}github-pat`, severity: 'critical', file: 'src/config.js', line: 1, endLine: 1, startColumn: 23, endColumn: 62, message: '', uriUnmapped: false, [SF]: true, ...over });
  const lineForm = (f: ParsedFinding, key = KEY) => `${SEC}${hmac(key, ['line', f.tool, f.ruleId, f.file ?? `unmapped:${f.uriId}`, f.line].join('\0'))}`;

  function expectFallback(f: ParsedFinding, ws: string, why: RegExp): void {
    const out = fingerprintFinding(f, { fpKey: KEY, workspace: ws });
    expect(out.by).toBe('line');
    expect(out.note).toMatch(why);
    expect(out.fingerprint).toBe(lineForm(f));
  }

  it('missing file', () => expectFallback(finding(), makeTempDir(), /missing/));

  it('region outside the file', () => {
    const ws = makeTempDir();
    writeFileSync(join(ws, 'src.js'), 'short\n');
    expectFallback(finding({ file: 'src.js', endColumn: 62 }), ws, /outside the file/);
    expectFallback(finding({ file: 'src.js', line: 9, endLine: 9 }), ws, /outside the file/);
  });

  it('a symbolic link as the file, pointing at the system accounts file: not read, flagged, line form', () => {
    const ws = makeTempDir();
    symlinkSync('/etc/passwd', join(ws, 'link.txt'));
    const f = finding({ file: 'link.txt', line: 1, endLine: 1, startColumn: 1, endColumn: 4 });
    expectFallback(f, ws, /link/);
    expect(readRegion(ws, f)).toEqual({ ok: false, reason: expect.stringMatching(/link/) });
  });

  it('a link in a folder of the path (src -> /etc) is refused; so is a link that stays inside the workspace', () => {
    const ws = makeTempDir();
    symlinkSync('/etc', join(ws, 'src'));
    expectFallback(finding({ file: 'src/passwd', startColumn: 1, endColumn: 4 }), ws, /link/);
    const inner = makeTempDir();
    mkdirSync(join(inner, 'real'));
    writeFileSync(join(inner, 'real', 'a.js'), `x = "${LEAK_ONE}"\n`);
    symlinkSync('real', join(inner, 'alias'));
    expectFallback(finding({ file: 'alias/a.js', startColumn: 6, endColumn: 45 }), inner, /link/);
  });

  it('a path that leaves the workspace (.. segments, absolute) is never opened', () => {
    const outer = makeTempDir();
    writeFileSync(join(outer, 'outside.txt'), `x = "${LEAK_ONE}"\n`);
    const ws = join(outer, 'ws');
    mkdirSync(ws);
    for (const file of ['../outside.txt', 'a/../../outside.txt', join(outer, 'outside.txt'), '/etc/passwd']) {
      const r = readRegion(ws, finding({ file, startColumn: 6, endColumn: 45 }));
      expect(r.ok, file).toBe(false);
      expect(fingerprintFinding(finding({ file, startColumn: 6, endColumn: 45 }), { fpKey: KEY, workspace: ws }).by, file).toBe('line');
    }
    // through the parser: an uri with .. is unmapped, so there is no file to read at all
    const parsedFinding = parseSarif({ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks' } }, results: [
      { ruleId: 'github-pat', message: { text: 'x' }, locations: [{ physicalLocation: { artifactLocation: { uri: '../outside.txt' }, region: { startLine: 1, startColumn: 6, endLine: 1, endColumn: 45 } } }] }] }] }, 'gitleaks', { workspace: ws }).findings[0];
    expect(parsedFinding.file).toBeUndefined();
    const out = fingerprintFinding(parsedFinding, { fpKey: KEY, workspace: ws });
    expect(out.by).toBe('line');
    expect(out.fingerprint).toBe(lineForm(parsedFinding));
  });

  it('a region over 64 KiB is not read; a region just under the cap is', () => {
    const ws = makeTempDir();
    writeFileSync(join(ws, 'big.txt'), `${'x'.repeat(REGION_MAX_BYTES + 10)}\n`);
    expectFallback(finding({ file: 'big.txt', startColumn: 1, endColumn: REGION_MAX_BYTES + 1 }), ws, /64 KiB/);
    const ok = readRegion(ws, finding({ file: 'big.txt', startColumn: 1, endColumn: REGION_MAX_BYTES }));
    expect(ok.ok && ok.bytes.length).toBe(REGION_MAX_BYTES);
  });

  it('a directory, a FIFO and a file that is not a regular file are refused without blocking', () => {
    const ws = makeTempDir();
    mkdirSync(join(ws, 'dir'));
    execFileSync('mkfifo', [join(ws, 'pipe')]);
    for (const file of ['dir', 'pipe']) expectFallback(finding({ file, startColumn: 1, endColumn: 4 }), ws, /regular file/);
  });

  it('an empty region (end before start) and a region with no columns are refused', () => {
    const ws = plantedWorkspace();
    expectFallback(finding({ startColumn: 30, endColumn: 20 }), ws, /region/);
    expectFallback(finding({ startColumn: undefined, endColumn: undefined }), ws, /region/);
  });

  it('a tool whose columns are not known (trivy, any other) is never read by region: its columns are placeholders', () => {
    const ws = plantedWorkspace();
    expectFallback(finding({ tool: 'trivy-config', startColumn: 1, endColumn: 1 }), ws, /columns/);
  });

  it('an unmapped file (an image layer, a ../ uri) uses the hash of its raw uri in the line form, so different ones differ', () => {
    const f = finding({ file: undefined, uriUnmapped: true, uriId: 'a'.repeat(32), tool: 'trivy-image' });
    const a = fingerprintFinding(f, { fpKey: KEY });
    const b = fingerprintFinding({ ...f, uriId: 'b'.repeat(32) }, { fpKey: KEY });
    expect(a.by).toBe('line');
    expect(a.fingerprint).toBe(lineForm(f));
    expect(a.fingerprint).not.toBe(b.fingerprint);
  });
});

describe('fingerprint: no key', () => {
  const f: ParsedFinding = { tool: 'gitleaks', ruleId: `${SEC}github-pat`, severity: 'critical', file: 'src/config.js', line: 4, message: '', uriUnmapped: false, [SF]: true };
  it('fingerprint: no key → secret-nokey fingerprint = sha256(tool, ruleId, uri, startLine)', () => {
    const out = fingerprintFinding(f, {});
    expect(out.by).toBe('nokey');
    expect(out.fingerprint).toBe(`${NOKEY}${sha([f.tool, f.ruleId, f.file, 4].join('\0'))}`);
  });
  it('the line is part of the nokey form (a moved secret is a new one, judged by the added-line rule), the key is not', () => {
    expect(fingerprintFinding({ ...f, line: 5 }, {}).fingerprint).not.toBe(fingerprintFinding(f, {}).fingerprint);
    expect(fingerprintFinding({ ...f, file: undefined, uriUnmapped: true, uriId: 'x'.repeat(32) }, {}).fingerprint).toMatch(new RegExp(`^${NOKEY}[0-9a-f]{64}$`));
  });
  it('keyProblem: empty on a non-fork event needs a key when a secrets tool is scrubbed; short keys are refused; a fork may go without', () => {
    expect(keyProblem(undefined, false, true)).toMatch(/PIPEGEN_FP_KEY is missing/);
    expect(keyProblem('', false, true)).toMatch(/PIPEGEN_FP_KEY is missing/);
    expect(keyProblem('', true, true)).toBeUndefined();
    expect(keyProblem('', false, false)).toBeUndefined();
    expect(keyProblem('x'.repeat(31), false, true)).toMatch(/at least 32/);
    expect(keyProblem('x'.repeat(31), true, true)).toMatch(/at least 32/);
    expect(keyProblem('x'.repeat(32), false, true)).toBeUndefined();
    expect(keyProblem('x'.repeat(31), false, true)).not.toContain('xxxx');
  });
});

describe('sha256Hex (pure TypeScript, for the uri id)', () => {
  it('equals node:crypto for edge lengths and non-ASCII text', async () => {
    const { sha256Hex } = await import('../gate/src/parse-common.js');
    for (const s of ['', 'a', 'abc', 'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(63), 'x'.repeat(64), 'x'.repeat(65), 'x'.repeat(119), 'x'.repeat(1000), 'ão \u{1f600} 中', '../../etc/passwd']) {
      expect(sha256Hex(s), s.slice(0, 8)).toBe(sha(s));
    }
  });
});

describe('fingerprint: rules that quote the matched string (bandit B105, B106, B107)', () => {
  const f = (message: string, over: Partial<ParsedFinding> = {}): ParsedFinding => ({ tool: 'bandit', ruleId: 'B105', severity: 'low', file: 'py/app.py', line: 4, message, uriUnmapped: false, [SF]: false, ...over });
  it('isQuotingFinding: bandit B105, B106 and B107 only', () => {
    expect(['B105', 'B106', 'B107'].every((id) => isQuotingFinding(f('m', { ruleId: id })))).toBe(true);
    expect(isQuotingFinding(f('m', { ruleId: 'B602' }))).toBe(false);
    expect(isQuotingFinding(f('m', { tool: 'semgrep' }))).toBe(false);
  });
  it('with a key: quoted: + HMAC over tool, rule, path and message; two different strings in one file differ; the line does not matter', () => {
    const a = fingerprintFinding(f(`${PW}'one-plain'`), { fpKey: KEY });
    expect(a.fingerprint).toBe(`${QP}${hmac(KEY, ['bandit', 'B105', 'py/app.py', `${PW}'one-plain'`].join('\0'))}`);
    expect(fingerprintFinding(f(`${PW}'two-plain'`), { fpKey: KEY }).fingerprint).not.toBe(a.fingerprint);
    expect(fingerprintFinding(f(`${PW}'one-plain'`, { line: 90 }), { fpKey: KEY }).fingerprint).toBe(a.fingerprint);
    expect(fingerprintFinding(f(`${PW}'one-plain'`), { fpKey: OTHER_KEY }).fingerprint).not.toBe(a.fingerprint);
    expect(a.fingerprint).not.toContain('one-plain');
  });
  it('without a key: quoted-nokey: + sha256 of tool, rule, path and line, no message (an unkeyed hash of a password string would be guessable)', () => {
    const a = fingerprintFinding(f(`${PW}'one-plain'`), {});
    expect(a).toMatchObject({ by: 'nokey', fingerprint: `${QPN}${sha(['bandit', 'B105', 'py/app.py', '4'].join('\0'))}` });
  });
});

describe('maskSecretShapes', () => {
  it('replaces every shape of the fake secrets and keeps the rest of the text', () => {
    for (const v of [fake.githubClassic(), fake.githubPat(), fake.stripeKey(), fake.openaiKey(), fake.awsKey(), fake.slackBot(), fake.jwt(), fake.slackWebhook(), fake.googleKey(), fake.npmPublish()]) {
      expect(maskSecretShapes(`before ${v} after`), v.slice(0, 4)).toBe('before [REDACTED] after');
    }
    expect(maskSecretShapes(`${fake.keyBegin()}\n${fake.keyBody()}\n${fake.keyEnd()} tail`)).toBe('[REDACTED] tail');
    expect(maskSecretShapes('Package: busybox 1.30.1-r2 CVE-2021-28831 https://avd.aquasec.com/nvd/cve-2021-28831')).toBe('Package: busybox 1.30.1-r2 CVE-2021-28831 https://avd.aquasec.com/nvd/cve-2021-28831');
  });
});
