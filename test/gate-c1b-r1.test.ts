// Plan C Task C1b, fix round 1 (review-C1b.md): every reproduction of the review as a regression test.
// C2 (uris are not percent-decoded for the secrets tools), I1 (the fingerprint form is marked), I3 (semgrep's message comes
// from the rule template; every other message goes through the shared masking core), m1 (a secret-shaped path is withheld),
// m2 (surviving mutants), m3 (one read per file), m4 (JSON-escaped last check, key shape, masked error texts).
import { createHash, createHmac } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { build } from 'esbuild';
import { maskText } from '../src/ai/redact-core.js';
import { afterEach, describe, expect, it } from 'vitest';
import { CONTENT_FORMS, fingerprintAll, fingerprintFinding, isPositionForm, keyProblem, POSITION_FORMS, readRegion, type FpBy } from '../gate/src/fingerprint.js';
import { normaliseUri, parseSarif, parseSarifText, SARIF_TOOLS, type ParsedFinding } from '../gate/src/sarif.js';
import { readScrubbed, scrubBytes } from '../gate/src/scrub.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';

type Obj = Record<string, unknown>;
const DIR = join(import.meta.dirname, 'fixtures', 'sarif');
const WS = '/home/runner/work/fixture/fixture';
const KEY = ['fp', 'test', 'a'.repeat(40)].join('-');
const read = (name: string) => readFileSync(join(DIR, name));
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const hmac = (key: string, data: string | Buffer) => createHmac('sha256', key).update(data).digest('hex');
const SEC = 'sec' + 'ret:';
const NOKEY = 'sec' + 'ret-nokey:';
const SF = ('sec' + 'ret') as 'secret';
const PUSH_EVENT = JSON.stringify({ repository: { id: 7 } });
const FORK_PR = JSON.stringify({ repository: { id: 7 }, pull_request: { head: { repo: { id: 8 } } } });
afterEach(cleanupRepos);

const LEAK_A = fake.githubClassic();
const LEAK_B = 'gh' + 'p_' + 'b'.repeat(36);
const run = (raw: Buffer | string, tool: string, over: Obj = {}) => scrubBytes(typeof raw === 'string' ? Buffer.from(raw) : raw, { tool, format: 'sarif', fpKey: KEY, eventText: PUSH_EVENT, workspace: WS, ...over } as Parameters<typeof scrubBytes>[1]);
function ok(o: ReturnType<typeof scrubBytes>): Extract<ReturnType<typeof scrubBytes>, { status: 'ok' }> {
  if (o.status !== 'ok') throw new Error(`expected ok, got ${o.error}`);
  return o;
}
/** A one-result SARIF of a secrets tool: columns 23..62 on line 1 (where the first line of FIRST() has the token). */
const leakSarif = (tool: 'betterleaks' | 'gitleaks', uri: string, ruleId = 'github-pat', line = 1) => JSON.stringify({ version: '2.1.0', runs: [{
  tool: { driver: { name: tool } },
  results: [{ ruleId, message: { text: 'x' }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line, startColumn: 23, endLine: line, endColumn: 62 } } }] }],
}] });
const FIRST = (leak: string) => `export const first = "${leak}";\n`;
function write(ws: string, rel: string, text: string): void {
  mkdirSync(join(ws, ...rel.split('/').slice(0, -1)), { recursive: true });
  writeFileSync(join(ws, rel), text);
}

// ---------------------------------------------------------------------------------------------------- C2
describe('C2: a uri is percent-decoded only for a tool that is known to percent-encode (x11, x14)', () => {
  it('the table: betterleaks and gitleaks write raw paths (measured with the pinned binaries); every other tool is unmeasured', () => {
    expect(SARIF_TOOLS.betterleaks.uriEncoding).toBe('raw');
    expect(SARIF_TOOLS.gitleaks.uriEncoding).toBe('raw');
    for (const [id, info] of Object.entries(SARIF_TOOLS)) {
      expect(['raw', 'percent', 'unmeasured'], id).toContain(info.uriEncoding);
      if (id !== 'betterleaks' && id !== 'gitleaks') expect(info.uriEncoding, id).toBe('unmeasured');
    }
    expect(Object.isFrozen(SARIF_TOOLS)).toBe(true);
  });

  it('normaliseUri: raw never decodes, percent decodes once, unmeasured (and no setting) refuses any "%"', () => {
    const n = (u: string, encoding?: 'raw' | 'percent' | 'unmeasured') => normaliseUri(u, { workspace: WS, ...(encoding === undefined ? {} : { encoding }) });
    expect(n('src/%61pp.js', 'raw')).toBe('src/%61pp.js');
    expect(n('src/%61pp.js', 'percent')).toBe('src/app.js');
    expect(n('src/%61pp.js', 'unmeasured')).toBeUndefined();
    expect(n('src/%61pp.js')).toBeUndefined();
    expect(n('a%20b.js', 'raw')).toBe('a%20b.js');
    expect(n('a%20b.js', 'unmeasured')).toBeUndefined();
    expect(n('src/app.js', 'unmeasured')).toBe('src/app.js');
    expect(n('src/app.js')).toBe('src/app.js');
    // raw: a "%2e%2e" is a file name, not a traversal; the other refusals still hold
    expect(n('%2e%2e/x', 'raw')).toBe('%2e%2e/x');
    expect(n('../x', 'raw')).toBeUndefined();
    expect(n('/etc/passwd', 'raw')).toBeUndefined();
    expect(n('a\\b', 'raw')).toBeUndefined();
    expect(n('a\u0000b', 'raw')).toBeUndefined();
    expect(n('src/100%.js', 'raw')).toBe('src/100%.js');   // a lone "%" is a valid raw name (and would be invalid percent-encoding)
  });

  for (const tool of ['betterleaks', 'gitleaks'] as const) {
    it(`${tool}: src/%61pp.js stays its own path and is read as its own file, never src/app.js (keyed)`, () => {
      const ws = makeTempDir();
      write(ws, 'src/%61pp.js', FIRST(LEAK_A));                    // the PR's new file, the secret is here
      write(ws, 'src/app.js', FIRST('gh' + 'p_' + 'q'.repeat(36)));   // the decoy the old decoding pointed at (same columns, other bytes)
      const parsed = parseSarifText(leakSarif(tool, 'src/%61pp.js'), tool, { workspace: ws });
      expect(parsed.toolError).toBeUndefined();
      expect(parsed.findings[0]).toMatchObject({ file: 'src/%61pp.js', uriUnmapped: false });
      const out = ok(run(leakSarif(tool, 'src/%61pp.js'), tool, { workspace: ws }));
      const back = readScrubbed(out.bytes, 'sarif').findings[0];
      expect(back).toMatchObject({ file: 'src/%61pp.js', fpBy: 'region' });
      expect(back.fingerprint).toBe(`${SEC}${hmac(KEY, Buffer.from(`${tool}\0${SEC}github-pat\0${LEAK_A}`))}`);   // the bytes of the new file
      expect(out.bytes.toString()).not.toContain('"src/app.js"');
    });

    it(`${tool}: src/%61pp.js without a key (a fork) keeps its own path, so the added-line rule looks at the right file`, () => {
      const ws = makeTempDir();
      write(ws, 'src/%61pp.js', `1\n2\n${FIRST(LEAK_A)}`);
      const out = ok(run(leakSarif(tool, 'src/%61pp.js', 'github-pat', 3), tool, { workspace: ws, fpKey: '', eventText: FORK_PR }));
      const back = readScrubbed(out.bytes, 'sarif').findings[0];
      expect(back).toMatchObject({ file: 'src/%61pp.js', line: 3, uriUnmapped: false, fpBy: 'nokey' });
      expect(back.fingerprint.startsWith(NOKEY)).toBe(true);
      expect(back.fingerprint).toBe(`${NOKEY}${sha([tool, `${SEC}github-pat`, 'src/%61pp.js', '3'].join('\0'))}`);
    });

    it(`${tool}: a literal "a%20b.js" is that file, not "a b.js"`, () => {
      const parsed = parseSarifText(leakSarif(tool, 'a%20b.js'), tool, { workspace: makeTempDir() });
      expect(parsed.findings[0]).toMatchObject({ file: 'a%20b.js' });
    });
  }

  it('a tool that is not measured: a uri with "%" is unmapped (fail closed: a keyless secret then stays new), without one it maps as before', () => {
    const raw = (uri: string) => JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Semgrep OSS' } }, results: [{ ruleId: 'r', level: 'error', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 3 } } }] }] }] });
    for (const uri of ['src/%61pp.js', 'a%20b.js', '%2e%2e/x']) {
      const f = parseSarifText(raw(uri), 'semgrep', { workspace: WS }).findings[0];
      expect(f, uri).toMatchObject({ uriUnmapped: true });
      expect(f.file, uri).toBeUndefined();
    }
    expect(parseSarifText(raw('src/app.js'), 'semgrep', { workspace: WS }).findings[0]).toMatchObject({ file: 'src/app.js', uriUnmapped: false });
    // the real fixtures of the unmeasured tools hold no "%" in a uri, so they still map
    for (const [file, tool] of [['semgrep.sarif', 'semgrep'], ['hadolint.sarif', 'hadolint'], ['trivy-config.sarif', 'trivy-config'], ['osv-scanner.sarif', 'osv-scanner']] as const) {
      expect(parseSarifText(read(file), tool, { workspace: WS }).findings.some((f) => f.file !== undefined), tool).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------------------------------- I1
describe('I1: every fingerprint says which form it is', () => {
  const finding = (over: Partial<ParsedFinding>): ParsedFinding => ({ tool: 'hadolint', ruleId: 'DL3000', severity: 'high', file: 'Dockerfile', line: 2, message: 'm', uriUnmapped: false, [SF]: false, ...over });

  it('the forms are exported, split into content forms and position forms (C2 compares them differently)', () => {
    expect([...CONTENT_FORMS].sort()).toEqual(['hash', 'quoted', 'region']);
    expect([...POSITION_FORMS].sort()).toEqual(['line', 'nokey', 'quoted-nokey']);
    for (const f of CONTENT_FORMS) expect(isPositionForm(f)).toBe(false);
    for (const f of POSITION_FORMS) expect(isPositionForm(f)).toBe(true);
  });

  it('each way of making a fingerprint reports its own form', () => {
    const ws = makeTempDir();
    write(ws, 'a.js', FIRST(LEAK_A));
    const leak = (over: Partial<ParsedFinding> = {}) => finding({ tool: 'betterleaks', ruleId: `${SEC}github-pat`, file: 'a.js', line: 1, startColumn: 23, endLine: 1, endColumn: 62, [SF]: true, ...over });
    const by = (f: ParsedFinding, fpKey: string | undefined = KEY, workspace: string | undefined = ws): FpBy => fingerprintFinding(f, { fpKey, workspace }).by;
    expect(by(finding({}))).toBe('hash');
    expect(by(leak())).toBe('region');
    expect(by(leak({ file: 'missing.js' }))).toBe('line');
    expect(by(leak(), '')).toBe('nokey');
    expect(by(finding({ tool: 'trivy-image', ruleId: `${SEC}x`, file: undefined, [SF]: true }))).toBe('line');
    expect(by(finding({ tool: 'bandit', ruleId: 'B105', message: 'x' }))).toBe('quoted');
    expect(by(finding({ tool: 'bandit', ruleId: 'B105', message: 'x' }), '')).toBe('quoted-nokey');
    expect(by(finding({ tool: 'zap-baseline', ruleId: '10001', method: 'GET' }))).toBe('hash');
  });

  it('the form is written, read back, counted, and an unknown or forged form is refused on read-back', () => {
    const ws = makeTempDir();
    write(ws, 'a.js', FIRST(LEAK_A));
    const doc = JSON.parse(leakSarif('gitleaks', 'a.js')) as { runs: { results: Obj[] }[] };
    doc.runs[0].results.push({ ...(doc.runs[0].results[0] as Obj), locations: [{ physicalLocation: { artifactLocation: { uri: 'gone.js' }, region: { startLine: 1, startColumn: 23, endLine: 1, endColumn: 62 } } }] });
    const out = ok(run(JSON.stringify(doc), 'gitleaks', { workspace: ws }));
    expect(readScrubbed(out.bytes, 'sarif').findings.map((f) => f.fpBy)).toEqual(['region', 'line']);
    expect(out.fpBy).toMatchObject({ region: 1, line: 1, nokey: 0, hash: 0, quoted: 0, 'quoted-nokey': 0 });
    for (const form of ['quoted', 'quoted-nokey']) {
      const bandit = { version: '2.1.0', runs: [{ tool: { driver: { name: 'Bandit' } }, results: [{ ruleId: 'B105', message: { text: 'x' }, properties: { issue_severity: 'LOW' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'p.py' }, region: { startLine: 1 } } }] }] }] };
      const o = ok(run(JSON.stringify(bandit), 'bandit', form === 'quoted' ? {} : { fpKey: '', eventText: FORK_PR }));
      expect(readScrubbed(o.bytes, 'sarif').findings[0].fpBy).toBe(form);
    }
    const forged = out.bytes.toString().replace('"pipegenFpBy":"region"', '"pipegenFpBy":"magic"');
    expect(readScrubbed(forged, 'sarif').toolError).toMatch(/unknown severity or fingerprint form/);
  });

  it('every real fixture scrubs to forms from the two lists only', () => {
    const forms = new Set<string>([...CONTENT_FORMS, ...POSITION_FORMS]);
    const ws = makeTempDir();
    write(ws, 'src/config.js', `${FIRST(LEAK_A)}`);
    for (const [file, tool] of [['betterleaks.sarif', 'betterleaks'], ['semgrep.sarif', 'semgrep'], ['trivy-image.sarif', 'trivy-image'], ['bandit.sarif', 'bandit']] as const) {
      const out = ok(run(read(file), tool, { workspace: ws }));
      for (const f of readScrubbed(out.bytes, 'sarif').findings) expect(forms.has(f.fpBy), `${tool} ${f.fpBy}`).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------------------------------- I3
describe('I3: messages and fingerprints come from the rule template (semgrep) or from the shared masking core', () => {
  const VALUE = 'e53fd24b97953be5915b106e26608212f4ecac45d2a575b4641e39d08354081b237908191ae296badc1994ee29eddd03d4a71c9d45add8fed17257f0e4cf69a3';
  const TEMPLATE = '$VALUE Found a string literal assignment to a production Rails session secret in `secrets.yaml`. Do not commit values to source control.';
  const RULE = 'ruby.rails.security.brakeman.check-rails-secret-yaml';
  const FULL_RULE: Obj = { id: RULE, fullDescription: { text: TEMPLATE }, shortDescription: { text: 'Semgrep Finding: x' } };
  const semgrep = (message: string, rules: Obj[] = [FULL_RULE], uri = 'config/secrets.prod.yml') => JSON.stringify({
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'Semgrep OSS', rules } }, results: [{ ruleId: RULE, ruleIndex: 0, level: 'warning', message: { text: message }, locations: [{ physicalLocation: { artifactLocation: { uri, uriBaseId: '%SRCROOT%' }, region: { startLine: 2, startColumn: 3, endLine: 2, endColumn: 148, snippet: { text: VALUE } } } }] }] }],
  });

  it('semgrep (x12, check-rails-secret-yaml): the interpolated value is nowhere in the output; the message is the rule template', () => {
    const out = ok(run(semgrep(`${VALUE} Found a string literal assignment to a production Rails session secret in \`secrets.yaml\`. Do not commit values to source control.`), 'semgrep'));
    const text = out.bytes.toString();
    expect(text).not.toContain(VALUE);
    expect(text).not.toContain(VALUE.slice(0, 24));
    const f = readScrubbed(out.bytes, 'sarif').findings[0];
    expect(f.message).toBe(TEMPLATE);
    expect(f.message).toContain('$VALUE');
  });

  it('semgrep: the fingerprint is over the template, so it is the same for any interpolated value, and it is the ruled hash of tool, rule, file and template', () => {
    const a = readScrubbed(ok(run(semgrep(`${VALUE} Found a string literal assignment to a production Rails session secret in \`secrets.yaml\`. Do not commit values to source control.`), 'semgrep')).bytes, 'sarif').findings[0];
    const b = readScrubbed(ok(run(semgrep(`${'0123456789abcdef'.repeat(8)} Found a string literal assignment to a production Rails session secret in \`secrets.yaml\`. Do not commit values to source control.`), 'semgrep')).bytes, 'sarif').findings[0];
    expect(a.fingerprint).toBe(b.fingerprint);
    expect(a.fingerprint).toBe(sha(['semgrep', RULE, 'config/secrets.prod.yml', TEMPLATE].join('\0')));
    expect(a.fpBy).toBe('hash');
  });

  it('semgrep: a rule with no template text (or no rule entry at all) gets a fixed message, never the result text', () => {
    for (const rules of [[{ id: RULE }], [], [{ id: RULE, fullDescription: { text: 5 } }], [{ id: RULE, fullDescription: { text: '' } }]]) {
      const raw = semgrep(`${VALUE} anything the tool interpolated`, rules);
      const parsed = parseSarif(JSON.parse(raw), 'semgrep');
      if (parsed.toolError !== undefined) continue;   // a malformed template is a tool error: also fail closed
      const out = ok(run(raw, 'semgrep'));
      expect(out.bytes.toString()).not.toContain(VALUE);
      expect(readScrubbed(out.bytes, 'sarif').findings[0].message).toBe(`finding of rule ${RULE}`);
    }
  });

  it('semgrep: findings of one rule in one file with different interpolated values are separate results with one fingerprint (C2 counts them)', () => {
    const doc = JSON.parse(semgrep('x one')) as { runs: { results: Obj[] }[] };
    doc.runs[0].results.push({ ...(doc.runs[0].results[0] as Obj), message: { text: 'y two' } });
    const fps = readScrubbed(ok(run(JSON.stringify(doc), 'semgrep')).bytes, 'sarif').findings.map((f) => f.fingerprint);
    expect(fps).toHaveLength(2);
    expect(fps[0]).toBe(fps[1]);
  });

  it('the real semgrep fixture: every message is its rule template and every fingerprint is a sha256 of that template', () => {
    const raw = JSON.parse(read('semgrep.sarif').toString()) as { runs: { tool: { driver: { rules: { id: string; fullDescription: { text: string } }[] } }; results: { ruleId: string }[] }[] };
    const templates = new Map(raw.runs[0].tool.driver.rules.map((r) => [r.id, r.fullDescription.text]));
    const out = readScrubbed(ok(run(read('semgrep.sarif'), 'semgrep')).bytes, 'sarif').findings;
    expect(out.length).toBeGreaterThan(0);
    for (const [i, f] of out.entries()) expect(f.message, f.ruleId).toBe(maskText(templates.get(raw.runs[0].results[i].ruleId) ?? '').slice(0, 1024));
  });

  it('every other non-secret tool: the message goes through the core masking (token, password-like assignment, JWT, connection-string password, entropy belt), and the fingerprint stays stable', () => {
    const doc = (text: string) => JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Bandit' } }, results: [{ ruleId: 'B999', message: { text }, properties: { issue_severity: 'HIGH' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'py/app.py' }, region: { startLine: 4 } } }] }] }] });
    const pw = 'hunter' + '2' + 'Xq9vB';
    const entropic = 'Zk3' + 'qP9xW2' + 'mT7vL5nR8' + 'cB4yH6';
    const forms = [
      (v: string) => `value ${v} here`,
      (v: string) => `${'pass' + 'word'} = "${v}"`,
      (v: string) => `connect to ${'postgres' + '://'}app:${v}@db.internal/app`,
    ];
    const shapes = [LEAK_A, entropic, fake.jwt()];   // recognisable anywhere in a sentence
    const plain = [pw, 'hunter' + '3' + 'Zz8wQ'];       // only with a password-like name or a connection string around them
    for (const [i, make] of forms.entries()) {
      const prints = new Set<string>();
      for (const v of i === 0 ? shapes : [...shapes, ...plain]) {
        const out = ok(run(doc(make(v)), 'bandit'));
        expect(out.bytes.toString(), `${make('V')} / ${v.slice(0, 6)}`).not.toContain(v);
        prints.add(readScrubbed(out.bytes, 'sarif').findings[0].fingerprint);
      }
      expect(prints.size, 'same masked text, one fingerprint').toBe(1);
    }
    // a hadolint message with a long random-looking run is masked in the same way
    const hado = JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Hadolint' } }, results: [{ ruleId: 'DL3000', level: 'error', message: { text: `Use absolute WORKDIR near ${entropic}` }, locations: [{ physicalLocation: { artifactLocation: { uri: 'Dockerfile' }, region: { startLine: 4 } } }] }] }] });
    expect(ok(run(hado, 'hadolint')).bytes.toString()).not.toContain(entropic);
  });

  it('ordinary messages of the real fixtures are not changed by the masking (no churn in their fingerprints)', () => {
    for (const [file, tool] of [['hadolint.sarif', 'hadolint'], ['kube-linter.sarif', 'kube-linter'], ['ruff.sarif', 'ruff'], ['gosec.sarif', 'gosec']] as const) {
      const raw = parseSarifText(read(file), tool, { workspace: WS }).findings;
      const back = readScrubbed(ok(run(read(file), tool)).bytes, 'sarif').findings;
      expect(back.map((f) => f.message), tool).toEqual(raw.map((f) => f.message.slice(0, 1024)));
    }
  });

  it('the gate scrub pulls in redact-core and nothing else of src/ai/ (no child_process, picomatch or limits.js)', async () => {
    const r = await build({ entryPoints: [join(import.meta.dirname, '..', 'gate/src/scrub.ts')], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent' });
    const files = Object.keys(r.metafile.inputs);
    expect(files.filter((f) => f.startsWith('src/ai/'))).toEqual(['src/ai/redact-core.ts']);
    expect(files).not.toContain('src/read/limits.ts');
    const externals = new Set(Object.values(r.metafile.inputs).flatMap((i) => i.imports.filter((x) => x.external).map((x) => x.path)));
    expect([...externals].filter((p) => ['node:child_process', 'child_process', 'picomatch', 'fast-glob', 'yaml'].includes(p))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------- m1
describe('m1: a secret-shaped path is withheld; the finding becomes unmapped', () => {
  it('betterleaks and gitleaks: a file name that holds a token shape: no uri is written, the finding is unmapped and says why; the fingerprint still covers the real path', () => {
    const ws = makeTempDir();
    const name = `src/${LEAK_B}.js`;
    write(ws, name, FIRST(LEAK_A));
    for (const tool of ['betterleaks', 'gitleaks'] as const) {
      const out = ok(run(leakSarif(tool, name), tool, { workspace: ws }));
      const text = out.bytes.toString();
      expect(text).not.toContain(LEAK_B);
      expect(text).not.toContain('"uri"');
      const doc = JSON.parse(text) as { runs: { results: { properties: Obj; locations?: unknown }[] }[] };
      expect(doc.runs[0].results[0].properties).toMatchObject({ pipegenUnmapped: true, pipegenPathWithheld: true });
      const back = readScrubbed(out.bytes, 'sarif').findings[0];
      expect(back.file).toBeUndefined();
      expect(back).toMatchObject({ uriUnmapped: true, pathWithheld: true, fpBy: 'region' });
      // fingerprints stay as computed over the real path and file
      expect(back.fingerprint).toBe(`${SEC}${hmac(KEY, Buffer.from(`${tool}\0${SEC}github-pat\0${LEAK_A}`))}`);
    }
  });

  it('without a key the withheld finding is a nokey fingerprint over the real path, with no mapped file: C2 reads it as new', () => {
    const ws = makeTempDir();
    const name = `src/${LEAK_B}.js`;
    write(ws, name, FIRST(LEAK_A));
    const out = ok(run(leakSarif('gitleaks', name), 'gitleaks', { workspace: ws, fpKey: '', eventText: FORK_PR }));
    const back = readScrubbed(out.bytes, 'sarif').findings[0];
    expect(back).toMatchObject({ uriUnmapped: true, pathWithheld: true, fpBy: 'nokey' });
    expect(back.file).toBeUndefined();
    expect(back.fingerprint).toBe(`${NOKEY}${sha(['gitleaks', `${SEC}github-pat`, name, '1'].join('\0'))}`);
  });

  it('an encoded secret in a path (base64, hex) and a high-entropy run are withheld too; an ordinary path is written', () => {
    for (const piece of [Buffer.from(LEAK_B).toString('base64'), Buffer.from(LEAK_B).toString('hex'), 'Zk3qP9xW2mT7vL5nR8cB4yH6']) {
      const ws = makeTempDir();
      write(ws, `cfg/${piece}.txt`, FIRST(LEAK_A));
      const back = readScrubbed(ok(run(leakSarif('betterleaks', `cfg/${piece}.txt`), 'betterleaks', { workspace: ws })).bytes, 'sarif').findings[0];
      expect(back, piece.slice(0, 8)).toMatchObject({ pathWithheld: true, uriUnmapped: true });
    }
    const ws = makeTempDir();
    write(ws, 'src/app.js', FIRST(LEAK_A));
    const back = readScrubbed(ok(run(leakSarif('betterleaks', 'src/app.js'), 'betterleaks', { workspace: ws })).bytes, 'sarif').findings[0];
    expect(back).toMatchObject({ file: 'src/app.js', pathWithheld: false, uriUnmapped: false });
  });

  it('a non-secrets tool: the same (a hadolint finding on a file named like a token)', () => {
    const raw = JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Hadolint' } }, results: [{ ruleId: 'DL3000', level: 'error', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri: `docker/${LEAK_B}/Dockerfile` }, region: { startLine: 4 } } }] }] }] });
    const out = ok(run(raw, 'hadolint'));
    expect(out.bytes.toString()).not.toContain(LEAK_B);
    expect(readScrubbed(out.bytes, 'sarif').findings[0]).toMatchObject({ uriUnmapped: true, pathWithheld: true });
  });

  it('zap: a url path that looks like a secret is withheld (no path, unmapped)', () => {
    const zap = (path: string) => JSON.stringify({ '@programName': 'ZAP', '@version': '2.16.0', site: [{ '@name': 'http://x', alerts: [{ pluginid: '10001', alert: 'A', name: 'A', riskcode: '2', instances: [{ uri: `http://x.example${path}`, method: 'GET' }] }] }] });
    const out = ok(scrubBytes(Buffer.from(zap(`/api/${LEAK_B}/x`)), { tool: 'zap-baseline', format: 'zap-json', fpKey: KEY, eventText: PUSH_EVENT }));
    expect(out.bytes.toString()).not.toContain(LEAK_B);
    const a = readScrubbed(out.bytes, 'zap-json').findings[0];
    expect(a.file).toBeUndefined();
    expect(a).toMatchObject({ uriUnmapped: true, pathWithheld: true });
    const plain = readScrubbed(ok(scrubBytes(Buffer.from(zap('/api/users')), { tool: 'zap-baseline', format: 'zap-json', fpKey: KEY, eventText: PUSH_EVENT })).bytes, 'zap-json').findings[0];
    expect(plain).toMatchObject({ file: '/api/users', pathWithheld: false });
  });

  it('a rule id that looks like a secret is masked (mutant: ruleId written as is)', () => {
    const ws = makeTempDir();
    write(ws, 'a.js', FIRST(LEAK_A));
    const out = ok(run(leakSarif('gitleaks', 'a.js', LEAK_B), 'gitleaks', { workspace: ws }));
    expect(out.bytes.toString()).not.toContain(LEAK_B);
    expect(out.bytes.toString()).toContain('[REDACTED]');
  });
});

// ---------------------------------------------------------------------------------------------------- m2, C1 belt
describe('m2: the surviving mutants, and the NUL belt of C1', () => {
  const leak = (over: Partial<ParsedFinding> = {}): ParsedFinding => ({ tool: 'betterleaks', ruleId: `${SEC}x`, severity: 'critical', file: 'a.txt', line: 1, startColumn: 1, endLine: 1, endColumn: 4, message: '', uriUnmapped: false, [SF]: true, ...over });

  it('M16: a region that runs past the end of its line is not read (the bytes of the next line are not a match)', () => {
    const ws = makeTempDir();
    write(ws, 'a.txt', 'abc\ndefghij\n');
    expect(readRegion(ws, leak({ endColumn: 3 }))).toMatchObject({ ok: true });
    expect(readRegion(ws, leak({ endColumn: 4 })).ok).toBe(false);    // line 1 is "abc": column 4 is the newline
    expect(readRegion(ws, leak({ endColumn: 8 })).ok).toBe(false);
    expect(readRegion(ws, leak({ line: 1, endLine: 2, startColumn: 2, endColumn: 4 }))).toMatchObject({ ok: true });
    expect(readRegion(ws, leak({ line: 1, endLine: 2, startColumn: 2, endColumn: 99 })).ok).toBe(false);
  });

  it('C1 belt: a region with a NUL byte is not used (the line form), single-line or not', () => {
    const ws = makeTempDir();
    write(ws, 'a.txt', 'ab\u0000cdef\nxy\n');
    const r = readRegion(ws, leak({ endColumn: 5 }));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/NUL/);
    expect(readRegion(ws, leak({ line: 1, endLine: 2, startColumn: 1, endColumn: 2 })).ok).toBe(false);
    expect(readRegion(ws, leak({ startColumn: 4, endColumn: 6 })).ok).toBe(true);   // a region after the NUL is fine
    expect(fingerprintFinding(leak({ endColumn: 5 }), { fpKey: KEY, workspace: ws }).by).toBe('line');
  });

  it('C1 (ident): the file as checked out (with an expanded keyword before the token) is the file the columns of a dir-mode scan describe', () => {
    const ws = makeTempDir();
    const expanded = `/* $Id: ${'0123456789abcdef'.repeat(2)}01234567 $ */ var x = "${LEAK_A}";\n`;
    write(ws, 'b.js', expanded);
    const start = expanded.indexOf(LEAK_A) + 1;
    const r = readRegion(ws, leak({ file: 'b.js', startColumn: start, endColumn: start + LEAK_A.length - 1 }));
    expect(r.ok && r.bytes.toString()).toBe(LEAK_A);
  });

  it('M9: a NUL inside a field cannot move a field border (two different findings never share a hash input)', () => {
    const a: ParsedFinding = { tool: 'hadolint', ruleId: 'R', severity: 'high', file: 'x\u0000y', line: 1, message: 'm', uriUnmapped: false, [SF]: false };
    const b: ParsedFinding = { ...a, file: 'x', message: 'y\u0000m' };
    expect(fingerprintFinding(a, {}).fingerprint).not.toBe(fingerprintFinding(b, {}).fingerprint);
    expect(fingerprintFinding(a, {}).fingerprint).toBe(sha(['hadolint', 'R', 'x�y', 'm'].join('\0')));
  });
});

// ---------------------------------------------------------------------------------------------------- m3
describe('m3: a file is read once per scrub, however many findings point into it', () => {
  it('2000 findings in one 8 MiB file: same fingerprints as the one-at-a-time read, and far less than the 25 s of the review', () => {
    const ws = makeTempDir();
    const line = `${'x'.repeat(30)}${LEAK_A}${'y'.repeat(20)}\n`;   // 87 bytes
    const lines = Math.floor((8 * 1024 * 1024) / line.length);
    write(ws, 'big.txt', line.repeat(lines));
    const findings: ParsedFinding[] = [];
    for (let i = 0; i < 2000; i++) {
      findings.push({ tool: 'betterleaks', ruleId: `${SEC}github-pat`, severity: 'critical', file: 'big.txt', line: lines - i * 7, startColumn: 31, endLine: lines - i * 7, endColumn: 30 + LEAK_A.length, message: '', uriUnmapped: false, [SF]: true });
    }
    const t0 = Date.now();
    const all = fingerprintAll(findings, { fpKey: KEY, workspace: ws });
    const ms = Date.now() - t0;
    expect(all.every((f) => f.fpBy === 'region')).toBe(true);
    expect(new Set(all.map((f) => f.fingerprint)).size).toBe(1);
    expect(all[0].fingerprint).toBe(fingerprintFinding(findings[0], { fpKey: KEY, workspace: ws }).fingerprint);
    expect(ms, `took ${ms} ms`).toBeLessThan(5000);
  });

  it('a file that cannot be read is answered from the cache with the same reason, and different files do not share an answer', () => {
    const ws = makeTempDir();
    write(ws, 'one.txt', 'abcdef\n');
    write(ws, 'two.txt', 'uvwxyz\n');
    const f = (file: string, over: Partial<ParsedFinding> = {}): ParsedFinding => ({ tool: 'betterleaks', ruleId: `${SEC}x`, severity: 'critical', file, line: 1, startColumn: 1, endLine: 1, endColumn: 3, message: '', uriUnmapped: false, [SF]: true, ...over });
    const out = fingerprintAll([f('one.txt'), f('two.txt'), f('nope.txt'), f('nope.txt', { line: 2, endLine: 2 }), f('one.txt', { startColumn: 2 })], { fpKey: KEY, workspace: ws });
    expect(out.map((x) => x.fpBy)).toEqual(['region', 'region', 'line', 'line', 'region']);
    expect(new Set(out.slice(0, 2).map((x) => x.fingerprint)).size).toBe(2);
    expect(out[2].fpNote).toBe(out[3].fpNote);
    expect(out[0].fingerprint).not.toBe(out[4].fingerprint);
  });
});

// ---------------------------------------------------------------------------------------------------- m4
describe('m4: the last check sees JSON-escaped text; the key must be plain; error texts are masked', () => {
  it('keyProblem refuses a key outside printable ASCII or holding a quote or a backslash, on any event', () => {
    const base = 'k'.repeat(40);
    for (const bad of [`${base}"`, `${base}\\`, `${base}\n`, `${base}\u0001`, `${base}é`, `${base}\u007f`, `${base}\t`]) {
      expect(keyProblem(bad, false, true), JSON.stringify(bad)).toMatch(/printable ASCII/);
      expect(keyProblem(bad, true, true), JSON.stringify(bad)).toMatch(/printable ASCII/);
    }
    expect(keyProblem(`${base} ~!#$%&'()*+,-./:;<=>?@[]^_\`{|}`, false, true)).toBeUndefined();
    const out = run(read('clean/gitleaks.sarif'), 'gitleaks', { fpKey: `${base}"` });
    expect(out).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/printable ASCII/) });
    expect(JSON.stringify(out)).not.toContain(base);
  });

  it('a multi-line region that reaches the output (JSON writes its newlines as \\n) is caught', () => {
    const ws = makeTempDir();
    const region = 'plain words one\nplain words two';
    write(ws, 'a.txt', `${region}\n`);
    const raw = JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks' } }, results: [{ ruleId: region, message: { text: 'x' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a.txt' }, region: { startLine: 1, startColumn: 1, endLine: 2, endColumn: 15 } } }] }] }] });
    const out = run(raw, 'gitleaks', { workspace: ws });
    expect(out).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/would hold the text of a secret region/) });
  });

  it('a region with a quote or a backslash in it is caught in its escaped form too', () => {
    const ws = makeTempDir();
    const region = 'say "hi" \\ there, friend';
    write(ws, 'a.txt', `${region}\n`);
    const raw = JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks' } }, results: [{ ruleId: region, message: { text: 'x' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a.txt' }, region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: region.length } } }] }] }] });
    expect(run(raw, 'gitleaks', { workspace: ws })).toMatchObject({ status: 'tool-error' });
  });

  it('an error text that echoes a tool string (the driver name) has secret shapes masked', () => {
    const raw = JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: LEAK_B } }, results: [] }] });
    for (const tool of ['betterleaks', 'semgrep']) {
      const out = run(raw, tool);
      expect(out.status).toBe('tool-error');
      expect(JSON.stringify(out)).not.toContain(LEAK_B);
    }
    // and the tool id itself
    const bad = run(read('gitleaks.sarif'), LEAK_B);
    expect(bad.status).toBe('tool-error');
    expect(JSON.stringify(bad)).not.toContain(LEAK_B);
  });
});
