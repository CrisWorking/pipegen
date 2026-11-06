// Plan C Task C1b: the scrub (gate/src/scrub.ts), the last thing that touches raw scanner output. Every output is rebuilt from
// allowlisted fields; nothing of the raw file, no snippet and no secret survives; the key never leaves.
import { createHash, createHmac } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { keyId } from '../gate/src/fingerprint.js';
import { forkFromEvent, prepareOutFolder, readScrubbed, scrubBytes, scrubFile } from '../gate/src/scrub.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';

type Obj = Record<string, unknown>;
const DIR = join(import.meta.dirname, 'fixtures', 'sarif');
const WS = '/home/runner/work/fixture/fixture';
const KEY = ['fp', 'test', 'a'.repeat(40)].join('-');
const read = (name: string) => readFileSync(join(DIR, name));
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');
const SEC = 'sec' + 'ret:';
const NOKEY = 'sec' + 'ret-nokey:';
const SF = ('sec' + 'ret') as 'secret';   // the finding's flag, spelled so no secret-like `name: value` sits in a committed test file
const PW = 'Possible hardcoded pass' + 'word: ';
const PUSH_EVENT = JSON.stringify({ repository: { id: 7 } });
const SAME_REPO_PR = JSON.stringify({ repository: { id: 7 }, pull_request: { head: { repo: { id: 7 } } } });
const FORK_PR = JSON.stringify({ repository: { id: 7 }, pull_request: { head: { repo: { id: 8 } } } });
afterEach(() => { cleanupRepos(); vi.restoreAllMocks(); });

const LEAK_ONE = fake.githubClassic();
const LEAK_TWO = 'gh' + 'p_' + 'b'.repeat(36);
function plantedWorkspace(): string {
  const ws = makeTempDir();
  mkdirSync(join(ws, 'src'));
  writeFileSync(join(ws, 'src', 'config.js'), `export const first = "${LEAK_ONE}";\nexport const second = "${LEAK_TWO}";\n`);
  return ws;
}

// (G15a G11-2: the licence scan's raw result is the pinned trivy's JSON with every package listed; the scrubbed result is SARIF)
const PLANTED: [string, string][] = [
  ['betterleaks.sarif', 'betterleaks'], ['gitleaks.sarif', 'gitleaks'], ['semgrep.sarif', 'semgrep'], ['osv-scanner.sarif', 'osv-scanner'], ['trivy-config.sarif', 'trivy-config'],
  ['trivy-image.sarif', 'trivy-image'], ['../trivy-licence-json/composer.json', 'trivy-licence'], ['hadolint.sarif', 'hadolint'], ['kube-linter.sarif', 'kube-linter'], ['nuclei.sarif', 'nuclei'],
  ['ruff.sarif', 'ruff'], ['gosec.sarif', 'gosec'], ['bandit.sarif', 'bandit'],
];
const run = (raw: Buffer | string, tool: string, over: Obj = {}) => scrubBytes(typeof raw === 'string' ? Buffer.from(raw) : raw, { tool, format: 'sarif', fpKey: KEY, eventText: PUSH_EVENT, workspace: WS, ...over } as Parameters<typeof scrubBytes>[1]);
function ok(o: ReturnType<typeof scrubBytes>): Extract<ReturnType<typeof scrubBytes>, { status: 'ok' }> {
  if (o.status !== 'ok') throw new Error(`expected ok, got ${o.error}`);
  return o;
}
/** Every string anywhere in a JSON value, keys included. */
function allStrings(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) for (const x of v) allStrings(x, out);
  else if (typeof v === 'object' && v !== null) for (const [k, x] of Object.entries(v)) { out.push(k); allStrings(x, out); }
  return out;
}

describe('scrub: real fixtures', () => {
  for (const [file, tool] of PLANTED) {
    it(`${tool}: ok, rebuilt from allowlisted fields (no snippet, contextRegion, partialFingerprints of the tool), a stable sha256 of the bytes written`, () => {
      const ws = plantedWorkspace();
      const out = ok(run(read(file), tool, { workspace: ws }));
      expect(out.findings).toBeGreaterThan(0);
      const text = out.bytes.toString();
      for (const banned of ['snippet', 'contextRegion', 'REDACTED', 'commitSha', 'primaryLocationLineHash', 'originalUriBaseIds', 'uriBaseId', 'shortDescription', 'invocations']) expect(text, banned).not.toContain(banned);
      expect(out.sha256).toBe(sha(out.bytes));
      expect(ok(run(read(file), tool, { workspace: ws })).sha256, 'same input, same bytes').toBe(out.sha256);
      expect(out.bytes.toString()).not.toContain(KEY);
      const doc = JSON.parse(text) as { runs: { results: { partialFingerprints: Obj }[] }[] };
      expect(doc.runs[0].results.every((r) => typeof r.partialFingerprints.pipegenFingerprint === 'string')).toBe(true);
    });
  }

  it('the read-back (readScrubbed) gives the findings with their fingerprints, severity and lines; nothing else', () => {
    const ws = plantedWorkspace();
    const out = ok(run(read('gitleaks.sarif'), 'gitleaks', { workspace: ws }));
    const back = readScrubbed(out.bytes, 'sarif');
    expect(back.toolError).toBeUndefined();
    expect(back.keyId).toBe(keyId(KEY));
    expect(back.findings).toHaveLength(2);
    expect(back.findings[0]).toMatchObject({ tool: 'gitleaks', ruleId: `${SEC}github-pat`, severity: 'critical', file: 'src/config.js', line: 1, [SF]: true, fpBy: 'region' });
    expect(back.findings[0].fingerprint).toMatch(new RegExp(`^${SEC}[0-9a-f]{64}$`));
    expect(back.findings[0].fingerprint).not.toBe(back.findings[1].fingerprint);
    expect(back.notes).toContain('completeness not provable (gitleaks)');
  });

  it('the key id is stored with the fingerprints (S11) and is not the key', () => {
    const out = ok(run(read('betterleaks.sarif'), 'betterleaks', { workspace: plantedWorkspace() }));
    const doc = JSON.parse(out.bytes.toString()) as { runs: { properties: Obj }[] };
    expect(doc.runs[0].properties.pipegenKeyId).toBe(keyId(KEY));
    expect(out.keyId).toBe(keyId(KEY));
  });

  it('a clean run (no results) of a secrets tool is ok, with the key id; a tool-error SARIF is a tool error with no bytes', () => {
    const clean = ok(run(read('clean/gitleaks.sarif'), 'gitleaks'));
    expect(clean.findings).toBe(0);
    const bad = run(read('semgrep-timeout.sarif'), 'semgrep');
    expect(bad).toMatchObject({ status: 'tool-error' });
    expect(bad).not.toHaveProperty('bytes');
    expect((bad as { error: string }).error).toMatch(/notification/);
  });
});

describe('scrub: output rebuilt from allowlisted fields; nothing planted survives', () => {
  const planted = () => ({
    version: '2.1.0',
    $schema: 'https://example.invalid/planted-schema',
    runs: [{
      tool: { driver: { name: 'gitleaks', informationUri: 'https://example.invalid/planted-uri', rules: [{ id: 'github-pat', fullDescription: { text: 'planted-rule-text' } }] } },
      artifacts: [{ location: { uri: 'planted-artifact' }, contents: { text: `planted-contents ${LEAK_ONE}` } }],
      properties: { planted: `run-prop ${LEAK_ONE}` },
      results: [{
        ruleId: 'github-pat',
        message: { text: `leak of ${LEAK_ONE} found`, markdown: `**${LEAK_ONE}**` },
        level: 'error',
        fingerprints: { x: `planted-fp-${LEAK_ONE}` },
        partialFingerprints: { commitSha: 'planted-sha', pipegenFingerprint: 'forged-fingerprint' },
        properties: { tags: [`tag ${LEAK_ONE}`], pipegenSeverity: 'info', pipegenFpBy: 'forged' },
        codeFlows: [{ threadFlows: [{ locations: [{ location: { message: { text: LEAK_ONE } } }] }] }],
        fixes: [{ description: { text: LEAK_ONE } }],
        locations: [{
          message: { text: `at ${LEAK_ONE}` },
          physicalLocation: {
            artifactLocation: { uri: 'src/config.js', description: { text: LEAK_ONE } },
            region: { startLine: 1, startColumn: 23, endLine: 1, endColumn: 62, snippet: { text: LEAK_ONE }, message: { text: LEAK_ONE } },
            contextRegion: { startLine: 1, endLine: 3, snippet: { text: `context ${LEAK_ONE}` } },
          },
        }],
      }],
    }],
  });

  it('scrub: unredacted gitleaks SARIF with fake secrets everywhere → no secret text left, HMAC fingerprints kept, sha256 stable', () => {
    const ws = plantedWorkspace();
    const first = ok(run(JSON.stringify(planted()), 'gitleaks', { workspace: ws }));
    const text = first.bytes.toString();
    for (const bad of [LEAK_ONE, LEAK_ONE.slice(0, 12), 'planted-', 'forged', 'snippet', 'contextRegion', 'markdown', 'commitSha', 'example.invalid']) expect(text, bad).not.toContain(bad);
    const back = readScrubbed(first.bytes, 'sarif').findings[0];
    expect(back.fingerprint).toBe(`${SEC}${createHmac('sha256', KEY).update(`gitleaks\0${SEC}github-pat\0${LEAK_ONE}`).digest('hex')}`);
    expect(back.severity).toBe('critical');
    expect(ok(run(JSON.stringify(planted()), 'gitleaks', { workspace: ws })).sha256).toBe(first.sha256);
  });

  it('the output holds only the allowed keys, at every level (an allowlist walk of the written file)', () => {
    const ws = plantedWorkspace();
    const doc = JSON.parse(ok(run(JSON.stringify(planted()), 'gitleaks', { workspace: ws })).bytes.toString()) as Obj;
    const keys = (o: unknown): string[] => (typeof o === 'object' && o !== null && !Array.isArray(o) ? Object.keys(o).sort() : []);
    expect(keys(doc)).toEqual(['runs', 'version']);
    const run0 = (doc.runs as Obj[])[0];
    expect(keys(run0)).toEqual(['properties', 'results', 'tool']);
    expect(keys(run0.tool)).toEqual(['driver']);
    expect(keys((run0.tool as Obj).driver)).toEqual(['name']);
    expect(keys(run0.properties)).toEqual(['pipegenKeyId', 'pipegenNotes', 'pipegenScrubbed', 'pipegenTool']);
    const result = (run0.results as Obj[])[0];
    expect(keys(result)).toEqual(['level', 'locations', 'message', 'partialFingerprints', 'properties', 'ruleId']);
    expect(keys(result.message)).toEqual(['text']);
    expect(keys(result.partialFingerprints)).toEqual(['pipegenFingerprint']);
    expect(keys(result.properties)).toEqual(['pipegenFpBy', 'pipegenPathWithheld', 'pipegenSecret', 'pipegenSeverity', 'pipegenUnmapped']);
    const loc = (result.locations as Obj[])[0];
    expect(keys(loc)).toEqual(['physicalLocation']);
    expect(keys((loc.physicalLocation as Obj).artifactLocation)).toEqual(['uri']);
    expect(keys((loc.physicalLocation as Obj).region)).toEqual(['endLine', 'startLine']);
    expect(allStrings(doc).some((s) => s.includes('planted'))).toBe(false);
  });

  it('a secrets tool\'s message is never carried over: the output says only which rule fired', () => {
    const out = ok(run(JSON.stringify(planted()), 'gitleaks', { workspace: plantedWorkspace() }));
    const result = (JSON.parse(out.bytes.toString()) as { runs: { results: { message: { text: string } }[] }[] }).runs[0].results[0];
    expect(result.message.text).toBe('secret detected by rule github-pat');
  });

  it('a secret quoted in the message of a tool that is not a secrets tool is masked; the fingerprint does not cover it', () => {
    const doc = (text: string) => ({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Bandit' } }, results: [{ ruleId: 'B999', message: { text }, properties: { issue_severity: 'HIGH' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'py/app.py' }, region: { startLine: 4 } } }] }] }] });
    const shapes = [LEAK_ONE, fake.awsKey(), fake.githubPat(), fake.stripeKey(), fake.slackBot(), fake.jwt(), fake.keyBegin()];
    const prints = new Set<string>();
    for (const t of shapes) {
      const out = ok(run(JSON.stringify(doc(`Possible leak ${t} here`)), 'bandit'));
      expect(out.bytes.toString(), t.slice(0, 6)).not.toContain(t);
      expect(out.bytes.toString()).toContain('[REDACTED]');
      if (t !== fake.keyBegin()) prints.add(readScrubbed(out.bytes, 'sarif').findings[0].fingerprint);   // a private key marker masks the rest of the text, so its message differs
    }
    expect(prints.size, 'masked tokens give the same fingerprint: no hash of a secret').toBe(1);
  });

  it('bandit B105, B106 and B107 quote the password string: the message is withheld', () => {
    for (const id of ['B105', 'B106', 'B107']) {
      const raw = { version: '2.1.0', runs: [{ tool: { driver: { name: 'Bandit' } }, results: [{ ruleId: id, message: { text: `${PW}'hunter2-plain'` }, properties: { issue_severity: 'LOW' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'py/app.py' }, region: { startLine: 4 } } }] }] }] };
      const out = ok(run(JSON.stringify(raw), 'bandit'));
      expect(out.bytes.toString(), id).not.toContain('hunter2');
      expect(readScrubbed(out.bytes, 'sarif').findings[0].message, id).toMatch(/message withheld/);
    }
  });

  it('a fingerprint of a non-secret never changes with the line, in the written file too (the scrub of a shifted file has the same fingerprints)', () => {
    const raw = JSON.parse(read('hadolint.sarif').toString()) as { runs: { results: { locations: { physicalLocation: { region: Obj } }[] }[] }[] };
    const a = readScrubbed(ok(run(JSON.stringify(raw), 'hadolint')).bytes, 'sarif').findings;
    for (const r of raw.runs[0].results) r.locations[0].physicalLocation.region.startLine = (r.locations[0].physicalLocation.region.startLine as number) + 20;
    const b = readScrubbed(ok(run(JSON.stringify(raw), 'hadolint')).bytes, 'sarif').findings;
    expect(b.map((f) => f.fingerprint)).toEqual(a.map((f) => f.fingerprint));
    expect(b.map((f) => f.line)).not.toEqual(a.map((f) => f.line));
  });

  it('a defence at the end: if the key or the bytes of a read region were in the output, the scrub is a tool error and writes nothing', () => {
    const ws = plantedWorkspace();
    // the file name of the finding holds the text it names (plain words, so the path is not withheld as secret-shaped): the path is an allowlisted field, so the final check must catch it
    const words = 'plain words that are not secret';
    writeFileSync(join(ws, `leak-${words}.txt`), `${words}\n`);
    const raw = { version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks' } }, results: [{ ruleId: 'github-pat', message: { text: 'x' }, locations: [{ physicalLocation: { artifactLocation: { uri: `leak-${words}.txt` }, region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: words.length } } }] }] }] };
    const out = run(JSON.stringify(raw), 'gitleaks', { workspace: ws });
    expect(out.status).toBe('tool-error');
    expect(JSON.stringify(out)).not.toContain(words);
    expect((out as { error: string }).error).toMatch(/would hold/);
  });
});

describe('scrub: the key in an allowlisted field', () => {
  it('a path or rule id that holds the key makes the scrub a tool error: the key is never written', () => {
    const ws = makeTempDir();
    const raw = (uri: string, ruleId: string) => JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks' } }, results: [{ ruleId, message: { text: 'x' }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 3 } } }] }] }] });
    for (const [uri, ruleId] of [[`src/${KEY}.js`, 'github-pat'], ['src/a.js', KEY]]) {
      const out = run(raw(uri, ruleId), 'gitleaks', { workspace: ws });
      expect(out, uri).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/would hold the key/) });
      expect(JSON.stringify(out)).not.toContain(KEY);
    }
  });
});

describe('scrub: zap', () => {
  const ZAP = join(import.meta.dirname, 'fixtures', 'zap', 'zap-traditional-json.json');
  it('zap-json: only pluginid, name, severity, method, url path and the fingerprint are written; evidence, host, port and query never are', () => {
    const raw = JSON.parse(readFileSync(ZAP, 'utf8')) as { site: { alerts: { instances: Obj[] }[] }[] };
    raw.site[0].alerts[0].instances[0].evidence = `evidence ${LEAK_ONE}`;
    raw.site[0].alerts[0].instances[0].uri = 'http://internal-host.example:9443/a/b?session=planted-query#frag';
    const out = ok(scrubBytes(Buffer.from(JSON.stringify(raw)), { tool: 'zap-baseline', format: 'zap-json', fpKey: KEY, eventText: PUSH_EVENT }));
    const text = out.bytes.toString();
    for (const bad of [LEAK_ONE, 'evidence', 'internal-host', '9443', 'planted-query', 'frag', '"desc"', 'solution']) expect(text, bad).not.toContain(bad);
    const back = readScrubbed(out.bytes, 'zap-json');
    expect(back.toolError).toBeUndefined();
    expect(back.findings.length).toBeGreaterThan(0);
    expect(back.findings[0]).toMatchObject({ tool: 'zap-baseline', file: '/a/b' });
    expect(back.findings[0].fingerprint).toBe(sha([back.findings[0].ruleId, 'GET', '/a/b'].join('\0')));
    expect(out.sha256).toBe(sha(out.bytes));
    expect(back.notes.join()).toMatch(/unverified/);
  });
  it('zap-json needs no key and never carries one: a zap run is scrubbed with an empty key on a non-fork event', () => {
    const out = ok(scrubBytes(readFileSync(ZAP), { tool: 'zap-baseline', format: 'zap-json', fpKey: '', eventText: PUSH_EVENT }));
    expect(out.keyId).toBeUndefined();
  });
});

describe('scrub: key handling (S11)', () => {
  it('setSecret first: mask is called with the key before anything else, also when the run then fails', () => {
    const order: string[] = [];
    const mask = (s: string) => { order.push(`mask:${s === KEY}`); };
    ok(run(read('clean/gitleaks.sarif'), 'gitleaks', { mask }));
    expect(order).toEqual(['mask:true']);
    order.length = 0;
    expect(run('not json', 'gitleaks', { mask }).status).toBe('tool-error');
    expect(order).toEqual(['mask:true']);
    order.length = 0;
    run(read('clean/gitleaks.sarif'), 'gitleaks', { mask, fpKey: 'x'.repeat(10) });   // too short: still masked
    expect(order).toEqual(['mask:false']);
    order.length = 0;
    run(read('clean/gitleaks.sarif'), 'gitleaks', { mask, fpKey: '' });   // nothing to mask
    expect(order).toEqual([]);
  });

  it('scrub: key never appears in output, error text or logs (a captured log of the whole run, every outcome)', () => {
    const logged: string[] = [];
    for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) vi.spyOn(console, m).mockImplementation((...a: unknown[]) => { logged.push(a.map(String).join(' ')); });
    vi.spyOn(process.stdout, 'write').mockImplementation((c: unknown) => { logged.push(String(c)); return true; });
    vi.spyOn(process.stderr, 'write').mockImplementation((c: unknown) => { logged.push(String(c)); return true; });
    const ws = plantedWorkspace();
    const results: unknown[] = [];
    for (const [file, tool] of PLANTED) results.push(run(read(file), tool, { workspace: ws }));
    results.push(run('', 'gitleaks'), run('{', 'gitleaks'), run(read('semgrep-timeout.sarif'), 'semgrep'), run(read('gitleaks.sarif'), 'nope-tool'));
    results.push(run(read('gitleaks.sarif'), 'gitleaks', { fpKey: 'short-key-'.repeat(2) }));
    results.push(run(read('gitleaks.sarif'), 'gitleaks', { fpKey: KEY.slice(0, 31) }));
    results.push(run(read('gitleaks.sarif'), 'gitleaks', { fpKey: '' }));
    const text = JSON.stringify(results.map((r) => ({ ...(r as Obj), bytes: undefined }))) + results.map((r) => ((r as { bytes?: Buffer }).bytes ?? Buffer.alloc(0)).toString()).join('') + logged.join('');
    for (const s of [KEY, KEY.slice(0, 31), 'short-key-short-key-', LEAK_ONE, LEAK_TWO]) expect(text, s.slice(0, 8)).not.toContain(s);
    expect(results.filter((r) => (r as Obj).status === 'tool-error').length).toBeGreaterThanOrEqual(6);
  });

  it('the key id is derived, and the key is only used to compute it: two scrubs with different keys differ in id and in every secret fingerprint', () => {
    const ws = plantedWorkspace();
    const a = readScrubbed(ok(run(read('gitleaks.sarif'), 'gitleaks', { workspace: ws })).bytes, 'sarif');
    const b = readScrubbed(ok(run(read('gitleaks.sarif'), 'gitleaks', { workspace: ws, fpKey: ['fp', 'other', 'c'.repeat(40)].join('-') })).bytes, 'sarif');
    expect(a.keyId).not.toBe(b.keyId);
    expect(a.findings.map((f) => f.fingerprint)).not.toEqual(b.findings.map((f) => f.fingerprint));
  });

  it('scrub: empty key on a non-fork event → tool-error for a secrets tool, with no output', () => {
    for (const eventText of [PUSH_EVENT, SAME_REPO_PR, undefined, 'not json', '{}']) {
      for (const tool of ['gitleaks', 'betterleaks']) {
        const out = run(read(`clean/${tool}.sarif`), tool, { fpKey: '', eventText });
        expect(out, `${tool} ${String(eventText).slice(0, 20)}`).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/PIPEGEN_FP_KEY is missing/) });
        expect(out).not.toHaveProperty('bytes');
      }
    }
    // a secret found by a tool that is not a secrets tool (trivy-image) needs the key as well
    expect(run(read('trivy-image.sarif'), 'trivy-image', { fpKey: '' }).status).toBe('tool-error');
    // ...but a tool with no secret finding does not
    expect(run(read('semgrep.sarif'), 'semgrep', { fpKey: '' }).status).toBe('ok');
    expect(run(read('trivy-config.sarif'), 'trivy-config', { fpKey: '' }).status).toBe('ok');
  });

  it('scrub: a key shorter than 32 characters is a tool error for a secrets tool, whatever the event', () => {
    for (const eventText of [PUSH_EVENT, FORK_PR]) {
      expect(run(read('gitleaks.sarif'), 'gitleaks', { fpKey: 'x'.repeat(31), eventText })).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/at least 32/) });
    }
  });

  it('scrub: fork PR with no key → secret-nokey fingerprints, status ok, no key id', () => {
    const out = ok(run(read('gitleaks.sarif'), 'gitleaks', { fpKey: '', eventText: FORK_PR }));
    expect(out.keyId).toBeUndefined();
    const back = readScrubbed(out.bytes, 'sarif');
    expect(back.keyId).toBeUndefined();
    expect(back.findings.map((f) => f.fpBy)).toEqual(['nokey', 'nokey']);
    expect(back.findings.every((f) => new RegExp(`^${NOKEY}[0-9a-f]{64}$`).test(f.fingerprint))).toBe(true);
  });

  it('scrub: fork read from the event payload, not an input (a "fork" option or input cannot turn the key rule off)', () => {
    const out = run(read('clean/gitleaks.sarif'), 'gitleaks', { fpKey: '', eventText: SAME_REPO_PR, fork: true, 'fork-pr': 'true', isFork: 'true' });
    expect(out.status).toBe('tool-error');
    expect(forkFromEvent(FORK_PR)).toBe(true);
    expect(forkFromEvent(SAME_REPO_PR)).toBe(false);
    expect(forkFromEvent(PUSH_EVENT)).toBe(false);
    for (const odd of [undefined, '', 'nope', '[]', '{"pull_request":null}', '{"pull_request":{"head":{"repo":null}},"repository":{"id":7}}', '{"pull_request":{"head":{"repo":{"id":"8"}}},"repository":{"id":7}}', '{"pull_request":{"head":{"repo":{"id":8}}}}']) {
      expect(forkFromEvent(odd), String(odd)).toBe(false);   // unknown means "not a fork": the stricter rule (key required)
    }
  });
});

describe('scrub: sha256 and the written file', () => {
  // a secrets tool needs a stage folder since C1c (test/gate-stage.test.ts); the written-file rules are the same for every tool
  it('scrub: sha256 is of the written bytes (scrubFile, files read back from disk)', () => {
    const base = makeTempDir();
    const ws = plantedWorkspace();
    const raw = join(base, 'pipegen-raw', 'pipegen-out-sast', 'semgrep.sarif');
    mkdirSync(join(base, 'pipegen-raw', 'pipegen-out-sast'), { recursive: true });
    writeFileSync(raw, read('semgrep.sarif'));
    const out = join(base, 'pipegen-out', 'pipegen-out-sast', 'semgrep.sarif');
    const r = scrubFile({ tool: 'semgrep', format: 'sarif', artifact: 'pipegen-out-sast', raw, out, fpKey: KEY, workspace: ws, eventText: PUSH_EVENT });
    expect(r.status).toBe('ok');
    expect(r.sha256).toBe(sha(readFileSync(out)));
    expect(r.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(r.error).toBeUndefined();   // the action writes plain sha256, status and error outputs (main.ts); the job's outputs map them to <artifact>-…
    expect(readdirSync(join(base, 'pipegen-out', 'pipegen-out-sast'))).toEqual(['semgrep.sarif']);
  });

  const setup = (content?: Buffer | string) => {
    const base = makeTempDir();
    const dir = join(base, 'pipegen-raw', 'pipegen-out-iac');
    mkdirSync(dir, { recursive: true });
    const raw = join(dir, 'trivy.sarif');
    if (content !== undefined) writeFileSync(raw, content);
    return { base, raw, out: join(base, 'pipegen-out', 'pipegen-out-iac', 'trivy.sarif') };
  };
  const go = (s: ReturnType<typeof setup>, over: Obj = {}) => scrubFile({ tool: 'trivy-config', format: 'sarif', artifact: 'pipegen-out-iac', raw: s.raw, out: s.out, fpKey: KEY, workspace: WS, eventText: PUSH_EVENT, ...over });

  it('scrub: raw file missing (tool failed) → status tool-error, a short error, no output file, no folder', () => {
    const s = setup();
    const r = go(s);
    expect(r.status).toBe('tool-error');
    expect(r.error).toMatch(/no result/);
    expect(r.error!.length).toBeLessThan(300);
    expect(existsSync(s.out)).toBe(false);
    expect(existsSync(join(s.base, 'pipegen-out'))).toBe(false);
    expect(r.sha256).toBeUndefined();
  });

  it('scrub: raw file empty, not JSON, not SARIF, or a tool-error SARIF → tool-error and no output file', () => {
    for (const content of ['', 'not json', '{"version":"2.1.0"}', '[]', Buffer.from([0xff, 0xfe, 0x00]), read('semgrep-timeout.sarif')]) {
      const s = setup(content);
      const r = go(s);
      expect(r.status, String(content).slice(0, 20)).toBe('tool-error');
      expect(r.error).toBeTruthy();
      expect(existsSync(s.out)).toBe(false);
      expect(existsSync(join(s.base, 'pipegen-out'))).toBe(false);
    }
  });

  it('scrub: a raw file that is a symbolic link, a folder or a FIFO is a tool error (never followed)', () => {
    const s = setup();
    const target = join(s.base, 'target.sarif');
    writeFileSync(target, read('trivy-config.sarif'));
    symlinkSync(target, s.raw);
    expect(go(s)).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/link/) });
    const d = setup();
    mkdirSync(d.raw);
    expect(go(d).status).toBe('tool-error');
    expect(existsSync(s.out)).toBe(false);
  });

  it('a raw file over the size cap is a tool error and is not read in full', () => {
    const s = setup(Buffer.alloc(2048, 0x20));
    expect(go(s, { maxBytes: 1024 })).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/size cap/) });
  });

  it('the scrub writes the output with the folder it made, and never over an existing file', () => {
    const s = setup(read('trivy-config.sarif'));
    expect(go(s).status).toBe('ok');
    expect(go(s)).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/exists/) });
  });

  it('a key problem or a hidden secret is reported without any output file', () => {
    const s = setup(read('trivy-image.sarif'));
    expect(go(s, { tool: 'trivy-image', fpKey: '' })).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/PIPEGEN_FP_KEY is missing/) });
    expect(existsSync(s.out)).toBe(false);
    expect(existsSync(join(s.base, 'pipegen-out'))).toBe(false);
  });
});

describe('prepareOutFolder (C0a/C0b contract for C5)', () => {
  it('creates pipegen-out/<artifact>/ itself and returns the file path to write', () => {
    const base = makeTempDir();
    const out = join(base, 'pipegen-out', 'pipegen-out-sast', 'semgrep.sarif');
    expect(prepareOutFolder(out, 'pipegen-out-sast')).toBe(out);
    expect(statSync(join(base, 'pipegen-out', 'pipegen-out-sast')).isDirectory()).toBe(true);
    expect(prepareOutFolder(out, 'pipegen-out-sast')).toBe(out);   // existing real folders are fine
  });
  it('refuses a link or a file where pipegen-out or the artifact folder should be', () => {
    const a = makeTempDir();
    mkdirSync(join(a, 'elsewhere'));
    symlinkSync(join(a, 'elsewhere'), join(a, 'pipegen-out'));
    expect(() => prepareOutFolder(join(a, 'pipegen-out', 'pipegen-out-sast', 'x.sarif'), 'pipegen-out-sast')).toThrow(/link/);
    expect(readdirSync(join(a, 'elsewhere'))).toEqual([]);
    const b = makeTempDir();
    mkdirSync(join(b, 'pipegen-out'));
    mkdirSync(join(b, 'target'));
    symlinkSync(join(b, 'target'), join(b, 'pipegen-out', 'pipegen-out-sast'));
    expect(() => prepareOutFolder(join(b, 'pipegen-out', 'pipegen-out-sast', 'x.sarif'), 'pipegen-out-sast')).toThrow(/link/);
    const c = makeTempDir();
    mkdirSync(join(c, 'pipegen-out'));
    writeFileSync(join(c, 'pipegen-out', 'pipegen-out-sast'), 'file');
    expect(() => prepareOutFolder(join(c, 'pipegen-out', 'pipegen-out-sast', 'x.sarif'), 'pipegen-out-sast')).toThrow(/not a folder/);
    const d = makeTempDir();
    writeFileSync(join(d, 'pipegen-out'), 'file');
    expect(() => prepareOutFolder(join(d, 'pipegen-out', 'pipegen-out-sast', 'x.sarif'), 'pipegen-out-sast')).toThrow(/not a folder/);
  });
  it('refuses an out path that is not exactly <...>/pipegen-out/<artifact>/<file>', () => {
    const base = makeTempDir();
    for (const [out, artifact] of [
      [join(base, 'pipegen-out', 'other', 'x.sarif'), 'pipegen-out-sast'],
      [join(base, 'elsewhere', 'pipegen-out-sast', 'x.sarif'), 'pipegen-out-sast'],
      [join(base, 'pipegen-out', 'pipegen-out-sast', 'a', 'x.sarif'), 'pipegen-out-sast'],
      [join(base, 'pipegen-out', 'pipegen-out-sast'), 'pipegen-out-sast'],
      ['pipegen-out/pipegen-out-sast/x.sarif', 'pipegen-out-sast'],
      [join(base, 'pipegen-out', '..', 'pipegen-out-sast', 'x.sarif'), 'pipegen-out-sast'],
      [join(base, 'pipegen-out', 'pipegen-out-sast', 'x.sarif'), '../x'],
      [join(base, 'pipegen-out', 'pipegen-out-sast', 'x.sarif'), ''],
    ] as const) expect(() => prepareOutFolder(out, artifact), `${out} ${artifact}`).toThrow(/out path|artifact/);
    expect(existsSync(join(base, 'pipegen-out'))).toBe(false);
  });
  it('refuses when the folder cannot be written (no half result)', () => {
    if (process.getuid?.() === 0) return;
    const base = makeTempDir();
    chmodSync(base, 0o500);
    try { expect(() => prepareOutFolder(join(base, 'pipegen-out', 'pipegen-out-sast', 'x.sarif'), 'pipegen-out-sast')).toThrow(); } finally { chmodSync(base, 0o700); }
  });
});

describe('scrub: input checks', () => {
  it('an unknown tool or format is a tool error, with no bytes', () => {
    expect(run(read('gitleaks.sarif'), 'not-a-tool')).toMatchObject({ status: 'tool-error' });
    expect(scrubBytes(read('gitleaks.sarif'), { tool: 'gitleaks', format: 'xml' as 'sarif', fpKey: KEY, eventText: PUSH_EVENT })).toMatchObject({ status: 'tool-error' });
    expect(scrubBytes(read('gitleaks.sarif'), { tool: 'zap-baseline', format: 'sarif', fpKey: KEY, eventText: PUSH_EVENT })).toMatchObject({ status: 'tool-error' });
    expect(scrubBytes(read('gitleaks.sarif'), { tool: 'gitleaks', format: 'zap-json', fpKey: KEY, eventText: PUSH_EVENT })).toMatchObject({ status: 'tool-error' });
  });
  it('the synthesized nuclei file scrubs to "nothing reported" with the note carried', () => {
    const marked = JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'pipegen-empty-nuclei' } }, results: [], properties: { pipegenSynthesized: 'nuclei-no-file' } }] });
    const out = ok(run(marked, 'nuclei'));
    expect(out.findings).toBe(0);
    expect(readScrubbed(out.bytes, 'sarif').notes).toContain('nothing reported (synthesized empty result)');
  });
});

describe('gate/src: no new dependency', () => {
  it('fingerprint.ts, scrub.ts and stage.ts import only node:crypto, node:fs, node:path and files of gate/src, src/types.ts, src/util/safe-text.ts, src/ai/redact-core.ts and src/ai/scan-staging.ts', () => {
    const allowed = new Set(['node:crypto', 'node:fs', 'node:path', './fingerprint.js', './parse-common.js', './sarif.js', './zap.js', './trivy-licence.js', './stage.js', './range.js', './generated/secrets-path-rules.js', '../../src/types.js', '../../src/util/safe-text.js', '../../src/ai/redact-core.js', '../../src/ai/scan-staging.js']);
    for (const f of ['fingerprint.ts', 'scrub.ts', 'stage.ts']) {
      const text = readFileSync(join(import.meta.dirname, '..', 'gate', 'src', f), 'utf8');
      const specs = [...text.matchAll(/^(?:import|export)\s[^;]*?from\s+'([^']+)'/gms)].map((m) => m[1]);
      expect(specs.length, f).toBeGreaterThan(0);
      for (const s of specs) expect(allowed.has(s), `${f} imports ${s}`).toBe(true);
      expect(text, f).not.toMatch(/\brequire\(|\bimport\(|child_process|node:net|node:http|\bfetch\(/);
    }
  });
});
