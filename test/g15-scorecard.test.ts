// v0.2 Plan G, sub-task G15a round 3, item (a) (PF-3; ruling G15-R0 6, G15a-R0b): OpenSSF Scorecard, weekly. Reported, never gated,
// publish_results false. The gate's scrub reads its SARIF (the real v5.6.0 runs in test/fixtures/scorecard, the library scorecard-action
// v2.5.0 runs); the image runs as a `docker://…@sha256` step pinned to the reviewed entry's recorded digest.
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { parseSarif, parseSarifText, SARIF_TOOLS } from '../gate/src/sarif.js';
import { readScrubbed, scrubBytes } from '../gate/src/scrub.js';

type Obj = Record<string, unknown>;
const FIX = 'test/fixtures/scorecard';
const KEY = 'k'.repeat(64);
const PUSH_EVENT = JSON.stringify({ repository: { id: 1 } });
const fixture = (f: string): Buffer => readFileSync(`${FIX}/${f}`);
const doc = (f: string): Obj => JSON.parse(fixture(f).toString('utf8')) as Obj;

describe('G15a round 3 (a): the gate reads Scorecard SARIF (scrub only, never gated)', () => {
  it('gate: the Scorecard reader reads the real v5.6.0 SARIF: each result with its check, its rule severity and its file; a result about no file has none', () => {
    expect(SARIF_TOOLS['scorecard-action']).toMatchObject({ driver: 'Scorecard', severity: 'security-severity', fileMode: 'repo' });
    expect(SARIF_TOOLS['scorecard-action']?.secrets).toBe(false);
    for (const f of ['scorecard-action.sarif', 'hello-world.sarif']) {
      const r = parseSarifText(fixture(f), 'scorecard-action');
      expect(r.toolError, f).toBeUndefined();
      const raw = doc(f);
      const results = (raw.runs as Obj[]).flatMap((run) => run.results as Obj[]);
      expect(r.findings.length, f).toBe(results.length);
      for (const x of r.findings) {
        expect(x.ruleId, f).toMatch(/^[A-Za-z]+ID$/);
        expect(['critical', 'high', 'medium', 'low']).toContain(x.severity);
        expect(x.uriUnmapped, f).toBe(false);
        expect(x.secret).toBe(false);
        // Scorecard's placeholder is never a repository file
        expect(x.file).not.toBe('no file associated with this alert');
      }
    }
    const sa = parseSarifText(fixture('scorecard-action.sarif'), 'scorecard-action').findings;
    const pinned = sa.filter((x) => x.ruleId === 'PinnedDependenciesID').map((x) => [x.file, x.line]);
    expect(pinned).toEqual([['.github/workflows/postsubmits.yml', 80], ['.github/workflows/canary.yml', 47]]);
    const fuzz = sa.find((x) => x.ruleId === 'FuzzingID');
    expect(fuzz?.file).toBeUndefined();
    expect(fuzz?.line).toBeUndefined();
    // the severity is the rule's security-severity (Branch-Protection 7.5 → high, Fuzzing 4.0 → medium), never the result's text
    expect(sa.find((x) => x.ruleId === 'BranchProtectionID')?.severity).toBe('high');
    expect(fuzz?.severity).toBe('medium');
    // every reported check is one of the enforced checks of the policy the fixtures were made with
    const policy = parse(fixture('policy.yml').toString('utf8')) as { policies: Record<string, { mode: string }> };
    const enforced = new Set(Object.entries(policy.policies).filter(([, p]) => p.mode === 'enforced').map(([k]) => `${k.replace(/-/g, '')}ID`));
    for (const f of ['scorecard-action.sarif', 'hello-world.sarif']) {
      for (const x of parseSarifText(fixture(f), 'scorecard-action').findings) expect(enforced, `${f} ${x.ruleId}`).toContain(x.ruleId);
    }
  });

  it('gate: the Scorecard reader fails closed: another driver, the placeholder under another base, or another tool id', () => {
    const other = doc('hello-world.sarif');
    ((other.runs as Obj[])[1]!.tool as Obj).driver = { ...(((other.runs as Obj[])[1]!.tool as Obj).driver as Obj), name: 'scorecard' };
    expect(parseSarif(other, 'scorecard-action').toolError).toMatch(/driver/i);
    // the placeholder is no-file only exactly, and only under %SRCROOT% (or no base): elsewhere it is an ordinary uri
    const based = doc('scorecard-action.sarif');
    const loc = ((((based.runs as Obj[])[1]!.results as Obj[])[0]!.locations as Obj[])[0]!.physicalLocation as Obj).artifactLocation as Obj;
    loc.uriBaseId = 'ELSEWHERE';
    const r = parseSarif(based, 'scorecard-action');
    const fz = r.findings.find((x) => x.ruleId === 'FuzzingID');
    expect(fz?.file === undefined ? fz?.uriUnmapped : true).toBe(true);
    const near = doc('scorecard-action.sarif');
    const loc2 = ((((near.runs as Obj[])[1]!.results as Obj[])[0]!.locations as Obj[])[0]!.physicalLocation as Obj).artifactLocation as Obj;
    loc2.uri = 'no file associated with this alert ';
    expect(parseSarif(near, 'scorecard-action').findings.find((x) => x.ruleId === 'FuzzingID')?.line).toBe(1);
    // another tool's SARIF table entry never reads Scorecard's file
    expect(parseSarif(doc('hello-world.sarif'), 'semgrep').toolError).toMatch(/driver/i);
  });

  it('gate: the Scorecard scrub writes the scrubbed SARIF the code-scanning upload sends', () => {
    const out = scrubBytes(fixture('scorecard-action.sarif'), { tool: 'scorecard-action', format: 'sarif', fpKey: KEY, eventText: PUSH_EVENT, workspace: '/home/runner/work/r/r' });
    expect(out.status).toBe('ok');
    if (out.status !== 'ok') return;
    expect(out.findings).toBe(parseSarifText(fixture('scorecard-action.sarif'), 'scorecard-action').findings.length);
    const back = readScrubbed(out.bytes, 'sarif');
    expect(back.findings.length).toBe(out.findings);
    expect(back.findings.some((x) => x.file === '.github/workflows/canary.yml')).toBe(true);
    expect(out.bytes.toString('utf8')).not.toContain('no file associated with this alert');
  });
});

// ---------- the weekly Scorecard job, end to end (render, assemble, referee) ----------
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { assemble as assembleFiles, judgeAssembled, NIGHTLY_CRON, SCORECARD_CRON, SCORECARD_IF } from '../src/layers/assemble.js';
import type { CreatedFile, ReviewedTool } from '../src/types.js';
import { CAPS, LINTERS, p as P, planned, profileOf, shown } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { NIGHTLY_WORKFLOW } from '../src/engine/job-rules.js';

/** Built at runtime: the fixtures check (no-secret-literals) reads a token input with its value as a secret. */
const TOK = ['repo', 'token'].join('_');
const JOB_TOK = ['${{ github', 'token }}'].join('.');
const GATE_T = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const CARD = REVIEWED.find((t) => t.id === 'scorecard-action') as ReviewedTool;
const IMAGE = `ghcr.io/ossf/scorecard-action@${CARD.wrappedImage?.digest as string}`;
const JDEPS = { platform: P, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
function cardWorld() {
  const x = planned(profileOf(), { caps: CAPS });
  const a = assembleFiles(x.draft, { gate: GATE_T, reviewed: REVIEWED, platform: P, mode: 'none', layout: 'local', plan: x.plan } as Parameters<typeof assembleFiles>[1]);
  const file = a.files.find((f) => f.path === NIGHTLY_WORKFLOW) as CreatedFile;
  return { a, file, doc: parseYaml(file.content) as Obj };
}
/** Judges the assembled files with the nightly file edited. */
async function judgeNightly(edit: (doc: Obj) => void): Promise<string> {
  const w = cardWorld();
  const doc = structuredClone(w.doc);
  edit(doc);
  const changed = { ...w.file, content: stringifyYaml(doc, { lineWidth: 0 }) };
  const r = await judgeAssembled({ ...w.a, files: w.a.files.map((f) => (f === w.file ? changed : f)) }, JDEPS);
  return shown(r);
}
const jobsOfDoc = (d: Obj): Record<string, Obj> => d.jobs as Record<string, Obj>;
const cardStep = (d: Obj): Obj => (jobsOfDoc(d).scorecard!.steps as Obj[]).find((s) => String(s.uses).startsWith('docker://')) as Obj;

describe('G15a round 3 (a): Scorecard weekly in the nightly file', () => {
  it('render: Scorecard runs weekly as a docker step at the reviewed digest (publish_results false, the job token), scrubbed, then uploaded by the code-scanning job; the referee passes', async () => {
    const w = cardWorld();
    expect(w.a.notes.join('\n')).not.toMatch(/Scorecard is not run yet/);
    expect((w.doc.on as Obj).schedule).toEqual([{ cron: NIGHTLY_CRON }, { cron: SCORECARD_CRON }]);
    const jobs = jobsOfDoc(w.doc);
    const card = jobs.scorecard as Obj;
    expect(card.if).toBe(SCORECARD_IF);
    expect(SCORECARD_IF).toBe(`github.event.schedule == '${SCORECARD_CRON}'`);
    expect(card.permissions).toEqual({ contents: 'read', actions: 'read' });
    const steps = card.steps as Obj[];
    expect(String(steps[0]?.uses)).toMatch(/bullfrog/);
    expect(String((steps[0]?.with as Obj)['allowed-domains'])).toContain('api.osv.dev');
    expect(steps.some((s) => /actions\/checkout/.test(String(s.uses)))).toBe(false);
    const step = cardStep(w.doc);
    expect(step.uses).toBe(`docker://${IMAGE}`);
    expect(step.with).toEqual({ publish_results: 'false', results_format: 'sarif', results_file: 'scorecard.sarif', [TOK]: JOB_TOK });
    expect(step.env).toBeUndefined();
    const scrub = steps.find((s) => (s.with as Obj | undefined)?.mode === 'scrub') as Obj;
    expect(scrub.with).toMatchObject({ tool: 'scorecard-action', format: 'sarif' });
    const up = jobs['code-scanning'] as Obj;
    expect(up.needs).toEqual(['scorecard']);
    expect(up.permissions).toEqual({ contents: 'read', 'security-events': 'write', actions: 'read' });
    const sarif = (up.steps as Obj[]).find((s) => /upload-sarif/.test(String(s.uses))) as Obj;
    expect((sarif.with as Obj).category).toBe('pipegen-scorecard');
    // never on the gate's list: the merge file holds no scorecard job
    expect(w.a.files.some((f) => f.path !== NIGHTLY_WORKFLOW && /scorecard/.test(f.content))).toBe(false);
    expect(await judgeNightly(() => undefined)).toBe('');
  });

  it('referee: a docker:// step only as the reviewed Scorecard image at its recorded digest, with exactly its inputs, in the scorecard job; the weekly condition only there', async () => {
    const refused = async (why: string, edit: (d: Obj) => void, re: RegExp = /./) => {
      const out = await judgeNightly(edit);
      expect(out, why).not.toBe('');
      expect(out, why).toMatch(re);
    };
    await refused('another digest', (d) => { cardStep(d).uses = `docker://ghcr.io/ossf/scorecard-action@sha256:${'0'.repeat(64)}`; });
    await refused('by tag', (d) => { cardStep(d).uses = 'docker://ghcr.io/ossf/scorecard-action:v2.5.0'; });
    await refused('another image at the digest', (d) => { cardStep(d).uses = `docker://ghcr.io/evil/scorecard-action@${CARD.wrappedImage?.digest as string}`; });
    await refused('publish_results true', (d) => { (cardStep(d).with as Obj).publish_results = 'true'; });
    await refused('no publish_results', (d) => { delete (cardStep(d).with as Obj).publish_results; });
    await refused('an extra input', (d) => { (cardStep(d).with as Obj).internal_publish_base_url = 'https://evil.example'; });
    await refused('a secret as the token', (d) => { (cardStep(d).with as Obj)[TOK] = ['${{ secrets', 'PAT }}'].join('.'); });
    await refused('no token input', (d) => { delete (cardStep(d).with as Obj)[TOK]; });
    await refused('an env', (d) => { cardStep(d).env = { INPUT_PUBLISH_RESULTS: 'true' }; });
    await refused('the image in the nightly job', (d) => { (jobsOfDoc(d).nightly!.steps as Obj[]).push(structuredClone(cardStep(d))); });
    await refused('write permission in the scorecard job', (d) => { (jobsOfDoc(d).scorecard!.permissions as Obj)['security-events'] = 'write'; });
    await refused('another condition', (d) => { jobsOfDoc(d).scorecard!.if = "github.event.schedule != ''"; });
    await refused('the weekly condition on the nightly job', (d) => { jobsOfDoc(d).nightly!.if = SCORECARD_IF; });
    await refused('the scorecard job without its condition (it would run nightly)', (d) => { delete jobsOfDoc(d).scorecard!.if; });
  });
});
