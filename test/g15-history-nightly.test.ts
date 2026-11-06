// G15a round 4 (b1, P-4): the nightly full-history secrets scan, end to end (render, assemble, referee). Written first. The nightly file gets
// the job secrets-history (a full checkout, then the history block: install, scan, scrub, upload; contents: read and no secret but the scrub's
// key) and the job code-scanning-history, which downloads the scrubbed result and uploads it to code scanning (category
// pipegen-secrets-history). Reported, never gated. With no code scanning, nothing would report it, so the job is not written and a note says so.
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { describe, expect, it } from 'vitest';
import { assemble as assembleFiles, judgeAssembled, NIGHTLY_CRON } from '../src/layers/assemble.js';
import type { CreatedFile, ReviewedTool } from '../src/types.js';
import { assemble as assembleJobs, CAPS, LINTERS, p as P, planned, profileOf, shown } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { HISTORY_UPLOAD_JOB, NIGHTLY_WORKFLOW, SECRETS_HISTORY_CATEGORY, SECRETS_HISTORY_JOB } from '../src/engine/job-rules.js';
import { SECRETS_HISTORY_ARTIFACT as H } from '../src/engine/artifact-names.js';
import { historyScanStepId } from '../src/engine/tool-flags.js';

type Obj = Record<string, unknown>;
const GATE_T = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const JDEPS = { platform: P, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
function world(caps = CAPS, prof = profileOf()) {
  const x = planned(prof, { caps });
  const a = assembleFiles(x.draft, { gate: GATE_T, reviewed: REVIEWED, platform: P, mode: 'none', layout: 'local', plan: x.plan } as Parameters<typeof assembleFiles>[1]);
  const file = a.files.find((f) => f.path === NIGHTLY_WORKFLOW) as CreatedFile;
  return { a, file, doc: parseYaml(file.content) as Obj };
}
async function judgeNightly(edit: (doc: Obj) => void): Promise<string> {
  const w = world();
  const doc = structuredClone(w.doc);
  edit(doc);
  const changed = { ...w.file, content: stringifyYaml(doc, { lineWidth: 0 }) };
  const r = await judgeAssembled({ ...w.a, files: w.a.files.map((f) => (f === w.file ? changed : f)) }, JDEPS);
  return shown(r);
}
const jobsOf = (d: Obj): Record<string, Obj> => d.jobs as Record<string, Obj>;
const stepsOf = (d: Obj, job = SECRETS_HISTORY_JOB): Obj[] => jobsOf(d)[job]!.steps as Obj[];
const scanOf = (d: Obj): Obj => stepsOf(d).find((s) => s.id === historyScanStepId) as Obj;

describe('G15a round 4 (b1): betterleaks over the full history, nightly', () => {
  it('render: the nightly file scans the whole history (a full checkout, the history block) and code-scanning-history uploads its scrubbed result; the referee passes', async () => {
    const w = world();
    expect((w.doc.on as Obj).schedule).toEqual(expect.arrayContaining([{ cron: NIGHTLY_CRON }]));
    const job = jobsOf(w.doc)[SECRETS_HISTORY_JOB] as Obj;
    expect(job.permissions).toEqual({ contents: 'read' });
    expect(job.if).toBeUndefined();
    const steps = stepsOf(w.doc);
    expect(String(steps[0]?.uses)).toMatch(/bullfrog/);
    const checkout = steps.find((s) => /actions\/checkout/.test(String(s.uses))) as Obj;
    expect((checkout.with as Obj)['fetch-depth']).toBe('0');
    expect(scanOf(w.doc).env).toMatchObject({ PIPEGEN_HISTORY_HEAD: '${{ github.sha }}' });
    const scrub = steps.find((s) => (s.with as Obj | undefined)?.mode === 'scrub') as Obj;
    expect(scrub.with).toMatchObject({ artifact: H, tool: 'betterleaks', format: 'sarif' });
    expect((scrub.with as Obj).stage).toBeUndefined();
    const up = jobsOf(w.doc)[HISTORY_UPLOAD_JOB] as Obj;
    expect(up.needs).toEqual([SECRETS_HISTORY_JOB]);
    expect(up.permissions).toEqual({ contents: 'read', 'security-events': 'write', actions: 'read' });
    const dl = (up.steps as Obj[]).find((s) => /download-artifact/.test(String(s.uses))) as Obj;
    expect((dl.with as Obj).name).toBe(H);
    const sarif = (up.steps as Obj[]).find((s) => /upload-sarif/.test(String(s.uses))) as Obj;
    expect((sarif.with as Obj).category).toBe(SECRETS_HISTORY_CATEGORY);
    expect(SECRETS_HISTORY_CATEGORY).toBe('pipegen-secrets-history');
    expect(String((sarif.with as Obj).sarif_file)).toBe(`\${{ runner.temp }}/pipegen-out/${H}/betterleaks.sarif`);
    // never gated: no other file holds the history scan
    expect(w.a.files.some((f) => f.path !== NIGHTLY_WORKFLOW && f.content.includes(H))).toBe(false);
    const clean = await judgeNightly(() => undefined);
    expect(clean, clean).toBe('');
  });

  it('referee: the history scan with a shallow checkout, another head, an edited run, a stage folder, or code-scanning power in the scan job → refused', async () => {
    const refused = async (why: string, edit: (d: Obj) => void, re: RegExp = /./) => {
      const out = await judgeNightly(edit);
      expect(out, why).not.toBe('');
      expect(out, why).toMatch(re);
    };
    await refused('a shallow checkout', (d) => { const c = stepsOf(d).find((s) => /actions\/checkout/.test(String(s.uses))) as Obj; delete (c.with as Obj)['fetch-depth']; }, /whole history|fetch-depth/);
    await refused('the head from an input', (d) => { (scanOf(d).env as Obj).PIPEGEN_HISTORY_HEAD = '${{ github.event.inputs.head }}'; });
    await refused('the range env on the history step', (d) => { (scanOf(d).env as Obj).PIPEGEN_RANGE_BASE = '${{ github.event.pull_request.base.sha }}'; });
    await refused('only the default branch (no --all)', (d) => { const s = scanOf(d); s.run = String(s.run).replace('logopts="--reverse --remerge-diff --text --all $last"', 'logopts="--reverse --remerge-diff --text $last"'); });
    await refused('a stage folder on the scrub', (d) => { ((stepsOf(d).find((s) => (s.with as Obj | undefined)?.mode === 'scrub') as Obj).with as Obj).stage = `\${{ runner.temp }}/pipegen-stage/${H}`; });
    await refused('the scrub as another tool', (d) => { ((stepsOf(d).find((s) => (s.with as Obj | undefined)?.mode === 'scrub') as Obj).with as Obj).tool = 'gitleaks'; });
    await refused('security-events write in the scan job', (d) => { (jobsOf(d)[SECRETS_HISTORY_JOB]!.permissions as Obj)['security-events'] = 'write'; });
    await refused('a checkout in the upload job', (d) => { (jobsOf(d)[HISTORY_UPLOAD_JOB]!.steps as Obj[]).splice(1, 0, structuredClone(stepsOf(d).find((s) => /actions\/checkout/.test(String(s.uses))) as Obj)); });
  });

  it('assemble: without code scanning nothing would report the history scan, so it is not written and a note says so', () => {
    const off = assembleJobs(planned({ ...profileOf(), private: true }, { caps: { ...CAPS, codeScanning: false } }));
    expect(Object.keys(off.nightly)).not.toContain(SECRETS_HISTORY_JOB);
    expect(Object.keys(off.nightly)).not.toContain(HISTORY_UPLOAD_JOB);
    expect(off.notes.join('\n')).toMatch(/whole history .*code scanning/);
    const on = assembleJobs(planned(profileOf(), { caps: CAPS }));
    expect(Object.keys(on.nightly)).toEqual(expect.arrayContaining([SECRETS_HISTORY_JOB, HISTORY_UPLOAD_JOB]));
    expect(on.notes.join('\n')).not.toMatch(/whole history/);
  });
});
