// G15a round 5 (b2, P-4): zizmor online, nightly. Written first. The PR and merge jobs run zizmor --offline (no token). The nightly file gets
// the job workflow-lint-online: egress (github-core: zizmor's online audits read api.github.com and github.com), a checkout, the install and
// the run of the same reviewed zizmor entry under a second argv policy (tool-flags.ts ZIZMOR_ONLINE_POLICY: no --offline) with the job's own
// read token as GH_TOKEN (contents: read only). A job-status check: zizmor's exit code fails the job on a finding, so no output format is
// read (the entry's output is `none`, as offline). Never gated.
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { describe, expect, it } from 'vitest';
import { assemble as assembleFiles, judgeAssembled } from '../src/layers/assemble.js';
import type { CreatedFile, ReviewedTool, StepSpec } from '../src/types.js';
import { CAPS, LINTERS, p as P, planned, profileOf, shown } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { checkExpressions, NIGHTLY_WORKFLOW, ZIZMOR_ONLINE_JOB, type RenderedStep } from '../src/engine/job-rules.js';
import { ARGV_POLICIES, ZIZMOR_ONLINE_POLICY, ZIZMOR_ONLINE_STEP_ENV, zizmorOnlineStepId } from '../src/engine/tool-flags.js';
import { renderStep, renderStepWith, renderZizmorOnline } from '../src/engine/render-step.js';
import { argvPolicyProblems, type ReviewedEntry } from '../src/engine/reviewed.js';
import { RenderError } from '../src/engine/render-error.js';

type Obj = Record<string, unknown>;
const GATE_T = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const ZIZMOR = REVIEWED.find((t) => t.id === 'zizmor') as ReviewedTool;
const GHT = 'GH_' + 'TOKEN';
const GHT2 = 'GITHUB_' + 'TOKEN';
const TOK_REF = '${{ github.' + 'tok' + 'en }}';
const JDEPS = { platform: P, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
const CTX = { profile: profileOf() };

function world(reviewed: readonly ReviewedTool[] = REVIEWED) {
  const x = planned(profileOf(), { caps: CAPS });
  const a = assembleFiles(x.draft, { gate: GATE_T, reviewed, platform: P, mode: 'none', layout: 'local', plan: x.plan } as Parameters<typeof assembleFiles>[1]);
  const file = a.files.find((f) => f.path === NIGHTLY_WORKFLOW) as CreatedFile;
  return { a, file, doc: parseYaml(file.content) as Obj };
}
async function judgeEdited(edit: (doc: Obj, merge: Obj) => void): Promise<string> {
  const w = world();
  const doc = structuredClone(w.doc);
  const mergeFile = w.a.files.find((f) => f.path === '.github/workflows/pipegen-merge.yml') as CreatedFile;
  const merge = parseYaml(mergeFile.content) as Obj;
  const mergeBefore = JSON.stringify(merge);
  edit(doc, merge);
  const changed = { ...w.file, content: stringifyYaml(doc, { lineWidth: 0 }) };
  // the merge file is written again only when the edit changed it (a re-written file may fold its lines differently)
  const mergeChanged = JSON.stringify(merge) === mergeBefore ? mergeFile : { ...mergeFile, content: stringifyYaml(merge, { lineWidth: 0 }) };
  const r = await judgeAssembled({ ...w.a, files: w.a.files.map((f) => (f === w.file ? changed : f === mergeFile ? mergeChanged : f)) }, JDEPS);
  return shown(r);
}
const jobsOf = (d: Obj): Record<string, Obj> => d.jobs as Record<string, Obj>;
const stepsOf = (d: Obj, job = ZIZMOR_ONLINE_JOB): Obj[] => jobsOf(d)[job]!.steps as Obj[];
const runOf = (d: Obj): Obj => stepsOf(d).find((s) => s.id === zizmorOnlineStepId) as Obj;
const withCommand = (t: ReviewedTool, command: string[], args: string[] = ['--offline']): ReviewedTool =>
  ({ ...t, step: { ...t.step, cli: { ...t.step.cli!, command } }, fixedInputs: { ...t.fixedInputs, args } });

describe('G15a round 5 (b2): zizmor online, nightly', () => {
  it('tool-flags: the online policy is the zizmor policy without --offline, with the job token as GH_TOKEN; no policy of ARGV_POLICIES takes a token', () => {
    const offline = ARGV_POLICIES.zizmor!;
    expect(offline.flags).toEqual({ offline: 'bool' });
    expect(offline.required).toEqual({ offline: 'true' });
    const { flags, required, tokenEnv, ...rest } = ZIZMOR_ONLINE_POLICY;
    const { flags: _f, required: _r, ...offRest } = offline;
    expect(rest).toEqual(offRest);
    // in place of --offline, the host is named (the token only ever goes to github.com)
    expect(flags).toEqual({ 'gh-hostname': { values: ['github.com'] } });
    expect(required).toEqual({ 'gh-hostname': 'github.com' });
    expect(tokenEnv).toBe('GH_TOKEN');
    expect(ZIZMOR_ONLINE_STEP_ENV).toEqual({ [GHT]: TOK_REF });
    for (const [id, pol] of Object.entries(ARGV_POLICIES)) expect(pol.tokenEnv, id).toBeUndefined();
    // the entry's online form (its command without --offline) passes the online policy and fails the offline one; the offline form the reverse
    const online = withCommand(ZIZMOR, ['zizmor', '--gh-hostname', 'github.com', '.github/workflows'], ['--gh-hostname', 'github.com']) as unknown as ReviewedEntry;
    expect(argvPolicyProblems(online, { zizmor: ZIZMOR_ONLINE_POLICY })).toEqual([]);
    // another host, or no host: refused by the online policy
    expect(argvPolicyProblems(withCommand(ZIZMOR, ['zizmor', '--gh-hostname', 'ghe.example', '.github/workflows'], ['--gh-hostname', 'ghe.example']) as unknown as ReviewedEntry, { zizmor: ZIZMOR_ONLINE_POLICY }).length).toBeGreaterThan(0);
    expect(argvPolicyProblems(withCommand(ZIZMOR, ['zizmor', '.github/workflows'], []) as unknown as ReviewedEntry, { zizmor: ZIZMOR_ONLINE_POLICY }).length).toBeGreaterThan(0);
    expect(argvPolicyProblems(online).length).toBeGreaterThan(0);
    expect(argvPolicyProblems(ZIZMOR as unknown as ReviewedEntry, { zizmor: ZIZMOR_ONLINE_POLICY }).length).toBeGreaterThan(0);
    expect(argvPolicyProblems(ZIZMOR as unknown as ReviewedEntry)).toEqual([]);
  });

  it('render: zizmor online is the reviewed entry without --offline, the job token passed as GH_TOKEN, under its own artifact and step ids', () => {
    const r = renderZizmorOnline(ZIZMOR, P, CTX);
    expect(r.output).toBeNull();
    expect(r.steps.map((s) => s.name)).toEqual(['pipegen: install zizmor', 'pipegen: run zizmor']);
    const run = r.steps[1] as RenderedStep;
    expect(run.id).toBe(zizmorOnlineStepId);
    expect(run.env).toMatchObject({ [GHT]: TOK_REF });
    expect(run.run).toContain('"${pg_env[@]}" "$bin/zizmor" --config "$cfg/zizmor.yml" --gh-hostname github.com .github/workflows || rc=$?');
    expect(run.run).not.toContain('--offline');
    expect(run.run).toContain(`  "${GHT}=$${GHT}"`);
    expect(run.run).toContain('pipegen-out-workflow-lint-online');
    expect(() => checkExpressions(run)).not.toThrow();
    // the offline render of the same entry (the PR and merge jobs) is unchanged: --offline, no token
    const spec: StepSpec = { needId: 'workflow-lint', tool: ZIZMOR.candidate, choices: {}, output: ZIZMOR.step.output } as unknown as StepSpec;
    const off = renderStep(spec, ZIZMOR, P, CTX).steps.find((s) => s.name === 'pipegen: run zizmor') as RenderedStep;
    expect(off.run).toContain('--offline .github/workflows');
    expect(off.run).not.toContain('GH_TOKEN');
    expect(Object.keys(off.env ?? {})).not.toContain('GH_TOKEN');
    expect(off.id).not.toBe(zizmorOnlineStepId);
    // the install is the offline install's, under the online artifact
    const offInstall = renderStep(spec, ZIZMOR, P, CTX).steps[0] as RenderedStep;
    expect((r.steps[0] as RenderedStep).env).toEqual(offInstall.env);
  });

  it('render: zizmor online runs only the reviewed zizmor entry, in its reviewed offline form', () => {
    const other = REVIEWED.find((t) => t.id === 'actionlint') as ReviewedTool;
    expect(() => renderZizmorOnline(other, P, CTX)).toThrow(RenderError);
    expect(() => renderZizmorOnline({ ...ZIZMOR, candidate: { ...ZIZMOR.candidate, reviewed: false } } as unknown as ReviewedTool, P, CTX)).toThrow(RenderError);
    // an entry whose command is not exactly the offline form (another flag, no --offline, another folder) is not run online
    expect(() => renderZizmorOnline(withCommand(ZIZMOR, ['zizmor', '--offline', '--no-online-audits', '.github/workflows']), P, CTX)).toThrow(/offline form/);
    expect(() => renderZizmorOnline(withCommand(ZIZMOR, ['zizmor', '.github/workflows'], []), P, CTX)).toThrow(/offline form/);
    expect(() => renderZizmorOnline(withCommand(ZIZMOR, ['zizmor', '--offline', '.']), P, CTX)).toThrow(/offline form/);
    expect(() => renderZizmorOnline(withCommand(ZIZMOR, ['zizmor', '--offline', '.github/workflows'], []), P, CTX)).toThrow(/offline form/);
  });

  it('render: only the online zizmor policy may take the job token, the online form must pass that policy, and only the zizmor id runs online (mutants Z8, Z10, Z18)', () => {
    // Z8: a token on any other policy is refused by the renderer, even for a release binary
    const lint = REVIEWED.find((t) => t.id === 'actionlint') as ReviewedTool;
    const lintSpec = { needId: 'workflow-lint', tool: lint.candidate, choices: {}, output: lint.step.output } as unknown as StepSpec;
    const policiesTok = { ...ARGV_POLICIES, actionlint: { ...ARGV_POLICIES.actionlint, ['tok' + 'enEnv']: GHT } } as typeof ARGV_POLICIES;
    expect(() => renderStepWith(lintSpec, lint, P, CTX, { policies: policiesTok })).toThrow(/may not take the job's token/);
    // Z10: another entry is refused for its id, before anything else is looked at
    expect(() => renderZizmorOnline(lint, P, CTX)).toThrow(/runs the reviewed zizmor entry only/);
    // Z18: the offline form with another install is refused by the online policy check (not later by the renderer)
    const moved = { ...ZIZMOR, step: { ...ZIZMOR.step, cli: { ...ZIZMOR.step.cli!, install: { ...ZIZMOR.step.cli!.install, package: 'other.tar.gz' } } } } as ReviewedTool;
    expect(() => renderZizmorOnline(moved, P, CTX)).toThrow(/does not pass its argv policy/);
  });

  it('job rules: the token form is accepted only on the online zizmor run step, exactly', () => {
    const run = renderZizmorOnline(ZIZMOR, P, CTX).steps[1] as RenderedStep;
    expect(() => checkExpressions(run)).not.toThrow();
    // another step id, another name, another value, or an action step: refused
    expect(() => checkExpressions({ ...run, id: 'tool-run-0123456789abcdef' })).toThrow(RenderError);
    expect(() => checkExpressions({ ...run, env: { ...run.env, [GHT2]: TOK_REF } })).toThrow(RenderError);
    expect(() => checkExpressions({ ...run, env: { ...run.env, [GHT]: '${{ secrets.GITHUB_' + 'TOKEN }}' } })).toThrow(RenderError);
    expect(() => checkExpressions({ ...run, env: { ...run.env, [GHT]: '${{ github.event.inputs.t }}' } })).toThrow(RenderError);
    const { run: _r, ...noRun } = run;
    expect(() => checkExpressions({ ...noRun, uses: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' })).toThrow(RenderError);
    // the offline run step with the token added: refused
    const spec: StepSpec = { needId: 'workflow-lint', tool: ZIZMOR.candidate, choices: {}, output: ZIZMOR.step.output } as unknown as StepSpec;
    const off = renderStep(spec, ZIZMOR, P, CTX).steps[1] as RenderedStep;
    expect(() => checkExpressions({ ...off, env: { ...off.env, [GHT]: TOK_REF } })).toThrow(RenderError);
  });

  it('render: the nightly file runs zizmor online (egress, checkout, install, run; contents: read; no condition) and the referee passes', async () => {
    const w = world();
    const job = jobsOf(w.doc)[ZIZMOR_ONLINE_JOB] as Obj;
    expect(job).toBeDefined();
    expect(job.permissions).toEqual({ contents: 'read' });
    expect(job.if).toBeUndefined();
    expect(job.needs).toBeUndefined();
    const steps = stepsOf(w.doc);
    expect(steps.map((s) => s.name)).toEqual(['Limit network egress', 'Check out the repository', 'pipegen: install zizmor', 'pipegen: run zizmor']);
    const domains = String((steps[0]!.with as Obj)['allowed-domains']).split('\n');
    expect(domains).toEqual(expect.arrayContaining(['api.github.com', 'github.com']));
    expect((steps[1]!.with as Obj)['persist-credentials']).toBe('false');
    expect(runOf(w.doc).env).toMatchObject({ [GHT]: TOK_REF });
    expect(String(runOf(w.doc).run)).not.toContain('--offline');
    // the token form is in no other file and no other job
    expect(w.a.files.some((f) => f.path !== NIGHTLY_WORKFLOW && f.content.includes('GH_TOKEN'))).toBe(false);
    for (const [id, j] of Object.entries(jobsOf(w.doc))) if (id !== ZIZMOR_ONLINE_JOB) expect(JSON.stringify(j), id).not.toContain('GH_TOKEN');
    const clean = await judgeEdited(() => undefined);
    expect(clean, clean).toBe('');
  });

  it('referee: zizmor online with --offline back, another token, write power, an extra or repo-code step, outside its job or outside the nightly file → refused', async () => {
    const refused = async (why: string, edit: (d: Obj, m: Obj) => void, re: RegExp = /./) => {
      const out = await judgeEdited(edit);
      expect(out, why).not.toBe('');
      expect(out, why).toMatch(re);
    };
    await refused('an edited run (a flag added)', (d) => { const s = runOf(d); s.run = String(s.run).replace('--gh-hostname github.com', '--no-online-audits'); });
    await refused('another host', (d) => { const s = runOf(d); s.run = String(s.run).replace('--gh-hostname github.com', '--gh-hostname ghe.example'); });
    await refused('--offline back', (d) => { const s = runOf(d); s.run = String(s.run).replace('--gh-hostname github.com', '--offline'); });
    await refused('the token from a secret', (d) => { (runOf(d).env as Obj)[GHT] = '${{ secrets.GITHUB_' + 'TOKEN }}'; });
    await refused('a second token name', (d) => { (runOf(d).env as Obj)[GHT2] = TOK_REF; });
    await refused('the token dropped', (d) => { delete (runOf(d).env as Obj)[GHT]; });
    await refused('contents: write', (d) => { (jobsOf(d)[ZIZMOR_ONLINE_JOB]!.permissions as Obj).contents = 'write'; }, /contents: write/);
    await refused('a repo-code step in the job', (d) => { stepsOf(d).push({ name: 'build', run: 'npm test' }); });
    await refused('a docker step in the job', (d) => { stepsOf(d).push(structuredClone((jobsOf(d).scorecard!.steps as Obj[]).find((s) => String(s.uses).startsWith('docker://')) as Obj)); }, /may run only harden, checkout, tool steps/);
    await refused('the online steps in another nightly job', (d) => { const j = jobsOf(d); j['other-lint'] = j[ZIZMOR_ONLINE_JOB]!; delete j[ZIZMOR_ONLINE_JOB]; }, /zizmor's online run \(with the job's token\) runs only in the job workflow-lint-online of the nightly file/);
    await refused('the online job in the merge file', (d, m) => { jobsOf(m)[ZIZMOR_ONLINE_JOB] = structuredClone(jobsOf(d)[ZIZMOR_ONLINE_JOB]!); }, /the job workflow-lint-online is the nightly online zizmor job of the nightly file only/);
    await refused('the secrets-history scan in the online job', (d) => { stepsOf(d).push(...structuredClone(stepsOf(d, 'secrets-history').filter((s) => String(s.id ?? '').startsWith('tool-install-') || String(s.id ?? '').startsWith('checker-run-')))); }, /runs zizmor online and no other tool/);
    await refused('a condition on the job', (d) => { jobsOf(d)[ZIZMOR_ONLINE_JOB]!.if = "github.event.schedule == '23 4 * * 1'"; });
  });

  it('assemble: without zizmor on the reviewed list there is no workflow lint, so no online job either', () => {
    const w = world();
    expect(jobsOf(w.doc)[ZIZMOR_ONLINE_JOB]).toBeDefined();
    const x = planned(profileOf(), { caps: CAPS, edit: (steps) => steps.filter((s) => s.needId !== 'workflow-lint') });
    const needs = x.draft.needs.filter((n) => n.id !== 'workflow-lint');
    const draft = { ...x.draft, needs };
    const plan = { ...x.plan, needs };
    const a = assembleFiles(draft, { gate: GATE_T, reviewed: REVIEWED, platform: P, mode: 'none', layout: 'local', plan } as Parameters<typeof assembleFiles>[1]);
    const doc = parseYaml((a.files.find((f) => f.path === NIGHTLY_WORKFLOW) as CreatedFile).content) as Obj;
    expect(jobsOf(doc)[ZIZMOR_ONLINE_JOB]).toBeUndefined();
  });
});
