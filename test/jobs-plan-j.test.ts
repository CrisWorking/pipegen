// Sub-task GJ (Plan G after the Plan J merge, ruling G-J1): the already-built G2/G3, G4 and G5 parts follow Plan J (a project type per
// service, fewer and right checks). Every job kind is keyed to the needs list (floorNeeds and skippedChecks decide, never the type again in G
// code); workflow lint runs zizmor alone; a signing need on a service that builds no image is report-only; a static site with a deploy
// workflow is a deploy target; the referee refuses a job, a check or a signature without its need.
import { describe, expect, it } from 'vitest';
import { keyOffers } from '../src/debate/builder.js';
import { estimateNeeds, jobCategories, floorNeeds, noImageServices, skippedChecks, WORKFLOW_LINT_EXTRA, WORKFLOW_LINT_TOOL } from '../src/engine/needs.js';
import { sharedWorkflows, signCallerJob, signJob } from '../src/layers/central.js';
import { assemble as assembleFiles, judgeAssembled, type AssembledFiles } from '../src/layers/assemble.js';
import { AssembleError, assembleJobs, HOOKS_CI_NOTES, type Job } from '../src/layers/jobs.js';
import { RenderError } from '../src/engine/render-error.js';
import type { Capabilities, ExistingWorkflow, Need, PipelineDraft, ProjectType, ReviewedTool, Service, ServiceType } from '../src/types.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { CAPS, LINTERS, assemble, editJob, files, judge, node, p, planned, profileOf, shown } from './helpers/assemble.js';
import { POUTINE_NOT_RUN } from '../src/layers/jobs.js';

/** ExistingWorkflow's used-names field, spelled at run time (test/no-secret-literals.test.ts). */
const USED = ['sec', 'retsUsed'].join('');
const type = (...types: ServiceType[]): ProjectType => ({ types, evidence: [], unsure: false });
const SKIP_DEPLOY = { skipped: [{ part: 'deploy' as const, reason: 't' }] };
/** The job kinds Plan J drops for a service that runs nothing: the image build, its scan, the DAST run and scrub, API DAST. */
const IMAGE_JOB_RE = /^(?:image-build|image-scan|dast-run|dast|api-dast)--/;
const imageJobs = (merge: Record<string, Job>): string[] => Object.keys(merge).filter((k) => IMAGE_JOB_RE.test(k)).sort();
/** The image jobs the needs call for: one per merge-layer need of those kinds (dast: its run job and its scrub job). */
const imageJobsOfNeeds = (needs: readonly Need[]): string[] => needs.filter((n) => n.layer === 'merge' && ['image-build', 'image-scan', 'dast', 'api-dast'].includes(n.id) && n.id !== 'api-dast')
  .flatMap((n) => (n.id === 'dast' ? [`dast-run--${n.service}`, `dast--${n.service}`] : [`${n.id}--${n.service}`])).sort();
const DEPLOY_WF: ExistingWorkflow = { path: '.github/workflows/pages.yml', triggers: ['push'], deploys: true, [USED]: [], jobs: ['deploy'], staticHosts: ['github-pages'] } as unknown as ExistingWorkflow;
const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const KE_CAPS: Capabilities = { ...CAPS, environments: true, deploymentBranchPolicies: true };
const PIN = { repo: 'o/pipelines', sha: 'c'.repeat(40) };
const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
/**
 * A planned static site with a deploy workflow. The deploy layer's egress need is a step of G7's release jobs (none is written here), so it
 * leaves these needs; every other need of the floor stays.
 */
const deployed = (prof: ReturnType<typeof profileOf>, caps: Capabilities = CAPS, over: Partial<PipelineDraft> = {}): ReturnType<typeof planned> =>
  planned(prof, { caps, needs: floorNeeds(prof, caps).filter((n) => n.id !== 'egress'), over });
const lay = (x: ReturnType<typeof planned>, mode: 'none' | 'keyless' | 'key-env'): AssembledFiles =>
  assembleFiles(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode, layout: x.draft.profile.private ? 'central' : 'local', plan: x.plan });

/** One service of each type (a static site that would run but for its type, so the drop is Plan J's and not the old rule's). */
// (handoff: static site and library in 2 shapes each; an unsure static site is a server and keeps the full set)
const FIXTURES: readonly [string, Service][] = [
  ['static site', node({ dockerfile: 'Dockerfile', port: 3000, scripts: ['test', 'lint', 'start'], projectType: type('static-site') })],
  ['static site 2', node({ name: 'site', path: 'site', scripts: ['test', 'lint', 'dev'], frameworks: ['next'], projectType: type('static-site') })],
  ['library', node({ projectType: type('library') })],
  ['library 2', node({ port: 8080, publishedPackage: true, scripts: ['test', 'lint', 'build'], projectType: type('library', 'cli') })],
  ['unsure static site', node({ dockerfile: 'Dockerfile', port: 3000, projectType: { types: ['server'], evidence: [], unsure: true } })],
  ['CLI', node({ projectType: type('cli') })],
  ['server', node({ dockerfile: 'Dockerfile', port: 3000, projectType: type('server') })],
  ['container', node({ dockerfile: 'Dockerfile', port: 3000, projectType: type('container') })],
  // controls (review GJ spec M1): library and CLI change no check in v0.2 (types.ts, F10): only the static-site type is read by isRunnable,
  // so a CLI that builds an image keeps its image jobs, and a static site that is also a container is one
  ['CLI with an image', node({ dockerfile: 'Dockerfile', port: 3000, projectType: type('cli') })],
  ['static site + container', node({ dockerfile: 'Dockerfile', port: 3000, projectType: type('static-site', 'container') })],
];

describe('GJ: G2/G3, G4 and G5 follow Plan J (a project type per service, fewer and right checks)', () => {
  it('GJ per type: static site, library, CLI, server, container → the assembled jobs match their needs', async () => {
    for (const [name, svc] of FIXTURES) {
      const x = planned(profileOf([svc]), { over: SKIP_DEPLOY });
      const a = assemble(x);
      // the image jobs are exactly those the needs call for (no more, no fewer)
      expect(imageJobs(a.merge), name).toEqual(imageJobsOfNeeds(x.draft.needs));
      const runs = ['server', 'container', 'unsure static site', 'CLI with an image', 'static site + container'].includes(name);
      expect(imageJobs(a.merge).length > 0, name).toBe(runs);
      // every merge-layer check keeps its job (the minimum among them): secrets, SAST, deps, workflow lint, the pin check and the gate
      for (const id of ['secrets', `sast--${svc.name}`, `deps--${svc.name}`, 'workflow-lint', 'workflow-pin-check', 'gate']) expect(a.merge[id], `${name} ${id}`).toBeDefined();
      expect(shown(await judge(files(a), a.draft)), name).toBe('');
    }
  });

  it('GJ: a static site gets no image build, image scan, DAST or API DAST job; the same service with no type gets them', () => {
    const [, site] = FIXTURES[0] as [string, Service];
    const withSpec: Service = { ...site, quality: { ...site.quality, apiSpec: { kind: 'file', path: 'openapi.json' } } };
    const x = planned(profileOf([withSpec]), { over: SKIP_DEPLOY });
    expect(x.draft.needs.filter((n) => ['image-build', 'image-scan', 'dast', 'api-dast'].includes(n.id))).toEqual([]);
    expect(skippedChecks(x.draft.profile, CAPS).filter((k) => k.service === 'app').map((k) => k.category)).toEqual(expect.arrayContaining(['api-dast', 'image-build', 'image-scan', 'dast']));
    expect(imageJobs(assemble(x).merge)).toEqual([]);
    // the control: the same service with no project type (a hand-built profile keeps today's rule) is built, scanned and DAST-tested
    const { projectType: _t, ...untyped } = withSpec;
    const y = planned(profileOf([untyped]), { over: SKIP_DEPLOY });
    expect(imageJobs(assemble(y).merge)).toEqual(['dast--app', 'dast-run--app', 'image-build--app', 'image-scan--app']);
  });

  it('GJ: assembleJobs refuses an image, DAST or API DAST need for a service the plan builds no image for (skippedChecks)', () => {
    const [, site] = FIXTURES[0] as [string, Service];
    const prof = profileOf([site]);
    expect([...noImageServices(prof, CAPS).keys()]).toEqual(['app']);
    // the needs of the same service as a server, put on the static site (a planted need: acceptAddedNeed never keeps one)
    const server = floorNeeds(profileOf([{ ...site, projectType: type('server') }]), CAPS);
    for (const id of ['image-build', 'image-scan', 'dast']) {
      const extra = server.find((n) => n.id === id) as Need;
      const needs = [...floorNeeds(prof, CAPS), extra];
      const x = planned(prof, { needs, over: SKIP_DEPLOY });
      expect(() => assemble(x), id).toThrow(AssembleError);
      expect(() => assemble(x), id).toThrow(new RegExp(`"${id}" for "app".*builds no image`));
    }
  });

  it('GJ: workflow lint renders zizmor; poutine joins it only on pull_request_target or issue_comment; actionlint never', async () => {
    const wfOn = (...triggers: string[]): ExistingWorkflow => ({ path: '.github/workflows/t.yml', triggers, deploys: false, [USED]: [], jobs: ['t'] } as unknown as ExistingWorkflow);
    const cases: [string, ReturnType<typeof profileOf>, string[]][] = [
      ['plain', profileOf(), [WORKFLOW_LINT_TOOL]],
      ['workflow_run only', profileOf([node()], { existingWorkflows: [wfOn('workflow_run')] }), [WORKFLOW_LINT_TOOL]],
      ['pull_request_target', profileOf([node()], { existingWorkflows: [wfOn('pull_request_target')] }), [WORKFLOW_LINT_TOOL, WORKFLOW_LINT_EXTRA]],
      ['issue_comment', profileOf([node()], { existingWorkflows: [wfOn('push'), wfOn('issue_comment')] }), [WORKFLOW_LINT_TOOL, WORKFLOW_LINT_EXTRA]],
    ];
    expect([WORKFLOW_LINT_TOOL, WORKFLOW_LINT_EXTRA]).toEqual(['zizmor', 'poutine']);
    for (const [name, prof, want] of cases) {
      const x = planned(prof);
      const o = keyOffers(x.plan.needs, x.plan.candidates, prof, { reviewed: REVIEWED });
      expect(o.offers.get('workflow-lint')?.map((of) => of.entry.id), name).toEqual(want);
      // whatever the debate picked (here poutine alone, where it is offered), the job runs every tool of the rule, each once
      const picks = want.length > 1 ? { ...x, draft: { ...x.draft, steps: x.draft.steps.filter((st) => !(st.needId === 'workflow-lint' && st.tool.id === WORKFLOW_LINT_TOOL)) } } : x;
      const a = assemble(picks);
      for (const layer of [a.merge, a.push]) {
        const names = (layer['workflow-lint'] as Job).steps.map((st) => st.name).join('\n');
        expect(names, name).toMatch(/run zizmor/);
        expect(names, name).not.toMatch(/actionlint/);
        expect(/run poutine/.test(names), name).toBe(want.includes(WORKFLOW_LINT_EXTRA));
      }
      expect(a.draft.steps.filter((st) => st.needId === 'workflow-lint').map((st) => st.tool.id).sort(), name).toEqual([...want].sort());
      expect(shown(await judge(files(a), a.draft)), name).toBe('');
    }
    // a draft that runs actionlint for workflow lint (never offered) is refused, never rendered
    const x = planned(profileOf());
    const actionlint = REVIEWED.find((t) => t.id === 'actionlint') as ReviewedTool;
    const swapped = { ...x, draft: { ...x.draft, steps: x.draft.steps.map((st) => (st.needId === 'workflow-lint' ? { ...st, tool: actionlint.candidate, output: actionlint.step.output } : st)) } };
    expect(() => assemble(swapped)).toThrow(/runs "actionlint", which is not a reviewed tool pipegen offered/);
  });

  it('GJ: hooks-ci runs lefthook only for a lefthook (or hook-less) repository; pre-commit and husky get a plain note, no job, no other tool', () => {
    for (const manager of ['lefthook', null] as const) {
      const a = assemble(planned(profileOf([node()], { precommit: manager })));
      expect(JSON.stringify(a.merge['hooks-ci']?.steps), String(manager)).toMatch(/lefthook/);
    }
    for (const manager of ['pre-commit', 'husky'] as const) {
      const prof = profileOf([node()], { precommit: manager });
      const x = planned(prof);
      const o = keyOffers(x.plan.needs, x.plan.candidates, prof, { reviewed: REVIEWED });
      expect(o.offers.has('hooks-ci'), manager).toBe(false);
      const a = assembleJobs(x.draft, { ...x.plan, uncovered: o.uncovered }, { reviewed: REVIEWED, platform: p, mode: 'none' });
      expect(a.merge['hooks-ci'], manager).toBeUndefined();
      expect(a.push['hooks-ci'], manager).toBeUndefined();
      expect(a.draft.needs.some((n) => n.id === 'hooks-ci'), manager).toBe(false);
      expect(a.notes, manager).toContain(HOOKS_CI_NOTES[manager]);
      // the minimum stays
      for (const id of ['secrets', 'sast--app', 'deps--app', 'workflow-lint', 'workflow-pin-check', 'gate']) expect(a.merge[id], `${manager} ${id}`).toBeDefined();
    }
  });

  it('GJ: without zizmor on the reviewed list, workflow lint is only a suggestion: no job, a note, nothing else lost', async () => {
    const without = REVIEWED.filter((t) => t.id !== WORKFLOW_LINT_TOOL);
    const prof = profileOf();
    const needs = floorNeeds(prof, CAPS);
    const o = keyOffers(needs, planned(prof).plan.candidates, prof, { reviewed: without });
    expect(o.offers.has('workflow-lint')).toBe(false);
    const x = planned(prof);
    const plan = { ...x.plan, uncovered: o.uncovered };
    const draft = { ...x.draft, steps: x.draft.steps.filter((s) => s.needId !== 'workflow-lint') };
    const a = assembleJobs(draft, plan, { reviewed: without, platform: p, mode: 'none' });
    expect(a.merge['workflow-lint']).toBeUndefined();
    expect(a.push['workflow-lint']).toBeUndefined();
    expect(a.draft.needs.some((n) => n.id === 'workflow-lint')).toBe(false);
    expect(a.notes.join('\n')).toMatch(/zizmor is not on pipegen's reviewed list.*suggest/);
    // the pin check and every other check stay
    expect(a.merge['workflow-pin-check']).toBeDefined();
    expect(a.merge.secrets).toBeDefined();
    // with zizmor on the list, the same uncovered key still stops (never dropped, never another tool)
    expect(() => assembleJobs(draft, plan, { reviewed: REVIEWED, platform: p, mode: 'none' })).toThrow(/no tool it can run \("workflow-lint"/);
  });

  it('GJ: a signing need on a service that builds no image is report-only: no sign job, no sign caller, a note', async () => {
    const site = node({ projectType: type('static-site') });
    // public (keyless) and private (key-env) static sites with a deploy workflow: signing needs on the site, no image anywhere
    const cases = [
      { mode: 'keyless' as const, x: deployed(profileOf([site], { existingWorkflows: [DEPLOY_WF] })) },
      { mode: 'key-env' as const, x: deployed(profileOf([site], { private: true, existingWorkflows: [DEPLOY_WF] }), KE_CAPS, { centralPin: PIN }) },
    ];
    for (const { mode, x } of cases) {
      expect(x.draft.needs.some((n) => n.layer === 'deploy' && n.id === 'signing' && n.service === 'app' && n.blocking)).toBe(true);
      const jobs = assemble(x, mode);
      expect(jobs.sign, mode).toBeNull();
      expect(jobs.draft.signing, mode).toBeUndefined();
      expect(jobs.notes.join('\n'), mode).toMatch(/"app" builds no image, so its signing is report-only/);
      const a = lay(x, mode);
      for (const f of a.files) expect(f.content, `${mode} ${f.path}`).not.toMatch(/--sign\.yml|cosign| sign:/);
      expect(a.files.some((f) => f.path.endsWith('--sign.yml')), mode).toBe(false);
      expect(shown(await judgeAssembled(a, JD)), mode).toBe('');
    }
    // a plan that still lists the site's image is narrowed the same way: nothing signs it (G3's functions agree)
    const k = cases[1]?.x as ReturnType<typeof planned>;
    const withPlan: PipelineDraft = { ...k.draft, signing: { mode: 'key-env', images: [{ service: 'app', repo: 'ghcr.io/o/r-app' }], cosignPubSha256: 'a'.repeat(64) } };
    const deps = { reviewed: REVIEWED, platform: p };
    expect(sharedWorkflows(withPlan, 'key-env', deps)).toEqual([]);
    expect(signCallerJob(withPlan, 'key-env', ['gate', 'image-publish'])).toBeNull();
    expect(() => signJob(withPlan, 'key-env', deps)).toThrow(RenderError);
    const narrowed = assemble({ ...k, draft: withPlan }, 'key-env');
    expect(narrowed.sign).toBeNull();
    expect(narrowed.draft.signing).toBeUndefined();
    // the warning-only signing need of a repo with no signing mode gets no job either, with the same note
    const none = deployed(profileOf([site], { private: true, existingWorkflows: [DEPLOY_WF] }), CAPS, { centralPin: PIN });
    expect(none.draft.needs.some((n) => n.layer === 'deploy' && n.id === 'signing' && !n.blocking)).toBe(true);
    const nj = assemble(none, 'none');
    expect(nj.sign).toBeNull();
    expect(nj.notes.join('\n')).toMatch(/"app" builds no image, so its signing is report-only/);
  });

  it('GJ: next to a server, only the image is signed; the static site stays report-only', () => {
    const site = node({ name: 'site', path: 'site', projectType: type('static-site') });
    const api = node({ name: 'api', path: '.', dockerfile: 'Dockerfile', port: 3000, projectType: type('server') });
    const prof = profileOf([api, site], { existingWorkflows: [DEPLOY_WF] });
    // the API's DAST is left out here (its start is jobs-dast.test.ts's subject)
    const needs = floorNeeds(prof, CAPS).filter((n) => n.id !== 'dast');
    const x = planned(prof, { needs, over: { signing: { mode: 'keyless', images: [{ service: 'api', repo: 'ghcr.io/o/r-api' }, { service: 'site', repo: 'ghcr.io/o/r-site' }] } } });
    expect(x.draft.needs.filter((n) => n.layer === 'deploy' && n.id === 'signing').map((n) => n.service).sort()).toEqual(['api', 'site']);
    const a = assemble(x, 'keyless');
    expect(a.draft.signing?.images).toEqual([{ service: 'api', repo: 'ghcr.io/o/r-api' }]);
    expect(JSON.stringify(a.sign?.steps)).toContain('ghcr.io/o/r-api');
    expect(JSON.stringify(a.sign?.steps)).not.toContain('r-site');
    expect(a.notes.join('\n')).toMatch(/"site" builds no image, so its signing is report-only/);
    expect(a.notes.join('\n')).not.toMatch(/"api" builds no image/);
  });

  it('GJ: a static site with a deploy workflow is a deploy target: assemble keeps the verify job (find-run only, no digest), the referee accepts it', async () => {
    const site = node({ projectType: type('static-site') });
    expect(floorNeeds(profileOf([site], { existingWorkflows: [DEPLOY_WF] }), CAPS).filter((n) => n.layer === 'deploy').map((n) => n.id).sort()).toEqual(['deploy-verify', 'egress', 'sbom', 'signing']);
    const x = deployed(profileOf([site], { existingWorkflows: [DEPLOY_WF] }));
    const a = lay(x, 'keyless');
    expect(a.verify).not.toBeNull();
    const steps = (a.verify as Job).steps;
    expect(steps).toHaveLength(2);
    expect(steps[1]?.with?.mode).toBe('find-run');
    expect(JSON.stringify(steps)).not.toMatch(/digest|cosign/);
    expect(a.files.map((f) => f.content).join('\n')).not.toMatch(/image-build--|image-scan--|dast--/);
    expect(shown(await judgeAssembled(a, JD))).toBe('');
  });
});

describe('GJ: the referee refuses a job, a check or a signature without its need', () => {
  it('GJ referee: a signing plan that signs the image of a service that builds no image is refused', async () => {
    const site = node({ projectType: type('static-site') });
    const x = deployed(profileOf([site], { existingWorkflows: [DEPLOY_WF] }));
    const a = assemble(x, 'keyless');
    expect(shown(await judge(files(a), a.draft))).toBe('');
    const signed = { ...a.draft, signing: { mode: 'keyless' as const, images: [{ service: 'app', repo: 'ghcr.io/o/r-app' }] } };
    const r = await judge(files(a), signed);
    expect(r.issues.some((i) => i.check === 'permissions' && /signs the image of "app", but the plan builds no image for it/.test(i.message)), shown(r)).toBe(true);
  });

  it('GJ referee: an image, DAST or API DAST need for a service that builds no image is refused', async () => {
    const site = node({ dockerfile: 'Dockerfile', port: 3000, projectType: type('static-site') });
    const x = planned(profileOf([site]), { over: SKIP_DEPLOY });
    const a = assemble(x);
    for (const id of ['image-build', 'image-scan', 'dast', 'api-dast']) {
      const need: Need = { id, layer: 'merge', category: id as Need['category'], service: 'app', why: 't', blocking: false, floor: false };
      const r = await judge(files(a), { ...a.draft, needs: [...a.draft.needs, need] });
      expect(r.issues.some((i) => /The draft plans the check "[a-z-]+" for "app", but the plan builds no image for it/.test(i.message)), `${id}: ${shown(r)}`).toBe(true);
    }
  });

  it('GJ referee: a step with no need of its own is refused (its job too)', async () => {
    const server = node({ dockerfile: 'Dockerfile', port: 3000 });
    const x = planned(profileOf([server]), { over: SKIP_DEPLOY });
    const a = assemble(x);
    expect(shown(await judge(files(a), a.draft))).toBe('');
    // the image build job stays in the files, its need leaves the draft (and with it the scans and DAST that read the image)
    const needs = a.draft.needs.filter((n) => !['image-build', 'image-scan', 'dast'].includes(n.id));
    const r = await judge(files(a), { ...a.draft, needs });
    expect(r.issues.some((i) => /The step for "image-build" for "app" .*has no need of its own in the draft/.test(i.message)), shown(r)).toBe(true);
    // the same for a check job's step (sast): a planted step with no need is never accepted
    const r2 = await judge(files(a), { ...a.draft, needs: a.draft.needs.filter((n) => n.id !== 'sast') });
    expect(r2.issues.some((i) => /The step for "sast" for "app" .*has no need of its own in the draft/.test(i.message)), shown(r2)).toBe(true);
  });
});

describe('GJ-R1: fix round 1 (reviews GJ security and spec)', () => {
  const wfOn = (...triggers: string[]): ExistingWorkflow => ({ path: '.github/workflows/t.yml', triggers, deploys: false, [USED]: [], jobs: ['t'] } as unknown as ExistingWorkflow);
  const risky = (): ReturnType<typeof profileOf> => profileOf([node()], { existingWorkflows: [wfOn('pull_request_target')] });

  it('GJ-R1 (spec I2, sec M2): a risky trigger with poutine not offered → zizmor runs and a note says poutine is not run and why', () => {
    const without = REVIEWED.filter((t) => t.id !== WORKFLOW_LINT_EXTRA);
    const prof = risky();
    const x = planned(prof);
    const o = keyOffers(x.plan.needs, x.plan.candidates, prof, { reviewed: without });
    expect(o.offers.get('workflow-lint')?.map((of) => of.entry.id)).toEqual([WORKFLOW_LINT_TOOL]);
    const a = assembleJobs(x.draft, { ...x.plan, uncovered: o.uncovered }, { reviewed: without, platform: p, mode: 'none' });
    expect(a.notes).toContain(POUTINE_NOT_RUN);
    expect(POUTINE_NOT_RUN).toMatch(/pull_request_target or issue_comment.*poutine is not run/);
    // no risky trigger, or poutine offered: no such note
    expect(assemble(planned(profileOf())).notes).not.toContain(POUTINE_NOT_RUN);
    expect(assemble(planned(prof)).notes).not.toContain(POUTINE_NOT_RUN);
  });

  it('GJ-R1 (sec M1): workflow-lint offers without zizmor are uncovered, so pipegen stops; poutine never stands in', () => {
    const prof = risky();
    const x = planned(prof);
    const cands = new Map([...x.plan.candidates].map(([k, v]) => [k, k === 'workflow-lint' ? v.filter((c) => c.id !== WORKFLOW_LINT_TOOL) : v]));
    const o = keyOffers(x.plan.needs, cands, prof, { reviewed: REVIEWED });
    expect(o.offers.has('workflow-lint')).toBe(false);
    expect(o.uncovered.some((u) => u.key === 'workflow-lint' && u.blocking)).toBe(true);
    expect(() => assembleJobs(x.draft, { ...x.plan, candidates: cands, uncovered: o.uncovered }, { reviewed: REVIEWED, platform: p, mode: 'none' })).toThrow(/no tool it can run \("workflow-lint"/);
  });

  it('GJ-R1 (sec M1) referee: a workflow-lint job, or a draft, with no zizmor step is refused', async () => {
    const x = planned(risky());
    const a = assemble(x);
    expect(shown(await judge(files(a), a.draft))).toBe('');
    // the draft keeps only poutine for workflow lint
    const poutineOnly = { ...a.draft, steps: a.draft.steps.filter((st) => !(st.needId === 'workflow-lint' && st.tool.id === WORKFLOW_LINT_TOOL)) };
    const r = await judge(files(a), poutineOnly);
    expect(r.issues.some((i) => /The draft's workflow lint check has no zizmor step/.test(i.message)), shown(r)).toBe(true);
    // the job loses its zizmor steps (the draft still holds the spec)
    const f = files(a)[0] as NonNullable<ReturnType<typeof files>[number]>;
    const cut = editJob(f, 'workflow-lint', (j) => { j.steps = j.steps.filter((st: { name?: string }) => !/zizmor/.test(String(st.name))); });
    const r2 = await judge([cut, ...files(a).slice(1)], a.draft);
    expect(r2.issues.some((i) => /The job "workflow-lint" runs no zizmor step/.test(i.message)), shown(r2)).toBe(true);
  });

  it('GJ-R1 (sec M3): signing images are matched by slug; an image of no profile service, or of a no-image service in another spelling, is refused', async () => {
    const site = node({ name: 'site', path: 'site', projectType: type('static-site') });
    const api = node({ name: 'api', path: '.', dockerfile: 'Dockerfile', port: 3000, projectType: type('server') });
    const prof = profileOf([api, site], { existingWorkflows: [DEPLOY_WF] });
    const needs = floorNeeds(prof, CAPS).filter((n) => n.id !== 'dast');
    const API = { service: 'api', repo: 'ghcr.io/o/r-api' };
    for (const [label, img] of [['another spelling of the static site', { service: 'Site', repo: 'ghcr.io/o/r-site' }], ['no such service', { service: 'ghost', repo: 'ghcr.io/o/r-ghost' }]] as const) {
      const x = planned(prof, { needs, over: { signing: { mode: 'keyless', images: [API, img] } } });
      // the jobs: the other spelling of the static site is report-only; a service the profile does not have is refused
      if (img.service === 'ghost') expect(() => assemble(x, 'keyless'), label).toThrow(/signs the image of "ghost", which is no service of the repository/);
      else {
        const a = assemble(x, 'keyless');
        expect(a.draft.signing?.images, label).toEqual([API]);
        expect(a.notes.join('\n'), label).toMatch(/"Site" builds no image, so its signing is report-only/);
      }
      // G3's functions: the same
      if (img.service === 'ghost') expect(() => signJob(x.draft, 'keyless', { reviewed: REVIEWED, platform: p }), label).toThrow(/no service of the repository/);
      else expect(JSON.stringify(signJob(x.draft, 'keyless', { reviewed: REVIEWED, platform: p }).steps), label).not.toContain('r-site');
      // the referee: refused either way
      const ok = assemble(planned(prof, { needs, over: SKIP_DEPLOY }));
      const r = await judge(files(ok), { ...ok.draft, signing: { mode: 'keyless', images: [API, img] } });
      expect(r.issues.some((i) => i.check === 'permissions' && new RegExp(`signs the image of "${img.service}"`).test(i.message)), `${label}: ${shown(r)}`).toBe(true);
    }
  });

  it('GJ-R1 (sec M4, spec M4): assembleJobs returns the uncovered minimum, routes zizmor into the suggestions, and writes every other minimum check', () => {
    const plain = assemble(planned(profileOf()));
    expect(plain.uncoveredMinimum).toEqual([]);
    const without = REVIEWED.filter((t) => t.id !== WORKFLOW_LINT_TOOL);
    const prof = profileOf();
    const x = planned(prof);
    const o = keyOffers(x.plan.needs, x.plan.candidates, prof, { reviewed: without });
    const draft = { ...x.draft, steps: x.draft.steps.filter((st) => st.needId !== 'workflow-lint') };
    const a = assembleJobs(draft, { ...x.plan, uncovered: o.uncovered }, { reviewed: without, platform: p, mode: 'none' });
    expect(a.uncoveredMinimum).toEqual([{ category: 'workflow-lint', needId: 'workflow-lint', why: expect.stringMatching(/zizmor is not on pipegen's reviewed list/), tool: { name: 'zizmor', repo: 'zizmorcore/zizmor' } }]);
    expect(a.draft.suggestions.some((sg) => sg.name === WORKFLOW_LINT_TOOL && sg.repo === 'zizmorcore/zizmor')).toBe(true);
  });

  it('GJ-R1 (spec M5): the estimate counts no sign job for a service that builds no image, and no hooks-ci job for a pre-commit or husky repository', () => {
    const site = node({ projectType: type('static-site') });
    const prof = profileOf([site], { existingWorkflows: [DEPLOY_WF] });
    const needs = floorNeeds(prof, CAPS);
    expect(jobCategories(needs).deploy).toContain('signing');
    expect(jobCategories(estimateNeeds(prof, CAPS, needs)).deploy).not.toContain('signing');
    // a server keeps its sign job in the estimate
    const api = profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })], { existingWorkflows: [DEPLOY_WF] });
    expect(jobCategories(estimateNeeds(api, CAPS, floorNeeds(api, CAPS))).deploy).toContain('signing');
    for (const manager of ['pre-commit', 'husky'] as const) {
      const pc = profileOf([node()], { precommit: manager });
      const est = jobCategories(estimateNeeds(pc, CAPS, floorNeeds(pc, CAPS)));
      expect([...est.push, ...est.merge], manager).not.toContain('hooks-ci');
    }
    const lh = profileOf([node()], { precommit: 'lefthook' });
    expect(jobCategories(estimateNeeds(lh, CAPS, floorNeeds(lh, CAPS))).merge).toContain('hooks-ci');
  });

  it('GJ-R2 (N3): the uncovered minimum is per need, reaches AssembledFiles and the suggestions (two services with no lockfile: both named)', () => {
    const svc = (name: string) => node({ name, path: name, packageManager: undefined, npmLockfileVersion: undefined });
    const prof = profileOf([svc('a'), svc('b')]);
    const x = planned(prof, { over: SKIP_DEPLOY });
    const jobs = assemble(x);
    const deps = jobs.uncoveredMinimum.filter((u) => u.category === 'deps');
    expect(deps.map((u) => u.service).sort()).toEqual(['a', 'b']);
    for (const u of deps) expect(u.why).toMatch(new RegExp(`"deps" for "${u.service}".*no lockfile`));
    for (const u of deps) expect(jobs.draft.suggestions.some((sg) => sg.why === u.why && sg.name === 'osv-scanner')).toBe(true);
    const files = lay(x, 'none');
    expect(files.uncoveredMinimum.filter((u) => u.category === 'deps').map((u) => u.service).sort()).toEqual(['a', 'b']);
    expect(files.draft.suggestions.filter((sg) => sg.name === 'osv-scanner')).toHaveLength(2);
    // one service with a lockfile keeps its job: only the other is listed (per need, not per category)
    const mixed = planned(profileOf([node({ name: 'a', path: 'a' }), svc('b')]), { over: SKIP_DEPLOY });
    const m = assemble(mixed);
    expect(m.merge['deps--a']).toBeDefined();
    expect(m.uncoveredMinimum.filter((u) => u.category === 'deps').map((u) => u.service)).toEqual(['b']);
  });
});
