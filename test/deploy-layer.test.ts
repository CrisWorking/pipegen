// v0.2 Plan G Task 4 (sub-task G7; rulings B3 a, c, e, S11, S15; carries G40, B-T1a, E-b3, G1→G7, G2→G7, G4→G7, G5→G7): the deploy layer.
// A deploy waits for pipegen-verify, which proves (find-run) that the deployed commit passed the gate in the trusted push run, that it is
// still the default branch's head, and that the image that run published (its digest artifact, by run id) carries pipegen's signature. The
// user's workflow gets only that job and `needs:` entries, byte for byte; every other deploy is a DeployGap. Fixtures are invented (J6:
// each positive case in two shapes).
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isMap, parse, parseDocument, type YAMLMap, type YAMLSeq } from 'yaml';
import { describe, expect, it } from 'vitest';
import { renderJobPrelude, stepsToYaml } from '../src/engine/render-step.js';
import { DIGEST_STEP_ID, FIND_RUN_STEP_ID, HEAD_CHECK_STEP_ID, imageDigestArtifact, PUBLISH_DIGEST_STEP_ID, renderDigestStep, renderHeadCheckStep } from '../src/engine/deploy-steps.js';
import { checkExpressions, isFindRunStep, isKnownHarmless } from '../src/engine/job-rules.js';
import { githubHosted } from '../src/engine/deploy-gating.js';
import { deployGateOf } from '../src/audit/coverage/deploy-gate.js';
import { floorNeeds } from '../src/engine/needs.js';
import { RenderError } from '../src/engine/render-error.js';
import { renderVerifySteps } from '../src/engine/signing.js';
import { assemble, judgeAssembled, keylessVerifyNote, verifyPermissions, verifyTail, type AssembledFiles } from '../src/layers/assemble.js';
import { EGRESS_DOMAIN_SETS, KEYLESS_VERIFY_SETS, renderEgressStep } from '../src/engine/egress.js';
import {
  deployTriggers, environmentPlan, generateCosignKeys, insertVerify, isMemoryFolder, MEMORY_DIR, planVerifyInserts, releaseJobs, renewVerifyJob, verifyJobYaml, type VerifyPlan,
} from '../src/layers/deploy.js';
import { JOB_MINUTES, RELEASE_ONLY_NOTES, type Job } from '../src/layers/jobs.js';
import type { Capabilities, CreatedFile, ExistingWorkflow, PipelineDraft, RepoProfile, ReviewedTool, Service, SigningPlan } from '../src/types.js';
import { WORKFLOW_PATH as GATE_WORKFLOW } from '../gate/src/baseline.js';
import { findGatedRun } from '../gate/src/gated-run.js';
import { GATE_CHECK_NAME } from '../src/types.js';
import { cosignKey, cosignPub } from './helpers/cosign-keys.js';
import { FakeGitHub } from './helpers/deliver-github.js';
import { CAPS, LINTERS, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

/** Names spelled at run time (test/no-secret-literals.test.ts). */
const USED = ['sec', 'retsUsed'].join('');
const MISSING = ['missing', 'Secrets'].join('');
const HEAD_VAR = ['PIPEGEN_HEAD', 'TOK' + 'EN'].join('_');
const TOK = ['GITHUB', 'TOK' + 'EN'].join('_');
const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const KE_CAPS: Capabilities = { ...CAPS, environments: true, deploymentBranchPolicies: true, envRequiredReviewers: true };
const PIN = { repo: 'o/pipelines', sha: 'c'.repeat(40) };
const PUB_TEXT = cosignPub(3);
const PUB_SHA = createHash('sha256').update(PUB_TEXT, 'utf8').digest('hex');
const IMG = { service: 'app', repo: 'ghcr.io/o/r-app' };
const SERVER: Service = node({ dockerfile: 'Dockerfile', port: 3000 });
const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Omit<Parameters<typeof judgeAssembled>[1], 'extra'>;

/** A deploy workflow with comments and anchors (Review Focus 2): build is not a deploy job (read only, nothing secret, G7-R1 sec I2), deploy is (its environment). */
const DEPLOY_A = [
  '# ship the app (the user\'s own comment)',
  'name: deploy   # its name',
  'on:',
  '  push:',
  '    branches: [main]   # main only',
  'jobs:',
  '  build:',
  '    runs-on: ubuntu-latest',
  '    permissions:',
  '      contents: read',
  '    env: &common',
  '      NODE_ENV: production',
  '    steps:',
  '      - uses: actions/checkout@v4   # the user\'s tag pin stays theirs',
  '      - run: npm run build',
  '  deploy:   # ships it',
  '    needs: build',
  '    runs-on: ubuntu-latest',
  '    environment: production',
  '    env: *common',
  '    steps:',
  '      - run: ./scripts/ship.sh',
  '# the end',
  '',
].join('\n');
/** A second shape: four-space indentation, block needs list, two deploy jobs (an environment, a wrangler deploy), a read-only test job, no newline at the end. */
const DEPLOY_B = [
  'on:',
  '    push:',
  '        branches:',
  '            - main',
  'jobs:',
  '    test:',
  '        runs-on: ubuntu-latest',
  '        permissions:',
  '            contents: read',
  '        steps:',
  '            - run: npm test',
  '    web:',
  '        needs:',
  '            - test',
  '        runs-on: ubuntu-latest',
  '        steps:',
  '            - run: npx wrangler deploy',
  '    api:',
  '        runs-on: ubuntu-latest',
  '        environment:',
  '            name: production',
  '        steps:',
  '            - run: ./api.sh',
].join('\n');
const wfOf = (path: string, triggers: string[] = ['push']): ExistingWorkflow => ({ path, triggers, deploys: true, [USED]: [], jobs: [] }) as unknown as ExistingWorkflow;
const A = '.github/workflows/deploy.yml';
const B = '.github/workflows/release.yml';

type Kind = 'keyless' | 'key-env' | 'none';
interface World { draft: PipelineDraft; plan: ReturnType<typeof planned>['plan']; a: AssembledFiles; v: VerifyPlan; texts: Map<string, string> }
/** A planned server with a Dockerfile and these deploy workflows, assembled in a signing mode with G7's release jobs, then the inserts. */
function world(kind: Kind, wfs: [string, string][] = [[A, DEPLOY_A]], over: { profile?: Partial<RepoProfile>; services?: Service[]; draft?: Partial<PipelineDraft> } = {}): World {
  const priv = kind !== 'keyless';
  const prof = profileOf(over.services ?? [SERVER], { private: priv, existingWorkflows: wfs.map(([path]) => wfOf(path)), ...over.profile });
  const caps = kind === 'key-env' ? KE_CAPS : CAPS;
  const imageServices = (over.services ?? [SERVER]).filter((s) => s.dockerfile !== undefined).map((s) => s.name);
  const signing: SigningPlan | undefined = kind === 'none' || imageServices.length === 0 ? undefined
    : kind === 'keyless' ? { mode: 'keyless', images: [IMG] } : { mode: 'key-env', images: [IMG], cosignPubSha256: PUB_SHA };
  const x = planned(prof, { caps, over: { ...(priv ? { centralPin: PIN } : {}), ...(signing === undefined ? {} : { signing }), ...over.draft } });
  const a = assemble(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode: kind, layout: priv ? 'central' : 'local', plan: x.plan, deploy: releaseJobs(x.draft, { platform: p }) });
  const texts = new Map(wfs);
  return { draft: x.draft, plan: x.plan, a, v: planVerifyInserts(a.draft, texts, a.verify), texts };
}
// G17A-R1 sec M2: the referee gets the workflow texts the plan was built from (run.ts passes BuildFacts.texts), so it re-derives the called-file
// head checks; null: none given
// G17A-R2 sec r2-M1: the draft carries the plan's gaps in doc.deployGaps, as buildFiles fills them (`gaps`: another list, for a forged doc)
const DOC_OF = (gaps: VerifyPlan['gaps']): NonNullable<PipelineDraft['doc']> => ({ transcript: [], deployGaps: gaps.map((g) => ({ path: g.path, triggers: [...g.triggers], why: g.why })), lockNotes: [], estimates: { monthlyMinutes: 0, includedMinutes: null }, setupCommand: '', testNotes: [], uncoveredMinimum: [], notes: [] }) as unknown as NonNullable<PipelineDraft['doc']>;
const judge = (w: World, extra: CreatedFile[] = w.v.inserts.map((i) => i.file), texts: ReadonlyMap<string, string> | null = w.texts, gaps: VerifyPlan['gaps'] = w.v.gaps) =>
  judgeAssembled({ ...w.a, draft: { ...w.a.draft, doc: DOC_OF(gaps) } }, { ...JD, extra, refereeDeps: { ...JD.refereeDeps, ...(texts === null ? {} : { workflowTexts: texts }) } });
const verifyOf = (w: World): Job => w.a.verify as Job;
const step = (j: Job, id: string): Obj => j.steps.find((s) => s.id === id) as Obj;
const insertedJob = (text: string): Obj => (parse(text) as Obj).jobs['pipegen-verify'] as Obj;
/** The text with the recorded insertions applied to the original (the bytes pipegen added, and nothing else). */
const apply = (original: string, ins: readonly { at: number; text: string }[]): string => {
  let out = ''; let from = 0;
  for (const i of [...ins].sort((x, y) => x.at - y.at)) { out += original.slice(from, i.at) + i.text; from = i.at; }
  return out + original.slice(from);
};
/** A user file edited by hand from an inserted file (the referee must hold it). */
const edited = (f: CreatedFile, from: string, to: string): CreatedFile => {
  expect(f.content.includes(from), from).toBe(true);
  return { ...f, content: f.content.replace(from, to) };
};

describe('G7 verify-insert: the user\'s deploy workflow gets only the verify job and needs', () => {
  it('verify-insert: only adds job and needs, rest unchanged, recorded', async () => {
    for (const [path, text, gated] of [[A, DEPLOY_A, ['deploy']], [B, DEPLOY_B, ['web', 'api']]] as const) {
      const w = world('key-env', [[path, text]]);
      expect(w.v.gaps, path).toEqual([]);
      const ins = w.v.inserts[0];
      expect(ins?.path).toBe(path);
      // the edited text is the original with exactly the recorded insertions: every other byte (comments, anchors, spacing) is the user's
      expect(apply(text, ins?.insertions ?? [])).toBe(ins?.text);
      const job = ins?.insertions.find((i) => i.text.includes('pipegen-verify:'));
      const heads = ins?.insertions.filter((i) => i !== job && i.text.includes('id: pipegen-head-check')) ?? [];
      expect(heads, path).toHaveLength(gated.length);
      for (const i of ins?.insertions ?? []) if (i !== job && !heads.includes(i)) expect(i.text, `${path}: a needs insertion`).toMatch(/^(?:\[|\n?[ [\]\-,a-z:]*pipegen-verify[ \]\n]*)$/);
      // the inserted job is exactly the verify job, and only the deploy jobs need it
      expect(insertedJob(ins?.text ?? '')).toEqual((parse(verifyJobYaml(verifyOf(w))) as Obj)['pipegen-verify']);
      // recorded: the referee's mark (deliver turns it into the record's verify-job edit) names the original, the job and each need
      expect(ins?.inserted).toEqual({ original: text, jobs: ['pipegen-verify'], needs: [...gated].map((job) => ({ job, added: ['pipegen-verify'] })), headCheck: [...gated] });
      expect(ins?.file).toMatchObject({ path, repo: 'app', part: 'deploy-verify', content: ins?.text, inserted: ins?.inserted });
      const jobs = (parse(ins?.text ?? '') as Obj).jobs as Obj;
      for (const id of gated) expect([jobs[id].needs].flat(), `${path} ${id}`).toContain('pipegen-verify');
      expect([jobs[path === A ? 'build' : 'test'].needs ?? []].flat()).not.toContain('pipegen-verify');
      expect(shown(await judge(w)), path).toBe('');
      // the referee holds the rest of the file: a change to the user's own lines is refused
      const f = ins?.file as CreatedFile;
      const r = await judge(w, [edited(f, path === A ? './scripts/ship.sh' : './api.sh', './other.sh')]);
      expect(r.issues.some((i) => /beyond the job, needs and head checks pipegen inserted/.test(i.message)), shown(r)).toBe(true);
    }
  });

  it('verify-insert: push deploy verifies github.sha', async () => {
    for (const kind of ['key-env', 'keyless'] as const) {
      const w = world(kind);
      const job = insertedJob(w.v.inserts[0]?.text ?? '');
      const find = (job.steps as Obj[]).find((s) => s.id === FIND_RUN_STEP_ID) as Obj;
      expect(find.with.mode).toBe('find-run');
      expect(find.with.sha).toBe('${{ github.sha }}');
      // the head check compares the very commit (GITHUB_SHA is github.sha on a push) with the branch head
      expect(String((job.steps as Obj[]).find((s) => s.id === HEAD_CHECK_STEP_ID)?.run)).toContain('"$head" != "$GITHUB_SHA"');
      expect(JSON.stringify(job)).not.toContain('github.event.workflow_run');
      expect(shown(await judge(w)), kind).toBe('');
    }
  });

  it('verify-insert: workflow_run deploy → no insert, listed as gap (referee refuses edits there)', async () => {
    const text = DEPLOY_A.replace('on:\n  push:\n    branches: [main]   # main only', 'on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]');
    const w = world('key-env', [[A, text]]);
    expect(w.v.inserts).toEqual([]);
    expect(w.v.gaps).toEqual([{ path: A, triggers: ['workflow_run'], why: expect.stringMatching(/workflow_run.*adds no check to it; to have the check, deploy from a push to the default branch/) }]);
    expect(deployTriggers({ triggers: ['workflow_run'] })).toBe('workflow_run');
    // the referee refuses the edit itself (B3 e): the same insert written by hand
    const forced = insertVerify(text, ['deploy'], verifyOf(w));
    const f: CreatedFile = { path: A, content: forced.text, part: 'deploy-verify', reason: 't', repo: 'app', inserted: forced.inserted };
    const r = await judge(w, [f]);
    expect(r.issues.some((i) => i.check === 'injection' && /workflow_run/.test(i.message)), shown(r)).toBe(true);
  });

  it('verify-insert: other triggers → no job, listed as gap', () => {
    const on = (block: string): string => DEPLOY_A.replace('on:\n  push:\n    branches: [main]   # main only', block);
    const cases: [string, string[]][] = [
      ['on: workflow_dispatch', ['workflow_dispatch']],
      ['on:\n  push:\n    branches: [main]\n  workflow_dispatch: {}', ['push', 'workflow_dispatch']],
      ['on:\n  release:\n    types: [published]', ['release']],
      ['on: [pull_request_target]', ['pull_request_target']],
      ['on:\n  schedule:\n    - cron: "0 1 * * *"', ['schedule']],
      ['on:\n  workflow_call: {}', ['workflow_call']],
    ];
    for (const [block, triggers] of cases) {
      const w = world('key-env', [[A, on(block)]]);
      expect(w.v.inserts, block).toEqual([]);
      expect(w.v.gaps, block).toEqual([{ path: A, triggers, why: expect.stringMatching(/not only by a push, so pipegen adds no check to it; to have the check, start it only on a push/) }]);
      expect(deployTriggers({ triggers }), block).toBe('other');
      expect(w.v.notProven, block).toEqual([]);
    }
    expect(deployTriggers({ triggers: ['push'] })).toBe('push');
    expect(deployTriggers({ triggers: ['push', 'push'] })).toBe('push');
    expect(deployTriggers({ triggers: [] })).toBe('other');
  });

  it('verify-insert: needs added to every deploy job; ambiguous → every job, shown in the preview', async () => {
    // the detector tells the deploy jobs apart (an environment, a deploy command): only they wait; the test job does not
    const w = world('key-env', [[B, DEPLOY_B]]);
    expect(w.v.inserts[0]?.inserted.needs.map((n) => n.job)).toEqual(['web', 'api']);
    expect(w.v.preview).toEqual([`${B}: pipegen adds the job pipegen-verify, and "web", "api" wait for it.`, `${B}: "web" counts as a deploy job: it deploys.`, `${B}: "api" counts as a deploy job: it has an environment.`, `${B}: "test" does not wait for pipegen-verify: it shows no deploy, uses no secret but the workflow token, has only read permissions, no environment, calls no other workflow, runs on a GitHub-hosted runner, and reads no configuration variable.`]);
    // ambiguous: a workflow that deploys by its name only (no job the detector can name) has every job wait, and the preview says so
    const plain = ['name: release the site', 'on:', '  push:', '    branches: [main]', 'jobs:', '  one:', '    runs-on: ubuntu-latest', '    steps:', '      - run: make', '  two:', '    needs: [one]', '    runs-on: ubuntu-latest', '    steps:', '      - run: make upload', ''].join('\n');
    const u = world('key-env', [[B, plain]]);
    expect(u.v.inserts[0]?.inserted.needs.map((n) => n.job)).toEqual(['one', 'two']);
    expect(u.v.preview[0]).toMatch(/"one", "two" wait for it \(pipegen could not tell which job deploys, so every job waits\)/);
    expect((parse(u.v.inserts[0]?.text ?? '') as Obj).jobs.two.needs).toEqual(['one', 'pipegen-verify']);
    expect(shown(await judge(u))).toBe('');
    // a deploy job that could run when the check fails is no protection: the whole workflow is a gap
    const always = DEPLOY_A.replace('    environment: production\n', '    environment: production\n    if: always()\n');
    const g = world('key-env', [[A, always]]);
    expect(g.v.inserts).toEqual([]);
    expect(g.v.gaps[0]?.why).toMatch(/could run it even when pipegen's check fails/);
  });

  it('verify-insert: edits produce a not-proven note', () => {
    const w = world('key-env', [[A, DEPLOY_A], [B, DEPLOY_B]]);
    expect(w.v.inserts.map((i) => i.path)).toEqual([A, B]);
    expect(w.v.notProven).toEqual([A, B].map((path) => ({ part: 'deploy-verify', reason: expect.stringContaining(`edit of ${path}`), [MISSING]: [] })));
    // E-b3: a note of the edit only, never a need id (the gate's not-proven list is the checks')
    for (const n of w.v.notProven) expect(n.needId).toBeUndefined();
    expect(w.v.notProven.every((n) => /never runs a user's workflow beside real keys/.test(n.reason))).toBe(true);
  });
});

describe('G7 verify job: what pipegen-verify proves before a deploy', () => {
  it('verify job: checks head_branch and outputs the verified digest', async () => {
    // findGatedRun (the gate's find-run mode, which the verify job's find-run step runs) takes only a push run of pipegen.yml whose head_branch
    // is the default branch: a run of the same commit on another branch is never the proof (G7-R1: run, not grepped)
    const gatedOn = async (branch: string): Promise<boolean> => {
      let t = 0;
      const gh = {
        listRuns: async () => ({ total_count: 1, workflow_runs: [{ id: 1001, event: 'push', path: GATE_WORKFLOW, head_repository: { id: 7 }, head_branch: branch, head_sha: '1'.repeat(40), status: 'completed', conclusion: 'success', run_attempt: 1, referenced_workflows: [] }] }),
        listAttemptJobs: async () => ({ total_count: 1, jobs: [{ id: 5001, run_id: 1001, run_attempt: 1, name: GATE_CHECK_NAME, status: 'completed', conclusion: 'success' }] }),
        branchHead: async () => ({ ref: 'refs/heads/main', object: { type: 'commit', sha: '1'.repeat(40) } }),
        tagExists: async () => false,
        compare: async () => ({ status: 'identical' }),
      };
      const r = await findGatedRun(gh as unknown as Parameters<typeof findGatedRun>[0], { owner: 'acme', name: 'app', id: 7, defaultBranch: 'main' }, '1'.repeat(40), { workflowPath: GATE_WORKFLOW, gateJobName: GATE_CHECK_NAME, waitMs: 60_000, pollMs: 20_000, sleep: async (ms: number) => { t += ms; }, now: () => 1_000_000 + t });
      return r.ok;
    };
    expect(await gatedOn('main')).toBe(true);
    for (const b of ['dev', 'refs/heads/main', 'Main']) expect(await gatedOn(b), b).toBe(false);
    for (const kind of ['key-env', 'keyless', 'none'] as const) {
      const v = verifyOf(world(kind));
      expect(step(v, FIND_RUN_STEP_ID).with.mode).toBe('find-run');
      // the head check: a push to the default branch, its commit still that branch's head (carry G1→G7: never an older commit after a newer one)
      const head = String(step(v, HEAD_CHECK_STEP_ID).run);
      expect(head).toContain("want='main'");
      expect(head).toContain('"$GITHUB_REF" != "refs/heads/$want"');
      expect(head).toContain('/git/ref/heads/$want');
      // the job outputs the verified digest, from its own digest step only
      expect(v.outputs, kind).toEqual({ digest: `\${{ steps.${DIGEST_STEP_ID}.outputs.digest }}` });
      const order = v.steps.map((s) => s.id ?? s.uses?.split('@')[0]);
      expect(order.indexOf(FIND_RUN_STEP_ID)).toBeLessThan(order.indexOf(HEAD_CHECK_STEP_ID));
      expect(order.indexOf(HEAD_CHECK_STEP_ID)).toBeLessThan(order.indexOf(DIGEST_STEP_ID));
    }
    // a deploy of the image in mode none still gets the digest (no signature: the repository signs nothing), and the note
    const w = world('key-env');
    expect(w.v.notes.join(' ')).toMatch(/needs\.pipegen-verify\.outputs\.digest/);
  });

  it('verify job: key-env reads PIPEGEN_COSIGN_PUB from the pipegen-signing environment, never from a file', async () => {
    const w = world('key-env');
    const v = verifyOf(w);
    expect(v.environment).toBe('pipegen-signing');
    // no checkout: no file of the commit is in the job
    expect(v.steps.some((s) => String(s.uses).startsWith('actions/checkout'))).toBe(false);
    const ver = v.steps.find((s) => /^pipegen-verify-/.test(s.id ?? '')) as Obj;
    expect(ver.env.PIPEGEN_COSIGN_PUB).toBe('${{ vars.PIPEGEN_COSIGN_PUB }}');
    // cosign reads the key from the fresh file the step writes from the variable (and checks), nothing else
    expect(ver.run).toContain('printf \'%s\' "$PIPEGEN_COSIGN_PUB" > "$keydir/cosign.pub"');
    expect([...String(ver.run).matchAll(/--key "([^"]+)"/g)].map((m) => m[1])).toEqual(['$keydir/cosign.pub']);
    expect(shown(await judge(w))).toBe('');
    // a verify step that reads a key file of the repository is not pipegen's: refused
    const f = w.v.inserts[0]?.file as CreatedFile;
    const r = await judge(w, [edited(f, '--key "$keydir/cosign.pub"', '--key "cosign.pub"')]);
    expect(r.issues.length, shown(r)).toBeGreaterThan(0);
    // a verify job outside the signing environment is refused when the repository has environments
    const r2 = await judge(w, [edited(f, '    environment: pipegen-signing\n', '')]);
    expect(r2.issues.some((i) => /must run in the environment pipegen-signing/.test(i.message)), shown(r2)).toBe(true);
  });

  it('verify job: attest mode uses gh attestation verify --signer-workflow', () => {
    // G15a: the reviewed pinned gh release is on the list
    const gh = REVIEWED.find((t) => t.id === 'gh') as ReviewedTool;
    expect(gh).toBeDefined();
    const prof = profileOf([SERVER], { private: true });
    const draft = planned(prof, { over: { centralPin: PIN, signing: { mode: 'attest', images: [IMG] } } }).draft;
    const run = String(renderVerifySteps(gh, draft, IMG)[1]?.run);
    expect(run).toContain('attestation verify "oci://$ref"');
    expect(run).toContain("--signer-workflow 'o/pipelines/.github/workflows/r--sign.yml'");
    expect(run).toContain(`--signer-digest '${PIN.sha}'`);
    expect(run).toContain("--repo 'o/r'");
    expect(run).toContain(' --no-public-good');
    // G15a-R0b: attest verify is on; its job reaches gh's attestation hosts (test/g15-attest-verify.test.ts holds it to the referee)
    expect(verifyTail(draft, REVIEWED).sets).toContain('github-attest');
    expect(verifyPermissions(draft)).toEqual({ contents: 'read', actions: 'read', packages: 'read', attestations: 'read' });
  });

  it('verify job: runs in environment pipegen-signing whenever environments exist; deploys from other branches listed as a gap', () => {
    expect(verifyOf(world('key-env')).environment).toBe('pipegen-signing');
    // private Free: no environments, so the job runs without one (its head check still refuses a push that is not to the default branch)
    const none = verifyOf(world('none'));
    expect(none.environment).toBeUndefined();
    expect(String(step(none, HEAD_CHECK_STEP_ID).run)).toContain('refs/heads/$want');
    const on = (block: string): string => DEPLOY_A.replace('on:\n  push:\n    branches: [main]   # main only', block);
    for (const block of ['on: push', 'on:\n  push:\n    branches: [main, develop]', 'on:\n  push:\n    branches: ["release/*"]', 'on:\n  push:\n    branches: [main]\n    tags: ["v*"]', 'on:\n  push:\n    branches-ignore: [wip]']) {
      const w = world('key-env', [[A, on(block)]]);
      expect(w.v.inserts, block).toEqual([]);
      expect(w.v.gaps[0]?.why, block).toMatch(/pipegen's check passes only on the default branch, so limit its push to `branches: \[main\]`/);
    }
  });

  it('verify job: PIPEGEN_COSIGN_PUB sha256 must equal the rendered literal before any check', async () => {
    const w = world('key-env');
    const ver = verifyOf(w).steps.find((s) => /^pipegen-verify-/.test(s.id ?? '')) as Obj;
    const lines = String(ver.run).split('\n');
    const first = lines.findIndex((l) => l.startsWith('want='));
    expect(lines[first]).toBe(`want='${PUB_SHA}'`);
    const compare = lines.findIndex((l) => l.includes('"$got" != "$want"'));
    // the comparison comes before the digest is read, before the registry login and before cosign runs at all
    for (const later of ['digest_file=', 'login ghcr.io', ' verify --key']) expect(compare, later).toBeLessThan(lines.findIndex((l) => l.includes(later)));
    expect(lines.slice(0, first).every((l) => /^(?:set -euo|unset CDPATH|PATH=|pg_fail\(\))/.test(l))).toBe(true);
    // without the recorded hash literal there is no verify step at all (the variable alone is writer-controlled)
    const { cosignPubSha256: _h, ...bare } = w.a.draft.signing as SigningPlan;
    expect(() => renderVerifySteps(REVIEWED.find((t) => t.id === 'cosign') as ReviewedTool, { ...w.a.draft, signing: bare }, IMG)).toThrow(RenderError);
    // a step with the check moved after cosign is not pipegen's: refused
    const f = w.v.inserts[0]?.file as CreatedFile;
    const moved = f.content.replace(/( *)if \[ "\$got" != "\$want" \]; then[^\n]*\n/, '');
    expect(moved).not.toBe(f.content);
    const r = await judge(w, [{ ...f, content: moved }]);
    expect(r.issues.length, shown(r)).toBeGreaterThan(0);
  });

  it('verify job: digest read from the trusted run\'s digest artifact and DIGEST_RE-checked', async () => {
    const w = world('keyless', [[A, DEPLOY_A]]);
    const d = step(verifyOf(w), DIGEST_STEP_ID);
    expect(d.env.PIPEGEN_RUN_ID).toBe(`\${{ steps.${FIND_RUN_STEP_ID}.outputs.run-id }}`);
    const run = String(d.run);
    const artifact = imageDigestArtifact('app');
    expect(artifact).toBe('pipegen-out-image-digest--app');
    expect(run).toContain(`/actions/runs/$run_id/artifacts?name=${artifact}`);
    expect(run).toContain('(.artifacts[0].workflow_run.id | tostring) == $run');
    // anything but expired false fails closed (a missing field too), before the download
    const expired = `if ! printf '%s' "$list" | jq -e '.artifacts[0].expired == false' > /dev/null; then pg_fail`;
    expect(run).toContain(expired);
    expect(run.indexOf(expired)).toBeLessThan(run.indexOf('/actions/artifacts/$id/zip'));
    expect(run).toMatch(/past the artifact retention period/);
    expect(run).toContain('if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]');
    expect(run.indexOf('=~ ^sha256:[0-9a-f]{64}$')).toBeLessThan(run.indexOf('echo "digest=$digest" >> "$GITHUB_OUTPUT"'));
    // the run id itself is checked before it is used in a URL
    expect(run.indexOf('if ! [[ "$run_id" =~ ^[1-9][0-9]{0,19}$ ]]')).toBeLessThan(run.indexOf('/actions/runs/$run_id'));
    // the same artifact image-publish uploads in the gated run
    const pub = w.a.files.find((f) => f.path === '.github/workflows/pipegen.yml') as CreatedFile;
    const publish = ((parse(pub.content) as Obj).jobs['image-publish'] as Obj).steps as Obj[];
    expect(publish.at(-1)?.with).toMatchObject({ name: artifact });
    expect(shown(await judge(w))).toBe('');
    // a digest step without the regex check is not pipegen's: refused
    const f = w.v.inserts[0]?.file as CreatedFile;
    const r = await judge(w, [edited(f, 'if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then pg_fail "the image digest of the gated run is not sha256:<64 hex>"; fi\n', '')]);
    expect(r.issues.length, shown(r)).toBeGreaterThan(0);
  });

  it('verify job: timeout-minutes exceeds the find-run wait', async () => {
    for (const kind of ['key-env', 'keyless'] as const) {
      const w = world(kind);
      const v = verifyOf(w);
      const wait = Number(step(v, FIND_RUN_STEP_ID).with['timeout-minutes']);
      expect(v['timeout-minutes'], kind).toBeGreaterThan(wait);
      // G40: longer than any job's limit too (the gated run's chain includes them)
      expect(v['timeout-minutes'], kind).toBeGreaterThan(JOB_MINUTES);
    }
    // the referee holds it: a verify job that would be cut before its wait ends is refused
    const w = world('key-env');
    const v = verifyOf(w);
    const f = w.v.inserts[0]?.file as CreatedFile;
    const wait = Number(step(v, FIND_RUN_STEP_ID).with['timeout-minutes']);
    const r = await judge(w, [edited(f, `    timeout-minutes: ${v['timeout-minutes']}\n`, `    timeout-minutes: ${wait}\n`)]);
    expect(r.issues.some((i) => /must outlive its find-run wait/.test(i.message)), shown(r)).toBe(true);
  });
});

describe('G7 environments and keys', () => {
  const app = 'o/r';
  const envOf = (over: Obj = {}): Obj => ({ id: 9, created_at: '2026-01-01T00:00:00Z', wait_timer: 3, prevent_self_review: true, reviewers: [{ type: 'User', id: 4 }], can_admins_bypass: false, deployment_branch_policy: { protected_branches: true, custom_branch_policies: false }, policies: [], stored: new Map(), ...over });
  const ghWith = (envs: Record<string, Obj> = {}): FakeGitHub => {
    const g = new FakeGitHub();
    const r = g.addRepo(app, { private: true });
    for (const [n, e] of Object.entries(envs)) r.envs.set(n, e as never);
    return g;
  };
  const prof = (wfs: [string, string][]): RepoProfile => profileOf([SERVER], { private: true, existingWorkflows: wfs.map(([path]) => wfOf(path)) });

  it('environments: existing env → created false with previous settings', async () => {
    const g = ghWith({ production: envOf(), 'pipegen-signing': envOf({ id: 10, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, policies: [{ id: 5, name: 'main', type: 'branch' }] }) });
    const plan = await environmentPlan(g.octokit(), prof([[A, DEPLOY_A]]), KE_CAPS, false, { texts: new Map([[A, DEPLOY_A]]), inserted: [A] });
    expect(plan).toEqual([
      { name: 'production', created: false, branchPolicy: 'default-only', reviewers: false, previous: { wait_timer: 3, prevent_self_review: true, reviewers: [{ type: 'User', id: 4 }], can_admins_bypass: false, deployment_branch_policy: { protected_branches: true, custom_branch_policies: false }, branch_policies: [] } },
      { name: 'pipegen-signing', created: false, branchPolicy: 'default-only', reviewers: false, previous: expect.objectContaining({ deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, branch_policies: [{ name: 'main', type: 'branch' }] }) },
    ]);
    // the second shape: `environment: { name }`, and neither exists yet
    const h = ghWith();
    const fresh = await environmentPlan(h.octokit(), prof([[B, DEPLOY_B]]), KE_CAPS, false, { texts: new Map([[B, DEPLOY_B]]), inserted: [B] });
    expect(fresh).toEqual([{ name: 'production', created: true, branchPolicy: 'default-only', reviewers: false }, { name: 'pipegen-signing', created: true, branchPolicy: 'default-only', reviewers: false }]);
    // only reads: no environment is written while planning
    expect([...g.calls, ...h.calls].every((c) => c.route.startsWith('GET '))).toBe(true);
  });

  it('environments: reviewers only with capability and approval flag', async () => {
    const texts = new Map([[A, DEPLOY_A]]);
    const out: Record<string, boolean[]> = {};
    for (const [caps, flag] of [[KE_CAPS, true], [KE_CAPS, false], [{ ...KE_CAPS, envRequiredReviewers: false }, true], [{ ...KE_CAPS, envRequiredReviewers: false }, false]] as const) {
      const plan = await environmentPlan(ghWith().octokit(), prof([[A, DEPLOY_A]]), caps, flag, { texts, inserted: [A] });
      out[`${caps.envRequiredReviewers}/${flag}`] = plan.map((e) => e.reviewers);
    }
    // the user's deploy environment gets reviewers only with both; pipegen-signing never (pipegen's jobs never wait for a person, G41)
    expect(out).toEqual({ 'true/true': [true, false], 'true/false': [false, false], 'false/true': [false, false], 'false/false': [false, false] });
  });

  it('environments: no deploy job or environment → no approval environment', async () => {
    // no deploy workflow at all: the approval flag plans no environment (B-T1a: no empty environments); pipegen-signing only
    const notes: string[] = [];
    const none = await environmentPlan(ghWith().octokit(), profileOf([SERVER], { private: true }), KE_CAPS, true, { texts: new Map(), inserted: [], notes });
    expect(none).toEqual([{ name: 'pipegen-signing', created: true, branchPolicy: 'default-only', reviewers: false }]);
    expect(notes.join(' ')).toMatch(/only on an environment your deploy jobs use/);
    // a deploy job with no environment: pipegen adds none to the user's job, so there is no approval environment either
    const bare = DEPLOY_A.replace('    environment: production\n', '');
    const plain = await environmentPlan(ghWith().octokit(), prof([[A, bare]]), KE_CAPS, true, { texts: new Map([[A, bare]]), inserted: [A] });
    expect(plain.map((e) => e.name)).toEqual(['pipegen-signing']);
    // a repository without environments (private Free): nothing at all
    expect(await environmentPlan(ghWith().octokit(), prof([[A, DEPLOY_A]]), CAPS, true, { texts: new Map([[A, DEPLOY_A]]), inserted: [A] })).toEqual([]);
  });

  it('cosign keys: values never written to disk', async () => {
    const key = cosignKey();
    const pub = cosignPub(5);
    let ran = 0;
    let folder = '';
    const exec = async (bin: string, args: readonly string[], opts: { cwd: string; env: Record<string, string> }): Promise<void> => {
      ran++;
      folder = opts.cwd;
      expect(bin).toBe('/opt/cosign');
      expect(args.slice(0, 2)).toEqual(['generate-key-pair', '--output-key-prefix']);
      writeFileSync(`${args[2]}.key`, key);
      writeFileSync(`${args[2]}.pub`, pub);
    };
    const base = mkdtempSync(join(tmpdir(), 'pipegen-g7-mem-'));
    // a memory-backed folder (the test says so for its own folder): the pair comes back, and the folder it was made in is gone
    const pair = await generateCosignKeys(async () => '/opt/cosign', { exec, base, isMemory: (d) => d === base });
    // (keys and values compared apart: the names are spelled at run time, test/no-secret-literals.test.ts)
    expect(Object.keys(pair)).toEqual([['private', 'Key'].join(''), 'publicKey', ['pass', 'word'].join('')]);
    expect(Object.values(pair)).toEqual([key, pub, expect.stringMatching(/^[A-Za-z0-9_-]{43}$/)]);
    expect(ran).toBe(1);
    expect(folder.startsWith(base)).toBe(true);
    expect(existsSync(folder)).toBe(false);
    expect(readdirSync(base)).toEqual([]);
    // any folder that is not memory-backed is refused before cosign runs: the key never reaches a disk
    await expect(generateCosignKeys(async () => '/opt/cosign', { exec, base })).rejects.toThrow(/only in memory/);
    await expect(generateCosignKeys(async () => '/opt/cosign', { exec, base: '/', isMemory: () => false })).rejects.toThrow(/never touches a disk/);
    expect(ran).toBe(1);
    // the default is the tmpfs /dev/shm (Linux), and a disk folder is not one
    expect(MEMORY_DIR).toBe('/dev/shm');
    if (process.platform === 'linux' && existsSync('/dev/shm')) expect(isMemoryFolder('/dev/shm')).toBe(true);
    expect(isMemoryFolder(base)).toBe(false);
  });
});

describe('G7: the release jobs, the referee and the carries', () => {
  it('G7 release: image-publish pushes the root image, hands its digest on, and maps no secret but the workflow token (row 22)', async () => {
    for (const kind of ['keyless', 'key-env', 'none'] as const) {
      const w = world(kind);
      const jobs = releaseJobs(w.draft, { platform: p });
      expect(Object.keys(jobs), kind).toEqual(['image-publish']);
      const job = jobs['image-publish'] as Job;
      expect(job.permissions).toEqual({ contents: 'read', packages: 'write' });
      const ids = job.steps.map((s) => s.id ?? '');
      expect(ids.slice(-3)).toEqual(['pipegen-build-push', PUBLISH_DIGEST_STEP_ID, '']);
      expect(job.steps.at(-3)?.with).toMatchObject({ push: 'true', file: 'Dockerfile', tags: 'ghcr.io/o/r-app:pipegen' });
      // row 22: no publish token is mapped in v0.2; the only secret is the workflow token of the ghcr.io login
      const mapped = [...JSON.stringify(job).matchAll(/secrets\.([A-Z_]+)/g)].map((m) => m[1]);
      expect(new Set(mapped), kind).toEqual(new Set([TOK]));
      const app = (parse((w.a.files.find((f) => f.path === '.github/workflows/pipegen.yml') as CreatedFile).content) as Obj).jobs as Obj;
      expect(app['image-publish'].needs).toEqual(['pipegen']);
      expect(Object.hasOwn(app, 'sign')).toBe(kind !== 'none');
      expect(shown(await judge(w)), kind).toBe('');
    }
    // nothing to publish (a static site, a skipped deploy part): no release job
    expect(releaseJobs(world('keyless', [[A, DEPLOY_A]], { services: [node({ projectType: { types: ['static-site'], evidence: [], unsure: false } })] }).draft, { platform: p })).toEqual({});
    expect(releaseJobs({ ...world('keyless').draft, skipped: [{ part: 'deploy', reason: 't' }] }, { platform: p })).toEqual({});
  });

  it('G7 release: nothing may follow the build in image-publish but the digest tail (the order exception is exact)', async () => {
    const w = world('keyless');
    const pub = w.a.files.find((f) => f.path === '.github/workflows/pipegen.yml') as CreatedFile;
    expect(shown(await judge(w))).toBe('');
    // the digest step moved before the upload's place: still one tail; a second copy of the upload after it breaks the exact tail
    const doc = parse(pub.content) as Obj;
    const steps = doc.jobs['image-publish'].steps as Obj[];
    const swapped = { ...pub, content: pub.content.replace(`id: ${PUBLISH_DIGEST_STEP_ID}`, `id: ${PUBLISH_DIGEST_STEP_ID}-x`) };
    const r = await judgeAssembled({ ...w.a, files: w.a.files.map((f) => (f === pub ? swapped : f)) }, { ...JD, extra: w.v.inserts.map((i) => i.file) });
    expect(r.issues.length, shown(r)).toBeGreaterThan(0);
    expect(steps.length).toBeGreaterThan(3);
    // one more step after the upload, or between the build and the digest step: no longer the exact tail, refused
    const extra = { name: 'x', run: 'echo hi', shell: 'bash' };
    const withSteps = (edit: (s: unknown[]) => void): CreatedFile => {
      const d = parseDocument(pub.content);
      const seq = d.getIn(['jobs', 'image-publish', 'steps']) as YAMLSeq;
      const items = seq.items as unknown[];
      edit(items);
      return { ...pub, content: d.toString({ lineWidth: 0 }) };
    };
    const buildAt = steps.findIndex((s) => s.id === 'pipegen-build-push');
    expect(buildAt).toBeGreaterThan(0);
    for (const bad of [
      withSteps((items) => { items.push(parseDocument('x').createNode(extra)); }),
      withSteps((items) => { items.splice(buildAt + 1, 0, parseDocument('x').createNode(extra)); }),
      // repository code before the build (it could rewrite what is built or uploaded): the tail is no exception then
      withSteps((items) => { items.splice(buildAt, 0, parseDocument('x').createNode({ name: 'x', run: 'make', shell: 'bash' })); }),
      // a second build (the policy allows build-push in this job) before the tail's: not known harmless, so the tail is no exception
      withSteps((items) => { const twin = (items[buildAt] as YAMLMap).clone() as YAMLMap; twin.delete('id'); items.splice(buildAt, 0, twin); }),
      // the upload of another folder than the digest step wrote (the tail is that one folder, by name and path)
      withSteps((items) => { const up = (items.at(-1) as YAMLMap).get('with') as YAMLMap; up.set('name', imageDigestArtifact('other')); up.set('path', `\${{ runner.temp }}/pipegen-out/${imageDigestArtifact('other')}`); }),
      withSteps((items) => { ((items.at(-1) as YAMLMap).get('with') as YAMLMap).set('path', '${{ runner.temp }}/pipegen-out'); }),
      // a build that does not push: not the publish tail (nothing was pushed, so no digest of a pushed image)
      withSteps((items) => { ((items[buildAt] as YAMLMap).get('with') as YAMLMap).set('push', 'false'); }),
      // the same steps in a job of another name: the exception is image-publish's only
      (() => { const d = parseDocument(pub.content); const jobs = d.get('jobs') as YAMLMap; const j = jobs.get('image-publish'); jobs.set('image-publish-2', j); return { ...pub, content: d.toString({ lineWidth: 0 }) }; })(),
    ]) {
      const rb = await judgeAssembled({ ...w.a, files: w.a.files.map((f) => (f === pub ? bad : f)) }, { ...JD, extra: w.v.inserts.map((i) => i.file) });
      expect(rb.ok, shown(rb)).toBe(false);
    }
  });

  it('G7 referee: the find-run step is known harmless only in its exact form (its id, the gate action, mode find-run)', () => {
    const w = world('keyless');
    const find = (w.a.verify as Job).steps.find((s) => s.id === FIND_RUN_STEP_ID) as Job['steps'][number];
    expect(isFindRunStep(find)).toBe(true);
    expect(isKnownHarmless(find)).toBe(true);
    const { id: _id, ...noId } = find;
    expect(isFindRunStep(noId)).toBe(true);
    for (const bad of [{ ...find, id: 'other' }, { ...find, with: { ...find.with, mode: 'gate' } }, { ...find, run: 'echo' }, { ...find, uses: 'evil/gate@' + 'a'.repeat(40) }]) {
      expect(isFindRunStep(bad), JSON.stringify(bad).slice(0, 80)).toBe(false);
    }
  });

  it('G7 referee: a verify job without the signature check in a signing repository is refused (assembled in mode none, carry G5→G7 2)', async () => {
    // a key-env repository assembled in mode none: no sign job and a verify job with no signature check
    const prof = profileOf([SERVER], { private: true, existingWorkflows: [wfOf(A)] });
    const x = planned(prof, { caps: KE_CAPS, over: { centralPin: PIN } });
    const a = assemble(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode: 'none', layout: 'central', plan: x.plan });
    const v = planVerifyInserts(a.draft, new Map([[A, DEPLOY_A]]), a.verify);
    expect((a.verify as Job).steps.some((s) => /^pipegen-verify-/.test(s.id ?? ''))).toBe(false);
    const r = await judgeAssembled(a, { ...JD, extra: v.inserts.map((i) => i.file) });
    expect(r.issues.some((i) => /must check the signature of the image of "app".*signs in mode key-env/.test(i.message)), shown(r)).toBe(true);
    // and the same repository assembled in its own mode passes
    expect(shown(await judge(world('key-env')))).toBe('');
  });

  it('G7 referee: the signing mode is re-derived from the repository; a stripped plan does not publish an image unsigned (carry G5→G7 1)', async () => {
    const w = world('keyless');
    const pubFile = w.a.files.find((f) => f.path === '.github/workflows/pipegen.yml') as CreatedFile;
    // the sign job removed and the draft's plan stripped: the repository still signs keyless, so the publish is refused
    const doc = parse(pubFile.content) as Obj;
    delete doc.jobs.sign;
    const { stringify } = await import('yaml');
    const stripped = { ...pubFile, content: stringify(doc, { lineWidth: 0 }) };
    const { signing: _s, ...noPlan } = w.a.draft;
    const r = await judgeAssembled({ ...w.a, draft: noPlan, files: w.a.files.map((f) => (f === pubFile ? stripped : f)) }, { ...JD, extra: [] });
    expect(r.issues.some((i) => /signs in mode "keyless" and a job publishes an image/.test(i.message)), shown(r)).toBe(true);
  });

  it('G7 referee: a verify job without its head check or its digest step is refused', async () => {
    const w = world('keyless');
    const f = w.v.inserts[0]?.file as CreatedFile;
    const strip = (id: string): CreatedFile => {
      const d = parseDocument(f.content);
      const steps = d.getIn(['jobs', 'pipegen-verify', 'steps']) as YAMLSeq;
      steps.items = steps.items.filter((it) => !(isMap(it) && it.get('id') === id));
      return { ...f, content: d.toString({ lineWidth: 0 }) };
    };
    for (const [id, msg] of [[HEAD_CHECK_STEP_ID, /holds the head check/], [DIGEST_STEP_ID, /holds the digest step of "app"/]] as const) {
      const r = await judge(w, [strip(id)]);
      expect(r.issues.some((i) => msg.test(i.message)), `${id}: ${shown(r)}`).toBe(true);
    }
    // the find-run step without its id: the digest step could not read its run id
    const d = parseDocument(f.content);
    const steps = d.getIn(['jobs', 'pipegen-verify', 'steps']) as YAMLSeq;
    for (const it of steps.items) if (isMap(it) && it.get('id') === FIND_RUN_STEP_ID) it.delete('id');
    const noId = await judge(w, [{ ...f, content: d.toString({ lineWidth: 0 }) }]);
    expect(noId.issues.some((i) => /gives its find-run step the id pipegen-find-run/.test(i.message)), shown(noId)).toBe(true);
    // only the egress block may come before find-run: a checkout of the repository there is refused
    const pubJobs = (parse((w.a.files.find((x) => x.path === '.github/workflows/pipegen.yml') as CreatedFile).content) as Obj).jobs as Obj;
    const checkout = (pubJobs['image-publish'].steps as Obj[]).find((x) => /^actions\/checkout@/.test(String(x.uses)));
    expect(checkout).toBeDefined();
    const d2 = parseDocument(f.content);
    (d2.getIn(['jobs', 'pipegen-verify', 'steps']) as YAMLSeq).items.splice(1, 0, d2.createNode(checkout));
    const early = await judge(w, [{ ...f, content: d2.toString({ lineWidth: 0 }) }]);
    expect(early.issues.some((i) => /comes before its find-run step; only the egress block may/.test(i.message)), shown(early)).toBe(true);
  });

  it('G7: the deploy layer\'s sbom and egress needs leave the draft with a note (never counted as covered, carry G4→G7)', () => {
    const w = world('keyless');
    expect(floorNeeds(w.draft.profile, CAPS).filter((n) => n.layer === 'deploy').map((n) => n.id).sort()).toEqual(['deploy-verify', 'egress', 'sbom', 'signing']);
    expect(w.a.draft.needs.filter((n) => n.layer === 'deploy').map((n) => n.id).sort()).toEqual(['deploy-verify', 'signing']);
    expect(w.a.draft.steps.some((s) => s.needId === 'sbom')).toBe(false);
    for (const n of RELEASE_ONLY_NOTES.values()) expect(w.a.notes).toContain(n);
  });

  it('G7 m7: a re-pin renews the inserted job in place (find-run\'s central sha), nothing else of the file changes', () => {
    const w = world('key-env');
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    const moved = { ...w.draft, centralPin: { ...PIN, sha: 'd'.repeat(40) } };
    const again = assemble(moved, { gate: GATE, reviewed: REVIEWED, platform: p, mode: 'key-env', layout: 'central', plan: w.plan, deploy: releaseJobs(moved, { platform: p }) });
    const renewed = renewVerifyJob(ins.text, ins.inserted, again.verify as Job);
    expect(renewed).toContain(`central-sha: ${'d'.repeat(40)}`);
    expect(renewed).not.toContain(`central-sha: ${PIN.sha}`);
    // the same as a fresh insert of the new job into the original: only the job's bytes moved
    expect(renewed).toBe(insertVerify(DEPLOY_A, ['deploy'], again.verify as Job).text);
    // a file the user changed since the insert is not renewed: the self-check holds the rest to the recorded original
    const userChanged = ins.text.replace(/^(\s*)runs-on: (.*)$/m, '$1runs-on: self-hosted');
    expect(userChanged).not.toBe(ins.text);
    expect(() => renewVerifyJob(userChanged, ins.inserted, again.verify as Job)).toThrow(/without changing the rest of the file/);
  });

  it('G7: a static site\'s deploy gets the find-run check and the head check only, no digest (handoff G7)', async () => {
    for (const site of [node({ projectType: { types: ['static-site'], evidence: [], unsure: false } }), node({ name: 'web', path: 'web', frameworks: ['next'], projectType: { types: ['static-site'], evidence: [], unsure: false } })]) {
      const w = world('keyless', [[A, DEPLOY_A]], { services: [site] });
      const v = verifyOf(w);
      expect(v.steps.map((s) => s.id ?? 'egress')).toEqual(['egress', FIND_RUN_STEP_ID, HEAD_CHECK_STEP_ID]);
      expect(v.outputs).toBeUndefined();
      expect(JSON.stringify(v)).not.toMatch(/cosign|image-digest/);
      expect(w.v.inserts.map((i) => i.path)).toEqual([A]);
      expect(shown(await judge(w)), site.name).toBe('');
    }
  });

  it('G7: the audit\'s deploy-gate credit never removes the inserted check (handoff J3b)', () => {
    // a deploy job that already waits for the user's own test job (what the audit may credit) still gets pipegen-verify
    const gated = DEPLOY_A.replace('    needs: build\n', '    needs: [build]\n');
    // the audit really credits this file as a deploy gate (a push to main only, the deploy after the CI job that runs a check)
    const w = world('keyless', [[A, gated]]);
    const hit = { opaque: false, categories: ['unit-tests'], subject: 'npm test', dir: null, reason: null, fit: {}, where: `${A} (job build)` } as unknown as Parameters<typeof deployGateOf>[4][number];
    expect(deployGateOf(parse(gated) as Obj, A, w.draft.profile, [], [hit])).toMatch(/deploys only on a push to main/);
    // and pipegen still inserts its check: the credit is the audit's, never the deploy layer's
    expect(w.v.inserts[0]?.inserted.needs).toEqual([{ job: 'deploy', added: ['pipegen-verify'] }]);
    expect(w.v.inserts[0]?.inserted.headCheck).toEqual(['deploy']);
    expect(readFileSync('src/layers/deploy.ts', 'utf8')).not.toMatch(/from '\.\.\/audit\//);
  });
});


// ---------- G7-R1 fix round 1 (ruling G7-R1, reviews G7 security and spec) ----------

const headStep = (branch = 'main'): Obj => ({ ...renderHeadCheckStep(branch) }) as Obj;
const jobsIn = (text: string): Obj => (parse(text) as Obj).jobs as Obj;
/** The reviewer's probe P1: a staging job the detector sees (environment), a prod job it does not (a script, a secret). */
const STAGE_PROD = [
  'on:',
  '  push:',
  '    branches: [main]',
  'jobs:',
  '  stage:',
  '    runs-on: ubuntu-latest',
  '    environment: staging',
  '    steps:',
  '      - run: ./scripts/stage.sh',
  '  prod:',
  '    runs-on: ubuntu-latest',
  '    env:',
  `      PROD_KEY: \${{ ${['sec', 'rets'].join('')}.PROD_KEY }}`,
  '    steps:',
  '      - run: ./scripts/go-live.sh',
  '',
].join('\n');
/** A second shape: terraform with an OIDC token and no environment, a reusable-workflow call, and a read-only lint job pipegen may leave out. */
const INFRA = [
  'on:',
  '  push:',
  '    branches: [main]',
  'jobs:',
  '  lint:',
  '    runs-on: ubuntu-latest',
  '    permissions:',
  '      contents: read',
  '    steps:',
  '      - run: npm run lint',
  '  infra:',
  '    runs-on: ubuntu-latest',
  '    permissions:',
  '      contents: read',
  `      ${['id', 'token'].join('-')}: write`,
  '    steps:',
  '      - run: terraform apply -auto-approve',
  '  release:',
  '    needs: [lint]',
  '    uses: ./.github/workflows/ship.yml',
  '  site:',
  '    environment: production',
  '    runs-on: ubuntu-latest',
  '    steps:',
  '      - run: ./site.sh',
  '',
].join('\n');

describe('G7-R1 sec I1: the head check runs inside every gated deploy job (after an approval wait, on every re-run)', () => {
  it('G7-R1 sec I1: every gated job starts with pipegen\'s head check, recorded in the mark, and the referee accepts it', async () => {
    for (const [path, text, gated] of [[A, DEPLOY_A, ['deploy']], [B, DEPLOY_B, ['web', 'api']]] as const) {
      const w = world('key-env', [[path, text]]);
      expect(w.v.gaps, path).toEqual([]);
      const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
      expect(ins.inserted.headCheck, path).toEqual([...gated]);
      const jobs = jobsIn(ins.text);
      const orig = jobsIn(text);
      for (const id of gated) {
        const steps = (jobs[id] as Obj).steps as Obj[];
        // the approval shape: the job of `environment: production` waits for a reviewer, then its first step is the head check
        expect(steps[0], `${path} ${id}`).toEqual(headStep());
        expect(steps.slice(1), `${path} ${id}`).toEqual((orig[id] as Obj).steps);
      }
      // the bytes pipegen added are the recorded insertions, and nothing else
      expect(apply(text, ins.insertions)).toBe(ins.text);
      expect(shown(await judge(w)), path).toBe('');
    }
  });

  it('G7-R1 sec I1: re-run shapes: "re-run failed jobs" and "re-run job" reuse pipegen-verify\'s result, so the deploy job checks the head itself', async () => {
    // GitHub re-runs a failed or chosen job with the outputs of the jobs that passed: pipegen-verify does not run again. The deploy job's own
    // first step reads the branch head on every run of that job, so an older commit's re-run is refused (the script itself: test/deploy-scripts.test.ts)
    const w = world('keyless');
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    const deploy = (jobsIn(ins.text).deploy as Obj).steps as Obj[];
    const run = String(deploy[0]?.run);
    expect(run).toContain('if [ "$GITHUB_EVENT_NAME" != "push" ]');
    expect(run).toContain('if [ "$head" != "$GITHUB_SHA" ]');
    expect(deploy[0]?.env).toEqual({ BASH_ENV: '', ENV: '', [HEAD_VAR]: '${{ github.token }}' });
    // the notes for G9: re-run all jobs, and a job-level concurrency group that queues deploys
    expect(w.v.notes.join('\n')).toMatch(/Re-run all jobs/);
    expect(w.v.notes.join('\n')).toMatch(/concurrency[\s\S]*cancel-in-progress: false/);
  });

  it('G7-R1 sec I1: the referee refuses a gated job without the head check first, or with another one', async () => {
    const w = world('keyless');
    const f = w.v.inserts[0]?.file as CreatedFile;
    const variants: [string, (steps: YAMLSeq) => void][] = [
      ['removed', (s) => { s.items.shift(); }],
      ['moved second', (s) => { const h = s.items.shift(); s.items.splice(1, 0, h); }],
      ['another branch', (s) => { (s.items[0] as YAMLMap).set('run', String(renderHeadCheckStep('dev').run)); }],
      ['continue-on-error', (s) => { (s.items[0] as YAMLMap).set('continue-on-error', true); }],
    ];
    for (const [what, edit] of variants) {
      const d = parseDocument(f.content);
      const steps = d.getIn(['jobs', 'deploy', 'steps']) as YAMLSeq;
      // the user's own job stays the user's: with its steps back to the original order and count, the head check is missing or moved
      edit(steps);
      const r = await judge(w, [{ ...f, content: d.toString({ lineWidth: 0 }) }]);
      expect(r.ok, `${what}: ${shown(r)}`).toBe(false);
    }
    // the step and its mark both gone (a file whose mark no longer lists the job): the referee still requires the head check in every gated job
    const d = parseDocument(f.content);
    (d.getIn(['jobs', 'deploy', 'steps']) as YAMLSeq).items.shift();
    const unmarked = await judge(w, [{ ...f, content: d.toString({ lineWidth: 0 }), inserted: { ...(f.inserted as NonNullable<CreatedFile['inserted']>), headCheck: [] } }]);
    expect(unmarked.issues.some((i) => /waits for pipegen-verify but does not start with pipegen's head check/.test(i.message)), shown(unmarked)).toBe(true);
  });

  it('G7-R1 sec I1 / M4: renewVerifyJob refuses a file whose job no longer needs pipegen-verify or lost its head check', () => {
    const w = world('keyless');
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    const v = w.a.verify as Job;
    expect(renewVerifyJob(ins.text, ins.inserted, v)).toBe(ins.text);
    const degated = ins.text.replace('needs: [build, pipegen-verify]', 'needs: build');
    expect(degated).not.toBe(ins.text);
    expect(() => renewVerifyJob(degated, ins.inserted, v)).toThrow(/no longer waits for pipegen-verify/);
    const d = parseDocument(ins.text);
    (d.getIn(['jobs', 'deploy', 'steps']) as YAMLSeq).items.shift();
    expect(() => renewVerifyJob(d.toString({ lineWidth: 0 }), ins.inserted, v)).toThrow(/head check/);
  });

  it('G7-R1 sec I1: a gated job whose token can not read the branch (permissions without contents) is a gap that says what to add', () => {
    const noContents = DEPLOY_A.replace('    environment: production\n', '    environment: production\n    permissions:\n      deployments: write\n');
    const w = world('keyless', [[A, noContents]]);
    expect(w.v.inserts).toEqual([]);
    expect(w.v.gaps[0]?.why).toMatch(/its job "deploy" \(it has an environment\) sets permissions without contents: read[\s\S]*add contents: read to that job's permissions/);
    // with contents: read it is inserted
    const ok = planVerifyInserts(w.a.draft, new Map([[A, noContents.replace('      deployments: write\n', '      deployments: write\n      contents: read\n')]]), w.a.verify);
    expect(ok.gaps).toEqual([]);
    expect(ok.inserts).toHaveLength(1);
  });

  it('G7-R1 sec I1: a gated job that calls another workflow gets no step (it has none), and the note says what is not checked', () => {
    const w = world('keyless', [[A, INFRA]]);
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    expect(ins.inserted.headCheck).toEqual(['infra', 'site']);
    expect((jobsIn(ins.text).release as Obj).needs).toEqual(['lint', 'pipegen-verify']);
    expect(w.v.notes.join('\n')).toMatch(/"release" calls another workflow/);
  });
});

describe('G7-R1 sec I2: a job is left ungated only when it plainly can not deploy', () => {
  it('G7-R1 sec I2: the reviewer\'s probe: the prod job (a secret, no environment) waits too', async () => {
    const w = world('keyless', [[A, STAGE_PROD]]);
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    expect(ins.inserted.needs.map((n) => n.job)).toEqual(['stage', 'prod']);
    expect(w.v.gaps).toEqual([]);
    expect(w.v.preview.join('\n')).toMatch(/"stage", "prod" wait/);
    expect(shown(await judge(w))).toBe('');
  });

  it('G7-R1 sec I2: an OIDC token, a reusable call or an environment gates a job; only the read-only, secret-free lint job is left out, and said so', async () => {
    const w = world('keyless', [[A, INFRA]]);
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    expect(ins.inserted.needs.map((n) => n.job)).toEqual(['infra', 'release', 'site']);
    const listed = [...w.v.preview, ...w.v.notes].join('\n');
    expect(listed).toMatch(/"lint" does not wait for pipegen-verify: it shows no deploy, uses no secret but the workflow token, has only read permissions, no environment, calls no other workflow, runs on a GitHub-hosted runner, and reads no configuration variable/);
    expect(shown(await judge(w))).toBe('');
    // a job with no permissions of its own may get a write token (the repository's default): it waits too
    const noPerms = INFRA.replace('  lint:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n', '  lint:\n    runs-on: ubuntu-latest\n');
    expect(planVerifyInserts(w.a.draft, new Map([[A, noPerms]]), w.a.verify).inserts[0]?.inserted.needs.map((n) => n.job)).toEqual(['lint', 'infra', 'release', 'site']);
    // an OIDC token (or any write permission) in the lint job gates it, whatever it runs
    for (const perm of [`${['id', 'token'].join('-')}: write`, 'packages: write', 'contents: write']) {
      const powered = INFRA.replace('  lint:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n', `  lint:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      ${perm}\n`.replace('      contents: read\n      contents: write\n', '      contents: write\n'));
      expect(powered, perm).not.toBe(INFRA);
      expect(planVerifyInserts(w.a.draft, new Map([[A, powered]]), w.a.verify).inserts[0]?.inserted.needs.map((n) => n.job), perm).toContain('lint');
    }
    // a call of another workflow is gated even with read-only permissions of its own (the called workflow may deploy)
    const readCall = INFRA.replace('    uses: ./.github/workflows/ship.yml\n', '    permissions:\n      contents: read\n    uses: ./.github/workflows/ship.yml\n');
    expect(readCall).not.toBe(INFRA);
    expect(planVerifyInserts(w.a.draft, new Map([[A, readCall]]), w.a.verify).inserts[0]?.inserted.needs.map((n) => n.job)).toContain('release');
    // a secret in the lint job (anything but the workflow token) gates it
    const withCfg = INFRA.replace('      - run: npm run lint', ['      - run: npm run lint', '        env:', ['          LINT_CFG:', '$' + '{{', `${['sec', 'rets'].join('')}.LINT_CFG`, '}}'].join(' ')].join('\n'));
    expect(planVerifyInserts(w.a.draft, new Map([[A, withCfg]]), w.a.verify).inserts[0]?.inserted.needs.map((n) => n.job)).toContain('lint');
  });
});

describe('G7-R1 sec M1-M7: the signature binds the commit; the verify job is exact and asks only what it uses', () => {
  it('G7-R1 sec M1: keyless verify binds the workflow commit, trigger and repository; key-env signs and verifies the commit annotation', () => {
    const kl = String(verifyOf(world('keyless')).steps.find((s) => /^pipegen-verify-/.test(s.id ?? ''))?.run);
    expect(kl).toContain('--certificate-github-workflow-sha "$GITHUB_SHA" --certificate-github-workflow-trigger push --certificate-github-workflow-repository \'o/r\'');
    const ke = world('key-env');
    const kv = String((ke.a.verify as Job).steps.find((s) => /^pipegen-verify-/.test(s.id ?? ''))?.run);
    expect(kv).toContain('verify --key "$keydir/cosign.pub" --insecure-ignore-tlog=true -a pipegen.commit="$GITHUB_SHA" "$ref"');
    const signFile = ke.a.files.find((f) => /sign/.test(f.path) && f.content.includes(' sign --yes --key')) as CreatedFile;
    expect(signFile.content).toContain('-a pipegen.commit="$GITHUB_SHA"');
  });

  it('G7-R1 sec M2: the head check refuses any event but push', () => {
    const run = String(renderHeadCheckStep('main').run);
    expect(run.indexOf('"$GITHUB_EVENT_NAME" != "push"')).toBeGreaterThan(-1);
    expect(run.indexOf('"$GITHUB_EVENT_NAME" != "push"')).toBeLessThan(run.indexOf('| curl -fsS'));
  });

  it('G7-R1 sec M3: the verify job holds no checkout and no artifact download (the digest comes from the API only)', async () => {
    const w = world('keyless');
    const f = w.v.inserts[0]?.file as CreatedFile;
    const pubJobs = jobsIn((w.a.files.find((x) => x.path === '.github/workflows/pipegen.yml') as CreatedFile).content);
    const checkout = ((pubJobs['image-publish'] as Obj).steps as Obj[]).find((x) => /^actions\/checkout@/.test(String(x.uses)));
    const download = { uses: String(checkout?.uses).replace(/^actions\/checkout/, 'actions/download-artifact'), with: { name: imageDigestArtifact('app'), path: `\${{ runner.temp }}/pipegen-out/${imageDigestArtifact('app')}` } };
    for (const extra of [checkout, download]) {
      const d = parseDocument(f.content);
      const steps = d.getIn(['jobs', 'pipegen-verify', 'steps']) as YAMLSeq;
      const at = steps.items.findIndex((x) => isMap(x) && x.get('id') === DIGEST_STEP_ID);
      steps.items.splice(at + 1, 0, d.createNode(extra));
      const r = await judge(w, [{ ...f, content: d.toString({ lineWidth: 0 }) }]);
      expect(r.ok, shown(r)).toBe(false);
    }
  });

  it('G7-R1 sec M5/M6: tokens go to curl on stdin; the zip download follows one redirect at most', () => {
    for (const s of [renderHeadCheckStep('main'), renderDigestStep('app')]) {
      const run = String(s.run);
      expect(run).not.toMatch(/curl[^\n]*Bearer/);
      expect(run).toContain(`printf '${['Author', 'ization'].join('')}: ${['Bear', 'er'].join('')} %s\\n' "$${['TOK', 'EN'].join('')}" | curl -fsS`);
    }
    expect(String(renderDigestStep('app').run)).toContain('-L --max-redirs 1 --max-filesize 65536');
  });

  it('G7-R1 sec M7: the verify job asks per mode and per published image', async () => {
    expect(verifyOf(world('keyless')).permissions).toEqual({ contents: 'read', actions: 'read', packages: 'read' });
    expect(verifyOf(world('key-env')).permissions).toEqual({ contents: 'read', actions: 'read', packages: 'read' });
    expect(verifyOf(world('none')).permissions).toEqual({ contents: 'read', actions: 'read' });
    const site = world('keyless', [[A, DEPLOY_A]], { services: [node({ projectType: { types: ['static-site'], evidence: [], unsure: false } })] });
    expect(verifyOf(site).permissions).toEqual({ contents: 'read', actions: 'read' });
    expect(shown(await judge(site))).toBe('');
    const prof = profileOf([SERVER], { private: true });
    const at = planned(prof, { over: { centralPin: PIN, signing: { mode: 'attest', images: [IMG] } } }).draft;
    expect(verifyPermissions(at)).toEqual({ contents: 'read', actions: 'read', packages: 'read', attestations: 'read' });
  });
});

describe('G7-R1 spec: the byte-level edit, the key, the network note, the environments', () => {
  /** The reviewer's failing shapes (probe4/probe6): the last job ends with its needs. */
  const LAST_NEEDS = [
    ['block needs at the end', 'on:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n  deploy:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./ship.sh\n    needs:\n      - build\n'],
    ['compact block needs at the end', 'on:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n  deploy:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./ship.sh\n    needs:\n    - build\n'],
    ['scalar needs, no newline at the end', 'on:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n  deploy:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./ship.sh\n    needs: build'],
    ['two deploy jobs, the last with block needs', 'on:\n  push:\n    branches: [main]\njobs:\n  web:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./web.sh\n  api:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./api.sh\n    needs:\n      - web\n'],
  ] as const;
  it('G7-R1 spec I1: a job that ends with its needs (at the end of the jobs map) gets the needs, then the job, at the same offset', async () => {
    for (const [what, text] of LAST_NEEDS) {
      const w = world('keyless', [[A, text]]);
      expect(w.v.gaps, what).toEqual([]);
      const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
      expect(apply(text, ins.insertions), what).toBe(ins.text);
      const jobs = jobsIn(ins.text);
      expect(Object.keys(jobs).at(-1), what).toBe('pipegen-verify');
      for (const n of ins.inserted.needs) expect((jobs[n.job] as Obj).needs, `${what} ${n.job}`).toContain('pipegen-verify');
      expect(shown(await judge(w)), what).toBe('');
    }
  });

  it('G7-R1 minor: needs written over several lines in [ ] are refused with what to change', () => {
    const text = 'on:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n  deploy:\n    environment: production\n    needs: [\n      build\n    ]\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./ship.sh\n';
    const w = world('keyless', [[A, text]]);
    expect(w.v.inserts).toEqual([]);
    expect(w.v.gaps[0]?.why).toMatch(/lists its needs over several lines inside \[ \]; write them on one line, or as a - list/);
  });

  it('G7-R1 minor: a CRLF file stays CRLF', async () => {
    const crlf = DEPLOY_A.replace(/\n/g, '\r\n');
    const w = world('keyless', [[A, crlf]]);
    expect(w.v.gaps).toEqual([]);
    const text = w.v.inserts[0]?.text as string;
    expect(text.replace(/\r\n/g, '')).not.toContain('\n');
    expect(text).toContain('pipegen-verify:');
    expect(shown(await judge(w))).toBe('');
  });

  it('G7-R1 minor: the user text says what to change (no "referee", no "read back")', () => {
    const wr = world('keyless', [[A, DEPLOY_A]], { profile: { existingWorkflows: [wfOf(A, ['workflow_run'])] } });
    const runText = DEPLOY_A.replace('on:\n  push:\n    branches: [main]   # main only\n', 'on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\n');
    const v = planVerifyInserts(wr.a.draft, new Map([[A, runText]]), wr.a.verify);
    const all = v.gaps.map((g) => g.why).join('\n');
    expect(all).toMatch(/workflow_run/);
    expect(all).not.toMatch(/referee|read back/);
    expect(readFileSync('src/layers/deploy.ts', 'utf8')).not.toMatch(/can not be read back|\(the referee refuses it\)/);
  });

  it('G7-R1 spec I3 / sec M8: the key is made in memory only; elsewhere a plain message names the alternative (and not finish)', async () => {
    await expect(generateCosignKeys(async () => '/opt/cosign', { base: '/', isMemory: () => false })).rejects.toThrow(/memory[\s\S]*\/dev\/shm[\s\S]*Linux/);
    await expect(generateCosignKeys(async () => '/opt/cosign', { base: '/', isMemory: () => false })).rejects.not.toThrow(/pipegen finish/);
  });

  it('G7-R1 spec I4 (G15a: the release blocker is fixed): a keyless verify job reaches the reviewed Sigstore set, so no release-blocker note', () => {
    const kl = world('keyless');
    expect(kl.a.notes.join('\n')).not.toMatch(/Your deploys stop/);
    expect(world('key-env').a.notes.join('\n')).not.toMatch(/Your deploys stop/);
  });

  it('G7-R1 minor: environments of workflows pipegen does not protect keep their branch rules, with a note', async () => {
    const devDeploy = DEPLOY_B.replace('            - main', '            - develop').replace('name: production', 'name: staging');
    const prof = profileOf([SERVER], { private: true, existingWorkflows: [wfOf(A), wfOf(B)] });
    const notes: string[] = [];
    const texts = new Map([[A, DEPLOY_A], [B, devDeploy]]);
    const g = new FakeGitHub();
    g.addRepo('o/r', { private: true });
    const plan = await environmentPlan(g.octokit(), prof, KE_CAPS, false, { texts, inserted: [A], notes });
    expect(plan.map((e) => e.name)).toEqual(['production', 'pipegen-signing']);
    expect(notes.join('\n')).toMatch(/"staging"[\s\S]*not limited to the default branch/);
  });

  it('G7-R1 minor: no dead helpers (sameRunStep, a second triggerNames)', async () => {
    const steps = await import('../src/engine/deploy-steps.js');
    const deploy = await import('../src/layers/deploy.js');
    expect('sameRunStep' in steps).toBe(false);
    expect('triggerNames' in deploy).toBe(false);
  });
});

describe('G7-R-sec1: a step-level if: can not run a deploy step after the head check failed', () => {
  const withStepIf = (cond: string): string => DEPLOY_A.replace('      - run: ./scripts/ship.sh\n', `      - run: ./scripts/ship.sh\n        if: ${cond}\n`);
  it('G7-R-sec1: a gated job with a step if: always() (or failure(), cancelled(), a top-level ||) → no insert, an honest gap', async () => {
    for (const cond of ['always()', '${{ failure() }}', 'cancelled()', "success() || github.ref == 'refs/heads/main'", '${{ !cancelled() }}']) {
      const w = world('keyless', [[A, withStepIf(cond)]]);
      expect(w.v.inserts, cond).toEqual([]);
      expect(w.v.gaps, cond).toEqual([{ path: A, triggers: ['push'], why: expect.stringMatching(/a step of its job "deploy" \(it has an environment\) has an if: that could run it after pipegen's head check failed/) }]);
    }
    // the referee refuses the same file edited by hand (the insert forced)
    const w = world('keyless', [[A, withStepIf('always()')]]);
    const forced = insertVerify(withStepIf('always()'), ['deploy'], verifyOf(w));
    const f: CreatedFile = { path: A, content: forced.text, part: 'deploy-verify', reason: 't', repo: 'app', inserted: forced.inserted };
    const r = await judge(w, [f]);
    expect(r.issues.some((i) => /Step \d+ of the job "deploy" has an if: that could run it after pipegen's head check failed/.test(i.message)), shown(r)).toBe(true);
  });
  it('G7-R-sec1: a step if: success() && <condition> is allowed', async () => {
    for (const cond of ["${{ success() && github.ref == 'refs/heads/main' }}", "github.ref == 'refs/heads/main'"]) {
      const w = world('keyless', [[A, withStepIf(cond)]]);
      expect(w.v.gaps, cond).toEqual([]);
      expect(w.v.inserts, cond).toHaveLength(1);
      expect(shown(await judge(w)), cond).toBe('');
    }
  });
});

// ---------- G7-R2 fix round 2 (ruling G7-R2, re-reviews G7 security r1 and spec r1) ----------

describe('G7-R2: the head check in the user\'s own job (its working folder, its tools, its runner)', () => {
  const MONO = DEPLOY_A.replace('    environment: production\n', '    environment: production\n    defaults:\n      run:\n        working-directory: web\n');
  it('G7-R2 1a: the head check runs in the runner\'s temp folder, so a job default working-directory (a folder made by checkout) does not break it', async () => {
    const head = renderHeadCheckStep('main');
    expect(head['working-directory']).toBe('${{ runner.temp }}');
    // that one expression, on that step only
    expect(() => checkExpressions(head)).not.toThrow();
    expect(() => checkExpressions({ ...head, 'working-directory': '${{ github.workspace }}' })).toThrow(RenderError);
    expect(() => checkExpressions({ ...head, id: 'other', 'working-directory': '${{ runner.temp }}' })).toThrow(RenderError);
    const w = world('keyless', [[A, MONO]]);
    expect(w.v.gaps).toEqual([]);
    const steps = (jobsIn(w.v.inserts[0]?.text as string).deploy as Obj).steps as Obj[];
    expect(steps[0]).toEqual({ ...head });
    expect(steps[0]?.['working-directory']).toBe('${{ runner.temp }}');
    expect(shown(await judge(w))).toBe('');
    // the referee's exact compare follows the renderer: the step without its working-directory is not pipegen's
    const f = w.v.inserts[0]?.file as CreatedFile;
    const d = parseDocument(f.content);
    ((d.getIn(['jobs', 'deploy', 'steps']) as YAMLSeq).items[0] as YAMLMap).delete('working-directory');
    expect((await judge(w, [{ ...f, content: d.toString({ lineWidth: 0 }) }])).ok).toBe(false);
  });

  it('G7-R2 1b: the head check\'s own first line checks for curl and jq, with a plain message', () => {
    const run = String(renderHeadCheckStep('main').run);
    const own = run.split('\n').slice(4);
    expect(own[0]).toBe('for t in curl jq; do command -v "$t" > /dev/null || pg_fail "this job\'s runner or container has no $t, which pipegen\'s head check needs; install $t there, or run this deploy job on ubuntu-latest"; done');
  });

  it('G7-R2 1c: a gated job in a container, on macOS or Windows, or self-hosted keeps its head check and gets a preview line and a note', async () => {
    const shapes: [string, string][] = [
      ['container', DEPLOY_A.replace('    environment: production\n', '    environment: production\n    container: node:22-alpine\n')],
      ['macos', DEPLOY_A.replace('    environment: production\n    env: *common', '    environment: production\n    env: *common').replace(/(  deploy:[\s\S]*?)runs-on: ubuntu-latest/, '$1runs-on: macos-14')],
      ['windows', DEPLOY_A.replace(/(  deploy:[\s\S]*?)runs-on: ubuntu-latest/, '$1runs-on: windows-latest')],
      ['self-hosted', DEPLOY_A.replace(/(  deploy:[\s\S]*?)runs-on: ubuntu-latest/, '$1runs-on: [self-hosted, linux]')],
    ];
    for (const [what, text] of shapes) {
      expect(text, what).not.toBe(DEPLOY_A);
      const w = world('keyless', [[A, text]]);
      expect(w.v.gaps, what).toEqual([]);
      const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
      expect(ins.inserted.headCheck, what).toEqual(['deploy']);
      expect(w.v.preview.join('\n'), what).toMatch(/"deploy" runs pipegen's head check on its own runner or container: the check needs bash, curl and jq on this runner/);
      expect(w.v.notes.join('\n'), what).toMatch(/"deploy"[\s\S]*the check needs bash, curl and jq on this runner/);
      expect(shown(await judge(w)), what).toBe('');
    }
    // a plain GitHub-hosted ubuntu runner gets no such line
    expect(world('keyless').v.notes.join('\n')).not.toMatch(/needs bash, curl and jq on this runner/);
  });
});

describe('G7-R2 2: a job on its own runner, or one that reads vars, may deploy', () => {
  it('G7-R2 2: a read-only, secret-free job on a self-hosted runner (or a runner group, or an expression) waits for the check', () => {
    const w = world('keyless', [[A, INFRA]]);
    for (const runsOn of ['[self-hosted, prod-vpc]', '{ group: deployers }', '${{ matrix.os }}']) {
      const text = INFRA.replace('  lint:\n    runs-on: ubuntu-latest\n', `  lint:\n    runs-on: ${runsOn}\n`);
      expect(text, runsOn).not.toBe(INFRA);
      expect(planVerifyInserts(w.a.draft, new Map([[A, text]]), w.a.verify).inserts[0]?.inserted.needs.map((n) => n.job), runsOn).toContain('lint');
    }
  });
  it('G7-R2 2: a job that reads a configuration variable (a deploy hook URL in vars) waits for the check', () => {
    const w = world('keyless', [[A, INFRA]]);
    const text = INFRA.replace('      - run: npm run lint\n', `      - run: curl -X POST "\${{ vars.HOOK_URL }}"\n`);
    expect(text).not.toBe(INFRA);
    expect(planVerifyInserts(w.a.draft, new Map([[A, text]]), w.a.verify).inserts[0]?.inserted.needs.map((n) => n.job)).toContain('lint');
  });
});

describe('G7-R2 3-6: what the notes and messages say', () => {
  it('G7-R2 3: the note of a job that calls another workflow covers an approval wait and a deliberate re-run', () => {
    const w = world('keyless', [[A, INFRA]]);
    const note = w.v.notes.find((n) => n.includes('"release" calls another workflow')) as string;
    expect(note).toMatch(/approval/);
    expect(note).toMatch(/re-run/i);
    expect(note).toMatch(/an older commit can still deploy/);
  });
  it('G7-R2 4: a push filtered by paths gets a preview line and a note; the head check says what to do when the newer commit deploys nothing', () => {
    for (const filter of ['paths', 'paths-ignore']) {
      const text = DEPLOY_A.replace('    branches: [main]   # main only\n', `    branches: [main]   # main only\n    ${filter}: ['src/**']\n`);
      const w = world('keyless', [[A, text]]);
      expect(w.v.gaps, filter).toEqual([]);
      expect(w.v.preview.join('\n'), filter).toMatch(/push only for some paths/);
      expect(w.v.notes.join('\n'), filter).toMatch(/a newer commit that starts no deploy[\s\S]*push again or re-run all jobs on the newest commit/);
    }
    expect(world('keyless').v.preview.join('\n')).not.toMatch(/push only for some paths/);
    expect(String(renderHeadCheckStep('main').run)).toContain('if that commit starts a deploy; otherwise push again or re-run all jobs on the newest commit');
  });
  it('G7-R2 6: the Sigstore note names no internal task and fires exactly when the verify job can not reach a host of the keyless verify set', () => {
    // G15a-R7 spec 4: keyed on the verify job's own egress step and the hosts of the set (never a copied list), checked by behaviour
    const w = world('keyless');
    const verify = verifyOf(w);
    expect(keylessVerifyNote(w.a.draft, verify)).toBeNull();
    expect(w.a.notes.join('\n')).not.toMatch(/Your deploys stop/);
    const hosts = KEYLESS_VERIFY_SETS.flatMap((x) => EGRESS_DOMAIN_SETS[x]);
    expect(hosts.length).toBeGreaterThan(0);
    for (const h of hosts) {
      const cut: Job = { ...verify, steps: verify.steps.map((s, i) => (i === 0 ? { ...s, with: { ...s.with, 'allowed-domains': String(s.with?.['allowed-domains']).split('\n').filter((x) => x !== h).join('\n') } } : s)) };
      const note = keylessVerifyNote(w.a.draft, cut);
      expect(note, h).toMatch(/^Your deploys stop: pipegen checks a keyless signature with Sigstore/);
      expect(note, h).not.toMatch(/\bG\d+\b|before release|adds them/);
    }
    // only keyless: a key-env verify job reaches no Sigstore host and gets no note
    const ke = world('key-env');
    expect(keylessVerifyNote(ke.a.draft, verifyOf(ke))).toBeNull();
  });
});

// ---------- G7-R3 (exception round, DECISIONS #108; re-reviews G7 security r2 and spec r2) ----------

describe('G7-R3: STRONG and WEAK reasons; a job gated only by its runner or vars never makes the workflow a gap', () => {
  const deployJob = ['  deploy:', '    needs: test', '    runs-on: ubuntu-latest', '    environment: production', '    permissions: { contents: read }', '    steps:', '      - run: ./ship.sh', ''];
  const wf = (test: string[]): string => ['on: { push: { branches: [main] } }', 'jobs:', '  test:', ...test, ...deployJob].join('\n');
  const Q: [string, string][] = [
    ['self-hosted test job with an always() upload', wf(['    runs-on: [self-hosted, linux]', '    permissions: { contents: read }', '    steps:', '      - run: make test', '      - uses: actions/upload-artifact@v4', '        if: always()', '        with: { name: logs, path: logs/ }'])],
    ['vars in a with, plus always()', wf(['    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - uses: actions/setup-node@v4', '        with: { node-version: "${{ vars.NODE_VERSION }}" }', '      - run: npm test', '      - run: echo done', '        if: always()'])],
    ['self-hosted, permissions: {}', wf(['    runs-on: [self-hosted, linux]', '    permissions: {}', '    steps:', '      - run: make test'])],
    ['matrix.os test job with always()', wf(['    strategy: { matrix: { os: [ubuntu-latest, windows-latest] } }', '    runs-on: ${{ matrix.os }}', '    permissions: { contents: read }', '    steps:', '      - run: make test', '      - run: echo done', '        if: always()'])],
  ];
  it('G7-R3 4: the four probe-Q shapes keep deploy gated with its head check; the workflow is not a gap', async () => {
    for (const [what, text] of Q) {
      const w = world('keyless', [[A, text]]);
      expect(w.v.gaps, what).toEqual([]);
      const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
      expect(ins.inserted.needs.map((n) => n.job), what).toEqual(['test', 'deploy']);
      expect(ins.inserted.headCheck, what).toEqual(['deploy']);
      const steps = (jobsIn(ins.text).deploy as Obj).steps as Obj[];
      expect(steps[0]?.id, what).toBe('pipegen-head-check');
      expect(((jobsIn(ins.text).test as Obj).steps as Obj[])[0]?.id, what).not.toBe('pipegen-head-check');
      // test waits for the check (needs only), and the note says what that leaves open
      expect(w.v.notes.join('\n'), what).toMatch(/"test" waits for pipegen-verify but gets no head check[\s\S]*an older commit can still run after an approval wait or a re-run of this job alone/);
      expect(shown(await judge(w)), what).toBe('');
    }
  });

  it('G7-R3 4: an ubuntu+windows matrix test job without always(): needs only, no head check', async () => {
    const text = wf(['    strategy: { matrix: { os: [ubuntu-latest, windows-latest] } }', '    runs-on: ${{ matrix.os }}', '    permissions: { contents: read }', '    steps:', '      - run: make test']);
    const w = world('keyless', [[A, text]]);
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    expect(ins.inserted.needs.map((n) => n.job)).toEqual(['test', 'deploy']);
    expect(ins.inserted.headCheck).toEqual(['deploy']);
    expect(w.v.preview.join('\n')).toMatch(/"test" counts as a deploy job: it runs on a runner of its own/);
    expect(shown(await judge(w))).toBe('');
  });

  it('G7-R3 4: round-1 probe R1 (a read-only terraform job on [self-hosted, prod-vpc]) stays gated', async () => {
    const text = ['on: { push: { branches: [main] } }', 'jobs:', '  stage:', '    runs-on: ubuntu-latest', '    environment: staging', '    steps:', '      - run: ./stage.sh', '  prod:', '    runs-on: [self-hosted, prod-vpc]', '    permissions: { contents: read }', '    steps:', '      - run: terraform apply -auto-approve', ''].join('\n');
    const w = world('keyless', [[A, text]]);
    expect(w.v.gaps).toEqual([]);
    expect(w.v.inserts[0]?.inserted.needs.map((n) => n.job)).toContain('prod');
    expect(shown(await judge(w))).toBe('');
  });

  it('G7-R3 4: a STRONG job with a step-level always() is still a gap that names why the job counts', () => {
    const text = DEPLOY_A.replace('      - run: ./scripts/ship.sh\n', '      - run: ./scripts/ship.sh\n        if: always()\n');
    const w = world('keyless', [[A, text]]);
    expect(w.v.inserts).toEqual([]);
    expect(w.v.gaps[0]?.why).toMatch(/a step of its job "deploy" \(it has an environment\) has an if:/);
  });

  it('G7-R3 1a: a WEAK job whose job-level if: defeats needs is left out with a preview line and a note; the workflow is not a gap', async () => {
    const text = wf(['    runs-on: [self-hosted, linux]', '    if: always()', '    permissions: { contents: read }', '    steps:', '      - run: make test']);
    const w = world('keyless', [[A, text]]);
    expect(w.v.gaps).toEqual([]);
    expect(w.v.inserts[0]?.inserted.needs.map((n) => n.job)).toEqual(['deploy']);
    const line = /"test" may deploy \(it runs on a runner of its own[^)]*\), but its if: could run it even when pipegen's check fails, so pipegen leaves it out/;
    expect(w.v.preview.join('\n')).toMatch(line);
    expect(w.v.notes.join('\n')).toMatch(line);
    expect(shown(await judge(w))).toBe('');
  });

  it('G7-R3 1b: checkEdit, renewVerifyJob and the referee take a needs-only WEAK job; the referee refuses needs-only on a STRONG job', async () => {
    const [, text] = Q[0] as [string, string];
    const w = world('keyless', [[A, text]]);
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    expect(ins.inserted.needsOnly).toEqual(['test']);
    expect(renewVerifyJob(ins.text, ins.inserted, w.a.verify as Job)).toBe(ins.text);
    // a mark that calls the real deploy job needs-only (and drops its head check) is refused
    const d = parseDocument(ins.text);
    (d.getIn(['jobs', 'deploy', 'steps']) as YAMLSeq).items.shift();
    const forged = { ...ins.file, content: d.toString({ lineWidth: 0 }), inserted: { ...ins.inserted, headCheck: [], needsOnly: ['test', 'deploy'] } };
    const r = await judge(w, [forged]);
    expect(r.issues.some((i) => /"deploy" may not wait without pipegen's head check: it has an environment/.test(i.message)), shown(r)).toBe(true);
  });

  it('G7-R3 1b: a WEAK job on plain GitHub ubuntu (vars only, contents: read, no status if) gets needs and the head check; only the others are needs-only', async () => {
    const text = wf(['    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - run: curl -X POST "${{ vars.HOOK_URL }}"']);
    const w = world('keyless', [[A, text]]);
    expect(w.v.gaps).toEqual([]);
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    expect(ins.inserted.needs.map((n) => n.job)).toEqual(['test', 'deploy']);
    expect(ins.inserted.headCheck).toEqual(['test', 'deploy']);
    expect(ins.inserted.needsOnly).toBeUndefined();
    expect(((jobsIn(ins.text).test as Obj).steps as Obj[])[0]?.id).toBe('pipegen-head-check');
    expect(w.v.preview.join('\n')).toMatch(/"test" counts as a deploy job: it reads a configuration variable \(vars\)/);
    expect(w.v.notes.join('\n')).not.toMatch(/"test" waits for pipegen-verify but gets no head check/);
    expect(shown(await judge(w))).toBe('');
  });

  it('G7-R3 2: the vars rule catches vars[\'X\'], VARS.X and toJSON(vars)', () => {
    const w = world('keyless', [[A, INFRA]]);
    for (const ref of ["${{ vars['HOOK_URL'] }}", '${{ VARS.HOOK_URL }}', '${{ toJSON(vars) }}']) {
      const text = INFRA.replace('      - run: npm run lint\n', `      - run: curl -X POST "${ref}"\n`);
      expect(planVerifyInserts(w.a.draft, new Map([[A, text]]), w.a.verify).inserts[0]?.inserted.needs.map((n) => n.job), ref).toContain('lint');
    }
  });

  it('G7-R3 3: only GitHub\'s own image labels count as hosted; ubuntu-prod-vpc is a runner of its own', () => {
    for (const label of ['ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-24.04-arm', 'windows-latest', 'windows-2022', 'windows-2025', 'windows-11-arm', 'macos-latest', 'macos-14', 'macos-15', 'macos-15-xlarge', 'macos-14-large']) {
      expect(githubHosted(label), label).toBe(true);
    }
    for (const label of ['ubuntu-prod-vpc', 'ubuntu-latest-8-cores', 'windows-gpu', 'macos-mine', 'self-hosted', 'ubuntu', 'Ubuntu-latest']) {
      expect(githubHosted(label), label).toBe(false);
    }
    const w = world('keyless', [[A, INFRA]]);
    const text = INFRA.replace('  lint:\n    runs-on: ubuntu-latest\n', '  lint:\n    runs-on: ubuntu-prod-vpc\n');
    expect(planVerifyInserts(w.a.draft, new Map([[A, text]]), w.a.verify).inserts[0]?.inserted.needs.map((n) => n.job)).toContain('lint');
  });

  it('G7-R3b M1: a newline or tab right before secrets or vars does not hide it', () => {
    const w = world('keyless', [[A, INFRA]]);
    const cases: [string, string, RegExp][] = [
      ['newline before secrets', '      - run: |\n          curl -H "X-Hook: ${{\n          secrets.HOOK_TOKEN }}" https://hooks.example.com/x\n', /it uses a secret/],
      ['tab before secrets', '      - run: "curl -H \\"A: ${{\\tsecrets.HOOK_TOKEN }}\\" https://hooks.example.com/x"\n', /it uses a secret/],
      ['newline before vars', '      - run: |\n          curl -X POST "${{\n          vars.HOOK_URL }}"\n', /it reads a configuration variable/],
    ];
    for (const [what, step, reason] of cases) {
      const text = INFRA.replace('      - run: npm run lint\n', step);
      expect(text, what).not.toBe(INFRA);
      const v = planVerifyInserts(w.a.draft, new Map([[A, text]]), w.a.verify);
      expect(v.inserts[0]?.inserted.needs.map((n) => n.job), what).toContain('lint');
      expect(v.preview.join('\n'), what).toMatch(new RegExp(`"lint" counts as a deploy job: ${reason.source}`));
    }
  });

  it('G7-R3b M4: only exact current GitHub image labels count as hosted (no free suffixes, no retired images)', () => {
    for (const label of ['ubuntu-latest-arm', 'windows-2019', 'macos-14-intel', 'macos-13', 'macos-13-large', 'macos-13-xlarge', 'macos-latest-intel', 'ubuntu-slim']) {
      expect(githubHosted(label), label).toBe(false);
    }
    for (const label of ['ubuntu-22.04-arm', 'macos-15-intel', 'macos-latest-xlarge', 'macos-15-large', 'windows-2025']) expect(githubHosted(label), label).toBe(true);
  });

  it('G7-R3b M5: the needs-only line is in the preview; the reason and the generic note name both exceptions', () => {
    const [, text] = Q[0] as [string, string];
    const w = world('keyless', [[A, text]]);
    expect(w.v.preview.join('\n')).toMatch(/"test" waits for pipegen-verify but gets no head check/);
    const exc = /except a job that calls another workflow, or one pipegen gates only for its runner or vars and can not start with the check \(see the notes\)/;
    expect(w.v.inserts[0]?.file.reason).toMatch(exc);
    expect(w.v.notes.join('\n')).toMatch(new RegExp(`Each deploy job starts with pipegen's head check, ${exc.source}`));
  });

  it('G7-R3 5: HEAD_CHECK_ENV has its own doc comment', () => {
    const src = readFileSync('src/engine/deploy-steps.ts', 'utf8');
    expect(src).toMatch(/\/\*\*[^\n]*\*\/\nexport const HEAD_CHECK_ENV:/);
  });
});

// ---------- G13: the G7-R2 carry (BINDING): the head check in the jobs of a local called workflow ----------

const SHIP = '.github/workflows/ship.yml';
/** A deploy that calls a local workflow (shape A: two-space indentation, a build job first). */
const CALLER_A = [
  'name: deploy',
  'on:',
  '  push:',
  '    branches: [main]',
  'jobs:',
  '  build:',
  '    runs-on: ubuntu-latest',
  '    permissions:',
  '      contents: read',
  '    steps:',
  '      - run: npm run build',
  '  ship:',
  '    needs: build',
  '    uses: ./.github/workflows/ship.yml',
  `    ${['sec', 'rets'].join('')}: inherit`,
  '',
].join('\n');
/** The called workflow: an approval wait (environment) and a smoke job after it. */
const CALLED_A = [
  'on:',
  '  workflow_call:',
  'jobs:',
  '  deploy:',
  '    runs-on: ubuntu-latest',
  '    environment: production',
  '    steps:',
  '      - run: ./ship.sh   # the user\'s own comment',
  '  smoke:',
  '    needs: deploy',
  '    runs-on: ubuntu-latest',
  '    steps:',
  '      - run: ./smoke.sh',
  '',
].join('\n');
/** Shape B: four-space indentation, the call is the only job, the called workflow has one job and no newline at the end. */
const CALLER_B = 'on:\n    push:\n        branches:\n            - main\njobs:\n    release:\n        uses: ./.github/workflows/ship.yml\n';
const CALLED_B = 'on: workflow_call\njobs:\n    publish:\n        runs-on: ubuntu-latest\n        environment:\n            name: production\n        steps:\n            -   run: ./publish.sh';
const calledWorld = (caller: string, called: string, extra: [string, string][] = []): World => world('keyless', [[A, caller], [SHIP, called], ...extra]);
const insertAt = (w: World, path: string) => w.v.inserts.find((i) => i.path === path);

describe('G13: the head check in a local called workflow (G7-R2 carry, BINDING)', () => {
  for (const [shape, caller, called, jobIds] of [['A', CALLER_A, CALLED_A, ['deploy', 'smoke']], ['B', CALLER_B, CALLED_B, ['publish']]] as const) {
    it(`G13 G7-R2: every job of a called workflow starts with the head check; the called file is no gap (shape ${shape})`, async () => {
      const w = calledWorld(caller, called);
      const ins = insertAt(w, SHIP);
      expect(ins?.inserted).toMatchObject({ original: called, jobs: [], needs: [], headCheck: [...jobIds], calledBy: [A] });
      expect(w.v.gaps.map((g) => g.path)).not.toContain(SHIP);
      const js = parse(ins?.text as string) as Obj;
      const want = (parse(String(new (await import('yaml')).Document(renderHeadCheckStep('main'))) ) as Obj);
      for (const id of jobIds) {
        const steps = ((js.jobs as Obj)[id] as Obj).steps as Obj[];
        expect(steps[0]?.id).toBe(HEAD_CHECK_STEP_ID);
        expect(steps[0]?.run).toBe(want.run);
        steps.shift();
      }
      expect(js).toEqual(parse(called));   // nothing else changed
      // no residual "calls another workflow" note for the covered call; the preview says what pipegen did
      expect(w.v.notes.join('\n')).not.toMatch(/calls another workflow, so pipegen can not start it/);
      expect(w.v.preview.join('\n')).toMatch(/ship\.yml: pipegen starts .* with its head check/);
      expect(shown(await judge(w))).toBe('');
    });
  }

  it('G13 G7-R2: the referee refuses a called edit without every head check, with a step after it that runs on failure, or with no gated caller', async () => {
    const w = calledWorld(CALLER_A, CALLED_A);
    const ins = insertAt(w, SHIP) as VerifyPlan['inserts'][number];
    const caller = insertAt(w, A)?.file as CreatedFile;
    const head = ins.text.indexOf('      - id: pipegen-head-check', ins.text.indexOf('  smoke:'));
    const end = ins.text.indexOf('      - run: ./smoke.sh');
    expect(head).toBeGreaterThan(0);
    // (a) smoke without its head check
    const noSmoke = { ...ins.file, content: ins.text.slice(0, head) + ins.text.slice(end) };
    expect(shown(await judge(w, [caller, noSmoke]))).toMatch(/smoke.*head check|Every job of a called workflow/);
    // (b) a later step that runs after a failed check
    const always = { ...ins.file, content: ins.text.replace('      - run: ./smoke.sh', '      - if: always()\n        run: ./smoke.sh') };
    expect(shown(await judge(w, [caller, always]))).toMatch(/after pipegen's head check failed/);
    // (c) the caller left out of the batch, or a caller that does not wait for pipegen-verify
    expect(shown(await judge(w, [ins.file]))).toMatch(/names as its caller is not in this batch/);
    const forged = { ...ins.file, inserted: { ...ins.inserted, calledBy: ['.github/workflows/other.yml'] } };
    expect(shown(await judge(w, [caller, forged]))).toMatch(/names as its caller/);
    // (d) a mark that claims a job pipegen added
    const job = { ...ins.file, inserted: { ...ins.inserted, jobs: ['pipegen-verify'] } };
    expect(shown(await judge(w, [caller, job]))).not.toBe('');
  });

  it('G13-R1 sec M1: the referee refuses a caller that does not wait for pipegen-verify, an anchored head check, defaults or env that change it, another trigger, a head check on no job', async () => {
    const w = calledWorld(CALLER_A, CALLED_A);
    const ins = insertAt(w, SHIP) as VerifyPlan['inserts'][number];
    const caller = insertAt(w, A)?.file as CreatedFile;
    const both = (content: string, original: string = ins.inserted.original as string): CreatedFile => ({ ...ins.file, content, inserted: { ...ins.inserted, original } } as CreatedFile);
    expect(shown(await judge(w, [caller, ins.file]))).toBe('');
    // (e) the caller calls this file but no longer waits for pipegen-verify
    const cdoc = parseDocument(caller.content);
    cdoc.setIn(['jobs', 'ship', 'needs'], 'build');
    const unwaited = { ...caller, content: cdoc.toString({ lineWidth: 0 }) };
    expect(shown(await judge(w, [unwaited, ins.file]))).toMatch(/has no job that calls this file and waits for pipegen-verify/);
    // (f) the head check written through a YAML anchor
    const anchored = ins.text.replace('      - id: pipegen-head-check', '      - &hc\n        id: pipegen-head-check');
    expect(anchored).not.toBe(ins.text);
    expect(shown(await judge(w, [caller, both(anchored)]))).toMatch(/uses a YAML anchor or alias/);
    // (g) workflow defaults: only defaults.run.shell bash or sh
    const withDefaults = (d: string, t: string): string => t.replace('jobs:\n', `${d}jobs:\n`);
    const wd = 'defaults:\n  run:\n    working-directory: elsewhere\n';
    expect(shown(await judge(w, [caller, both(withDefaults(wd, ins.text), withDefaults(wd, CALLED_A))]))).toMatch(/defaults that would change pipegen's head check/);
    const pwsh = 'defaults:\n  run:\n    shell: pwsh\n';
    expect(shown(await judge(w, [caller, both(withDefaults(pwsh, ins.text), withDefaults(pwsh, CALLED_A))]))).toMatch(/defaults that would change pipegen's head check/);
    const shell = 'defaults:\n  run:\n    shell: bash\n';
    // the repository's text is that original too (G17A-R2 r2-N1: the edit's original is the text pipegen read)
    expect(shown(await judge(w, [caller, both(withDefaults(shell, ins.text), withDefaults(shell, CALLED_A))], new Map([[A, CALLER_A], [SHIP, withDefaults(shell, CALLED_A)]])))).toBe('');
    // (h) a workflow env that changes how the check runs
    const env = `env:\n  ${['BASH', 'ENV'].join('_')}: ./evil.sh\n`;
    expect(shown(await judge(w, [caller, both(withDefaults(env, ins.text), withDefaults(env, CALLED_A))]))).toMatch(/changes how code runs on the runner/);
    // (i) started by more than workflow_call (in the file and its original)
    const disp = (t: string): string => t.replace('  workflow_call:\n', '  workflow_call:\n  workflow_dispatch:\n');
    expect(shown(await judge(w, [caller, both(disp(ins.text), disp(CALLED_A))]))).toMatch(/started by workflow_call alone/);
    // (j) the mark names a head check on a job the file does not have
    const ghost = { ...ins.file, inserted: { ...ins.inserted, headCheck: [...(ins.inserted.headCheck as string[]), 'ghost'] } } as CreatedFile;
    expect(shown(await judge(w, [caller, ghost]))).toMatch(/Every job of a called workflow|not a job of the workflow/);
    // (j2) a job left without the head check, and the mark leaving it out too: only the list check sees it
    const head = ins.text.indexOf('      - id: pipegen-head-check', ins.text.indexOf('  smoke:'));
    const end = ins.text.indexOf('      - run: ./smoke.sh');
    const unmarked = { ...ins.file, content: ins.text.slice(0, head) + ins.text.slice(end), inserted: { ...ins.inserted, headCheck: ['deploy'] } } as CreatedFile;
    expect(shown(await judge(w, [caller, unmarked]))).toMatch(/Every job of a called workflow pipegen edits must start with its head check/);
    // (j3) a job added to the called file is named as such (the rest compare refuses it too)
    const added = { ...ins.file, content: `${ins.text.trimEnd()}\n  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n` } as CreatedFile;
    expect(shown(await judge(w, [caller, added]))).toMatch(/adds or removes a job of the user's called workflow/);
    // (j4) any other change to the user's file (a step's command) is refused
    const changed = { ...ins.file, content: ins.text.replace('./ship.sh', './other.sh') } as CreatedFile;
    expect(changed.content).not.toBe(ins.text);
    expect(shown(await judge(w, [caller, changed]))).toMatch(/changes the user's called workflow beyond the head checks/);
    // (k) update can not renew a verify job in a called file (it holds none)
    expect(() => renewVerifyJob(ins.text, ins.inserted, w.a.verify as Job)).toThrow(/no pipegen-verify job/);
  });

  it('G13 G7-R2: no head check in a called workflow another, ungated workflow calls, or one started by more than workflow_call; the residual note says why', () => {
    const lint = 'on: pull_request\njobs:\n  check:\n    uses: ./.github/workflows/ship.yml\n';
    const w = world('keyless', [[A, CALLER_A], [SHIP, CALLED_A]], { profile: { existingWorkflows: [wfOf(A), wfOf(SHIP), { ...wfOf('.github/workflows/lint.yml'), deploys: false }] } });
    const v = planVerifyInserts(w.a.draft, new Map([[A, CALLER_A], [SHIP, CALLED_A], ['.github/workflows/lint.yml', lint]]), w.a.verify);
    expect(v.inserts.map((i) => i.path)).toEqual([A]);
    expect(v.notes.join('\n')).toMatch(/"ship" calls another workflow.*also called by ".github\/workflows\/lint.yml:check"/s);
    const dispatch = CALLED_A.replace('  workflow_call:', '  workflow_call:\n  workflow_dispatch:');
    const u = calledWorld(CALLER_A, dispatch);
    expect(insertAt(u, SHIP)).toBeUndefined();
    expect(u.v.notes.join('\n')).toMatch(/started by more than workflow_call/);
    // the called file is a gap when nothing pipegen gates calls it (a workflow_call deploy on its own)
    const alone = world('keyless', [[SHIP, CALLED_A]]);
    expect(alone.v.gaps.map((g) => g.path)).toEqual([SHIP]);
    expect(alone.v.gaps[0]?.why).toMatch(/workflow_call/);
  });
});

// ---------- G17 group A rows 2-4 (probe R9, sec r3 M2/M3): the referee re-derives the gated set and the needs-only set ----------
describe('G17 A rows 2-4: the referee re-derives which user jobs wait for pipegen-verify, never trusting the mark', () => {
  const SEC = ['sec', 'rets'].join('');
  /** A forged edit of the same original: insertVerify over other jobs (a well-formed edit, a dishonest mark). */
  const forge = (w: World, jobs: string[], needsOnly: string[] = []): CreatedFile => {
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    const e = insertVerify(ins.inserted.original as string, jobs, w.a.verify as Job, needsOnly);
    return { ...ins.file, content: e.text, inserted: e.inserted };
  };
  it('G17 row 2 (probe R9): a mark that drops a secret-holding job from needs is refused', async () => {
    const text = ['on: { push: { branches: [main] } }', 'jobs:', '  stage:', '    runs-on: ubuntu-latest', '    environment: staging', '    steps:', '      - run: ./stage.sh',
      '  prod:', '    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - run: ./prod.sh', '        env:', `          KEY: \${{ ${SEC}.PROD_KEY }}`, ''].join('\n');
    const w = world('keyless', [[A, text]]);
    expect(w.v.inserts[0]?.inserted.needs.map((n) => n.job)).toEqual(['stage', 'prod']);
    expect(shown(await judge(w))).toBe('');
    const r = await judge(w, [forge(w, ['stage'])]);
    expect(r.issues.some((i) => /"prod" must wait for pipegen-verify \(it uses a secret\)/.test(i.message)), shown(r)).toBe(true);
  });
  it('G17 row 3 (probes R3, R4): a mark that moves a head-checked job to needs-only, or drops it, is refused', async () => {
    // R3: no job the detector names; two read-only jobs on GitHub's ubuntu runner both take the head check
    const plain = ['name: release the site', 'on:', '  push:', '    branches: [main]', 'jobs:', '  one:', '    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - run: make',
      '  two:', '    needs: [one]', '    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - run: make upload', ''].join('\n');
    const w = world('key-env', [[B, plain]]);
    expect(w.v.inserts[0]?.inserted.headCheck).toEqual(['one', 'two']);
    expect(shown(await judge(w))).toBe('');
    const moved = await judge(w, [forge(w, ['one', 'two'], ['two'])]);
    expect(moved.issues.some((i) => /"two" may not wait without pipegen's head check/.test(i.message)), shown(moved)).toBe(true);
    const dropped = await judge(w, [forge(w, ['one'])]);
    expect(dropped.issues.some((i) => /"two" must wait for pipegen-verify/.test(i.message)), shown(dropped)).toBe(true);
    // R4: a WEAK vars job on plain GitHub ubuntu that the layer starts with the head check
    const vars = ['on: { push: { branches: [main] } }', 'jobs:', '  test:', '    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - run: curl -X POST "${{ vars.HOOK_URL }}"',
      '  deploy:', '    needs: test', '    runs-on: ubuntu-latest', '    environment: production', '    permissions: { contents: read }', '    steps:', '      - run: ./ship.sh', ''].join('\n');
    const v = world('keyless', [[A, vars]]);
    expect(v.v.inserts[0]?.inserted.headCheck).toEqual(['test', 'deploy']);
    const r4 = await judge(v, [forge(v, ['test', 'deploy'], ['test'])]);
    expect(r4.issues.some((i) => /"test" may not wait without pipegen's head check/.test(i.message)), shown(r4)).toBe(true);
  });
  it('G17 row 4 (probe C4): with no job the detector names, each job keeps its own STRONG reason; ship gets verify, not a gap', async () => {
    const c4 = ['on: { push: { branches: [main] } }', 'jobs:', '  test:', '    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - run: make test', '      - uses: actions/upload-artifact@v4', '        if: always()', '        with: { name: logs, path: logs/ }',
      '  ship:', '    needs: test', '    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - run: ./upload.sh', '        env:', `          HOOK: \${{ ${SEC}.HOOK_TOKEN }}`, ''].join('\n');
    const w = world('keyless', [[A, c4]]);
    expect(w.v.gaps).toEqual([]);
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    expect(ins.inserted.needs.map((n) => n.job)).toEqual(['test', 'ship']);
    expect(ins.inserted.headCheck).toEqual(['ship']);
    expect(ins.inserted.needsOnly).toEqual(['test']);
    expect(w.v.preview[0]).toMatch(/"test", "ship" wait for it \(pipegen could not tell which job deploys, so every job waits\)/);
    expect(shown(await judge(w))).toBe('');
    // a could-not-tell job whose own if: defeats needs still makes the workflow a gap (as before: every job waits, so none may run past the check)
    const g = world('keyless', [[A, c4.replace('  test:\n    runs-on', '  test:\n    if: always()\n    runs-on')]]);
    expect(g.v.inserts).toEqual([]);
    expect(g.v.gaps[0]?.why).toMatch(/"test" \(pipegen could not tell which job deploys, so every job waits\) has an if:/);
  });
  it('G17 rows 2-4: a mark that gates a job the layer leaves out, or edits a workflow the reader found no deploy in, is refused', async () => {
    const text = ['on: { push: { branches: [main] } }', 'jobs:', '  deploy:', '    runs-on: ubuntu-latest', '    environment: production', '    steps:', '      - run: ./scripts/ship.sh',
      '  lint:', '    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - run: make lint', ''].join('\n');
    const w = world('keyless', [[A, text]]);
    expect(w.v.inserts[0]?.inserted.needs.map((n) => n.job)).toEqual(['deploy']);
    expect(shown(await judge(w))).toBe('');
    const extra = await judge(w, [forge(w, ['deploy', 'lint'])]);
    expect(extra.issues.some((i) => /The edit makes the job "lint" wait for pipegen-verify, but pipegen's deploy layer does not gate it/.test(i.message)), shown(extra)).toBe(true);
    // the reader's deploy flag is the layer's too: a workflow it found no deploy in gets no insert
    const prof = w.a.draft.profile;
    const notDeploy = { ...w.a.draft, profile: { ...prof, existingWorkflows: prof.existingWorkflows.map((x) => ({ ...x, deploys: false })) } };
    const r = await judgeAssembled({ ...w.a, draft: notDeploy }, { ...JD, extra: w.v.inserts.map((i) => i.file) });
    expect(r.issues.some((i) => /pipegen adds no pipegen-verify job to this workflow: pipegen's reader found no deploy in it/.test(i.message)), shown(r)).toBe(true);
  });
  it('G17 rows 2-4: a mark on a workflow the layer makes a gap is refused', async () => {
    const text = DEPLOY_A.replace('      - run: ./scripts/ship.sh\n', '      - run: ./scripts/ship.sh\n        if: always()\n');
    const ok = world('keyless', [[A, DEPLOY_A]]);
    const original = ok.v.inserts[0]?.inserted.original as string;
    expect(original).toBe(DEPLOY_A);
    const e = insertVerify(text, ['deploy'], ok.a.verify as Job, ['deploy']);
    const forged: CreatedFile = { ...(ok.v.inserts[0] as VerifyPlan['inserts'][number]).file, content: e.text, inserted: e.inserted };
    const r = await judge(ok, [forged]);
    expect(r.issues.some((i) => /pipegen adds no pipegen-verify job to this workflow: a step of its job "deploy" \(it has an environment\) has an if:/.test(i.message)), shown(r)).toBe(true);
  });
});

// ---------- G17A-R1 (sec I1, I2, M2): the referee judges the file and the batch, never the mark ----------
describe('G17A-R1: the referee judges the edited file and the batch, never the mark', () => {
  const SEC = ['sec', 'rets'].join('');
  const ROW2 = ['on: { push: { branches: [main] } }', 'jobs:', '  stage:', '    runs-on: ubuntu-latest', '    environment: staging', '    steps:', '      - run: ./stage.sh',
    '  prod:', '    runs-on: ubuntu-latest', '    permissions: { contents: read }', '    steps:', '      - run: ./prod.sh', '        env:', `          KEY: \${{ ${SEC}.PROD_KEY }}`, ''].join('\n');
  /** A harmless job (egress and prelude steps, contents read), added to `text` under `id`. */
  const withJob = (text: string, id: string): string => {
    const doc = parseDocument(text);
    doc.setIn(['jobs', id], doc.createNode({ 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', 'timeout-minutes': 5 }));
    doc.setIn(['jobs', id, 'steps'], stepsToYaml([renderEgressStep([], { dockerNetworks: false }), ...renderJobPrelude({}, p).steps]));
    return doc.toString({ lineWidth: 0 });
  };
  it('G17A-R1 sec I1 (probe P1): a mark that inserts a job other than pipegen-verify, or one beside it, is refused', async () => {
    const w = world('keyless', [[A, DEPLOY_A]]);
    expect(shown(await judge(w))).toBe('');
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    // P1: the original plus one harmless job, marked as the only insert: nothing waits for any check
    const noop: CreatedFile = { ...ins.file, content: withJob(DEPLOY_A, 'noop'), inserted: { original: DEPLOY_A, jobs: ['noop'], needs: [] } };
    const r1 = await judge(w, [noop]);
    expect(r1.issues.some((i) => /inserts exactly one job, pipegen-verify/.test(i.message)), shown(r1)).toBe(true);
    // the verify insert with an extra job beside pipegen-verify
    const extra: CreatedFile = { ...ins.file, content: withJob(ins.text, 'noop'), inserted: { ...ins.inserted, jobs: ['pipegen-verify', 'noop'] } };
    const r2 = await judge(w, [extra]);
    expect(r2.issues.some((i) => /inserts exactly one job, pipegen-verify/.test(i.message)), shown(r2)).toBe(true);
  });
  it('G17A-R1 sec I2 (probe P2): a gated job the file does not make wait is refused, whatever the mark says; added is exactly pipegen-verify', async () => {
    const w = world('keyless', [[A, ROW2]]);
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    expect(ins.inserted.needs.map((n) => n.job)).toEqual(['stage', 'prod']);
    expect(shown(await judge(w))).toBe('');
    // P2: prod's added need line removed from the file (its head check kept), the mark keeps prod with added: []
    const lines = ins.text.split('\n');
    const prodAt = lines.findIndex((l) => l === '  prod:');
    const needAt = lines.findIndex((l, i) => i > prodAt && /^\s+needs: \[pipegen-verify\]$/.test(l));
    expect(needAt).toBeGreaterThan(prodAt);
    const text = [...lines.slice(0, needAt), ...lines.slice(needAt + 1)].join('\n');
    expect(((parse(text) as Obj).jobs as Obj).prod).not.toHaveProperty('needs');
    const mark = { ...ins.inserted, needs: ins.inserted.needs.map((n) => (n.job === 'prod' ? { job: 'prod', added: [] } : n)) };
    const r = await judge(w, [{ ...ins.file, content: text, inserted: mark }]);
    expect(r.issues.some((i) => /"prod" must wait for pipegen-verify \(it uses a secret\)/.test(i.message)), shown(r)).toBe(true);
    // added other than exactly ['pipegen-verify'] (here twice): the mark says what pipegen added, and it adds that one need only
    const twice = { ...ins.inserted, needs: ins.inserted.needs.map((n) => (n.job === 'prod' ? { job: 'prod', added: ['pipegen-verify', 'pipegen-verify'] } : n)) };
    const r2 = await judge(w, [{ ...ins.file, inserted: twice }]);
    expect(r2.issues.some((i) => /adds exactly the need pipegen-verify to "prod"/.test(i.message)), shown(r2)).toBe(true);
  });
  it('G17A-R1 sec M2: a called workflow the layer starts with the head check must be edited in the same batch, naming this caller', async () => {
    const w = calledWorld(CALLER_A, CALLED_A);
    const caller = insertAt(w, A)?.file as CreatedFile;
    const called = insertAt(w, SHIP)?.file as CreatedFile;
    expect(called).toBeDefined();
    expect(shown(await judge(w, [caller, called]))).toBe('');
    // the called file's edit dropped from the batch: the caller still waits, but no head check runs in the called deploy
    const r = await judge(w, [caller]);
    expect(r.issues.some((i) => /"ship" calls \.github\/workflows\/ship\.yml, whose jobs pipegen starts with its head check, and the batch holds no such edit of it naming this workflow/.test(i.message)), shown(r)).toBe(true);
    // without the workflow texts the referee can not tell: refused unless the edit is there (fails closed)
    const blind = await judge(w, [caller], null);
    expect(blind.issues.some((i) => /pipegen can not tell whether \.github\/workflows\/ship\.yml takes its head check/.test(i.message)), shown(blind)).toBe(true);
    expect(shown(await judge(w, [caller, called], null))).toBe('');
    // an edit of the called file whose mark names another caller is no edit for this one (mutation survivor, R1)
    const other = { ...called, inserted: { ...called.inserted, calledBy: ['.github/workflows/other.yml'] } } as CreatedFile;
    const ro = await judge(w, [caller, other]);
    expect(ro.issues.some((i) => /"ship" calls \.github\/workflows\/ship\.yml, whose jobs pipegen starts with its head check, and the batch holds no such edit of it naming this workflow/.test(i.message)), shown(ro)).toBe(true);
    // shape B (one job, four-space indentation): the same rule
    const b = calledWorld(CALLER_B, CALLED_B);
    expect(shown(await judge(b))).toBe('');
    const rb = await judge(b, [insertAt(b, A)?.file as CreatedFile]);
    expect(rb.issues.some((i) => /"release" calls \.github\/workflows\/ship\.yml, whose jobs pipegen starts with its head check/.test(i.message)), shown(rb)).toBe(true);
  });
  it('G17A-R1 (row 5 mutation survivor): an edited user workflow is never a layout file, so its pipegen-verify holding the gate is refused', async () => {
    const w = world('keyless', [[A, DEPLOY_A]]);
    const ins = w.v.inserts[0] as VerifyPlan['inserts'][number];
    expect(ins.text.split('mode: find-run').length).toBe(2);
    const r = await judge(w, [{ ...ins.file, content: ins.text.replace('mode: find-run', 'mode: gate') }]);
    expect(r.issues.some((i) => i.check === 'not-gate-readable' && /outside pipegen's layout/.test(i.message)), shown(r)).toBe(true);
  });
  it('G17A-R1 sec M2: no false refusal when the called workflow can not take the head check (another, ungated workflow calls it; more than workflow_call)', async () => {
    const LINT = '.github/workflows/lint.yml';
    const lint = 'on: pull_request\njobs:\n  check:\n    uses: ./.github/workflows/ship.yml\n';
    const w = world('keyless', [[A, CALLER_A], [SHIP, CALLED_A]], { profile: { existingWorkflows: [wfOf(A), wfOf(SHIP), { ...wfOf(LINT), deploys: false }] } });
    const texts = new Map([[A, CALLER_A], [SHIP, CALLED_A], [LINT, lint]]);
    const v = planVerifyInserts(w.a.draft, texts, w.a.verify);
    expect(v.inserts.map((i) => i.path)).toEqual([A]);
    expect(v.gaps.map((g) => g.path)).toEqual([SHIP]);
    expect(shown(await judge(w, v.inserts.map((i) => i.file), texts, v.gaps))).toBe('');
    const dispatch = CALLED_A.replace('  workflow_call:', '  workflow_call:\n  workflow_dispatch:');
    const u = calledWorld(CALLER_A, dispatch);
    expect(insertAt(u, SHIP)).toBeUndefined();
    expect(shown(await judge(u))).toBe('');
  });
});

// ---------- G17A-R2 (sec r2-M1, r2-N1): every deploy workflow the layer gates is edited or a listed gap; an edit's original is the text read ----------
describe('G17A-R2: the referee binds the batch to the plan\'s inputs', () => {
  const CALLER_B2 = 'on:\n  push:\n    branches: [main]\njobs:\n  release:\n    uses: ./.github/workflows/ship.yml\n';
  const notHandled = (path: string): RegExp => new RegExp(`The deploy workflow ${path.replace(/[./]/g, '\\$&')} is neither edited by pipegen in this batch nor listed as a gap`);
  it('G17A-R2 sec r2-M1: two gated callers of one called file; the second caller\'s insert and the called edit dropped → refused', async () => {
    const two = world('keyless', [[A, CALLER_A], [B, CALLER_B2], [SHIP, CALLED_A]]);
    expect(two.v.inserts.map((i) => i.path).sort()).toEqual([A, B, SHIP].sort());
    expect(shown(await judge(two))).toBe('');
    const r = await judge(two, [insertAt(two, A)?.file as CreatedFile]);
    expect(r.issues.some((i) => notHandled(B).test(i.message)), shown(r)).toBe(true);
    expect(r.issues.some((i) => notHandled(SHIP).test(i.message)), shown(r)).toBe(true);
  });
  it('G17A-R2 sec r2-M1: a single caller\'s insert and its called edit both dropped → refused; listed as gaps → accepted', async () => {
    const w = calledWorld(CALLER_A, CALLED_A);
    const r = await judge(w, []);
    expect(r.issues.some((i) => notHandled(A).test(i.message)), shown(r)).toBe(true);
    expect(r.issues.some((i) => notHandled(SHIP).test(i.message)), shown(r)).toBe(true);
    // a plain deploy whose insert is dropped is refused too, unless the doc lists it as a gap (PIPEGEN.md then says it is unprotected)
    const plain = world('keyless', [[A, DEPLOY_A]]);
    expect((await judge(plain, [])).issues.some((i) => notHandled(A).test(i.message))).toBe(true);
    expect(shown(await judge(plain, [], plain.texts, [{ path: A, triggers: ['push'], why: 'listed' }]))).toBe('');
    // only pipegen's marked edit counts: the same text written as a whole file (no mark) is not an edit of the user's workflow (R2 mutation survivor)
    const whole = { ...(plain.v.inserts[0] as VerifyPlan['inserts'][number]).file, inserted: undefined } as unknown as CreatedFile;
    expect((await judge(plain, [whole])).issues.some((i) => notHandled(A).test(i.message)), 'whole file').toBe(true);
    // the gaps pipegen itself lists (a workflow_run deploy) are accepted
    const wr = world('keyless', [[A, DEPLOY_A.replace(/on:[\s\S]*?jobs:/, 'on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\njobs:')]]);
    expect(wr.v.inserts).toEqual([]);
    expect(wr.v.gaps.map((g) => g.path)).toEqual([A]);
    expect(shown(await judge(wr))).toBe('');
  });
  it('G17A-R2 sec r2-N1: with the texts given, every edit\'s original is the text pipegen read', async () => {
    const w = calledWorld(CALLER_A, CALLED_A);
    expect(shown(await judge(w))).toBe('');
    const other = CALLER_A.replace('npm run build', 'npm run build:all');
    const r = await judge(w, undefined, new Map([[A, other], [SHIP, CALLED_A]]));
    expect(r.issues.some((i) => new RegExp(`The edit's original of ${A.replace(/[./]/g, '\\$&')} is not the text pipegen read`).test(i.message)), shown(r)).toBe(true);
    const r2 = await judge(w, undefined, new Map([[A, CALLER_A]]));
    expect(r2.issues.some((i) => new RegExp(`The edit's original of ${SHIP.replace(/[./]/g, '\\$&')} is not the text pipegen read`).test(i.message)), shown(r2)).toBe(true);
  });
});
