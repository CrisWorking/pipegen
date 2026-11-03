// Plan E E3 (Task 2, second half; rulings B5, B7, S6, S8 tests, E3-R1): the proof harness. It runs only in the private scratch
// repo, next to the user's real test keys, so every job starts with the reviewed egress step, no step holds a literal secret,
// no job can be started by hand, and every action is pinned by commit. The harness is rendered from a draft; the YAML is parsed
// back and judged as data. Nothing touches the network.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { COMPOSE_PATH, planCompose } from '../src/create/compose.js';
import { loadBaseImages } from '../src/engine/base-images.js';
import { EGRESS_DOMAIN_SETS, renderEgressCheckStep, renderEgressStep } from '../src/engine/egress.js';
import { PLATFORM_ACTION_IDS } from '../src/engine/pin.js';
import { RenderError } from '../src/engine/render-error.js';
import { releaseInstallStep, renderStarterTestRun } from '../src/engine/render-cli.js';
import { PROOF_OVERRIDE_PATH, renderComposeUp, renderFindRunStep, renderRuntimeEnv } from '../src/engine/render-step.js';
import { parseYaml } from '../src/engine/yaml-parse.js';
import { harnessWorkflow, HARNESS_PATH, PROOF_SIGNING_MODE, proofAppFiles, proofOverrideText, type HarnessOptions } from '../src/proof/harness.js';
import { checkCentralPins } from '../src/proof/snapshot.js';
import { proofTarget } from '../src/proof/target.js';
import type { Capabilities, CreatedFile, Dependency, DependencyKind, PipelineDraft, Service } from '../src/types.js';
import { platform, reviewedList, service, profile } from './helpers/render.js';
import { gitRepoWith } from './helpers/git-repo-with.js';

const list = loadBaseImages();
const reviewed = reviewedList();
const PLATFORM = platform(reviewed);
const CENTRAL_SHA = 'c'.repeat(40);
const PIN_SHA = 'd'.repeat(40);

const dep = (kind: DependencyKind, envVars: string[] = []): Dependency => ({ kind, name: kind, evidence: 'x', envVars });
const api = (over: Partial<Service> = {}): Service => service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000, scripts: ['start'], dependsOn: [dep('postgres', ['DATABASE_URL'])], ...over });
const web = (over: Partial<Service> = {}): Service => service({ name: 'web', path: 'apps/web', dockerfile: 'apps/web/Dockerfile', port: 3001, scripts: ['start'], dependsOn: [dep('redis', ['REDIS_URL'])], ...over });
const caps = (): Capabilities => ({ branchProtection: true, environments: true, envRequiredReviewers: false, deploymentBranchPolicies: true, attestations: false, codeScanning: false, keylessSigningAllowed: false });

function draft(services: Service[] = [api()], over: Partial<PipelineDraft> = {}, extra: CreatedFile[] = []): PipelineDraft {
  const p = { ...profile(services), owner: 'CrisWorking', repo: 'shop', private: true };
  const compose = planCompose(p, list, []).text;
  const created: CreatedFile[] = [...(compose === null ? [] : [{ path: COMPOSE_PATH, content: compose, part: 'compose' as const, reason: 'r', repo: 'app' as const }]), ...extra];
  return {
    profile: p, capabilities: caps(), needs: [], steps: [], created, notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false,
    skipped: [], suggestions: [], centralPin: { repo: 'CrisWorking/pipelines', sha: PIN_SHA }, ...over,
  };
}
const opts = (over: Partial<HarnessOptions> = {}): HarnessOptions => ({ platform: PLATFORM, reviewed, centralSha: CENTRAL_SHA, createdTests: false, signing: 'key-env', ...over });

type Step = { id?: string; name: string; uses?: string; with?: Record<string, string>; run?: string; env?: Record<string, string>; if?: string };
type Job = { if?: string; 'runs-on': string; permissions: Record<string, string>; steps: Step[]; services?: Record<string, { image: string; ports: string[] }> };
type Wf = { on: Record<string, { branches: string[] }>; permissions: Record<string, string>; jobs: Record<string, Job> };
const wfOf = (d: PipelineDraft = draft(), o: HarnessOptions = opts()): Wf => parse(harnessWorkflow(d, o).file.content) as Wf;
const runs = (j: Job): string => j.steps.map((s) => s.run ?? '').join('\n');
const startedTests = (): CreatedFile[] => [{ path: 'api/test/pipegen-starter.test.js', content: 'test', part: 'tests', reason: 'r', repo: 'app' }];
const bullfrog = reviewed.find((t) => t.id === 'bullfrog')!;

describe('harness: jobs, triggers, permissions', () => {
  it('harness: egress step is the first step of every job', () => {
    const wf = wfOf(draft([api()]), opts({ createdTests: true }));
    const d = draft([api()], {}, startedTests());
    const all = [wf, wfOf(d, opts({ createdTests: true })), wfOf(draft([api()], { centralPin: undefined }), opts({ centralSha: undefined, signing: 'none' }))];
    for (const w of all) {
      expect(Object.keys(w.jobs).length).toBeGreaterThan(1);
      for (const [id, job] of Object.entries(w.jobs)) {
        const first = job.steps[0]!;
        expect(first.uses, id).toBe(bullfrog.step.action!.uses);
        expect(first.with, id).toMatchObject(bullfrog.fixedInputs.with!);
        expect(first.with!['enable-sudo'], id).toBe('false');
        expect(first.with!['egress-policy'], id).toBe('block');
        // nothing runs before it: no job-level env, no container, no other step
        expect(Object.keys(job), id).not.toContain('env');
        expect(Object.keys(job), id).not.toContain('container');
        expect(job.steps.filter((s) => s.uses === bullfrog.step.action!.uses), id).toHaveLength(1);
      }
    }
    expect(Object.keys(all[1]!.jobs).sort()).toEqual(['app-start', 'egress-check', 'sign-roundtrip', 'tests-repeat', 'verify-lookup']);
  });

  it('harness (E3-R1): each job lists exactly the egress sets it needs', () => {
    const h = harnessWorkflow(draft([api()], {}, startedTests()), opts({ createdTests: true }));
    const by = Object.fromEntries(h.jobs.map((j) => [j.id, j]));
    expect(by['egress-check']).toMatchObject({ egress: [], dockerNetworks: false });
    expect(by['verify-lookup']).toMatchObject({ egress: [], dockerNetworks: false });
    expect(by['app-start']).toMatchObject({ egress: ['dockerhub', 'npm'], dockerNetworks: true });
    expect(by['sign-roundtrip']).toMatchObject({ egress: ['dockerhub', 'github-releases', 'npm'], dockerNetworks: true });
    expect(by['tests-repeat']).toMatchObject({ egress: ['dockerhub', 'npm'], dockerNetworks: false });
    // and the rendered step is exactly renderEgressStep of that list
    const wf = parse(h.file.content) as Wf;
    for (const j of h.jobs) expect(wf.jobs[j.id]!.steps[0]!.with, j.id).toEqual(renderEgressStep(j.egress, { dockerNetworks: j.dockerNetworks }).with);
    // no job asks for the scanner hosts it doesn't need
    expect(h.file.content).not.toContain('api.osv.dev');
    expect(h.file.content).not.toContain('mirror.gcr.io');
  });

  it('harness: no workflow_dispatch trigger in any proof workflow', () => {
    const h = harnessWorkflow(draft(), opts());
    const wf = parse(h.file.content) as Wf;
    expect(Object.keys(wf.on).sort()).toEqual(['pull_request', 'push']);
    expect(wf.on.pull_request).toEqual({ branches: ['main'] });
    expect(wf.on.push).toEqual({ branches: ['main'] });
    expect(h.file.content).not.toMatch(/workflow_dispatch|repository_dispatch|workflow_run|pull_request_target|schedule/);
    // the app's own default branch, never a hard-coded main
    const dev = draft();
    dev.profile.defaultBranch = 'develop';
    expect((wfOf(dev).on.push)).toEqual({ branches: ['develop'] });
    dev.profile.defaultBranch = 'a..b';
    expect(() => harnessWorkflow(dev, opts())).toThrow(RenderError);
  });

  it('harness: workflow permissions {}; every job contents: read; verify-lookup adds actions: read only', () => {
    const wf = wfOf(draft([api()], {}, startedTests()), opts({ createdTests: true }));
    expect(wf.permissions).toEqual({});
    for (const [id, job] of Object.entries(wf.jobs)) {
      expect(job.permissions, id).toEqual(id === 'verify-lookup' ? { contents: 'read', actions: 'read' } : { contents: 'read' });
      expect(job['runs-on'], id).toBe('ubuntu-24.04');
    }
  });

  it('harness: the file is a freshly rendered app workflow E2 takes, and it parses strictly (no anchor, tag or merge key)', () => {
    const h = harnessWorkflow(draft(), opts());
    expect(h.file.path).toBe(HARNESS_PATH);
    expect(Object.keys(h.file).sort()).toEqual(['content', 'part', 'path', 'reason', 'repo']);
    expect(h.file.repo).toBe('app');
    expect('problems' in parseYaml(h.file.content, 'strict')).toBe(false);
    expect(h.file.content).not.toMatch(/^\s*[^#\n]*(?:<<:|![a-z!]|&[a-z])/m);
    // E2's pin check accepts it: the layout is the proof's central sha, the gate is not a pipelines reference
    const t = proofTarget({ owner: 'CrisWorking', repo: 'shop', private: true, ownerType: 'User', defaultBranch: 'main' });
    expect(() => checkCentralPins([{ path: h.file.path, content: h.file.content }, { path: '.github/workflows/pipegen.yml', content: `on: push\njobs:\n  a:\n    uses: CrisWorking/pipelines/.github/workflows/shop--merge.yml@${CENTRAL_SHA}\n` }], t, CENTRAL_SHA, new Set(['.github/workflows/shop--merge.yml']))).not.toThrow();
  });
});

describe('harness: egress-check', () => {
  it('harness: egress-check step: curl to a non-allowed host must fail', () => {
    const wf = wfOf();
    const job = wf.jobs['egress-check']!;
    expect(job.if).toBeUndefined();   // both events
    expect(job.steps).toHaveLength(2);
    const check = job.steps[1]!;
    expect(check.run).toBe(renderEgressCheckStep().run);
    expect(check.run).toContain('https://example.com');
    // example.com is in no egress set, so the request must fail: an answer fails the job
    for (const hosts of Object.values(EGRESS_DOMAIN_SETS)) expect(hosts).not.toContain('example.com');
    expect(job.steps[0]!.with!['allowed-domains']!.split('\n')).toEqual([...EGRESS_DOMAIN_SETS['github-core']].sort());
    // E0d review: a BASH_ENV or ENV can't stand in for curl: the step clears both, and the job sets no env at all
    expect(check.env).toEqual({ BASH_ENV: '', ENV: '' });
    expect(Object.keys(job)).not.toContain('env');
  });
});

describe('harness: app-start (ruling B7)', () => {
  const twoApps = () => draft([api(), web()]);

  it('harness: app-start uses compose and runtimeEnv, no literal secrets', () => {
    const h = harnessWorkflow(twoApps(), opts());
    const job = (parse(h.file.content) as Wf).jobs['app-start']!;
    expect(job.if).toBe("github.event_name == 'pull_request'");
    expect(runs(job)).toContain('docker compose --env-file /dev/null -f docker-compose.pipegen.yml');
    const rt = renderRuntimeEnv(planCompose(twoApps().profile, list, []).env);
    expect(job.steps.find((s) => s.id === rt.id)?.run).toBe(rt.run);
    // no secret value and no secret reference at all in the harness, except the workflow token of the find-run step
    const refs = [...h.file.content.matchAll(/\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g)].map((m) => m[1]);
    expect(refs).toEqual(['GITHUB_TOKEN']);
    expect(h.file.content).not.toMatch(/(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9+/_-]{8,}/i);
    expect(runs(job)).toContain('openssl rand -hex');
  });

  it('harness: app-start uses renderRuntimeEnv then renderComposeUp in the same job', () => {
    const job = wfOf(twoApps()).jobs['app-start']!;
    const ids = job.steps.map((s) => s.id);
    const rt = renderRuntimeEnv(planCompose(twoApps().profile, list, []).env);
    const up = renderComposeUp({ proofOverride: true });
    const iRt = ids.indexOf(rt.id);
    const iUp = ids.indexOf(up.id);
    expect(iRt).toBeGreaterThan(0);
    expect(iUp).toBeGreaterThan(iRt);
    expect(job.steps[iUp]!.run).toBe(up.run);
    expect(job.steps[1]!.uses).toBe(PLATFORM.checkout.step.action!.uses);
    expect(job.steps[1]!.with!['persist-credentials']).toBe('false');
  });

  it('harness: app-start builds with docker build --network host, then compose up --no-build', () => {
    const job = wfOf(twoApps()).jobs['app-start']!;
    const builds = job.steps.filter((s) => /docker build/.test(s.run ?? ''));
    expect(builds).toHaveLength(2);
    for (const b of builds) expect(b.run).toMatch(/docker build --network host -t "pipegen-proof\/app-[a-z]+:\$\{GITHUB_SHA\}" /);
    const up = job.steps.find((s) => (s.run ?? '').includes('up -d --wait'))!;
    expect(up.run).toContain('--no-build');
    expect(up.run).toContain(`-f "${PROOF_OVERRIDE_PATH}"`);
    expect(job.steps.indexOf(up)).toBeGreaterThan(job.steps.indexOf(builds[1]!));
    // the override is computed: only image: per app service, the same tag the build used; it is in no proof file
    const write = job.steps.find((s) => s.env?.PIPEGEN_PROOF_OVERRIDE !== undefined)!;
    expect(write.env!.PIPEGEN_PROOF_OVERRIDE).toBe(proofOverrideText([{ key: 'app-api' }, { key: 'app-web' }]));
    expect(parse(write.env!.PIPEGEN_PROOF_OVERRIDE!)).toEqual({ services: { 'app-api': { image: 'pipegen-proof/app-api:${GITHUB_SHA:?}' }, 'app-web': { image: 'pipegen-proof/app-web:${GITHUB_SHA:?}' } } });
    expect(write.run).toContain(`> "${PROOF_OVERRIDE_PATH}"`);
    expect(job.steps.indexOf(write)).toBeLessThan(job.steps.indexOf(up));
    // docker networks need allowed-ips (S8); the registry the build needs is listed
    expect(job.steps[0]!.with!['allowed-ips']).toBe('172.16.0.0/12');
    expect(job.steps[0]!.with!['allowed-domains']).toContain('registry.npmjs.org');
    // a probe per app on its own port: started = a status below 500
    for (const port of [3000, 3001]) {
      const probe = job.steps.find((s) => (s.run ?? '').includes(`http://127.0.0.1:${port}/`))!;
      expect(probe.run).toContain("curl --silent --retry 10 --retry-connrefused --retry-delay 3 --max-time 10 -o /dev/null -w '%{http_code}'");
      expect(probe.run).toContain('[1-4][0-9][0-9]) exit 0');
    }
  });

  it('harness: app-start probe: a status below 500 passes, 5xx and no answer fail', () => {
    const probe = wfOf(twoApps()).jobs['app-start']!.steps.find((s) => (s.run ?? '').includes('http://127.0.0.1:3000/'))!.run!;
    const runWith = (code: string) => {
      try {
        execFileSync('bash', ['-c', `curl() { printf '%s' '${code}'; }\ndocker() { :; }\n${probe}`], { stdio: 'pipe', env: { PATH: process.env.PATH, RUNNER_TEMP: '/tmp' } });
        return 0;
      } catch (e) { return (e as { status: number }).status; }
    };
    for (const ok of ['200', '302', '404', '401', '499']) expect(runWith(ok), ok).toBe(0);
    for (const bad of ['500', '503', '000', '', '5000', 'abc']) expect(runWith(bad), bad).toBe(1);
  });

  it('harness: app-start builds each service from its own folder', () => {
    const job = wfOf(draft([api(), web(), api({ name: 'root', path: '.', dockerfile: 'Dockerfile', port: 4000 })])).jobs['app-start']!;
    const builds = job.steps.filter((s) => /docker build/.test(s.run ?? '')).map((s) => s.run!.split('\n')[1]);
    expect(builds).toEqual([
      'docker build --network host -t "pipegen-proof/app-api:${GITHUB_SHA}" ./api',
      'docker build --network host -t "pipegen-proof/app-root:${GITHUB_SHA}" .',
      'docker build --network host -t "pipegen-proof/app-web:${GITHUB_SHA}" ./apps/web',
    ]);
  });

  it('harness: no app-start without the computed compose file (absent, or not the computed one)', () => {
    const none = harnessWorkflow(draft([api({ dependsOn: [] })]), opts());
    expect(none.jobs.map((j) => j.id)).not.toContain('app-start');
    expect(none.notes.join(' ')).toMatch(/no docker-compose\.pipegen\.yml/);
    const edited = draft();
    edited.created[0] = { ...edited.created[0]!, content: `${edited.created[0]!.content}  extra: {}\n` };
    const h = harnessWorkflow(edited, opts());
    expect(h.jobs.map((j) => j.id)).not.toContain('app-start');
    expect(h.notes.join(' ')).toMatch(/not the file pipegen computes/);
  });

  it('harness: proofOverrideText takes only computed app keys', () => {
    expect(proofOverrideText([{ key: 'app-api' }])).toBe('services:\n  app-api:\n    image: "pipegen-proof/app-api:${GITHUB_SHA:?}"\n');
    for (const key of ['api', 'app-', 'app-A', 'app-x\n  privileged: true', 'postgres']) expect(() => proofOverrideText([{ key }]), key).toThrow(RenderError);
    expect(() => proofOverrideText([])).toThrow(RenderError);
  });
});

describe('harness: sign-roundtrip', () => {
  it('harness: sign-roundtrip uses local registry service, key-based, tlog-upload=false', () => {
    const job = wfOf().jobs['sign-roundtrip']!;
    const registry = reviewed.find((t) => t.id === 'registry')!;
    expect(job.if).toBe("github.event_name == 'pull_request'");
    expect(job.services).toEqual({ registry: { image: `registry:2.8.3@${registry.candidate.pin.digest}`, ports: ['127.0.0.1:5000:5000'] } });
    const text = runs(job);
    expect(text).toContain('docker build --network host -t "localhost:5000/pipegen-proof/app-api:${GITHUB_SHA}" ./api');
    expect(text).toContain('docker push --quiet "localhost:5000/pipegen-proof/app-api:${GITHUB_SHA}"');
    expect(text).toMatch(/generate-key-pair --output-key-prefix "\$RUNNER_TEMP\/pipegen-sign\/proof"/);
    expect(text).toMatch(/ sign --yes --key "\$RUNNER_TEMP\/pipegen-sign\/proof\.key" --tlog-upload=false --use-signing-config=false "\$ref"/);
    expect(text).toMatch(/ verify --key "\$RUNNER_TEMP\/pipegen-sign\/proof\.pub" --insecure-ignore-tlog=true "\$ref"/);
    // never keyless, never a Sigstore host, never a stored key
    expect(text).not.toMatch(/--identity-token|fulcio|rekor|sigstore\.dev|oidc|secrets\./i);
    expect(job.steps[0]!.with!['allowed-domains']).not.toMatch(/sigstore|fulcio|rekor/);
    // the reviewed cosign, by its pinned release and sha256
    const cosign = reviewed.find((t) => t.id === 'cosign')!;
    const install = job.steps.find((s) => s.env?.PIPEGEN_DL_URL !== undefined)!;
    expect(install.env!.PIPEGEN_DL_URL).toBe(`https://github.com/sigstore/cosign/releases/download/${cosign.step.cli!.install.version}/cosign-linux-amd64`);
    expect(install.env!.PIPEGEN_DL_SHA256).toBe(cosign.candidate.pin.checksum);
    expect(job.steps[0]!.with!['allowed-ips']).toBe('172.16.0.0/12');
  });

  it('harness: sign-roundtrip only when the delivered signing mode is not none, and only with an image to sign', () => {
    for (const mode of ['keyless', 'attest', 'key-env'] as const) expect(harnessWorkflow(draft(), opts({ signing: mode })).jobs.map((j) => j.id), mode).toContain('sign-roundtrip');
    const none = harnessWorkflow(draft(), opts({ signing: 'none' }));
    expect(none.jobs.map((j) => j.id)).not.toContain('sign-roundtrip');
    expect(none.notes.join(' ')).toMatch(/signing mode is none/);
    const noImage = harnessWorkflow(draft([api({ dockerfile: undefined, dependsOn: [] })]), opts());
    expect(noImage.jobs.map((j) => j.id)).not.toContain('sign-roundtrip');
    // a Dockerfile the draft creates counts
    const created = harnessWorkflow(draft([api({ dockerfile: undefined, dependsOn: [] })], {}, [{ path: 'api/Dockerfile', content: 'FROM x', part: 'docker', reason: 'r', repo: 'app' }]), opts());
    expect(created.jobs.map((j) => j.id)).toContain('sign-roundtrip');
  });

  it('harness: proof pipeline assembled with signing none', async () => {
    const modes: string[] = [];
    const shas: (string | undefined)[] = [];
    const d = draft();
    const dir = gitRepoWith({});
    const files = proofAppFiles(d, {
      assemble: (mode, sha) => { modes.push(mode); shas.push(sha); return [{ path: '.github/workflows/pipegen.yml', content: 'on: push\njobs: {}\n', part: 'pipeline', reason: 'r', repo: 'app' }]; },
      harness: { platform: PLATFORM, reviewed, createdTests: false, signing: 'key-env' },
      dir,
    });
    const out = await files.appFiles(CENTRAL_SHA);
    expect(modes).toEqual(['none']);
    expect(PROOF_SIGNING_MODE).toBe('none');
    expect(shas).toEqual([CENTRAL_SHA]);
    expect(out.map((f) => f.path)).toEqual(['.github/workflows/pipegen.yml', HARNESS_PATH]);
    // the delivered mode (key-env) is what sign-roundtrip proves
    expect(files.last()!.harness.jobs.map((j) => j.id)).toContain('sign-roundtrip');
    // a path given twice is a stop
    const twice = proofAppFiles(d, { assemble: () => [{ path: HARNESS_PATH, content: 'x', part: 'pipeline', reason: 'r', repo: 'app' }], harness: { platform: PLATFORM, reviewed, createdTests: false, signing: 'none' }, dir });
    await expect(twice.appFiles(CENTRAL_SHA)).rejects.toThrow(/Two proof files/);
  });
});

describe('harness: tests-repeat (S6, D7-R7)', () => {
  it('harness: tests-repeat runs created tests a second time', () => {
    const d = draft([api()], {}, startedTests());
    const job = wfOf(d, opts({ createdTests: true })).jobs['tests-repeat']!;
    expect(job.if).toBe("github.event_name == 'pull_request'");
    const text = runs(job);
    expect(text).toContain('node node_modules/vitest/vitest.mjs run --isolate --reporter=junit');
    // its own JUnit report, uploaded under its own name, for Plan D sameResults against the first run
    const up = job.steps.find((s) => s.uses === PLATFORM['upload-artifact'].step.action!.uses)!;
    expect(up.with!.name).toBe('pipegen-out-junit-repeat-api');
    expect(up.with!.path).toBe('${{ runner.temp }}/pipegen-out/pipegen-out-junit-repeat-api');
    expect(up.if).toBe('always()');
    expect(text).toContain('"$RUNNER_TEMP/pipegen-out/pipegen-out-junit-repeat-api/junit.xml"');
  });

  it('harness: tests-repeat only with created tests; vitest run --isolate --reporter=junit', () => {
    const withFiles = draft([api()], {}, startedTests());
    // createdTests false (always in v0.2 until Plan G's isolated job, D7-R7): no job, even with test files
    expect(harnessWorkflow(withFiles, opts({ createdTests: false })).jobs.map((j) => j.id)).not.toContain('tests-repeat');
    // createdTests true without a created test file: no job
    expect(harnessWorkflow(draft(), opts({ createdTests: true })).jobs.map((j) => j.id)).not.toContain('tests-repeat');
    // other created files in a service folder (a Dockerfile) are not created tests
    const docker = draft([api()], {}, [{ path: 'api/Dockerfile', content: 'FROM x', part: 'docker', reason: 'r', repo: 'app' }]);
    expect(harnessWorkflow(docker, opts({ createdTests: true })).jobs.map((j) => j.id)).not.toContain('tests-repeat');
    expect(() => harnessWorkflow(withFiles, opts({ createdTests: 'yes' as unknown as boolean }))).toThrow(RenderError);
    const text = runs(wfOf(withFiles, opts({ createdTests: true })).jobs['tests-repeat']!);
    expect(text).toMatch(/vitest\.mjs run --isolate --reporter=junit --outputFile\.junit=\S+/);
    expect(text).not.toMatch(/--passWithNoTests|--allowOnly/);
    // the reviewed vitest version is checked in the lockfile before npm ci
    const vitest = reviewed.find((t) => t.id === 'vitest-coverage')!;
    expect(JSON.stringify(wfOf(withFiles, opts({ createdTests: true })).jobs['tests-repeat'])).toContain(`\\"version\\":\\"${vitest.step.cli!.install.version}\\"`);
  });

  it('harness: created tests run with --network none or an internal network', () => {
    const job = wfOf(draft([api()], {}, startedTests()), opts({ createdTests: true })).jobs['tests-repeat']!;
    const vitestLines = runs(job).split('\n').filter((l) => l.includes('vitest.mjs run'));
    expect(vitestLines).toHaveLength(1);
    for (const l of vitestLines) {
      expect(l).toMatch(/docker create .*--network none /);
      expect(l).toContain('--cap-drop ALL');
      expect(l).toContain('--security-opt no-new-privileges');
    }
    // and never a vitest run on the runner itself
    expect(runs(job).split('\n').filter((l) => /vitest/.test(l) && !l.includes('docker create'))).toEqual([]);
  });

  it('harness (S6): renderStarterTestRun and releaseInstallStep refuse anything but the reviewed entries and plain values', () => {
    const vitest = reviewed.find((t) => t.id === 'vitest-coverage')!;
    const image = 'node:24-bookworm-slim@sha256:' + 'a'.repeat(64);
    const ok = { vitest, image, nodeMajor: '24', artifact: 'pipegen-out-junit-repeat-api' };
    expect(renderStarterTestRun(api(), ok)).toHaveLength(4);
    expect(() => renderStarterTestRun(api(), { ...ok, vitest: reviewed.find((t) => t.id === 'c8')! })).toThrow(RenderError);
    expect(() => renderStarterTestRun(api(), { ...ok, image: 'node:24' })).toThrow(RenderError);
    expect(() => renderStarterTestRun(api(), { ...ok, nodeMajor: '24; rm' })).toThrow(RenderError);
    expect(() => renderStarterTestRun(api(), { ...ok, artifact: 'junit' })).toThrow(RenderError);
    expect(() => renderStarterTestRun(api({ path: '../x' }), ok)).toThrow(RenderError);
    expect(() => releaseInstallStep(reviewed.find((t) => t.id === 'semgrep')!, 'x')).toThrow(RenderError);
    expect(() => releaseInstallStep(reviewed.find((t) => t.id === 'cosign')!, 'Bad Name')).toThrow(RenderError);
    // the default compose-up is unchanged (Plan G's referee recognises it exactly)
    expect(renderComposeUp().run).toBe('set -euo pipefail\ndocker compose --env-file /dev/null -f docker-compose.pipegen.yml up -d --wait');
    expect(() => renderComposeUp({ proofOverride: false as unknown as true })).toThrow(RenderError);
  });

  it('harness (S6): src/proof never sets isolatedTestJob', () => {
    const dir = join(import.meta.dirname, '../src/proof');
    for (const f of readdirSync(dir)) expect(readFileSync(join(dir, f), 'utf8'), f).not.toMatch(/isolatedTestJob/);
  });
});

describe('harness: verify-lookup', () => {
  it('harness: verify-lookup runs on push to the default branch only and uses findGatedRun', () => {
    const wf = wfOf();
    const job = wf.jobs['verify-lookup']!;
    expect(job.if).toBe("github.event_name == 'push'");
    expect(wf.on.push).toEqual({ branches: ['main'] });
    const gate = reviewed.find((t) => t.id === 'pipegen-gate')!;
    expect(job.steps).toHaveLength(2);
    expect(job.steps[1]!.uses).toBe(gate.step.action!.uses);
    expect(job.steps[1]!.with!.mode).toBe('find-run');
    // every other job runs on pull requests (or both, the egress check): verify-lookup is the only push-only job
    for (const [id, j] of Object.entries(wf.jobs)) if (id !== 'verify-lookup') expect(j.if ?? 'both', id).not.toBe("github.event_name == 'push'");
  });

  it('harness: verify-lookup = renderFindRunStep with layout from centralPin, sha github.sha', () => {
    const gate = reviewed.find((t) => t.id === 'pipegen-gate')!;
    const central = wfOf().jobs['verify-lookup']!.steps[1]!;
    const want = renderFindRunStep(gate, { central: { repo: 'CrisWorking/pipelines', sha: CENTRAL_SHA, project: 'shop' }, sha: 'github.sha', timeoutMinutes: 45 });
    expect(central.with).toEqual(want.with);
    expect(central.with!.layout).toBe('central');
    expect(central.with!['central-sha']).toBe(CENTRAL_SHA);   // the proof's central commit, not the delivered pin
    expect(central.with!.sha).toBe('${{ github.sha }}');
    const inline = wfOf(draft([api()], { centralPin: undefined }), opts({ centralSha: undefined })).jobs['verify-lookup']!.steps[1]!;
    expect(inline.with).toEqual(renderFindRunStep(gate, { sha: 'github.sha', timeoutMinutes: 45 }).with);
    expect(inline.with!.layout).toBe('inline');
    // the layout must agree with the draft
    expect(() => harnessWorkflow(draft(), opts({ centralSha: undefined }))).toThrow(RenderError);
    expect(() => harnessWorkflow(draft([api()], { centralPin: undefined }), opts())).toThrow(RenderError);
    expect(() => harnessWorkflow(draft(), opts({ centralSha: 'abc' }))).toThrow(RenderError);
  });
});

describe('harness: S8 rules', () => {
  const all = () => wfOf(draft([api(), web()], {}, startedTests()), opts({ createdTests: true }));

  it('harness: no -v host mounts in jobs with enable-sudo false', () => {
    const wf = all();
    for (const [id, job] of Object.entries(wf.jobs)) {
      expect(job.steps[0]!.with!['enable-sudo']).toBe('false');
      const text = runs(job);
      // every docker command line: no bind mount of any form (Bullfrog refuses host paths while sudo is off, S8)
      for (const line of text.split('\n').filter((l) => /\bdocker\b/.test(l))) expect(line, id).not.toMatch(/(?:^|\s)(?:-v|--volume|--mount)(?:[\s=])/);
      expect(text, id).not.toMatch(/\bsudo\b|--privileged|--pid[= ]host|--cap-add/);
      for (const svc of Object.values(job.services ?? {})) expect(Object.keys(svc).sort(), id).toEqual(['image', 'ports']);
    }
  });

  it('harness: every action pinned by sha from PlatformActions or the reviewed list', () => {
    const wf = all();
    const allowed = new Set([...Object.keys(PLATFORM_ACTION_IDS).map((k) => PLATFORM[k as keyof typeof PLATFORM].step.action!.uses), ...reviewed.flatMap((t) => (t.step.action === undefined ? [] : [t.step.action.uses]))]);
    let n = 0;
    for (const [id, job] of Object.entries(wf.jobs)) {
      for (const s of job.steps) {
        if (s.uses === undefined) continue;
        n++;
        expect(s.uses, id).toMatch(/^[a-z0-9_.-]+\/[a-z0-9_./-]+@[0-9a-f]{40}$/i);
        expect(allowed.has(s.uses), `${id} ${s.uses}`).toBe(true);
      }
      for (const svc of Object.values(job.services ?? {})) expect(svc.image, id).toMatch(/@sha256:[0-9a-f]{64}$/);
    }
    expect(n).toBeGreaterThan(8);
    // images pulled by steps are pinned by digest too
    const images = [...JSON.stringify(wf).matchAll(/PIPEGEN_IMAGE":"([^"]+)"/g)].map((m) => m[1]!);
    expect(images.length).toBeGreaterThan(0);
    for (const i of images) expect(i).toMatch(/@sha256:[0-9a-f]{64}$/);
  });

  it('harness: every base image is on Docker Hub (the sets app-start and sign-roundtrip add assume it)', () => {
    for (const b of list) expect(b.image, b.id).not.toMatch(/\//);
  });
});

