// v0.2 Plan G, sub-task G15a, ruling G15a-R11 (security re-review r5 CHANGES REQUIRED, Important since G7: the digest race on the classic
// image store). Each item as a failing test first, from the reviewer's probes (zz-r5-sec.test.ts, zz-r5b-sec.test.ts).
// r5-1: the publish digest step proves the digest is the image this job built: the daemon's RepoDigests of the build's imageid hold
//       <repo>@<digest> (the script runs, both store shapes, in test/deploy-scripts.test.ts); the referee requires that exact step.
// r5-2: the image-publish build and tag are bound to the PUBLISHED service, not to any root service whose Dockerfile is built.
// r5-3: build-push, docker login, setup-buildx, the publish digest step and attest are refused in a composite action (central and local).
// r5-4: setup-buildx is no step of image-publish.
import { Document, parse, stringify } from 'yaml';
import { describe, expect, it } from 'vitest';
import { BUILD_PUSH_STEP_ID, PUBLISH_DIGEST_ENV, PUBLISH_DIGEST_STEP_ID, renderPublishDigestStep } from '../src/engine/deploy-steps.js';
import { renderPlatformStep } from '../src/engine/render-step.js';
import { assemble as assembleFiles, judgeAssembled } from '../src/layers/assemble.js';
import { releaseJobs } from '../src/layers/deploy.js';
import type { Capabilities, CreatedFile, PipelineDraft, ReviewedTool, Service } from '../src/types.js';
import { CAPS, LINTERS, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

const web = (name = 'app', port = 3000, path = '.', dockerfile = 'Dockerfile') => node({ name, dockerfile, port, path });
const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const PIN = { repo: 'o/pipelines', sha: 'c'.repeat(40) };
const MODES = ['attest', 'key-env', 'keyless'] as const;
type Mode = (typeof MODES)[number];
function signWorld(mode: Mode, svcs: Service[] = [web()], images = [{ service: 'app', repo: 'ghcr.io/o/r/pipegen-app' }]) {
  const priv = mode !== 'keyless';
  const caps: Capabilities = mode === 'attest' ? { ...CAPS, attestations: true, environments: true }
    : mode === 'key-env' ? { ...CAPS, environments: true, deploymentBranchPolicies: true, envRequiredReviewers: true } : { ...CAPS, keylessSigningAllowed: true };
  const signing = mode === 'key-env' ? { mode, images, cosignPubSha256: 'b'.repeat(64) } : { mode, images };
  const x = planned(profileOf(svcs, { private: priv }), { caps, over: { ...(priv ? { centralPin: PIN } : {}), signing } as Partial<PipelineDraft> });
  return assembleFiles(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode, layout: priv ? 'central' : 'local', plan: x.plan, deploy: releaseJobs(x.draft, { platform: p }) } as Parameters<typeof assembleFiles>[1]);
}
type W = ReturnType<typeof signWorld>;
const APP = '.github/workflows/pipegen.yml';
const appFile = (a: W) => a.files.find((x) => x.repo === 'app' && x.path === APP) as CreatedFile;
const appJobs = (a: W): Obj => (parse(appFile(a).content) as Obj).jobs as Obj;
function editApp(a: W, edit: (js: Obj) => void, extra: CreatedFile[] = []): W {
  const f = appFile(a);
  const js = parse(f.content) as Obj;
  edit(js);
  return { ...a, files: [...a.files.map((x) => (x === f ? { ...f, content: stringify(js, { lineWidth: 0 }) } : x)), ...extra] };
}
const editPub = (a: W, edit: (steps: Obj[]) => Obj[] | void): W => editApp(a, (js) => {
  const j = (js.jobs as Obj)['image-publish'] as Obj;
  const out = edit(j.steps as Obj[]);
  if (Array.isArray(out)) j.steps = out;
});
const bpAt = (steps: Obj[]): number => steps.findIndex((s) => s.id === BUILD_PUSH_STEP_ID);
const strip = ({ usesComment: _c, ...rest }: Obj): Obj => rest;

describe('G15a-R11 r5-1: the publish digest step proves the digest is the image this job built', () => {
  it('render: the step reads the build\'s imageid too and checks the daemon\'s RepoDigests of that image for <repo>@<digest> before writing', () => {
    const step = renderPublishDigestStep('app', 'ghcr.io/o/r/pipegen-app');
    expect(PUBLISH_DIGEST_ENV).toEqual({ PIPEGEN_IMAGE_DIGEST: `\${{ steps.${BUILD_PUSH_STEP_ID}.outputs.digest }}`, PIPEGEN_IMAGE_ID: `\${{ steps.${BUILD_PUSH_STEP_ID}.outputs.imageid }}` });
    expect(step.env).toMatchObject(PUBLISH_DIGEST_ENV);
    const run = String(step.run);
    expect(run).toContain(`docker image inspect --format '{{json .RepoDigests}}' -- "$image_id"`);
    expect(run).toContain("repo='ghcr.io/o/r/pipegen-app'\nwant=\"$repo@$digest\"");
    // the check comes before anything is written for the upload
    expect(run.indexOf('RepoDigests')).toBeGreaterThan(-1);
    expect(run.indexOf('RepoDigests')).toBeLessThan(run.indexOf('mkdir'));
    // a repository that is not pipegen's plain ghcr.io form is never written into the script
    for (const bad of ["ghcr.io/o/r/pipegen-app'; id; '", 'docker.io/o/r/app', 'ghcr.io/o/r/pipegen-app:pipegen', '', 'ghcr.io/o/r', 'ghcr.io/o/r/pipegen-app/x', 'ghcr.io//r/app']) expect(() => renderPublishDigestStep('app', bad), bad).toThrow();
  });

  it('referee: pipegen\'s own files pass in every mode; the digest step without the RepoDigests check (the G7 form) is refused', async () => {
    for (const mode of MODES) {
      const a = signWorld(mode);
      expect(shown(await judgeAssembled(a, JD)), mode).toBe('');
      const pub = appJobs(a)['image-publish'].steps as Obj[];
      expect(pub.find((s) => s.id === PUBLISH_DIGEST_STEP_ID)?.env, mode).toMatchObject(PUBLISH_DIGEST_ENV);
      const old = editPub(a, (steps) => {
        const d = steps.find((s) => s.id === PUBLISH_DIGEST_STEP_ID) as Obj;
        d.run = String(d.run).split('\n').filter((l) => !/image_id|RepoDigests|want=|command -v/.test(l)).join('\n');
        delete (d.env as Obj).PIPEGEN_IMAGE_ID;
      });
      const r = await judgeAssembled(old, JD);
      expect(r.ok, mode).toBe(false);
    }
  });
});

describe('G15a-R11 r5-2: image-publish bound to the published service', () => {
  // two services at the root: web (the deploy target, published) and api (no image to publish: a static site)
  const api = (dockerfile: string) => node({ name: 'api', dockerfile, port: 3001, path: '.', projectType: { types: ['static-site'] } } as Partial<Service>);
  it('own output passes with api first (its own Dockerfile.api, or the shared Dockerfile); a publish of api\'s image is refused', async () => {
    for (const mode of MODES) {
      for (const df of ['Dockerfile.api', 'Dockerfile']) {
        const a = signWorld(mode, [api(df), web('web', 3000, '.', 'Dockerfile')], [{ service: 'web', repo: 'ghcr.io/o/r/pipegen-web' }]);
        expect(shown(await judgeAssembled(a, JD)), `${mode} ${df} own`).toBe('');
        const r = await judgeAssembled(editPub(a, (s) => { const w = (s[bpAt(s)] as Obj).with as Obj; w.file = df; w.tags = 'ghcr.io/o/r/pipegen-api:pipegen'; }), JD);
        expect(r.ok, `${mode} ${df} api`).toBe(false);
        expect(shown(r), `${mode} ${df} api`).toMatch(/tags must be exactly ghcr\.io\/o\/r\/pipegen-web:pipegen/);
        if (df === 'Dockerfile.api') expect(shown(r), `${mode} ${df} api`).toMatch(/Dockerfile of a service at the repository root that pipegen publishes/);
      }
    }
  });
});

describe('G15a-R11 r5-3: no registry step in a composite action', () => {
  const login = renderPlatformStep('docker-login', p, { username: '${{ github.actor }}', [['pass', 'word'].join('')]: `${'$'}{{ secrets.${['GITHUB', 'TOK' + 'EN'].join('_')} }}` }, { registry: 'ghcr.io' });
  const push = renderPlatformStep('build-push', p, { file: 'Dockerfile', tags: 'ghcr.io/o/r/pipegen-other:pipegen' }, { push: 'true' });
  const buildx = renderPlatformStep('setup-buildx', p);
  const action = (repo: 'app' | 'central', steps: Obj[]): CreatedFile => {
    const doc = new Document();
    doc.contents = doc.createNode({ name: 'x', description: 'x', runs: { using: 'composite' } });
    doc.setIn(['runs', 'steps'], doc.createNode(steps.map(strip)));
    return { path: '.github/actions/x/action.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo } as CreatedFile;
  };
  it('build-push, docker login, setup-buildx and the publish digest step in a composite action are refused, in the central and the app repository', async () => {
    const a = signWorld('attest');
    const digest = renderPublishDigestStep('app', 'ghcr.io/o/r/pipegen-app');
    for (const repo of ['central', 'app'] as const) {
      for (const [name, steps] of [['build-push', [push]], ['docker-login', [login]], ['setup-buildx', [buildx]], ['login and push', [login, push]], ['publish-digest', [digest]]] as const) {
        const r = await judgeAssembled({ ...a, files: [...a.files, action(repo, steps as unknown as Obj[])] }, JD);
        expect(shown(r), `${repo} ${name}`).toMatch(/runs only in its own job, never in a composite action/);
      }
    }
  });
});

describe('G15a-R11 r5-4: setup-buildx is no step of image-publish', () => {
  it('a setup-buildx step in image-publish is refused by the job\'s step list', async () => {
    for (const mode of MODES) {
      const a = signWorld(mode);
      const r = await judgeAssembled(editPub(a, (s) => { s.splice(1, 0, strip(renderPlatformStep('setup-buildx', p) as unknown as Obj)); }), JD);
      expect(shown(r), mode).toMatch(/is a setup-buildx step; the job image-publish may run only/);
    }
  });
});
