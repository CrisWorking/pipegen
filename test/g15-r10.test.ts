// v0.2 Plan G, sub-task G15a, ruling G15a-R10 (security re-review r4 CHANGES REQUIRED; amends R9). Each item as a failing test first, from the
// reviewer's probe (zz-r4-sec.test.ts). r4-1: image-publish, and any job with a build that pushes, is refused outside pipegen.yml outright,
// so a stand-in image-publish can not let the real push run beside the sign job. r4-2: after its pushing build, image-publish ends with the
// digest step and its upload. r4-3: image-publish tags exactly the plan's image (publishedImageRepo:PUBLISH_TAG).
import { parse, stringify } from 'yaml';
import { describe, expect, it } from 'vitest';
import { assemble as assembleFiles, judgeAssembled } from '../src/layers/assemble.js';
import { releaseJobs } from '../src/layers/deploy.js';
import type { Capabilities, CreatedFile, PipelineDraft, ReviewedTool } from '../src/types.js';
import { CAPS, LINTERS, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

const web = (name = 'app', port = 3000, path = '.') => node({ name, dockerfile: path === '.' ? 'Dockerfile' : `${path}/Dockerfile`, port, path });
const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const PIN = { repo: 'o/pipelines', sha: 'c'.repeat(40) };
const DEPLOY_IF = "github.event_name == 'push'";
const MODES = ['attest', 'key-env', 'keyless'] as const;
type Mode = (typeof MODES)[number];
function signWorld(mode: Mode) {
  const priv = mode !== 'keyless';
  const caps: Capabilities = mode === 'attest' ? { ...CAPS, attestations: true, environments: true }
    : mode === 'key-env' ? { ...CAPS, environments: true, deploymentBranchPolicies: true, envRequiredReviewers: true } : { ...CAPS, keylessSigningAllowed: true };
  const images = [{ service: 'app', repo: 'ghcr.io/o/r/pipegen-app' }];
  const signing = mode === 'key-env' ? { mode, images, cosignPubSha256: 'b'.repeat(64) } : { mode, images };
  const x = planned(profileOf([web()], { private: priv }), { caps, over: { ...(priv ? { centralPin: PIN } : {}), signing } as Partial<PipelineDraft> });
  return assembleFiles(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode, layout: priv ? 'central' : 'local', plan: x.plan, deploy: releaseJobs(x.draft, { platform: p }) } as Parameters<typeof assembleFiles>[1]);
}
type W = ReturnType<typeof signWorld>;
const APP = '.github/workflows/pipegen.yml';
const appFile = (a: W) => a.files.find((x) => x.repo === 'app' && x.path === APP) as CreatedFile;
const appJobs = (a: W): Obj => (parse(appFile(a).content) as Obj).jobs as Obj;
const centralSign = (a: W): CreatedFile | undefined => a.files.find((f) => f.repo === 'central' && /--sign\.yml$/.test(f.path));
/** the real signing job: the inline keyless job, or the job sign of the central sign workflow */
const realSign = (a: W): Obj => {
  const c = centralSign(a);
  const j = c === undefined ? appJobs(a).sign : ((parse(c.content) as Obj).jobs as Obj).sign;
  const out = structuredClone(j) as Obj; delete out.if; delete out.needs; return out;
};
function editApp(a: W, edit: (js: Obj) => void, extra: CreatedFile[] = []): W {
  const f = appFile(a);
  const js = parse(f.content) as Obj;
  edit(js);
  return { ...a, files: [...a.files.map((x) => (x === f ? { ...f, content: stringify(js, { lineWidth: 0 }) } : x)), ...extra] };
}
const calledFile = (path: string, jobs: Obj, repo: 'app' | 'central' = 'app'): CreatedFile => ({ repo, path, content: stringify({ name: 'pipegen called', on: { workflow_call: null }, permissions: {}, jobs }, { lineWidth: 0 }) }) as CreatedFile;
const pubCopy = (a: W): Obj => { const j = structuredClone(appJobs(a)['image-publish']) as Obj; delete j.if; delete j.needs; return j; };
/** a job that does nothing and holds no power: the egress step only */
const standIn = (a: W, name: string, needs?: string[]): Obj => {
  const harden = structuredClone((appJobs(a)['image-publish'].steps as Obj[])[0]);
  return { name, 'runs-on': 'ubuntu-24.04', 'timeout-minutes': 5, ...(needs ? { needs } : {}), permissions: { contents: 'read' }, 'cache-mode': 'none', steps: [harden] };
};
const union = (...ps: Obj[]): Obj => {
  const L: Record<string, number> = { none: 0, read: 1, write: 2 };
  const out: Obj = {};
  for (const p0 of ps) for (const [k, v] of Object.entries(p0 ?? {})) if (out[k] === undefined || (L[v as string] as number) > (L[out[k] as string] as number)) out[k] = v;
  return out;
};
const OUTSIDE = /publishes outside \.github\/workflows\/pipegen\.yml/;
async function refused(w: W, label: string, re: RegExp): Promise<void> {
  const r = await judgeAssembled(w, JD);
  expect(r.ok, label).toBe(false);
  expect(shown(r), label).toMatch(re);
}

describe('G15a-R10: control', () => {
  it('pipegen\'s own files pass in all three signing modes', async () => {
    for (const mode of MODES) expect(shown(await judgeAssembled(signWorld(mode), JD)), mode).toBe('');
  });
});

describe('G15a-R10 r4-1: image-publish and any pushing build refused outside pipegen.yml', () => {
  it('S3: pipegen.yml\'s image-publish a stand-in, the real push in a local release.yml beside a stand-in sign (sign, Sign), every mode', async () => {
    for (const mode of MODES) {
      const a = signWorld(mode);
      for (const sid of ['sign', 'Sign']) {
        const w = editApp(a, (js) => {
          const jobs = js.jobs as Obj;
          jobs['image-publish'] = { ...standIn(a, 'pipegen image publish', ['pipegen']), if: DEPLOY_IF };
          jobs.release = { uses: './.github/workflows/release.yml', if: DEPLOY_IF, needs: ['pipegen', 'image-publish'], permissions: pubCopy(a).permissions };
        }, [calledFile('.github/workflows/release.yml', { 'image-publish': pubCopy(a), [sid]: standIn(a, 'pipegen sign', ['image-publish']) })]);
        await refused(w, `S3 ${mode} ${sid}`, OUTSIDE);
      }
    }
  });

  it('S3c: the real push in a central r--release.yml called at the pin (attest, key-env)', async () => {
    for (const mode of ['attest', 'key-env'] as const) {
      const a = signWorld(mode);
      const w = editApp(a, (js) => {
        const jobs = js.jobs as Obj;
        jobs['image-publish'] = { ...standIn(a, 'pipegen image publish', ['pipegen']), if: DEPLOY_IF };
        jobs.release = { uses: `o/pipelines/.github/workflows/r--release.yml@${'c'.repeat(40)}`, if: DEPLOY_IF, needs: ['pipegen', 'image-publish'], permissions: pubCopy(a).permissions };
      }, [calledFile('.github/workflows/r--release.yml', { 'image-publish': pubCopy(a), sign: standIn(a, 'pipegen sign', ['image-publish']) }, 'central')]);
      await refused(w, `S3c ${mode}`, OUTSIDE);
    }
  });

  it('S1, S2b: a second publisher in a called file (with the real sign after it; tail-less with a stand-in sign), every mode', async () => {
    for (const mode of MODES) {
      const a = signWorld(mode);
      const sj = realSign(a);
      const s1 = editApp(a, (js) => {
        (js.jobs as Obj).release = { uses: './.github/workflows/release.yml', if: DEPLOY_IF, needs: ['pipegen', 'image-publish'], permissions: union(pubCopy(a).permissions as Obj, sj.permissions as Obj) };
      }, [calledFile('.github/workflows/release.yml', { 'image-publish': pubCopy(a), sign: { ...sj, needs: ['image-publish'] } })]);
      await refused(s1, `S1 ${mode}`, OUTSIDE);
      const pub = pubCopy(a);
      const steps = pub.steps as Obj[];
      pub.steps = steps.slice(0, steps.findIndex((s) => s.id === 'pipegen-build-push') + 1);
      const s2b = editApp(a, (js) => {
        (js.jobs as Obj).release = { uses: './.github/workflows/release.yml', if: DEPLOY_IF, needs: ['pipegen', 'image-publish'], permissions: pubCopy(a).permissions };
      }, [calledFile('.github/workflows/release.yml', { 'image-publish': pub, sign: standIn(a, 'pipegen sign', ['image-publish']) })]);
      await refused(s2b, `S2b ${mode}`, OUTSIDE);
    }
  });

  it('a pushing build under another id in a called file is refused too', async () => {
    const a = signWorld('keyless');
    const w = editApp(a, (js) => {
      (js.jobs as Obj).release = { uses: './.github/workflows/release.yml', if: DEPLOY_IF, needs: ['pipegen', 'image-publish'], permissions: pubCopy(a).permissions };
    }, [calledFile('.github/workflows/release.yml', { publish: pubCopy(a) })]);
    await refused(w, 'publish', OUTSIDE);
  });
});

describe('G15a-R10 r4-2: image-publish ends with the digest step and its upload', () => {
  it('S8: pipegen.yml\'s image-publish without its digest hand-off (no digest step and no upload; no upload) is refused, every mode', async () => {
    for (const mode of MODES) {
      const a = signWorld(mode);
      const cut2 = editApp(a, (js) => { const j = (js.jobs as Obj)['image-publish'] as Obj; j.steps = (j.steps as Obj[]).slice(0, -2); });
      await refused(cut2, `S8 ${mode} cut 2`, /must end with the digest step and its upload/);
      const cut1 = editApp(a, (js) => { const j = (js.jobs as Obj)['image-publish'] as Obj; j.steps = (j.steps as Obj[]).slice(0, -1); });
      await refused(cut1, `S8 ${mode} cut 1`, /must end with the digest step and its upload/);
      // a step after the tail
      const after = editApp(a, (js) => { const j = (js.jobs as Obj)['image-publish'] as Obj; const s = j.steps as Obj[]; j.steps = [...s, structuredClone(s[s.length - 2])]; });
      expect((await judgeAssembled(after, JD)).ok, `S8 ${mode} after`).toBe(false);
    }
  });
});

describe('G15a-R10 r4-3: image-publish tags exactly the plan\'s image', () => {
  it('S11: another repository, another tag, another registry, two tags: each refused, every mode', async () => {
    for (const mode of MODES) {
      const a = signWorld(mode);
      for (const tag of ['ghcr.io/o/r/pipegen-other:pipegen', 'ghcr.io/o/r/pipegen-app:latest', 'docker.io/o/r/app:pipegen', 'ghcr.io/o/r/pipegen-app:pipegen,ghcr.io/o/r/pipegen-other:pipegen']) {
        const w = editApp(a, (js) => { const st = ((js.jobs as Obj)['image-publish'].steps as Obj[]).find((s) => s.id === 'pipegen-build-push') as Obj; (st.with as Obj).tags = tag; });
        await refused(w, `S11 ${mode} ${tag}`, /tags must be exactly ghcr\.io\/o\/r\/pipegen-app:pipegen/);
      }
    }
  });
});
