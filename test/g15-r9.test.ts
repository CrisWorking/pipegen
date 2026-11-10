// v0.2 Plan G, sub-task G15a, ruling G15a-R9 (re-review r3: spec APPROVED, security CHANGES REQUIRED). Each item as a failing test first.
// sec r3-1: the sign-needs rule follows the job that signs, whatever its id or file: a caller of a workflow holding the job sign needs
// image-publish; in a workflow_call-only file the job sign needs every job of that file that writes to the registry; image-publish outside
// pipegen.yml is refused unless its file's sign job needs it (amended by G15a-R10 r4-1: refused outright). The three dodges of the r3 probe (zz-r3-sec.test.ts) are each a test.
// spec r3-1: the 45-minute ZAP ceiling reaches the long report (the consent screen is pinned in consent.test.ts).
import { parse, stringify } from 'yaml';
import { describe, expect, it } from 'vitest';
import { EXCLUDED_PATTERNS } from '../src/ai/redact.js';
import { renderMarkdown, renderTerminal, type RenderOptions } from '../src/audit/render.js';
import { estimate } from '../src/estimate/estimate.js';
import { floorNeeds, jobCategories } from '../src/engine/needs.js';
import { assemble as assembleFiles, judgeAssembled } from '../src/layers/assemble.js';
import { releaseJobs } from '../src/layers/deploy.js';
import type { Capabilities, CreatedFile, PipelineDraft, ReviewedTool } from '../src/types.js';
import { CAPS, LINTERS, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { freePrivateReport } from './fixtures/audit-report.js';

const web = (name = 'app', port = 3000, path = '.') => node({ name, dockerfile: path === '.' ? 'Dockerfile' : `${path}/Dockerfile`, port, path });
const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const PIN = { repo: 'o/pipelines', sha: 'c'.repeat(40) };
type Mode = 'attest' | 'key-env' | 'keyless';
function signWorld(mode: Mode) {
  const priv = mode !== 'keyless';
  const caps: Capabilities = mode === 'attest' ? { ...CAPS, attestations: true, environments: true }
    : mode === 'key-env' ? { ...CAPS, environments: true, deploymentBranchPolicies: true, envRequiredReviewers: true } : { ...CAPS, keylessSigningAllowed: true };
  const images = [{ service: 'app', repo: 'ghcr.io/o/r/app' }];
  const signing = mode === 'key-env' ? { mode, images, cosignPubSha256: 'b'.repeat(64) } : { mode, images };
  const x = planned(profileOf([web()], { private: priv }), { caps, over: { ...(priv ? { centralPin: PIN } : {}), signing } as Partial<PipelineDraft> });
  return assembleFiles(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode, layout: priv ? 'central' : 'local', plan: x.plan, deploy: releaseJobs(x.draft, { platform: p }) } as Parameters<typeof assembleFiles>[1]);
}
type W = ReturnType<typeof signWorld>;
const APP = '.github/workflows/pipegen.yml';
const appJobs = (a: W): Obj => (parse((a.files.find((x) => x.repo === 'app' && x.path === APP) as CreatedFile).content) as Obj).jobs as Obj;
function editApp(a: W, edit: (js: Obj) => void, extra: CreatedFile[] = []): W {
  const f = a.files.find((x) => x.repo === 'app' && x.path === APP) as CreatedFile;
  const js = parse(f.content) as Obj;
  edit(js);
  const changed = { ...f, content: stringify(js, { lineWidth: 0 }) };
  return { ...a, files: [...a.files.map((x) => (x === f ? changed : x)), ...extra] };
}
const renameJob = (js: Obj, from: string, to: string) => {
  const jobs: Obj = {};
  for (const [k, v] of Object.entries(js.jobs as Obj)) jobs[k === from ? to : k] = v;
  for (const v of Object.values(jobs) as Obj[]) if (Array.isArray(v.needs)) v.needs = v.needs.map((n: string) => (n === from ? to : n));
  js.jobs = jobs;
};
const calledFile = (path: string, jobs: Obj): CreatedFile => ({ repo: 'app', path, content: stringify({ name: 'pipegen called', on: { workflow_call: null }, permissions: {}, jobs }, { lineWidth: 0 }) }) as CreatedFile;
const CALLER_NEEDS = /calls the sign workflow, so it must need image-publish/;

describe('G15a-R9 sec r3-1: the sign-needs rule follows the job that signs', () => {
  it('control: pipegen\'s own files pass in every mode; a renamed caller that needs image-publish passes', async () => {
    for (const mode of ['attest', 'key-env', 'keyless'] as const) {
      const a = signWorld(mode);
      expect(shown(await judgeAssembled(a, JD)), mode).toBe('');
      if (mode !== 'keyless') expect(shown(await judgeAssembled(editApp(a, (js) => { renameJob(js, 'sign', 'signing'); }), JD)), mode).toBe('');
    }
  });

  it('M4-1: the attest and key-env caller renamed (signing, Sign, release) with only the gate holder as a need is refused', async () => {
    for (const mode of ['attest', 'key-env'] as const) {
      const a = signWorld(mode);
      for (const to of ['signing', 'Sign', 'release']) {
        const r = await judgeAssembled(editApp(a, (js) => { renameJob(js, 'sign', to); (js.jobs as Obj)[to].needs = ['pipegen']; }), JD);
        expect(r.ok, `${mode} ${to}`).toBe(false);
        expect(shown(r), `${mode} ${to}`).toMatch(CALLER_NEEDS);
      }
    }
  });

  it('M4-2: the keyless sign job moved into a local called file, called by a job signing that needs only the gate holder, is refused', async () => {
    const a = signWorld('keyless');
    const sj = structuredClone(appJobs(a).sign) as Obj;
    delete sj.if; delete sj.needs;
    for (const to of ['signing', 'sign']) {
      const r = await judgeAssembled(editApp(a, (js) => {
        const jobs = js.jobs as Obj;
        const perms = (jobs.sign as Obj).permissions;
        delete jobs.sign;
        jobs[to] = { uses: './.github/workflows/sign.yml', if: "github.event_name == 'push'", needs: ['pipegen'], permissions: perms };
        for (const v of Object.values(jobs) as Obj[]) if (Array.isArray(v.needs)) v.needs = v.needs.map((n: string) => (n === 'sign' ? to : n));
      }, [calledFile('.github/workflows/sign.yml', { sign: sj })]), JD);
      expect(r.ok, to).toBe(false);
      expect(shown(r), to).toMatch(/must need image-publish/);
    }
  });

  it('C1: one called file holding image-publish and sign with no need between them is refused (keyless and attest)', async () => {
    for (const mode of ['keyless', 'attest'] as const) {
      const a = signWorld(mode);
      const jobs0 = appJobs(a);
      const pub = structuredClone(jobs0['image-publish']) as Obj;
      delete pub.if; delete pub.needs;
      let signJ: Obj;
      if (mode === 'keyless') { signJ = structuredClone(jobs0.sign) as Obj; delete signJ.if; delete signJ.needs; } else {
        const central = a.files.find((f) => f.repo === 'central' && /sign/.test(f.path)) as CreatedFile;
        signJ = structuredClone(((parse(central.content) as Obj).jobs as Obj).sign) as Obj;
      }
      const world = (sign: Obj): W => {
        const w = editApp(a, (js) => {
          const jobs = js.jobs as Obj;
          const perms = { ...(jobs.sign as Obj).permissions as Obj, packages: 'write' };
          delete jobs.sign; delete jobs['image-publish'];
          jobs.release = { uses: './.github/workflows/release.yml', if: "github.event_name == 'push'", needs: ['pipegen'], permissions: perms };
          for (const v of Object.values(jobs) as Obj[]) if (Array.isArray(v.needs)) v.needs = [...new Set(v.needs.map((n: string) => (n === 'sign' || n === 'image-publish' ? 'release' : n)))];
        }, [calledFile('.github/workflows/release.yml', { 'image-publish': pub, sign })]);
        return { ...w, files: w.files.filter((f) => !(f.repo === 'central' && /sign/.test(f.path))) };
      };
      // side by side: the called sign job needs nothing, and image-publish runs outside pipegen.yml
      const r = await judgeAssembled(world(signJ), JD);
      expect(r.ok, mode).toBe(false);
      expect(shown(r), mode).toMatch(/workflow started only by workflow_call must need every job of its file that writes to the image registry/);
      expect(shown(r), mode).toMatch(/publishes outside \.github\/workflows\/pipegen\.yml/);
      expect(shown(r), mode).toMatch(CALLER_NEEDS);
      // with the need inside the called file, the in-file need rule holds; the caller still needs image-publish in its own file, and
      // (G15a-R10 r4-1, amending R9) image-publish outside pipegen.yml is refused outright, its file's sign job or not
      const r2 = shown(await judgeAssembled(world({ ...signJ, needs: ['image-publish'] }), JD));
      expect(r2, mode).not.toMatch(/must need every job of its file/);
      expect(r2, mode).toMatch(/publishes outside \.github\/workflows\/pipegen\.yml/);
      expect(r2, mode).toMatch(CALLER_NEEDS);
    }
  });
});

describe('G15a-R9 spec r3-1: the 45-minute ZAP ceiling reaches the long report', () => {
  it('render: the Markdown report and the verbose terminal report hold the ceiling basis line', () => {
    const prof = profileOf([web()], { private: true, plan: 'free' });
    const est = estimate(prof, jobCategories(floorNeeds(prof, CAPS), { codeSecurity: true }), 1, { pushes: 40, prs: 10, capped: false }, null);
    const r = { ...freePrivateReport(EXCLUDED_PATTERNS), estimates: est };
    const OPTS: RenderOptions = { knownValues: [], now: () => Date.parse('2026-11-07T00:00:00Z'), verbose: true };
    const flat = (s: string) => s.replace(/\s+/g, ' ');
    expect(flat(renderMarkdown(r, OPTS))).toMatch(/ZAP active scan[^\n]*about 5 min[^\n]*up to 45 min/);
    expect(flat(renderTerminal(r, OPTS))).toMatch(/ZAP active scan[^\n]*about 5 min[^\n]*up to 45 min/);
  });
});
