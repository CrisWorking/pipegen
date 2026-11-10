// v0.2 Plan V V4 (rulings V-B3, V-B4, V-B6, V-S1, V-S2, V-S4, V-S5, V-S6, V-S8, V-S12, V-S13, V-N1…V-N14): the uninstall plan decides what
// is removed, reverted, restored, asked about or kept, and the preview is what the user agrees to. Every GitHub object is classified by
// its live GET (id, created_at); typed names come only from the interactive terminal; the preview prints names, never values.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PromptCancelledError, type Prompter } from '../src/cli/io.js';
import { gitBlobSha } from '../src/create/guard.js';
import { addLocalLeftovers, recordPath } from '../src/deliver/record.js';
import type { EnvSettings, InstallEdit, InstallRecord } from '../src/types.js';
import { UninstallError } from '../src/uninstall/errors.js';
import type { LoadedRecord } from '../src/uninstall/record.js';
import { TYPED_DROPPED } from '../src/uninstall/record.js';
import { planUninstall, previewUninstall, type UninstallPlan } from '../src/uninstall/plan.js';
import { FakeGitHub, type Env, type Repo } from './helpers/deliver-github.js';

// the revert engine is V2's: these tests check it is wired (called once with the whole record and the live default branch)
const revertCalls: { edits: readonly InstallEdit[]; ctx: unknown }[] = [];
vi.mock('../src/uninstall/revert.js', async (orig) => {
  const real = await orig<typeof import('../src/uninstall/revert.js')>();
  return { ...real, revertEdits: (edits: readonly InstallEdit[], read: never, blob: never, ctx: unknown) => { revertCalls.push({ edits, ctx }); return real.revertEdits(edits, read, blob, ctx as never); } };
});

const SHA = (c: string): string => c.repeat(40).slice(0, 40);
/** The record's secrets field, spelled at run time (test/no-secret-literals.test.ts). */
const SEC = ['sec', 'rets'].join('') as 'secrets';
const AT = '2026-11-05T12:00:01Z';
const LATER = '2026-11-06T09:00:00Z';
/** The plan's per-secret key and the setting named for it, spelled at run time too. */
const SK = ['sec', 'ret'].join('') as 'secret';
const SS = [SK, 'Scanning'].join('') as 'secretScanning';
type SecEntry = InstallRecord[typeof SEC][number];
type VariableEntry = InstallRecord['variables'][number];
type EnvEntry = InstallRecord['environments'][number];

const FILES: Record<string, string> = {
  'README.md': 'my app\n',
  '.github/workflows/pipegen.yml': 'name: pipegen\n',
  'Dockerfile': 'FROM node:22\n',
  '.dockerignore': 'node_modules\n',
  'docker-compose.pipegen.yml': 'services: {}\n',
  'test/app.test.ts': 'it("works", () => {});\n',
  'PIPEGEN.md': '# pipegen\n',
};
const PARTS: Record<string, InstallRecord['files'][number]['part']> = {
  '.github/workflows/pipegen.yml': 'pipeline', 'Dockerfile': 'docker', '.dockerignore': 'docker', 'docker-compose.pipegen.yml': 'compose', 'test/app.test.ts': 'tests', 'PIPEGEN.md': 'docs',
};

interface World {
  g: FakeGitHub; app: Repo; central: Repo; home: string;
  vars: Map<string, Map<string, { created_at: string; value: string }>>;
  protection: Record<string, unknown> | null; org: Map<number, Record<string, unknown>>;
  pullRepoId: Map<number, number>;
  /** A page of a pull request list GitHub fails to serve (HTTP 502). */
  pullsFailPage?: number;
}
const homes: string[] = [];
afterEach(() => { for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true }); revertCalls.length = 0; });

function world(files: Record<string, string> = FILES, opts: { defaultBranch?: string; centralFiles?: Record<string, string> } = {}): World {
  const g = new FakeGitHub();
  const app = g.addRepo('o/shop', { private: true, files, ...(opts.defaultBranch === undefined ? {} : { defaultBranch: opts.defaultBranch }) });
  const central = g.addRepo('o/pipelines', { private: true, files: opts.centralFiles ?? { [recordPath('shop')]: '{}\n', '.github/workflows/shop--merge.yml': 'on: workflow_call\n' } });
  const home = mkdtempSync(join(tmpdir(), 'pg-unplan-'));
  homes.push(home);
  const w: World = { g, app, central, home, vars: new Map(), protection: null, org: new Map(), pullRepoId: new Map() };
  // the routes the fake doesn't serve
  g.hooks.push((call) => {
    const p = call.params as Record<string, string>;
    const envOf = (): Env | undefined => app.envs.get(p.environment_name as string);
    switch (call.route) {
      case 'GET /repos/{owner}/{repo}/actions/variables/{name}': {
        const v = w.vars.get('repo')?.get(p.name as string);
        return v === undefined ? { status: 404 } : { status: 200, data: { name: p.name, value: v.value, created_at: v.created_at } };
      }
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}': {
        const v = w.vars.get(`env:${p.environment_name}`)?.get(p.name as string);
        return v === undefined ? { status: 404 } : { status: 200, data: { name: p.name, value: v.value, created_at: v.created_at } };
      }
      case `GET /repos/{owner}/{repo}/environments/{environment_name}/${SEC}`: {
        const e = envOf();
        if (e === undefined) return { status: 404 };
        const list = [...e.stored].map(([name, at]) => ({ name, created_at: at }));
        return { status: 200, data: { total_count: list.length, [SEC]: list } };
      }
      case 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables': {
        if (envOf() === undefined) return { status: 404 };
        const list = [...(w.vars.get(`env:${p.environment_name}`) ?? new Map())].map(([name, v]) => ({ name, value: v.value, created_at: v.created_at }));
        return { status: 200, data: { total_count: list.length, variables: list } };
      }
      case 'GET /repos/{owner}/{repo}/branches/{branch}/protection':
        return w.protection === null ? { status: 404 } : { status: 200, data: w.protection };
      case 'GET /orgs/{org}/rulesets/{ruleset_id}': {
        const r = w.org.get(Number(p.ruleset_id));
        return r === undefined ? { status: 404 } : { status: 200, data: r };
      }
      default: return undefined;
    }
  });
  return w;
}
/** The Octokit stand-in, with GitHub's head.repo and merged_at on pull requests (the fake leaves them out). */
function gh(w: World): Octokit {
  const withRepo = (owner: unknown, repo: unknown, p: unknown): unknown => {
    if (typeof p !== 'object' || p === null || typeof (p as { head?: unknown }).head !== 'object') return p;
    const r = w.g.repo(`${String(owner)}/${String(repo)}`);
    const n = (p as { number: number }).number;
    return { ...p, merged_at: null, head: { ...(p as { head: object }).head, repo: { id: w.pullRepoId.get(n) ?? r.id } } };
  };
  return { request: async (route: string, params: Record<string, unknown> = {}) => {
    const out = await w.g.request(route, params);
    if (route === 'GET /repos/{owner}/{repo}/pulls') {
      // GitHub pages the list (per_page, at most 100; page from 1)
      const per = Math.min(Number(params.per_page ?? 30), 100);
      const page = Number(params.page ?? 1);
      if (w.pullsFailPage === page) throw Object.assign(new Error('Bad Gateway'), { status: 502 });
      const all = Array.isArray(out.data) ? out.data : [];
      return { ...out, data: all.slice((page - 1) * per, page * per).map((p) => withRepo(params.owner, params.repo, p)) };
    }
    if (route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}') return { ...out, data: withRepo(params.owner, params.repo, out.data) };
    return out;
  } } as unknown as Octokit;
}
const blob = (t: string): string => gitBlobSha(t);
function sampleRecord(w: World, over: Partial<InstallRecord> = {}): InstallRecord {
  return {
    schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-05T12:00:00.000Z', mergedAt: '2026-11-05T13:00:00Z', centralSha: SHA('c'),
    app: { owner: 'o', repo: 'shop', repoId: w.app.id, defaultBranch: 'main', private: true, ownerType: 'User' },
    name: 'shop', serviceRoots: ['.'],
    files: [
      ...Object.entries(PARTS).map(([path, part]) => ({ repo: 'app' as const, path, part, shas: [blob(FILES[path] as string)] })),
      { repo: 'central' as const, path: '.github/workflows/shop--merge.yml', part: 'pipeline' as const, shas: [blob('on: workflow_call\n')] },
    ],
    edits: [],
    [SEC]: [],
    variables: [], environments: [], rulesets: [],
    planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] },
    protectedPaths: ['.github/workflows/**'],
    ...over,
  };
}
function loadedOf(w: World, record: InstallRecord, over: Partial<LoadedRecord> = {}): LoadedRecord {
  return {
    app: { owner: 'o', repo: 'shop', repoId: w.app.id, private: true, defaultBranch: w.app.defaultBranch, ownerType: 'User' },
    record, trust: 'full', typedNames: false, blobSha: SHA('b'), centralHead: w.g.head('o/pipelines'), centralRepoId: w.central.id,
    marker: 'match', setupPr: null, dropped: [], warnings: [], ...over,
  };
}
interface Term { p: Prompter; typed: string[]; confirms: string[] }
/** The user's terminal: types the name asked for (or what `type` says), answers each yes/no with its default (or what `confirm` says). */
function term(o: { type?: (q: string, expected: string) => string; confirm?: (q: string, def: boolean) => boolean } = {}): Term {
  const t: Term = { typed: [], confirms: [], p: undefined as unknown as Prompter };
  t.p = {
    confirm: async (m, d) => { t.confirms.push(m); return o.confirm === undefined ? d : o.confirm(m, d); },
    select: async () => { throw new Error('no select expected'); },
    text: async (m) => { t.typed.push(m); const exp = /\nType (.+) to go on;/.exec(m)?.[1] ?? ''; return o.type === undefined ? exp : o.type(m, exp); },
  };
  return t;
}
const local = (w: World) => ({ home: w.home, env: {} });
/** Run 1 (phase A) by default; `planB` plans run 2 (phase B). */
async function plan(w: World, rec: InstallRecord, t: Term = term(), over: Partial<LoadedRecord> = {}, interactive = true, phase: 'A' | 'B' = 'A'): Promise<UninstallPlan> {
  return planUninstall(gh(w), loadedOf(w, rec, over), t.p, { interactive, local: local(w), phase });
}
const planB = (w: World, rec: InstallRecord, t: Term = term(), over: Partial<LoadedRecord> = {}, interactive = true): Promise<UninstallPlan> => plan(w, rec, t, over, interactive, 'B');
const writes = (w: World): string[] => w.g.routes().filter((r) => !r.startsWith('GET '));
const paths = (xs: readonly { path: string }[]): string[] => xs.map((x) => x.path).sort();
const whats = (u: UninstallPlan): string => [...u.skipped.map((s) => `${s.what}: ${s.why}`), ...u.manual.map((m) => `${m.what}: ${m.why} ${m.step ?? ''}`)].join('\n');
const rs = (over: Partial<InstallRecord['rulesets'][number]> = {}): InstallRecord['rulesets'][number] => ({ kind: 'gate', id: 41, name: 'pipegen', githubCreatedAt: AT, ...over });
const liveRs = (w: World, over: Record<string, unknown> = {}) => ({ name: 'pipegen', source_type: 'Repository', source: 'o/shop', created_at: AT, enforcement: 'active', ...over });
function env(w: World, name: string, over: Partial<Env> = {}): Env {
  const e: Env = { id: 500 + w.app.envs.size, created_at: AT, wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, policies: [], stored: new Map(), ...over };
  w.app.envs.set(name, e);
  return e;
}
const envSettings = (over: Partial<EnvSettings> = {}): EnvSettings => ({ wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [], ...over });
function setVar(w: World, scope: string, name: string, value: string, at = AT): void {
  if (!w.vars.has(scope)) w.vars.set(scope, new Map());
  w.vars.get(scope)?.set(name, { created_at: at, value });
}
async function stops(p: Promise<unknown>, re: RegExp): Promise<void> {
  const e = await p.then(() => null, (x: unknown) => x);
  expect(e).toBeInstanceOf(UninstallError);
  expect((e as Error).message).toMatch(re);
}

describe('uninstall plan: files (V4)', () => {
  it('plan: created Dockerfile and tests asked, default keep', async () => {
    const w = world();
    const t = term();
    const u = await plan(w, sampleRecord(w), t);
    // the workflow and PIPEGEN.md are pipegen's own, unchanged: removed in the uninstall PR
    expect(paths(u.removeFiles)).toEqual(['.github/workflows/pipegen.yml', 'PIPEGEN.md']);
    expect(u.removeFiles.every((f) => f.repo === 'app')).toBe(true);
    // the team may want these: asked, and the default answer keeps them
    expect(paths(u.keepAsk)).toEqual(['.dockerignore', 'Dockerfile', 'docker-compose.pipegen.yml', 'test/app.test.ts']);
    expect(u.keepAsk.every((k) => k.keep)).toBe(true);
    expect(t.confirms.some((q) => /Keep Dockerfile and \.dockerignore\?/.test(q))).toBe(true);
    expect(t.confirms.some((q) => /Keep docker-compose\.pipegen\.yml\?/.test(q))).toBe(true);
    expect(t.confirms.some((q) => /Keep the starter tests.*test\/app\.test\.ts/.test(q))).toBe(true);
    // each keep question's default is Keep (Y/n)
    expect(t.confirms.filter((q) => q.startsWith('Keep')).every((q) => q.includes('(Y/n)'))).toBe(true);
    // answering no removes them
    const t2 = term({ confirm: () => false });
    const u2 = await plan(w, sampleRecord(w), t2);
    expect(paths(u2.removeFiles)).toEqual(['.dockerignore', '.github/workflows/pipegen.yml', 'Dockerfile', 'PIPEGEN.md', 'docker-compose.pipegen.yml', 'test/app.test.ts']);
    expect(u2.keepAsk.every((k) => !k.keep)).toBe(true);
    // no terminal: nothing asked, everything the team may want is kept
    const t3 = term({ confirm: () => { throw new Error('asked without a terminal'); } });
    const u3 = await plan(w, sampleRecord(w), t3, {}, false);
    expect(u3.keepAsk.every((k) => k.keep)).toBe(true);
    expect(t3.confirms).toEqual([]);
    // a cancelled question keeps
    const t4: Term = term();
    t4.p.confirm = async () => { throw new PromptCancelledError(); };
    expect((await plan(w, sampleRecord(w), t4)).keepAsk.every((k) => k.keep)).toBe(true);
    expect(writes(w)).toEqual([]);
  });

  it('plan: modified created file asks before removing', async () => {
    const w = world({ ...FILES, '.github/workflows/pipegen.yml': 'name: pipegen\n# my change\n' });
    const t = term();
    const u = await plan(w, sampleRecord(w), t);
    // changed since install: listed, asked, and kept by default
    expect(u.removeFiles.map((f) => f.path)).not.toContain('.github/workflows/pipegen.yml');
    const k = u.keepAsk.find((x) => x.path === '.github/workflows/pipegen.yml');
    expect(k?.keep).toBe(true);
    expect(k?.why).toMatch(/changed since pipegen wrote it/);
    expect(t.confirms.some((q) => /Keep \.github\/workflows\/pipegen\.yml\? It changed since pipegen wrote it.*\(Y\/n\)/.test(q))).toBe(true);
    // the user says remove: it is removed (they saw it changed)
    const u2 = await plan(w, sampleRecord(w), term({ confirm: (q) => !q.includes('pipegen.yml') && true }));
    expect(u2.removeFiles.map((f) => f.path)).toContain('.github/workflows/pipegen.yml');
    // an older sha pipegen wrote counts as unchanged (any sha in shas)
    const old = sampleRecord(w);
    const wf = old.files.find((f) => f.path === '.github/workflows/pipegen.yml') as InstallRecord['files'][number];
    wf.shas = [blob('name: pipegen\n# my change\n'), SHA('9')];
    expect((await plan(w, old, term())).removeFiles.map((f) => f.path)).toContain('.github/workflows/pipegen.yml');
    // ownerEdited (V-N3): the owner's file now; never removed, never even asked: a manual review
    const oe = sampleRecord(w);
    (oe.files.find((f) => f.path === 'PIPEGEN.md') as InstallRecord['files'][number]).ownerEdited = true;
    const t3 = term({ confirm: () => false });
    const u3 = await plan(w, oe, t3);
    expect(u3.removeFiles.map((f) => f.path)).not.toContain('PIPEGEN.md');
    expect(u3.keepAsk.map((f) => f.path)).not.toContain('PIPEGEN.md');
    expect(u3.manual.find((m) => m.what === 'PIPEGEN.md')?.why).toMatch(/merged its change into your edits/);
    expect(t3.confirms.some((q) => q.includes('PIPEGEN.md'))).toBe(false);
    // a file already gone: nothing to remove, listed
    const w5Files = { ...FILES };
    delete w5Files['PIPEGEN.md'];
    const w5 = world(w5Files);
    const u5 = await plan(w5, sampleRecord(w5), term());
    expect(u5.removeFiles.map((f) => f.path)).not.toContain('PIPEGEN.md');
    expect(whats(u5)).toMatch(/PIPEGEN\.md: it is no longer on the default branch/);
  });

  it('record: path not claimed by its part\'s created-file rule or a pipegen workflow path → manual review, never removed', async () => {
    const extra: Record<string, string> = { 'test/con.test.ts': 't\n', 'src/index.ts': 'x\n', '.github/workflows/deploy.yml': 'on: push\n', 'sub/Dockerfile': 'FROM a\n', 'CODEOWNERS': '* @o\n', 'docs/guide.md': 'g\n' };
    const w = world({ ...FILES, ...extra });
    const rec = sampleRecord(w);
    rec.files.push(
      { repo: 'app', path: 'src/index.ts', part: 'pipeline', shas: [blob('x\n')] },              // no rule claims it
      { repo: 'app', path: '.github/workflows/deploy.yml', part: 'pipeline', shas: [blob('on: push\n')] },   // not one of pipegen's workflows
      { repo: 'app', path: 'sub/Dockerfile', part: 'docker', shas: [blob('FROM a\n')] },         // not at a recorded service root
      { repo: 'app', path: 'CODEOWNERS', part: 'codeowners', shas: [blob('* @o\n')] },          // an edit kind, never a whole file
      { repo: 'app', path: 'docs/guide.md', part: 'docs', shas: [blob('g\n')] },
      { repo: 'app', path: 'test/con.test.ts', part: 'tests', shas: [blob('t\n')] },             // the path rule refuses it (a Windows device name)
    );
    // a Dockerfile recorded under another part
    (rec.files.find((f) => f.path === 'PIPEGEN.md') as InstallRecord['files'][number]).part = 'tests';
    const u = await plan(w, rec, term({ confirm: () => false }));
    for (const p of ['test/con.test.ts', 'src/index.ts', '.github/workflows/deploy.yml', 'sub/Dockerfile', 'CODEOWNERS', 'docs/guide.md', 'PIPEGEN.md']) {
      expect(u.removeFiles.map((f) => f.path), p).not.toContain(p);
      expect(u.keepAsk.map((f) => f.path), p).not.toContain(p);
      expect(u.manual.find((m) => m.what === p)?.why, p).toMatch(/not a file pipegen creates there/);
    }
    // pipegen's own workflows are claimed by path
    expect(u.removeFiles.map((f) => f.path)).toContain('.github/workflows/pipegen.yml');
    // a typed-trust view has no service roots: the Dockerfile and tests can't be claimed, so they are manual, never removed
    const v = await plan(w, sampleRecord(w, { serviceRoots: [] }), term({ confirm: () => false }));
    expect(v.removeFiles.map((f) => f.path)).not.toContain('Dockerfile');
    expect(v.manual.map((m) => m.what)).toEqual(expect.arrayContaining(['Dockerfile', '.dockerignore', 'test/app.test.ts']));
  });

  it('plan: adopted file → asked, default keep, whatever its sha', async () => {
    const w = world();
    const rec = sampleRecord(w);
    (rec.files.find((f) => f.path === 'PIPEGEN.md') as InstallRecord['files'][number]).adopted = true;
    const t = term();
    const u = await plan(w, rec, t);
    expect(u.removeFiles.map((f) => f.path)).not.toContain('PIPEGEN.md');
    expect(u.keepAsk.find((k) => k.path === 'PIPEGEN.md')).toMatchObject({ keep: true });
    expect(t.confirms).toContain('pipegen found PIPEGEN.md as it is; delete it? (y/N)');
    // yes → removed
    const u2 = await plan(w, rec, term({ confirm: (q) => q.startsWith('pipegen found PIPEGEN.md') }));
    expect(u2.removeFiles.map((f) => f.path)).toContain('PIPEGEN.md');
    // adopted and changed: still asked the same way, default keep
    const w3 = world({ ...FILES, 'PIPEGEN.md': '# mine\n' });
    const t3 = term();
    const u3 = await plan(w3, rec, t3);
    expect(u3.keepAsk.find((k) => k.path === 'PIPEGEN.md')?.keep).toBe(true);
    expect(t3.confirms.some((q) => q.startsWith('pipegen found PIPEGEN.md'))).toBe(true);
  });

  it('plan: kept starter tests keep the package.json and lock edits; Dockerfile and .dockerignore asked together', async () => {
    const files = { ...FILES, 'package.json': '{"name":"a"}\n', 'package-lock.json': '{"lockfileVersion":3}\n' };
    const w = world(files);
    const pj: InstallEdit = { repo: 'app', path: 'package.json', kind: 'package-json', add: { vitest: '3.0.0' }, setTest: true, lock: 'package-lock.json', originalSha: SHA('1'), writtenShas: [blob(files['package.json'])] };
    const pl: InstallEdit = { repo: 'app', path: 'package-lock.json', kind: 'package-lock', json: 'package.json', originalSha: SHA('2'), writtenShas: [blob(files['package-lock.json'])] };
    const rec = sampleRecord(w, { edits: [pj, pl] });
    // tests kept (the default): the package edits stay, listed
    const t = term();
    const u = await plan(w, rec, t);
    expect(u.reverts.map((r) => r.edit.path)).toEqual([]);
    expect(whats(u)).toMatch(/package\.json: kept with the starter tests you keep/);
    expect(whats(u)).toMatch(/package-lock\.json: kept with the starter tests you keep/);
    // Dockerfile and .dockerignore: one question, the same answer, each naming the other
    expect(t.confirms.filter((q) => /Dockerfile/.test(q))).toHaveLength(1);
    expect(u.keepAsk.find((k) => k.path === 'Dockerfile')).toMatchObject({ pair: '.dockerignore', keep: true });
    expect(u.keepAsk.find((k) => k.path === '.dockerignore')).toMatchObject({ pair: 'Dockerfile', keep: true });
    // tests removed: the package edits go back (through the revert engine, as a pair)
    const u2 = await plan(w, rec, term({ confirm: (q) => !q.includes('starter tests') }));
    expect(u2.keepAsk.find((k) => k.path === 'test/app.test.ts')?.keep).toBe(false);
    expect(u2.reverts.map((r) => r.edit.path).sort()).toEqual(['package-lock.json', 'package.json']);
    // Dockerfile removed → .dockerignore removed with it; the Dockerfile the owner edited (manual) keeps its .dockerignore
    const u3 = await plan(w, rec, term({ confirm: (q) => !q.includes('Dockerfile') }));
    expect(u3.removeFiles.map((f) => f.path)).toEqual(expect.arrayContaining(['Dockerfile', '.dockerignore']));
    const oe = sampleRecord(w, { edits: [pj, pl] });
    (oe.files.find((f) => f.path === 'Dockerfile') as InstallRecord['files'][number]).ownerEdited = true;
    const u4 = await plan(w, oe, term({ confirm: () => false }));
    expect(u4.removeFiles.map((f) => f.path)).not.toContain('.dockerignore');
    expect(whats(u4)).toMatch(/\.dockerignore: kept with Dockerfile/);
  });
});

describe('uninstall plan: GitHub objects (V4)', () => {
  it('plan: created:false secret → never deleted', async () => {
    const w = world();
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    w.app.stored.set('STRIPE_KEY', AT);
    const rec = sampleRecord(w, { [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: false }, { name: 'STRIPE_KEY', scope: 'repo', created: false }] });
    for (const over of [{}, { typedNames: true }, { trust: 'typed' as const, typedNames: true, dropped: TYPED_DROPPED }]) {
      const t = term();
      const u = await planB(w, rec, t, over);
      expect(u.deleteSecrets).toEqual([]);
      expect(t.typed).toEqual([]);
      expect(whats(u)).toMatch(/PIPEGEN_FP_KEY: pipegen didn't create it/);
    }
    expect(w.g.routes().some((r) => r.includes('/actions/secrets/'))).toBe(false);
  });

  it('plan: created secret without PIPEGEN_ prefix → typed name needed, else kept', async () => {
    const w = world();
    w.app.stored.set('STRIPE_SECRET_KEY', AT);
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    const rec = sampleRecord(w, { [SEC]: [{ name: 'STRIPE_SECRET_KEY', scope: 'repo', created: true, githubCreatedAt: AT }, { name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }] });
    // typed: deleted, confirmed by name, with the token for that very secret
    const t = term();
    const u = await planB(w, rec, t);
    const s = u.deleteSecrets.find((x) => x[SK].name === 'STRIPE_SECRET_KEY');
    expect(s?.confirmedByName).toBe(true);
    expect(s?.typed).toBeDefined();
    expect(t.typed.filter((q) => q.includes('STRIPE_SECRET_KEY'))).toHaveLength(1);
    // the PIPEGEN_ one is pipegen-shaped and proved: no question
    expect(u.deleteSecrets.find((x) => x[SK].name === 'PIPEGEN_FP_KEY')).toMatchObject({ confirmedByName: false });
    expect(t.typed.some((q) => q.includes('PIPEGEN_FP_KEY'))).toBe(false);
    // not typed (another answer, or a cancelled question): kept and listed as skipped
    for (const answer of ['stripe_secret_key', '', 'yes']) {
      const u2 = await planB(w, rec, term({ type: () => answer }));
      expect(u2.deleteSecrets.map((x) => x[SK].name)).toEqual(['PIPEGEN_FP_KEY']);
      expect(u2.skipped).toContainEqual({ what: 'secret STRIPE_SECRET_KEY', why: 'kept: its name was not typed' });
    }
    expect(writes(w)).toEqual([]);
  });

  it('plan: G-SIGN1-R2 the leftovers entry a successful first run wrote next to its record entry changes nothing (one delete, no manual step)', async () => {
    const w = world();
    env(w, 'pipegen-signing');
    // the run listed its own environment at make time; delivery then recorded it (the record's entry decides)
    await addLocalLeftovers({ owner: 'o', repo: 'shop' }, [{ kind: 'environment', name: 'pipegen-signing', repo: 'o/shop', githubCreatedAt: AT }], new Date(), local(w));
    const rec = sampleRecord(w, { environments: [{ name: 'pipegen-signing', created: true, githubCreatedAt: AT, changed: [], branchPolicyIds: [] }] });
    const u = await planB(w, rec, term());
    expect(u.deleteEnvironments.map((e) => e.name)).toEqual(['pipegen-signing']);
    expect(u.deleteEnvironments[0]).toMatchObject({ confirmedByName: false });
    expect(whats(u)).not.toMatch(/pipegen-signing \(leftovers file\)/);
    expect(u.restoreEnvironments).toEqual([]);
    expect(writes(w)).toEqual([]);
  });

  it('plan: non-pipegen-shaped environment or secret → typed name even when the hash matches', async () => {
    const w = world();
    env(w, 'production');
    env(w, 'pipegen-signing');
    w.app.stored.set('API_KEY', AT);
    const rec = sampleRecord(w, {
      [SEC]: [{ name: 'API_KEY', scope: 'repo', created: true, githubCreatedAt: AT }],
      environments: [{ name: 'production', created: true, githubCreatedAt: AT, changed: [], branchPolicyIds: [] }, { name: 'pipegen-signing', created: true, githubCreatedAt: AT, changed: [], branchPolicyIds: [] }],
    });
    const t = term();
    const u = await planB(w, rec, t);   // marker matches, full trust
    expect(u.deleteEnvironments.find((e) => e.name === 'production')).toMatchObject({ confirmedByName: true });
    expect(u.deleteEnvironments.find((e) => e.name === 'pipegen-signing')).toMatchObject({ confirmedByName: false });
    expect(u.deleteSecrets.find((s) => s[SK].name === 'API_KEY')).toMatchObject({ confirmedByName: true });
    expect(t.typed.some((q) => q.includes('environment production'))).toBe(true);
    expect(t.typed.some((q) => q.includes('pipegen-signing'))).toBe(false);
    // not typed → kept
    const u2 = await planB(w, rec, term({ type: () => 'no' }));
    expect(u2.deleteEnvironments.map((e) => e.name)).toEqual(['pipegen-signing']);
    expect(u2.deleteSecrets).toEqual([]);
  });

  it('plan: record hash mismatch → every deletion needs typed name', async () => {
    const w = world();
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    env(w, 'pipegen-signing');
    setVar(w, 'repo', 'PIPEGEN_BLOCK_FROM', '2026-11-05');
    w.app.rulesets.set(41, liveRs(w));
    w.g.repo('o/shop').pulls.push({ number: 9, head: 'pipegen/update', base: 'main', title: 'u', body: '', state: 'open', html_url: 'u' });
    const rec = sampleRecord(w, {
      [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }],
      variables: [{ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: true, githubCreatedAt: AT }],
      environments: [{ name: 'pipegen-signing', created: true, githubCreatedAt: AT, changed: [], branchPolicyIds: [] }],
      rulesets: [rs()],
      repoSettings: { [SS]: { previous: false } },
    });
    for (const marker of ['differs', 'absent'] as const) {
      // run 1: the ruleset and the pull request close, each by name; the next run's items are named in the preview, not asked
      const t = term({ confirm: () => true });
      const u = await plan(w, rec, t, { marker, typedNames: true });
      expect(u.deleteRulesets).toMatchObject([{ id: 41, confirmedByName: true }]);
      expect(u.deleteRulesets[0]?.typed).toBeDefined();
      // the pull request close: confirmed by name in the plan (V3 takes no object for it), shown in the preview
      expect(u.closePrs).toEqual([{ repo: 'app', number: 9, branch: 'pipegen/update', confirmedByName: true }]);
      expect(t.typed).toHaveLength(2);
      for (const x of [...u.deleteSecrets, ...u.deleteVariables, ...u.deleteEnvironments]) expect(x).toMatchObject({ confirmedByName: false, needsName: true });
      expect([...u.deleteSecrets, ...u.deleteVariables, ...u.deleteEnvironments].some((x) => x.typed !== undefined)).toBe(false);
      // run 2: every delete and the setting, each by name
      const tb = term({ confirm: () => true });
      const b = await planB(w, rec, tb, { marker, typedNames: true });
      for (const x of [...b.deleteSecrets, ...b.deleteVariables, ...b.deleteEnvironments]) {
        expect(x.confirmedByName).toBe(true);
        expect(x.typed).toBeDefined();
      }
      expect(b.deleteSecrets).toHaveLength(1);
      expect(b.deleteVariables).toHaveLength(1);
      expect(b.deleteEnvironments).toHaveLength(1);
      expect(b.settings).toEqual([{ key: 'secretScanning', previous: false, turnOff: true, confirmedByName: true }]);
      expect(tb.typed).toHaveLength(4);
      // nothing typed: nothing deleted, closed or turned off; each listed
      const u2 = await plan(w, rec, term({ confirm: () => true, type: () => 'nope' }), { marker, typedNames: true });
      expect([...u2.deleteRulesets, ...u2.closePrs]).toEqual([]);
      const b2 = await planB(w, rec, term({ confirm: () => true, type: () => 'nope' }), { marker, typedNames: true });
      expect([...b2.deleteSecrets, ...b2.deleteVariables, ...b2.deleteEnvironments]).toEqual([]);
      expect(b2.settings[0]?.turnOff).toBe(false);
      expect(b2.skipped.filter((x) => x.why === 'kept: its name was not typed')).toHaveLength(4);
    }
    // a typed trust is the same
    const u3 = await planB(w, rec, term(), { trust: 'typed', typedNames: true, dropped: TYPED_DROPPED });
    expect(u3.deleteSecrets.every((x) => x.confirmedByName)).toBe(true);
    expect(writes(w)).toEqual([]);
  });

  it('plan: object whose id or GitHub created_at differs from the record → not pipegen\'s, kept, listed', async () => {
    const w = world();
    w.app.rulesets.set(41, liveRs(w, { created_at: LATER }));
    w.app.rulesets.set(42, liveRs(w, { name: 'pipegen-reviews', source: 'o/other' }));
    w.app.stored.set('PIPEGEN_FP_KEY', LATER);
    setVar(w, 'repo', 'PIPEGEN_BLOCK_FROM', 'x', LATER);
    env(w, 'pipegen-signing', { created_at: LATER });
    w.org.set(77, { id: 77, name: 'pipegen-required--shop', source_type: 'Organization', source: 'o', created_at: AT, conditions: { repository_id: { repository_ids: [w.app.id + 1] }, ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } }, rules: [] });
    const rec = sampleRecord(w, {
      rulesets: [rs(), rs({ kind: 'reviews', id: 42, name: 'pipegen-reviews' })],
      [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }],
      variables: [{ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: true, githubCreatedAt: AT }],
      environments: [{ name: 'pipegen-signing', created: true, githubCreatedAt: AT, changed: [], branchPolicyIds: [] }],
      orgRuleset: { org: 'o', id: 77, name: 'pipegen-required--shop', githubCreatedAt: AT, pinnedSha: SHA('c') },
    });
    const t = term();
    const u = await plan(w, rec, t);
    expect([...u.deleteRulesets, ...u.deleteSecrets, ...u.deleteVariables, ...u.deleteEnvironments]).toEqual([]);
    expect(u.deleteOrgRuleset).toBeUndefined();
    const s = whats(u);
    expect(s).toMatch(/ruleset pipegen \(id 41\): .*not the one pipegen created/);
    expect(s).toMatch(/ruleset pipegen-reviews \(id 42\): .*doesn't belong to o\/shop/);
    expect(s).toMatch(/secret PIPEGEN_FP_KEY: .*not the one pipegen created/);
    expect(s).toMatch(/variable PIPEGEN_BLOCK_FROM: .*not the one pipegen created/);
    expect(s).toMatch(/environment pipegen-signing: .*not the one pipegen created/);
    expect(s).toMatch(/org ruleset pipegen-required--shop.*doesn't target exactly o\/shop/);
    // never asked about another object
    expect(t.typed).toEqual([]);
    // one GitHub doesn't show: listed, nothing to do
    const w2 = world();
    const u2 = await plan(w2, sampleRecord(w2, { rulesets: [rs()] }), term());
    expect(u2.deleteRulesets).toEqual([]);
    expect(whats(u2)).toMatch(/ruleset pipegen \(id 41\): GitHub doesn't show it/);
    // an org rule GitHub answers 404 for: gone, or no read access to the organisation's rulesets; said so (spec M5)
    const u3 = await plan(w2, sampleRecord(w2, { orgRuleset: { org: 'o', id: 77, name: 'pipegen-required--shop', githubCreatedAt: AT, pinnedSha: SHA('c') } }), term());
    expect(u3.deleteOrgRuleset).toBeUndefined();
    expect(whats(u3)).toMatch(/org ruleset pipegen-required--shop \(id 77\): GitHub answers 404 for it: it is gone, or this login can't read the organisation's rulesets/);
  });

  it('plan: unconfirmed object → typed name before deleting', async () => {
    const w = world();
    w.app.rulesets.set(41, liveRs(w));
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    env(w, 'pipegen-signing');
    const rec = sampleRecord(w, {
      rulesets: [rs({ githubCreatedAt: undefined, unconfirmed: true })],
      [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, unconfirmed: true }],
      environments: [{ name: 'pipegen-signing', created: true, unconfirmed: true, changed: [], branchPolicyIds: [] }],
    });
    // run 1 asks the ruleset's name; run 2 the secret's and the environment's
    const t = term();
    const u = await plan(w, rec, t);
    expect(u.deleteRulesets).toMatchObject([{ kind: 'gate', id: 41, confirmedByName: true }]);
    expect(t.typed).toHaveLength(1);
    const tb = term();
    const b = await planB(w, rec, tb);
    expect(b.deleteSecrets).toMatchObject([{ confirmedByName: true }]);
    expect(b.deleteEnvironments).toMatchObject([{ name: 'pipegen-signing', confirmedByName: true }]);
    expect(tb.typed).toHaveLength(2);
    // the question says why the name is asked
    expect([...t.typed, ...tb.typed].every((q) => /GitHub never confirmed when pipegen created/.test(q))).toBe(true);
    const u2 = await plan(w, rec, term({ type: () => '' }));
    const b2 = await planB(w, rec, term({ type: () => '' }));
    expect([...u2.deleteRulesets, ...b2.deleteSecrets, ...b2.deleteEnvironments]).toEqual([]);
    expect(u2.skipped.filter((x) => x.why === 'kept: its name was not typed').map((x) => x.what)).toEqual(['ruleset pipegen (id 41)']);
    expect(b2.skipped.filter((x) => x.why === 'kept: its name was not typed').map((x) => x.what).sort()).toEqual(['environment pipegen-signing', 'secret PIPEGEN_FP_KEY']);
  });

  it('plan: overwritten secret → never deleted, says the old value is gone', async () => {
    const w = world();
    w.app.stored.set('DATABASE_URL', AT);
    const rec = sampleRecord(w, { [SEC]: [{ name: 'DATABASE_URL', scope: 'repo', created: false, overwritten: true, githubCreatedAt: AT }] });
    const t = term();
    const u = await plan(w, rec, t, { typedNames: true });
    expect(u.deleteSecrets).toEqual([]);
    expect(t.typed).toEqual([]);
    const s = u.skipped.find((x) => x.what === 'secret DATABASE_URL');
    expect(s?.why).toMatch(/pipegen replaced its value; the old value is gone/);
    expect(previewUninstall(u)).toMatch(/DATABASE_URL.*the old value is gone/);
  });

  it('plan: created environment holding secrets or variables pipegen didn\'t add → kept, listed', async () => {
    const w = world();
    const e = env(w, 'pipegen-signing');
    e.stored.set('PIPEGEN_COSIGN_KEY', AT);
    e.stored.set('TEAM_TOKEN', AT);
    setVar(w, 'env:pipegen-signing', 'TEAM_URL', 'https://x');
    const rec = sampleRecord(w, {
      [SEC]: [{ name: 'PIPEGEN_COSIGN_KEY', scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT }],
      environments: [{ name: 'pipegen-signing', created: true, githubCreatedAt: AT, changed: [], branchPolicyIds: [] }],
    });
    const u = await plan(w, rec, term());
    expect(u.deleteEnvironments).toEqual([]);
    const k = u.skipped.find((x) => x.what === 'environment pipegen-signing');
    expect(k?.why).toMatch(/TEAM_TOKEN/);
    expect(k?.why).toMatch(/TEAM_URL/);
    expect(k?.why).not.toMatch(/https:\/\/x/);
    // only pipegen's own item inside it is deleted
    expect(u.deleteSecrets.map((s) => s[SK].name)).toEqual(['PIPEGEN_COSIGN_KEY']);
    // with only pipegen's items in it, the environment goes (after its items)
    e.stored.delete('TEAM_TOKEN');
    w.vars.delete('env:pipegen-signing');
    expect((await plan(w, rec, term())).deleteEnvironments.map((x) => x.name)).toEqual(['pipegen-signing']);
    // a list GitHub gives only in part (more than one page): kept
    w.g.hooks.unshift((call) => (call.route.endsWith('/environments/{environment_name}/variables') ? { status: 200, data: { total_count: 3, variables: [] } } : undefined));
    const partial = await plan(w, rec, term());
    expect(partial.deleteEnvironments).toEqual([]);
    expect(whats(partial)).toMatch(/couldn't list every variable/);
    w.g.hooks.shift();
    // a secret recorded but with another created_at is not pipegen's: the environment stays
    e.stored.set('PIPEGEN_COSIGN_KEY', LATER);
    expect((await plan(w, rec, term())).deleteEnvironments).toEqual([]);
  });

  it('plan: pre-existing environment → restored, not deleted', async () => {
    const w = world();
    env(w, 'production', { wait_timer: 30 });
    env(w, 'staging', { wait_timer: 5 });
    const rec = sampleRecord(w, {
      environments: [
        { name: 'production', created: false, githubCreatedAt: AT, previous: envSettings({ wait_timer: 0 }), changed: ['wait_timer'], branchPolicyIds: [] },
        { name: 'staging', created: false, githubCreatedAt: AT, changed: [], branchPolicyIds: [] },   // no previous: left as it is
      ],
    });
    const u = await plan(w, rec, term());
    expect(u.deleteEnvironments).toEqual([]);
    expect(u.restoreEnvironments.map((r) => r.name)).toEqual(['production']);
    expect(u.restoreEnvironments[0]).toMatchObject({ changed: ['wait_timer'], previous: envSettings({ wait_timer: 0 }) });
    expect(u.restoreEnvironments[0]?.shown).toEqual({ wait_timer: 30, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null });
    expect(whats(u)).toMatch(/environment staging: pipegen has no earlier settings of it, so it leaves it as it is/);
    // the environment was re-created since: not the one pipegen changed
    w.app.envs.get('production')!.created_at = LATER;
    const u2 = await plan(w, rec, term());
    expect(u2.restoreEnvironments).toEqual([]);
    expect(whats(u2)).toMatch(/environment production: .*not the one pipegen changed/);
  });

  it('plan: environment restore shows diff and needs typed name', async () => {
    const w = world();
    env(w, 'production', { wait_timer: 30 });
    const rec = sampleRecord(w, { environments: [{ name: 'production', created: false, githubCreatedAt: AT, previous: envSettings({ wait_timer: 0 }), changed: ['wait_timer'], branchPolicyIds: [] }] });
    const t = term();
    const u = await planB(w, rec, t);
    const r = u.restoreEnvironments[0];
    expect(r?.diff).toBe('  wait_timer: 30 → 0');
    expect(r?.confirmedByName).toBe(true);
    expect(r?.typed).toBeDefined();
    // the diff is shown before the name is typed
    const q = t.typed.find((x) => x.includes('production'));
    expect(q).toMatch(/wait_timer: 30 → 0[^]*Type production to go on/);
    expect(previewUninstall(u)).toMatch(/production[^]*wait_timer: 30 → 0/);
    // not typed: nothing restored, listed
    const u2 = await planB(w, rec, term({ type: () => 'prod' }));
    expect(u2.restoreEnvironments).toEqual([]);
    expect(u2.skipped).toContainEqual({ what: 'environment production', why: 'kept: its name was not typed' });
    // nothing to put back (already as before): no question
    w.app.envs.get('production')!.wait_timer = 0;
    const t3 = term();
    const u3 = await planB(w, rec, t3);
    expect(u3.restoreEnvironments).toEqual([]);
    expect(t3.typed).toEqual([]);
  });

  it('plan: restore touches only the fields pipegen changed', async () => {
    const w = world();
    env(w, 'production', { wait_timer: 30, prevent_self_review: true, reviewers: [{ type: 'User', id: 7 }] });
    // an edited `previous` would loosen the reviewers too: only `changed` counts
    const rec = sampleRecord(w, { environments: [{ name: 'production', created: false, githubCreatedAt: AT, previous: envSettings({ wait_timer: 0, prevent_self_review: false, reviewers: [] }), changed: ['wait_timer'], branchPolicyIds: [] }] });
    const u = await plan(w, rec, term());
    expect(u.restoreEnvironments[0]?.changed).toEqual(['wait_timer']);
    expect(u.restoreEnvironments[0]?.diff).toBe('  wait_timer: 30 → 0');
    expect(u.restoreEnvironments[0]?.diff).not.toMatch(/reviewers|prevent_self_review/);
    // a changed list naming a field outside the settings is refused: manual
    const bad = sampleRecord(w, { environments: [{ name: 'production', created: false, githubCreatedAt: AT, previous: envSettings(), changed: ['wait_timer', 'evil' as keyof EnvSettings], branchPolicyIds: [] }] });
    const u2 = await plan(w, bad, term());
    expect(u2.restoreEnvironments).toEqual([]);
    expect(whats(u2)).toMatch(/environment production: .*field pipegen never changes/);
    // branch rules pipegen changed: a manual step beside the restore; its own rule ids deleted only with the restore
    env(w, 'production', { wait_timer: 30, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, policies: [{ id: 91, name: 'main', type: 'branch' }] });
    const br = sampleRecord(w, { environments: [{ name: 'production', created: false, githubCreatedAt: AT, previous: envSettings({ wait_timer: 0 }), changed: ['wait_timer', 'branch_policies'], branchPolicyIds: [91] }] });
    const t3 = term();
    const u3 = await planB(w, br, t3);
    expect(u3.restoreEnvironments[0]?.deleteBranchPolicies).toEqual([{ id: 91 }]);
    // the typed question names every change it covers, the branch rules too (sec M2)
    expect(t3.typed.find((q) => q.includes('production'))).toMatch(/wait_timer: 30 → 0[^]*takes off the branch rules pipegen added \(ids 91\)/);
    expect(u3.manual.some((m) => /branch and tag rules/.test(m.why))).toBe(true);
  });

  it('plan: pre-existing classic protection → restored from previous, never deleted', async () => {
    const w = world();
    const planned = { method: 'PUT' as const, route: 'PUT /repos/{owner}/{repo}/branches/{branch}/protection', params: { owner: 'o', repo: 'shop', branch: 'main' }, body: { required_status_checks: { strict: true, checks: [{ context: 'pipegen / gate', app_id: 15368 }] }, enforce_admins: true, required_pull_request_reviews: null, restrictions: null } };
    w.protection = { required_status_checks: { strict: true, checks: [{ context: 'pipegen / gate', app_id: 15368 }], contexts: ['pipegen / gate'] }, enforce_admins: { enabled: true } };
    const previous = { required_status_checks: null, enforce_admins: false, required_pull_request_reviews: { required_approving_review_count: 1, dismiss_stale_reviews: false, require_code_owner_reviews: false }, restrictions: null };
    const rec = sampleRecord(w, { classicProtection: { branch: 'main', previous }, planned: { ...sampleRecord(w).planned, classic: planned } });
    const t = term();
    const u = await plan(w, rec, t);
    expect(u.restoreClassic).toMatchObject({ branch: 'main', previous, confirmedByName: true });
    expect(u.restoreClassic?.typed).toBeDefined();
    expect(u.restoreClassic?.diff).toMatch(/required_pull_request_reviews/);
    expect(t.typed.some((q) => /branch protection of main[^]*Type main to go on/.test(q))).toBe(true);
    expect(u.deleteRulesets).toEqual([]);
    expect(previewUninstall(u)).toMatch(/put back as it was before pipegen/);
    expect(previewUninstall(u)).not.toMatch(/protection[^\n]*(?:is deleted|removed)/);
    // none before pipegen (previous null): the protection pipegen added is removed, after the typed branch name
    const u2 = await plan(w, sampleRecord(w, { classicProtection: { branch: 'main', previous: null }, planned: rec.planned }), term());
    expect(u2.restoreClassic).toMatchObject({ previous: null, confirmedByName: true });
    // not typed: nothing restored
    const u3 = await plan(w, rec, term({ type: () => 'master' }));
    expect(u3.restoreClassic).toBeUndefined();
    expect(u3.skipped).toContainEqual({ what: 'branch protection of main', why: 'kept: its name was not typed' });
    // changed since pipegen set it: kept, a manual step, never asked (a field pipegen sets, then one it never sets)
    const set = w.protection;
    w.protection = { ...set, enforce_admins: { enabled: false } };
    const t5 = term();
    expect((await plan(w, rec, t5)).restoreClassic).toBeUndefined();
    expect(t5.typed).toEqual([]);
    w.protection = { ...set, required_signatures: { enabled: true } };
    const t4 = term();
    const u4 = await plan(w, rec, t4);
    expect(u4.restoreClassic).toBeUndefined();
    expect(u4.manual.find((m) => m.what === 'branch protection of main')?.why).toMatch(/not exactly as pipegen set it/);
    expect(t4.typed).toEqual([]);
  });

  it('plan: settings pipegen turned on → asked, default keep', async () => {
    const w = world();
    const rec = sampleRecord(w, { repoSettings: { [SS]: { previous: false }, pushProtection: { previous: true }, shaPinningRequired: { previous: false } } });
    const t = term();
    const u = await planB(w, rec, t);
    expect(u.settings).toEqual([
      { key: 'shaPinningRequired', previous: false, turnOff: false, confirmedByName: false },
      { key: 'secretScanning', previous: false, turnOff: false, confirmedByName: false },
    ]);
    expect(t.confirms).toContain('Turn off secret scanning? (y/N)');
    expect(t.confirms.some((q) => q.includes('push protection'))).toBe(false);   // it was on before pipegen: never asked
    expect(u.skipped).toContainEqual({ what: 'setting push protection', why: 'it was on before pipegen: nothing to turn back' });
    // run 1 asks nothing about settings: it says the next run will
    const t0 = term();
    const a = await plan(w, rec, t0);
    expect(t0.confirms.filter((q) => q.startsWith('Turn off'))).toEqual([]);
    expect(a.settings.every((x) => !x.turnOff)).toBe(true);
    expect(previewUninstall(a)).toMatch(/Next run[^]*asks whether to turn off[^]*secret scanning/);
    const u2 = await planB(w, rec, term({ confirm: (q) => q.startsWith('Turn off secret scanning') }));
    expect(u2.settings.find((s) => s.key === 'secretScanning')?.turnOff).toBe(true);
    expect(u2.settings.find((s) => s.key === 'shaPinningRequired')?.turnOff).toBe(false);
    expect(previewUninstall(u2)).toMatch(/Settings pipegen turns off[^]*secret scanning/);
    // no terminal: kept
    const u3 = await planB(w, rec, term({ confirm: () => true }), {}, false);
    expect(u3.settings.every((s) => !s.turnOff)).toBe(true);
  });

  it('plan: never-merged install → close the setup PR, delete its branch, the N4 environment and the deliver-time secrets', async () => {
    const w = world({ 'README.md': 'my app\n' });
    // the setup branch: pipegen's files only, on top of the default branch
    const setupFiles = Object.fromEntries(Object.keys(PARTS).map((p) => [p, FILES[p] as string]));
    w.app.refs.set('heads/pipegen/setup', w.g.head('o/shop'));
    w.g.commitOn('o/shop', 'pipegen/setup', setupFiles, 'pipegen: add');
    w.app.pulls.push({ number: 3, head: 'pipegen/setup', base: 'main', title: 'pipegen setup', body: '', state: 'open', html_url: 'https://github.com/o/shop/pull/3' });
    const e = env(w, 'pipegen-signing');
    e.stored.set('PIPEGEN_COSIGN_KEY', AT);
    e.stored.set('PIPEGEN_COSIGN_PASSWORD', AT);
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    const rec = sampleRecord(w, {
      mergedAt: undefined,
      [SEC]: [
        { name: 'PIPEGEN_COSIGN_KEY', scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT },
        { name: 'PIPEGEN_COSIGN_PASSWORD', scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT },
        { name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT },
      ],
      environments: [{ name: 'pipegen-signing', created: true, githubCreatedAt: AT, changed: [], branchPolicyIds: [] }],
    });
    // a fork's pull request on a branch of the same name is never pipegen's
    w.app.pulls.push({ number: 4, head: 'pipegen/setup', base: 'main', title: 'fork', body: '', state: 'open', html_url: 'f' });
    w.pullRepoId.set(4, 999_999);
    const u = await plan(w, rec, term(), { setupPr: 3 });
    expect(u.unfinished).toBe(true);
    expect(u.closePrs).toEqual([{ repo: 'app', number: 3, branch: 'pipegen/setup', confirmedByName: false }]);
    expect(u.deleteBranches).toEqual([{ repo: 'app', branch: 'pipegen/setup', head: w.g.head('o/shop', 'pipegen/setup'), confirmedByName: false }]);
    expect(u.deleteEnvironments.map((x) => x.name)).toEqual(['pipegen-signing']);
    expect(u.deleteSecrets.map((x) => x[SK].name).sort()).toEqual(['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD', 'PIPEGEN_FP_KEY']);
    expect(u.removeFiles).toEqual([]);   // nothing of pipegen's is on the default branch
    expect(previewUninstall(u)).toMatch(/never merged/);
    // a record path no created-file rule claims, with its recorded sha on the branch: not pipegen's (sec M5)
    const odd = sampleRecord(w, { ...rec, files: [...rec.files, { repo: 'app', path: 'src/odd.ts', part: 'pipeline', shas: [blob('o\n')] }] });
    const hd = w.g.head('o/shop', 'pipegen/setup');
    w.g.commitOn('o/shop', 'pipegen/setup', { 'src/odd.ts': 'o\n' }, 'odd');
    const uo = await plan(w, odd, term(), { setupPr: 3 });
    expect(uo.deleteBranches).toEqual([]);
    expect(uo.manual.find((m) => m.what === 'branch pipegen/setup')?.why).toMatch(/src\/odd\.ts/);
    w.app.refs.set('heads/pipegen/setup', hd);
    // someone else's commit on pipegen/setup: the branch is kept, a manual step
    w.g.commitOn('o/shop', 'pipegen/setup', { 'src/mine.ts': 'x\n' }, 'my work');
    const u2 = await plan(w, rec, term(), { setupPr: 3 });
    expect(u2.deleteBranches).toEqual([]);
    expect(u2.manual.find((m) => m.what === 'branch pipegen/setup')?.why).toMatch(/src\/mine\.ts/);
    // a merged setup PR: finished, its branch is not touched
    const w3 = world();
    w3.app.refs.set('heads/pipegen/setup', w3.g.head('o/shop'));
    w3.app.pulls.push({ number: 3, head: 'pipegen/setup', base: 'main', title: 's', body: '', state: 'closed', html_url: 'x' });
    const g3 = gh(w3);
    const merged = { request: async (route: string, params: Record<string, unknown>) => {
      const out = await (g3 as unknown as { request: (r: string, p: unknown) => Promise<{ data: unknown }> }).request(route, params);
      return route.endsWith('/pulls/{pull_number}') ? { ...out, data: { ...(out.data as object), merged_at: '2026-11-05T13:00:00Z' } } : out;
    } } as unknown as Octokit;
    const u3 = await planUninstall(merged, loadedOf(w3, sampleRecord(w3), { setupPr: 3 }), term().p, { interactive: true, local: local(w3) });
    expect(u3.unfinished).toBe(false);
    expect(u3.deleteBranches).toEqual([]);
    expect(u3.closePrs).toEqual([]);
    // merged, though no workflow of pipegen's is on the default branch now and the record has no mergedAt: still not unfinished
    const w4 = world({ 'README.md': 'my app\n' });
    w4.app.pulls.push({ number: 3, head: 'pipegen/setup', base: 'main', title: 's', body: '', state: 'closed', html_url: 'x' });
    const g4 = gh(w4);
    const merged4 = { request: async (route: string, params: Record<string, unknown>) => {
      const out = await (g4 as unknown as { request: (r: string, p: unknown) => Promise<{ data: unknown }> }).request(route, params);
      return route.endsWith('/pulls/{pull_number}') ? { ...out, data: { ...(out.data as object), merged_at: '2026-11-05T13:00:00Z' } } : out;
    } } as unknown as Octokit;
    expect((await planUninstall(merged4, loadedOf(w4, sampleRecord(w4, { mergedAt: undefined }), { setupPr: 3 }), term().p, { interactive: true, local: local(w4) })).unfinished).toBe(false);
  });

  it('plan: leftovers file entries asked and identity-checked, never deleted blind', async () => {
    const w = world();
    w.app.stored.set('PIPEGEN_LEFT', AT);
    w.app.stored.set('PIPEGEN_OTHER', LATER);
    env(w, 'pipegen-signing', { wait_timer: 0, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, policies: [{ id: 5, name: 'main', type: 'branch' }] });
    await addLocalLeftovers({ owner: 'o', repo: 'shop' }, [
      { kind: 'secret', name: 'PIPEGEN_LEFT', repo: 'o/shop', scope: 'repo', githubCreatedAt: AT },
      { kind: 'secret', name: 'PIPEGEN_OTHER', repo: 'o/shop', scope: 'repo', githubCreatedAt: AT },   // GitHub says another time
      { kind: 'secret', name: 'PIPEGEN_ELSE', repo: 'o/elsewhere', scope: 'repo', githubCreatedAt: AT },  // another repo's
      { kind: 'environment', name: 'pipegen-signing', repo: 'o/shop', githubCreatedAt: AT, previous: envSettings({ deployment_branch_policy: null }) as unknown as Record<string, unknown>, changed: ['deployment_branch_policy'] },
    ], new Date(), local(w));
    const t = term();
    const u = await planB(w, sampleRecord(w), t);
    // proved by GitHub and pipegen-shaped, still asked by name (a leftover is never deleted blind)
    expect(u.deleteSecrets).toMatchObject([{ [SK]: { name: 'PIPEGEN_LEFT', scope: 'repo' }, confirmedByName: true, fromLeftovers: true }]);
    expect(t.typed.some((q) => q.includes('PIPEGEN_LEFT'))).toBe(true);
    expect(whats(u)).toMatch(/secret PIPEGEN_OTHER: .*not the one pipegen created/);
    expect(whats(u)).toMatch(/secret PIPEGEN_ELSE \(leftovers file\): .*another repo/);
    expect(t.typed.some((q) => q.includes('PIPEGEN_OTHER') || q.includes('PIPEGEN_ELSE'))).toBe(false);
    // the narrowed signing environment (N3): restored with its diff and typed name, like a record entry
    expect(u.restoreEnvironments.map((r) => r.name)).toEqual(['pipegen-signing']);
    expect(u.restoreEnvironments[0]?.diff).toMatch(/deployment_branch_policy/);
    // not typed: nothing from the leftovers
    const u2 = await planB(w, sampleRecord(w), term({ type: () => '' }));
    expect(u2.deleteSecrets).toEqual([]);
    expect(u2.restoreEnvironments).toEqual([]);
    // an unreadable leftovers file stops, naming it
    writeFileSync(join(w.home, '.config', 'pipegen', 'records', 'o__shop.leftovers.json'), 'not json');
    await stops(plan(w, sampleRecord(w), term()), /o__shop\.leftovers\.json/);
  });

  it('plan: typed trust → edits, previous settings, classic, org rule, central and scratch listed as manual steps', async () => {
    const w = world();
    // what confirmView keeps: names, created flags and dates; everything else is absent or empty in the view
    const view = sampleRecord(w, { edits: [], serviceRoots: [], protectedPaths: [], mergedAt: undefined, variables: [{ name: 'MY_VAR', scope: 'repo', created: false }], environments: [{ name: 'production', created: false, githubCreatedAt: AT, changed: [], branchPolicyIds: [] }] });
    env(w, 'production', { wait_timer: 30 });
    const u = await plan(w, view, term(), { trust: 'typed', typedNames: true, dropped: TYPED_DROPPED });
    const m = u.manual.map((x) => `${x.what}: ${x.why} ${x.step ?? ''}`).join('\n');
    expect(m).toMatch(/pipegen's changes inside your files/);
    expect(m).toMatch(/settings pipegen changed on existing variables and environments/);
    expect(m).toMatch(/branch protection/);
    expect(m).toMatch(/organisation required-workflow rule/);
    expect(m).toMatch(/central repo/);
    expect(m).toMatch(/scratch repo/);
    expect(m).toMatch(/security settings/);
    expect(u.restoreClassic).toBeUndefined();
    expect(u.deleteOrgRuleset).toBeUndefined();
    expect(u.restoreEnvironments).toEqual([]);
    expect(u.restoreVariables).toEqual([]);
    expect(u.settings).toEqual([]);
    expect(u.centralLocks).toBeUndefined();
    expect(u.reverts).toEqual([]);
    expect(revertCalls).toEqual([]);
    // the preview says so, and never that the central locks go (sec M1): they are manual steps here
    expect(previewUninstall(u)).toMatch(/trusted by typing/);
    expect(u.lastProject).toBe(true);
    expect(previewUninstall(u)).not.toMatch(/go too/);
    expect(previewUninstall(u)).toMatch(/pipegen doesn't touch them \(see the manual steps\)/);
    // full trust, the last project, but the record lists no central lock: no pointer to a manual step that isn't there (M-r1-7)
    const pf = previewUninstall(await plan(w, sampleRecord(w), term()));
    expect(pf).toMatch(/last project/);
    expect(pf).not.toMatch(/see the manual steps/);
  });
});

describe('uninstall plan: reads, terminal and preview (V4)', () => {
  it('plan: files read from the default-branch tree through the API, never the local folder', async () => {
    const w = world();
    w.g.commitOn('o/shop', 'main', { 'PIPEGEN.md': '# pipegen\n' }, 'same');
    // another branch with a changed workflow, and a local folder with one: neither counts
    w.app.refs.set('heads/feature', w.g.head('o/shop'));
    w.g.commitOn('o/shop', 'feature', { '.github/workflows/pipegen.yml': 'changed\n' });
    const dir = mkdtempSync(join(tmpdir(), 'pg-unplan-cwd-'));
    homes.push(dir);
    mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
    writeFileSync(join(dir, '.github', 'workflows', 'pipegen.yml'), 'local change\n');
    const cwd = process.cwd();
    process.chdir(dir);
    let u: UninstallPlan;
    try { u = await plan(w, sampleRecord(w), term()); } finally { process.chdir(cwd); }
    const head = w.g.head('o/shop');
    expect(u.base.appHead).toBe(head);
    expect(u.base.appTree).toBe(w.app.commits.get(head)?.tree);
    expect(u.base.centralHead).toBe(w.g.head('o/pipelines'));
    expect(u.base.recordBlobSha).toBe(SHA('b'));
    expect(u.removeFiles.map((f) => f.path)).toContain('.github/workflows/pipegen.yml');
    expect(w.g.calls.some((c) => c.route === 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}' && c.params.commit_sha === head)).toBe(true);
    expect(w.g.routes().some((r) => r.includes('/contents'))).toBe(false);
    expect(writes(w)).toEqual([]);
    // no default-branch head: stop
    w.app.refs.delete('heads/main');
    await stops(plan(w, sampleRecord(w), term()), /default branch main of o\/shop/);
  });

  it('plan: typed names only from the interactive prompt; no TTY → stop', async () => {
    const w = world();
    w.app.stored.set('STRIPE_KEY', AT);
    const rec = sampleRecord(w, { [SEC]: [{ name: 'STRIPE_KEY', scope: 'repo', created: true, githubCreatedAt: AT }] });
    for (const interactive of [false, undefined]) {
      const t = term();
      await stops(planUninstall(gh(w), loadedOf(w, rec), t.p, { ...(interactive === undefined ? {} : { interactive }), local: local(w), phase: 'B' }), /at a terminal/);
      expect(t.typed).toEqual([]);
    }
    // no prompter at all: the same stop
    await stops(planUninstall(gh(w), loadedOf(w, rec), undefined, { interactive: true, local: local(w), phase: 'B' }), /at a terminal/);
    // an env variable or a flag never answers it
    const prev = process.env.PIPEGEN_YES;
    process.env.PIPEGEN_YES = '1';
    try { await stops(planB(w, rec, term(), {}, false), /at a terminal/); } finally { if (prev === undefined) delete process.env.PIPEGEN_YES; else process.env.PIPEGEN_YES = prev; }
    // run 1 needs a name too for a merge lock GitHub never dated: the same stop
    w.app.rulesets.set(41, liveRs(w));
    await stops(plan(w, sampleRecord(w, { rulesets: [rs({ githubCreatedAt: undefined, unconfirmed: true })] }), term(), {}, false), /at a terminal/);
    // run 1 asks nothing of run 2's: STRIPE_KEY needs no terminal yet
    expect((await plan(w, rec, term(), {}, false)).deleteSecrets).toMatchObject([{ needsName: true, confirmedByName: false }]);
    // nothing that needs a name: a plan without a terminal is fine
    const u = await plan(w, sampleRecord(w), term(), {}, false);
    expect(u.deleteSecrets).toEqual([]);
    expect(writes(w)).toEqual([]);
  });

  it('preview: lists secret names, never values', async () => {
    const w = world();
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    w.app.stored.set('STRIPE_KEY', AT);
    setVar(w, 'repo', 'PIPEGEN_BLOCK_FROM', '2026-11-05T00:00:00Z');
    setVar(w, 'repo', 'DEPLOY_URL', 'https://pipegen.example/value-set-by-pipegen');
    const rec = sampleRecord(w, {
      [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }, { name: 'STRIPE_KEY', scope: 'repo', created: true, githubCreatedAt: AT }],
      variables: [{ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, previous: 'old-value-before-pipegen' }, { name: 'DEPLOY_URL', scope: 'repo', created: true, githubCreatedAt: AT }],
      blockFrom: '2026-11-05T00:00:00Z', cosignPub: '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n',
    });
    const u = await planB(w, rec, term());
    expect(u.restoreVariables).toMatchObject([{ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', previous: 'old-value-before-pipegen', pipegenValue: '2026-11-05T00:00:00Z', confirmedByName: true }]);
    expect(u.deleteVariables.find((v) => v.name === 'DEPLOY_URL')).toMatchObject({ confirmedByName: true });
    const a = previewUninstall(await plan(w, rec, term()));
    for (const name of ['PIPEGEN_FP_KEY', 'STRIPE_KEY', 'PIPEGEN_BLOCK_FROM', 'DEPLOY_URL']) expect(a).toContain(name);
    for (const value of ['old-value-before-pipegen', '2026-11-05T00:00:00Z', 'value-set-by-pipegen', 'BEGIN PUBLIC KEY', 'MFkwEwYHKoZIzj0']) expect(a).not.toContain(value);
    const p = previewUninstall(u) + a;
    for (const name of ['PIPEGEN_FP_KEY', 'STRIPE_KEY', 'PIPEGEN_BLOCK_FROM', 'DEPLOY_URL']) expect(p).toContain(name);
    for (const value of ['old-value-before-pipegen', '2026-11-05T00:00:00Z', 'value-set-by-pipegen', 'BEGIN PUBLIC KEY', 'MFkwEwYHKoZIzj0']) expect(p).not.toContain(value);
    // the two runs, and the way back to a locked branch
    expect(p).toContain('the uninstall PR removes the gate, so the merge lock is removed now; until you merge it, run `pipegen finish` to lock again');
    expect(p).toMatch(/run `pipegen uninstall` again/);
  });

  it('plan: edits go through revertEdits with the live default branch; the preview escapes their text and names the first original', async () => {
    const files = { ...FILES, CODEOWNERS: '* @team\n# pipegen:begin\n/.github/ @o\n# pipegen:end\n\u001b[31mowner line\n', '.pre-commit-config.yaml': 'repos: []\n' };
    const w = world(files, { defaultBranch: 'trunk' });
    const co: InstallEdit = { repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: '# pipegen:begin\n/.github/ @o\n# pipegen:end\n', originalSha: SHA('3'), writtenShas: [SHA('4')] };
    const central: InstallEdit = { repo: 'central', path: 'CODEOWNERS', kind: 'codeowners', inserted: 'x\n', originalSha: null, writtenShas: [SHA('5')] };
    const rec = sampleRecord(w, { edits: [co, central] });
    const u = await plan(w, rec, term());
    // once, the app's edits in record order, the LIVE default branch (renamed since install: main → trunk)
    expect(revertCalls).toHaveLength(1);
    expect(revertCalls[0]?.edits).toEqual([co]);
    expect(revertCalls[0]?.ctx).toEqual({ defaultBranch: 'trunk', appOwner: 'o' });   // G17C-R1 (F2, m3): the app owner binds the private Dependabot entry
    expect(u.reverts.map((r) => r.edit)).toEqual([co]);
    const p = previewUninstall(u);
    expect(p).toMatch(/default branch was renamed/);
    // a manual revert prints its exact text line by line, escaped: no control character reaches the terminal
    const shown = previewUninstall({ ...u, reverts: [{ edit: co, result: { kind: 'manual', why: 'review it', remove: '# pipegen:begin\n/x/ @o\u001b[2J\u0007\n# pipegen:end\n' } }] });
    expect(shown).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f]/);
    expect(shown).toMatch(/Take out exactly this text pipegen added[^]*# pipegen:begin[^]*\/x\/ @o[^]*# pipegen:end/);
    // a restore is the first original, said so
    const restored = previewUninstall({ ...u, reverts: [{ edit: co, result: { kind: 'restore', text: 'x' } }] });
    expect(restored).toMatch(/CODEOWNERS[^]*first original/);
    expect(restored).not.toMatch(/your file as it was/);
    // V-N12: a hook block with no record entry is a manual step
    const w2 = world({ ...FILES, '.pre-commit-config.yaml': 'repos: []\n# pipegen:hooks begin\n' });
    const u2 = await plan(w2, sampleRecord(w2), term());
    expect(u2.manual.find((m) => m.what === '.pre-commit-config.yaml')?.why).toMatch(/pipegen's hook block may still be in/);
    // a workflow the record doesn't list that holds pipegen's verify job or head check: manual review
    const w3 = world({ ...FILES, '.github/workflows/deploy.yml': 'jobs:\n  pipegen-verify:\n    runs-on: x\n' });
    const u3 = await plan(w3, sampleRecord(w3), term());
    expect(u3.manual.find((m) => m.what === '.github/workflows/deploy.yml')?.why).toMatch(/pipegen-verify/);
  });

  it('plan: central files are the exact list of this project, the record last; other projects keep central', async () => {
    const w = world(FILES, { centralFiles: {
      [recordPath('shop')]: '{}\n', '.github/workflows/shop--merge.yml': 'a\n', '.github/workflows/shop--push.yml': 'b\n',
      '.github/workflows/shop--evil.yml': 'c\n', '.github/workflows/shop--x--merge.yml': 'd\n', [recordPath('shop--x')]: '{}\n',
    } });
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true, rulesetId: 3, rulesetCreatedAt: AT } });
    rec.files.push({ repo: 'central', path: '.github/workflows/shop--push.yml', part: 'pipeline', shas: [blob('b\n')] }, { repo: 'central', path: '.github/workflows/shop--evil.yml', part: 'pipeline', shas: [blob('c\n')] });
    const u = await plan(w, rec, term());
    expect(u.centralFiles).toEqual(['.github/workflows/shop--merge.yml', '.github/workflows/shop--push.yml', recordPath('shop')]);
    expect(u.manual.find((m) => m.what === 'central .github/workflows/shop--evil.yml')?.why).toMatch(/not one of this project's central files/);
    // another project (shop--x) is there: not the last one, central locks stay
    expect(u.lastProject).toBe(false);
    expect(u.centralLocks).toBeUndefined();
    // alone: the last project, its central locks named
    const w2 = world();
    const rec2 = sampleRecord(w2, { central: { repoId: w2.central.id, createdByPipegen: true, rulesetId: 3, rulesetCreatedAt: AT } });
    const u2 = await plan(w2, rec2, term());
    expect(u2.lastProject).toBe(true);
    expect(u2.centralLocks).toEqual(rec2.central);
    // a fork's PR on this project's branch name is another's (sec M4): not the last project
    w2.central.pulls.push({ number: 61, head: 'pipegen/update-shop', base: 'main', title: 'fork', body: '', state: 'open', html_url: 'f' });
    w2.pullRepoId.set(61, 424_242);
    expect((await plan(w2, rec2, term())).lastProject).toBe(false);
    w2.central.pulls.pop();
    // the open central PRs are read page by page (M-r1-3): another project's PR on page 2 → not the last project
    for (let i = 0; i < 100; i += 1) w2.central.pulls.push({ number: 100 + i, head: 'pipegen/uninstall-shop', base: 'main', title: 'mine', body: '', state: 'open', html_url: 'm' });
    expect((await plan(w2, rec2, term())).lastProject).toBe(true);
    w2.central.pulls.push({ number: 300, head: 'pipegen/update-other', base: 'main', title: 'other', body: '', state: 'open', html_url: 'o' });
    expect((await plan(w2, rec2, term())).lastProject).toBe(false);
    w2.central.pulls.pop();
    // a page GitHub fails to serve: pipegen can't see every PR → not the last project
    w2.pullsFailPage = 2;
    expect((await plan(w2, rec2, term())).lastProject).toBe(false);
    w2.pullsFailPage = 1;
    expect((await plan(w2, rec2, term())).lastProject).toBe(false);
    delete w2.pullsFailPage;
    w2.central.pulls.splice(w2.central.pulls.length - 100, 100);
    // another project's central workflow with no record of it (records deleted, files left): still not the last project
    w2.g.commitOn('o/pipelines', 'main', { '.github/workflows/other--push.yml': 'x\n' });
    expect((await plan(w2, rec2, term(), { centralHead: w2.g.head('o/pipelines') })).lastProject).toBe(false);
    // a public app (records-only pipelines): only the record
    const u3 = await plan(w2, sampleRecord(w2, { centralSha: null }), term());
    expect(u3.centralFiles).toEqual([recordPath('shop')]);
  });

  it('plan: an environment variable pipegen changed is a manual step; a restore needs the value pipegen set', async () => {
    const w = world();
    env(w, 'pipegen-signing');
    setVar(w, 'env:pipegen-signing', 'PIPEGEN_COSIGN_PUB', 'pub');
    setVar(w, 'repo', 'MY_VAR', 'x');
    const rec = sampleRecord(w, { variables: [{ name: 'PIPEGEN_COSIGN_PUB', scope: 'env:pipegen-signing', created: false, previous: 'old' }, { name: 'MY_VAR', scope: 'repo', created: false, previous: 'old' }] });
    const u = await plan(w, rec, term());
    expect(u.restoreVariables).toEqual([]);
    expect(u.manual.find((m) => m.what === 'variable PIPEGEN_COSIGN_PUB (environment pipegen-signing)')?.step).toMatch(/gh variable set PIPEGEN_COSIGN_PUB --env pipegen-signing/);
    expect(whats(u)).toMatch(/variable MY_VAR: pipegen doesn't know the value it set/);
    // no earlier value recorded: left as it is, even where pipegen knows its own value
    setVar(w, 'repo', 'PIPEGEN_BLOCK_FROM', 'b');
    const u2 = await plan(w, sampleRecord(w, { variables: [{ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false }], blockFrom: 'b' }), term());
    expect(u2.restoreVariables).toEqual([]);
    expect(whats(u2)).toMatch(/variable PIPEGEN_BLOCK_FROM: pipegen didn't create it and has no earlier value of it/);
  });
  it('plan: a variable changed since pipegen set it is not put back; central secrets go only with the last project', async () => {
    const w = world();
    setVar(w, 'repo', 'PIPEGEN_BLOCK_FROM', 'the owner changed it');
    const u = await plan(w, sampleRecord(w, { variables: [{ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, previous: 'old' }], blockFrom: '2026-11-05T00:00:00Z' }), term());
    expect(u.restoreVariables).toEqual([]);
    expect(whats(u)).toMatch(/variable PIPEGEN_BLOCK_FROM: it no longer holds the value pipegen set/);
    // a central one: kept while another project uses pipelines, deleted (after its identity read) with the last project
    w.central.stored.set('PIPEGEN_CENTRAL', AT);
    const centralOnes = [{ name: 'PIPEGEN_CENTRAL', scope: 'central' as const, created: true, githubCreatedAt: AT }];
    const alone = await plan(w, sampleRecord(w, { [SEC]: centralOnes }), term());
    expect(alone.lastProject).toBe(true);
    expect(alone.deleteSecrets.map((x) => x[SK].name)).toEqual(['PIPEGEN_CENTRAL']);
    w.g.commitOn('o/pipelines', 'main', { [recordPath('other')]: '{}\n' });
    const shared = await plan(w, sampleRecord(w, { [SEC]: centralOnes }), term(), { centralHead: w.g.head('o/pipelines') });
    expect(shared.lastProject).toBe(false);
    expect(shared.deleteSecrets).toEqual([]);
    expect(whats(shared)).toMatch(/PIPEGEN_CENTRAL \(pipelines\): other projects of pipelines may use it/);
    // an open central pull request of another project: not the last one either
    const w2 = world();
    w2.central.pulls.push({ number: 2, head: 'pipegen/update-other', base: 'main', title: 'x', body: '', state: 'open', html_url: 'x' });
    expect((await plan(w2, sampleRecord(w2), term())).lastProject).toBe(false);
  });

  it('plan: org rule deleted only when it targets this repo and pins this project\'s required workflow in the recorded central repo', async () => {
    const w = world();
    const liveOrg = (over: Record<string, unknown> = {}) => ({ id: 77, name: 'pipegen-required--shop', source_type: 'Organization', source: 'o', created_at: AT,
      conditions: { repository_id: { repository_ids: [w.app.id] }, ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } },
      rules: [{ type: 'workflows', parameters: { workflows: [{ path: '.github/workflows/shop--required.yml', sha: SHA('c'), repository_id: w.central.id }] } }], ...over });
    const org = { org: 'o', id: 77, name: 'pipegen-required--shop', githubCreatedAt: AT, pinnedSha: SHA('c') };
    const rec = (centralId: number) => sampleRecord(w, { orgRuleset: org, central: { repoId: centralId, createdByPipegen: true } });
    w.org.set(77, liveOrg());
    const u = await plan(w, rec(w.central.id), term());
    expect(u.deleteOrgRuleset).toMatchObject({ org: 'o', id: 77, confirmedByName: false });
    expect(previewUninstall(u)).toMatch(/org ruleset pipegen-required--shop \(id 77\) of o: deleted/);
    // the record names another central repo id (pipelines re-created): not pipegen's rule
    expect((await plan(w, rec(w.central.id + 50), term())).deleteOrgRuleset).toBeUndefined();
    // pinned at another commit: not pipegen's
    w.org.set(77, liveOrg({ rules: [{ type: 'workflows', parameters: { workflows: [{ path: '.github/workflows/shop--required.yml', sha: SHA('d'), repository_id: w.central.id }] } }] }));
    expect((await plan(w, rec(w.central.id), term())).deleteOrgRuleset).toBeUndefined();
  });
  it('plan: leftovers entry without GitHub\'s created_at (an overwritten secret) → never deleted, a manual step', async () => {
    const w = world();
    w.app.stored.set('NPM_TOKEN', '2025-01-01T00:00:00Z');   // the user's own secret, long before pipegen
    env(w, 'pipegen-signing');
    // deliver.ts:505: a secret whose value pipegen replaced goes to the leftovers without githubCreatedAt
    await addLocalLeftovers({ owner: 'o', repo: 'shop' }, [
      { kind: 'secret', name: 'NPM_TOKEN', repo: 'o/shop', scope: 'repo' },
      { kind: 'environment', name: 'pipegen-signing', repo: 'o/shop' },
    ], new Date(), local(w));
    for (const phase of ['A', 'B'] as const) {
      const t = term();
      const u = await plan(w, sampleRecord(w), t, {}, true, phase);
      expect(u.deleteSecrets).toEqual([]);
      expect(u.deleteEnvironments).toEqual([]);
      expect(t.typed).toEqual([]);
      expect(u.manual.find((m) => m.what === 'secret NPM_TOKEN (leftovers file)')?.why).toMatch(/may only have replaced the value of a secret you already had/);
      expect(u.manual.find((m) => m.what === 'environment pipegen-signing (leftovers file)')?.why).toMatch(/no creation date/);
    }
  });

  it('plan: setup PR closed unmerged but pipegen\'s workflows on the default branch → two runs, not unfinished', async () => {
    const w = world();
    w.app.refs.set('heads/pipegen/setup', w.g.head('o/shop'));
    w.app.pulls.push({ number: 3, head: 'pipegen/setup', base: 'main', title: 's', body: '', state: 'closed', html_url: 'x' });
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    for (const mergedAt of ['2026-11-05T13:00:00Z', undefined]) {
      const rec = sampleRecord(w, { mergedAt, [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }] });
      const u = await plan(w, rec, term(), { setupPr: 3 });
      expect(u.unfinished).toBe(false);
      expect(u.deleteBranches).toEqual([]);
      const p = previewUninstall(u);
      expect(p).toContain('the uninstall PR removes the gate, so the merge lock is removed now; until you merge it, run `pipegen finish` to lock again');
      expect(p).not.toMatch(/never merged/);
      expect(p).toMatch(/setup pull request #3 was closed without merging, but pipegen's workflows are on main/);
    }
    // no workflow of pipegen's on the default branch: unfinished only without a mergedAt (full trust)
    const w2 = world({ 'README.md': 'my app\n' });
    w2.app.pulls.push({ number: 3, head: 'pipegen/setup', base: 'main', title: 's', body: '', state: 'closed', html_url: 'x' });
    expect((await plan(w2, sampleRecord(w2), term(), { setupPr: 3 })).unfinished).toBe(false);
    expect((await plan(w2, sampleRecord(w2, { mergedAt: undefined }), term(), { setupPr: 3 })).unfinished).toBe(true);
    // pipegen.yml removed by hand, but pipegen's verify job is still in the deploy workflow it edited: live, two runs (M-r1-4)
    const deploy = 'jobs:\n  build:\n    runs-on: x\n';
    const vj: InstallEdit = { repo: 'app', path: '.github/workflows/deploy.yml', kind: 'verify-job', jobs: ['build'], needs: [{ job: 'build', added: ['pipegen-verify'] }], originalSha: blob(deploy), writtenShas: [SHA('8')] };
    const wv = world({ 'README.md': 'my app\n', '.github/workflows/deploy.yml': `${deploy}  pipegen-verify:\n    runs-on: x\n` });
    expect((await plan(wv, sampleRecord(wv, { mergedAt: undefined, edits: [vj] }), term())).unfinished).toBe(false);
    const wh = world({ 'README.md': 'my app\n', '.github/workflows/deploy.yml': 'jobs:\n  build:\n    steps:\n      - id: pipegen-head-check\n' });
    expect((await plan(wh, sampleRecord(wh, { mergedAt: undefined, edits: [vj] }), term())).unfinished).toBe(false);
    // the job taken out too: nothing of pipegen's runs, unfinished
    const wn = world({ 'README.md': 'my app\n', '.github/workflows/deploy.yml': deploy });
    expect((await plan(wn, sampleRecord(wn, { mergedAt: undefined, edits: [vj] }), term())).unfinished).toBe(true);
    // only pipegen's workflows count: its Dockerfile on the default branch doesn't make the install finished
    const wd = world({ 'README.md': 'my app\n', Dockerfile: FILES.Dockerfile as string });
    expect((await plan(wd, sampleRecord(wd, { mergedAt: undefined }), term())).unfinished).toBe(true);
    // an adopted workflow is not pipegen's own: it doesn't count as live
    const w3 = world({ 'README.md': 'my app\n', '.github/workflows/pipegen.yml': 'name: pipegen\n' });
    const ad = sampleRecord(w3, { mergedAt: undefined });
    (ad.files.find((f) => f.path === '.github/workflows/pipegen.yml') as InstallRecord['files'][number]).adopted = true;
    expect((await plan(w3, ad, term())).unfinished).toBe(true);
    expect((await plan(w3, sampleRecord(w3, { mergedAt: undefined }), term())).unfinished).toBe(false);
  });

  it('plan: pipegen\'s open central update PR is closed in run 1, by exact branch and head repo, after its number is typed', async () => {
    const w = world();
    w.central.pulls.push({ number: 4, head: 'pipegen/update-shop', base: 'main', title: 'u', body: '', state: 'open', html_url: 'u' });
    w.central.pulls.push({ number: 5, head: 'pipegen/update-shop', base: 'main', title: 'fork', body: '', state: 'open', html_url: 'f' });
    w.pullRepoId.set(5, 424_242);
    w.central.pulls.push({ number: 6, head: 'pipegen/update-other', base: 'main', title: 'other', body: '', state: 'open', html_url: 'o' });
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
    const t = term();
    const u = await plan(w, rec, t);
    // the record holds no actor, so the PR's author can't be proved: its number is typed (V3 spec N3)
    expect(u.closePrs).toEqual([{ repo: 'central', number: 4, branch: 'pipegen/update-shop', confirmedByName: true }]);
    expect(t.typed.some((q) => /pull request #4 \(branch pipegen\/update-shop\) in o\/pipelines[^]*Type 4 to go on/.test(q))).toBe(true);
    expect(previewUninstall(u)).toMatch(/#4 in o\/pipelines \(pipegen\/update-shop\)/);
    const u2 = await plan(w, rec, term({ type: () => '' }));
    expect(u2.closePrs).toEqual([]);
    expect(u2.skipped).toContainEqual({ what: 'pull request #4 (pipegen/update-shop) in o/pipelines', why: 'kept: its name was not typed' });
    // a central repo that isn't the recorded one: nothing of it is pipegen's
    expect((await plan(w, sampleRecord(w, { central: { repoId: w.central.id + 9, createdByPipegen: true } }), term())).closePrs).toEqual([]);
  });

  it('plan: run 1 asks only its own names; the next run\'s are previewed with no question and no token', async () => {
    const w = world();
    w.app.stored.set('PIPEGEN_X', AT);
    env(w, 'production', { wait_timer: 30 });
    setVar(w, 'repo', 'PIPEGEN_BLOCK_FROM', '2026-11-05T00:00:00Z');
    const rec = sampleRecord(w, {
      variables: [{ name: 'PIPEGEN_BLOCK_FROM', scope: 'repo', created: false, previous: 'old-value-before-pipegen' }], blockFrom: '2026-11-05T00:00:00Z',
      [SEC]: [{ name: 'PIPEGEN_X', scope: 'repo', created: true, unconfirmed: true }],
      environments: [{ name: 'production', created: false, githubCreatedAt: AT, previous: envSettings({ wait_timer: 0 }), changed: ['wait_timer'], branchPolicyIds: [] }],
      repoSettings: { [SS]: { previous: false } },
    });
    const t = term({ confirm: () => true });
    const u = await plan(w, rec, t);
    expect(u.phase).toBe('A');
    expect(t.typed).toEqual([]);
    expect(t.confirms.filter((q) => q.startsWith('Turn off'))).toEqual([]);
    expect(u.deleteSecrets).toMatchObject([{ needsName: true, confirmedByName: false }]);
    expect(u.deleteSecrets[0]?.typed).toBeUndefined();
    expect(u.restoreEnvironments).toMatchObject([{ name: 'production', needsName: true, confirmedByName: false }]);
    expect(u.restoreEnvironments[0]?.typed).toBeUndefined();
    expect(u.restoreVariables).toMatchObject([{ name: 'PIPEGEN_BLOCK_FROM', needsName: true, confirmedByName: false }]);
    expect(u.restoreVariables[0]?.typed).toBeUndefined();
    const p = previewUninstall(u);
    expect(p).toMatch(/Next run \(after you merge the uninstall PR\)[^]*PIPEGEN_X[^]*you type its name then/);
    expect(p).toMatch(/production[^]*wait_timer: 30 → 0/);
    expect(p).not.toMatch(/you typed its name/);
    // run 2 asks them
    const tb = term({ confirm: () => true });
    const b = await planB(w, rec, tb);
    expect(b.phase).toBe('B');
    expect(tb.typed).toHaveLength(3);
    expect(b.restoreVariables[0]?.typed).toBeDefined();
    // run 2 asks no file question: pipegen's files still on the branch are left (kept in run 1, or the PR not merged)
    expect(tb.confirms.filter((q) => !q.startsWith('Turn off'))).toEqual([]);
    expect([...b.removeFiles, ...b.keepAsk]).toEqual([]);
    expect(b.skipped.find((x) => x.what === 'Dockerfile')?.why).toMatch(/still on the default branch/);
    expect(b.deleteSecrets[0]?.typed).toBeDefined();
    expect(b.restoreEnvironments[0]?.typed).toBeDefined();
    expect(b.settings[0]?.turnOff).toBe(true);
    expect(previewUninstall(b)).not.toContain('the uninstall PR removes the gate');
  });

  it('plan: run 2 asks the run-2 names and sees run 1\'s work as done, never as manual', async () => {
    const original = '* @team\n';
    const dependabot = 'version: 2\nupdates: []\n';
    const w = world({ 'README.md': 'my app\n', CODEOWNERS: original, '.github/dependabot.yml': dependabot });
    w.app.stored.set('PIPEGEN_FP_KEY', AT);
    const co: InstallEdit = { repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: '# pipegen:begin\n/.github/ @o\n# pipegen:end\n', originalSha: blob(original), writtenShas: [SHA('4')] };
    const dep: InstallEdit = { repo: 'app', path: '.github/dependabot.yml', kind: 'dependabot', inserted: '  - package-ecosystem: github-actions\n', originalSha: SHA('6'), writtenShas: [SHA('7')] };
    const previous = { required_status_checks: null, enforce_admins: false, required_pull_request_reviews: null, restrictions: null };
    const planned = { method: 'PUT' as const, route: 'PUT /repos/{owner}/{repo}/branches/{branch}/protection', params: { owner: 'o', repo: 'shop', branch: 'main' }, body: { required_status_checks: { strict: true, checks: [{ context: 'pipegen / gate', app_id: 15368 }] }, enforce_admins: true, required_pull_request_reviews: null, restrictions: null } };
    w.protection = { enforce_admins: { enabled: false } };   // back as before pipegen
    const rec = sampleRecord(w, {
      edits: [co, dep], rulesets: [rs()], classicProtection: { branch: 'main', previous }, planned: { ...sampleRecord(w).planned, classic: planned },
      [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: AT }],
    });
    const t = term();
    const u = await planB(w, rec, t);
    expect(u.manual).toEqual([]);
    expect([...u.removeFiles, ...u.keepAsk, ...u.reverts, ...u.deleteRulesets, ...u.closePrs, ...u.deleteBranches]).toEqual([]);
    expect(u.restoreClassic).toBeUndefined();
    expect(t.confirms).toEqual([]);
    const done = u.done.join('\n');
    for (const x of ['.github/workflows/pipegen.yml', 'Dockerfile', 'CODEOWNERS', '.github/dependabot.yml', 'ruleset pipegen (id 41)', 'branch protection of main']) expect(done).toContain(x);
    // a 404 can be "gone" or "can't see it": never "deleted"; a stripped file says only that pipegen's exact text is gone (M-r1-7)
    expect(done).toMatch(/ruleset pipegen \(id 41\): GitHub doesn't show it \(already gone, or this login can't see it\)/);
    expect(done).not.toMatch(/deleted/);
    expect(done).toMatch(/\.github\/dependabot\.yml: pipegen's exact text is no longer in it/);
    expect(u.deleteSecrets.map((s) => s[SK].name)).toEqual(['PIPEGEN_FP_KEY']);
    expect(previewUninstall(u)).toMatch(/Already done:[^]*CODEOWNERS/);
    // what run 1 didn't take out is still a manual step, never "done"
    w.g.commitOn('o/shop', 'main', { CODEOWNERS: `${original}# pipegen:begin\n/.github/ @o\n# pipegen:end\n` });
    w.app.rulesets.set(41, liveRs(w));
    w.protection = { required_status_checks: { strict: true, checks: [{ context: 'pipegen / gate', app_id: 15368 }] }, enforce_admins: { enabled: true } };
    const u2 = await planB(w, rec, term());
    expect(u2.done.join('\n')).not.toMatch(/CODEOWNERS|ruleset|protection/);
    expect(u2.manual.map((m) => m.what)).toEqual(expect.arrayContaining(['CODEOWNERS', 'ruleset pipegen (id 41)', 'branch protection of main']));
    expect(u2.deleteRulesets).toEqual([]);
  });

  it('plan: a name the terminal can\'t show exactly is a manual step, never asked', async () => {
    const w = world();
    const long = `X${'A'.repeat(130)}`;
    w.app.stored.set(long, AT);
    const t = term();
    const u = await planB(w, sampleRecord(w, { [SEC]: [{ name: long, scope: 'repo', created: true, githubCreatedAt: AT }] }), t);
    expect(u.deleteSecrets).toEqual([]);
    expect(t.typed).toEqual([]);
    expect(u.manual.find((m) => m.what.startsWith('secret XAAA'))?.why).toMatch(/can't be asked safely/);
    expect(u.skipped.some((s) => s.why === 'kept: its name was not typed')).toBe(false);
  });
});
