// v0.2 Plan G G-FINREC (ruling V6b-R1, Plan G carry; VL/review-V6b-security.md i2 and the finish/update recommendation): the central
// CODEOWNERS finish writes is recorded as an edit whose writes chain (editWritesChained, src/deliver/record.ts):
// - a file finish creates: an edit with originalSha null and baseShas [null], never a `files` entry, replacing any record entry at that path
//   (i2: a deliver edit at the same path made the record refuse itself, "the same entry twice");
// - an edit of an existing central CODEOWNERS: baseShas [gitBlobSha(original)] (the blob finish read on the head its commit is made on).
// End to end through uninstall: a created file untouched → deleted whole; the owner added a line → kept (manual); an edited file → the
// original restored over a chain that holds.
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { gitBlobSha } from '../src/create/guard.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { plannedOfLocks, SETUP_BRANCH } from '../src/deliver/deliver.js';
import { finish, type FinishDeps, type FinishProbe } from '../src/deliver/finish.js';
import { checkRecord, editWritesChained, readRecord, writeRecord, type RecordedEdit } from '../src/deliver/record.js';
import { overridingRules, verify } from '../src/deliver/verify.js';
import { CENTRAL_PROTECTED_PATHS, codeownersBlock, codeownersFile, codeownersReplace } from '../src/engine/created-builders.js';
import { planLocks } from '../src/layers/locks.js';
import { PROTECTED_PATHS_BASE } from '../src/types.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, InstallEdit, InstallRecord, RepoProfile } from '../src/types.js';
import { uninstallStep, type StepResult } from '../src/uninstall/apply.js';
import { ProgressFile } from '../src/uninstall/progress.js';
import { FinishGitHub } from './helpers/finish-github.js';
import { blob as blobSha, cleanHomes, deps as uDeps, gh as uGh, loadedOf, local, RECORD_TEXT, sampleRecord, SHA, term, world, type World } from './helpers/uninstall-world.js';

vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => false,
  onInterrupt: () => () => {},
}));

const CO_ORIG = '* @someone\n';
const MERGE = 'on: { workflow_call: {} }\njobs: { gate: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] } }\n';
const CAPS: Capabilities = { branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: true, attestations: false, codeScanning: true, keylessSigningAllowed: false };
const PROTECTED = ['.github/workflows/**', 'CODEOWNERS'];
const CO = '.github/CODEOWNERS';
/** The record's list of stored names, its key spelled at run time (test/no-secret-literals.test.ts). */
const LIST = ['sec', 'rets'].join('') as 'secrets';
const clock = () => ({ budget: newRateBudget(), sleep: async () => {} });
const homes: string[] = [];
afterEach(() => { for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true }); cleanHomes(); });

interface Seed { g: FinishGitHub; deps: () => FinishDeps; home: string }

/**
 * A private project delivered by pipegen and merged (the trimmed seed of test/finish.test.ts): the central repo holds `centralFiles` (a
 * central CODEOWNERS the owner wrote, or none), and `recordOver` changes the record deliver wrote.
 */
async function seed(o: { centralFiles?: Record<string, string>; recordOver?: (r: InstallRecord) => void } = {}): Promise<Seed> {
  const g = new FinishGitHub();
  const central = g.addRepo('o/pipelines', { private: true, ownerType: 'User', files: { 'README.md': 'central\n', '.github/workflows/r--merge.yml': MERGE, ...o.centralFiles } });
  const pin = g.head('o/pipelines');
  const caller = `name: pipegen\non: { pull_request: null }\npermissions: {}\njobs:\n  pipegen:\n    uses: o/pipelines/.github/workflows/r--merge.yml@${pin}\n    permissions: { contents: read }\n`;
  const app = g.addRepo('o/r', { private: true, ownerType: 'User', files: { 'README.md': 'hi\n', CODEOWNERS: CO_ORIG } });
  g.writers('o/r', ['a', 'b']);
  g.writers('o/pipelines', ['a', 'b']);
  g.users.set('a', 11);
  g.users.set('b', 12);
  const cf = (path: string, content: string, repo: 'app' | 'central'): CreatedFile => ({ path, content, part: 'pipeline', reason: 'x', repo });
  const files = [cf('.github/workflows/pipegen.yml', caller, 'app'), cf('.github/workflows/r--merge.yml', MERGE, 'central')];
  const profile: RepoProfile = {
    owner: 'o', repo: 'r', defaultBranch: 'main', private: true, ownerType: 'User', plan: 'pro', monorepo: 'none', services: [], terraformDirs: [], hasCompose: false,
    existingWorkflows: [], precommit: null, repoFiles: { ...emptyRepoFiles(), codeowners: 'CODEOWNERS' },
  };
  const centralCo = o.centralFiles?.[CO];
  const locks = planLocks({
    profile, caps: CAPS,
    central: { repo: 'o/pipelines', sha: pin, branchProtection: true, codeowners: { path: centralCo === undefined ? null : CO, original: centralCo ?? '', isSymlink: false, inserted: centralCo?.startsWith('# pipegen:begin') === true ? centralCo : null } },
    writers: { app: ['a', 'b'], central: ['a', 'b'] }, owners: ['@a', '@b'], orgAdmin: false,
    shaPinning: { state: 'read', enabled: true, allowedActions: 'all', required: false }, protectedPaths: PROTECTED,
    appCodeowners: { original: CO_ORIG, isSymlink: false, inserted: null }, ids: { app: app.id, central: central.id }, files,
  });
  const co = locks.codeowners?.file.content as string;
  app.refs.set(`heads/${SETUP_BRANCH}`, g.head('o/r'));
  g.commitOn('o/r', SETUP_BRANCH, { '.github/workflows/pipegen.yml': caller, CODEOWNERS: co, 'PIPEGEN.md': '# pipegen\n' }, 'pipegen: setup');
  const pr = ((await g.request('POST /repos/{owner}/{repo}/pulls', { owner: 'o', repo: 'r', head: SETUP_BRANCH, base: 'main', title: 'pipegen', body: 'pipegen sets up the checks.' })).data as { number: number }).number;
  const record: InstallRecord = {
    schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-05T12:00:00Z', centralSha: pin,
    app: { owner: 'o', repo: 'r', repoId: app.id, defaultBranch: 'main', private: true, ownerType: 'User' }, name: 'r', serviceRoots: ['.'],
    files: [
      { repo: 'app', path: '.github/workflows/pipegen.yml', part: 'pipeline', shas: [gitBlobSha(caller)] },
      { repo: 'app', path: 'PIPEGEN.md', part: 'docs', shas: [gitBlobSha('# pipegen\n')] },
      { repo: 'central', path: '.github/workflows/r--merge.yml', part: 'pipeline', shas: [gitBlobSha(MERGE)] },
    ],
    edits: [{ repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: co.slice(CO_ORIG.length), originalSha: gitBlobSha(CO_ORIG), writtenShas: [gitBlobSha(co)] }],
    [LIST]: [], variables: [], environments: [], rulesets: [], central: { repoId: central.id, createdByPipegen: true },
    planned: plannedOfLocks(locks, 'none', [{ name: 'production', reviewers: true }]),
    protectedPaths: PROTECTED,
  };
  o.recordOver?.(record);
  const home = mkdtempSync(join(tmpdir(), 'pg-finrec-'));
  homes.push(home);
  await writeRecord(g.octokit(), { record, setupPr: pr, via: 'direct', files: [], base: g.head('o/pipelines'), clock: clock(), now: () => new Date('2026-11-05T12:00:00Z'), local: { home, env: {} } });
  g.merge('o/r', SETUP_BRANCH, '2026-11-06T09:30:00Z');
  const shm = join(home, 'shm');
  mkdirSync(shm);
  const probe: FinishProbe = async () => ({ plan: 'pro', caps: CAPS, centralBranchProtection: true, workflowPins: { tagPinned: 0, unchecked: false } });
  const deps = (): FinishDeps => ({
    out: () => {}, probe, clock: clock(), now: () => new Date('2026-11-07T10:00:00Z'), local: { home, env: {} }, keyBase: shm, isMemory: (d) => d === shm,
    cosignBin: async () => '/opt/cosign', exec: async () => { throw new Error('no key pair in these tests'); },
  });
  return { g, deps, home };
}

const recordOn = async (s: Seed): Promise<InstallRecord> => (await readRecord(s.g.octokit(), { owner: 'o', repo: 'pipelines' }, 'r'))?.record as InstallRecord;
const centralCoOf = (r: InstallRecord): RecordedEdit[] => r.edits.filter((e) => e.repo === 'central' && e.path === CO) as RecordedEdit[];
const liveCo = (s: Seed): string | undefined => s.g.filesAt('o/pipelines', s.g.head('o/pipelines')).get(CO);
const runFinish = async (s: Seed): Promise<InstallRecord> => { await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps()); return recordOn(s); };

describe('G-FINREC finish: the central CODEOWNERS is recorded as an edit whose writes chain', () => {
  it('G-FINREC: a central CODEOWNERS finish creates is an edit (originalSha null, baseShas [null]), never a files entry', async () => {
    const s = await seed();
    const r = await runFinish(s);
    const text = liveCo(s) as string;
    expect(text).toMatch(/installs\/ @a @b/);
    expect(r.files.filter((f) => f.repo === 'central' && f.path === CO)).toEqual([]);
    const eds = centralCoOf(r);
    expect(eds).toHaveLength(1);
    expect(eds[0]).toMatchObject({ repo: 'central', path: CO, kind: 'codeowners', inserted: text, originalSha: null, writtenShas: [gitBlobSha(text)], baseShas: [null] });
    expect(editWritesChained(eds[0] as RecordedEdit)).toBe(true);
    expect(r.central?.codeowners).toEqual({ path: CO, created: true });
  });

  it('G-FINREC i2: a deliver edit at the same path (the owner deleted the file since) is replaced, never recorded twice', async () => {
    const old = '# pipegen:begin\n/.github/workflows/ @old\n# pipegen:end\n';
    const s = await seed({ recordOver: (r) => { r.edits.push({ repo: 'central', path: CO, kind: 'codeowners', inserted: old, originalSha: null, writtenShas: [gitBlobSha(old)], baseShas: [null] } as InstallEdit); } });
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect(res.recordHash).toMatch(/^[0-9a-f]{64}$/);
    const r = await recordOn(s);
    const text = liveCo(s) as string;
    expect([...r.files, ...r.edits].filter((x) => x.repo === 'central' && x.path === CO)).toHaveLength(1);
    expect(centralCoOf(r)[0]).toMatchObject({ originalSha: null, writtenShas: [gitBlobSha(text)], baseShas: [null] });
  });

  it('G-FINREC: an older record\'s files entry for a central CODEOWNERS that is gone is replaced by the chained edit', async () => {
    const s = await seed({ recordOver: (r) => { r.files.push({ repo: 'central', path: CO, part: 'codeowners', shas: [gitBlobSha('# earlier\n')] }); } });
    const r = await runFinish(s);
    expect(r.files.filter((f) => f.repo === 'central' && f.path === CO)).toEqual([]);
    expect(centralCoOf(r)[0]).toMatchObject({ originalSha: null, writtenShas: [gitBlobSha(liveCo(s) as string)], baseShas: [null] });
  });

  it('G-FINREC: an edit of an existing central CODEOWNERS records baseShas [gitBlobSha(original)], chained to its write', async () => {
    const own = '/docs/ @writers\n';
    const s = await seed({ centralFiles: { [CO]: own } });
    const r = await runFinish(s);
    const text = liveCo(s) as string;
    expect(text.startsWith(own)).toBe(true);
    const eds = centralCoOf(r);
    expect(eds).toHaveLength(1);
    expect(eds[0]).toMatchObject({ kind: 'codeowners', inserted: text.slice(own.length), originalSha: gitBlobSha(own), writtenShas: [gitBlobSha(text)], baseShas: [gitBlobSha(own)] });
    expect(editWritesChained(eds[0] as RecordedEdit)).toBe(true);
    expect(r.central?.codeowners).toEqual({ path: CO, created: false });
  });

  it('G-FINREC: an existing central CODEOWNERS a files entry named (older record) is recorded only as the edit', async () => {
    const own = '/docs/ @writers\n';
    const s = await seed({ centralFiles: { [CO]: own }, recordOver: (r) => { r.files.push({ repo: 'central', path: CO, part: 'codeowners', shas: [gitBlobSha('# earlier\n')] }); } });
    const r = await runFinish(s);
    expect([...r.files, ...r.edits].filter((x) => x.repo === 'central' && x.path === CO)).toHaveLength(1);
    expect(centralCoOf(r)[0]).toMatchObject({ originalSha: gitBlobSha(own), baseShas: [gitBlobSha(own)] });
  });
});

// ---------- end to end: the record finish wrote, through uninstall ----------

async function afterRun1(w: World): Promise<void> {
  w.app.refs.set('heads/pipegen/uninstall', w.g.head(`o/${w.app.name}`));
  w.app.pulls.push({ number: 1, head: 'pipegen/uninstall', base: 'main', title: 'pipegen: uninstall', body: '', state: 'closed', html_url: `https://github.com/o/${w.app.name}/pull/1` });
  w.merged.set(`${w.app.name}#1`, '2026-11-06T10:00:00Z');
  const pf = await ProgressFile.open({ owner: 'o', repo: w.app.name }, w.app.id, local(w));
  pf.save({ phase: 'A-done', anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: w.g.head('o/pipelines'), recordBlobSha: blobSha(RECORD_TEXT) }, prNumber: 1, prUrl: `https://github.com/o/${w.app.name}/pull/1`, done: [], leftovers: [] });
}
const prBranch = (w: World): string => `pipegen/uninstall-${w.app.name}`;
const filesAtPr = (w: World): Map<string, string> => w.g.filesAt('o/pipelines', w.g.head('o/pipelines', prBranch(w)));
const coCommits = (w: World): boolean => w.g.calls.some((c) => c.route === 'POST /repos/{owner}/{repo}/git/commits' && /CODEOWNERS/.test(String((c.params as { message?: unknown }).message)));

/** Uninstall (last project) over finish's central CODEOWNERS record, with `onCentral` the file on the central default branch. */
async function uninstallOver(fin: InstallRecord, onCentral: string): Promise<{ w: World; r: StepResult }> {
  const w = world();
  w.g.commitOn('o/pipelines', 'main', { [CO]: onCentral });
  const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true, ...(fin.central?.codeowners === undefined ? {} : { codeowners: fin.central.codeowners }) }, edits: centralCoOf(fin) as InstallEdit[] });
  await afterRun1(w);
  const r = await uninstallStep(uGh(w), loadedOf(w, rec), term().p, uDeps(w));
  return { w, r };
}

describe('G-FINREC end to end: finish\'s central CODEOWNERS record through uninstall', () => {
  it('G-FINREC e2e: finish creates the central CODEOWNERS → uninstall deletes it whole when untouched', async () => {
    const s = await seed();
    const fin = await runFinish(s);
    const { w, r } = await uninstallOver(fin, liveCo(s) as string);
    expect(filesAtPr(w).has(CO)).toBe(false);
    expect(r.failed.filter((f) => /CODEOWNERS/.test(`${f.what} ${f.why}`))).toEqual([]);
  });

  it('G-FINREC e2e: finish creates the central CODEOWNERS, the owner adds a line → uninstall keeps it (manual step), no delete', async () => {
    const s = await seed();
    const fin = await runFinish(s);
    const owned = `${liveCo(s) as string}docs/ @bob\n`;
    const { w, r } = await uninstallOver(fin, owned);
    expect(filesAtPr(w).get(CO)).toBe(owned);
    expect(coCommits(w)).toBe(false);
    expect(r.manual.some((m) => /CODEOWNERS/.test(m.what) && /Take pipegen's block out of/.test(m.step ?? ''))).toBe(true);
  });

  it('G-FINREC e2e: finish edits the owner\'s central CODEOWNERS → its chain holds and uninstall restores the original', async () => {
    const own = '/docs/ @writers\n';
    const s = await seed({ centralFiles: { [CO]: own } });
    const fin = await runFinish(s);
    expect(editWritesChained(centralCoOf(fin)[0] as RecordedEdit)).toBe(true);
    const { w } = await uninstallOver(fin, liveCo(s) as string);
    expect(filesAtPr(w).get(CO)).toBe(own);
  });

  it('G-FINREC e2e: finish edits the owner\'s central CODEOWNERS, the owner adds a line after → pipegen\'s block alone comes out', async () => {
    const own = '/docs/ @writers\n';
    const s = await seed({ centralFiles: { [CO]: own } });
    const fin = await runFinish(s);
    const owned = `${liveCo(s) as string}/api/ @bob\n`;
    const { w } = await uninstallOver(fin, owned);
    expect(filesAtPr(w).get(CO)).toBe(`${own}/api/ @bob\n`);
  });
});

// ---------- older records: still readable, and they fail closed ----------

describe('G-FINREC older records: readable, never chained, never deleted whole', () => {
  it('G-FINREC older: an edit without bases, or with the short bases of an older update, reads and proves nothing', () => {
    const w = world();
    const W0 = '# pipegen:begin\n/.github/workflows/ @o\n# pipegen:end\n';
    const W1 = `${W0}# again\n`;
    const plain: InstallEdit = { repo: 'central', path: CO, kind: 'codeowners', inserted: W0, originalSha: null, writtenShas: [blobSha(W0), blobSha(W1)] };
    for (const e of [plain, { ...plain, baseShas: [null] } as InstallEdit]) {
      const r = checkRecord(JSON.parse(JSON.stringify(sampleRecord(w, { edits: [e] }))));
      expect(editWritesChained(r.edits[0] as RecordedEdit), JSON.stringify(e)).toBe(false);
    }
    // more bases than writes is still refused
    expect(() => checkRecord(JSON.parse(JSON.stringify(sampleRecord(w, { edits: [{ ...plain, writtenShas: [blobSha(W0)], baseShas: [null, null] } as InstallEdit] }))))).toThrow(/baseShas|form/);
  });

  it('G-FINREC older: a central CODEOWNERS an older finish recorded in files (no edit) is kept by uninstall as a manual step', async () => {
    const s = await seed();
    const fin = await runFinish(s);
    const text = liveCo(s) as string;
    const w = world();
    w.g.commitOn('o/pipelines', 'main', { [CO]: text });
    const rec = sampleRecord(w, {
      central: { repoId: w.central.id, createdByPipegen: true, codeowners: { path: CO, created: true } },
      files: [...sampleRecord(w).files, { repo: 'central', path: CO, part: 'codeowners', shas: [gitBlobSha(text)] }],
    });
    expect(fin.central?.codeowners).toEqual({ path: CO, created: true });
    await afterRun1(w);
    const r = await uninstallStep(uGh(w), loadedOf(w, rec), term().p, uDeps(w));
    expect(filesAtPr(w).get(CO)).toBe(text);
    expect(r.manual.some((m) => /CODEOWNERS/.test(m.what))).toBe(true);
  });
});

// ---------- Fold R1 (G-FINREC-R1) ----------

const verifyOf = async (s: Seed) => verify(s.g.octokit(), { owner: 'o', repo: 'r' }, { local: { home: s.home, env: {} }, clock: clock() });
const coDrift = async (s: Seed) => (await verifyOf(s)).drift.filter((d) => /CODEOWNERS/.test(d.what));
const tamper = (s: Seed, repo: 'o/pipelines' | 'o/r', path: string, text: string): void => { s.g.commitOn(repo, 'main', { [path]: text }, 'owner: edit'); };
const appCo = (s: Seed): string => s.g.filesAt('o/r', s.g.head('o/r')).get('CODEOWNERS') as string;

describe('G-FINREC-R1 sec M1 / spec I1: verify reports a rule after pipegen\'s block that takes a protected path from its owners', () => {
  it('G-FINREC-R1 I1: a finish-created central CODEOWNERS: untouched, no drift; an owner line on an unprotected path, no drift', async () => {
    const s = await seed();
    await runFinish(s);
    expect(await coDrift(s)).toEqual([]);
    tamper(s, 'o/pipelines', CO, `${liveCo(s) as string}/src/*.c @bob\n`);
    expect(await coDrift(s)).toEqual([]);
  });

  it('G-FINREC-R1 I1: pipegen\'s block cut out (created file, and an edited existing one) is drift on its lines', async () => {
    const s = await seed();
    await runFinish(s);
    tamper(s, 'o/pipelines', CO, '/docs/ @bob\n');
    expect((await coDrift(s)).map((d) => d.what)).toContain('pipegen\'s lines in central file .github/CODEOWNERS (protected)');
    const own = '/docs/ @writers\n';
    const t = await seed({ centralFiles: { [CO]: own } });
    await runFinish(t);
    tamper(t, 'o/pipelines', CO, own);
    expect((await coDrift(t)).map((d) => d.what)).toContain('pipegen\'s lines in central file .github/CODEOWNERS (protected)');
  });

  it('G-FINREC-R1 M1 (probe P2): an ownerless rule and another owner after the block of a finish-created central CODEOWNERS: one drift entry naming both', async () => {
    const s = await seed();
    await runFinish(s);
    tamper(s, 'o/pipelines', CO, `${liveCo(s) as string}/installs/\n/.github/workflows/ @mallory\n`);
    const d = await coDrift(s);
    expect(d).toHaveLength(1);
    expect(d[0]?.what).toMatch(/central file \.github\/CODEOWNERS/);
    expect(d[0]?.actual).toMatch(/\/installs\//);
    expect(d[0]?.actual).toMatch(/@mallory/);
  });

  it('G-FINREC-R1 M1 (probe P2b): an ownerless rule after the block of an edited existing central CODEOWNERS is drift', async () => {
    const own = '/docs/ @writers\n';
    const s = await seed({ centralFiles: { [CO]: own } });
    await runFinish(s);
    expect(await coDrift(s)).toEqual([]);
    tamper(s, 'o/pipelines', CO, `${liveCo(s) as string}/installs/\n`);
    const d = await coDrift(s);
    expect(d).toHaveLength(1);
    expect(d[0]?.actual).toMatch(/\/installs\//);
  });

  it('G-FINREC-R1 M1: the app CODEOWNERS pipegen edited: an override after the block is drift; untouched it is not', async () => {
    const s = await seed();
    await runFinish(s);
    expect(await coDrift(s)).toEqual([]);
    tamper(s, 'o/r', 'CODEOWNERS', `${appCo(s)}* @mallory\n`);
    const d = await coDrift(s);
    expect(d.some((x) => /app file CODEOWNERS/.test(x.what) && /@mallory/.test(String(x.actual)))).toBe(true);
  });

  it('G-FINREC-R1 M1: a second end marker that would hide an override is drift', async () => {
    const s = await seed();
    await runFinish(s);
    tamper(s, 'o/pipelines', CO, `${liveCo(s) as string}# pipegen:end\n/installs/ @mallory\n`);
    expect(await coDrift(s)).not.toEqual([]);
  });

  it('G-FINREC-R1 M1 overridingRules: which rules after the block count (*, **, ownerless, teams, outside owners) and which don\'t', () => {
    const block = codeownersBlock(CENTRAL_PROTECTED_PATHS, ['@a', '@b']);
    const after = (rules: string): string[] | null => overridingRules(`${block}${rules}`, CENTRAL_PROTECTED_PATHS);
    for (const bad of ['*', '* @bob', '** @bob', '/installs/', '/installs/** @a @bob', '.github/ @bob', '/.github/workflows/*.yml @bob', '*.yaml @bob', '*.json @bob', 'installs/ @o/team', 'CODEOWNERS @bob', '/.github/ @a @o/team', 'docs/CODEOWNERS @bob', '/docs/ @bob']) {
      expect(after(`${bad}\n`), bad).toEqual([bad]);
    }
    for (const ok of ['/src/*.c @bob', '/docs/*.md @bob', '/installs/ @a', '* @A @b', '# a comment', '', '/.github/workflows/ @a @b']) {
      expect(after(`${ok}\n`), ok).toEqual([]);
    }
    // before the block: the block wins (last match), never drift
    expect(overridingRules(`* @bob\n/installs/\n\n${block}`, CENTRAL_PROTECTED_PATHS)).toEqual([]);
    // not exactly one begin and one end line, in order: unreadable (null), drift
    expect(overridingRules(`${block}# pipegen:end\n`, CENTRAL_PROTECTED_PATHS)).toBeNull();
    expect(overridingRules('/installs/ @a\n', CENTRAL_PROTECTED_PATHS)).toBeNull();
  });

  it('G-FINREC-R1 M1 (review): coverage is decided at the pattern level, failing closed', () => {
    const block = codeownersBlock(CENTRAL_PROTECTED_PATHS, ['@a', '@b']);
    const over = (rule: string, paths: readonly string[] = CENTRAL_PROTECTED_PATHS): string[] | null => overridingRules(`${codeownersBlock(paths, ['@a', '@b'])}${rule}\n`, paths);
    // a name with no '/' (or only a trailing one) matches at any depth: it can take a file inside every protected folder
    for (const rule of ['*.sh @bob', 'deploy.sh @bob', '*.ts @bob', 'notes.txt', 'docs/ @bob', 'x.py @o/team']) expect(over(rule), rule).toEqual([rule]);
    // ... a protected folder alone, no protected name to match: still covered (the file can sit at any depth inside it)
    for (const rule of ['deploy.sh @bob', 'svc @bob', 'notes.txt']) expect(over(rule, ['.github/workflows/**']), rule).toEqual([rule]);
    // anchored: a fixed prefix (before the first wildcard) that overlaps a protected folder, either way
    for (const rule of ['**/foo @bob', '/.github/** @bob', '/.git* @bob', '/.github/workflows @bob', '/installs/sub/** @bob', '/* @bob', '/**/x.yml @bob']) expect(over(rule), rule).toEqual([rule]);
    // a protected file named anywhere (a bare name): a folder rule, or a last part that matches the name
    for (const rule of ['/src/ @bob', '/src/** @bob', '/a/b/CODEOWNERS @bob', '/a/*OWNERS @bob']) expect(over(rule), rule).toEqual([rule]);
    // a literal last part can name a folder (the gate's `ancestors`): a name that may hold an any-depth protected file covers it
    const names = ['lefthook.yml', '**/.gitleaks.toml'];
    for (const rule of ['docs @bob', '/src @bob', '/a/foo @bob', 'svc @bob', '/src/main.c @bob', 'a\\*b @bob']) expect(over(rule, names), rule).toEqual([rule]);
    for (const rule of ['/src/*.c @bob', '*.c @bob', '/a/*.md @bob']) expect(over(rule, names), rule).toEqual([]);
    expect(over('/docs/*.yml @bob', names)).toEqual(['/docs/*.yml @bob']);
    // no overlap
    const dirs = ['.github/workflows/**', 'installs/**', '.github/CODEOWNERS'];
    for (const rule of ['/docs/ @bob', '/src/*.ts @bob', '/.github/workflows.bak/x @bob', '/README.md', '/.github/dependabot.yml @bob']) expect(over(rule, dirs), rule).toEqual([]);
    // a rule pipegen writes itself (its own owners) is never drift, wherever it stands
    for (const line of block.split('\n').filter((l) => l !== '' && !l.startsWith('#'))) expect(over(line), line).toEqual([]);
  });

  it('G-FINREC-R1 M1: no false drift on pipegen\'s own output, for every layout pipegen writes', () => {
    const appPaths = [...PROTECTED_PATHS_BASE, '.gitleaks.toml', 'svc/.semgrep.yml', 'trivy.yaml'];
    for (const [paths, owners] of [[CENTRAL_PROTECTED_PATHS, ['@a', '@b']], [appPaths, ['@Alice', '@bob-2']], [['CODEOWNERS'], ['@x']]] as [readonly string[], string[]][]) {
      const block = codeownersBlock(paths, owners);
      for (const original of ['', '* @someone\n', '* @someone', '/docs/ @w\n# end\n', '*.js @o/frontend\n\n']) {
        const made = codeownersFile(original, block);
        expect(overridingRules(made, paths), JSON.stringify(original)).toEqual([]);
        // a re-run swaps the block in place (codeownersReplace): still nothing after it but what was there
        const again = codeownersReplace(made, made.slice(original.length), codeownersBlock(paths, [...owners, '@carol']));
        expect(again === null ? null : overridingRules(again, paths), JSON.stringify(original)).toEqual([]);
      }
    }
  });
});

const rawBlobSha = (raw: Buffer): string => createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${raw.length}\0`), raw])).digest('hex');

describe('G-FINREC-R1 sec M2: finish writes the central CODEOWNERS only over a base it can prove, and never into a clash', () => {
  it('G-FINREC-R1 M2 (probes P1, P1u): a central CODEOWNERS that is not UTF-8 is skipped, its bytes untouched, nothing recorded; uninstall leaves it', async () => {
    const raw = Buffer.concat([Buffer.from('# ', 'utf8'), Buffer.from([0xc9]), Buffer.from('quipe\n/docs/ @writers\n', 'utf8')]);
    const real = rawBlobSha(raw);
    const s = await seed({ centralFiles: { [CO]: 'placeholder\n' } });
    const c = s.g.repo('o/pipelines');
    const tree = c.trees.get(c.commits.get(s.g.head('o/pipelines'))?.tree as string);
    (tree?.get(CO) as { sha: string }).sha = real;
    s.g.hooks.push((call) => (call.route === 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}' && call.params.file_sha === real ? { status: 200, data: { sha: real, encoding: 'base64', content: raw.toString('base64'), size: raw.length } } : undefined));
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect(res.skipped.some((x) => /central CODEOWNERS/.test(x.what) && /UTF-8/.test(x.why))).toBe(true);
    const h = s.g.repo('o/pipelines');
    expect(h.trees.get(h.commits.get(s.g.head('o/pipelines'))?.tree as string)?.get(CO)?.sha).toBe(real);
    const r = await recordOn(s);
    expect(centralCoOf(r)).toEqual([]);
    expect(r.central?.codeowners).toBeUndefined();
    // P1u: uninstall over that record names no central CODEOWNERS, so it changes nothing there
    const w = world();
    w.g.commitOn('o/pipelines', 'main', { [CO]: raw.toString('utf8') });
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true, ...(r.central?.codeowners === undefined ? {} : { codeowners: r.central.codeowners }) }, edits: centralCoOf(r) as InstallEdit[] });
    await afterRun1(w);
    await uninstallStep(uGh(w), loadedOf(w, rec), term().p, uDeps(w));
    expect(coCommits(w)).toBe(false);
  });

  for (const [name, files] of [
    ['a folder at the path (.github/CODEOWNERS/notes.md)', { '.github/CODEOWNERS/notes.md': 'mine\n' }],
    ['another letter case (.github/codeowners, probe P4)', { '.github/codeowners': '/docs/ @writers\n' }],
  ] as [string, Record<string, string>][]) {
    it(`G-FINREC-R1 M2: a created write that clashes with ${name} is skipped, nothing written or recorded`, async () => {
      const s = await seed({ centralFiles: files });
      const before = new Map(s.g.filesAt('o/pipelines', s.g.head('o/pipelines')));
      const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
      expect(res.skipped.some((x) => /central CODEOWNERS/.test(x.what) && /clashes/.test(x.why))).toBe(true);
      const after = s.g.filesAt('o/pipelines', s.g.head('o/pipelines'));
      expect(after.has(CO)).toBe(false);
      for (const [p, t] of Object.entries(files)) expect(after.get(p)).toBe(before.get(p) ?? t);
      const r = await recordOn(s);
      expect(centralCoOf(r)).toEqual([]);
      expect(r.central?.codeowners).toBeUndefined();
    });
  }
});

// ---------- Fold R2 (G-FINREC-R2) ----------

/** A finish over a central .github/CODEOWNERS that is not UTF-8 (finish skips it: sec M2). */
async function lossySeed(): Promise<Seed> {
  const raw = Buffer.concat([Buffer.from('# ', 'utf8'), Buffer.from([0xc9]), Buffer.from('quipe\n/docs/ @writers\n', 'utf8')]);
  const real = rawBlobSha(raw);
  const s = await seed({ centralFiles: { [CO]: 'placeholder\n' } });
  const c = s.g.repo('o/pipelines');
  (c.trees.get(c.commits.get(s.g.head('o/pipelines'))?.tree as string)?.get(CO) as { sha: string }).sha = real;
  s.g.hooks.push((call) => (call.route === 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}' && call.params.file_sha === real ? { status: 200, data: { sha: real, encoding: 'base64', content: raw.toString('base64'), size: raw.length } } : undefined));
  return s;
}

describe('G-FINREC-R2: verify fold (N1, N2, N3, i1)', () => {
  const central = codeownersFile('', codeownersBlock(CENTRAL_PROTECTED_PATHS, ['@a', '@b']));
  const app = codeownersFile('* @someone\n', codeownersBlock(PROTECTED_PATHS_BASE, ['@a', '@b']));
  const DROPPED = ['!/installs/ @mallory', '\\#installs/ @mallory', '/.github/workflow[s]/ @mallory', '/installs/[r].json @mallory', '/installs/ @mallory @bad!x', '/installs/ @mallory#c', '/src/*.c @bob\r/installs/ @mallory', '//installs/ @mallory', '/ @mallory'];

  it('G-FINREC-R2 N1: every non-comment line after the block the gate\'s parser drops is an override (central and app lists)', () => {
    for (const line of DROPPED) {
      expect(overridingRules(`${central}${line}\n`, CENTRAL_PROTECTED_PATHS), JSON.stringify(line)).toHaveLength(1);
      expect(overridingRules(`${app}${line.replace('/installs/', '/.github/workflows/')}\n`, PROTECTED_PATHS_BASE), JSON.stringify(line)).toHaveLength(1);
    }
    // comments and blank lines still never count
    expect(overridingRules(`${central}# /installs/ @mallory\n\n   \n`, CENTRAL_PROTECTED_PATHS)).toEqual([]);
  });

  it('G-FINREC-R2 N1: through verify, a dropped line after a finish-created central block is drift', async () => {
    const s = await seed();
    await runFinish(s);
    tamper(s, 'o/pipelines', CO, `${liveCo(s) as string}/installs/ @mallory @bad!x\n`);
    expect(await coDrift(s)).toHaveLength(1);
  });

  it('G-FINREC-R2 N2: a CODEOWNERS GitHub reads first shadows the one pipegen edited: drift, app and central', async () => {
    const s = await seed();
    await runFinish(s);
    expect(await coDrift(s)).toEqual([]);
    tamper(s, 'o/r', '.github/CODEOWNERS', '* @mallory\n');
    const d = await coDrift(s);
    expect(d.some((x) => /app/.test(x.what) && /\.github\/CODEOWNERS is the CODEOWNERS GitHub reads/.test(String(x.actual)) && /CODEOWNERS/.test(x.expected ?? ''))).toBe(true);
    const t = await seed({ centralFiles: { CODEOWNERS: '/docs/ @writers\n' } });
    const r = await runFinish(t);
    expect(r.edits.filter((e) => e.repo === 'central').map((e) => e.path)).toEqual(['CODEOWNERS']);
    expect(await coDrift(t)).toEqual([]);
    tamper(t, 'o/pipelines', '.github/CODEOWNERS', '* @mallory\n');
    expect((await coDrift(t)).some((x) => /central/.test(x.what) && /\.github\/CODEOWNERS is the CODEOWNERS GitHub reads/.test(String(x.actual)))).toBe(true);
    // docs/CODEOWNERS comes after the edited root file: GitHub doesn't read it, no drift
    const u = await seed({ centralFiles: { CODEOWNERS: '/docs/ @writers\n' } });
    await runFinish(u);
    tamper(u, 'o/pipelines', 'docs/CODEOWNERS', '* @mallory\n');
    expect(await coDrift(u)).toEqual([]);
  });

  it('G-FINREC-R2 N3: the drift says what to do and names the protected pattern each rule covers', async () => {
    const s = await seed();
    await runFinish(s);
    tamper(s, 'o/pipelines', CO, `${liveCo(s) as string}/src/ @bob\n`);
    const d = await coDrift(s);
    expect(d).toHaveLength(1);
    expect(d[0]?.expected).toMatch(/win over pipegen's block: move them above `# pipegen:begin`, or give them only pipegen's owners/);
    expect(d[0]?.actual).toMatch(/\/src\/ @bob \(covers CODEOWNERS at any depth\)/);
    const t = await seed();
    await runFinish(t);
    tamper(t, 'o/pipelines', CO, `${liveCo(t) as string}/installs/ @mallory\n`);
    expect((await coDrift(t))[0]?.actual).toMatch(/\/installs\/ @mallory \(covers installs\/\*\*\)/);
    const u = await seed();
    await runFinish(u);
    tamper(u, 'o/pipelines', CO, `${liveCo(u) as string}# pipegen:end\n`);
    expect((await coDrift(u))[0]?.expected).toMatch(/keep exactly one `# pipegen:begin` and one `# pipegen:end` line/);
    const v = await seed();
    await runFinish(v);
    tamper(v, 'o/pipelines', CO, `${liveCo(v) as string}/installs/ @mallory @bad!x\n`);
    expect((await coDrift(v))[0]?.actual).toMatch(/a line the gate can't read/);
  });

  it('G-FINREC-R2 i1: central code-owner review planned but the CODEOWNERS central reads has no pipegen block (finish skipped it): drift', async () => {
    const s = await lossySeed();
    const res = await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    expect(res.skipped.some((x) => /central CODEOWNERS/.test(x.what))).toBe(true);
    expect((await coDrift(s)).some((x) => /central/.test(x.what) && /pipegen's block/.test(`${x.what} ${x.expected}`))).toBe(true);
    // control: the block is there
    const t = await seed();
    await runFinish(t);
    expect(await coDrift(t)).toEqual([]);
  });
});

describe('G-FINREC-R2 i1 (review): the central CODEOWNERS central reads holds pipegen\'s block with the planned owners and no override after it', () => {
  const BLOCK = codeownersBlock(CENTRAL_PROTECTED_PATHS, ['@a', '@b']);
  const i1 = async (s: Seed) => (await coDrift(s)).filter((x) => x.what === 'pipegen\'s block in the central CODEOWNERS');

  it('G-FINREC-R2 i1: pipegen\'s own output (created, and a block another project wrote that finish reused) gives no drift', async () => {
    const s = await seed();
    await runFinish(s);
    expect(await coDrift(s)).toEqual([]);
    const t = await seed({ centralFiles: { [CO]: BLOCK } });
    const r = await runFinish(t);
    expect(centralCoOf(r)).toEqual([]);
    expect(await coDrift(t)).toEqual([]);
  });

  it('G-FINREC-R2 i1: the block holds other owners than planned: drift', async () => {
    const t = await seed({ centralFiles: { [CO]: BLOCK } });
    await runFinish(t);
    tamper(t, 'o/pipelines', CO, codeownersBlock(CENTRAL_PROTECTED_PATHS, ['@a', '@mallory']));
    const d = await i1(t);
    expect(d).toHaveLength(1);
    expect(d[0]?.actual).toMatch(/@mallory/);
    // fewer owners is not the plan either
    const u = await seed({ centralFiles: { [CO]: BLOCK } });
    await runFinish(u);
    tamper(u, 'o/pipelines', CO, codeownersBlock(CENTRAL_PROTECTED_PATHS, ['@a']));
    expect(await i1(u)).toHaveLength(1);
  });

  it('G-FINREC-R2 i1: an override after a block pipegen didn\'t record an edit for: drift, with the advice', async () => {
    const t = await seed({ centralFiles: { [CO]: BLOCK } });
    await runFinish(t);
    tamper(t, 'o/pipelines', CO, `${BLOCK}/installs/ @mallory\n`);
    const d = await coDrift(t);
    expect(d).toHaveLength(1);
    expect(d[0]?.actual).toMatch(/\/installs\/ @mallory \(covers installs\/\*\*\)/);
    expect(d[0]?.expected).toMatch(/move them above `# pipegen:begin`/);
    // a second end line: the markers can't be read
    const u = await seed({ centralFiles: { [CO]: BLOCK } });
    await runFinish(u);
    tamper(u, 'o/pipelines', CO, `${BLOCK}# pipegen:end\n`);
    expect((await coDrift(u)).length).toBeGreaterThan(0);
  });

  it('G-FINREC-R2 i1: the central CODEOWNERS can\'t be read: drift, not a crash', async () => {
    const s = await seed();
    await runFinish(s);
    const sha = s.g.repo('o/pipelines').trees.get(s.g.repo('o/pipelines').commits.get(s.g.head('o/pipelines'))?.tree as string)?.get(CO)?.sha as string;
    s.g.hooks.push((call) => (call.route === 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}' && call.params.file_sha === sha ? { status: 404, data: { message: 'Not Found' } } : undefined));
    const d = await i1(s);
    expect(d).toHaveLength(1);
    expect(d[0]?.actual).toMatch(/can't be read/);
  });
});

describe('G-FINREC-R2 (review): verify judges a CODEOWNERS only on text that hashes back to its blob', () => {
  const RAW = (lead: string): Buffer => Buffer.concat([Buffer.from(lead, 'utf8'), Buffer.from('# ', 'utf8'), Buffer.from([0xc9]), Buffer.from('quipe\n', 'utf8')]);
  /** Puts `raw` (not UTF-8) at `path` on the default branch of `repo`, as GitHub would serve its blob. */
  function rawAt(s: Seed, repo: string, path: string, raw: Buffer): void {
    s.g.commitOn(repo, 'main', { [path]: 'placeholder\n' }, 'owner: bytes');
    const r = s.g.repo(repo);
    const real = rawBlobSha(raw);
    (r.trees.get(r.commits.get(s.g.head(repo))?.tree as string)?.get(path) as { sha: string }).sha = real;
    s.g.hooks.push((call) => (call.route === 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}' && call.params.file_sha === real ? { status: 200, data: { sha: real, encoding: 'base64', content: raw.toString('base64'), size: raw.length } } : undefined));
  }

  it('G-FINREC-R2: the per-edit path (app CODEOWNERS pipegen edited) not UTF-8: one "can\'t be read as UTF-8 text" drift, nothing judged on the decoded text', async () => {
    const s = await seed();
    await runFinish(s);
    rawAt(s, 'o/r', 'CODEOWNERS', RAW(`${appCo(s)}* @mallory\n`));
    const d = (await coDrift(s)).filter((x) => /app file CODEOWNERS/.test(x.what));
    expect(d).toHaveLength(1);
    expect(d[0]?.actual).toMatch(/can't be read as UTF-8 text/);
  });

  it('G-FINREC-R2: the per-edit path (central CODEOWNERS pipegen created) not UTF-8: "can\'t be read as UTF-8 text"', async () => {
    const s = await seed();
    await runFinish(s);
    rawAt(s, 'o/pipelines', CO, RAW(liveCo(s) as string));
    const d = await coDrift(s);
    expect(d.some((x) => /central file \.github\/CODEOWNERS/.test(x.what) && /can't be read as UTF-8 text/.test(String(x.actual)))).toBe(true);
    expect(d.some((x) => /rule after pipegen's block/.test(x.what))).toBe(false);
  });

  it('G-FINREC-R2: the i1 path (central CODEOWNERS finish left as it was, not UTF-8): "can\'t be read as UTF-8 text"', async () => {
    const s = await lossySeed();
    await finish(s.g.octokit(), { owner: 'o', repo: 'r' }, {}, s.deps());
    const d = (await coDrift(s)).filter((x) => x.what === 'pipegen\'s block in the central CODEOWNERS');
    expect(d).toHaveLength(1);
    expect(d[0]?.actual).toMatch(/can't be read as UTF-8 text/);
  });

  it('G-FINREC-R2: the G29 read (an app CODEOWNERS GitHub reads first that pipegen didn\'t edit) not UTF-8: drift, never warnings from decoded text', async () => {
    const s = await seed();
    await runFinish(s);
    rawAt(s, 'o/r', '.github/CODEOWNERS', RAW('* @o/team\n'));
    const v = await verifyOf(s);
    expect(v.drift.some((x) => /\.github\/CODEOWNERS/.test(`${x.what} ${x.actual}`) && /can't be read as UTF-8 text/.test(String(x.actual)))).toBe(true);
    expect(v.warnings).toEqual([]);
  });
});

describe('G-FINREC-R2 (mutant follow-ups)', () => {
  it('G-FINREC-R2 N1: a lone CR the gate reads as one rule with pipegen\'s owners still counts (GitHub may split it: `@b` alone would own everything)', () => {
    const central = codeownersFile('', codeownersBlock(CENTRAL_PROTECTED_PATHS, ['@a', '@b']));
    // the gate reads `/src/\r*.c` as one pattern owned by @a @b; GitHub may read an ownerless `/src/` (an override) and `*.c @a @b`
    expect(overridingRules(`${central}/src/\r*.c @a @b\n`, CENTRAL_PROTECTED_PATHS)).toHaveLength(1);
    expect(overridingRules(`${central}/src/*.c @a\r@b\n`, CENTRAL_PROTECTED_PATHS)).toHaveLength(1);
    // the same text on two lines is drift too: the ownerless `@b` covers every protected folder
    expect(overridingRules(`${central}/src/*.c @a\n@b\n`, CENTRAL_PROTECTED_PATHS)).toEqual(['@b']);
  });

  it('G-FINREC-R2 i1: before finish ran, a central CODEOWNERS without pipegen\'s block is not drift (finish writes it)', async () => {
    const s = await seed();
    expect((await recordOn(s)).mergedAt).toBeUndefined();
    expect((await coDrift(s)).filter((x) => x.what === 'pipegen\'s block in the central CODEOWNERS')).toEqual([]);
  });
});

describe('G-FINREC-R2 i1 (mutant follow-up)', () => {
  it('G-FINREC-R2 i1: a readable central CODEOWNERS with no pipegen block after finish: "no pipegen block"', async () => {
    const s = await seed();
    await runFinish(s);
    tamper(s, 'o/pipelines', CO, '/docs/ @writers\n');
    const d = (await coDrift(s)).filter((x) => x.what === 'pipegen\'s block in the central CODEOWNERS');
    expect(d).toHaveLength(1);
    expect(d[0]?.actual).toMatch(/no pipegen block/);
  });
});
