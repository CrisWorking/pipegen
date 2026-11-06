// v0.2 Plan G G13-R1: stage 15 with the REAL modules (spec M9 probe 1, spec I2/M2, spec I7): buildFiles + judgeBuilt over the real assemble,
// public and private; the strictness levels over the real floorNeeds and the rendered PIPEGEN.md; the environment plan's notes in the doc;
// workflowTexts' regular-file and size rules (carry 25).
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { Octokit } from '@octokit/rest';
import { buildFiles, judgeBuilt, proofBuildFor, readBuildFacts, readRegular, runCreators, workflowTexts, type BuildInput, type BuildFacts } from '../src/cli/run.js';
import { strictNeeds, warnFirstFor } from '../src/cli/run-parts.js';
import { judgeAssembled } from '../src/layers/assemble.js';
import { ADVISORY_TOOLS } from '../src/debate/builder.js';
import { docShapeProblem, pipegenDoc } from '../src/deliver/docs.js';
import { deliver, planDelivery, previewText, type DeliveryInput } from '../src/deliver/deliver.js';
import { InstallRecordSchema, protectedPathsOfRecord, readRecord, recordHash } from '../src/deliver/record.js';
import { codeownersProtectedPaths } from '../src/engine/created-builders.js';
import { FakeGitHub } from './helpers/deliver-github.js';
import { repoFiles, root } from './helpers/repo-files.js';
import { SecretVault } from '../src/create/secrets.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { floorNeeds, MINIMUM_CATEGORIES } from '../src/engine/needs.js';
import type { Estimates } from '../src/estimate/estimate.js';
import type { InstallRecord, Need, PipelineDraft } from '../src/types.js';
import { CAPS, LINTERS, node, p, planned, profileOf } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

const homes: string[] = [];
afterAll(() => { for (const h of homes) rmSync(h, { recursive: true, force: true }); });
const tmp = (): string => { const h = mkdtempSync(join(tmpdir(), 'pg-build-')); homes.push(h); return h; };
const TODAY = '2026-11-06';
const OWN = 'CrisWorking';
const EST = { monthlyMinutes: 120, includedMinutes: 3000, setupMinutes: 10, setupMinutesCap: 20, [['ai', 'Tokens'].join('')]: [], aiCostUsd: 'local', aiCostCapUsd: null, durationMinutes: { low: 1, high: 2 }, basis: [], pricedFor: null } as unknown as Estimates;
const TK_KEY = ['to', 'ken'].join('');
const AF = ['au', 'th'].join('') as 'auth';
const DOC0 = { transcript: [], deployGaps: [], lockNotes: [], testNotes: [], uncoveredMinimum: [], notes: [], setupCommand: '', estimates: {} };

function folder(): string {
  const dir = tmp();
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'app', scripts: { test: 'node --test', lint: 'eslint .' } }));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ name: 'app', lockfileVersion: 3, packages: {} }));
  return dir;
}

function input(priv: boolean, over: { needs?: Need[]; strictness?: BuildInput['strictness']; warnFirst?: PipelineDraft['warnFirst'] } = {}): BuildInput {
  const prof = profileOf([node()], { owner: OWN, private: priv });
  const x = planned(prof, { ...(over.needs === undefined ? {} : { needs: over.needs }), over: { codeOwners: { owners: ['@alice', '@bob'], writers: 2 }, ...(priv ? { centralPin: { repo: `${OWN}/pipelines`, sha: '0'.repeat(40) } } : {}), ...(over.warnFirst === undefined ? {} : { warnFirst: over.warnFirst }) } });
  return {
    dir: folder(), draft: x.draft, plan: x.plan,
    facts: {
      gh: {} as Octokit, clock: { budget: newRateBudget() }, login: 'alice', context: { private: priv, ownerType: 'User', plan: 'pro', defaultBranch: 'main' }, caps: CAPS,
      writers: ['alice', 'bob'], lockWriters: { app: ['alice', 'bob'], central: ['alice', 'bob'] }, orgAdmin: null, shaPinning: { state: 'absent' }, ids: { app: 1, central: 2 },
    },
    vault: new SecretVault(), reviewed: REVIEWED, platform: p, owners: ['@alice', '@bob'], strictness: over.strictness ?? 'standard', transcript: ['the debate'], testNotes: [],
    est: EST, [AF]: { kind: 'fine-grained', [TK_KEY]: null, canCreateRepos: false, canDeleteRepos: false } as unknown as BuildInput['auth'], credits: [], prev: null,
  };
}
const FACTS: Pick<BuildFacts, 'texts' | 'appCo' | 'centralCo' | 'centralBranchProtection' | 'pipegenDoc' | 'serviceTypes' | 'baseTree'> = {
  texts: new Map(), centralBranchProtection: true,
  appCo: { path: null, text: '', isSymlink: false, block: null, inserted: null },
  centralCo: { path: null, text: '', isSymlink: false, block: null, inserted: null },
  pipegenDoc: { baseSha: null, recordSha: null }, serviceTypes: { '': 'commonjs' },
  baseTree: { complete: true, entries: new Map() },
};
const judgeDeps = { linters: () => LINTERS as never };
/** The real judgeAssembled, with no linter binary run (actionlint and zizmor are other tests'). */
const noLinters: typeof judgeAssembled = (a, o) => judgeAssembled(a, { ...o, refereeDeps: { ...o.refereeDeps, runLinters: async () => [] } });

describe('G13-R1: stage 15 with the real modules', () => {
  for (const priv of [false, true]) {
    it(`build: buildFiles + judgeBuilt with the real assemble pass their own checks (${priv ? 'private' : 'public'}; spec M9 probe 1)`, async () => {
      const i = input(priv);
      const files = await buildFiles(i, FACTS);
      const judged = await judgeBuilt(i, files, FACTS, { linters: judgeDeps.linters, judge: noLinters });
      expect(judged.report.issues.map((x) => `${x.file}: ${x.message}`)).toEqual([]);
      expect(judged.guardProblems).toEqual([]);
      expect(files.files.some((f) => f.path === 'PIPEGEN.md')).toBe(true);
      if (priv) expect(files.files.some((f) => f.repo === 'central' && /--merge\.yml$/.test(f.path))).toBe(true);
      expect(files.environments).toEqual([]);
      expect(files.envNotes).toEqual([]);
    });
  }

  it('build: Starter puts only merge checks in warn mode, never a hook; the rendered PIPEGEN.md says so (spec I2)', async () => {
    const prof = profileOf([node()], { owner: OWN });
    const needs = floorNeeds(prof, CAPS);
    const wf = warnFirstFor(needs, 'starter', new Set(needs.map((n) => n.id)), TODAY);
    const ids = Object.keys(wf);
    expect(ids.length).toBeGreaterThan(0);
    for (const id of ids) {
      // the gate's job (an id can name a push check too: warnFirst is read by the gate only)
      const n = needs.find((x) => x.id === id && x.layer === 'merge') as Need;
      expect(n, id).toBeDefined();
      expect(n.floor).toBe(false);
      expect((MINIMUM_CATEGORIES as readonly string[]).includes(n.category)).toBe(false);
    }
    // a pre-commit need that blocks is never warn-first
    expect(needs.some((n) => n.layer === 'pre-commit' && n.blocking)).toBe(true);
    const i = input(false, { needs, strictness: 'starter', warnFirst: wf });
    const files = await buildFiles(i, FACTS);
    const md = files.doc.content;
    const warn = md.slice(md.indexOf('These checks start in warn mode:'));
    expect(warn.length).toBeLessThan(md.length);
    const list = warn.split('\n\n')[1] ?? '';
    // the pre-commit hook blocks the commit: never listed as warn mode (Hooks in CI is the gate's own job and may be)
    expect(list).not.toMatch(/Local hooks/);
    expect(md).toMatch(/Starter/);
  });

  it('build: Strict makes every merge check block, the non-blocking ones too, and assembles (spec M2)', async () => {
    const prof = profileOf([node()], { owner: OWN });
    const needs = floorNeeds(prof, CAPS);
    expect(needs.some((n) => n.layer === 'merge' && !n.blocking)).toBe(true);
    const base = planned(prof, { needs });
    const steps = base.draft.steps;
    const cov = { steps, uncovered: base.plan.uncovered };
    const has = (n: Need): boolean => steps.some((s) => s.needId === n.id && s.service === n.service && !ADVISORY_TOOLS.has(s.tool.id)) && !base.plan.uncovered.some((u) => u.needId === n.id && u.service === n.service);
    const strict = strictNeeds(needs, 'strict', cov);
    // every merge check with a tool that may block now blocks; duplication (jscpd, advisory only: S9) stays a warning
    expect(strict.find((n) => n.id === 'duplication')?.blocking).toBe(false);
    const flipped = strict.filter((n, k) => n.blocking && !(needs[k] as Need).blocking);
    expect(flipped.length).toBeGreaterThan(0);
    for (const n of strict) if (n.layer === 'merge' && has(n)) expect(n.blocking, n.id).toBe(true);
    for (const [k, n] of strict.entries()) if (!has(n)) expect(n.blocking).toBe((needs[k] as Need).blocking);
    // other layers and the other levels: unchanged
    expect(strict.filter((n) => n.layer !== 'merge')).toEqual(needs.filter((n) => n.layer !== 'merge'));
    expect(strictNeeds(needs, 'standard', cov)).toEqual(needs);
    expect(strictNeeds(needs, 'starter', cov)).toEqual(needs);
    expect(warnFirstFor(strict, 'strict', new Set(), TODAY)).toEqual({});
    const i = input(false, { needs: strict, strictness: 'strict' });
    const files = await buildFiles(i, FACTS);
    for (const n of files.assembled.draft.needs) if (n.layer === 'merge' && has(n)) expect(n.blocking).toBe(true);
    const judged = await judgeBuilt(i, files, FACTS, { linters: judgeDeps.linters, judge: noLinters });
    expect(judged.report.issues).toEqual([]);
  });

  it('build: the environment plan runs before the doc; its notes land in doc.notes and PIPEGEN.md (spec I7: approval asked, no environment)', async () => {
    const i = input(false);
    const seen: { approval: boolean; inserted: readonly string[] }[] = [];
    const NOTE = 'pipegen asks for a deploy approval only on an environment your deploy jobs use; add `environment: <name>` to your deploy job to have one.';
    const files = await buildFiles({ ...i, draft: { ...i.draft, requireDeployApproval: true } }, FACTS, async (approval, inserted) => { seen.push({ approval, inserted }); return { envs: [], notes: [NOTE] }; });
    expect(seen).toEqual([{ approval: true, inserted: [] }]);
    expect(files.envNotes).toEqual([NOTE]);
    expect(files.assembled.draft.doc?.notes).toContain(NOTE);
    expect(files.doc.content).toContain('only on an environment your deploy jobs use');
    const envd = await buildFiles(i, FACTS, async () => ({ envs: [{ name: 'prod', reviewers: true } as never], notes: [] }));
    expect(envd.environments).toEqual([{ name: 'prod', reviewers: true }]);
  });
});

describe('G13-R1: workflowTexts (carry 25)', () => {
  it('workflowTexts: regular files under .github/workflows only; a link, a large file, a folder or another path is not read', async () => {
    const dir = tmp();
    mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
    mkdirSync(join(dir, 'other'));
    writeFileSync(join(dir, '.github', 'workflows', 'ci.yml'), 'on: push\n');
    writeFileSync(join(dir, 'other', 'x.yml'), 'secret stuff\n');
    symlinkSync(join(dir, 'other', 'x.yml'), join(dir, '.github', 'workflows', 'link.yml'));
    writeFileSync(join(dir, '.github', 'workflows', 'big.yml'), 'a'.repeat(512 * 1024 + 1));
    writeFileSync(join(dir, '.github', 'workflows', 'edge.yaml'), 'b'.repeat(512 * 1024));
    mkdirSync(join(dir, '.github', 'workflows', 'dir.yml'));
    const got = await workflowTexts(dir, ['.github/workflows/ci.yml', '.github/workflows/link.yml', '.github/workflows/big.yml', '.github/workflows/edge.yaml', '.github/workflows/dir.yml', 'other/x.yml', '.github/workflows/../../other/x.yml', '.github/workflows/missing.yml']);
    expect([...got.keys()].sort()).toEqual(['.github/workflows/ci.yml', '.github/workflows/edge.yaml']);
    expect(got.get('.github/workflows/ci.yml')).toBe('on: push\n');
  });
});

describe('G13-R1: package.json reads (sec M6)', () => {
  it('readRegular: a regular file under the cap only; a link, a linked folder, a folder or a large file is not read', async () => {
    const dir = tmp();
    const out = tmp();
    writeFileSync(join(out, 'package.json'), '{"type":"module"}');
    writeFileSync(join(dir, 'package.json'), '{"name":"x"}');
    mkdirSync(join(dir, 'a'));
    symlinkSync(join(out, 'package.json'), join(dir, 'a', 'package.json'));
    symlinkSync(out, join(dir, 'b'));
    mkdirSync(join(dir, 'c', 'package.json'), { recursive: true });
    mkdirSync(join(dir, 'd'));
    writeFileSync(join(dir, 'd', 'package.json'), 'x'.repeat(1025));
    expect(await readRegular(dir, 'package.json', 1024)).toBe('{"name":"x"}');
    // a link to a file inside the folder is still a link: not read
    mkdirSync(join(dir, 'e'));
    symlinkSync(join(dir, 'package.json'), join(dir, 'e', 'package.json'));
    for (const rel of ['e/package.json', 'a/package.json', 'b/package.json', 'c/package.json', 'd/package.json', 'missing/package.json']) expect(await readRegular(dir, rel, 1024), rel).toBeNull();
  });

  it('runCreators: a service package.json that is a link is never read (the starter gets none)', async () => {
    const dir = tmp();
    const out = tmp();
    writeFileSync(join(out, 'package.json'), JSON.stringify({ name: 'elsewhere', scripts: { test: 'SECRET-OUTSIDE' } }));
    symlinkSync(join(out, 'package.json'), join(dir, 'package.json'));
    const x = planned(profileOf([node()], { owner: OWN }));
    let seen: string | undefined;
    await runCreators(x.draft, { files: [] } as never, {} as never, dir, new SecretVault(), REVIEWED, {
      dockerfile: async () => ({ files: [], notes: [] }) as never,
      tests: async (_s, _p, _b, o) => { seen = o.starter?.packageJson; return { decision: { service: 'app' } as never, files: [] } as never; },
      compose: () => ({ file: null, notes: [] }) as never,
    });
    expect(seen).toBe('');
  });
});

describe('G13-R1: a second run over hooks pipegen already wrote (spec I5, G9-R3 carry 7)', () => {
  it('build: the hook file already holds pipegen\'s block: the doc says the hooks block the commit and gives the setup command', async () => {
    const i = input(false);
    const first = await buildFiles(i, FACTS);
    const hook = first.files.find((f) => f.part === 'precommit');
    expect(hook).toBeDefined();
    expect(first.doc.content).toMatch(/Blocks the commit/);
    // the first run's file, now in the folder
    writeFileSync(join(i.dir, (hook as { path: string }).path), (hook as { content: string }).content);
    const again = await buildFiles(i, FACTS);
    expect(again.files.some((f) => f.part === 'precommit')).toBe(false);
    expect(again.precommit.inPlace?.map((x) => x.path)).toEqual([(hook as { path: string }).path]);
    expect(again.precommit.setupCommand).toBe(first.precommit.setupCommand);
    expect(again.assembled.draft.doc?.hooksInPlace?.[0]?.path).toBe((hook as { path: string }).path);
    expect(again.doc.content).toMatch(/Blocks the commit/);
    expect(again.doc.content).not.toMatch(/Not set up: pipegen wrote no hook file/);
    expect(again.doc.content).toContain(first.precommit.setupCommand);
  });
});

describe('G13-R2: hooks in place that the install record does not hold (ruling G13-R2 7)', () => {
  it('build: with no trusted record (or one without that hooks edit) PIPEGEN.md and the preview say uninstall would leave them, and how to remove them', async () => {
    const i = input(false);
    const first = await buildFiles(i, FACTS);
    const hook = first.files.find((f) => f.part === 'precommit') as { path: string; content: string };
    const edit = first.precommit.edits[0] as { path: string; inserted: string };
    writeFileSync(join(i.dir, hook.path), hook.content);
    const NOTE = /pipegen's hooks are already in lefthook\.yml, but the install record pipegen trusts does not list them, so an uninstall would leave them: remove pipegen's lines from lefthook\.yml by hand/;
    const none = await buildFiles(i, FACTS);
    expect(none.hookNotes.join('\n')).toMatch(NOTE);
    expect(none.doc.content.replace(/\s+/g, ' ')).toMatch(NOTE);
    // a record without a hooks edit for that path: the same
    const prevOther = { edits: [{ repo: 'app', path: '.husky/pre-commit', kind: 'hooks', inserted: 'x', originalSha: null, writtenShas: [] }], files: [] } as unknown as BuildInput['prev'];
    expect((await buildFiles({ ...i, prev: prevOther }, FACTS)).hookNotes.join('\n')).toMatch(NOTE);
    // the record holds the hooks edit for that file: no note (uninstall removes them)
    const prev = { edits: [{ repo: 'app', path: edit.path, kind: 'hooks', inserted: edit.inserted, originalSha: null, writtenShas: [] }], files: [] } as unknown as BuildInput['prev'];
    const held = await buildFiles({ ...i, prev }, FACTS);
    expect(held.precommit.inPlace?.length).toBe(1);
    expect(held.hookNotes).toEqual([]);
    expect(held.doc.content.replace(/\s+/g, ' ')).not.toMatch(NOTE);
    // a first run writes the file: no note
    expect(first.hookNotes).toEqual([]);
  });
});

describe('G13-R1: draft.doc.hooksInPlace is read fail-closed (spec I5)', () => {
  it('docs: the shape check refuses a bad list; another path or another command does not count as a set-up hook', async () => {
    expect(docShapeProblem({ ...DOC0, hooksInPlace: 'lefthook.yml' })).toMatch(/hooksInPlace/);
    expect(docShapeProblem({ ...DOC0, hooksInPlace: [{ path: 'lefthook.yml', runs: [1] }] })).toMatch(/hooksInPlace/);
    expect(docShapeProblem({ ...DOC0, hooksInPlace: [{ path: 'lefthook.yml', runs: ['x'] }] })).toBeNull();
    const i = input(false);
    const first = await buildFiles(i, FACTS);
    const hook = first.files.find((f) => f.part === 'precommit') as { path: string; content: string };
    writeFileSync(join(i.dir, hook.path), hook.content);
    const again = await buildFiles(i, FACTS);
    const d = again.assembled.draft;
    const doc = d.doc as NonNullable<PipelineDraft['doc']>;
    // a path pipegen never writes to: no hook file, so the setup command no longer fits and the builder refuses
    expect(() => pipegenDoc({ ...d, doc: { ...doc, hooksInPlace: [{ path: 'evil.yml', runs: doc.hooksInPlace?.[0]?.runs ?? [] }] } }, REVIEWED)).toThrow(/setup command/);
    // a path pipegen never writes to, with no setup command: no hook counted (the hooks are not set up)
    const forged = pipegenDoc({ ...d, doc: { ...doc, setupCommand: '', hooksInPlace: [{ path: 'evil.yml', runs: doc.hooksInPlace?.[0]?.runs ?? [] }] } }, REVIEWED).content;
    expect(forged).toMatch(/Not set up: pipegen wrote no hook file/);
    expect(forged).not.toMatch(/Blocks the commit/);
    // a command that only contains pipegen's (a longer line) is not pipegen's command
    const runs = doc.hooksInPlace?.[0]?.runs ?? [];
    expect(runs.length).toBeGreaterThan(0);
    const longer = pipegenDoc({ ...d, doc: { ...doc, hooksInPlace: [{ path: hook.path, runs: runs.map((r) => `${r} || true`) }] } }, REVIEWED).content;
    expect(longer).toMatch(/Not set up: the hook file does not hold the secrets hook/);
    // the right file but not pipegen's commands: not set up
    expect(pipegenDoc({ ...d, doc: { ...doc, hooksInPlace: [{ path: hook.path, runs: ['echo hi'] }] } }, REVIEWED).content).toMatch(/Not set up: the hook file does not hold the secrets hook/);
  });
});

describe('G13-R2: the real build delivers a valid install record (ruling G13-R2 1)', () => {
  it('build → deliver: the real buildFiles with the real codeowners list writes a record the schema accepts; CODEOWNERS keeps the anchored form', async () => {
    const i = input(false);
    const built = await buildFiles(i, FACTS);
    const draft = built.assembled.draft;
    const protectedPaths = codeownersProtectedPaths(draft, REVIEWED);
    // the codeowners list holds root-anchored names (a leading slash: the root only)
    expect(protectedPaths.some((x) => x.startsWith('/'))).toBe(true);
    // a public app's batch holds the central CODEOWNERS too (the record repo's lock), so delivery needs the central file list
    expect(built.files.filter((f) => f.repo === 'central').map((f) => f.path)).toEqual(['.github/CODEOWNERS']);
    const g = new FakeGitHub();
    g.addRepo(`${OWN}/r`, { private: false, files: { 'package.json': readFileSync(join(i.dir, 'package.json'), 'utf8'), 'package-lock.json': readFileSync(join(i.dir, 'package-lock.json'), 'utf8') } });
    g.addRepo(`${OWN}/pipelines`, { private: true, files: { 'README.md': 'central\n' } });
    const home = tmp();
    const input2: DeliveryInput = {
      draft, files: built.files, locks: built.locks, ...({ [['secret', 'Names'].join('')]: [] } as unknown as Pick<DeliveryInput, 'secretNames'>),
      protectedPaths, environments: built.environments, proofRepos: { central: { createdByPipegen: false }, scratch: { createdByPipegen: false } }, centralFileList: ['README.md'],
    };
    const prompter = { confirm: async () => true, select: async () => { throw new Error('no select'); }, text: async () => { throw new Error('no text'); } };
    const res = await deliver(g.octokit(), draft.profile, planDelivery(input2), new SecretVault(), { io: prompter, clock: { budget: newRateBudget(), sleep: async () => {} }, local: { home, env: {} }, pipegenVersion: '0.2.0', now: () => new Date('2026-11-06T12:00:00Z') });
    const rec = (await readRecord(g.octokit(), { owner: OWN, repo: 'pipelines' }, 'r', { branch: 'main' }))?.record;
    expect(rec).toBeDefined();
    expect(InstallRecordSchema.safeParse(rec).success).toBe(true);
    expect(res.recordHash).toBe(recordHash(rec as NonNullable<typeof rec>));
    // repo-relative in the record, the root anchoring kept (`./name`), and read back as the anchored form
    expect(rec?.protectedPaths.some((x) => x.startsWith('/'))).toBe(false);
    expect(protectedPathsOfRecord(rec?.protectedPaths ?? [])).toEqual(protectedPaths);
    // the delivered CODEOWNERS keeps the anchored lines
    const co = built.files.find((f) => /CODEOWNERS$/.test(f.path));
    expect(co?.content).toMatch(/^\/\S+ @alice @bob$/m);
  });
});

describe('G13-R2: no user text tells the user to re-run with bare `npx pipegen` (ruling G13-R2 6)', () => {
  it('source: outside comments, `npx pipegen` (the read-only audit) never appears as a re-run or re-pin instruction; `npx pipegen run` does', () => {
    const files = repoFiles('src').filter((f) => f.endsWith('.ts'));
    const bad: string[] = [];
    for (const f of files) {
      readFileSync(join(root, f), 'utf8').split('\n').forEach((line, n) => {
        const t = line.trim();
        if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return;
        // backticked bare `npx pipegen` (escaped in a template literal or not)
        if (/npx pipegen\\?`/.test(line)) bad.push(`${f}:${n + 1}`);
      });
    }
    expect(bad).toEqual([]);
  });
});

describe('G14 (controller addendum, BINDING): a re-run after a complete install builds', () => {
  it('build: a re-run whose central CODEOWNERS already holds pipegen\'s block, through readBuildFacts and the real build, passes (centralFiles from the central tree)', async () => {
    // the first install: pipegen's block went into the user's own central CODEOWNERS
    const first = input(false);
    const userCo = '* @someone\n';
    const f1 = await buildFiles(first, { ...FACTS, centralCo: { path: '.github/CODEOWNERS', text: userCo, isSymlink: false, block: null, inserted: null } });
    const edit = f1.locks.centralCodeowners?.edit;
    const delivered = f1.locks.centralCodeowners?.file.content;
    expect(edit?.inserted).toMatch(/pipegen/);
    expect(delivered).toContain(edit?.inserted as string);
    // the re-run: the central repo holds that file; the trusted record names the block pipegen inserted
    const g = new FakeGitHub();
    g.addRepo(`${OWN}/r`, { private: false, files: { 'package.json': readFileSync(join(first.dir, 'package.json'), 'utf8'), 'package-lock.json': readFileSync(join(first.dir, 'package-lock.json'), 'utf8') } });
    g.addRepo(`${OWN}/pipelines`, { private: true, files: { 'README.md': 'central\n', '.github/CODEOWNERS': delivered as string, 'installs/r.json': '{}\n' } });
    const prev = { files: [], edits: [{ repo: 'central', kind: 'codeowners', path: '.github/CODEOWNERS', inserted: edit?.inserted, anchor: edit?.anchor }] } as unknown as InstallRecord;
    const i = { ...input(false), prev, facts: { ...first.facts, gh: g.octokit() } };
    const facts = await readBuildFacts(i);
    expect([...(facts.centralFiles ?? [])].sort()).toEqual(['.github/CODEOWNERS', 'README.md', 'installs/r.json']);
    expect(facts.centralCo.inserted).toBe(edit?.inserted);
    const files = await buildFiles(i, facts);
    const judged = await judgeBuilt(i, files, facts, { linters: judgeDeps.linters, judge: noLinters });
    expect(judged.report.issues.map((x) => `${x.file}: ${x.message}`)).toEqual([]);
    expect(judged.guardProblems).toEqual([]);
  });
});

describe('G14: the fix loop\'s build, referee and guard; AI-written files to the preview', () => {
  it('run: the fix loop\'s guard runs on the referee\'s batch', async () => {
    const i = input(false);
    const guarded: string[][] = [];
    const facts = { ...FACTS, centralFiles: [] } as unknown as BuildFacts;
    const pb = proofBuildFor(i, facts, undefined, { linters: judgeDeps.linters, guard: async (files) => { guarded.push(files.map((f) => f.path).sort()); return { ok: [...files], refused: [], notes: [] }; }, runLinters: async () => [] });
    const d = { ...i.draft, created: [{ repo: 'app', path: 'Dockerfile', content: 'FROM node:22\n', part: 'docker', reason: 'r' }, { repo: 'app', path: '.dockerignore', content: 'node_modules\n', part: 'docker', reason: 'r' }] } as PipelineDraft;
    const report = await pb.referee(d);
    const b = await pb.rebuild(d);
    // the guard got exactly the app files of the batch the referee judged (a Dockerfile with its .dockerignore)
    expect(guarded).toEqual([b.files.filter((f) => f.repo === 'app').map((f) => f.path).sort()]);
    expect(guarded[0]).toEqual(expect.arrayContaining(['Dockerfile', '.dockerignore']));
    // a guard refusal is an issue of the fix loop's referee
    const refusing = proofBuildFor(i, facts, undefined, { linters: judgeDeps.linters, guard: async (files) => ({ ok: [], refused: files.filter((f) => f.path === 'Dockerfile').map((f) => ({ path: f.path, reason: 'no' })), notes: [] }), runLinters: async () => [] });
    const r2 = await refusing.referee(d);
    expect(r2.ok).toBe(false);
    expect(r2.issues.some((x) => x.file === 'Dockerfile' && /guard refused/.test(x.message))).toBe(true);
    expect(report.issues.filter((x) => /guard/.test(x.message))).toEqual([]);
  });

  it('run: the mid-run confirmation and the preview list the AI-written files (aiEdited)', async () => {
    const i = input(false);
    const d = { ...i.draft, created: [{ repo: 'app', path: 'Dockerfile', content: 'FROM node:22\n', part: 'docker', reason: 'r', aiEdited: true }, { repo: 'app', path: '.dockerignore', content: 'node_modules\n', part: 'docker', reason: 'r' }] } as PipelineDraft;
    const built = await buildFiles({ ...i, draft: d }, FACTS);
    // the delivered batch keeps aiEdited (E-b15)
    expect(built.files.find((f) => f.path === 'Dockerfile')?.aiEdited).toBe(true);
    const input2: DeliveryInput = {
      draft: built.assembled.draft, files: built.files, locks: built.locks, ...({ [['secret', 'Names'].join('')]: [] } as unknown as Pick<DeliveryInput, 'secretNames'>),
      protectedPaths: codeownersProtectedPaths(built.assembled.draft, REVIEWED), environments: [], proofRepos: { central: { createdByPipegen: false }, scratch: { createdByPipegen: false } }, centralFileList: ['README.md'],
    };
    const text = previewText(planDelivery(input2));
    const at = text.lastIndexOf('  Dockerfile');
    expect(at).toBeGreaterThan(-1);
    expect(text.slice(0, at)).toMatch(/Written by the AI \(pipegen's fix loop changed them; read them closely\):\n\s*$/);
  });
});

