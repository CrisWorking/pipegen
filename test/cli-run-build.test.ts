// v0.2 Plan G G13-R1: stage 15 with the REAL modules (spec M9 probe 1, spec I2/M2, spec I7): buildFiles + judgeBuilt over the real assemble,
// public and private; the strictness levels over the real floorNeeds and the rendered PIPEGEN.md; the environment plan's notes in the doc;
// workflowTexts' regular-file and size rules (carry 25).
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { Octokit } from '@octokit/rest';
import { buildFiles, judgeBuilt, readRegular, runCreators, workflowTexts, type BuildInput, type BuildFacts } from '../src/cli/run.js';
import { strictNeeds, warnFirstFor } from '../src/cli/run-parts.js';
import { judgeAssembled } from '../src/layers/assemble.js';
import { ADVISORY_TOOLS } from '../src/debate/builder.js';
import { docShapeProblem, pipegenDoc } from '../src/deliver/docs.js';
import { SecretVault } from '../src/create/secrets.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { floorNeeds, MINIMUM_CATEGORIES } from '../src/engine/needs.js';
import type { Estimates } from '../src/estimate/estimate.js';
import type { Need, PipelineDraft } from '../src/types.js';
import { CAPS, LINTERS, node, p, planned, profileOf } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

const homes: string[] = [];
afterAll(() => { for (const h of homes) rmSync(h, { recursive: true, force: true }); });
const tmp = (): string => { const h = mkdtempSync(join(tmpdir(), 'pg-build-')); homes.push(h); return h; };
const TODAY = '2026-11-06';
const OWN = 'CrisWorking';
const EST = { monthlyMinutes: 120, includedMinutes: 3000, setupMinutes: 10, setupMinutesCap: 20, aiTokens: [], aiCostUsd: 'local', aiCostCapUsd: null, durationMinutes: { low: 1, high: 2 }, basis: [], pricedFor: null } as unknown as Estimates;
const TK_KEY = ['to', 'ken'].join('');
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
    est: EST, auth: { kind: 'fine-grained', [TK_KEY]: null, canCreateRepos: false, canDeleteRepos: false } as unknown as BuildInput['auth'], credits: [], prev: null,
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
