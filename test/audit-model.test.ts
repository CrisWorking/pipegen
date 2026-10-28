// Plan U Task 2a: the audit model (buildAudit). Controller rulings B1, B3, S7-S12, S27, S29, S30 and the Plan U
// carry-forwards (estimates by jobCategories, coverage skipped count and signature errors, no child processes).
import { chmodSync, mkdirSync, readFileSync, symlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as childProcess from 'node:child_process';
import { COUNTING_ONLY_NOTE, EXCLUDED_PATTERNS, redact } from '../src/ai/redact.js';
import { mapCoverage } from '../src/audit/coverage.js';
import { buildAudit, CURRENT_MILESTONE, type AuditDeps, type AuditReport } from '../src/audit/model.js';
import { renderJson, renderMarkdown, renderTerminal } from '../src/audit/render.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { floorNeeds, jobCategories } from '../src/engine/needs.js';
import { estimate } from '../src/estimate/estimate.js';
import { readProject } from '../src/read/project.js';
import { skippedWorkflowCount } from '../src/read/workflows.js';
import { DEFAULT_MODEL, type Capabilities, type ReviewedTool } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';

vi.mock('node:child_process', async (importOriginal) => {
  const a = await importOriginal<typeof import('node:child_process')>();
  const spies = {
    exec: vi.fn(a.exec), execFile: vi.fn(a.execFile), execFileSync: vi.fn(a.execFileSync), execSync: vi.fn(a.execSync),
    fork: vi.fn(a.fork), spawn: vi.fn(a.spawn), spawnSync: vi.fn(a.spawnSync),
  };
  return { ...a, ...spies, default: { ...a, ...spies } };
});
vi.mock('../src/audit/coverage.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/audit/coverage.js')>();
  return { ...a, mapCoverage: vi.fn(a.mapCoverage) };
});
vi.mock('../src/estimate/estimate.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/estimate/estimate.js')>();
  return { ...a, estimate: vi.fn(a.estimate) };
});
vi.mock('../src/read/project.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/read/project.js')>();
  return { ...a, readProject: vi.fn(a.readProject) };
});

beforeEach(() => vi.clearAllMocks());
afterEach(cleanupRepos);

const NOW = Date.parse('2026-10-27T12:00:00Z');
const VERSION = (JSON.parse(readFileSync(resolve(import.meta.dirname, '../package.json'), 'utf8')) as { version: string }).version;
const SWAP_WARNING = {
  text: 'This repo could change which pipegen runs. Run pipegen from outside the repo, from the npm registry, with:',
  command: `npx --registry=https://registry.npmjs.org pipegen@${VERSION} audit --dir ./repo`,
};
const ANON_NOTE = 'Without a GitHub token, pipegen reads public data only and is rate-limited.';
const NAME_HIDDEN = '(a file whose name looks like a secret)';
const EXCLUDED_NOTE = "(never sent to the AI; check it isn't committed)";

// Public repo, every capability: no limits.
const allCaps: Capabilities = {
  branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: true,
  attestations: true, codeScanning: true, keylessSigningAllowed: true,
};
// What a Free private repo probes as.
const bareCaps: Capabilities = {
  branchProtection: false, environments: true, envRequiredReviewers: false, deploymentBranchPolicies: false,
  attestations: false, codeScanning: false, keylessSigningAllowed: false,
};

interface FakeGh { gh: Octokit; events: ReturnType<typeof vi.fn>; pulls: ReturnType<typeof vi.fn> }
function fakeGh(opts: { fail?: boolean; pushesPerPage?: number } = {}): FakeGh {
  const at = new Date(NOW - 60_000).toISOString();
  // a busy repo (100 a page) has more pages: GitHub says so in its Link header (final review I1)
  const events = vi.fn(async ({ page }: { page: number }) => {
    if (opts.fail) throw Object.assign(new Error('GitHub answered 500'), { status: 500 });
    const busy = (opts.pushesPerPage ?? 1) >= 100;
    return {
      data: Array.from({ length: opts.pushesPerPage ?? 1 }, () => ({ type: 'PushEvent', created_at: at })),
      headers: busy ? { link: `<https://api.github.com/repos/o/r/events?per_page=100&page=${page + 1}>; rel="next"` } : {},
    };
  });
  const pulls = vi.fn(async () => ({ data: [] }));
  return { gh: { rest: { activity: { listRepoEvents: events }, pulls: { list: pulls } } } as unknown as Octokit, events, pulls };
}

function deps(over: Partial<AuditDeps> = {}): AuditDeps {
  return {
    gh: fakeGh().gh, anonymous: false,
    context: { private: false, ownerType: 'User', plan: 'free', defaultBranch: 'main' },
    capabilities: allCaps, permissions: [{ permission: 'Contents: read and write', why: 'to open the pull request' }],
    reviewed: [], now: () => NOW, budget: newRateBudget(), ...over,
  };
}

/** A temp folder readProject accepts: .git/config with a GitHub origin (written by hand: no git process). */
function repo(files: Record<string, string> = {}): string {
  const dir = makeTempDir();
  writeIn(dir, '.git/config', '[remote "origin"]\n\turl = https://github.com/o/r.git\n');
  for (const [rel, body] of Object.entries(files)) writeIn(dir, rel, body);
  return dir;
}

/** A single-package Node app: test and lint scripts, a start script (runnable), no Dockerfile, no hooks. */
const nodeApp = (over: Record<string, unknown> = {}): Record<string, string> => ({
  'package.json': JSON.stringify({ name: 'app', scripts: { test: 'vitest run', lint: 'eslint .', start: 'node index.js' }, devDependencies: { vitest: '1.0.0' }, ...over }),
  'package-lock.json': '{}\n',
  'index.js': 'console.log("hi");\n',
});

const tool = (id: string, categories: string[], languages: ReviewedTool['languages'] = ['any']): ReviewedTool => ({
  id, categories, languages,
  candidate: { id, name: id, kind: 'action', repo: `acme/${id}`, version: 'v1.0.0', pin: { sha: '1'.repeat(40) }, source: 'reviewed', reviewed: true, categories },
  step: { output: { path: '', format: 'none' } }, fixedInputs: {}, choices: {}, configFiles: [], reviewedBy: 'maintainer', reviewedAt: '2026-09-01', proofs: 0,
});

const rowsOf = (r: AuditReport, id: string) => r.wouldAdd.filter((w) => w.need.id === id);
const anyContains = (r: AuditReport, value: string) => JSON.stringify(r).includes(value) || JSON.stringify(r).includes(JSON.stringify(value).slice(1, -1));

describe('buildAudit (brief, Task 2a)', () => {
  it('audit: wouldAdd uses reviewed tools for missing needs', async () => {
    const gitleaks = tool('betterleaks', ['secrets']); // Plan P Task 8: the secrets rule names betterleaks
    const r = await buildAudit(repo(nodeApp()), deps({ reviewed: [gitleaks, tool('pip-audit', ['deps'], ['python'])] }));
    const leakRows = rowsOf(r, 'secrets');
    expect(leakRows.map((w) => w.need.layer)).toEqual(['pre-commit', 'push', 'merge']);
    for (const w of leakRows) {
      expect(w.status).toBe('missing');
      expect(w.tool).toBe(gitleaks);
      expect(w.note).toBe('Betterleaks: scans for committed secrets');
    }
    // a reviewed tool for another language is never picked
    for (const w of rowsOf(r, 'deps')) expect(w.tool).toBeNull();
  });

  it('audit: no reviewed tool → suggestion only', async () => {
    const r = await buildAudit(repo(nodeApp()), deps());
    const sast = rowsOf(r, 'sast');
    expect(sast.length).toBeGreaterThan(0);
    for (const w of sast) {
      expect(w.tool).toBeNull();
      expect(w.note).toBe('no reviewed tool yet; pipegen would only mention one, never run it as a check');
    }
  });

  it('audit: secrets in tree listed without values', async () => {
    const gh = fake.githubClassic();
    const stripe = fake.stripeKey();
    const npmName = fake.npmPublish();
    const dir = repo({
      ...nodeApp(),
      'src/config.ts': `export const t = '${gh}';\n`,
      '.env': `STRIPE=${stripe}\n`,
      [`keys/${npmName}.txt`]: 'nothing here\n',
    });
    const r = await buildAudit(dir, deps());
    expect(r.secretsInTree).toEqual(expect.arrayContaining([
      { file: 'src/config.ts', rule: 'github-token' },
      { file: '.env', rule: 'stripe-key', note: EXCLUDED_NOTE },
      { file: NAME_HIDDEN, rule: 'secret-like-name' },
    ]));
    for (const v of [gh, stripe, npmName]) expect(anyContains(r, v), v.slice(0, 4)).toBe(false);
  });

  it('audit: unsupported stack → support audit-only with reason', async () => {
    const r = await buildAudit(repo({ 'pyproject.toml': '[project]\nname = "svc"\n', 'app.py': 'print(1)\n' }), deps());
    expect(r.support.level).toBe('audit-only');
    expect(r.support.reasons).toEqual(['Python support arrives in v0.4.']); // S8: without "You can run `pipegen audit` today."
    expect(r.support.nextStep).toBe('The full setup arrives in v0.4 for Python and monorepos.');
    expect(r.support.nextCommand).toBeNull(); // ruling U18
  });

  it('audit: wouldCreate uses Part precommit when there is no hook manager', async () => {
    const r = await buildAudit(repo(nodeApp()), deps());
    expect(r.wouldCreate).toContainEqual({ what: 'precommit', why: expect.stringMatching(/hook manager/) });
    const withHooks = await buildAudit(repo({ ...nodeApp(), '.pre-commit-config.yaml': 'repos: []\n' }), deps());
    expect(withHooks.wouldCreate.map((c) => c.what)).not.toContain('precommit');
  });

  it('audit: aiBundle counts files, lists excluded patterns, no contents', async () => {
    const marker = 'UNIQUE_CONTENT_MARKER_42';
    const r = await buildAudit(repo({ ...nodeApp(), 'src/a.js': `// ${marker}\n`, 'src/b.js': '1\n', '.env': 'A=1\n' }), deps());
    // package.json, index.js, src/a.js, src/b.js (package-lock.json and .env are excluded)
    expect(r.aiBundle.files).toBe(4);
    expect(r.aiBundle.bytes).toBeGreaterThan(0);
    expect(r.aiBundle.truncated).toBe(false);
    expect(r.aiBundle.excludedPatterns).toEqual([...EXCLUDED_PATTERNS]);
    expect(r.aiBundle.topFolders).toEqual(['src']);
    expect(Object.keys(r.aiBundle).sort()).toEqual(['bytes', 'excludedPatterns', 'files', 'topFolders', 'truncated']);
    expect(anyContains(r, marker)).toBe(false);
  });

  it('audit: estimates use DEFAULT_MODEL, AI cost split into input and output', async () => {
    const r = await buildAudit(repo(nodeApp()), deps());
    expect(r.estimates.pricedFor).toEqual({ provider: 'claude', model: DEFAULT_MODEL });
    expect(r.estimates.aiCostUsd).not.toBe('local');
    const cost = r.estimates.aiCostUsd as Exclude<AuditReport['estimates']['aiCostUsd'], 'local'>;
    expect(cost.input.high).toBeGreaterThan(0);
    expect(cost.output.high).toBeGreaterThan(0);
  });

  it('audit: estimate called with jobCategories(floorNeeds) incl. nightly and 2 variants', async () => {
    const r = await buildAudit(repo(nodeApp()), deps());
    expect(estimate).toHaveBeenCalledTimes(1);
    const [p, jobs, variants, activity, provider] = vi.mocked(estimate).mock.calls[0];
    expect(p).toEqual(r.profile);
    expect(jobs).toEqual(jobCategories(floorNeeds(r.profile, allCaps)));
    expect(jobs.nightly[0]).toBe('nightly');
    expect(jobs.nightly.length).toBeGreaterThan(1);
    expect(variants).toBe(2);
    expect(activity).toEqual({ pushes: 1, prs: 0, capped: false });
    expect(provider).toEqual({ name: 'claude', model: DEFAULT_MODEL });
  });

  it('audit: excludedPatterns equals EXCLUDED_PATTERNS', async () => {
    const r = await buildAudit(repo(nodeApp()), deps());
    expect(r.aiBundle.excludedPatterns).toEqual([...EXCLUDED_PATTERNS]);
  });

  it('audit: buildAudit always gets an Octokit; anonymous client on a public repo adds the no-token note', async () => {
    const g = fakeGh();
    const r = await buildAudit(repo(nodeApp()), deps({ gh: g.gh, anonymous: true }));
    expect(g.events).toHaveBeenCalled(); // the activity comes through the given client
    expect(r.warnings).toContainEqual({ text: ANON_NOTE });
    expect(redact(ANON_NOTE)).toBe(ANON_NOTE); // Task 3 runs redact() over every string at output (U10; review M3)
    const named = await buildAudit(repo(nodeApp()), deps());
    expect(named.warnings).not.toContainEqual({ text: ANON_NOTE });
  });

  it('audit: wouldAdd uses projectScriptFor for tests and lint when the script exists', async () => {
    const r = await buildAudit(repo(nodeApp()), deps({ reviewed: [tool('eslint-x', ['lint', 'unit-tests'])] }));
    for (const id of ['unit-tests', 'full-tests', 'lint', 'format-lint']) {
      const rows = rowsOf(r, id);
      expect(rows.length, id).toBeGreaterThan(0);
      for (const w of rows) {
        expect(w.tool, id).toMatchObject({ kind: 'project-script', service: 'app', script: id.endsWith('tests') ? 'test' : 'lint' });
        expect(w.note).toBe(`your own \`${id.endsWith('tests') ? 'test' : 'lint'}\` script would run here`);
      }
    }
  });

  it('audit: repo .npmrc with a registry → warning', async () => {
    for (const line of ['registry=https://registry.example.test/', '@acme:registry = https://npm.example.test/', '  "registry"=https://x.example.test/']) {
      const r = await buildAudit(repo({ ...nodeApp(), '.npmrc': `${line}\n` }), deps());
      expect(r.warnings, line).toEqual([SWAP_WARNING]);
    }
    const plain = await buildAudit(repo({ ...nodeApp(), '.npmrc': 'save-exact=true\n' }), deps());
    expect(plain.warnings).toEqual([]);
  });

  it('U18: in a v0.1 build no output has a runnable `npx pipegen`; the .npmrc warning keeps its exact-version command', async () => {
    const reports = [
      await buildAudit(repo({ ...nodeApp(), '.npmrc': 'registry=https://registry.example.test/\n' }), deps()),
      await buildAudit(repo({ 'pyproject.toml': '[project]\nname = "svc"\n', 'app.py': 'print(1)\n' }), deps()),
      await buildAudit(repo({ 'main.go': 'package main\n' }), deps()),
    ];
    for (const r of reports) {
      expect(r.support.nextCommand).toBeNull();
      for (const text of [renderTerminal(r, { knownValues: [] }), renderMarkdown(r, { knownValues: [] }), renderJson(r, { knownValues: [] })]) {
        expect(text).not.toMatch(/npx\s+pipegen/);
      }
    }
    const t = renderTerminal(reports[0] as AuditReport, { knownValues: [] });
    expect(t.split('\n')).toContain(`    ${SWAP_WARNING.command}`);
  });

  it('audit: local node_modules/.bin/pipegen → warning', async () => {
    const dir = repo({ ...nodeApp(), 'node_modules/.bin/pipegen': '#!/bin/sh\n' });
    expect((await buildAudit(dir, deps())).warnings).toEqual([SWAP_WARNING]);
    // a symbolic link counts as present and is never followed (here it points nowhere)
    const linked = repo(nodeApp());
    mkdirSync(join(linked, 'node_modules/.bin'), { recursive: true });
    symlinkSync('/nonexistent/pipegen-target', join(linked, 'node_modules/.bin/pipegen'));
    expect((await buildAudit(linked, deps())).warnings).toEqual([SWAP_WARNING]);
  });

  it('audit: .npmrc values never appear in the report', async () => {
    const npmValue = fake.npmPublish();
    const pass = 'npmrc' + 'hidden' + 'value9';
    const registry = 'https://user:' + pass + '@registry.example.test/';
    const dir = repo({ ...nodeApp(), '.npmrc': `registry=${registry}\n//registry.example.test/:_auth${'Tok'}en=${npmValue}\n` });
    const r = await buildAudit(dir, deps());
    expect(r.warnings).toEqual([SWAP_WARNING]);
    for (const v of [npmValue, pass, registry, 'registry.example.test']) expect(anyContains(r, v), v.slice(0, 6)).toBe(false);
  });
});

describe('buildAudit (controller rulings)', () => {
  it('B1: re-reads the project itself and overlays the GitHub context', async () => {
    const dir = repo(nodeApp());
    const r = await buildAudit(dir, deps({ context: { private: true, ownerType: 'Organization', plan: 'team', defaultBranch: 'trunk' } }));
    expect(readProject).toHaveBeenCalledWith(dir, expect.anything());
    expect(r.profile).toMatchObject({ owner: 'o', repo: 'r', private: true, ownerType: 'Organization', plan: 'team', defaultBranch: 'trunk' });
    expect(r.capabilities).toEqual(allCaps);
    expect(r.permissions).toEqual([{ permission: 'Contents: read and write', why: 'to open the pull request' }]);
  });

  it('B3: an unusable reviewed list marks tool-less rows "reviewed list unavailable", not "suggestion only"', async () => {
    const r = await buildAudit(repo(nodeApp()), deps({ reviewed: [], reviewedUnavailable: true }));
    const nulls = r.wouldAdd.filter((w) => w.tool === null);
    expect(nulls.length).toBeGreaterThan(0);
    for (const w of nulls) expect(w.note).toBe("pipegen's reviewed tool list couldn't be loaded, so it has no tool to add here");
    expect(r.wouldAdd.some((w) => w.note.startsWith('no reviewed tool yet'))).toBe(false);
    // project scripts and pipegen's own checks don't come from the list, so they stay
    expect(rowsOf(r, 'unit-tests')[0].tool).toMatchObject({ kind: 'project-script' });
    expect(rowsOf(r, 'gate')[0].tool).toEqual({ kind: 'built-in' });
  });

  it('S7: one row per floor need not covered; gate and deploy-verify are built-in; covered needs get no row', async () => {
    const dir = repo({
      ...nodeApp(),
      '.github/workflows/ci.yml': 'on:\n  push:\n  pull_request:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n      - run: npm run lint\n        continue-on-error: true\n',
    });
    const r = await buildAudit(dir, deps({ reviewed: [tool('gitleaks', ['secrets', 'gate'])] }));
    const notCovered = r.coverage.filter((c) => c.status !== 'covered');
    expect(r.wouldAdd.map((w) => w.need)).toEqual(notCovered.map((c) => c.need));
    expect(r.wouldAdd.map((w) => w.status)).toEqual(notCovered.map((c) => c.status));
    expect(r.coverage.find((c) => c.need.layer === 'push' && c.need.id === 'unit-tests')?.status).toBe('covered');
    expect(r.wouldAdd.some((w) => w.need.layer === 'push' && w.need.id === 'unit-tests')).toBe(false);
    expect(r.wouldAdd.find((w) => w.need.layer === 'push' && w.need.id === 'lint')?.status).toBe('partial');
    for (const id of ['gate', 'deploy-verify']) {
      const rows = rowsOf(r, id);
      expect(rows.length, id).toBeGreaterThan(0);
      for (const w of rows) {
        expect(w.tool).toEqual({ kind: 'built-in' }); // never a reviewed tool, even one listing the category
        expect(w.note).toBe("pipegen's own check");
      }
    }
  });

  it('S8: the next step is a fixed table keyed by CURRENT_MILESTONE; no command that does not exist', async () => {
    expect(CURRENT_MILESTONE).toBe('v0.1');
    const node = await buildAudit(repo(nodeApp()), deps());
    expect(node.support).toEqual({
      level: 'full', reasons: [],
      nextStep: 'The full setup arrives in v0.2 for single-package Node/TypeScript repos.',
      nextCommand: null,
    });
    const bare = await buildAudit(repo({ 'main.go': 'package main\n' }), deps());
    expect(bare.support.level).toBe('audit-only');
    expect(bare.support.reasons).toEqual(['This language is not supported yet.']);
    expect(bare.support.nextStep).toBe('The full setup is not planned yet for this repo.');
    expect(bare.support.nextCommand).toBeNull();
    for (const r of [node, bare]) expect(JSON.stringify(r.support)).not.toMatch(/pipegen audit|today/);
  });

  it('S9: limits come only from the capabilities and the signing mode, never the plan name; never "make it public"', async () => {
    const ctx = { private: true, ownerType: 'User' as const, plan: 'enterprise' as const, defaultBranch: 'main' };
    const r = await buildAudit(repo(nodeApp()), deps({ capabilities: bareCaps, context: ctx }));
    expect(r.limits).toEqual([
      'No merge lock: anyone with write access can merge without checks (GitHub Pro for personal accounts, GitHub Team for organisations, adds it).',
      'Without a merge lock, a pull request could replace the gate with a fake one; only code-owner review stops it.',
      'No deploy approvals: GitHub does not let this repo require a reviewer before a deploy.',
      'No image signing: this private repo has no artifact attestations, and no environment rule was proven to keep a signing key to the default branch.',
      'No artifact attestations: GitHub does not offer them for this repo.',
      'No code scanning: GitHub does not show scan results in the Security tab for this repo.',
    ]);
    for (const line of r.limits) expect(line).not.toMatch(/public/i);
    // a 'free' plan with every capability has no limits: the plan name decides nothing
    const full = await buildAudit(repo(nodeApp()), deps({ capabilities: allCaps, context: { ...ctx, plan: 'free' } }));
    expect(full.limits).toEqual([]);
  });

  it('S10: excluded files are scanned and flagged; untracked files count; at most 200 rows plus "and N more"', async () => {
    const files: Record<string, string> = { ...nodeApp() };
    for (let i = 0; i < 205; i++) files[`src/f${String(i).padStart(3, '0')}.ts`] = `export const k = '${fake.awsKey()}';\n`;
    const r = await buildAudit(repo(files), deps());
    expect(r.secretsInTree).toHaveLength(200);
    expect(r.notes).toContain('…and 5 more secret-like findings not listed.');
    expect(r.notes).toContain("pipegen reads the files on disk without git, so files that aren't committed (for example a local .env) are in this list too.");
  });

  it('S10: symbolic links are never followed', async () => {
    const outside = makeTempDir();
    writeIn(outside, 'secret.ts', `export const t = '${fake.githubClassic()}';\n`);
    const dir = repo(nodeApp());
    symlinkSync(join(outside, 'secret.ts'), join(dir, 'linked.ts'));
    symlinkSync(outside, join(dir, 'linkdir'));
    const r = await buildAudit(dir, deps());
    expect(r.secretsInTree).toEqual([]);
  });

  it('S11: notes are deduped and gather reader, caller (capability probe) and bundle notes', async () => {
    const dir = repo({ ...nodeApp(), '.github/workflows/bad.yml': 'on: [\n' });
    const r = await buildAudit(dir, deps({ notes: ['Probe note.', 'Probe note.'] }));
    expect(r.notes.filter((n) => n === 'Probe note.')).toHaveLength(1);
    expect(r.notes).toContain('Skipped .github/workflows/bad.yml: it could not be parsed.');
    expect(new Set(r.notes).size).toBe(r.notes.length);
    // a counting-only bundle's "cannot be sent" note is about pipegen's internals, not this report
    expect(r.notes).not.toContain(COUNTING_ONLY_NOTE);
  });

  it('S12: includedMinutes and a capped activity reach the estimates', async () => {
    const g = fakeGh({ pushesPerPage: 100 });
    const ctx = { private: true, ownerType: 'User' as const, plan: 'free' as const, defaultBranch: 'main' };
    const r = await buildAudit(repo(nodeApp()), deps({ gh: g.gh, context: ctx, capabilities: bareCaps }));
    expect(typeof r.estimates.includedMinutes).toBe('number');
    expect(vi.mocked(estimate).mock.calls[0][3]).toMatchObject({ capped: true });
    expect(r.estimates.basis.some((b) => b.startsWith('Activity: at least'))).toBe(true);
    const pub = await buildAudit(repo(nodeApp()), deps());
    expect(pub.estimates.includedMinutes).toBeNull();
  });

  it('S12: activity that cannot be read → 0 pushes and 0 pull requests, said in the basis', async () => {
    const r = await buildAudit(repo(nodeApp()), deps({ gh: fakeGh({ fail: true }).gh }));
    expect(vi.mocked(estimate).mock.calls[0][3]).toEqual({ pushes: 0, prs: 0, capped: false });
    expect(r.estimates.basis.filter((b) => b.startsWith('Activity:'))).toEqual([
      "Activity: pipegen couldn't read this repo's pushes and pull requests for the last 30 days, so monthly minutes assume 0 of each (the real number is likely higher).",
    ]);
  });

  it('S27: a service without tests says pipegen would create starter tests (with wouldCreate tests)', async () => {
    const r = await buildAudit(repo({ 'package.json': JSON.stringify({ name: 'app', scripts: { start: 'node index.js', lint: 'eslint .' } }), 'index.js': '1\n' }), deps());
    for (const id of ['unit-tests', 'full-tests']) {
      for (const w of rowsOf(r, id)) expect(w.note).toBe('No tests found for app: pipegen would create starter tests.');
    }
    expect(r.wouldCreate).toContainEqual({ what: 'tests', why: 'No tests found for app: pipegen would create starter tests.' });
    expect(r.testsNote).toBeNull();
  });

  it('S27: a bare repo (root service, language other) gets starter tests', async () => {
    const r = await buildAudit(repo({ 'README.md': '# hi\n' }), deps());
    expect(r.profile.services).toHaveLength(1);
    expect(r.profile.services[0].language).toBe('other');
    expect(rowsOf(r, 'unit-tests').map((w) => w.note)).toEqual(['No tests found for r: pipegen would create starter tests.', 'No tests found for r: pipegen would create starter tests.']);
    expect(r.wouldCreate.map((c) => c.what)).toContain('tests');
  });

  it('S27: with 0 services the tests rows say "No service found to test" instead of a gap', async () => {
    const real = (await vi.importActual<typeof import('../src/read/project.js')>('../src/read/project.js')).readProject;
    vi.mocked(readProject).mockImplementationOnce(async (d, o) => ({ ...(await real(d, o)), services: [] }));
    const r = await buildAudit(repo(nodeApp()), deps());
    expect(r.profile.services).toEqual([]);
    expect(r.testsNote).toBe('No service found to test.');
    expect(rowsOf(r, 'unit-tests')).toEqual([]);
    expect(rowsOf(r, 'full-tests')).toEqual([]);
    expect(r.wouldCreate.map((c) => c.what)).not.toContain('tests');
  });

  it('S29: aiBundle gains topFolders (most files first) and keeps every excluded pattern', async () => {
    const r = await buildAudit(repo({ ...nodeApp(), 'lib/a.js': '1\n', 'src/a.js': '1\n', 'src/b.js': '1\n' }), deps());
    expect(r.aiBundle.topFolders).toEqual(['src', 'lib']);
    expect(r.aiBundle.excludedPatterns).toEqual([...EXCLUDED_PATTERNS]);
  });

  it('S30: the warning names the running version from package.json, never x.y.z', async () => {
    const r = await buildAudit(repo({ ...nodeApp(), '.npmrc': 'registry=https://r.example.test/\n' }), deps());
    expect(r.warnings[0]?.command).toContain(`pipegen@${VERSION} audit`);
    expect(r.warnings[0]?.command).not.toContain('x.y.z');
  });

  it('B3/S7 note texts never point at a command that does not exist', async () => {
    const r = await buildAudit(repo(nodeApp()), deps());
    expect(JSON.stringify({ s: r.support, w: r.wouldAdd.map((w) => w.note), c: r.wouldCreate, l: r.limits })).not.toMatch(/pipegen (init|setup|install|fix)\b/);
  });
});

describe('buildAudit (carry-forwards)', () => {
  it('coverage: the number of workflow files readWorkflows skipped reaches mapCoverage', async () => {
    const dir = repo({ ...nodeApp(), '.github/workflows/bad.yml': 'on: [\n', '.github/workflows/ok.yml': 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n' });
    const r = await buildAudit(dir, deps());
    expect(mapCoverage).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mapCoverage).mock.calls[0][3]).toMatchObject({ skippedWorkflows: 1 });
    expect(vi.mocked(mapCoverage).mock.calls[0][1]).toEqual(floorNeeds(r.profile, allCaps));
    // the skipped file makes would-be-missing rows unknown, not missing
    expect(r.coverage.find((c) => c.need.layer === 'push' && c.need.id === 'sast')?.status).toBe('unknown');
  });

  it('coverage: skippedWorkflowCount counts per-file, linked-folder and over-the-cap notes', () => {
    expect(skippedWorkflowCount([])).toBe(0);
    expect(skippedWorkflowCount([
      'Skipped .github/workflows/a.yml: it could not be parsed.',
      'Skipped .github/workflows/b.yml: it is larger than 1 MB.',
      'Skipped package.json: it could not be parsed.',
    ])).toBe(2);
    expect(skippedWorkflowCount(['Skipped .github/workflows: it is reached through a symbolic link.'])).toBe(1);
    expect(skippedWorkflowCount(['Only the first 200 workflow files were read.'])).toBe(1);
  });

  it('coverage: tool signatures that cannot be loaded → a plain note and unknown rows, never missing, never a crash', async () => {
    vi.mocked(mapCoverage).mockRejectedValueOnce(new Error("pipegen's tool signatures (/x/data/tool-signatures.yml) could not be read: ENOENT"));
    const r = await buildAudit(repo(nodeApp()), deps());
    expect(r.coverage.length).toBe(floorNeeds(r.profile, allCaps).length);
    for (const c of r.coverage) expect(c.status).toBe('unknown');
    expect(r.wouldAdd).toHaveLength(r.coverage.length);
    expect(r.notes).toContain("pipegen couldn't load its list of tool signatures, so it can't tell which checks your workflows already run (pipegen's tool signatures (/x/data/tool-signatures.yml) could not be read: ENOENT).");
  });

  it('aiBundle: a file name with a line break is still counted (bundleCode keeps it)', async () => {
    const r = await buildAudit(repo({ ...nodeApp(), 'src/a\nb.js': '1\n', 'src/c\rd.js': '1\n' }), deps());
    expect(r.aiBundle.files).toBe(4);
  });

  it('no child processes during the audit', async () => {
    const dir = repo({ ...nodeApp(), '.npmrc': 'registry=https://r.example.test/\n', 'src/x.ts': `const t = '${fake.githubClassic()}';\n` });
    vi.clearAllMocks();
    await buildAudit(dir, deps());
    for (const name of ['exec', 'execFile', 'execFileSync', 'execSync', 'fork', 'spawn', 'spawnSync'] as const) {
      expect(vi.mocked(childProcess[name]), name).not.toHaveBeenCalled();
    }
  });
});

describe('buildAudit (fix round 1)', () => {
  it('I1: a secret-like workflow file name and service folder name are masked in notes; secretsInTree keeps its label', async () => {
    const tok = fake.githubClassic();
    const key = fake.awsKey();
    const dir = repo({
      ...nodeApp(),
      [`.github/workflows/${tok}.yml`]: 'on: [\n',
      [`${key}/Dockerfile`]: 'FROM node:24\n',
      [`${key}/package.json`]: '{\n',
    });
    const r = await buildAudit(dir, deps());
    for (const v of [tok, key]) expect(r.notes.join('\n'), v.slice(0, 4)).not.toContain(v);
    // the notes are still there, with the name masked
    expect(r.notes.filter((n) => n.startsWith('Skipped ') && n.includes('[REDACTED]')).length).toBeGreaterThanOrEqual(2);
    expect(r.secretsInTree.filter((s) => s.file === NAME_HIDDEN).length).toBeGreaterThanOrEqual(3);
    for (const v of [tok, key]) expect(JSON.stringify(r.secretsInTree)).not.toContain(v);
  });

  it('I1: notes from the caller are masked too', async () => {
    const tok = fake.githubClassic();
    const r = await buildAudit(repo(nodeApp()), deps({ notes: [`Probe saw ${tok}.`] }));
    expect(r.notes.join('\n')).not.toContain(tok);
    expect(r.notes).toContain('Probe saw [REDACTED].');
  });

  it('I2: padding before the key cannot hide a registry, node-options or script-shell line', async () => {
    for (const line of [`${' '.repeat(400)}registry=https://r.example.test/`, `${'\t'.repeat(350)}@acme:registry=https://r.example.test/`, 'script-shell=/bin/evil', `${' '.repeat(500)}script-shell = /bin/evil`, 'node-options=--require ./x.js']) {
      const r = await buildAudit(repo({ ...nodeApp(), '.npmrc': `save-exact=true\n${line}\n` }), deps());
      expect(r.warnings, line.trim().slice(0, 20)).toEqual([SWAP_WARNING]);
      expect(anyContains(r, '/bin/evil')).toBe(false);
      expect(anyContains(r, 'r.example.test')).toBe(false);
    }
  });

  it('U12: a proxy that turns TLS checks off in the repo .npmrc → warning, and its values never appear', async () => {
    const proxyHost = ['proxy', 'example', 'test'].join('.');
    for (const text of [`https-proxy=http://${proxyHost}:8080\nstrict-ssl=false\n`, `https-proxy=http://${proxyHost}:8080\n`, 'strict-ssl=false\n', `proxy=http://${proxyHost}:3128\n`]) {
      const r = await buildAudit(repo({ ...nodeApp(), '.npmrc': `save-exact=true\n${text}` }), deps());
      expect(r.warnings, text.slice(0, 12)).toEqual([SWAP_WARNING]);
      expect(anyContains(r, proxyHost)).toBe(false);
    }
  });

  it('U12: a CA file or certificate setting in the repo .npmrc → warning', async () => {
    for (const line of ['cafile=/tmp/evil-ca.pem', 'ca=MIIB-not-a-cert', 'cert=/tmp/c.pem', '  CAFILE = /tmp/evil-ca.pem']) {
      const r = await buildAudit(repo({ ...nodeApp(), '.npmrc': `${line}\n` }), deps());
      expect(r.warnings, line.trim().slice(0, 8)).toEqual([SWAP_WARNING]);
      expect(anyContains(r, 'evil-ca')).toBe(false);
    }
  });

  it('U12: any key outside the safe list warns (scripts, shells, prefix, cache, auth, `_` keys, sections, odd audit values)', async () => {
    const kv = (name: string) => `${name}${'='}abc`; // auth-like lines built at runtime (no secret-like literals in test/)
    for (const line of [
      'ignore-scripts=false', 'shell=/bin/evil', 'node-options=--require ./x.js', 'prefix=./evil', 'cache=./evil', 'globalconfig=./evil',
      kv('_auth' + 'Token'), kv('//registry.example.test/:_' + 'auth'), 'email=a@b.test', '[section]', 'audit=maybe', 'audit', 'save-exact[]=true',
      'some-future-key=1', '"save-exact"x=true',
    ]) {
      const r = await buildAudit(repo({ ...nodeApp(), '.npmrc': `fund=false\n${line}\n` }), deps());
      expect(r.warnings, line.slice(0, 14)).toEqual([SWAP_WARNING]);
      expect(anyContains(r, '/bin/evil')).toBe(false);
    }
  });

  it('U12: an .npmrc with only safe keys (and comments) gives no warning', async () => {
    const safe = [
      '# project settings', '; npm style comment', '', 'save-exact=true', 'save-prefix=~', 'engine-strict=true', 'fund=false', 'audit=false',
      'audit = true', 'package-lock=true', 'loglevel=warn', 'progress=false', 'legacy-peer-deps=true', 'lockfile-version=3', 'update-notifier=false',
      'color=false', '  save-exact = true  ', '"fund"=false',
    ].join('\r\n');
    const r = await buildAudit(repo({ ...nodeApp(), '.npmrc': `${safe}\n` }), deps());
    expect(r.warnings).toEqual([]);
  });

  it('Task 5 (item 5): keys that only make npm stricter give no warning (express .npmrc shape)', async () => {
    // express's .npmrc, written by hand
    const express = ['package-lock=false', 'min-release-age=7', 'ignore-scripts=true', 'allow-git=none'].join('\n');
    expect((await buildAudit(repo({ ...nodeApp(), '.npmrc': `${express}\n` }), deps())).warnings).toEqual([]);
    const stricter = ['ignore-scripts = true', 'IGNORE-SCRIPTS=TRUE', 'min-release-age=0', 'min-release-age = 30', 'allow-git=root', 'allow-git=all', 'allow-git = NONE',
      'strict-peer-deps=true', 'engine-strict=true'].join('\n');
    expect((await buildAudit(repo({ ...nodeApp(), '.npmrc': `${stricter}\n` }), deps())).warnings).toEqual([]);
  });

  it('Task 5 (item 5, adversarial): the same keys with values that are not stricter, and audit-level, still warn', async () => {
    for (const line of ['ignore-scripts=false', 'ignore-scripts=1', 'ignore-scripts', 'min-release-age=-1', 'min-release-age=7d', 'min-release-age=', 'allow-git=some',
      'strict-peer-deps=false', 'audit-level=none', 'audit-level=critical', 'before=2020-01-01']) {
      const r = await buildAudit(repo({ ...nodeApp(), '.npmrc': `ignore-scripts=true\n${line}\n` }), deps());
      expect(r.warnings, line).toEqual([SWAP_WARNING]);
    }
  });

  it('Task 5 fix round 1 (I5): a service with a port read as a published library gets a plain note', async () => {
    const files = {
      'pyproject.toml': '[project]\nname = "Flask"\ndependencies = ["werkzeug>=3"]\n',
      'app.py': 'def run(port=5000):\n    pass\n',
      '.github/workflows/publish.yaml': "on:\n  push:\n    tags: ['*']\njobs:\n  p:\n    runs-on: x\n    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n",
    };
    const r = await buildAudit(repo(files), deps());
    expect(r.notes).toContain("Flask listens on a port but looks like a published package, so pipegen didn't add container image or running-app (web) scan checks. If Flask is an app, add a start script or a Dockerfile and pipegen will treat it as one.");
    expect(r.wouldCreate.some((w) => w.what === 'docker')).toBe(false);
    // an app with a start script gets no such note
    const app = await buildAudit(repo(nodeApp()), deps());
    expect(app.notes.some((n) => n.includes('looks like a published package'))).toBe(false);
  });

  it('U11: the report says whether the reviewed list was unavailable', async () => {
    expect((await buildAudit(repo(nodeApp()), deps())).reviewedUnavailable).toBe(false);
    expect((await buildAudit(repo(nodeApp()), deps({ reviewedUnavailable: true }))).reviewedUnavailable).toBe(true);
  });

  it('M2: npm\'s default "no test specified" script is not offered as the tool on a starter-tests row', async () => {
    const files = nodeApp({ scripts: { test: 'echo "Error: no test specified" && exit 1', start: 'node index.js' }, devDependencies: {} });
    const bare = await buildAudit(repo(files), deps());
    expect(bare.profile.services[0].hasTests).toBe(false);
    for (const id of ['unit-tests', 'full-tests']) {
      const rows = rowsOf(bare, id);
      expect(rows.length, id).toBeGreaterThan(0);
      for (const w of rows) {
        expect(w.tool).toBeNull();
        expect(w.note).toBe('No tests found for app: pipegen would create starter tests.');
      }
    }
    const runner = tool('test-runner', ['unit-tests', 'full-tests']);
    const withTool = await buildAudit(repo(files), deps({ reviewed: [runner] }));
    for (const w of [...rowsOf(withTool, 'unit-tests'), ...rowsOf(withTool, 'full-tests')]) {
      expect(w.tool).toBe(runner);
      expect(w.note).toBe('No tests found for app: pipegen would create starter tests.');
    }
  });

  it('M5: the report says which folders the secrets scan skipped', async () => {
    const r = await buildAudit(repo(nodeApp()), deps());
    expect(r.notes).toContain('The secrets scan did not check dependency and build folders (node_modules, .venv, dist, build, vendor, target) or .git, so committed build output was not checked either.');
  });

  it.skipIf(process.getuid?.() === 0)('M7: an unreadable file (mode 000) gives a note, not a crash', async () => {
    const dir = repo({ ...nodeApp(), 'src/locked.ts': 'x\n' });
    chmodSync(join(dir, 'src/locked.ts'), 0o000);
    try {
      const r = await buildAudit(dir, deps());
      expect(r.notes).toContain("The secrets scan couldn't read 1 file (no permission, or it changed while being read); it was not checked.");
    } finally {
      chmodSync(join(dir, 'src/locked.ts'), 0o644);
    }
  });
});

// ---------- Plan U final review: M4 (image wording on packages), M10 (Review Focus 6's fixture) ----------

describe('buildAudit (Plan U final review)', () => {
  const RELEASE = 'on:\n  release:\n    types: [published]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n';
  const pkgFiles = (): Record<string, string> => ({
    'package.json': JSON.stringify({ name: 'lib', version: '1.0.0', scripts: { test: 'vitest run' }, devDependencies: { vitest: '1.0.0' } }),
    'package-lock.json': '{}\n', 'index.js': 'module.exports = 1;\n', '.github/workflows/release.yml': RELEASE,
  });
  const flatTerm = (r: AuditReport) => renderTerminal(r, { knownValues: [] }).replace(/\s+/g, ' ');

  it('M4: a package with nothing runnable gets release wording for signing and attestation, never image wording', async () => {
    const r = await buildAudit(repo(pkgFiles()), deps());
    const signing = r.coverage.find((c) => c.need.id === 'signing');
    const attestation = r.coverage.find((c) => c.need.id === 'attestation');
    expect(signing?.why).toBe('Without release signing, nothing proves that a published release came from this pipeline.');
    expect(attestation?.why).toBe('Without an attestation, nothing records how and where the release was built.');
    const t = flatTerm(r);
    expect(t).toContain('Release signing for lib');
    expect(t).not.toMatch(/image signing|deployed image|the image was built/i);
    // a runnable app keeps the image wording
    const app = await buildAudit(repo({ ...nodeApp(), '.github/workflows/release.yml': RELEASE }), deps());
    expect(app.coverage.find((c) => c.need.id === 'signing')?.why).toBe('Without image signing, nothing proves that a deployed image came from this pipeline.');
    expect(flatTerm(app)).toContain('Image signing for app');
  });

  it('M10 / Review Focus 6: .env, *.tfstate and .npmrc (built at runtime) are never counted or shown; every output lists the patterns', async () => {
    const mark = (k: string) => ['RF6', k, 'CONTENT', 'MARK'].join('_');
    const files: Record<string, string> = {
      ...nodeApp(), 'src/a.js': `// ${mark('SRC')}\n`,
      ['.e' + 'nv']: `${['DB', 'HOST'].join('_')}=${mark('ENV')}\n`,
      ['infra/prod.tf' + 'state']: JSON.stringify({ outputs: { db: { value: mark('TFSTATE') } } }) + '\n',
      ['.np' + 'mrc']: `# ${mark('NPMRC')}\n`,
    };
    const r = await buildAudit(repo(files), deps());
    // package.json, index.js and src/a.js only: the lockfile and the three secret files are left out
    expect(r.aiBundle.files).toBe(3);
    expect(r.aiBundle.topFolders).toEqual(['src']);
    for (const p of ['**/.env*', '**/*.tfstate', '**/.npmrc']) expect(r.aiBundle.excludedPatterns).toContain(p);
    const term = renderTerminal(r, { knownValues: [] });
    const md = renderMarkdown(r, { knownValues: [] });
    const json = renderJson(r, { knownValues: [] });
    for (const out of [term, md, json]) {
      for (const k of ['SRC', 'ENV', 'TFSTATE', 'NPMRC']) expect(out, k).not.toContain(mark(k));
    }
    const section = (t: string) => t.slice(t.indexOf('What the full setup would send to the AI'), t.indexOf('Permissions the full setup needs'));
    expect(section(term).replace(/\s+/g, ' ')).toContain('pipegen would send 3 files');
    for (const name of ['.env files', '.npmrc', '*.tfstate']) expect(section(term), name).toContain(name);
    expect(section(md)).toContain('pipegen would send 3 files');
    for (const p of ['\\*\\*/.env\\*', '\\*\\*/\\*.tfstate', '\\*\\*/.npmrc']) expect(section(md), p).toContain(p);
  });
});

describe('buildAudit: Plan P Task 8 (choosing, skipped checks, settings)', () => {
  // A fixture list: Task 6 adds the real entries later (ruling P14), so these tests build their own.
  const LIST = [
    tool('biome', ['lint', 'format'], ['node']), tool('prettier', ['format'], ['node']), tool('ruff', ['lint'], ['python']),
    tool('ruff-format', ['format'], ['python']), tool('mypy', ['type-check'], ['python']), tool('betterleaks', ['secrets']),
    tool('vitest-coverage', ['coverage'], ['node']), tool('jscpd', ['duplication']),
  ];
  const monorepo = () => repo({
    'web/package.json': JSON.stringify({ name: 'web', scripts: { start: 'node index.js' }, devDependencies: { typescript: '5.4.5' } }),
    'web/package-lock.json': '{}\n', 'web/index.js': 'console.log(1);\n', 'web/tsconfig.json': '{}\n',
    'web/Dockerfile': 'FROM node:20\n',
    'py/pyproject.toml': '[project]\nname = "py"\n', 'py/app.py': 'print(1)\n', 'py/Dockerfile': 'FROM python:3.12\n',
  });

  it('audit: node + python monorepo → per-service rows and picks; ruff in py/ doesn\'t cover web', async () => {
    const r = await buildAudit(monorepo(), deps({ reviewed: LIST }));
    const lint = r.wouldAdd.filter((w) => w.need.id === 'lint' && w.need.layer === 'push');
    const toolOf = (service: string) => lint.find((w) => w.need.service === service)?.tool as { id?: string } | null | undefined;
    const services = r.profile.services.map((s) => `${s.name}:${s.language}`).sort();
    expect(services).toEqual(['py:python', 'web:node']);
    expect(toolOf('py')?.id).toBe('ruff');
    expect(toolOf('web')?.id).toBe('biome');
    const format = r.wouldAdd.filter((w) => w.need.id === 'format' && w.need.layer === 'push');
    expect((format.find((w) => w.need.service === 'py')?.tool as { id?: string } | null)?.id).toBe('ruff-format');
    expect((format.find((w) => w.need.service === 'web')?.tool as { id?: string } | null)?.id).toBe('biome');
    // the Python type checker is for py only: web has no mypy row
    expect(r.wouldAdd.filter((w) => w.need.id === 'type-check' && w.need.service === 'web').every((w) => w.tool === null || (w.tool as { kind?: string }).kind === 'repo-tool')).toBe(true);
    // the Python picks never reach the Node service
    for (const w of r.wouldAdd.filter((x) => x.need.service === 'web')) {
      expect(JSON.stringify(w.tool ?? null)).not.toMatch(/"id":"(ruff|ruff-format|mypy)"/);
    }
  });

  it('audit: a pick with an unavailable reviewed list keeps the "list unavailable" note', async () => {
    const r = await buildAudit(monorepo(), deps({ reviewed: [], reviewedUnavailable: true }));
    const lint = r.wouldAdd.find((w) => w.need.id === 'lint');
    expect(lint?.tool).toBeNull();
    expect(lint?.note).toBe("pipegen's reviewed tool list couldn't be loaded, so it has no tool to add here");
  });

  it('audit: a null pick keeps its own note when the reviewed list is unavailable (Task 9)', async () => {
    const r = await buildAudit(repo({ ...nodeApp(), 'deny.toml': '' }), deps({ reviewed: [], reviewedUnavailable: true }));
    const licences = r.wouldAdd.find((w) => w.need.id === 'licences');
    expect(licences?.tool).toBeNull();
    expect(licences?.note).toBe('cargo-deny: a deny.toml is already in the repo (suggestion only)');
    // a null pick that only lacks its entry still reads "list unavailable"
    const scan = r.wouldAdd.find((w) => w.need.id === 'secrets');
    expect(scan?.note).toBe("pipegen's reviewed tool list couldn't be loaded, so it has no tool to add here");
  });

  it('audit: a missing reviewed entry gives suggestion only with the rule\'s reason', async () => {
    const r = await buildAudit(repo(nodeApp()), deps({ reviewed: [] }));
    const found = r.wouldAdd.find((w) => w.need.id === 'secrets');
    expect(found?.tool).toBeNull();
    expect(found?.note).toContain('not on the reviewed list');
    expect(found?.also).toEqual([]);
  });

  it('audit: skipped lists every Plan P check that doesn\'t apply, with its why', async () => {
    const r = await buildAudit(repo(nodeApp()), deps());
    const flat = r.skipped.flatMap((g) => g.categories.map((c) => `${c}|${g.why}`));
    expect(flat).toContain('fuzzing|no fuzz targets found');
    expect(flat).toContain('dockerfile-lint|no Dockerfile found');
    expect(flat).toContain('publishing|no workflow publishes a package');
    expect(new Set(r.skipped.map((g) => g.why)).size).toBe(r.skipped.length);
  });

  it('audit: wouldSet has sha-pinning and Dependabot alerts on every repo; secret scanning public only; private gets the paid note, no public wording', async () => {
    const pub = await buildAudit(repo(nodeApp()), deps());
    expect(pub.wouldSet.map((x) => x.setting)).toEqual(['sha-pinning', 'dependabot-alerts', 'secret-scanning']);
    expect(pub.wouldSet[2]?.why).toContain('push protection');
    const priv = await buildAudit(repo(nodeApp()), deps({ context: { private: true, ownerType: 'User', plan: 'free', defaultBranch: 'main' }, capabilities: bareCaps }));
    expect(priv.wouldSet.map((x) => x.setting)).toEqual(['sha-pinning', 'dependabot-alerts', 'secret-scanning']);
    expect(priv.wouldSet[2]?.why).toContain('Needs GitHub Secret Protection (a paid add-on)');
    expect(priv.wouldSet[2]?.why).not.toMatch(/push protection|public/i);
  });

  it('audit: estimates use jobCategories with JOB_GROUP (no job for update-config, publishing, egress, fuzzing)', async () => {
    const r = await buildAudit(repo(nodeApp()), deps({ reviewed: LIST }));
    const jobs = vi.mocked(estimate).mock.calls.at(-1)?.[1] as Record<string, string[]>;
    expect(jobs).toEqual(jobCategories(floorNeeds(r.profile, allCaps)));
    const all = Object.values(jobs).flat();
    for (const id of ['update-config', 'publishing', 'egress', 'fuzzing']) expect(all, id).not.toContain(id);
    // the Task 8 rows don't add jobs: picking a tool never changes the estimate
    expect(r.wouldAdd.some((w) => w.need.id === 'update-config')).toBe(true);
  });
});

