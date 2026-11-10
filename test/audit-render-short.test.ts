// Plan J J4 (DECISIONS #123): the short terminal report by default, the full one behind `verbose`; caveats only where they
// apply; every warning and every secret-like finding stays visible (ruling B5). Real audits run on invented repos of
// three kinds (a static Next.js site, a Python tool published to PyPI, a Node API in a container), so no rule is tuned to
// one shape.
import { afterEach, describe, expect, it } from 'vitest';
import { EXCLUDED_PATTERNS, GIT_EXCLUDED_LINES } from '../src/ai/redact.js';
import { buildAudit, LIMIT, SECRET_CHECK, type AuditDeps, type AuditReport, type LocalAudit } from '../src/audit/model.js';
import type { Coverage } from '../src/audit/coverage.js';
import { buildShortDoc, LIMIT_CATEGORIES, rankGaps, shortParts } from '../src/audit/render-short.js';
import { PART_TITLE, type PartId } from '../src/audit/parts.js';
import { cantSeeFor, CANT_SEE, ctxFor, layerViews, renderJson, renderLocalTerminal, renderMarkdown, renderTerminal, type RenderOptions } from '../src/audit/render.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import type { Capabilities, ProjectType, RepoProfile, ServiceType } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { CHECK, freePrivateReport, need, reviewedTool, TREE } from './fixtures/audit-report.js';

afterEach(cleanupRepos);

const NOW = Date.parse('2026-10-27T12:00:00Z');
const SHORT: RenderOptions = { knownValues: [], now: () => NOW };
const FULL: RenderOptions = { ...SHORT, verbose: true };
const lines = (t: string) => t.split('\n');
/** Terminal text with the 100-column wrapping undone, for content checks. */
const flat = (t: string) => t.replace(/\n {2,}(?![-⚠] )/g, ' ');

// ---------- three invented repos ----------

const CHECKOUT = 'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683';
const NODE_CI = `name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ${CHECKOUT}
      - run: npm ci
      - run: npm test
`;
const PY_CI = `name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ${CHECKOUT}
      - run: pip install tox
      - run: tox
`;
const PY_RELEASE = `name: release
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: ${CHECKOUT}
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
`;

/** A static site built with Next.js pages and `output: 'export'`, tested in CI. */
const STATIC_NEXT_PAGES: Record<string, string> = {
  'package.json': JSON.stringify({ name: 'site', scripts: { build: 'next build', test: 'vitest run' }, dependencies: { next: '15.0.0' } }),
  'package-lock.json': '{}\n',
  'next.config.mjs': "export default { output: 'export' };\n",
  'src/pages/index.tsx': 'export default function Home() { return null; }\n',
  '.github/workflows/ci.yml': NODE_CI,
};
/** A Python tool published to PyPI, tested with tox. */
const PYTHON_TOOL: Record<string, string> = {
  'pyproject.toml': '[project]\nname = "tool"\nversion = "1.0.0"\n[project.scripts]\ntool = "tool.main:main"\n',
  'tool/main.py': 'def main():\n    print(1)\n',
  'tests/test_main.py': 'def test_x():\n    assert True\n',
  'tox.ini': '[tox]\nenv_list = py312\n',
  '.github/workflows/ci.yml': PY_CI,
  '.github/workflows/release.yml': PY_RELEASE,
};
/** A Node API with express, a Dockerfile and a test run in CI. */
const NODE_CONTAINER: Record<string, string> = {
  'package.json': JSON.stringify({ name: 'api', scripts: { start: 'node index.js', test: 'vitest run' }, dependencies: { express: '4.0.0' } }),
  'package-lock.json': '{}\n',
  'index.js': 'require("express")().listen(process.env.PORT || 3000);\n',
  Dockerfile: 'FROM node:22\nCOPY . .\nCMD ["node","index.js"]\n',
  '.github/workflows/ci.yml': NODE_CI,
};

const bare: Capabilities = {
  branchProtection: false, environments: true, envRequiredReviewers: false, deploymentBranchPolicies: false,
  attestations: false, codeScanning: false, keylessSigningAllowed: false,
};
const denied = () => Object.assign(new Error('not allowed'), { status: 403, response: { status: 403, data: {}, headers: {} } });
const gh = {
  rest: {
    activity: { listRepoEvents: async () => ({ data: [], headers: {} }) }, pulls: { list: async () => ({ data: [] }) },
    codeScanning: { getDefaultSetup: async () => { throw denied(); } },
    actions: {
      listRepoWorkflows: async () => ({ data: { total_count: 0, workflows: [] } }),
      listWorkflowRuns: async () => ({ data: { total_count: 0, workflow_runs: [] } }),
      listJobsForWorkflowRun: async () => ({ data: { total_count: 0, jobs: [] } }),
    },
  },
} as unknown as AuditDeps['gh'];

async function auditOf(files: Record<string, string>): Promise<AuditReport> {
  const dir = makeTempDir();
  writeIn(dir, '.git/config', '[remote "origin"]\n\turl = https://github.com/o/r.git\n');
  for (const [rel, body] of Object.entries(files)) writeIn(dir, rel, body);
  return buildAudit(dir, {
    gh, anonymous: false, context: { private: false, ownerType: 'User', plan: 'free', defaultBranch: 'main' }, capabilities: bare,
    permissions: [], reviewed: [], now: () => NOW, budget: newRateBudget(),
  });
}

/** The "- label ..." lines of the Fix first and Consider lists. */
function listLines(t: string): string[] {
  return lines(t).filter((l) => l.startsWith('  - '));
}

describe('short report: invented repos of different kinds', () => {
  it('static-next-pages fixture → within the line budget', async () => {
    const r = await auditOf(STATIC_NEXT_PAGES);
    const t = renderTerminal(r, SHORT);
    expect(lines(t).length, t).toBeLessThanOrEqual(32);
    // the Type line carries the evidence
    const type = lines(t).find((l) => l.startsWith('Type:')) as string;
    expect(type).toContain('site: static-site');
    expect(t).toContain('output: "export"');
    // what a static site doesn't need: one line, the reasons are in --verbose
    expect(lines(t).filter((l) => l.startsWith('Not needed here:'))).toHaveLength(1);
    expect(flat(renderTerminal(r, FULL))).toMatch(/Container image build/);
    // no check appears twice in the parts
    const checks = shortParts(r).flatMap((p) => [...p.fix, ...p.consider].map((g) => `${g.check}|${g.services.join(',')}`));
    expect(new Set(checks).size).toBe(checks.length);
    // the layout, in order
    const at = ['Type:', '1 On your computer', '2 Every pull request', 'Not needed here:', 'What now?', '  Setup cost:', '  More: pipegen --verbose'].map((s) => t.indexOf(s));
    expect(at.every((i) => i >= 0), t).toBe(true);
    expect(at).toEqual([...at].sort((a, b) => a - b));
    expect(lines(t)[lines(t).length - 1]).toBe('  More: pipegen --verbose (file, line, how to fix) · --out report.md');
    // nothing the full report says about the checks by layer or the caveats
    expect(t).not.toContain('Checks by layer');
    expect(t).not.toContain("What this audit can't see");
  });

  it("verbose → today's full doc minus caveats that don't apply", async () => {
    const r = await auditOf(STATIC_NEXT_PAGES);
    const t = renderTerminal(r, FULL);
    for (const section of ['Verdict:', 'Checks by layer', 'What pipegen would add', 'Costs of the full setup', "What this audit can't see", 'Next step']) expect(t).toContain(section);
    // the Type line is in the full report too
    expect(t).toContain('output: "export"');
    // a static site with a Node CI has none of these caveats
    const caveats = t.slice(t.indexOf("What this audit can't see"));
    for (const word of [/tox/i, /nox/i, /Kubernetes/, /Renovate/, /PyPI/, /\.vue/, /Dockerfile RUN/, /ENTRYPOINT/, /pre-commit hook pinned/]) {
      expect(caveats, String(word)).not.toMatch(word);
    }
    // the workflow limits do apply to it
    expect(t).toContain('Workflows limited by');
    expect(t).toContain('Commands given through a variable');
  });

  it('python tool published to PyPI → tox and PyPI caveats shown, container and Kubernetes ones not', async () => {
    const r = await auditOf(PYTHON_TOOL);
    const full = renderTerminal(r, FULL);
    expect(full).toContain('`tox` counts as your own test run');
    expect(full).toContain('PyPI publish action');
    const caveats = full.slice(full.indexOf("What this audit can't see"));
    for (const word of ['Kubernetes', 'Renovate', '.vue', 'ENTRYPOINT']) expect(caveats, word).not.toContain(word);
    const short = renderTerminal(r, SHORT);
    expect(lines(short).find((l) => l.startsWith('Type:'))).toMatch(/tool: library/);
    // a library builds no image: no container check is asked for in any part
    const asked = short.slice(0, short.indexOf('Not needed here:'));
    expect(asked).not.toMatch(/Container image|Running-app scan/);
    expect(lines(short).length).toBeLessThanOrEqual(32);
  });

  it('node container service → server and container, no Dockerfile or DAST in "Not needed here"', async () => {
    const r = await auditOf(NODE_CONTAINER);
    const short = renderTerminal(r, SHORT);
    expect(lines(short).find((l) => l.startsWith('Type:'))).toMatch(/api: server, container/);
    const skipped = lines(short).find((l) => l.startsWith('Not needed here:')) as string;
    expect(skipped).not.toMatch(/Dockerfile lint/);
    expect(skipped).not.toMatch(/Running-app scan/);
    const full = renderTerminal(r, FULL);
    expect(full).toContain('Dockerfile RUN lines count only');
    expect(full.slice(full.indexOf("What this audit can't see"))).not.toContain('PyPI');
    expect(lines(short).length).toBeLessThanOrEqual(32);
  });

  it('markdown and json unchanged except cantSee', async () => {
    const r = await auditOf(STATIC_NEXT_PAGES);
    const json = JSON.parse(renderJson(r, SHORT)) as Record<string, unknown>;
    // every key of the report is still there, plus cantSee
    expect(Object.keys(json).sort()).toEqual([...Object.keys(r), 'cantSee'].sort());
    expect(json.cantSee).toEqual(cantSeeFor(r.profile));
    expect((json.cantSee as string[]).length).toBeLessThan(CANT_SEE.length);
    expect((json.cantSee as string[]).join(' ')).not.toMatch(/tox|Kubernetes|Renovate|PyPI|\.vue/);
    // the data is the full data, whatever the terminal option
    expect(json.coverage).toHaveLength(r.coverage.length);
    expect(json.skipped).toHaveLength(r.skipped.length);
    expect(renderJson(r, FULL)).toBe(renderJson(r, SHORT));
    // Markdown keeps every section the full terminal report has, whatever the option
    const md = renderMarkdown(r, SHORT);
    expect(renderMarkdown(r, FULL)).toBe(md);
    for (const title of ['Checks by layer', 'What pipegen would add', 'Costs of the full setup (estimates)', "What this audit can't see", 'Next step']) expect(md).toContain(`## ${title}`);
    expect(md.slice(md.indexOf("## What this audit can't see"))).not.toMatch(/tox|Kubernetes|Renovate|PyPI/i);
  });
});

describe('short report: what must never be hidden (ruling B5)', () => {
  const report = () => freePrivateReport(EXCLUDED_PATTERNS);
  const RATE = { text: "GitHub's rate limit was reached, so pipegen couldn't read everything it needs from GitHub." };
  const ANON = { text: 'Without a GitHub token, pipegen reads public data only and is rate-limited.' };
  const SWAP = { text: 'This repo could change which pipegen runs. Run pipegen from outside the repo, from the npm registry, with:', command: 'npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./repo' };

  it('short: warnings, quick-check findings and the rate-limit line come first', () => {
    const r = { ...report(), warnings: [RATE, ANON, SWAP], wouldAddNote: 'These picks are based on incomplete GitHub data (rate limit).' };
    const t = flat(renderTerminal(r, SHORT));
    const at = (s: string) => t.indexOf(s);
    for (const s of [RATE.text, ANON.text, SWAP.text, SWAP.command, 'incomplete GitHub data', 'Secret-like text on disk: 2 files (.env, config/dev.json; --verbose for all)']) expect(at(s), s).toBeGreaterThan(-1);
    // all of it before the type and the parts
    const firstList = Math.min(...['Type:', '1 On your computer', '2 Every pull request'].map(at).filter((i) => i >= 0));
    for (const s of [RATE.text, ANON.text, SWAP.command, 'Secret-like text on disk', 'incomplete GitHub data']) expect(at(s), s).toBeLessThan(firstList);
    // the command stays on one line of its own, unwrapped
    expect(lines(renderTerminal(r, SHORT))).toContain(`    ${SWAP.command}`);
    // values are never shown, only the file names and the count
    expect(t).not.toMatch(new RegExp(['AK', 'IA'].join('') + '|' + ['gh', 'p_'].join('')));
  });

  it('short: the secret-like line names at most three files and points to --verbose', () => {
    const r = { ...report(), [TREE]: ['a.env', 'b.env', 'c.env', 'd.env', 'e.env'].map((file) => ({ file, rule: 'generic-api-key' })) };
    const t = renderTerminal(r, SHORT);
    expect(t).toContain('⚠ Secret-like text on disk: 5 files (a.env, b.env, c.env; --verbose for all)');
    expect(t).not.toContain('d.env');
    expect(renderTerminal(r, FULL)).toContain('d.env');
  });

  it('short: no secret line when nothing was found, and the quick-check text only in verbose', () => {
    const r = { ...report(), [TREE]: [] };
    const t = renderTerminal(r, SHORT);
    expect(t).not.toContain('Secret-like text');
    expect(t).not.toContain("It doesn't look for");
    expect(t).not.toContain('not a secret scan');
    expect(renderTerminal(r, FULL)).toContain('not a secret scan');
    // with findings, the scope text appears once in the full report
    const full = renderTerminal(report(), FULL);
    expect(full.split("It doesn't look for").length - 1).toBe(1);
  });

  it('short: unknown rows → one "Couldn\'t tell" line', () => {
    const r = report(); // one unknown row (DAST)
    const t = renderTerminal(r, SHORT);
    expect(lines(t).filter((l) => l.startsWith("Couldn't tell"))).toEqual(["Couldn't tell: 1 check (--verbose)"]);
    const more: Coverage = { need: need('push', 'sbom', 'shop-api'), status: 'unknown', why: 'unreadable.' };
    const t2 = renderTerminal({ ...r, coverage: [...r.coverage, more, { ...more, need: need('merge', 'sbom', 'shop-api') }] }, SHORT);
    // the same check on push and merge is one check
    expect(lines(t2).filter((l) => l.startsWith("Couldn't tell"))).toEqual(["Couldn't tell: 2 checks (--verbose)"]);
    const none = renderTerminal({ ...r, coverage: r.coverage.filter((c) => c.status !== 'unknown') }, SHORT);
    expect(none).not.toContain("Couldn't tell");
  });

  it('short: the two never-sent lines J1 added are in Markdown and JSON', () => {
    const r = report();
    const md = renderMarkdown(r, SHORT);
    expect(md).toContain('files your .gitignore lists');
    expect(md).toContain("files that aren't committed, when pipegen can read git's file list");
    const j = JSON.parse(renderJson(r, SHORT)) as { aiBundle: { gitExcluded: string[] } };
    expect(j.aiBundle.gitExcluded).toEqual(GIT_EXCLUDED_LINES.map((l) => l.replace(/^- /, '')));
  });
});

describe('short report: ranking, merging and plan limits', () => {
  const report = () => freePrivateReport(EXCLUDED_PATTERNS);

  it('rankGaps: serious first, push and merge rows of one check are one line, the worst status wins', () => {
    const r = report();
    const g = rankGaps(r);
    const checks = [...g.fixFirst, ...g.consider].map((x) => `${x.check}|${x.services.join(',')}`);
    expect(new Set(checks).size).toBe(checks.length);
    // the secret scan is missing on push and merge and before commit: two lines (the hook is its own), never three
    expect(g.fixFirst.filter((x) => x.check.startsWith('Secret scan')).map((x) => x.check).sort()).toEqual(['Secret scan', 'Secret scan before each commit']);
    // the dependency check is partial on push: one line; pipegen's own gate is in Consider, not Fix first
    expect(g.fixFirst.some((x) => x.check === 'Dependency check' && x.services.join() === 'shop-api')).toBe(true);
    expect(g.consider.some((x) => x.check === 'Merge gate (pipegen)')).toBe(true);
    expect(g.fixFirst.some((x) => x.check === 'Merge gate (pipegen)')).toBe(false);
    // the tool the setup would add is named
    expect(g.fixFirst.find((x) => x.check === 'Code scan (SAST)')?.tool).toBe('semgrep');
  });

  it('rankGaps: worst status wins across push and merge (partial on push, missing on merge → missing)', () => {
    const r = report();
    const rows: Coverage[] = [
      { need: need('push', 'lint', 'a'), status: 'partial', why: 'partial on push.' },
      { need: need('merge', 'lint', 'a'), status: 'missing', why: 'missing on merge.' },
    ];
    const g = rankGaps({ ...r, coverage: rows, wouldAdd: [] });
    expect(g.fixFirst).toEqual([{ check: 'Lint', services: ['a'], why: 'missing on merge.', tool: null }]);
    const t = renderTerminal({ ...r, coverage: rows, wouldAdd: [] }, SHORT);
    expect(t).toContain('✗ Lint for a');
    expect(t).not.toContain('(partial)');
  });

  it('rankGaps: the same check on several services is one line naming them', () => {
    const r = report();
    const rows: Coverage[] = ['a', 'b', 'c'].map((s) => ({ need: need('push', 'sast', s), status: 'missing', why: 'No code scan.' }));
    const g = rankGaps({ ...r, coverage: rows, wouldAdd: [] });
    expect(g.fixFirst).toHaveLength(1);
    expect(g.fixFirst[0]?.services).toEqual(['a', 'b', 'c']);
    expect(renderTerminal({ ...r, coverage: rows, wouldAdd: [] }, SHORT)).toContain('Code scan (SAST) for a, b and c');
  });

  it('two services, node and python, missing lint → each names its own tool', () => {
    const r = report();
    const rows: Coverage[] = ['web', 'api'].map((s) => ({ need: need('push', 'lint', s), status: 'missing', why: 'No lint.' }));
    const eslint = reviewedTool('eslint', 'eslint/eslint', 'v9.0.0', ['lint']);
    const ruff = reviewedTool('ruff', 'astral-sh/ruff-action', 'v3.0.0', ['lint']);
    const wouldAdd = [
      { need: rows[0]!.need, status: 'missing' as const, tool: eslint, also: [], note: 'reviewed tool' },
      { need: rows[1]!.need, status: 'missing' as const, tool: ruff, also: [], note: 'reviewed tool' },
    ];
    const g = rankGaps({ ...r, coverage: rows, wouldAdd });
    const all = [...g.fixFirst, ...g.consider];
    expect(all.map((x) => `${x.services.join(',')}=${x.tool}`).sort()).toEqual(['api=ruff', 'web=eslint']);
    const t = renderTerminal({ ...r, coverage: rows, wouldAdd }, SHORT);
    expect(t).toContain('Lint for web [eslint]');
    expect(t).toContain('Lint for api [ruff]');
  });

  it('two node services, same tool → one line, one tool', () => {
    const r = report();
    const rows: Coverage[] = ['web', 'api'].map((s) => ({ need: need('push', 'lint', s), status: 'missing', why: 'No lint.' }));
    const eslint = reviewedTool('eslint', 'eslint/eslint', 'v9.0.0', ['lint']);
    const wouldAdd = rows.map((c) => ({ need: c.need, status: 'missing' as const, tool: eslint, also: [], note: 'reviewed tool' }));
    const g = rankGaps({ ...r, coverage: rows, wouldAdd });
    const all = [...g.fixFirst, ...g.consider];
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ services: ['web', 'api'], tool: 'eslint' });
    const t = renderTerminal({ ...r, coverage: rows, wouldAdd }, SHORT);
    expect(t.split('\n').filter((l) => l.includes('eslint'))).toHaveLength(1);
  });

  it('short: a part shows at most two lines of fix-first checks, with the count of the rest; the summary counts all', () => {
    const r = report();
    const ids = ['secrets', 'sast', 'deps', 'unit-tests', 'full-tests', 'lint', 'coverage', 'dead-code', 'duplication', 'iac', 'licences', 'dockerfile-lint', 'workflow-lint'];
    const rows: Coverage[] = ids.map((id) => ({ need: need('push', id), status: 'missing', why: `No ${id}.` }));
    const t = renderTerminal({ ...r, coverage: rows, wouldAdd: [] }, SHORT);
    const part = lines(t).slice(lines(t).findIndex((l) => l.startsWith('2 Every pull request')) + 1);
    const fixLines = part.slice(0, part.findIndex((l) => !l.startsWith('  ✗ ') && !l.startsWith('    ')));
    expect(fixLines.length).toBeLessThanOrEqual(2);
    const shown = fixLines.join(' ').match(/and (\d+) more \(--verbose\)/);
    expect(shown, t).not.toBeNull();
    const visible = fixLines.join(' ').replace(/ and \d+ more \(--verbose\)/, '').split('; ').length;
    expect(visible + Number(shown?.[1])).toBe(rankGaps({ ...r, coverage: rows, wouldAdd: [] }).fixFirst.length);
    expect(lines(t)[1]).toMatch(/^13 to fix /);
    expect(shortParts({ ...r, coverage: rows, wouldAdd: [] })[1]?.fix).toHaveLength(ids.length);
  });

  it('short: a check is "already good" only when every row of it is covered (rate-stop shape, and one service covered but another missing)', () => {
    const r = report();
    const goodLine = (rows: Coverage[]) => {
      const t = flat(renderTerminal({ ...r, coverage: rows, wouldAdd: [] }, SHORT));
      return { t, good: shortParts({ ...r, coverage: rows, wouldAdd: [] }).flatMap((p) => p.good) };
    };
    // shape 1: under a rate stop the push row of a check is unknown while the merge row is covered
    const rate = goodLine([
      { need: need('push', 'sast', 'a'), status: 'unknown', why: 'Could not read the run history.' },
      { need: need('merge', 'sast', 'a'), status: 'covered', by: 'codeql', why: 'ok.' },
      { need: need('push', 'secrets'), status: 'covered', by: 'betterleaks', why: 'ok.' },
    ]);
    expect(rate.good).toContain('Secret scan');
    expect(rate.good).not.toContain('Code scan (SAST)');
    expect(rate.t).toContain("Couldn't tell: 1 check");
    // shape 2: covered on one service, missing on another
    const two = goodLine([
      { need: need('push', 'deps', 'web'), status: 'covered', by: 'osv', why: 'ok.' },
      { need: need('push', 'deps', 'api'), status: 'missing', why: 'No dependency scan.' },
      { need: need('push', 'lint', 'web'), status: 'covered', by: 'eslint', why: 'ok.' },
    ]);
    expect(two.good).toContain('Lint');
    expect(two.good).not.toContain('Dependency check');
    // shape 3: covered on one service, unknown on another
    const three = goodLine([
      { need: need('push', 'lint', 'web'), status: 'covered', by: 'eslint', why: 'ok.' },
      { need: need('push', 'lint', 'api'), status: 'unknown', why: 'Could not tell.' },
    ]);
    expect(three.good).toEqual([]);
    expect(lines(three.t)[1]).toMatch(/^0 to fix · 0 to consider · 0 already good · 1 couldn't tell$/);
    expect(three.t).not.toContain('✓');
  });

  it('short: a plan limit is printed only when one of its checks is in Fix first', () => {
    const r = report();
    // the fixture has a code scan gap (serious) and no merge lock; the gate is pipegen's own, never serious
    const t = renderTerminal(r, SHORT);
    expect(flat(t)).toContain(LIMIT.noCodeScanning);
    expect(t).not.toContain(LIMIT.noLock);
    expect(t).not.toContain(LIMIT.noAttestations);
    expect(t).not.toContain(LIMIT.noApprovals);
    // with the code scan covered, its limit goes
    const covered = r.coverage.map((c): Coverage => (c.need.id === 'sast' ? { ...c, status: 'covered', why: 'ok.' } : c));
    expect(renderTerminal({ ...r, coverage: covered }, SHORT)).not.toContain(LIMIT.noCodeScanning);
    // the full report lists them all
    for (const l of [LIMIT.noLock, LIMIT.noAttestations, LIMIT.noApprovals, LIMIT.noCodeScanning]) expect(flat(renderTerminal(r, FULL))).toContain(l);
  });

  it('LIMIT_CATEGORIES: every plan limit names the checks it blocks', () => {
    expect(Object.keys(LIMIT_CATEGORIES).sort()).toEqual(Object.keys(LIMIT).sort());
    expect(LIMIT_CATEGORIES).toMatchObject({
      noLock: ['gate'], fakeGate: ['gate'], noSigning: ['signing'], noReleaseSigning: ['signing'], noAttestations: ['attestation'],
      noCodeScanning: ['sast', 'scorecard'], noApprovals: ['deploy-verify'],
    });
  });

  it('Type line: unsure and overridden services say so', () => {
    const r = report();
    const svc = r.profile.services[0] as RepoProfile['services'][number];
    const withType = (projectType: NonNullable<RepoProfile['services'][number]['projectType']>): AuditReport => ({ ...r, profile: { ...r.profile, services: [{ ...svc, projectType }] } });
    const unsure = renderTerminal(withType({ types: ['server'], unsure: true, evidence: ['looks like a static site, but it has the server signs above'] }), SHORT);
    expect(unsure).toContain('Type: shop-api: server (unsure:');
    // one line per service, cut at the width (the whole text is in --verbose)
    expect(lines(unsure).filter((l) => l.startsWith('Type:'))).toHaveLength(1);
    // an unsure library, or a folder that is not standalone, is not treated as a server, and the line must not say it is
    for (const types of [['library'], ['library', 'static-site']] as const) {
      const lib = renderTerminal(withType({ types: [...types], unsure: true, evidence: ['no run script'] }), SHORT);
      expect(flat(lib)).toContain('(unsure: --type sets it)');
      expect(lib).not.toContain('treats it as a server');
    }
    const set = renderTerminal(withType({ types: ['static-site'], unsure: false, overridden: true, evidence: ['set to static-site by you'] }), SHORT);
    expect(set).toContain('Type: shop-api: static-site (set by you) — set to static-site by you');
    // evidence is cut to three pieces in the short report, whole in the full one
    const many = withType({ types: ['server'], unsure: false, evidence: ['e1', 'e2', 'e3', 'e4', 'e5'] });
    expect(renderTerminal(many, SHORT)).toContain('e1; e2; e3; and 2 more (--verbose)');
    expect(renderTerminal(many, FULL)).toContain('e1; e2; e3; e4; e5');
  });

  it('buildShortDoc: a Doc whose terminal lines are the report', async () => {
    const r = report();
    const doc = buildShortDoc(r, ctxFor('terminal', SHORT, false, r.profile.services));
    expect(doc.title).toBe('pipegen audit: acme/shop-api');
    expect(doc.terminal?.join('\n')).toBe(renderTerminal(r, SHORT));
  });

  it('short: hostile values are cleaned like the full report', () => {
    const r = report();
    const bad = '\u001b[31mred\u202e';
    const rows: Coverage[] = [
      { need: need('push', 'custom-check', `svc${bad}`), status: 'missing', why: `Why ${bad}.` },
      { need: need('push', `good-check${bad}`), status: 'covered', why: 'ok.' },
    ];
    const t = renderTerminal({ ...r, coverage: rows, wouldAdd: [], warnings: [{ text: `warn ${bad}` }] }, SHORT);
    expect(t).not.toContain('\u001b');
    expect(t).not.toContain('\u202e');
  });
});

describe('full report plumbing (S7, Owner choice 6)', () => {
  const report = () => freePrivateReport(EXCLUDED_PATTERNS);

  it('credit: a credited row reads as its credit in the full report, and JSON keeps it whole', () => {
    const r = report();
    const long = `CI runs the same tools as your hooks: ${'x'.repeat(260)}`;
    const credited: Coverage = { need: need('push', 'hooks-ci'), status: 'covered', by: 'pre-commit', why: 'ordinary why.', credit: long, creditKind: 'hooks-ci' };
    const rr = { ...r, coverage: r.coverage.map((c) => (c.need.layer === 'push' && c.need.id === 'hooks-ci' ? credited : c)) };
    const t = renderTerminal(rr, FULL);
    expect(t).toContain('CI runs the same tools as your hooks');
    expect(t).not.toContain('ordinary why.');
    const j = JSON.parse(renderJson(rr, SHORT)) as { coverage: { credit?: string }[] };
    expect(j.coverage.find((c) => c.credit !== undefined)?.credit).toBe(long);
  });

  it('CANT_SEE: each caveat shows only for a repo it applies to', async () => {
    const quiet = (await auditOf({ 'package.json': JSON.stringify({ name: 'lib', main: 'index.js' }), 'index.js': 'module.exports = 1;\n' })).profile;
    const texts = cantSeeFor(quiet);
    expect(texts).toContain('Repo settings on GitHub (required checks, secret scanning, the default token permissions) aren\'t read, so pipegen can\'t say whether they are already on.');
    // no workflow, no hooks, no Python, no Docker: only the always-on limits remain
    expect(texts.length).toBeLessThan(5);
    const everything = report().profile;
    const all: RepoProfile = {
      ...everything, precommit: 'pre-commit', hasCompose: true,
      repoFiles: { ...everything.repoFiles, renovate: 'renovate.json', kubernetes: true },
      existingWorkflows: everything.existingWorkflows.map((w) => ({ ...w, publishes: ['pypi' as const] })),
      services: everything.services.map((s) => ({ ...s, language: 'python' as const, alsoLanguages: ['node' as const], dockerfile: 'Dockerfile', quality: { ...s.quality, uiFrameworks: ['vue' as const] } })),
    };
    expect(cantSeeFor(all)).toEqual(CANT_SEE.map((x) => x.text));
  });

  it('local-only report shows the Type lines', () => {
    const r = report();
    const svc = r.profile.services[0] as RepoProfile['services'][number];
    const profile = { ...r.profile, services: [{ ...svc, projectType: { types: ['static-site' as const], unsure: false, evidence: ['output: "export" in next.config.mjs'] } }] };
    const l: LocalAudit = { profile, commit: null, [TREE]: [], [CHECK]: { ...SECRET_CHECK }, aiBundle: r.aiBundle, warnings: [], notes: [] } as LocalAudit;
    const t = renderLocalTerminal(l, SHORT);
    expect(t).toContain('Type: shop-api: static-site — output: "export" in next.config.mjs');
  });
});

describe('short report: severity by project type (PL-A2)', () => {
  const pt = (types: ServiceType[], unsure = false): ProjectType => ({ types, evidence: [], unsure });
  const withType = (r: AuditReport, projectType: ProjectType): AuditReport =>
    ({ ...r, profile: { ...r.profile, services: [{ ...r.profile.services[0], name: 'site', projectType }] } });
  const rows = (): Coverage[] => [
    { need: need('push', 'format', 'site'), status: 'missing', why: 'no format.' },
    { need: need('push', 'coverage', 'site'), status: 'missing', why: 'no coverage.' },
    { need: need('push', 'secrets'), status: 'missing', why: 'no secrets.' },
  ];
  const rank = (projectType: ProjectType) => {
    const r = withType(freePrivateReport(EXCLUDED_PATTERNS), projectType);
    const g = rankGaps({ ...r, coverage: rows(), wouldAdd: [] });
    return { fix: g.fixFirst.map((x) => x.check), consider: g.consider.map((x) => x.check) };
  };

  it('small static site: missing format and coverage → Consider', () => {
    const g = rank(pt(['static-site']));
    expect(g.consider.some((c) => /format/i.test(c))).toBe(true);
    expect(g.consider.some((c) => /coverage/i.test(c))).toBe(true);
    expect(g.fix.some((c) => /format|coverage/i.test(c))).toBe(false);
  });

  it('small static site: missing secrets stays fix first', () => {
    const g = rank(pt(['static-site']));
    expect(g.fix.some((c) => c.startsWith('Secret scan'))).toBe(true);
    expect(g.consider.some((c) => c.startsWith('Secret scan'))).toBe(false);
  });

  it('server repo: missing coverage stays fix first', () => {
    const g = rank(pt(['server']));
    expect(g.fix.some((c) => /coverage/i.test(c))).toBe(true);
    expect(g.fix.some((c) => /format/i.test(c))).toBe(true);
  });

  it('unsure static → not small', () => {
    expect(rank(pt(['static-site'], true)).fix.some((c) => /coverage/i.test(c))).toBe(true);
  });

  it('static + container → not small', () => {
    expect(rank(pt(['static-site', 'container'])).fix.some((c) => /coverage/i.test(c))).toBe(true);
  });

  it('small static site: the full report and its layer verdict agree (no ⚠ on format and coverage)', () => {
    const only = (projectType: ProjectType) => ({ ...withType(freePrivateReport(EXCLUDED_PATTERNS), projectType), coverage: rows().slice(0, 2), wouldAdd: [] });
    const md = (projectType: ProjectType) => renderMarkdown(only(projectType), FULL).split('\n').filter((l) => /^\| ⚠ \| missing/.test(l));
    expect(md(pt(['static-site']))).toEqual([]);
    expect(md(pt(['server']))).toHaveLength(2);
    expect(layerViews(only(pt(['static-site']))).some((v) => v.serious)).toBe(false);
    expect(layerViews(only(pt(['server']))).some((v) => v.serious)).toBe(true);
  });
});

describe('short report by parts (PL-A4)', () => {
  const report = () => freePrivateReport(EXCLUDED_PATTERNS);
  const SUMMARY = /^(\d+) to fix · (\d+) to consider · (\d+) already good(?: · (\d+) couldn't tell)?$/;
  /** The part blocks of a short report: title line, then the lines under it up to the next part or the footer. */
  function blocks(t: string): { id: number; title: string; lines: string[] }[] {
    const out: { id: number; title: string; lines: string[] }[] = [];
    for (const l of lines(t)) {
      const m = /^([1-6]) (\S.*)$/.exec(l);
      if (m !== null && Object.values(PART_TITLE).includes(m[2] as string)) out.push({ id: Number(m[1]), title: m[2] as string, lines: [] });
      else if (/^(What now\?|Not needed here:|Couldn't tell:)/.test(l)) out.push({ id: 0, title: l, lines: [] });
      else out.at(-1)?.lines.push(l);
    }
    return out;
  }
  /** The items of one mark in a part block (wrapped lines joined; ✗ and ⚠ items are separated by "; ", ✓ by ", "). */
  const itemsOf = (b: { lines: string[] }, mark: '✗' | '⚠' | '✓'): string[] => {
    const joined = b.lines.join('\n').replace(/\n {4}/g, ' ');
    const line = joined.split('\n').find((l) => l.startsWith(`  ${mark} `));
    return line === undefined ? [] : line.slice(4).split(mark === '✓' ? ', ' : '; ');
  };

  it('summary counts equal the lines of the parts', () => {
    const r = report();
    const t = renderTerminal(r, SHORT);
    const m = SUMMARY.exec(lines(t)[1] as string);
    expect(m, lines(t)[1]).not.toBeNull();
    const parts = blocks(t).filter((b) => b.id > 0);
    const sum = (mark: '✗' | '⚠' | '✓') => parts.reduce((n, b) => n + itemsOf(b, mark).length, 0);
    expect([sum('✗'), sum('⚠'), sum('✓')]).toEqual([Number(m?.[1]), Number(m?.[2]), Number(m?.[3])]);
    // the model agrees, and nothing is cut: every gap of rankGaps is in a part
    const g = rankGaps(r);
    expect(Number(m?.[1])).toBe(g.fixFirst.length);
    expect(Number(m?.[2])).toBe(g.consider.length);
    expect(shortParts(r).reduce((n, p) => n + p.fix.length + p.consider.length, 0)).toBe(g.fixFirst.length + g.consider.length);
  });

  it('summary counts: the "couldn\'t tell" count is added only when a check is unknown', () => {
    const t = renderTerminal(report(), SHORT);
    expect(lines(t)[1]).toMatch(/ · 1 couldn't tell$/);
    const none = renderTerminal({ ...report(), coverage: report().coverage.filter((c) => c.status !== 'unknown') }, SHORT);
    expect(lines(none)[1]).not.toContain("couldn't tell");
  });

  it('layout: title and commit, the summary line, B5 warnings, Type, the parts, What now? last', () => {
    const t = renderTerminal(report(), SHORT);
    const ls = lines(t);
    expect(ls[0]).toBe('pipegen audit: acme/shop-api (f4bcfab on main)');
    expect(ls[1]).toMatch(SUMMARY);
    const at = (s: string) => ls.findIndex((l) => l.startsWith(s));
    const order = ['⚠ Secret-like text on disk', '1 On your computer', '2 Every pull request', 'What now?'].map(at);
    expect(order.every((i) => i > 1), t).toBe(true);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    // What now? is the last block: no part title, no list item after it
    const now = at('What now?');
    expect(ls.slice(now + 1).every((l) => l.startsWith('  ') || l === ''), t).toBe(true);
    expect(ls.slice(now + 1).join('\n')).toContain('pipegen --verbose');
    expect(t).not.toMatch(/^Verdict:|^Fix first|^Consider|^Already good|^Details:/m);
  });

  it('parts in order 1–6, and a part holds only its own checks', () => {
    const t = renderTerminal(report(), SHORT);
    const ids = blocks(t).filter((b) => b.id > 0).map((b) => b.id);
    expect(ids).toEqual([...ids].sort((a, b) => a - b));
    expect(new Set(ids).size).toBe(ids.length);
    const b = (id: number) => blocks(t).find((x) => x.id === id);
    expect(itemsOf(b(1) as { lines: string[] }, '✗').some((x) => x.startsWith('Secret scan before each commit'))).toBe(true);
    expect(itemsOf(b(2) as { lines: string[] }, '✗').some((x) => x.startsWith('Code scan (SAST)'))).toBe(true);
    expect(itemsOf(b(3) as { lines: string[] }, '⚠').some((x) => x.startsWith('Merge gate (pipegen)'))).toBe(true);
  });

  it('empty part left out', () => {
    const t = renderTerminal(report(), SHORT);
    // the fixture has rows in parts 1 to 5 only (no scheduled or repo-setting check)
    const shown = blocks(t).filter((b) => b.id > 0).map((b) => b.id);
    expect(shown).toEqual([1, 2, 3, 4, 5]);
    expect(t).not.toContain(PART_TITLE[6 as PartId]);
    const nothing = renderTerminal({ ...report(), coverage: [], wouldAdd: [], warnings: [], secretsInTree: [] }, SHORT);
    for (const title of Object.values(PART_TITLE)) expect(nothing).not.toContain(title);
  });

  it('every part has the checks of its own rows, nothing is dropped (all six parts)', () => {
    const cats = ['hooks', 'secrets', 'gate', 'sbom', 'deploy-verify', 'scorecard'];
    const rows: Coverage[] = cats.map((id) => ({ need: { ...need(id === 'hooks' ? 'pre-commit' : 'push', id), category: id } as Coverage['need'], status: 'missing', why: `No ${id}.` }));
    const t = renderTerminal({ ...report(), coverage: rows, wouldAdd: [] }, SHORT);
    expect(blocks(t).filter((b) => b.id > 0).map((b) => b.id)).toEqual([1, 2, 3, 4, 5, 6]);
    const total = blocks(t).filter((b) => b.id > 0).reduce((n, b) => n + itemsOf(b, '✗').length + itemsOf(b, '⚠').length, 0);
    expect(total).toBe(6);
  });

  it('already-good and consider checks take one line each; the rest is counted, and the summary still counts all', () => {
    const r = report();
    const good = ['secrets', 'sast', 'deps', 'unit-tests', 'full-tests', 'lint', 'coverage', 'dead-code', 'duplication', 'iac', 'licences', 'dockerfile-lint', 'workflow-lint'];
    const warn = ['format', 'coverage', 'licences', 'dead-code', 'duplication', 'iac', 'sast', 'deps', 'lint', 'unit-tests', 'full-tests', 'workflow-lint'];
    const rows: Coverage[] = [
      ...good.map((id): Coverage => ({ need: need('push', id), status: 'covered', by: 'x', why: 'ok.' })),
      ...warn.map((id): Coverage => ({ need: { ...need('merge', `w-${id}`), category: id, blocking: false } as Coverage['need'], status: 'missing', why: 'no.' })),
    ];
    const t = renderTerminal({ ...r, coverage: rows, wouldAdd: [], profile: { ...r.profile, services: [] } }, SHORT);
    const block = lines(t).slice(lines(t).findIndex((l) => l.startsWith('2 Every pull request')) + 1);
    const goodLine = block.filter((l) => l.startsWith('  ✓ '));
    expect(goodLine).toHaveLength(1);
    expect(goodLine[0]).toMatch(/and \d+ more \(--verbose\)$/);
    const warnLine = block.filter((l) => l.startsWith('  ⚠ '));
    expect(warnLine).toHaveLength(1);
    expect(warnLine[0]).toMatch(/and \d+ more \(--verbose\)$/);
    expect(block.slice(0, block.findIndex((l) => l.startsWith('What now?'))).filter((l) => /^ {4}\S/.test(l))).toEqual([]);
    const parts = shortParts({ ...r, coverage: rows, wouldAdd: [], profile: { ...r.profile, services: [] } });
    expect(parts[1]?.good).toHaveLength(good.length);
    expect(parts[1]?.consider.length).toBeGreaterThan(5);
    expect(lines(t)[1]).toMatch(new RegExp(`^0 to fix · ${parts[1]?.consider.length} to consider · ${good.length} already good`));
  });

  it('B5: every warning still shown', () => {
    const RATE = { text: "GitHub's rate limit was reached, so pipegen couldn't read everything it needs from GitHub." };
    const SWAP = { text: 'This repo could change which pipegen runs. Run pipegen from outside the repo with:', command: 'npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./repo' };
    const r = { ...report(), warnings: [RATE, SWAP], wouldAddNote: 'These picks are based on incomplete GitHub data (rate limit).' };
    const t = renderTerminal(r, SHORT);
    const f = flat(t);
    for (const s of [RATE.text, SWAP.text, 'incomplete GitHub data', 'Secret-like text on disk: 2 files (.env, config/dev.json; --verbose for all)']) expect(f, s).toContain(s);
    expect(lines(t)).toContain(`    ${SWAP.command}`);
    // all of it above the parts
    const firstPart = lines(t).findIndex((l) => /^1 On your computer/.test(l));
    for (const s of ['rate limit was reached', 'which pipegen runs', 'incomplete GitHub data', 'Secret-like text']) expect(lines(t).findIndex((l) => l.includes(s)), s).toBeLessThan(firstPart);
  });

  it('no file:line and no "how to fix" text in the short report', () => {
    const r = report();
    const t = renderTerminal(r, SHORT);
    expect(t).not.toMatch(/[\w./-]+\.(ya?ml|json|ts|js|md):\d+/);
    for (const c of r.coverage) if (c.why !== '') expect(flat(t)).not.toContain(c.why);
    expect(t).not.toMatch(/Without a /);
    // the full report still has them
    expect(flat(renderTerminal(r, FULL))).toContain('Without a code scan');
  });

  it('a one-service repo does not repeat the service name on each line', () => {
    const t = renderTerminal(report(), SHORT);
    expect(blocks(t).filter((b) => b.id > 0).flatMap((b) => b.lines).join('\n')).not.toContain('for shop-api');
    const rows: Coverage[] = ['a', 'b'].map((s) => ({ need: need('push', 'sast', s), status: 'missing', why: 'No code scan.' }));
    expect(renderTerminal({ ...report(), coverage: rows, wouldAdd: [] }, SHORT)).toContain('Code scan (SAST) for a and b');
  });

  it('a partial check says so; the tool the setup names is in brackets', () => {
    const t = renderTerminal(report(), SHORT);
    expect(flat(t)).toContain('Dependency check (partial)');
    expect(t).toContain('Code scan (SAST) [semgrep]');
  });

  it('a credit note sits under the part of its credit', () => {
    const r = { ...report(), profile: { ...report().profile, private: true } };
    const signed: Coverage = { need: { ...need('deploy', 'signing', 'shop-api'), category: 'signing' } as Coverage['need'], status: 'covered', by: 'cosign', why: 'ok.', credit: 'CI signs the release artifacts with cosign (sign-blob)', creditKind: 'signing' };
    const t = renderTerminal({ ...r, coverage: [...r.coverage, signed] }, SHORT);
    const four = blocks(t).find((b) => b.id === 4) as { lines: string[] };
    expect(four.lines.join(' ')).toContain('public Sigstore log');
    expect(itemsOf(four, '✓').some((x) => /signing/i.test(x))).toBe(true);
  });

  it('a plan limit is shown under What now? only when it blocks a fix-first check', () => {
    const t = renderTerminal(report(), SHORT);
    const now = lines(t).findIndex((l) => l.startsWith('What now?'));
    expect(flat(lines(t).slice(now).join('\n'))).toContain(LIMIT.noCodeScanning);
    expect(flat(lines(t).slice(0, now).join('\n'))).not.toContain(LIMIT.noCodeScanning);
  });

  it('every line is at most 80 columns (own commands excepted)', () => {
    const r = { ...report(), warnings: [{ text: 'x '.repeat(120) }] };
    for (const l of lines(renderTerminal(r, SHORT))) expect([...l].length, l).toBeLessThanOrEqual(80);
  });
});
