// Plan J J6: a generic proof set. Invented repos of different kinds and shapes (static Next.js export, the same with a local
// preview server, Astro, a Vite SPA, a CLI, a container service, plus the older fixtures) are audited for real
// (buildAudit on a copy of each fixture, GitHub stubbed) and checked for what Plan J promises, one test per promise:
// the project type, the minimum, no image/DAST rows for a static site, credits only where the repo really has the
// equivalent, the rows against a baseline recorded before Plan J (10d48df, ruling B6; every difference named), and the
// length of the short report. Nothing here is tuned to one repo: the fixtures differ on purpose (both deploy-gate forms,
// pre-commit / husky / no hooks, SHA-pinned and tag-pinned actions, gitleaks as a checked binary or as the action).
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { buildAudit, type AuditReport } from '../src/audit/model.js';
import { PART_TITLE, partOf } from '../src/audit/parts.js';
import { shortParts } from '../src/audit/render-short.js';
import { renderTerminal } from '../src/audit/render.js';
import { MINIMUM_CATEGORIES, STATIC_SKIP } from '../src/engine/needs.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import type { Capabilities, ServiceType } from '../src/types.js';
import { cleanupRepos, makeRepo } from './helpers/make-repo.js';
import { BASELINE_10D48DF } from './fixtures/plan-j-baseline-10d48df.js';

afterEach(cleanupRepos);

const NOW = Date.parse('2026-10-27T12:00:00Z');
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
} as unknown as Parameters<typeof buildAudit>[1]['gh'];

const FIXTURES = [
  'static-next-export', 'static-next-export-preview', 'static-astro', 'static-vite-spa', 'node-cli', 'node-container-service',
  'node-express', 'node-library', 'go-module', 'workspaces-python-backend', 'node-api-ci-deploy',
  'flask-api-gated', 'node-cli-ts', 'node-web-chain',
] as const;
type Fixture = typeof FIXTURES[number];

const reports = new Map<Fixture, AuditReport>();
async function audit(f: Fixture): Promise<AuditReport> {
  const have = reports.get(f);
  if (have) return have;
  const dir = makeRepo(f, 'https://github.com/o/r.git');
  const r = await buildAudit(dir, {
    gh, anonymous: false, context: { private: false, ownerType: 'User', plan: 'free', defaultBranch: 'main' }, capabilities: bare,
    permissions: [], reviewed: [], now: () => NOW, budget: newRateBudget(),
  });
  reports.set(f, r);
  return r;
}
const rowKey = (c: AuditReport['coverage'][number]) => `${c.need.category}|${c.need.layer}|${c.need.service ?? ''}|${c.status}`;
const rowsOf = async (f: Fixture) => (await audit(f)).coverage.map(rowKey).sort();
const typesOf = async (f: Fixture) => (await audit(f)).profile.services.map((s) => ({ name: s.name, types: s.projectType?.types, unsure: s.projectType?.unsure }));

// ---------- 1. the project type ----------
describe('Plan J proof set: project type', () => {
  const EXPECTED: Record<Fixture, { types: ServiceType[]; unsure: boolean }[]> = {
    'static-next-export': [{ types: ['static-site'], unsure: false }],
    // a start script that serves the build locally with a port: pipegen can't tell a preview from a server, so it asks
    'static-next-export-preview': [{ types: ['server'], unsure: true }],
    'static-astro': [{ types: ['static-site'], unsure: false }],
    'static-vite-spa': [{ types: ['static-site'], unsure: false }],
    'node-cli': [{ types: ['cli'], unsure: false }],
    'node-container-service': [{ types: ['server', 'container'], unsure: false }],
    'node-express': [{ types: ['server'], unsure: false }],
    'node-api-ci-deploy': [{ types: ['server'], unsure: false }],
    'node-web-chain': [{ types: ['server'], unsure: false }],
    // a TypeScript CLI with a bin map of two commands
    'node-cli-ts': [{ types: ['cli'], unsure: false }],
    // a Python service with a port default and a server package: server
    'flask-api-gated': [{ types: ['server'], unsure: false }],
    'node-library': [{ types: ['library'], unsure: false }],
    // not a Node project: today's rule (no type found, nothing dropped)
    'go-module': [{ types: [], unsure: false }],
    'workspaces-python-backend': [{ types: ['server', 'container'], unsure: false }, { types: ['server', 'container'], unsure: false }],
  };
  for (const f of FIXTURES) {
    it(`${f} → ${EXPECTED[f].map((e) => e.types.join('+') || 'today\'s rule').join(' and ')}${EXPECTED[f][0]!.unsure ? ' (unsure)' : ''}`, async () => {
      expect((await typesOf(f)).map(({ types, unsure }) => ({ types, unsure }))).toEqual(EXPECTED[f]);
    });
  }
});

// ---------- 2. the minimum ----------
describe('Plan J proof set: the minimum is kept', () => {
  for (const f of FIXTURES) {
    it(`${f}: every minimum check has a row, none is skipped as "not needed"`, async () => {
      const r = await audit(f);
      const cats = new Set(r.coverage.map((c) => c.need.category));
      for (const m of MINIMUM_CATEGORIES) expect(cats.has(m), `${f} lacks ${m}`).toBe(true);
      const skipped = new Set(r.skipped.flatMap((s) => s.categories));
      for (const m of MINIMUM_CATEGORIES) expect(skipped.has(m), `${f} skips ${m}`).toBe(false);
    });
  }
});

// ---------- 3. static sites: nothing for a container or a running app ----------
describe('Plan J proof set: static sites have no container or DAST rows', () => {
  const GONE = ['image-build', 'image-scan', 'dast', 'api-dast', 'dockerfile-lint'];
  for (const f of ['static-next-export', 'static-astro', 'static-vite-spa'] as const) {
    it(`${f}: no ${GONE.join(' / ')} row; the skip says why; the short report does not ask for them`, async () => {
      const r = await audit(f);
      expect(r.coverage.filter((c) => GONE.includes(c.need.category)).map(rowKey)).toEqual([]);
      const skip = r.skipped.find((s) => s.categories.includes('image-build'));
      expect(skip?.why).toBe(STATIC_SKIP);
      expect(skip?.categories).toEqual(expect.arrayContaining(['image-build', 'image-scan', 'dast']));
      const t = renderTerminal(r, { knownValues: [], now: () => NOW });
      const asked = t.slice(0, t.indexOf('Not needed here'));
      expect(asked).not.toMatch(/image|DAST|Dockerfile|container/i);
    });
  }
  it('the unsure preview-server fixture and the container service keep their image and DAST rows (fail-safe)', async () => {
    for (const f of ['static-next-export-preview', 'node-container-service'] as const) {
      const cats = new Set((await audit(f)).coverage.map((c) => c.need.category));
      expect(cats.has('image-build'), f).toBe(true);
      expect(cats.has('dast'), f).toBe(true);
    }
  });
});

// ---------- 4. credits ----------
describe('Plan J proof set: credits only where the repo has the equivalent', () => {
  // The rows each fixture is credited on, by name. A credit is a row that was not covered before (see the baseline test)
  // and is covered now because the repo has the equivalent: every push is covered through its pull-request run
  // (push-default), or the pre-commit hooks it has run in CI (hooks-ci).
  const CREDITED: Record<Fixture, string[]> = {
    'static-next-export': ['deploy-verify|deploy|deploy-gate', 'hooks-ci|merge|hooks-ci', 'secrets|push|push-default', 'unit-tests|push|push-default'],
    'static-next-export-preview': [],
    'static-astro': ['unit-tests|push|push-default'],
    'static-vite-spa': [],
    'node-cli': ['unit-tests|push|push-default'],
    'node-container-service': ['deps|push|push-default', 'unit-tests|push|push-default'],   // deps: the trivy-action scan, safe SHA
    'node-express': [], 'node-library': [], 'go-module': [], 'workspaces-python-backend': [],
    // gate form (b): the deploy job is in the CI workflow, needs every CI job, runs on a push to exactly [main]
    'node-api-ci-deploy': ['deploy-verify|deploy|deploy-gate'],
    // form (b) again, in a different layout: one workflow for push and pull_request, build -> e2e -> release chain, event guard
    'node-web-chain': ['deploy-verify|deploy|deploy-gate', 'unit-tests|push|push-default'],
    'node-cli-ts': [],
    // form (a) by checking out the tested commit (ref: head_sha, exact branches filter), pre-commit with only the gitleaks hook
    // run by CI's checked binary, trivy-action at a safe SHA with its default version written out
    'flask-api-gated': ['deploy-verify|deploy|deploy-gate', 'deps|push|push-default', 'hooks-ci|merge|hooks-ci', 'secrets|push|push-default', 'unit-tests|push|push-default'],
  };
  const creditedOf = async (f: Fixture) => (await audit(f)).coverage.filter((c) => c.credit !== undefined)
    .map((c) => `${c.need.category}|${c.need.layer}|${c.creditKind}`).sort();
  for (const f of FIXTURES) {
    it(`${f}: credited on exactly ${CREDITED[f].length === 0 ? 'nothing' : CREDITED[f].map((x) => x.split('|').slice(0, 2).join(' ')).join(', ')}`, async () => {
      const r = await audit(f);
      expect(await creditedOf(f)).toEqual([...CREDITED[f]].sort());
      for (const c of r.coverage.filter((x) => x.credit !== undefined)) {
        expect(c.status, `${f} ${c.need.category}`).toBe('covered');
        expect(c.credit!.length).toBeGreaterThan(10);
        expect(c.creditKind).toMatch(/^(push-default|hooks-ci|signing|deploy-gate)$/);
      }
    });
  }
  it('hooks that CI never runs get no credit: husky (preview, vite) and a pre-commit file with no secret hook (container service)', async () => {
    for (const f of ['static-next-export-preview', 'static-vite-spa', 'node-container-service'] as const) {
      const hooksCi = (await audit(f)).coverage.filter((c) => c.need.category === 'hooks-ci');
      expect(hooksCi.map((c) => c.status), f).not.toContain('covered');
      expect(hooksCi.some((c) => c.credit !== undefined), f).toBe(false);
    }
  });
  it('push-default negative: CI that runs only on a push to main (no pull_request) and the deploy-only workflows get no push credit', async () => {
    // node-api-ci-deploy: every job runs on push to main only, so no row is "partial for want of a push trigger" to credit
    expect((await creditedOf('node-api-ci-deploy')).filter((x) => x.endsWith('push-default'))).toEqual([]);
    for (const f of ['static-next-export-preview', 'static-vite-spa'] as const) expect((await creditedOf(f)).filter((x) => x.endsWith('push-default')), f).toEqual([]);
  });
  it('the credited rows are shown with their credit text in the full report', async () => {
    const t = renderTerminal(await audit('static-next-export'), { knownValues: [], now: () => NOW, verbose: true });
    for (const c of (await audit('static-next-export')).coverage.filter((x) => x.credit !== undefined)) expect(t.replace(/\s+/g, ' ')).toContain(c.credit!.replace(/\s+/g, ' '));
  });
  it('no fixture has a covered signing, attestation or sbom row (nothing here signs or builds an SBOM)', async () => {
    for (const f of FIXTURES) {
      const bad = (await audit(f)).coverage.filter((c) => ['signing', 'attestation', 'sbom'].includes(c.need.category) && c.status === 'covered');
      expect(bad.map(rowKey), f).toEqual([]);
    }
  });
});

// ---------- 5. rows against the baseline recorded at 10d48df (ruling B6) ----------
describe('Plan J proof set: rows against the baseline at 10d48df', () => {
  // Each difference Plan J makes, by name: rows gone, and rows whose status changed (from → to). Anything else must be the
  // same row with the same status. The baseline file was recorded from the old commit, never from this code.
  interface Diff { gone?: string[]; changed?: [from: string, to: string][] }
  const STATIC_IMAGE_ROWS = (svc: string) => [`dast|merge|${svc}|missing`, `image-build|merge|${svc}|missing`, `image-scan|merge|${svc}|missing`];
  const PUSH_CREDIT = (svc: string): [string, string] => [`unit-tests|push|${svc}|partial`, `unit-tests|push|${svc}|covered`];
  const DIFFS: Record<Fixture, Diff> = {
    // static: image build, image scan and the running-app scan are not asked for; push rows credited through the PR run
    // (unit-tests, secrets); the hooks-ci row credited because the pre-commit secret hook is run by CI's gitleaks job
    'static-next-export': {
      gone: STATIC_IMAGE_ROWS('docs-site'),
      changed: [PUSH_CREDIT('docs-site'), ['secrets|push||partial', 'secrets|push||covered'], ['hooks-ci|merge||missing', 'hooks-ci|merge||covered'],
        ['deploy-verify|deploy|docs-site|missing', 'deploy-verify|deploy|docs-site|covered']],   // deploy gate, form (a) (J3b)
    },
    // an unsure static site is treated as a server: nothing dropped, nothing credited
    'static-next-export-preview': {},
    'static-astro': { gone: STATIC_IMAGE_ROWS('blog'), changed: [PUSH_CREDIT('blog')] },
    // a static site with no deploy workflow has no deploy target: the deploy-layer rows (they need a running service) go too
    'static-vite-spa': {
      gone: [...STATIC_IMAGE_ROWS('dashboard-ui'), 'deploy-verify|deploy|dashboard-ui|missing', 'egress|deploy|dashboard-ui|missing', 'sbom|deploy|dashboard-ui|missing', 'signing|deploy|dashboard-ui|missing'],
    },
    'node-cli': { changed: [PUSH_CREDIT('tidy-files')] },
    // trivy-action at a pinned safe SHA with default inputs is not never-listed any more: its fs scan (vulnerabilities and
    // licences) covers the dependency and licence rows (J3b)
    'node-container-service': {
      changed: [PUSH_CREDIT('orders-api'), ['deps|merge|orders-api|partial', 'deps|merge|orders-api|covered'],
        ['deps|push|orders-api|partial', 'deps|push|orders-api|covered'], ['licences|merge||partial', 'licences|merge||covered']],
    },
    'node-express': {}, 'node-library': {}, 'go-module': {}, 'workspaces-python-backend': {},
    'node-api-ci-deploy': { changed: [['deploy-verify|deploy|notes-api|missing', 'deploy-verify|deploy|notes-api|covered']] },   // deploy gate, form (b) (J3b)
    'node-web-chain': { changed: [PUSH_CREDIT('booking-web'), ['deploy-verify|deploy|booking-web|missing', 'deploy-verify|deploy|booking-web|covered']] },
    'node-cli-ts': {},
    // form (a) by ref; hooks-ci credit; trivy-action by safe SHA (deps rows); push credits; the ruff-free pre-commit file
    'flask-api-gated': {
      changed: [PUSH_CREDIT('ledger-api'), ['secrets|push||partial', 'secrets|push||covered'], ['hooks-ci|merge||missing', 'hooks-ci|merge||covered'],
        ['deploy-verify|deploy|ledger-api|missing', 'deploy-verify|deploy|ledger-api|covered'],
        ['deps|merge|ledger-api|partial', 'deps|merge|ledger-api|covered'], ['deps|push|ledger-api|partial', 'deps|push|ledger-api|covered']],
    },
  };
  for (const f of FIXTURES) {
    it(`${f}: today's rows = the 10d48df rows minus ${DIFFS[f].gone?.length ?? 0} gone, with ${DIFFS[f].changed?.length ?? 0} changed`, async () => {
      const base = [...BASELINE_10D48DF[f]!];
      const expected = [...base];
      for (const g of DIFFS[f].gone ?? []) {
        const i = expected.indexOf(g);
        expect(i, `${g} must be in the baseline`).toBeGreaterThanOrEqual(0);
        expected.splice(i, 1);
      }
      for (const [from, to] of DIFFS[f].changed ?? []) {
        const i = expected.indexOf(from);
        expect(i, `${from} must be in the baseline`).toBeGreaterThanOrEqual(0);
        expected[i] = to;
      }
      expect(await rowsOf(f)).toEqual(expected.sort());
    });
  }
  it('no row got worse: nothing went from covered/partial to missing/unknown, and no row appeared', async () => {
    const rank = { covered: 3, partial: 2, missing: 1, unknown: 0 } as const;
    for (const f of FIXTURES) {
      const now = new Map((await rowsOf(f)).map((r) => [r.split('|').slice(0, 3).join('|'), r.split('|')[3]!]));
      for (const b of BASELINE_10D48DF[f]!) {
        const [c, l, s, st] = b.split('|');
        const key = `${c}|${l}|${s}`;
        const cur = now.get(key);
        if (cur === undefined) continue;                                   // a row that went (named in DIFFS)
        expect(rank[cur as keyof typeof rank], `${f} ${key}: ${st} → ${cur}`).toBeGreaterThanOrEqual(rank[st as keyof typeof rank]);
      }
      expect(now.size, f).toBeLessThanOrEqual(BASELINE_10D48DF[f]!.length);
    }
  });
});

// ---------- 6. J3b: the deploy-gate credit and trivy-action by a safe SHA ----------
describe('Plan J proof set: deploy gate and trivy-action by SHA (J3b)', () => {
  const rowOf = async (f: Fixture, key: string) => (await audit(f)).coverage.find((c) => `${c.need.category}|${c.need.layer}|${c.need.service ?? ''}` === key);
  const GATE_WHY = /deploys run only after CI passed on main, for the commit CI tested, never for a fork's run/;
  it('form (a), two shapes: a guarded workflow_run deploy (env-var SHA check; or checking out the tested commit by ref with an exact branches filter) → covered, with its credit', async () => {
    for (const [f, key] of [['static-next-export', 'deploy-verify|deploy|docs-site'], ['flask-api-gated', 'deploy-verify|deploy|ledger-api']] as const) {
      const r = await rowOf(f, key);
      expect(r, f).toMatchObject({ status: 'covered', creditKind: 'deploy-gate' });
      expect(r!.credit, f).toMatch(GATE_WHY);
    }
  });
  it('form (b), two layouts: the deploy job inside CI, needing every CI job, on a push to exactly [main] (push-only chain; or push + pull_request with an event guard) → covered', async () => {
    for (const [f, key] of [['node-api-ci-deploy', 'deploy-verify|deploy|notes-api'], ['node-web-chain', 'deploy-verify|deploy|booking-web']] as const) {
      const r = await rowOf(f, key);
      expect(r, f).toMatchObject({ status: 'covered', creditKind: 'deploy-gate' });
      expect(r!.credit, f).toMatch(GATE_WHY);
      expect(r!.why, f).toMatch(/deploys only on a push to main, after every other job of the same run passed/);
    }
  });
  it('hooks-ci credit, two shapes: pre-commit with the gitleaks hook, run in CI by a checksum-checked gitleaks binary (detect; or git) → covered, naming the hook', async () => {
    for (const f of ['static-next-export', 'flask-api-gated'] as const) {
      const r = await rowOf(f, 'hooks-ci|merge|');
      expect(r, f).toMatchObject({ status: 'covered', creditKind: 'hooks-ci' });
      expect(r!.credit, f).toMatch(/hook/i);
    }
  });
  it('form (b) shape in its own push workflow (not inside CI, so the deploy does not wait for the tests) → deploy-verify stays missing', async () => {
    // static-next-export-preview deploys from deploy.yml on push [main] with a github.ref guard, but no job there needs the
    // CI jobs: J3b credits form (b) only when the deploy is in the CI workflow itself, so this is missing on purpose.
    const r = await rowOf('static-next-export-preview', 'deploy-verify|deploy|marketing-site');
    expect(r?.status).toBe('missing');
    expect(r?.credit).toBeUndefined();
  });
  it('a Pages deploy by an environment, with no check that the commit passed → deploy-verify stays missing (astro)', async () => {
    expect((await rowOf('static-astro', 'deploy-verify|deploy|blog'))?.status).toBe('missing');
  });
  it('trivy-action at a safe SHA, two shapes (own default inputs; or its default version written out) → not never-listed: rows covered, saying the action\'s cache is not re-checked', async () => {
    for (const [f, keys] of [['node-container-service', ['deps|merge|orders-api', 'deps|push|orders-api', 'licences|merge|']], ['flask-api-gated', ['deps|merge|ledger-api', 'deps|push|ledger-api']]] as const) {
      for (const key of keys) {
        const r = await rowOf(f, key);
        expect(r?.status, `${f} ${key}`).toBe('covered');
        expect(r?.why, `${f} ${key}`).toMatch(/cache isn't re-checked/);
      }
    }
  });
  it('the same trivy-action step with `version:` set → still never-listed (partial, no cache note)', async () => {
    const dir = makeRepo('node-container-service', 'https://github.com/o/r.git');
    const ci = join(dir, '.github/workflows/ci.yml');
    const text = readFileSync(ci, 'utf8');
    expect(text).toContain("          scan-type: fs\n");
    writeFileSync(ci, text.replace("          scan-type: fs\n", "          scan-type: fs\n          version: v0.60.0\n"));
    const r = await buildAudit(dir, {
      gh, anonymous: false, context: { private: false, ownerType: 'User', plan: 'free', defaultBranch: 'main' }, capabilities: bare,
      permissions: [], reviewed: [], now: () => NOW, budget: newRateBudget(),
    });
    const row = (k: string) => r.coverage.find((c) => `${c.need.category}|${c.need.layer}|${c.need.service ?? ''}` === k)!;
    for (const key of ['deps|merge|orders-api', 'licences|merge|']) {
      expect(row(key).status, key).toBe('partial');
      expect(row(key).why, key).not.toMatch(/cache isn't re-checked/);
    }
  });
});

// ---------- 7. the short report ----------
describe('Plan J proof set: the short report', () => {
  // PL-A4. Owner choice 3 asked for <= 20 lines (one service) and <= 30 (several) at 80 columns. With six populated parts
  // (a header line each) plus the title, summary, type, cost and pointer lines, that cannot hold for a repo that has
  // something to say in every part (see task-PL-A4-report.md); the bound kept here is the old one (32), now at 80 columns.
  const LINE_BUDGET = 32;
  /** The checks listed on one mark's lines of a part (wrapped lines joined), "and N more" counted as N. */
  const countMarks = (t: string, mark: string): number => {
    let n = 0;
    for (const line of t.slice(0, t.indexOf('What now?')).replace(/\n {4}(?! )/g, ' ').split('\n')) {
      if (!line.startsWith(`  ${mark} `)) continue;
      const body = line.slice(4);
      const more = /(?:^|; |, )and (\d+) more \(--verbose\)$/.exec(body);
      const shown = more === null ? body : body.slice(0, more.index);
      n += (shown === '' ? 0 : shown.split(mark === '✓' ? ', ' : '; ').length) + (more === null ? 0 : Number(more[1]));
    }
    return n;
  };
  for (const f of FIXTURES) {
    it(`${f}: every line ≤ 80 columns, within the line budget, the parts in order and none empty`, async () => {
      const r = await audit(f);
      const t = renderTerminal(r, { knownValues: [], now: () => NOW });
      const ls = t.split('\n');
      expect(ls.length, t).toBeLessThanOrEqual(LINE_BUDGET);
      for (const l of ls) expect([...l].length, l).toBeLessThanOrEqual(80);
      expect(t).toMatch(/^Type: /m);
      const ids = ls.map((l) => /^([1-6]) (\S.*)$/.exec(l)).filter((m) => m !== null && Object.values(PART_TITLE).includes(m[2] as string)).map((m) => Number(m?.[1]));
      expect(ids).toEqual([...ids].sort((a, b) => a - b));
      // an empty part is left out: every shown part has a ✗, ⚠, ✓ or Note line before the next header
      const parts = shortParts(r);
      expect(ids).toEqual(parts.filter((p) => p.fix.length + p.consider.length + p.good.length + p.notes.length > 0).map((p) => p.part));
      expect(t).not.toMatch(/[\w./-]+\.(ya?ml|json|ts|js):\d+/);
    });
    it(`${f}: summary counts equal the lines of the parts`, async () => {
      const r = await audit(f);
      const t = renderTerminal(r, { knownValues: [], now: () => NOW });
      const m = /^(\d+) to fix · (\d+) to consider · (\d+) already good/.exec(t.split('\n')[1] as string);
      expect(m, t).not.toBeNull();
      expect([countMarks(t, '✗'), countMarks(t, '⚠'), countMarks(t, '✓')]).toEqual([Number(m?.[1]), Number(m?.[2]), Number(m?.[3])]);
      // every gap row is in a part: its part lists a check of the same category as a ✗ or ⚠ item
      const parts = shortParts(r);
      for (const c of r.coverage) if (c.status === 'missing' || c.status === 'partial') {
        const p = parts.find((x) => x.part === partOf(c.need));
        expect([...(p?.fix ?? []), ...(p?.consider ?? [])].some((g) => g.category === c.need.category), `${f} ${rowKey(c)}`).toBe(true);
      }
    });
  }
});
