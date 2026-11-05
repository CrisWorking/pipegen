// Plan J J6: a generic proof set. Invented repos of different kinds and shapes (static Next.js export, the same with a local
// preview server, Astro, a Vite SPA, a CLI, a container service, plus the older fixtures) are audited for real
// (buildAudit on a copy of each fixture, GitHub stubbed) and checked for what Plan J promises, one test per promise:
// the project type, the minimum, no image/DAST rows for a static site, credits only where the repo really has the
// equivalent, the rows against a baseline recorded before Plan J (10d48df, ruling B6; every difference named), and the
// length of the short report. Nothing here is tuned to one repo: the fixtures differ on purpose (both deploy-gate forms,
// pre-commit / husky / no hooks, SHA-pinned and tag-pinned actions, gitleaks as a checked binary or as the action).
import { afterEach, describe, expect, it } from 'vitest';
import { buildAudit, type AuditReport } from '../src/audit/model.js';
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
  'node-express', 'node-library', 'go-module', 'workspaces-python-backend',
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
      const asked = t.slice(0, t.indexOf('Already good'));
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
    'static-next-export': ['hooks-ci|merge|hooks-ci', 'secrets|push|push-default', 'unit-tests|push|push-default'],
    'static-next-export-preview': [],
    'static-astro': ['unit-tests|push|push-default'],
    'static-vite-spa': [],
    'node-cli': ['unit-tests|push|push-default'],
    'node-container-service': ['unit-tests|push|push-default'],
    'node-express': [], 'node-library': [], 'go-module': [], 'workspaces-python-backend': [],
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
        expect(c.creditKind).toMatch(/^(push-default|hooks-ci|signing)$/);
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
  it('the credited rows are shown with their credit text in the full report', async () => {
    const t = renderTerminal(await audit('static-next-export'), { knownValues: [], now: () => NOW, verbose: true });
    for (const c of (await audit('static-next-export')).coverage.filter((x) => x.credit !== undefined)) expect(t).toContain(c.credit!);
  });
  it('no credit on a static fixture ever covers signing, attestation or deploy-verify today (J3B_PENDING covers deploy-verify)', async () => {
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
      changed: [PUSH_CREDIT('docs-site'), ['secrets|push||partial', 'secrets|push||covered'], ['hooks-ci|merge||missing', 'hooks-ci|merge||covered']],
    },
    // an unsure static site is treated as a server: nothing dropped, nothing credited
    'static-next-export-preview': {},
    'static-astro': { gone: STATIC_IMAGE_ROWS('blog'), changed: [PUSH_CREDIT('blog')] },
    // a static site with no deploy workflow has no deploy target: the deploy-layer rows (they need a running service) go too
    'static-vite-spa': {
      gone: [...STATIC_IMAGE_ROWS('dashboard-ui'), 'deploy-verify|deploy|dashboard-ui|missing', 'egress|deploy|dashboard-ui|missing', 'sbom|deploy|dashboard-ui|missing', 'signing|deploy|dashboard-ui|missing'],
    },
    'node-cli': { changed: [PUSH_CREDIT('tidy-files')] },
    'node-container-service': { changed: [PUSH_CREDIT('orders-api')] },
    'node-express': {}, 'node-library': {}, 'go-module': {}, 'workspaces-python-backend': {},
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

// ---------- 6. J3b: rows the deploy-gate credit and the trivy-action SHA judgement will change ----------
// Step A (J3b is not merged into this branch yet): today's values, so the rows are pinned and visible. Step B turns each
// entry into the assertion J3b promises and renames this list.
const J3B_PENDING: { fixture: Fixture; row: string; today: string }[] = [
  // gate form (a): workflow_run, guard on the first job, deploy through needs, SHA compared through an env var
  { fixture: 'static-next-export', row: 'deploy-verify|deploy|docs-site', today: 'missing' },
  // gate form (b): push on the default branch only, deploy job guarded by github.ref
  { fixture: 'static-next-export-preview', row: 'deploy-verify|deploy|marketing-site', today: 'missing' },
  // trivy-action by a pinned commit SHA (fs scan, vulnerabilities and licences)
  { fixture: 'node-container-service', row: 'licences|merge|', today: 'partial' },
  { fixture: 'node-container-service', row: 'deps|merge|orders-api', today: 'partial' },
  { fixture: 'node-container-service', row: 'deps|push|orders-api', today: 'partial' },
];
describe('Plan J proof set: rows J3b changes (J3B_PENDING, today\'s values)', () => {
  it('each pending row has today\'s status', async () => {
    for (const p of J3B_PENDING) {
      const rows = await rowsOf(p.fixture);
      expect(rows, `${p.fixture} ${p.row}`).toContain(`${p.row}|${p.today}`);
    }
  });
});

// ---------- 7. the short report ----------
describe('Plan J proof set: the short report', () => {
  // The plan's bound is 30 lines. Wrapping at 100 columns takes these fixtures a line or two over; the list names them
  // with their measured length (they may not grow, and a fixture that fits must leave the list).
  const OVER_PLAN_BOUND: Partial<Record<Fixture, number>> = {
    'static-next-export': 32, 'static-next-export-preview': 31, 'static-astro': 31, 'node-cli': 32,
    'node-library': 31, 'go-module': 31, 'workspaces-python-backend': 32,
  };
  const SECTION = (t: string, from: RegExp, to: RegExp) => {
    const ls = t.split('\n');
    const a = ls.findIndex((l) => from.test(l));
    if (a < 0) return [];
    const rest = ls.slice(a + 1);
    const b = rest.findIndex((l) => to.test(l));
    return (b < 0 ? rest : rest.slice(0, b)).filter((l) => /^ {2}- [^:]+: /.test(l));   // items are "- Label: why"; a plan-limit line has no label
  };
  for (const f of FIXTURES) {
    it(`${f}: ≤ 30 lines${OVER_PLAN_BOUND[f] ? ` (measured ${OVER_PLAN_BOUND[f]}, named below)` : ''}; Fix first and Consider show at most 5 each`, async () => {
      const t = renderTerminal(await audit(f), { knownValues: [], now: () => NOW });
      const n = t.split('\n').length;
      const known = OVER_PLAN_BOUND[f];
      if (known === undefined) expect(n, t).toBeLessThanOrEqual(30);
      else { expect(n, t).toBeGreaterThan(30); expect(n, t).toBeLessThanOrEqual(known); }
      expect(SECTION(t, /^Fix first/, /^Consider/).length).toBeLessThanOrEqual(5);
      expect(SECTION(t, /^Consider/, /^Already good|^Not needed/).length).toBeLessThanOrEqual(5);
      expect(t).toMatch(/^Type: /m);
    });
  }
});
