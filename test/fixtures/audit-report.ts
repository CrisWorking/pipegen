// A realistic AuditReport built from literals (Plan U Task 3): a private Node + Express service on GitHub Free,
// read with a token, with a husky hook and one CI workflow. Every text a renderer shows is written out here, so a
// snapshot changes only when the renderer does. Hostile and secret-like variants are built from it in the tests.
import type { AuditAi, AuditReport, WouldAddRow } from '../../src/audit/model.js';
import type { Coverage } from '../../src/audit/coverage.js';
import type { Layer, Need, ReviewedTool, Service } from '../../src/types.js';

export const need = (layer: Layer, id: string, service?: string, blocking = id !== 'format-lint'): Need => ({
  id, layer, category: id, ...(service === undefined ? {} : { service }), why: `Why ${id}.`, blocking,
  floor: ['secrets', 'sast', 'deps', 'unit-tests', 'full-tests', 'gate'].includes(id),
});

export const reviewedTool = (id: string, repo: string, version: string, categories: string[]): ReviewedTool => ({
  id, categories, languages: ['any'],
  candidate: { id, name: id, kind: 'action', repo, version, pin: { sha: '1'.repeat(40) }, source: 'reviewed', reviewed: true, categories },
  step: { output: { path: '', format: 'none' } }, fixedInputs: {}, choices: {}, configFiles: [], reviewedBy: 'maintainer', reviewedAt: '2026-09-01', proofs: 1,
});

// Field names written as computed keys: a secret-like key name followed by a colon and a value, in a committed test file,
// trips the secret-literal check (test/no-secret-literals.test.ts).
export const TREE = 'secretsInTree' as const;
const USED = 'secretsUsed' as const;
const AI_TOK = 'aiTokens' as const;
const IN_TOK = 'inputTokens' as const;
const OUT_TOK = 'outputTokens' as const;
const CR_TOK = 'cacheReadTokens' as const;
const CW_TOK = 'cacheWriteTokens' as const;
/** AuditAi.usage with these token counts (no cache). */
export const usageOf = (input: number, output: number) => ({ [IN_TOK]: input, [OUT_TOK]: output, [CR_TOK]: 0, [CW_TOK]: 0 });

const SVC = 'shop-api';
const CI = '.github/workflows/ci.yml';

export const service = (over: Partial<Service> = {}): Service => ({
  name: SVC, path: '.', language: 'node', packageManager: 'npm', runtimeVersion: '20', hasTests: true, testFramework: 'jest',
  envVars: ['DATABASE_URL'], dependsOn: [{ kind: 'postgres', name: 'postgres', evidence: 'package.json: pg', envVars: ['DATABASE_URL'] }],
  scripts: ['start', 'test', 'lint'], frameworks: ['express'], ...over,
});

const cov = (layer: Layer, id: string, status: Coverage['status'], why: string, extra: { service?: string; by?: string; where?: string } = {}): Coverage => ({
  need: need(layer, id, extra.service), status, why,
  ...(extra.by === undefined ? {} : { by: extra.by }), ...(extra.where === undefined ? {} : { where: extra.where }),
});

const coverage = (): Coverage[] => [
  cov('pre-commit', 'hooks', 'covered', 'The repo uses husky to run git hooks.', { by: 'husky', where: '.husky/pre-commit' }),
  cov('pre-commit', 'secrets', 'missing', 'Without a secret scan before each commit, a key can be committed without anyone noticing.'),
  cov('pre-commit', 'format-lint', 'missing', 'Without a format and lint hook, style problems are only found later, in CI or in review.', { service: SVC }),
  cov('push', 'hooks-ci', 'missing', 'Without running the hooks in CI, anyone who skips them locally is never caught.'),
  cov('push', 'secrets', 'missing', 'Without a secret scan in CI, a key committed without the local hook is only found after it leaks.'),
  cov('push', 'sast', 'missing', 'Without a code scan, common security bugs reach the main branch unnoticed.', { service: SVC }),
  cov('push', 'deps', 'partial', 'npm-audit runs, but its failure is ignored (continue-on-error), so it can never fail the build.',
    { service: SVC, by: 'npm-audit', where: `${CI} (job audit)` }),
  cov('push', 'unit-tests', 'covered', 'Your own `npm test` runs on every push.', { service: SVC, by: 'your own `npm test`', where: `${CI} (job test)` }),
  cov('push', 'lint', 'covered', 'Your own `npm run lint` runs on every push.', { service: SVC, by: 'your own `npm run lint`', where: `${CI} (job test)` }),
  cov('merge', 'secrets', 'missing', 'Without a secret scan in CI, a key committed without the local hook is only found after it leaks.'),
  cov('merge', 'unit-tests', 'covered', 'Your own `npm test` runs on every pull request.', { service: SVC, by: 'your own `npm test`', where: `${CI} (job test)` }),
  cov('merge', 'full-tests', 'covered', 'Your own `npm test` runs on every pull request.', { service: SVC, by: 'your own `npm test`', where: `${CI} (job test)` }),
  cov('merge', 'gate', 'missing', 'No single required check sums up every scan, so a failing scan does not stop a merge.'),
  cov('merge', 'dast', 'unknown', "A job calls a reusable workflow from another repo, and pipegen can't see inside it.",
    { service: SVC, by: 'acme/security/.github/workflows/zap.yml@v2', where: `${CI} (job zap)` }),
  cov('deploy', 'sbom', 'missing', 'Without an SBOM, nobody can tell later which components a release shipped.', { service: SVC }),
  cov('deploy', 'deploy-verify', 'missing', "Deploys don't check that the commit passed the pipeline.", { service: SVC }),
];

export const SUGGESTION_NOTE = 'no reviewed tool yet; pipegen would only mention one, never run it as a check';

const row = (c: Coverage, tool: WouldAddRow['tool'], note: string): WouldAddRow => ({ need: c.need, status: c.status as WouldAddRow['status'], tool, note });

const gitleaks = reviewedTool('gitleaks', 'gitleaks/gitleaks-action', 'v2.3.9', ['secrets']);
const semgrep = reviewedTool('semgrep', 'semgrep/semgrep', '1.95.0', ['sast']);

function wouldAdd(c: Coverage[]): WouldAddRow[] {
  const at = (layer: Layer, id: string) => c.find((x) => x.need.layer === layer && x.need.id === id) as Coverage;
  return [
    row(at('pre-commit', 'secrets'), gitleaks, 'reviewed tool'),
    row(at('pre-commit', 'format-lint'), null, SUGGESTION_NOTE),
    row(at('push', 'hooks-ci'), null, SUGGESTION_NOTE),
    row(at('push', 'secrets'), gitleaks, 'reviewed tool'),
    row(at('push', 'sast'), semgrep, 'reviewed tool'),
    row(at('push', 'deps'), null, SUGGESTION_NOTE),
    row(at('merge', 'secrets'), gitleaks, 'reviewed tool'),
    row(at('merge', 'gate'), { kind: 'built-in' }, "pipegen's own check"),
    row(at('merge', 'dast'), null, SUGGESTION_NOTE),
    row(at('deploy', 'sbom'), null, SUGGESTION_NOTE),
    row(at('deploy', 'deploy-verify'), { kind: 'built-in' }, "pipegen's own check"),
  ];
}

export const FREE_PRIVATE_LIMITS = [
  'No merge lock: anyone with write access can merge without checks (GitHub Pro for personal accounts, GitHub Team for organisations, adds it).',
  'Without a merge lock, a pull request could replace the gate with a fake one; only code-owner review stops it.',
  'No deploy approvals: GitHub does not let this repo require a reviewer before a deploy.',
  'No artifact attestations: GitHub does not offer them for this repo.',
  'No code scanning: GitHub does not show scan results in the Security tab for this repo.',
];

/** EXCLUDED_PATTERNS is passed in, so the fixture keeps the model's rule (aiBundle.excludedPatterns equals it exactly). */
export function freePrivateReport(excludedPatterns: readonly string[]): AuditReport {
  const c = coverage();
  return {
    profile: {
      owner: 'acme', repo: 'shop-api', defaultBranch: 'main', private: true, ownerType: 'User', plan: 'free',
      monorepo: 'none', services: [service()], terraformDirs: [], hasCompose: false,
      existingWorkflows: [{ path: CI, triggers: ['push', 'pull_request'], deploys: false, [USED]: [], jobs: ['test', 'audit', 'zap'] }],
      precommit: 'husky',
    },
    capabilities: {
      branchProtection: false, environments: true, envRequiredReviewers: false, deploymentBranchPolicies: true,
      attestations: false, codeScanning: false, keylessSigningAllowed: false,
    },
    support: {
      level: 'full', reasons: [],
      nextStep: 'The full setup arrives in v0.2 for single-package Node/TypeScript repos.',
      nextCommand: null,
    },
    coverage: c,
    wouldAdd: wouldAdd(c),
    wouldCreate: [
      { what: 'docker', why: 'shop-api runs but has no Dockerfile: pipegen would create one, so the image can be built and scanned.' },
      { what: 'compose', why: 'The app uses postgres: pipegen would create a Compose file that starts them for the tests.' },
    ],
    testsNote: null,
    estimates: {
      setupMinutes: 70, setupMinutesCap: 140, monthlyMinutes: 1240, includedMinutes: 2000,
      [AI_TOK]: [{ stage: 'needs', input: 30000, output: 3000 }],
      aiCostUsd: { input: { low: 1.2, high: 3.6 }, output: { low: 0.9, high: 2.7 }, low: 2.1, high: 6.3 }, aiCostCapUsd: 12.6,
      durationMinutes: { low: 12, high: 24 },
      basis: [
        'Setup runs the pipeline for 2 proof variants (the real changes, and the same with planted problems), plus 30% for re-runs (× 1.3).',
        'Activity: at least 300 pushes and at least 41 pull requests in the last 30 days (GitHub lists only the last 300 events and pipegen reads at most 1,000 pull requests).',
        'Your free plan has 2,000 included minutes a month for private repos (docs.github.com, checked 2026-10-26).',
        'The AI cost cap is twice the high estimate ($12.60); pipegen stops calling the AI there.',
      ],
      pricedFor: { provider: 'claude', model: 'claude-opus-5-5' },
    },
    permissions: [
      { permission: 'Contents: read and write', why: 'Opens the pull request with the pipeline files.' },
      { permission: 'Workflows: read and write', why: 'Adds the pipeline workflow files.' },
    ],
    limits: [...FREE_PRIVATE_LIMITS],
    [TREE]: [
      { file: '.env', rule: 'generic-api-' + 'key', note: "(never sent to the AI; check it isn't committed)" },
      { file: 'config/dev.json', rule: 'aws-access-' + 'key' },
      { file: 'config/dev.json', rule: 'private-' + 'key' },
    ],
    aiBundle: { files: 142, bytes: 431_000, truncated: false, excludedPatterns: [...excludedPatterns], topFolders: ['src', 'test', 'scripts'] },
    warnings: [],
    notes: [
      'The secrets scan did not check dependency and build folders (node_modules, .venv, dist, build, vendor, target) or .git, so committed build output was not checked either.',
      "pipegen reads the files on disk without git, so files that aren't committed (for example a local .env) are in this list too.",
    ],
    reviewedUnavailable: false,
  };
}

export const aiPart = (over: Partial<AuditAi> = {}): AuditAi => ({
  extraNeeds: [{ ...need('push', 'type-check', SVC), why: 'The code is TypeScript; a type check catches mistakes the tests miss.' }],
  suggestions: [{ name: 'zizmor', repo: 'woodruffw/zizmor', why: 'Finds risky settings in GitHub Actions workflows.' }],
  notes: ['In this version only GitHub Actions and npm packages can become suggestions.'],
  usage: usageOf(41_200, 3_100),
  costUsd: 0.4235,
  attempts: [
    { model: 'claude-opus-5-5', input: 36_000, output: 2_400, cacheRead: 0, cacheWrite: 0, listUsd: 0.38 },
    { model: 'claude-opus-5-5', input: 5_200, output: 700, cacheRead: 0, cacheWrite: 0, listUsd: 0.0435 },
  ],
  local: false,
  capUsd: 5.5,
  ...over,
} as AuditAi);
