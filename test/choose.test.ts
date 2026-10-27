// Plan P Task 8: the catalogue's choose-rules. Every test uses a fixture reviewed list built here (ruling P14: Task 6
// adds the real entries later), so the rules are checked whatever the data file holds.
import { describe, expect, it } from 'vitest';
import { CHOOSER_IDS, chooseTools, skippedGroups, wouldSetSettings } from '../src/audit/choose.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import type { Capabilities, ExistingWorkflow, Need, RepoProfile, ReviewedTool, Service } from '../src/types.js';

// computed key: a secret-like key name with a value trips the repo's secret-literal check
const USED = 'secretsUsed' as const;
const BASELINE = 'secretsBaseline' as const;
const caps: Capabilities = {
  branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: true,
  attestations: true, codeScanning: true, keylessSigningAllowed: true,
};
const bareCaps: Capabilities = { ...caps, codeScanning: false, attestations: false };

const fixtureTool = (id: string, categories: string[], languages: ReviewedTool['languages'] = ['any'], repo = `acme/${id}`): ReviewedTool => ({
  id, categories, languages,
  candidate: { id, name: id, kind: 'cli', repo, version: '1.0.0', pin: { checksum: 'a'.repeat(64) }, source: 'reviewed', reviewed: true, categories },
  step: { output: { path: '', format: 'none' } }, fixedInputs: {}, choices: {}, configFiles: [], reviewedBy: 'maintainer', reviewedAt: '2026-09-01', proofs: 0,
});

// The fixture list: every id the chooser can name, in the categories and languages the catalogue gives it.
const LIST: ReviewedTool[] = [
  fixtureTool('biome', ['lint', 'format'], ['node']), fixtureTool('eslint', ['lint'], ['node']), fixtureTool('eslint-typescript', ['lint'], ['node']),
  fixtureTool('oxlint-typeaware', ['lint'], ['node']), fixtureTool('prettier', ['format'], ['node']),
  fixtureTool('ruff', ['lint'], ['python']), fixtureTool('ruff-format', ['format'], ['python']), fixtureTool('mypy', ['type-check'], ['python']),
  fixtureTool('vitest-coverage', ['coverage'], ['node']), fixtureTool('c8', ['coverage'], ['node']), fixtureTool('coverage-py', ['coverage'], ['python']),
  fixtureTool('knip', ['dead-code'], ['node']), fixtureTool('creosote', ['dead-code'], ['python']), fixtureTool('vulture', ['dead-code'], ['python']),
  fixtureTool('jscpd', ['duplication']), fixtureTool('hadolint', ['dockerfile-lint']),
  fixtureTool('actionlint', ['workflow-lint']), fixtureTool('zizmor', ['workflow-lint']), fixtureTool('poutine', ['workflow-lint']), fixtureTool('pinact', ['workflow-pin-check']),
  fixtureTool('osv-scanner', ['dependency-review']), fixtureTool('dependency-review-action', ['dependency-review']), fixtureTool('trivy-licence', ['licences']),
  fixtureTool('schemathesis', ['api-dast']), fixtureTool('trivy-config', ['iac']), fixtureTool('kube-linter', ['iac']),
  fixtureTool('betterleaks', ['secrets']), fixtureTool('bullfrog', ['egress']), fixtureTool('scorecard-action', ['scorecard']),
];

const svc = (over: Partial<Service> = {}, quality: Partial<Service['quality']> = {}): Service => ({
  name: 'app', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: [], frameworks: [],
  quality: { ...emptyServiceQuality(), ...quality }, ...over,
});
const profile = (services: Service[] = [svc()], over: Partial<RepoProfile> = {}): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none', services, terraformDirs: [], hasCompose: false,
  existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(), ...over,
});
const needOf = (category: string, service?: string): Need => ({ id: category, layer: 'push', category, ...(service === undefined ? {} : { service }), why: '', blocking: true, floor: false });
const choose = (category: string, p: RepoProfile, list: ReviewedTool[] = LIST, c: Capabilities = caps) => {
  const service = p.services[0];
  const n = needOf(category, ['workflow-lint', 'workflow-pin-check', 'dependency-review', 'licences', 'iac', 'secrets', 'update-config', 'publishing', 'egress', 'scorecard', 'duplication'].includes(category) ? undefined : service?.name);
  return chooseTools(n, n.service === undefined ? undefined : service, p, c, list);
};
const idOf = (t: unknown) => (t as { id?: string; kind?: string; tool?: string } | null)?.id ?? (t as { tool?: string } | null)?.tool ?? null;
const alsoIds = (c: { also: unknown[] }) => c.also.map(idOf);
const ownTool = (c: { tool: unknown }) => c.tool as { kind: string; tool: string; version: string | null };

describe('choose: lint', () => {
  it('choose: no linter config, plain TS library → biome for lint and format', () => {
    const p = profile([svc({}, { tsconfig: true })]);
    const lint = choose('lint', p);
    expect(idOf(lint.tool)).toBe('biome');
    expect(lint.note).toBe('Biome: no linter configured; TypeScript repo without a framework plugin');
    expect(idOf(choose('format', p).tool)).toBe('biome');
  });
  it('choose: no config, Vue app on TS 6 → eslint-typescript lint + prettier format', () => {
    const p = profile([svc({}, { tsconfig: true, uiFrameworks: ['vue'], versions: { typescript: '6.0.3' } })]);
    expect(idOf(choose('lint', p).tool)).toBe('eslint-typescript');
    expect(idOf(choose('format', p).tool)).toBe('prettier');
  });
  it('choose: TS 7 → own tsc 7.0.2; Next app lint = ESLint + Oxlint type-aware, never typescript-eslint', () => {
    const p = profile([svc({}, { tsconfig: true, uiFrameworks: ['next'], versions: { typescript: '7.0.2' } })]);
    const lint = choose('lint', p);
    expect(idOf(lint.tool)).toBe('eslint');
    expect(alsoIds(lint)).toEqual(['oxlint-typeaware']);
    expect(JSON.stringify(lint)).not.toContain('eslint-typescript');
    const tc = ownTool(choose('type-check', p));
    expect(tc).toMatchObject({ kind: 'repo-tool', tool: 'tsc', version: '7.0.2' });
  });
  it('choose: Next, Nuxt, Svelte, Astro and React Native without a config get ESLint; plain JS gets eslint, not typescript-eslint', () => {
    for (const f of ['next', 'nuxt', 'svelte', 'astro', 'react-native'] as const) {
      expect(idOf(choose('lint', profile([svc({}, { uiFrameworks: [f] })])).tool), f).toBe('eslint');
    }
  });
  it('choose: repo ESLint config → own eslint at its lockfile version, never biome', () => {
    const p = profile([svc({}, { eslintConfig: 'flat', versions: { eslint: '9.39.1' }, uiFrameworks: ['vue'] })]);
    const lint = choose('lint', p);
    expect(ownTool(lint)).toMatchObject({ kind: 'repo-tool', tool: 'eslint', version: '9.39.1' });
    expect(JSON.stringify(choose('lint', profile([svc({}, { eslintConfig: 'flat' })])))).not.toContain('biome');
  });
  it('choose: ESLint 10 with only an eslintrc → own eslint, note says error and names the migration tool (never a switch)', () => {
    const lint = choose('lint', profile([svc({}, { eslintConfig: 'eslintrc', versions: { eslint: '10.1.0' } })]));
    expect(ownTool(lint).tool).toBe('eslint');
    expect(lint.note).toContain('error');
    expect(lint.note).toContain('@eslint/migrate-config');
    expect(lint.note).not.toContain('npx');
  });
  it('choose: a Biome or Oxlint config is the repo\'s own linter', () => {
    expect(ownTool(choose('lint', profile([svc({}, { configs: ['biome'], versions: { '@biomejs/biome': '2.5.15' } })])))).toMatchObject({ tool: 'biome', version: '2.5.15' });
    expect(ownTool(choose('lint', profile([svc({}, { configs: ['oxlint'], versions: { oxlint: '1.40.0' } })])))).toMatchObject({ tool: 'oxlint', version: '1.40.0' });
  });
  it('choose: Prettier config with Biome lint → prettier for format', () => {
    const p = profile([svc({}, { configs: ['biome', 'prettier'], versions: { '@biomejs/biome': '2.5.15' } })]);
    expect(idOf(choose('format', p).tool)).toBe('prettier');
    const owned = profile([svc({}, { configs: ['prettier'], versions: { prettier: '3.6.0' } })]);
    expect(ownTool(choose('format', owned))).toMatchObject({ tool: 'prettier', version: '3.6.0' });
  });
  it('choose: Python → ruff lint (flake8 or pylint configured → own), ruff-format (Black configured → own), mypy (a configured checker → own)', () => {
    const py = (q: Partial<Service['quality']> = {}) => profile([svc({ language: 'python', packageManager: 'pip' }, q)]);
    expect(idOf(choose('lint', py()).tool)).toBe('ruff');
    expect(ownTool(choose('lint', py({ configs: ['flake8'] }))).tool).toBe('flake8');
    expect(ownTool(choose('lint', py({ configs: ['pylint'] }))).tool).toBe('pylint');
    expect(idOf(choose('format', py()).tool)).toBe('ruff-format');
    expect(ownTool(choose('format', py({ configs: ['black'] }))).tool).toBe('black');
    expect(idOf(choose('type-check', py()).tool)).toBe('mypy');
    expect(ownTool(choose('type-check', py({ configs: ['pyright'] }))).tool).toBe('pyright');
  });
  it('choose: a node tool is never picked for a Python service, nor a Python tool for Node', () => {
    const py = profile([svc({ language: 'python', packageManager: 'pip' })]);
    expect(JSON.stringify(choose('lint', py, [fixtureTool('biome', ['lint'], ['node'])]))).not.toContain('biome');
    expect(choose('lint', py, [fixtureTool('biome', ['lint'], ['node'])]).tool).toBeNull();
    expect(choose('lint', profile([svc()]), [fixtureTool('ruff', ['lint'], ['python'])]).tool).toBeNull();
  });
});

describe('choose: type-check', () => {
  it('choose: Vue → vue-tsc, Svelte → svelte-check, Astro → astro check (own, at the lockfile version)', () => {
    const q = (f: 'vue' | 'svelte' | 'astro', versions: Service['quality']['versions']) => profile([svc({}, { uiFrameworks: [f], tsconfig: true, versions })]);
    expect(ownTool(choose('type-check', q('vue', { 'vue-tsc': '3.1.0', typescript: '6.0.3' })))).toMatchObject({ tool: 'vue-tsc', version: '3.1.0' });
    expect(ownTool(choose('type-check', q('svelte', { 'svelte-check': '4.3.0' })))).toMatchObject({ tool: 'svelte-check', version: '4.3.0' });
    expect(ownTool(choose('type-check', q('astro', { '@astrojs/check': '0.9.5' })))).toMatchObject({ tool: 'astro check', version: '0.9.5' });
  });
  it('choose: the checker is not in the lockfile → suggestion only, named', () => {
    const c = choose('type-check', profile([svc({}, { uiFrameworks: ['vue'], tsconfig: true, versions: { typescript: '6.0.3' } })]));
    expect(c.tool).toBeNull();
    expect(c.note).toContain('vue-tsc');
  });
});

describe('choose: coverage', () => {
  const withRunner = (q: Partial<Service['quality']>, over: Partial<Service> = {}) => profile([svc(over, q)]);
  it('choose: vitest / jest / node:test / pytest → vitest-coverage / own jest / c8 / coverage-py', () => {
    expect(idOf(choose('coverage', withRunner({ versions: { vitest: '5.0.5' } })).tool)).toBe('vitest-coverage');
    expect(ownTool(choose('coverage', withRunner({ versions: { jest: '30.2.0' } })))).toMatchObject({ kind: 'repo-tool', tool: 'jest', version: '30.2.0' });
    expect(idOf(choose('coverage', withRunner({}, { testFramework: 'node:test' })).tool)).toBe('c8');
    expect(idOf(choose('coverage', profile([svc({ language: 'python', packageManager: 'pip', testFramework: 'pytest' })])).tool)).toBe('coverage-py');
  });
  it('choose: the coverage note gives the floor rule', () => {
    expect(choose('coverage', withRunner({ versions: { vitest: '5.0.5' } })).note).toContain('`floor(current) - 1`; 60% of lines for repos with few tests; an existing minimum is kept');
  });
});

describe('choose: dead code, duplication, dockerfile', () => {
  it('choose: knip.json → blocking note; none → report-only note', () => {
    expect(choose('dead-code', profile([svc({}, { configs: ['knip'] })])).note).toContain('blocking because `knip.json` exists');
    expect(choose('dead-code', profile()).note).toContain('report-only on the first run');
    expect(idOf(choose('dead-code', profile()).tool)).toBe('knip');
  });
  it('choose: Python dead code → creosote and also vulture', () => {
    const c = choose('dead-code', profile([svc({ language: 'python', packageManager: 'pip' })]));
    expect(idOf(c.tool)).toBe('creosote');
    expect(alsoIds(c)).toEqual(['vulture']);
  });
  it('choose: Go dead code → report-only note, no tool', () => {
    const c = choose('dead-code', profile([svc({ language: 'go' })]));
    expect(c.tool).toBeNull();
    expect(c.note).toContain('go mod tidy -diff');
  });
  it('choose: duplication → jscpd, warning only; dockerfile → hadolint, Trivy config stays on', () => {
    const d = choose('duplication', profile());
    expect(idOf(d.tool)).toBe('jscpd');
    expect(d.note).toContain('warning only; new copy-paste in the pull request only');
    const h = choose('dockerfile-lint', profile());
    expect(idOf(h.tool)).toBe('hadolint');
    expect(h.note).toContain("Trivy config's Dockerfile checks stay on");
  });
});

describe('choose: workflows, dependencies, licences', () => {
  const wf = (triggers: string[]): ExistingWorkflow => ({ path: '.github/workflows/a.yml', triggers, deploys: false, [USED]: [], jobs: ['a'] });
  it('choose: pull_request_target → workflow-lint also poutine; plain triggers → zizmor only', () => {
    const risky = choose('workflow-lint', profile([svc()], { existingWorkflows: [wf(['pull_request_target'])] }));
    expect(idOf(risky.tool)).toBe('actionlint');
    expect(alsoIds(risky)).toEqual(['zizmor', 'poutine']);
    expect(alsoIds(choose('workflow-lint', profile([svc()], { existingWorkflows: [wf(['push'])] })))).toEqual(['zizmor']);
    expect(alsoIds(choose('workflow-lint', profile([svc()], { existingWorkflows: [wf(['workflow_run'])] })))).toContain('poutine');
    expect(alsoIds(choose('workflow-lint', profile([svc()], { existingWorkflows: [wf(['issue_comment'])] })))).toContain('poutine');
  });
  it('choose: pinact; an actions lock adds the note', () => {
    expect(idOf(choose('workflow-pin-check', profile()).tool)).toBe('pinact');
    const locked = choose('workflow-pin-check', profile([svc()], { repoFiles: { ...emptyRepoFiles(), actionsLock: true } }));
    expect(locked.note).toContain("won't rewrite its pins");
  });
  it('choose: public → osv-scanner + dependency-review-action; user-owned private → osv-scanner only (R4)', () => {
    expect(alsoIds(choose('dependency-review', profile()))).toEqual(['dependency-review-action']);
    const userPrivate = choose('dependency-review', profile([svc()], { private: true, ownerType: 'User' }), LIST, caps);
    expect(idOf(userPrivate.tool)).toBe('osv-scanner');
    expect(userPrivate.also).toEqual([]);
    expect(alsoIds(choose('dependency-review', profile([svc()], { private: true, ownerType: 'Organization' }), LIST, caps))).toEqual(['dependency-review-action']);
    expect(choose('dependency-review', profile([svc()], { private: true, ownerType: 'Organization' }), LIST, bareCaps).also).toEqual([]);
  });
  it('choose: deny.toml → cargo-deny suggestion; .fossa.yml → keep FOSSA; else trivy-licence', () => {
    const lc = (licenceConfig: 'deny.toml' | '.grant.yaml' | '.fossa.yml' | null) => choose('licences', profile([svc()], { repoFiles: { ...emptyRepoFiles(), licenceConfig } }));
    expect(lc('deny.toml')).toMatchObject({ tool: null });
    expect(lc('deny.toml').note).toContain('cargo-deny');
    expect(lc('.grant.yaml').note).toContain('grant');
    expect(lc('.fossa.yml')).toMatchObject({ tool: null });
    expect(lc('.fossa.yml').note).toContain('keep FOSSA');
    expect(idOf(lc(null).tool)).toBe('trivy-licence');
  });
  it('choose: schemathesis names the spec path, or the framework that serves it', () => {
    const file = choose('api-dast', profile([svc({}, { apiSpec: { kind: 'file', path: 'docs/openapi.yaml' } })]));
    expect(idOf(file.tool)).toBe('schemathesis');
    expect(file.note).toContain('docs/openapi.yaml');
    expect(choose('api-dast', profile([svc({}, { apiSpec: { kind: 'served', by: 'fastapi' } })])).note).toContain('served by FastAPI');
    expect(choose('api-dast', profile([svc({}, { apiSpec: { kind: 'served', by: '@nestjs/swagger' } })])).note).toContain('served by NestJS');
  });
});

describe('choose: iac, secrets, update config, publishing, the scheduled checks', () => {
  it('choose: k8s → iac also kube-linter', () => {
    expect(alsoIds(choose('iac', profile([svc()], { repoFiles: { ...emptyRepoFiles(), kubernetes: true } })))).toEqual(['kube-linter']);
    expect(choose('iac', profile()).also).toEqual([]);
    expect(idOf(choose('iac', profile()).tool)).toBe('trivy-config');
  });
  it('choose: betterleaks; a .secrets.baseline adds the detect-secrets note', () => {
    expect(idOf(choose('secrets', profile()).tool)).toBe('betterleaks');
    expect(choose('secrets', profile([svc()], { repoFiles: { ...emptyRepoFiles(), [BASELINE]: true } })).note).toContain('detect-secrets also runs');
  });
  it('choose: Renovate config → keep Renovate; none → Dependabot built-in with 7-day cooldown', () => {
    const renovate = choose('update-config', profile([svc()], { repoFiles: { ...emptyRepoFiles(), renovate: 'renovate.json' } }));
    expect(renovate.tool).toEqual({ kind: 'built-in' });
    expect(renovate.note).toBe('keep Renovate; set `minimumReleaseAge: "7 days"`');
    const none = choose('update-config', profile());
    expect(none.tool).toEqual({ kind: 'built-in' });
    expect(none.note).toBe('pipegen would write `.github/dependabot.yml`: weekly, grouped, `cooldown.default-days: 7`');
  });
  it('choose: publishing is built in; egress → bullfrog; scorecard → scorecard-action; fuzzing → nothing, built in v0.3', () => {
    expect(choose('publishing', profile())).toMatchObject({ tool: { kind: 'built-in' }, note: 'trusted publishing (OIDC); no long-lived token' });
    expect(idOf(choose('egress', profile()).tool)).toBe('bullfrog');
    expect(idOf(choose('scorecard', profile()).tool)).toBe('scorecard-action');
    expect(choose('fuzzing', profile())).toMatchObject({ tool: null, note: 'pipegen builds fuzzing in v0.3' });
  });
  it('choose: a check with no rule keeps the first reviewed entry (PS35)', () => {
    const c = choose('sast', profile(), [fixtureTool('semgrep', ['sast'], ['node']), fixtureTool('other', ['sast'])]);
    expect(idOf(c.tool)).toBe('semgrep');
    expect(c.note).toBe('reviewed tool');
    expect(choose('sast', profile(), []).note).toBe('');
  });
});

describe('choose: the reviewed list', () => {
  it('choose: every CHOOSER_IDS entry is in data/reviewed-tools.yml', { todo: true }, () => {
    // Enabled by Task 6, which adds the ~28 real entries (ruling P14); until then the fixture list above stands in.
  });
  it('choose: CHOOSER_IDS lists every id the fixture list needs, once each', () => {
    expect(new Set(CHOOSER_IDS).size).toBe(CHOOSER_IDS.length);
    expect([...CHOOSER_IDS].sort()).toEqual(LIST.map((t) => t.id).sort());
  });
  it('choose: an id missing from the list → suggestion only, no crash', () => {
    const p = profile([svc({}, { tsconfig: true })]);
    const c = choose('lint', p, []);
    expect(c.tool).toBeNull();
    expect(c.also).toEqual([]);
    expect(c.note).toContain('Biome');
    expect(c.note).toContain('not on the reviewed list');
    for (const category of ['lint', 'format', 'coverage', 'dead-code', 'duplication', 'workflow-lint', 'iac', 'secrets', 'dependency-review']) {
      expect(() => choose(category, p, [])).not.toThrow();
    }
  });
  it('choose: a never-listed tool is never chosen, even when a fixture list holds it', () => {
    // tfsec is on the never-list; the same id under another owner, or with a look-alike name, is refused too
    const listed = [fixtureTool('trivy-config', ['iac'], ['any'], 'aquasecurity/tfsec'), fixtureTool('zizmor', ['workflow-lint'], ['any'], 'zizmorcore/zizmor-action'),
      fixtureTool('actionlint', ['workflow-lint'])];
    expect(choose('iac', profile(), listed).tool).toBeNull();
    const wl = choose('workflow-lint', profile(), listed);
    expect(idOf(wl.tool)).toBe('actionlint');
    expect(wl.also).toEqual([]);
    // an image on the never-list
    const image = fixtureTool('trivy-config', ['iac'], ['any'], 'aquasec/trivy');
    image.candidate.kind = 'docker';
    expect(choose('iac', profile(), [image]).tool).toBeNull();
    // a fork of a never-listed name under any owner
    expect(choose('iac', profile(), [fixtureTool('trivy-config', ['iac'], ['any'], 'someone/tfsec')]).tool).toBeNull();
  });
});

describe('skipped checks, grouped', () => {
  it('choose: identical skips collapse to one line per reason, listing the checks and services', () => {
    const none = skippedGroups(profile([]), caps);
    const reasons = none.map((g) => g.why);
    expect(new Set(reasons).size).toBe(reasons.length);
    const noServices = none.find((g) => g.why === 'no services found');
    expect(noServices?.categories).toEqual(expect.arrayContaining(['format', 'type-check', 'coverage', 'dead-code', 'duplication', 'fuzzing']));
    const two = skippedGroups(profile([svc({ name: 'a' }), svc({ name: 'b' })]), caps);
    const fuzz = two.filter((g) => g.categories.includes('fuzzing'));
    expect(fuzz).toHaveLength(1);
    expect(fuzz[0]).toMatchObject({ why: 'no fuzz targets found', services: ['a', 'b'] });
  });
});

describe('wouldSet', () => {
  it('audit: sha-pinning and Dependabot alerts on every repo; secret scanning public only; private gets the paid note', () => {
    const pub = wouldSetSettings(profile(), []);
    expect(pub.map((x) => x.setting)).toEqual(['sha-pinning', 'dependabot-alerts', 'secret-scanning']);
    expect(pub[2]?.why).toContain('push protection');
    const priv = wouldSetSettings(profile([svc()], { private: true }), []);
    expect(priv.map((x) => x.setting)).toEqual(['sha-pinning', 'dependabot-alerts', 'secret-scanning']);
    expect(priv[2]?.why).toBe("A paid add-on (GitHub Secret Protection); pipegen can't turn it on here.");
    expect(priv[2]?.why).not.toMatch(/public|push protection/i);
    expect(pub[0]?.why).toContain("can't see this setting with read access");
  });
  it('wouldSet: the sha-pinning why follows the pin check row (PS36)', () => {
    const covered = [{ need: needOf('workflow-pin-check'), status: 'covered', why: '' }] as never;
    expect(wouldSetSettings(profile(), covered)[0]?.why).toContain('passes today');
    expect(wouldSetSettings(profile(), [])[0]?.why).toContain('would stop running');
  });
});
