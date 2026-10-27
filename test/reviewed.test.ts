import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parse, stringify } from 'yaml';
import { checkPinnedAgainstReviewed, loadPinnedBinaries } from '../src/engine/linters.js';
import { NEED_ID_CATEGORY } from '../src/engine/needs.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { COOLDOWN_DAYS, PinError, PLATFORM_ACTION_IDS, resolvePin } from '../src/engine/pin.js';
import {
  effectiveProtectedPaths, loadReviewed, MUST_VERIFY, nearDuplicate, NEVER_REPOS, neverListed, packageExists, projectScriptFor, ReviewedListError, reviewedFor, TOOL_CATEGORIES,
} from '../src/engine/reviewed.js';
import { BETTERLEAKS_FORBIDDEN_FLAGS } from '../src/engine/tool-flags.js';
import { NEED_CATEGORIES, PROTECTED_PATHS_BASE, type Need, type ReviewedTool, type Service } from '../src/types.js';
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
    choices: { 'node-version': ['22', '24'] },
    configFiles: [],
    reviewedBy: 'PENDING', reviewedAt: 'PENDING', proofs: 0,
  };
}

/** A reviewed release-binary entry (pinned by sha256). */
function cliEntry(over: Entry = {}): Entry {
  const id = over.id ?? 'gitleaks';
  const repo = over.repo ?? 'gitleaks/gitleaks';
  const categories = over.categories ?? ['secrets'];
  return {
    id, categories, languages: ['any'], releasedAt: '2026-01-01T00:00:00Z',
    candidate: candidate(id, 'cli', repo, 'v8.30.1', { checksum: SUM }, categories),
    step: {
      cli: { install: { method: 'github-release', package: 'gitleaks_8.30.1_linux_x64.tar.gz', version: 'v8.30.1' }, command: ['gitleaks', 'git', '--no-banner', '--report-format', 'sarif', '--report-path', 'gitleaks.sarif'] },
      output: { path: 'gitleaks.sarif', format: 'sarif' },
    },
    fixedInputs: { args: ['--report-format', 'sarif'], config: { content: '[extend]\nuseDefault = true\n', passAs: { flag: '--config' } } },
    choices: {},
    configFiles: ['.gitleaks.toml', '.gitleaksignore'],
    reviewedBy: 'PENDING', reviewedAt: 'PENDING', proofs: 0,
  };
}

/** The Semgrep CE entry: an image, with a rules pack pinned by commit SHA and archive sha256 (ruling S22). */
function semgrepEntry(env: Record<string, string> = RULES_ENV, command?: string[], args = ['--metrics=off', '--config', RULES_DIR]): Entry {
  const categories = ['sast'];
  return {
    id: 'semgrep', categories, languages: ['node', 'python'], releasedAt: '2026-01-01T00:00:00Z',
    candidate: candidate('semgrep', 'docker', 'semgrep/semgrep', '1.181.0', { digest: DIGEST }, categories),
    step: {
      cli: { install: { method: 'docker', package: 'semgrep/semgrep', version: '1.181.0' }, command: command ?? ['semgrep', 'scan', '--metrics=off', '--config', RULES_DIR, '--sarif', '--output', 'semgrep.sarif'], env },
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

const load = (tools: Entry[]) => loadReviewed(writeList(tools));
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
    // present but empty is fine: cosign loads no config file from the repo
    const empty = cliEntry({ id: 'cosign', repo: 'sigstore/cosign', categories: ['signing'] });
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
    const scan = (...rest: string[]) => ['semgrep', 'scan', '--metrics=off', '--config', RULES_DIR, ...rest];
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
    expect(load([semgrepEntry(undefined, ['semgrep', 'scan', '--metrics=off', `--config=${RULES_DIR}`], ['--metrics=off', `--config=${RULES_DIR}`])])).toHaveLength(1);
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
      if (ok) expect(load([withImage(pkg)]), `reviewed: ${pkg}`).toHaveLength(1);
      else expect(() => load([withImage(pkg)]), `reviewed: ${pkg}`).toThrow(/image name/);
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
    const ok = cliEntry();
    ok.choices = { severity: ['high'] };
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
/** A recorded signature check (PS24): the exact certificate identity, never a regex. */
const verified = (over: Entry = {}): Entry => ({
  method: 'cosign-bundle', asset: 'checksums.txt', identity: 'https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1.0.0',
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

/** A release-binary entry for any repo, valid unless the test breaks it (cliEntry with the parts the test names). */
function binEntry(repo: string, over: { id?: string; command?: string[]; args?: string[]; env?: Record<string, string>; config?: Entry | null; verifiedWith?: Entry | null; choices?: Entry } = {}): Entry {
  const e = cliEntry({ id: over.id ?? 'tool', repo });
  e.candidate.version = 'v1.0.0';
  e.step.cli.install = { method: 'github-release', package: 'tool_1.0.0_linux_amd64.tar.gz', version: 'v1.0.0' };
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
  const e = cliEntry({ id: 'linter', repo: method === 'npm' ? 'eslint/eslint' : 'schemathesis/schemathesis', categories: ['lint'] });
  e.candidate.version = version;
  e.candidate.pin = { checksum: method === 'npm' ? SRI : SUM };
  e.step.cli.install = { method, package: pkg, version };
  e.step.cli.command = [method === 'npm' ? 'eslint' : 'st', '--format', 'sarif'];
  e.fixedInputs = { args: ['--format', 'sarif'] };
  e.configFiles = [];
  if (plugins !== undefined) e.step.cli.plugins = plugins;
  return e;
}
const npmPlugin = (pkg: string, over: Entry = {}): Entry => ({ method: 'npm', package: pkg, version: '8.72.0', checksum: SRI, ...over });
const pipPlugin = (pkg: string, over: Entry = {}): Entry => ({ method: 'pip', package: pkg, version: '1.2.3', checksum: SUM, ...over });

/** The trivy fixture: the three hardening flags in the command and the fixed args, and the signature check. */
function trivyEntry(over: { command?: string[]; args?: string[]; verifiedWith?: Entry | null; repo?: string } = {}): Entry {
  return binEntry(over.repo ?? 'aquasecurity/trivy', {
    id: 'trivy-config',
    command: over.command ?? ['trivy', 'config', ...TRIVY_FLAGS, '--format', 'sarif', '--output', 'tool.sarif', '--exit-code', '1', '.'],
    args: over.args ?? [...TRIVY_FLAGS, '--format', 'sarif'],
    verifiedWith: over.verifiedWith === undefined ? verified({ identity: TRIVY_IDENTITY.replace('v0.76.0', 'v1.0.0') }) : over.verifiedWith,
  });
}
const jscpdEntry = (over: Parameters<typeof binEntry>[1] = {}) => binEntry('kucherenko/jscpd', {
  id: 'jscpd', command: ['jscpd', '--reporters', 'sarif', '--output', '.'], args: ['--reporters', 'sarif'], verifiedWith: verified({ identity: 'https://github.com/kucherenko/jscpd/.github/workflows/release.yml@refs/heads/master' }), ...over,
});
const betterleaksEntry = (over: Parameters<typeof binEntry>[1] = {}) => binEntry('betterleaks/betterleaks', {
  id: 'betterleaks', command: ['betterleaks', 'git', '--report-format', 'sarif', '--report-path', 'tool.sarif'], args: ['--report-format', 'sarif'],
  config: { content: '[extend]\nuseDefault = true\n', passAs: { flag: '--config' } }, verifiedWith: verified({ identity: 'https://github.com/betterleaks/betterleaks/.github/workflows/release.yml@refs/tags/v1.0.0' }), ...over,
});
const nucleiCmd = (...rest: string[]) => ['nuclei', '-duc', '-t', NUCLEI_DIR, '-severity', 'medium,high,critical', '-sarif-export', 'tool.sarif', ...rest];
const nucleiEntry = (over: Parameters<typeof binEntry>[1] = {}) => binEntry('projectdiscovery/nuclei', {
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
    for (const r of ['aquasecurity/trivy-actions', 'aquasecurlty/trivy-action', 'checkmarx/kicss', 'zizmorcore/zizmor-acton', 'reviewdoq/action-setup', 'portswiger/dastardly']) {
      expect(neverListed(r), r).not.toBeNull();
      rejects([actionEntry({ id: 'x', repo: r })], NEVER_MSG);
    }
    rejects([imageEntry('checkmarx/klcs')], NEVER_MSG);
    // far enough away: fine
    for (const r of ['aquasecurity/trivy', 'fine/tool', 'reviewers/tool', 'checkmarx/other-tool']) expect(neverListed(r), r).toBeNull();
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
    // any trivy: found by its repo in any case, its image or its command, not only aquasecurity/trivy
    rejects([trivyEntry({ repo: 'AquaSecurity/Trivy', args: ['--format', 'sarif'], command: ['trivy', 'config', '--format', 'sarif', '--output', 'tool.sarif'] })], /--disable-telemetry/);
    const img = imageEntry('aquasec/trivy');
    img.step.cli.command = ['trivy', 'image', '--format', 'sarif'];
    img.fixedInputs.args = ['--format', 'sarif'];
    rejects([img], /--disable-telemetry/);
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
        method: 'cosign-bundle', asset: 'trivy_0.76.0_checksums.txt', identity: TRIVY_IDENTITY, issuer: ISSUER, verifiedOn: '2026-10-27',
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
    rejects([jscpdEntry({ command: [...cmd, '--semantic'], args: ['--reporters', 'sarif', '--semantic'] })], SEMANTIC);
    rejects([jscpdEntry({ env: { JSCPD_SEMANTIC: 'true' } })], SEMANTIC);
    rejects([jscpdEntry({ env: { JSCPD_ARGS: '--semantic' } })], SEMANTIC);
    rejects([jscpdEntry({ choices: { mode: ['--semantic'] } })], SEMANTIC);
    rejects([jscpdEntry({ choices: { semantic: ['true'] } })], SEMANTIC);
    rejects([jscpdEntry({ config: { content: '{ "semantic": true }\n', passAs: { flag: '--config' } } })], SEMANTIC);
    // a jscpd step under another repo or package name is still jscpd
    rejects([binEntry('fine/tool', { command: ['npx', 'jscpd', '--semantic'], args: [] })], SEMANTIC);
    const npm = pkgEntry('npm', undefined, 'jscpd');
    npm.step.cli.command = ['jscpd', '--format', 'sarif', '--semantic'];
    rejects([npm], SEMANTIC);
  });

  it('reviewed: betterleaks with --validate, --analyze or --unsafe-auto-load-config refused; without a pinned --config refused', () => {
    expect([...BETTERLEAKS_FORBIDDEN_FLAGS]).toEqual(['--validate', '--analyze', '--unsafe-auto-load-config']);
    expect(load([betterleaksEntry()])).toHaveLength(1);
    const cmd = ['betterleaks', 'git', '--report-format', 'sarif', '--report-path', 'tool.sarif'];
    for (const flag of BETTERLEAKS_FORBIDDEN_FLAGS) {
      const re = new RegExp(flag);
      rejects([betterleaksEntry({ command: [...cmd, flag] })], re);
      rejects([betterleaksEntry({ command: [...cmd, `${flag}=true`] })], re);
      rejects([betterleaksEntry({ command: [...cmd, flag.slice(1)] })], re); // one dash
      rejects([betterleaksEntry({ command: [...cmd, flag], args: ['--report-format', 'sarif', flag] })], re);
      rejects([betterleaksEntry({ choices: { [flag.replace(/^--/, '')]: ['true'] } })], re);
      rejects([betterleaksEntry({ choices: { extra: [flag] } })], re);
    }
    rejects([betterleaksEntry({ config: null })], /pinned --config/);
    rejects([betterleaksEntry({ config: { content: 'x\n', passAs: { flag: '--baseline-path' } } })], /pinned --config/);
    rejects([betterleaksEntry({ command: [...cmd, '--config', 'repo.toml'] })], /pinned --config/); // a second config
    rejects([betterleaksEntry({ command: [...cmd, '-c=repo.toml'] })], /pinned --config/);
    rejects([betterleaksEntry({ env: { BETTERLEAKS_CONFIG: 'repo.toml' } })], /pinned --config/);
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

  it('reviewed: plugins must be exact, hashed npm/pip packages; at most 4', () => {
    const ok = load([pkgEntry('npm', [npmPlugin('typescript-eslint'), npmPlugin('@eslint/js')])])[0];
    expect(ok?.step.cli?.plugins?.map((p) => p.package)).toEqual(['typescript-eslint', '@eslint/js']);
    expect(load([pkgEntry('pip', [pipPlugin('hypothesis')])])).toHaveLength(1);
    // the wrapper's own platform package is a different name, so it is allowed (PS26)
    expect(load([pkgEntry('npm', [npmPlugin('@biomejs/cli-linux-x64')], '@biomejs/biome')])).toHaveLength(1);
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
    expect([...MUST_VERIFY].sort()).toEqual(['aquasecurity/trivy', 'betterleaks/betterleaks', 'hadolint/hadolint', 'kucherenko/jscpd', 'securego/gosec', 'stackrox/kube-linter']);
    const entries: Record<string, (v: Entry | null) => Entry> = {
      'aquasecurity/trivy': (v) => trivyEntry({ verifiedWith: v }),
      'betterleaks/betterleaks': (v) => betterleaksEntry({ verifiedWith: v }),
      'kucherenko/jscpd': (v) => jscpdEntry({ verifiedWith: v }),
      'hadolint/hadolint': (v) => binEntry('hadolint/hadolint', { verifiedWith: v }),
      'stackrox/kube-linter': (v) => binEntry('stackrox/kube-linter', { verifiedWith: v }),
      'securego/gosec': (v) => binEntry('securego/gosec', { verifiedWith: v }),
    };
    for (const repo of MUST_VERIFY) {
      const make = entries[repo] as (v: Entry | null) => Entry;
      rejects([make(null)], /verifiedWith/);
      const upper = make(null);
      upper.candidate.repo = repo.toUpperCase();
      upper.candidate.name = repo.toUpperCase();
      rejects([upper], /verifiedWith/);
      const v = verified({ identity: `https://github.com/${repo}/.github/workflows/release.yml@refs/tags/v1.0.0` });
      expect(load([make(v)])[0]?.verifiedWith, repo).toEqual(v); // it stays on the ReviewedTool (PS24)
    }
    // any entry may record one; it is checked the same way
    expect(load([binEntry('fine/tool', { verifiedWith: verified() })])[0]?.verifiedWith?.method).toBe('cosign-bundle');
    const hado = (over: Entry) => binEntry('hadolint/hadolint', { verifiedWith: verified({ identity: 'https://github.com/hadolint/hadolint/.github/workflows/haskell.yml@refs/tags/v1.0.0', ...over }) });
    expect(load([hado({ method: 'github-attestation', asset: 'hadolint-linux-x86_64' })])).toHaveLength(1);
    expect(load([hado({ method: 'cosign-signature' })])).toHaveLength(1);
    rejects([hado({ method: 'gpg' })]);
    rejects([hado({ issuer: 'https://accounts.google.com' })]);
    rejects([hado({ verifiedOn: '2026-10-25' })], /pinnedOn/); // the fixture list is pinned on 2026-10-26
    rejects([hado({ verifiedOn: '2026-02-30' })], /verifiedOn/);
    rejects([hado({ asset: '../checksums.txt' })]);
    rejects([hado({ identity: '^https://github.com/hadolint/.*$' })], /identity/); // exact identity, never a regex
    rejects([hado({ identity: 'https://github.com/hadolint/hadolint/.github/workflows/.*' })], /identity/);
    rejects([hado({ identity: 'https://example.com/hadolint/hadolint/.github/workflows/haskell.yml@refs/tags/v1.0.0' })], /identity/);
    rejects([hado({ identity: 'https://github.com/hadolint/hadolint/.github/workflows/haskell.yml@refs/tags/v0.9.0' })], /identity/); // another release's tag
    const extra = hado({});
    extra.verifiedWith.note = 'x';
    rejects([extra]);
    expect(load([hado({ identity: 'https://github.com/o/shared/.github/workflows/release.yaml@1cf29d7b17983b901021799b87a55d357cfff790' })])).toHaveLength(1);
    expect(load([hado({ identity: 'https://github.com/hadolint/hadolint/.github/workflows/haskell.yml@refs/heads/master' })])).toHaveLength(1);
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
      for (const c of ['unit-tests', 'full-tests', 'lint', 'format-lint']) expect(t.categories, t.id).not.toContain(c);
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
    const l = load([actionEntry({ id: 'actions-setup-go', repo: 'actions/setup-go' })]);
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
