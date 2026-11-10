// Plan U Task 4b: `pipegen audit`. The brief's cli tests, adapted to the rulings (B1, B3, S15, S18, S19, S21-S23,
// S30, U10, U18, R10), plus one test per checklist item. Every network call is a fake fetch (CliIO.fetch), the AI is a
// fake provider, the secret scanner (betterleaks, or gitleaks with the switch) is the shared stub, and no test starts git or any other process of its own (the child
// process spy would see it). Secret-like strings are built at runtime.
import * as childProcess from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as execa from 'execa';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { makeProvider } from '../src/ai/provider.js';
import { bundleCode, chooseSecretScanner, SECRET_SCANNER_ENV as SCANNER_ENV, SecretScanError } from '../src/ai/redact.js';
import { addAiSuggestions, buildAudit, foldName, safeRunCommand, swapRisk, swapRiskWhy, type AuditReport } from '../src/audit/model.js';
import { CANT_SEE, renderTerminal } from '../src/audit/render.js';
import { EXIT_UNSAFE_FOLDER } from '../src/cli/audit.js';
import { run } from '../src/cli/main.js';
import { PromptCancelledError, type CliIO, type Prompter } from '../src/cli/io.js';
import { withRateLimit, type RateBudget, type RateClock } from '../src/engine/github-rate.js';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { loadReviewed, ReviewedListError } from '../src/engine/reviewed.js';
import { fetchStats, type StatsDeps } from '../src/engine/stats.js';
import { permissionsTable } from '../src/github/client.js';
import { DEFAULT_MODEL, type AiProvider, type AiRequest, type AiUsage } from '../src/types.js';
import { packageVersion } from '../src/util/package-data.js';
import { fakeFetch, type Call, type Reply, type Routes } from './helpers/fake-http.js';
import { CLEAN, makeStub } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';

const hooks = vi.hoisted(() => ({ ai: null as AiProvider | null, scanner: null as string | null }));

vi.mock('node:child_process', async (importOriginal) => {
  const a = await importOriginal<typeof import('node:child_process')>();
  const spies = {
    exec: vi.fn(a.exec), execFile: vi.fn(a.execFile), execFileSync: vi.fn(a.execFileSync), execSync: vi.fn(a.execSync),
    fork: vi.fn(a.fork), spawn: vi.fn(a.spawn), spawnSync: vi.fn(a.spawnSync),
  };
  return { ...a, ...spies, default: { ...a, ...spies } };
});
vi.mock('execa', () => ({ execa: vi.fn(), execaSync: vi.fn(), execaNode: vi.fn(), execaCommand: vi.fn(), execaCommandSync: vi.fn(), $: vi.fn() }));
// The AI: the real makeProvider runs (its key and flag checks), then a test's fake provider stands in for it.
vi.mock('../src/ai/provider.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/ai/provider.js')>();
  return { ...a, makeProvider: vi.fn((opts: Parameters<typeof a.makeProvider>[0]) => { const real = a.makeProvider(opts); return hooks.ai ?? real; }) };
});
// No download: the pinned secret scanner (either name) is the stub when a test sets one, else refused.
vi.mock('../src/engine/linters.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/engine/linters.js')>();
  return { ...a, ensurePinnedBinary: vi.fn(async () => { if (hooks.scanner === null) throw new a.PinnedBinaryError('No download in tests.'); return hooks.scanner; }) };
});
vi.mock('../src/engine/memory.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/engine/memory.js')>();
  return { ...a, openMemory: vi.fn(async () => ({ lookup: () => [], record: () => {}, save: async () => {}, notes: [] })) };
});
vi.mock('../src/engine/reviewed.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/engine/reviewed.js')>();
  return { ...a, loadReviewed: vi.fn(a.loadReviewed) };
});
vi.mock('../src/audit/model.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/audit/model.js')>();
  return { ...a, buildAudit: vi.fn(a.buildAudit), addAiSuggestions: vi.fn(a.addAiSuggestions) };
});
// J5: the terminal report's input and options (the type lines and the short report itself are J4's)
vi.mock('../src/audit/render.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/audit/render.js')>();
  return { ...a, renderTerminal: vi.fn(a.renderTerminal) };
});
vi.mock('../src/engine/github-rate.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/engine/github-rate.js')>();
  return { ...a, withRateLimit: vi.fn(a.withRateLimit) };
});
vi.mock('../src/ai/redact.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/ai/redact.js')>();
  return { ...a, bundleCode: vi.fn(a.bundleCode) };
});
vi.mock('../src/engine/stats.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/engine/stats.js')>();
  return { ...a, fetchStats: vi.fn(a.fetchStats) };
});

const API = 'https://api.github.com';
const R = `${API}/repos/o/r`;
/** Env var names kept out of `NAME: value` shapes (the secret-literal guard). */
const GH_VAR = 'GITHUB' + '_TOKEN';
const ANTHROPIC_VAR = 'ANTHROPIC' + '_API_KEY';
const OPENAI_VAR = 'OPENAI' + '_API_KEY';
const VERSION = packageVersion() as string;
const RUN_COMMAND = `npx --registry=https://registry.npmjs.org pipegen@${VERSION} audit --dir ./repo`;
const S15 = 'audit --ai needs an AI provider: set ANTHROPIC_API_KEY or OPENAI_API_KEY, or use --ai ollama.';
const S21 = 'audit --ai needs Linux or macOS for now (WSL works).';
const B3_PREFIX = "pipegen's reviewed tool list isn't usable in this build: ";
const B3_SUFFIX = ". The 'would add' section shows no tools.";
/** Characters safeText removes: C0 (except newline), DEL, C1, bidi controls. */
const UNSAFE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/;
const err = (status: number, message: string): Reply => ({ status, body: { message } });

/** A public repo read without a token, with GitHub's activity lists, plus discovery's searches and `o/good` (it passes the quality bar). */
const publicRoutes = (over: Routes = {}): Routes => ({
  [`GET ${R}`]: { body: { private: false, default_branch: 'main', owner: { type: 'User', login: 'o' } } },
  [`GET ${R}/rulesets`]: { body: [] },
  [`GET ${R}/environments`]: { body: { total_count: 0, environments: [] } },
  [`GET ${R}/code-scanning/analyses`]: err(401, 'Requires authentication'),
  [`GET ${R}/events`]: { body: [] },
  [`GET ${R}/pulls`]: { body: [] },
  [`GET ${API}/search/repositories`]: { body: { total_count: 0, items: [] } },
  [`GET ${API}/advisories`]: { body: [] },
  'GET https://registry.npmjs.org/-/v1/search': { body: { objects: [] } },
  [`GET ${API}/repos/o/good`]: { body: { full_name: 'o/good', stargazers_count: 2000, archived: false, license: { spdx_id: 'MIT' }, owner: { login: 'o', type: 'User' } } },
  [`GET ${API}/repos/o/good/releases/latest`]: { body: { tag_name: 'v1.2.3', published_at: '2026-09-01T10:00:00Z' } },
  [`GET ${API}/repos/o/good/contents`]: { body: [{ name: 'README.md', type: 'file' }, { name: 'action.yml', type: 'file' }] },
  'GET https://api.scorecard.dev/projects/github.com/o/good': { body: { date: '2026-10-01', score: 7.5 } },
  ...over,
});
/** A private Free repo read with a fine-grained token whose login is the owner. */
const privateRoutes = (over: Routes = {}): Routes => publicRoutes({
  [`GET ${API}/user`]: { body: { login: 'o', plan: { name: 'free' } } },
  [`GET ${R}`]: { body: { private: true, default_branch: 'main', owner: { type: 'User', login: 'o' } } },
  [`GET ${R}/rulesets`]: err(403, 'Upgrade to GitHub Pro or make this repository public to enable this feature.'),
  [`GET ${R}/code-scanning/analyses`]: err(403, 'Code scanning is not enabled for this repository.'),
  ...over,
});

/** A temp folder readProject accepts: .git/config with a GitHub origin, written by hand (no git process). */
function repo(files: Record<string, string> = {}, remote = 'https://github.com/o/r.git'): string {
  const dir = makeTempDir();
  writeIn(dir, '.git/config', `[remote "origin"]\n\turl = ${remote}\n`);
  const all: Record<string, string> = {
    'package.json': JSON.stringify({ name: 'app', scripts: { test: 'vitest run', lint: 'eslint .', start: 'node index.js' }, devDependencies: { vitest: '1.0.0' } }),
    'package-lock.json': '{}\n',
    'index.js': 'console.log("hi");\n',
    ...files,
  };
  for (const [rel, body] of Object.entries(all)) writeIn(dir, rel, body);
  return dir;
}

/** A prompter that answers the consent question with `yes` and records what it was shown. */
function prompter(yes: boolean): Prompter & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    confirm: vi.fn(async (msg: string) => { asked.push(msg); return yes; }),
    select: async () => { throw new Error('audit asks no select'); },
    text: async () => { throw new Error('audit asks no text'); },
  };
}

/** `fake`: a fake GitHub the test made itself (to see how many calls were made when a question was asked). */
interface RunOpts { cwd: string; routes?: Routes; env?: NodeJS.ProcessEnv; prompt?: Prompter; interactive?: boolean; fake?: ReturnType<typeof fakeFetch> }
async function audit(argv: string[], o: RunOpts) {
  const f = o.fake ?? fakeFetch(o.routes ?? publicRoutes());
  const lines: string[] = [];
  const errs: string[] = [];
  const prompt = o.prompt ?? prompter(false);
  const io: CliIO = {
    prompt, out: (s) => { lines.push(s); }, err: (s) => { errs.push(s); }, env: o.env ?? {}, cwd: o.cwd, fetch: f.fetch,
    ...(o.interactive === undefined ? {} : { interactive: o.interactive }),
  };
  const code = await run(argv, io);
  const out = lines.join('\n');
  const stderr = errs.join('\n');
  return { code, out, err: stderr, all: `${out}\n${stderr}`, calls: f.calls };
}

const needBlock = (req: AiRequest) => JSON.parse(/<need>\n(.*)\n<\/need>/.exec(req.user)?.[1] ?? 'null') as { needId: string; category: string; language: string } | null;
/**
 * A fake Claude: one extra need (a type check for `app`, which no reviewed tool covers, so discovery runs); for every
 * need, the healthy action o/good, with `why` (which may echo a value back).
 */
function fakeAi(why = 'Checks things.', service = 'app') {
  const reqs: AiRequest[] = [];
  const complete = vi.fn(async (req: AiRequest) => {
    reqs.push(req);
    const usage = Object.fromEntries([['input' + 'Tokens', 1000], ['output' + 'Tokens', 100]]) as unknown as AiUsage; // names built at runtime (secret-literal guard)
    if (req.schemaName === 'needs') {
      const add = [{ id: 'migration-check', layer: 'push', category: 'full-tests', service, why: 'Types catch mistakes.', blocking: false }];
      return { data: { add, skipLayers: [], requireDeployApproval: false }, usage };
    }
    const n = needBlock(req);
    if (n === null) throw new Error('unexpected request');
    return { data: { candidates: [{ needId: n.needId, category: n.category, language: n.language, kind: 'action', name: 'good', repo: 'o/good', why }] }, usage };
  });
  const p: AiProvider = { name: 'claude', model: DEFAULT_MODEL, complete };
  return { p, reqs, complete };
}

/** Every child_process function the spy wraps, with its calls. */
const childCalls = () => (['exec', 'execFile', 'execFileSync', 'execSync', 'fork', 'spawn', 'spawnSync'] as const)
  .flatMap((fn) => vi.mocked(childProcess[fn]).mock.calls.map((args) => ({ fn, args })));
const execaCalls = () => Object.values(execa).filter((v) => vi.isMockFunction(v)).flatMap((m) => vi.mocked(m as () => unknown).mock.calls);
const listTree = (dir: string): string[] => readdirSync(dir, { recursive: true, withFileTypes: false }).map(String).sort();

let globalFetch: ReturnType<typeof vi.fn>;
let anthropicVal: string;
beforeEach(() => {
  vi.clearAllMocks();
  hooks.ai = null;
  hooks.scanner = null;
  // anything not going through CliIO.fetch would land here
  globalFetch = vi.fn(async () => { throw new Error('unexpected network call'); });
  vi.stubGlobal('fetch', globalFetch);
  // a key shape no redact rule knows: only the run's known values can hide it (rulings S19, U10)
  anthropicVal = ['zq', 'anthropic', 'value', 'Q'.repeat(12)].join('-');
});
afterEach(() => {
  vi.unstubAllGlobals();
  cleanupRepos();
});

/** --ai with a fake Claude and the scanner stub (`body`: its report and exit); the env carries the Anthropic key. */
function aiSetup(why?: string, service?: string, body = CLEAN) {
  const ai = fakeAi(why, service);
  hooks.ai = ai.p;
  const stub = makeStub(body);
  hooks.scanner = stub.bin;
  return { ai, stub, env: { [ANTHROPIC_VAR]: anthropicVal } as NodeJS.ProcessEnv };
}

// ---------- the brief ----------

describe('pipegen audit (brief)', () => {
  it('cli: audit prints report, exit 0, makes no write calls (only GET), report on stdout', async () => {
    const dir = repo();
    const r = await audit(['audit', '--verbose'], { cwd: dir });
    expect(r.code).toBe(0);
    expect(r.out).toContain('pipegen audit: o/r');
    expect(r.out).toContain('pipegen changed nothing in the repo or on GitHub.');
    expect(r.out).toContain('Nothing was sent to an AI.');
    expect(r.out).toMatch(/Verdict: /);
    expect(r.out).toContain('Checks by layer');
    expect(r.calls.length).toBeGreaterThan(0);
    for (const c of r.calls) expect(`${c.method} ${c.url.href}`).toMatch(/^GET https:\/\/api\.github\.com\//);
    expect(globalFetch).not.toHaveBeenCalled();
    expect(r.err).toBe('');
  });

  it('cli: --out writes the file outside the repo, nothing committed', async () => {
    const dir = repo();
    const work = makeTempDir();
    const before = listTree(dir);
    const r = await audit(['audit', '--verbose', '--dir', dir, '--out', 'report.md'], { cwd: work });
    expect(r.code).toBe(0);
    const file = join(work, 'report.md');
    const md = readFileSync(file, 'utf8');
    expect(md).toMatch(/^# pipegen audit: o\/r\n/);
    expect(md).toContain('## Checks by layer');
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(listTree(dir)).toEqual(before); // nothing written in the repo (and no git: nothing committed)
    expect(readFileSync(join(dir, '.git/config'), 'utf8')).toBe('[remote "origin"]\n\turl = https://github.com/o/r.git\n');
    expect(r.err).toContain(`The Markdown report was written to ${file}.`);
    expect(r.out).toContain('pipegen audit: o/r'); // the terminal report too
  });

  it('cli: --json prints AuditReport (stdout is only JSON)', async () => {
    const dir = repo();
    const r = await audit(['audit', '--verbose', '--json'], { cwd: dir });
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out) as Record<string, unknown> & { profile: { owner: string; repo: string }; coverage: unknown[]; warnings: { text: string }[] };
    expect(j.profile).toMatchObject({ owner: 'o', repo: 'r', private: false });
    expect(Array.isArray(j.coverage)).toBe(true);
    for (const k of ['support', 'wouldAdd', 'estimates', 'permissions', 'limits', 'secretsInTree', 'aiBundle', 'notes', 'reviewedUnavailable']) expect(j).toHaveProperty(k);
    expect(j.permissions).toEqual(permissionsTable('write', { appCreatesRepos: false })); // what the full run would need (B1)
  });

  it('cli: private repo without auth → fine-grained read-only instructions, no gh auth login (S22)', async () => {
    const dir = repo();
    const r = await audit(['audit', '--verbose'], { cwd: dir, routes: publicRoutes({ [`GET ${R}`]: err(404, 'Not Found') }) });
    expect(r.code).toBe(1);
    expect(r.err).toContain("pipegen can't see o/r: it's private or doesn't exist. If it's private, pipegen needs read access to o/r.");
    expect(r.err).toContain('fine-grained token for this one repo');
    for (const row of permissionsTable('read')) expect(r.err).toContain(row.permission);
    expect(r.err).not.toContain('GitHub App');   // #127: v0.2 has no App login to offer
    expect(r.err).toContain('pipegen refuses broad classic tokens');
    expect(r.all).not.toMatch(/gh auth login/);
    // with a token that can't see the repo: the same read-only steps
    const withTok = await audit(['audit', '--verbose'], { cwd: dir, env: { [GH_VAR]: fake.githubPat() }, routes: privateRoutes({ [`GET ${R}`]: err(404, 'Not Found') }) });
    expect(withTok.code).toBe(1);
    expect(withTok.err).toContain('pipegen needs read access to o/r. Create a fine-grained token for this one repo');
    expect(withTok.all).not.toMatch(/gh auth login/);
    expect(withTok.all).not.toContain(fake.githubPat());
  });

  it('cli: --ai asks consent first; declined → report without suggestions (no secret scan, no AI call)', async () => {
    const dir = repo();
    const { ai, env } = aiSetup();
    const ask = prompter(false);
    const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env, prompt: ask });
    expect(r.code).toBe(0);
    expect(ask.asked).toHaveLength(1);
    expect(ask.asked[0]).toContain('pipegen audit --ai is about to send part of your code to an AI. Nothing has left this computer yet.');
    expect(ai.complete).not.toHaveBeenCalled();
    expect(ensurePinnedBinary).not.toHaveBeenCalled(); // no scanner download without a yes
    expect(addAiSuggestions).not.toHaveBeenCalled();
    expect(r.out).toContain('Nothing was sent to an AI.');
    expect(r.out).not.toContain('What the AI suggests');
    expect(r.err).toContain('No consent (you said no, or the question was cancelled): nothing was sent to an AI.');
  });

  it('cli: --ai accepted → suggestions shown, consent had no repo lines and read-only permissions', async () => {
    const dir = repo();
    const { ai, env } = aiSetup();
    const ask = prompter(true);
    const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env, prompt: ask });
    expect(r.code).toBe(0);
    expect(ai.complete).toHaveBeenCalled();
    expect(r.out).toContain('You ran it with --ai');
    expect(r.out).toContain('Tools the AI mentions (not reviewed, never run by pipegen):');
    expect(r.out).toContain('good (o/good): Checks things.');
    const screen = ask.asked[0] as string;
    expect(screen).not.toMatch(/pipelines|pipegen-proof|gh repo create/);
    expect(screen).not.toMatch(/\bwrite\b/);
    expect(screen).toContain('GitHub permissions (read-only)');
    for (const row of permissionsTable('read')) expect(screen).toContain(`${row.permission}: ${row.why}`);
    expect(screen).toMatch(/pipegen sends at most \d+ files? /); // counted before the secret scan (S21)
    expect(screen).toContain('betterleaks 1.9.0, which pipegen downloads (checksum-verified) into its cache');
  });

  it('cli: --dir reads the given folder; default is the current folder', async () => {
    const here = repo();
    const other = repo({ 'package.json': JSON.stringify({ name: 'other-app' }) }, 'https://github.com/o/r2.git');
    const R2 = `${API}/repos/o/r2`;
    const routes = publicRoutes({
      [`GET ${R2}`]: { body: { private: false, default_branch: 'main', owner: { type: 'User', login: 'o' } } },
      [`GET ${R2}/rulesets`]: { body: [] }, [`GET ${R2}/events`]: { body: [] }, [`GET ${R2}/pulls`]: { body: [] },
    });
    const dflt = await audit(['audit', '--verbose', '--json'], { cwd: here, routes });
    expect((JSON.parse(dflt.out) as { profile: { repo: string } }).profile.repo).toBe('r');
    const given = await audit(['audit', '--verbose', '--json', '--dir', other], { cwd: here, routes });
    expect((JSON.parse(given.out) as { profile: { repo: string } }).profile.repo).toBe('r2');
    // a relative --dir is read from the current folder
    const work = makeTempDir();
    const rel = await audit(['audit', '--verbose', '--json', '--dir', join('..', other.split('/').pop() as string)], { cwd: resolve(work), routes });
    expect((JSON.parse(rel.out) as { profile: { repo: string } }).profile.repo).toBe('r2');
  });

  it('cli: --help shows `npx pipegen` first and the safe-mode command with --registry and an exact version (#124, S10, S30)', async () => {
    const r = await audit(['--help'], { cwd: makeTempDir() });
    expect(r.code).toBe(0);
    expect(r.out).toContain(RUN_COMMAND);
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    for (const flag of ['--dir', '--out', '--force', '--json', '--ai', '--model', '--effort', '--allow-broad-token', '--type', '--verbose']) expect(r.out).toContain(flag);
    expect(r.out).toContain('Linux or macOS (WSL works)');
    // #124: plain `npx pipegen` inside the folder comes first; the only other runnable form is the exact-version,
    // registry-pinned safe mode (U18 still holds for it)
    const npx = [...r.out.matchAll(/npx[^\n]*/g)].map((m) => m[0]);
    expect(npx[0]).toMatch(/^npx pipegen(?: |$)/);
    expect(r.out.indexOf('npx pipegen')).toBeLessThan(r.out.indexOf(RUN_COMMAND));
    for (const line of npx) expect(line, line).toMatch(new RegExp(`^npx (?:pipegen(?: |$)|--registry=https://registry\\.npmjs\\.org pipegen@${VERSION.replace(/\./g, '\\.')} )`));
    expect(r.out).toMatch(/safe mode/i);
    expect(r.out).not.toContain('x.y.z');
  });

  it('cli: no token on a public repo → anonymous Octokit, no-token note, exit 0', async () => {
    const dir = repo();
    const r = await audit(['audit', '--verbose'], { cwd: dir });
    expect(r.code).toBe(0);
    expect(r.out).toContain('Without a GitHub token, pipegen reads public data only and is rate-limited.');
    for (const c of r.calls) expect(c.headers.authorization).toBeUndefined();
  });

  it('cli: --json and --out never contain the token or secret values (terminal, JSON, Markdown, stderr, consent screen)', async () => {
    const ghVal = fake.githubPat();
    const awsVal = fake.awsKey();
    // the repo carries the values: workflow files named like the token and the AI key, a folder named like the token, a
    // config file with a key, a file named like a key
    const dir = repo({
      [`.github/workflows/${ghVal}.yml`]: 'on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n',
      [`${ghVal}/index.js`]: 'export const x = 1;\n',
      [`.github/workflows/${anthropicVal}.yml`]: 'on: pull_request\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n',
      'config/dev.json': JSON.stringify({ region: 'x', id: awsVal }),
      [`notes/${awsVal}.txt`]: 'hello\n',
    });
    // the fake GitHub echoes the token back wherever it can
    const routes = privateRoutes({
      [`GET ${API}/user`]: { body: { login: 'o', plan: { name: 'free' }, name: ghVal, bio: ghVal } },
      [`GET ${R}/rulesets`]: err(403, `Resource not accessible for ${ghVal}`),
      [`GET ${R}/environments`]: (c: Call) => ({ body: { total_count: 0, environments: [], echo: c.headers.authorization } }),
    });
    const { env } = aiSetup(`Use it with ${anthropicVal} and ${ghVal}.`); // the AI echoes the key and the token back
    env[GH_VAR] = ghVal;
    const work = makeTempDir();
    const ask = prompter(true);
    const json = await audit(['audit', '--verbose', '--dir', dir, '--json', '--ai', '--out', 'r.md'], { cwd: work, env, routes, prompt: ask });
    expect(json.code).toBe(0);
    const term = await audit(['audit', '--verbose', '--dir', dir], { cwd: work, env, routes });
    expect(term.code).toBe(0);
    const md = readFileSync(join(work, 'r.md'), 'utf8');
    // the values were really there: the GitHub calls carried the token, the repo's workflow and folder are named like it
    expect(json.calls.some((c) => (c.headers.authorization ?? '').includes(ghVal))).toBe(true);
    expect(vi.mocked(buildAudit).mock.results[0]?.type).toBe('return');
    const built = await (vi.mocked(buildAudit).mock.results[0]?.value as ReturnType<typeof buildAudit>);
    expect(built.profile.existingWorkflows.map((w) => w.path)).toEqual(expect.arrayContaining([`.github/workflows/${ghVal}.yml`, `.github/workflows/${anthropicVal}.yml`]));
    const tree = (JSON.parse(json.out) as Record<string, { rule: string }[]>)['secrets' + 'InTree'];
    expect(tree?.length).toBeGreaterThan(0);
    for (const text of [json.out, json.err, term.out, term.err, md, ...ask.asked]) {
      expect(text).not.toContain(ghVal);
      expect(text).not.toContain(awsVal);
      expect(text).not.toContain(anthropicVal);
      expect(text).not.toMatch(UNSAFE);
    }
    // the AI step ran (the echo was really produced) and the values never reached the AI either
    expect(json.out).toContain('o/good');
    const sent = vi.mocked((hooks.ai as AiProvider).complete).mock.calls.map((c) => c[0]);
    expect(sent.length).toBeGreaterThan(0);
    for (const req of sent) {
      expect(JSON.stringify(req)).not.toContain(ghVal);
      expect(JSON.stringify(req)).not.toContain(awsVal);
      expect(JSON.stringify(req)).not.toContain(anthropicVal);
    }
  });

  it('cli: audit without --ai starts no child process (child_process and execa spied)', async () => {
    const dir = repo();
    vi.clearAllMocks();
    const r = await audit(['audit', '--verbose', '--out', join(makeTempDir(), 'x.md')], { cwd: dir });
    expect(r.code).toBe(0);
    expect(childCalls()).toEqual([]);
    expect(execaCalls()).toEqual([]);
    expect(ensurePinnedBinary).not.toHaveBeenCalled();
  });

  it('cli: audit --ai starts only the pinned betterleaks binary (gitleaks with the switch)', async () => {
    for (const [env, name, sub, version] of [[{}, 'betterleaks', 'dir', '1.9.0'], [{ [SCANNER_ENV]: 'gitleaks' }, 'gitleaks', 'detect', '8.30.1']] as const) {
      const dir = repo();
      const s = aiSetup();
      const ask = prompter(true);
      vi.clearAllMocks();
      const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env: { ...s.env, ...env }, prompt: ask });
      expect(r.code, name).toBe(0);
      expect(s.ai.complete, name).toHaveBeenCalled();
      const calls = childCalls();
      expect(calls.length, name).toBeGreaterThan(0);
      for (const c of calls) {
        expect(c.fn).toBe('execFile');
        expect(c.args[0]).toBe(s.stub.bin);
      }
      expect(execaCalls()).toEqual([]);
      expect(ensurePinnedBinary, name).toHaveBeenCalledTimes(1);
      // the version the screen showed is the one of the pins entry the binary is verified against (review M3)
      expect(ensurePinnedBinary, name).toHaveBeenCalledWith(name, undefined, { pins: expect.objectContaining({ [name]: expect.objectContaining({ version }) }) });
      expect(s.stub.record().argv[0], name).toBe(sub); // the stub really ran as that scanner
      // the screen named the scanner that ran, with its pinned version
      expect(ask.asked[0], name).toContain(`checked for secrets with ${name} ${version}, which pipegen downloads (checksum-verified)`);
      expect(r.out, name).toContain(`${name} checked the bundle`);
      // the download happens after the consent question, never before (S21, B4)
      const asked = vi.mocked(ask.confirm).mock.invocationCallOrder[0] as number;
      expect(vi.mocked(ensurePinnedBinary).mock.invocationCallOrder[0], name).toBeGreaterThan(asked);
    }
  });

  // the brief's name, with the variable's name from the constant (pipegen's own redact() hides `NAME=value` in test files)
  it(`scanner: default betterleaks; ${SCANNER_ENV}=gitleaks picks gitleaks; any other value refused with exit 1`, async () => {
    expect(SCANNER_ENV).toBe('PIPEGEN' + '_SECRET_SCANNER');
    expect(chooseSecretScanner({})).toBe('betterleaks');
    expect(chooseSecretScanner({ [SCANNER_ENV]: 'betterleaks' })).toBe('betterleaks');
    expect(chooseSecretScanner({ [SCANNER_ENV]: 'gitleaks' })).toBe('gitleaks');
    const odd = 'odd-' + 'Q'.repeat(30); // a value that is never echoed back
    for (const bad of ['', 'Gitleaks', 'BETTERLEAKS', ' gitleaks', 'gitleaks\n', 'trufflehog', odd]) {
      expect(() => chooseSecretScanner({ [SCANNER_ENV]: bad }), JSON.stringify(bad)).toThrow(SecretScanError);
    }
    // the CLI: refused before any GitHub call and before the consent question, exit 1, the value not shown
    const dir = repo();
    const { ai, env } = aiSetup();
    const ask = prompter(true);
    vi.clearAllMocks();
    const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env: { ...env, [SCANNER_ENV]: odd }, prompt: ask });
    expect(r.code).toBe(1);
    expect(r.err).toContain('PIPEGEN_SECRET_SCANNER must be betterleaks (the default) or gitleaks.');
    expect(r.all).not.toContain(odd);
    expect(r.calls).toEqual([]);
    expect(ask.asked).toEqual([]);
    expect(ensurePinnedBinary).not.toHaveBeenCalled();
    expect(ai.complete).not.toHaveBeenCalled();
    // without --ai nothing is scanned or sent, so the setting is not read
    const plain = await audit(['audit', '--verbose'], { cwd: dir, env: { [SCANNER_ENV]: odd } });
    expect(plain.code).toBe(0);
  });

  it('bundle: scanner exit code other than clean/found → no AI call, note names the gitleaks fallback', async () => {
    for (const code of [2, 126, 255]) {
      const dir = repo();
      const s = aiSetup(undefined, undefined, `writeReport('[]'); process.exit(${code});`);
      const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env: s.env, prompt: prompter(true) });
      expect(r.code, String(code)).toBe(0); // the plain audit is still reported
      expect(s.ai.complete, String(code)).not.toHaveBeenCalled();
      const out = oneLine(r.out);
      expect(out, String(code)).toContain(`the required betterleaks check couldn't run. betterleaks failed (exit code ${code}).`);
      // the note survives pipegen's own output cleaning (a `NAME=value` form would be hidden by redact())
      expect(out, String(code)).toContain('To use the gitleaks fallback instead, set PIPEGEN_SECRET_SCANNER to gitleaks and run again.');
    }
    // gitleaks is already the fallback: its failure names no other scanner
    const dir = repo();
    const s = aiSetup(undefined, undefined, 'process.exit(2);');
    const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env: { ...s.env, [SCANNER_ENV]: 'gitleaks' }, prompt: prompter(true) });
    expect(s.ai.complete).not.toHaveBeenCalled();
    expect(oneLine(r.out)).toContain("the required gitleaks check couldn't run. gitleaks failed (exit code 2).");
    expect(r.out).not.toContain('To use the gitleaks fallback');
  });
});

// ---------- the checklist ----------

describe('pipegen audit (flags and help)', () => {
  it('flags: an unknown flag is exit 1 with a cleaned message; audit takes no positional arguments', async () => {
    const cwd = makeTempDir();
    const bad = await audit(['audit', '--verbose', '--evil\u001b[31m\u202e'], { cwd });
    expect(bad.code).toBe(1);
    expect(bad.err).toMatch(/Unknown option/);
    expect(bad.all).not.toMatch(UNSAFE);
    const extra = await audit(['audit', '--verbose', 'stray'], { cwd });
    expect(extra.code).toBe(1);
    expect(extra.err).toContain('pipegen audit takes no arguments');
    const unknownAi = await audit(['audit', '--verbose', '--ai=gemini'], { cwd });
    expect(unknownAi.code).toBe(1);
    expect(unknownAi.err).toContain('Unknown --ai value "gemini". Use claude, openai or ollama.');
    const modelOnly = await audit(['audit', '--verbose', '--model', 'x'], { cwd });
    expect(modelOnly.code).toBe(1);
    expect(modelOnly.err).toContain('--model and --effort only work with --ai.');
    const inspectOut = await audit(['inspect', '--out', 'x.md'], { cwd });
    expect(inspectOut.code).toBe(1);
    expect(inspectOut.err).toContain('--out works with pipegen audit only.');
  });

  it('flags (M8): a repeated option is refused with a clear message, exit 1', async () => {
    const cwd = makeTempDir();
    for (const argv of [['audit', '--ai', 'claude', '--ai', 'ollama'], ['audit', '--out', 'a.md', '--out', 'b.md'], ['audit', '--dir', 'a', '--dir', 'b'], ['audit', '--json', '--json'], ['inspect', '--dir', 'a', '--dir=b']]) {
      const r = await audit(argv, { cwd });
      expect(r.code, argv.join(' ')).toBe(1);
      expect(r.err).toMatch(/^--(ai|out|dir|json) was given more than once\. Give each option once\./);
      expect(r.calls).toEqual([]);
    }
  });

  it('flags: --ai takes an optional provider name (bare, before another flag, with = or as the next word)', async () => {
    const dir = repo();
    for (const argv of [['audit', '--ai'], ['audit', '--ai', '--json'], ['audit', '--ai', 'claude'], ['audit', '--ai=claude']]) {
      vi.mocked(makeProvider).mockClear();
      const r = await audit(argv, { cwd: dir, env: {}, prompt: prompter(false) });
      expect(r.code, argv.join(' ')).toBe(1); // no key set: S15
      expect(r.err).toContain(S15);
      expect(vi.mocked(makeProvider).mock.calls[0]?.[0].ai).toBe(argv.includes('claude') || argv.includes('--ai=claude') ? 'claude' : undefined);
    }
  });

  it('--version prints the running version from packageVersion() (main.ts has no version reader of its own)', async () => {
    const r = await audit(['--version'], { cwd: makeTempDir() });
    expect(r.out).toBe(`pipegen ${VERSION}`);
    const src = readFileSync(resolve(import.meta.dirname, '../src/cli/main.ts'), 'utf8');
    expect(src).toContain('packageVersion()');
    expect(src).not.toMatch(/function version\(|package\.json/);
  });

  it('README: `npx pipegen` first, then the exact-version safe-mode command; audit --ai needs Linux or macOS (#124, S21, S30)', () => {
    const readme = readFileSync(resolve(import.meta.dirname, '../README.md'), 'utf8');
    expect(readme).toContain(RUN_COMMAND.replace('./repo', './my-repo'));
    const npx = [...readme.matchAll(/npx[^\n`]*/g)].map((m) => m[0]);
    expect(npx.length).toBeGreaterThan(0);
    const safe = `npx --registry=https://registry\\.npmjs\\.org pipegen@(?:${VERSION.replace(/\./g, '\\.')}|x\\.y\\.z) audit `;
    for (const line of npx) expect(line, line).toMatch(new RegExp(`^(?:npx pipegen(?: |$)|${safe})`));
    // the npm name isn't published yet: the Commands section opens with the warning, before any command (J5 review I1)
    const commands = readme.slice(readme.indexOf('## Commands'));
    const NOT_YET = "> **Not on npm yet: don't run these until the first release.** The npm name isn't published yet, so until then `npx pipegen` would run whatever package holds the name";
    expect(commands.split('\n')[2]).toContain(NOT_YET);
    expect(commands.indexOf(NOT_YET)).toBeLessThan(commands.indexOf('```')); // before the first command block
    expect(readme).not.toMatch(/don't work until the first release|no other pipegen command is safe/);
    expect(readme).toContain("would run someone else's package: don't run them until the first release");
    // the plain form first and the safe mode second
    const first = [...commands.matchAll(/npx[^\n`]*/g)].map((m) => m[0]);
    expect(first[0]).toMatch(/^npx pipegen(?: |$)/);
    expect(first.findIndex((l) => new RegExp(`^${safe}`).test(l))).toBeGreaterThan(0);
    expect(commands).toMatch(/safe mode/i);
    expect(readme).toContain('`audit --ai` needs Linux or macOS for now (WSL works)');
  });
});

describe('pipegen audit (auth and GitHub, ruling B1)', () => {
  it('access, S18: the run uses ONE rate budget for every GitHub call, buildAudit, addAiSuggestions and fetchStats (S18)', async () => {
    const dir = repo();
    const { env } = aiSetup();
    const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env, prompt: prompter(true) });
    expect(r.code).toBe(0);
    const budget = vi.mocked(buildAudit).mock.calls[0]?.[1].budget as RateBudget;
    expect(budget).toBeDefined();
    expect(vi.mocked(addAiSuggestions).mock.calls[0]?.[2].budget).toBe(budget);
    const rate = vi.mocked(withRateLimit).mock.calls;
    expect(rate.length).toBeGreaterThan(3);
    for (const c of rate) expect((c[1] as RateClock).budget).toBe(budget);
    const stats = vi.mocked(fetchStats).mock.calls;
    expect(stats.length).toBeGreaterThan(0);
    for (const c of stats) expect((c[1] as StatsDeps).budget).toBe(budget);
  });

  it('access, B1: GET /user only with a token; the login reads a personal plan; buildAudit gets the context, the probe and the full-run permissions', async () => {
    const dir = repo();
    const anon = await audit(['audit', '--verbose'], { cwd: dir });
    expect(anon.calls.some((c) => c.url.pathname === '/user')).toBe(false);
    const withTok = await audit(['audit', '--verbose', '--json'], { cwd: dir, env: { [GH_VAR]: fake.githubPat() }, routes: privateRoutes() });
    expect(withTok.code).toBe(0);
    expect(withTok.calls.filter((c) => c.url.pathname === '/user').length).toBeGreaterThan(0);
    const deps = vi.mocked(buildAudit).mock.calls[1]?.[1];
    expect(deps?.anonymous).toBe(false);
    expect(deps?.context).toEqual({ private: true, ownerType: 'User', plan: 'free', defaultBranch: 'main' });
    expect(deps?.capabilities.branchProtection).toBe(false);
    expect(deps?.permissions).toEqual(permissionsTable('write', { appCreatesRepos: false }));
    expect(JSON.parse(withTok.out)).toMatchObject({ profile: { private: true, plan: 'free' } });
  });

  it('access, S23: classic tokens are refused unless the broad-token flag is given', async () => {
    const dir = repo();
    const env = { [GH_VAR]: fake.githubClassic() };
    const refused = await audit(['audit', '--verbose'], { cwd: dir, env, routes: privateRoutes() });
    expect(refused.code).toBe(1);
    expect(refused.err).toContain("pipegen won't use this token");
    expect(refused.err).toContain('it is a classic token, which reaches every repo you have');
    expect(refused.err).toContain('--allow-broad-token');
    expect(refused.all).not.toContain(fake.githubClassic());
    const allowed = await audit(['audit', '--verbose', '--allow-broad-token'], { cwd: dir, env, routes: privateRoutes() });
    expect(allowed.code).toBe(0);
    expect(allowed.all).not.toContain(fake.githubClassic());
  });

  it('access, S21: not a GitHub repo → a friendly message, exit 1 (S21)', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', '{}');
    const r = await audit(['audit', '--verbose'], { cwd: dir });
    expect(r.code).toBe(1);
    expect(r.err).toContain('pipegen audit needs a clone of a GitHub repository');
    expect(r.err).toContain('--dir');
    expect(r.out).toBe('');
  });

  it('access, R10: GitHub can\'t be read (no answer, 5xx) → only the local parts, "GitHub: not read", exit 1 (R10); no guessed GitHub facts', async () => {
    const dir = repo({ 'config/dev.json': JSON.stringify({ id: fake.awsKey() }), '.github/workflows/ci.yml': 'on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n' });
    const down = publicRoutes({ [`GET ${R}`]: err(503, 'Service Unavailable') });
    const r = await audit(['audit', '--verbose'], { cwd: dir, routes: down });
    expect(r.code).toBe(1);
    expect(r.out).toContain('pipegen audit: o/r');
    expect(r.out).toContain('GitHub: not read (the error is on stderr).');
    expect(r.out).toContain('Secret-like text in the files on disk now');
    expect(r.out).toContain('.github/workflows/ci.yml');
    expect(r.out).toContain('What the full setup would send to the AI');
    expect(r.out).not.toMatch(/Verdict|Checks by layer|What your GitHub plan allows|Costs of the full setup|Permissions the full setup needs/);
    expect(r.err).toContain("GitHub: not read: pipegen couldn't reach https://api.github.com to check o/r (HTTP 503");
    // --json: the local parts as JSON, github "not read"
    const j = await audit(['audit', '--verbose', '--json'], { cwd: dir, routes: down });
    expect(j.code).toBe(1);
    expect(JSON.parse(j.out)).toMatchObject({ github: 'not read', profile: { owner: 'o', repo: 'r' } });
    // --out: no half report is written
    const work = makeTempDir();
    const o = await audit(['audit', '--verbose', '--dir', dir, '--out', 'r.md'], { cwd: work, routes: down });
    expect(o.code).toBe(1);
    expect(existsSync(join(work, 'r.md'))).toBe(false);
    expect(o.err).toContain('No report file was written: GitHub could not be read.');
  });

  it('access, M12: GitHub names the repo differently (renamed or transferred) → a note, and the run goes on', async () => {
    const dir = repo();
    const moved = publicRoutes({ [`GET ${R}`]: { body: { full_name: 'newowner/new-name', private: false, default_branch: 'main', owner: { type: 'Organization', login: 'newowner' } } } });
    const r = await audit(['audit', '--verbose', '--json'], { cwd: dir, routes: moved });
    expect(r.code).toBe(0);
    expect((JSON.parse(r.out) as { notes: string[] }).notes).toContain('GitHub says this repo is now newowner/new-name (renamed or transferred); the facts below are for that repo.');
    // the same name in another letter case is the same repo: no note
    const same = await audit(['audit', '--verbose', '--json'], { cwd: dir, routes: publicRoutes({ [`GET ${R}`]: { body: { full_name: 'O/R', private: false, default_branch: 'main', owner: { type: 'User', login: 'O' } } } }) });
    expect(same.code).toBe(0);
    expect(same.out).not.toContain('GitHub says this repo is now');
  });

  it('reviewed list unusable (B3) → runs with no reviewed tools, the top warning first, exit 0', async () => {
    const dir = repo();
    const msg = 'This pipegen release refuses its reviewed tool list: 23 entries still wait for human review (a, b and 21 more). Nothing unreviewed may run in your CI.';
    vi.mocked(loadReviewed).mockImplementation(() => { throw new ReviewedListError(msg); });
    try {
      await reviewedUnavailable(dir, msg);
    } finally {
      vi.mocked(loadReviewed).mockReset(); // back to the real loader
    }
  });
});

/** The B3 checks, with loadReviewed failing (the caller restores it). */
async function reviewedUnavailable(dir: string, msg: string) {
  const r = await audit(['audit', '--verbose', '--json'], { cwd: dir });
  expect(r.code).toBe(0);
  const j = JSON.parse(r.out) as { warnings: { text: string }[]; reviewedUnavailable: boolean; wouldAdd: { note: string; tool: unknown }[] };
  expect(j.warnings[0]?.text).toBe(`${B3_PREFIX}${msg.replace(/\.$/, '')}${B3_SUFFIX}`); // one full stop
  expect(j.reviewedUnavailable).toBe(true);
  expect(j.wouldAdd.some((w) => w.note === "pipegen's reviewed tool list couldn't be loaded, so it has no tool to add here")).toBe(true);
  expect(j.wouldAdd.every((w) => w.tool === null || (w.tool as { kind: string }).kind !== 'reviewed')).toBe(true);
  expect(vi.mocked(buildAudit).mock.calls[0]?.[1]).toMatchObject({ reviewed: [], reviewedUnavailable: true });
  const t = await audit(['audit', '--verbose'], { cwd: dir });
  expect(t.code).toBe(0);
  const warnAt = t.out.indexOf('⚠ Warnings');
  expect(t.out.indexOf(B3_PREFIX)).toBeGreaterThan(warnAt);
  expect(t.out.indexOf(B3_PREFIX)).toBeLessThan(t.out.indexOf('What your GitHub plan allows'));
}

describe('pipegen audit (Task 5: real-repo fixes)', () => {
  it('requests (M6): an anonymous audit of an organisation repo reads GET /repos once, skips /orgs and makes at most 8 GitHub requests', async () => {
    const dir = repo();
    const at = new Date().toISOString();
    const page = Array.from({ length: 100 }, () => ({ type: 'PushEvent', created_at: at })); // a busy repo: every event page is read
    const routes = publicRoutes({
      [`GET ${R}`]: { body: { private: false, default_branch: 'main', full_name: 'o/r', owner: { type: 'Organization', login: 'o' } } },
      [`GET ${API}/orgs/o`]: { body: { login: 'o' } },
      [`GET ${R}/events`]: { body: page },
    });
    const r = await audit(['audit', '--verbose', '--json'], { cwd: dir, routes });
    expect(r.code).toBe(0);
    const gh = r.calls.filter((c) => c.url.origin === API);
    expect(gh.filter((c) => c.url.pathname === '/repos/o/r')).toHaveLength(1);
    expect(gh.some((c) => c.url.pathname.startsWith('/orgs/'))).toBe(false);
    expect(gh.length).toBeLessThanOrEqual(8);
    const j = JSON.parse(r.out) as { profile: { ownerType: string; plan: string; defaultBranch: string; private: boolean } };
    expect(j.profile).toMatchObject({ ownerType: 'Organization', plan: 'unknown', defaultBranch: 'main', private: false });
  });

  it('requests (M6): with a token, GET /repos is still read once (getAuth makes no anonymous check)', async () => {
    const dir = repo();
    const r = await audit(['audit', '--verbose', '--json'], { cwd: dir, routes: privateRoutes(), env: { [GH_VAR]: fake.githubPat() } });
    expect(r.code).toBe(0);
    expect(r.calls.filter((c) => c.url.origin === API && c.url.pathname === '/repos/o/r')).toHaveLength(1);
  });

  it('wording (M7): the B3 warning gives the loader\'s short reason once, without the install-time sentence', async () => {
    const dir = repo();
    const reason = '23 entries still wait for human review (a, b and 21 more)';
    vi.mocked(loadReviewed).mockImplementation(() => { throw new ReviewedListError(`This pipegen release refuses its reviewed tool list: ${reason}. Nothing unreviewed may run in your CI.`, { reason }); });
    try {
      const r = await audit(['audit', '--verbose', '--json'], { cwd: dir });
      expect(r.code).toBe(0);
      const j = JSON.parse(r.out) as { warnings: { text: string }[] };
      expect(j.warnings[0]?.text).toBe(`${B3_PREFIX}${reason}${B3_SUFFIX}`);
      expect(j.warnings[0]?.text).not.toMatch(/refuses|Nothing unreviewed/);
    } finally {
      vi.mocked(loadReviewed).mockReset();
    }
  });

  it('README (item 7): the status line no longer says "design only, no code yet"', () => {
    const readme = readFileSync(resolve(import.meta.dirname, '../README.md'), 'utf8');
    expect(readme).not.toMatch(/design only|no code yet/i);
    expect(readme).toMatch(/> \*\*Status: .*`pipegen audit`/);
  });
});

describe('pipegen audit --ai (checks before consent)', () => {
  it('platform: an unsupported platform stops --ai before consent (S21)', async () => {
    const dir = repo();
    const { ai, env } = aiSetup();
    const ask = prompter(true);
    const desc = Object.getOwnPropertyDescriptor(process, 'platform') as PropertyDescriptor;
    Object.defineProperty(process, 'platform', { ...desc, value: 'win32' });
    let r: Awaited<ReturnType<typeof audit>>;
    try {
      r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env, prompt: ask });
    } finally {
      Object.defineProperty(process, 'platform', desc);
    }
    expect(r.code).toBe(1);
    expect(r.err).toContain(S21);
    expect(ask.asked).toEqual([]);
    expect(ai.complete).not.toHaveBeenCalled();
    expect(r.calls).toEqual([]); // stopped before reading GitHub
  });

  it('provider: no AI key → the audit --ai message (S15), exit 1, nothing asked', async () => {
    const dir = repo();
    const ask = prompter(true);
    const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env: {}, prompt: ask });
    expect(r.code).toBe(1);
    expect(r.err).toBe(S15);
    expect(ask.asked).toEqual([]);
    const openai = await audit(['audit', '--verbose', '--ai', 'openai'], { cwd: dir, env: { [OPENAI_VAR]: 'x'.repeat(20) }, prompt: ask });
    expect(openai.code).toBe(1);
    expect(openai.err).toContain('needs a model: pass --model');
  });

  it('unpriced: a model with no price stops before consent with the estimate\'s message (U14)', async () => {
    const dir = repo();
    const ask = prompter(true);
    const r = await audit(['audit', '--verbose', '--ai', 'openai', '--model', 'gpt-5-pro'], { cwd: dir, env: { [OPENAI_VAR]: 'x'.repeat(20) }, prompt: ask });
    expect(r.code).toBe(1);
    expect(r.err).toContain("pipegen doesn't know the price of gpt-5-pro, so it can't keep a hard cost limit. Choose one of: gpt-5, gpt-5-mini, gpt-5.5.");
    expect(ask.asked).toEqual([]);
    expect(addAiSuggestions).not.toHaveBeenCalled();
  });

  it('ollama: OLLAMA_HOST on ollama.com, a cloud model behind a local name, or no answer → refused before consent (fail closed)', async () => {
    const dir = repo();
    const ask = prompter(false);
    const show = (reply: Reply): Routes => publicRoutes({ 'POST http://127.0.0.1:11434/api/show': reply });
    const cloudHost = await audit(['audit', '--verbose', '--ai', 'ollama'], { cwd: dir, env: { OLLAMA_HOST: 'https://ollama.com' }, prompt: ask });
    expect(cloudHost.code).toBe(1);
    expect(cloudHost.err).toContain('OLLAMA_HOST points at ollama.com');
    expect(cloudHost.calls).toEqual([]);
    for (const host of ['api.OLLAMA.com:443', 'ollama.com..', 'OLLAMA.COM.', 'https://Ollama.Com.../x', '\uff4f\uff4c\uff4c\uff41\uff4d\uff41\u3002com']) {
      const sub = await audit(['audit', '--verbose', '--ai', 'ollama'], { cwd: dir, env: { OLLAMA_HOST: host }, prompt: ask });
      expect(sub.code, host).toBe(1);
      expect(sub.err, host).toContain('OLLAMA_HOST points at ollama.com'); // refused by name, before any request (M10)
      expect(sub.calls, host).toEqual([]);
    }
    const remote = await audit(['audit', '--verbose', '--ai', 'ollama', '--model', 'llama3.1'], { cwd: dir, env: {}, prompt: ask, routes: show({ body: { remote_host: 'https://ollama.com:443', remote_model: 'gpt-oss:120b', details: {} } }) });
    expect(remote.code).toBe(1);
    expect(remote.err).toContain('Ollama cloud models send your code to ollama.com');
    const down = await audit(['audit', '--verbose', '--ai', 'ollama'], { cwd: dir, env: {}, prompt: ask, routes: show({ status: 500, body: {} }) });
    expect(down.code).toBe(1);
    expect(down.err).toContain('pipegen couldn\'t confirm that the Ollama model "llama3.1" runs on 127.0.0.1:11434');
    const notJson = await audit(['audit', '--verbose', '--ai', 'ollama'], { cwd: dir, env: {}, prompt: ask, routes: show({ raw: 'not json' }) });
    expect(notJson.code).toBe(1);
    expect(ask.asked).toEqual([]);
    // a model that runs on that server: the consent screen is shown (and answered No here)
    const ok = await audit(['audit', '--verbose', '--ai', 'ollama'], { cwd: dir, env: {}, prompt: ask, routes: show({ body: { details: { family: 'llama' }, model_info: {} } }) });
    expect(ok.code).toBe(0);
    expect(ask.asked).toHaveLength(1);
    const showCall = ok.calls.find((c) => c.url.pathname === '/api/show') as Call;
    expect(JSON.parse(showCall.body as string)).toEqual({ model: 'llama3.1' });
    expect(ok.out).toContain('Ollama support is experimental'); // S15: the experimental note is in the report notes
  });

  it('consent: the screen shows the cap, and the same cap, provider, key and token reach addAiSuggestions (S19, U13)', async () => {
    const dir = repo();
    const { env } = aiSetup();
    const ghVal = fake.githubPat();
    env[GH_VAR] = ghVal;
    const ask = prompter(true);
    const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env, routes: privateRoutes(), prompt: ask });
    expect(r.code).toBe(0);
    const deps = vi.mocked(addAiSuggestions).mock.calls[0]?.[2];
    if (deps === undefined) throw new Error('addAiSuggestions was not called');
    expect(deps.capUsd).toBe(deps.consent.terms.capUsd);
    expect(ask.asked[0]).toContain(`pipegen stops if the AI cost reaches $${(deps.capUsd as number).toFixed(2)}.`);
    expect(deps.knownValues).toEqual(expect.arrayContaining([ghVal, anthropicVal]));
    expect(deps.anonymous).toBe(false);
    expect(deps.ai).toBe(hooks.ai);
    expect(deps.consent.terms.mode).toBe('audit-ai');
  });
});

describe('pipegen audit (output)', () => {
  it('out: --out inside the repo is refused without --force, also when --dir is not given (dir always passed); errors on stderr, exit 1', async () => {
    const dir = repo();
    const before = listTree(dir);
    const r = await audit(['audit', '--verbose', '--out', 'report.md'], { cwd: dir });
    expect(r.code).toBe(1);
    expect(r.err).toContain("Don't write the report into the repo you're auditing");
    expect(listTree(dir)).toEqual(before);
    // an existing file is refused without --force; --force replaces it
    const work = makeTempDir();
    writeFileSync(join(work, 'old.md'), 'old\n');
    const exists = await audit(['audit', '--verbose', '--dir', dir, '--out', 'old.md'], { cwd: work });
    expect(exists.code).toBe(1);
    expect(exists.err).toMatch(/already exists/);
    expect(readFileSync(join(work, 'old.md'), 'utf8')).toBe('old\n');
    const forced = await audit(['audit', '--verbose', '--dir', dir, '--out', 'old.md', '--force'], { cwd: work });
    expect(forced.code).toBe(0);
    expect(readFileSync(join(work, 'old.md'), 'utf8')).toMatch(/^# pipegen audit/);
  });

  it('out: --json and --out together: JSON on stdout, Markdown in the file, the "written" line on stderr', async () => {
    const dir = repo();
    const work = makeTempDir();
    const r = await audit(['audit', '--verbose', '--dir', dir, '--json', '--out', 'r.md'], { cwd: work });
    expect(r.code).toBe(0);
    expect(() => JSON.parse(r.out) as unknown).not.toThrow();
    expect(readFileSync(join(work, 'r.md'), 'utf8')).toMatch(/^# pipegen audit: o\/r/);
    expect(r.err).toContain('The Markdown report was written to');
  });

  it('safeRunCommand is what --help prints (one source for the command)', () => {
    expect(safeRunCommand(VERSION)).toBe(RUN_COMMAND);
  });
});

// ---------- Plan U final review fixes (final-review.md I1, I3, M1, M5, M6, M7, M9) ----------

/** GitHub's repo events, served page by page with its `Link: rel="next"` header (pages can hold fewer than 100). */
const eventPages = (list: unknown[][]) => (c: Call): Reply => {
  const n = Number(c.url.searchParams.get('page') ?? '1');
  return {
    body: list[n - 1] ?? [],
    headers: n < list.length ? { link: `<${R}/events?per_page=100&page=${n + 1}>; rel="next", <${R}/events?per_page=100&page=${list.length}>; rel="last"` } : {},
  };
};
const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString();
const oneLine = (s: string) => s.replace(/\s+/g, ' ');

describe('pipegen audit (Plan U final review)', () => {
  it('I1 / Review Focus 5: fake GitHub pages → buildAudit → report: pushes on page 2 count, monthly minutes follow, "at least" when the 30 days aren\'t reached', async () => {
    const dir = repo();
    // page 1: 97 events and no push (what GitHub served for express), with Link rel="next"
    const first = Array.from({ length: 97 }, (_, i) => ({ type: 'WatchEvent', created_at: daysAgo(i / 40) }));
    const pushes = [3, 4, 5].map((d) => ({ type: 'PushEvent', created_at: daysAgo(d) }));
    const json = async (pages: unknown[][]) => {
      const r = await audit(['audit', '--verbose', '--json'], { cwd: dir, routes: publicRoutes({ [`GET ${R}/events`]: eventPages(pages) }) });
      expect(r.code).toBe(0);
      return (JSON.parse(r.out) as { estimates: { monthlyMinutes: number; basis: string[] } }).estimates;
    };
    // page 2 holds the pushes and an event older than 30 days: an exact count
    const exact = await json([first, [...pushes, { type: 'WatchEvent', created_at: daysAgo(40) }]]);
    expect(exact.basis).toContain('Activity: 3 pushes and 0 pull requests in the last 30 days.');
    const none = await json([first]);
    expect(none.basis).toContain('Activity: 0 pushes and 0 pull requests in the last 30 days.');
    expect(exact.monthlyMinutes).toBeGreaterThan(none.monthlyMinutes);
    // three pages, all inside the 30 days: GitHub's list ended at its limit, so the count is a lower bound
    const short = (from: number) => Array.from({ length: 97 }, (_, i) => ({ type: 'WatchEvent', created_at: daysAgo(from + i / 100) }));
    const pages = [short(0), [...pushes, ...short(6)], short(8)];
    const capped = await json(pages);
    expect(capped.basis.some((b) => b.startsWith('Activity: at least 3 pushes and at least 0 pull requests in the last 30 days'))).toBe(true);
    expect(capped.monthlyMinutes).toBe(exact.monthlyMinutes);
    const t = await audit(['audit', '--verbose'], { cwd: dir, routes: publicRoutes({ [`GET ${R}/events`]: eventPages(pages) }) });
    expect(oneLine(t.out)).toContain(`After setup: about ${capped.monthlyMinutes.toLocaleString('en-US')} minutes a month, or more (pipegen could count only part of the activity).`);
    expect(oneLine(t.out)).toContain('Activity: at least 3 pushes');
  });

  it('I3: the private-repo access steps ask for exactly Metadata, Pull requests, Actions and Code scanning alerts, all read', async () => {
    const dir = repo();
    const r = await audit(['audit', '--verbose'], { cwd: dir, routes: publicRoutes({ [`GET ${R}`]: err(404, 'Not Found') }) });
    expect(r.code).toBe(1);
    expect(r.err).toContain('with Metadata: read, Pull requests: read, Actions: read, Code scanning alerts: read,');
    expect(r.err).not.toMatch(/Secrets|Variables|Environments|Administration|Contents|Workflows|write/);
    expect(permissionsTable('read').map((p) => p.permission)).toEqual(['Metadata: read', 'Pull requests: read', 'Actions: read', 'Code scanning alerts: read']);
    // --help names the same list
    const help = await audit(['--help'], { cwd: makeTempDir() });
    expect(oneLine(help.out)).toContain('Metadata: read, Pull requests: read, Actions: read, Code scanning alerts: read');
    // the README too
    const readme = readFileSync(resolve(import.meta.dirname, '../README.md'), 'utf8');
    for (const p of permissionsTable('read')) expect(readme).toContain(p.permission);
  });

  it('M1: the catch-all error line hides secret-like text it didn\'t write', async () => {
    const dir = repo();
    const leaked = fake.githubClassic(); // not a known value: only redact() can hide it
    vi.mocked(buildAudit).mockRejectedValueOnce(new Error(`unexpected failure near ${leaked}`));
    const r = await audit(['audit', '--verbose'], { cwd: dir });
    expect(r.code).toBe(1);
    expect(r.err).toContain('pipegen audit failed: unexpected failure near');
    expect(r.all).not.toContain(leaked);
  });

  it('M5: an anonymous run says "without a token", never "with this token"', async () => {
    const dir = repo();
    const r = await audit(['audit', '--verbose', '--json'], { cwd: dir });
    expect(r.code).toBe(0);
    const notes = (JSON.parse(r.out) as { notes: string[] }).notes;
    expect(notes.some((n) => n.startsWith("Couldn't check code scanning without a token"))).toBe(true);
    expect(notes.join('\n')).not.toContain('with this token');
  });

  it('M6 / M9: after --ai the report repeats the agreed limit; the code bundle is built once to count and once to check', async () => {
    const dir = repo();
    const { env } = aiSetup();
    const ask = prompter(true);
    const r = await audit(['audit', '--verbose', '--ai'], { cwd: dir, env, prompt: ask });
    expect(r.code).toBe(0);
    const cap = /pipegen stops if the AI cost reaches (\$\d+\.\d\d)\./.exec(ask.asked[0] as string)?.[1];
    expect(cap).toBeDefined();
    expect(oneLine(r.out)).toMatch(/AI cost of this audit: about \$\d+\.\d\d at list price \(/);
    expect(oneLine(r.out)).toContain(`the limit you agreed to: ${cap as string}.`);
    expect(vi.mocked(bundleCode)).toHaveBeenCalledTimes(2);
    const [counting, checked] = vi.mocked(bundleCode).mock.calls;
    expect(counting?.[1]?.secretScanner).toBeUndefined();
    expect(checked?.[1]?.secretScanner).toBeDefined();
    // the report's count and the consent screen's count are the same count
    const files = /pipegen sends at most (\d+) files?/.exec(ask.asked[0] as string)?.[1];
    expect(oneLine(r.out)).toContain(`pipegen would send ${files} file`);
    // a plain run builds it once
    vi.mocked(bundleCode).mockClear();
    expect((await audit(['audit', '--verbose'], { cwd: dir })).code).toBe(0);
    expect(vi.mocked(bundleCode)).toHaveBeenCalledTimes(1);
  });

  it('M7: --json carries the "what this audit can\'t see" list', async () => {
    const dir = repo();
    const r = await audit(['audit', '--verbose', '--json'], { cwd: dir });
    // J4: only the limits that apply to the repo; a repo with no workflows is not told about workflow limits
    const cantSee = (JSON.parse(r.out) as { cantSee: string[] }).cantSee;
    const all = CANT_SEE.map((x) => x.text);
    expect(cantSee.length).toBeGreaterThan(0);
    for (const t of cantSee) expect(all).toContain(t);
  });
});

// ---------- P40: names the secret scan flagged are masked in the whole report ----------

describe('pipegen audit --ai (P40: report-wide masking of scanner-flagged names)', () => {
  it('P40: a base64-encoded secret as a file name, flagged by the scanner (decoded), is masked in every part of the terminal, JSON and Markdown report', async () => {
    // the scanner reports the DECODED value, which is not in the name as written, so no name check by pattern sees it
    const decoded = ['decoded', 'name', 'secret', randomBytes(6).toString('hex')].join('-');
    const encoded = Buffer.from(decoded).toString('base64').replace(/=+$/, '');
    expect(encoded).toMatch(/^[A-Za-z0-9+]+$/); // a plain file name (no slash)
    // the file also holds a secret-like value, so the plain audit names it in "secrets in the files on disk"
    const name = `src/${encoded}.ts`;
    const dir = repo({ [name]: `export const t = "${fake.githubPat()}";\n` });
    const body = `writeReport(JSON.stringify(findingsFor(${JSON.stringify(encoded)}).filter((x) => /paths/.test(x.File)).map((x) => ({ ...x, Match: ${JSON.stringify(decoded)}, ['Sec' + 'ret']: ${JSON.stringify(decoded)} })))); process.exit(1);`;
    const work = makeTempDir();
    for (const json of [false, true]) {
      const { env } = aiSetup(undefined, undefined, body);
      const argv = ['audit', '--verbose', '--ai', '--dir', dir, '--out', json ? 'r2.md' : 'r1.md', ...(json ? ['--json'] : [])];
      const r = await audit(argv, { cwd: work, env, prompt: prompter(true) });
      expect(r.code, r.err).toBe(0);
      const md = readFileSync(join(work, json ? 'r2.md' : 'r1.md'), 'utf8');
      // the --ai run happened and the scanner flagged the name (the bundle left the file out)
      expect(oneLine(r.out)).toMatch(/flagged as secret-like/);
      for (const [where, text] of [['stdout', r.out], ['stderr', r.err], ['markdown', md]] as const) {
        expect(text, `${String(json)} ${where}`).not.toContain(encoded);
        expect(text, `${String(json)} ${where}`).not.toContain(decoded);
      }
      // the plain-audit warning still says a file holds a secret-like value, with the name masked
      expect(md).toContain('(a file whose name looks like a secret)');
      if (json) {
        const j = JSON.parse(r.out) as AuditReport;
        expect(j.secretsInTree.map((s) => s.file)).toContain('(a file whose name looks like a secret)');
      } else {
        expect(r.out).toContain('(a file whose name looks like a secret)');
      }
    }
  });
});

describe('pipegen audit --ai (P45: every printable name is scanned; what the scan found is masked in the whole report)', () => {
  /** --ai with the stub scanner (`body`), --json once and terminal once, each with --out; every output text. */
  async function runAi(dir: string, body: string): Promise<{ where: string; text: string }[]> {
    const work = makeTempDir();
    const outs: { where: string; text: string }[] = [];
    for (const json of [false, true]) {
      const { env } = aiSetup(undefined, undefined, body);
      const file = json ? 'j.md' : 't.md';
      const r = await audit(['audit', '--verbose', '--ai', '--dir', dir, '--out', file, ...(json ? ['--json'] : [])], { cwd: work, env, prompt: prompter(true) });
      expect(r.code, r.err).toBe(0);
      expect(oneLine(r.out), 'the --ai scan ran').toMatch(/checked the bundle/);
      outs.push({ where: `${json ? 'json' : 'terminal'} stdout`, text: r.out }, { where: 'stderr', text: r.err }, { where: `${file}`, text: readFileSync(join(work, file), 'utf8') });
    }
    return outs;
  }
  /** The stub reports `decoded` on every file-list line that holds `encoded` (as the real scanners report a base64 name). */
  const decodedOn = (encoded: string, decoded: string) => `writeReport(JSON.stringify(findingsFor(${JSON.stringify(encoded)}).filter((x) => /paths/.test(x.File)).map((x) => ({ ...x, Match: ${JSON.stringify(decoded)}, ['Sec' + 'ret']: ${JSON.stringify(decoded)} })))); process.exit(1);`;
  const encodedPair = () => {
    const decoded = ['decoded', 'name', 'secret', randomBytes(6).toString('hex')].join('-');
    return { decoded, encoded: Buffer.from(decoded).toString('base64').replace(/=+$/, '') };
  };
  const noLeak = (outs: { where: string; text: string }[], ...values: string[]) => {
    for (const { where, text } of outs) for (const v of values) expect(text, `${where} holds ${v.slice(0, 8)}…`).not.toContain(v);
  };

  it('P45 repro A: the same encoded secret in an excluded file name (config/<b64>.env) is masked too', async () => {
    const { decoded, encoded } = encodedPair();
    const dir = repo({ [`src/${encoded}.ts`]: `export const t = "${fake.githubPat()}";\n`, [`config/${encoded}.env`]: `T=${fake.githubPat()}\n` });
    const outs = await runAi(dir, decodedOn(encoded, decoded));
    noLeak(outs, encoded, decoded);
    // the .env name is now in the scanned file list, so the scanner flags it and the report shows it masked whole
    const j = JSON.parse(outs.find((o) => o.where === 'json stdout')?.text ?? '{}') as AuditReport;
    expect(j.secretsInTree.map((s) => s.file).filter((f) => f === '(a file whose name looks like a secret)')).toHaveLength(2);
  });

  it('P45 repro B: a skipped binary with the encoded secret in its name (assets/<b64>.bin) is masked in the notes', async () => {
    const { decoded, encoded } = encodedPair();
    const dir = repo({ [`src/${encoded}.ts`]: 'export const a = 1;\n' });
    writeIn(dir, `assets/${encoded}.bin`, '');
    writeFileSync(join(dir, `assets/${encoded}.bin`), Buffer.from([0x50, 0, 0x51]));
    const outs = await runAi(dir, decodedOn(encoded, decoded));
    noLeak(outs, encoded, decoded);
  });

  it('P45 repro C: a 12-character flagged value used as a top folder is masked (top folders, notes, every output)', async () => {
    const value = 'Zq' + randomBytes(5).toString('hex');
    expect(value).toHaveLength(12);
    const dir = repo({ [`${value}/main.ts`]: 'export const m = 1;\n' });
    const body = `writeReport(JSON.stringify(findingsFor(${JSON.stringify(value)}).filter((x) => /paths/.test(x.File)))); process.exit(1);`;
    const outs = await runAi(dir, body);
    noLeak(outs, value);
  });

  it('P45 repro D: a path over 300 characters with the encoded secret across the old 300-character cut leaks no part of it', async () => {
    const { decoded, encoded } = encodedPair();
    const deep = `deep/${'d'.repeat(140)}/${'e'.repeat(140)}`; // 286 characters, so the name runs across 300
    const name = `${deep}/${encoded}.bin`;
    expect(name.length).toBeGreaterThan(300);
    const dir = repo({ [`src/${encoded}.ts`]: 'export const a = 1;\n' });
    writeIn(dir, name, '');
    writeFileSync(join(dir, name), Buffer.from([0x50, 0, 0x51]));
    const outs = await runAi(dir, decodedOn(encoded, decoded));
    noLeak(outs, encoded, decoded, encoded.slice(0, 10));
  });
});

describe('pipegen audit --ai (P45 addendum: a name longer than the scanner saw is hidden whole)', () => {
  it('P45: a 1,200-character path with a secret after character 1,000 (past the scanned part) never appears in terminal, JSON or Markdown', async () => {
    const value = ['tail', 'secret', randomBytes(8).toString('hex')].join('-');
    const head = `p/${Array.from({ length: 5 }, (_, i) => `${i}${'q'.repeat(198)}`).join('/')}`; // 1,001 characters
    const name = `${head}/${value}-${'r'.repeat(1_200 - head.length - value.length - 5)}.ts`;
    expect(name.length).toBe(1_200);
    expect(name.indexOf(value)).toBeGreaterThan(1_000);
    const dir = repo({ 'src/a.ts': 'export const a = 1;\n' });
    writeIn(dir, name, `export const t = "${fake.githubPat()}";\n`); // a secret-like value: the warnings name the file
    const work = makeTempDir();
    // the stub flags the value wherever it sees it: it never does (the scanned name is cut at 1,000 characters)
    const body = `writeReport(JSON.stringify(findingsFor(${JSON.stringify(value)}))); process.exit(1);`;
    for (const json of [false, true]) {
      const { env } = aiSetup(undefined, undefined, body);
      const file = json ? 'j.md' : 't.md';
      const r = await audit(['audit', '--verbose', '--ai', '--dir', dir, '--out', file, ...(json ? ['--json'] : [])], { cwd: work, env, prompt: prompter(true) });
      expect(r.code, r.err).toBe(0);
      expect(oneLine(r.out)).toMatch(/checked the bundle/);
      const md = readFileSync(join(work, file), 'utf8');
      expect(md, 'the warning names the file, hidden whole').toContain('(a file whose name looks like a secret)');
      for (const [where, text] of [['stdout', r.out], ['stderr', r.err], ['markdown', md]] as const) {
        expect(text, `${String(json)} ${where}`).not.toContain(value);
        expect(text, `${String(json)} ${where}`).not.toContain('r'.repeat(40));
      }
    }
  });
});

// DoD run 2026-10-29: GitHub's rate limit (anonymous 60 an hour) made `audit` exit 1 with no report. Plan U's promise:
// the audit completes from the local files, says plainly that the limit was hit and when it resets, and suggests a
// read-only GITHUB_TOKEN. Every check that needed GitHub is unknown, never covered and never missing. Exit code 3.
describe('GitHub rate limit (DoD)', () => {
  const resetSec = () => Math.floor(Date.now() / 1000) + 3300;
  const limited403 = (reset: number): Reply => ({ status: 403, body: { message: 'API rate limit exceeded for 203.0.113.9.' }, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-limit': '60', 'x-ratelimit-reset': String(reset) } });
  const limited429 = (): Reply => ({ status: 429, body: { message: 'You have exceeded a secondary rate limit.' }, headers: { 'retry-after': '3300' } });
  // the push trigger is limited to main (partial on every push, whatever the default branch); the pull request
  // trigger targets main, which is covered only if main is the default branch
  const CI = 'on:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n';
  const READ_PERMS = 'Metadata: read, Pull requests: read, Actions: read, Code scanning alerts: read';
  type J = { githubIncomplete: { reason: string; resetsAt: string | null; unread: string[]; rows: number } | null; coverage: { need: { id: string; layer: string }; status: string; why: string }[]; profile: Record<string, unknown> };
  const cov = (j: J, layer: string, id: string) => j.coverage.find((c) => c.need.layer === layer && c.need.id === id);

  it('rate limit at the first call (anonymous): full report from the files, unknown where GitHub was needed, reset time, token hint, exit 3', async () => {
    const dir = repo({ '.github/workflows/ci.yml': CI });
    const reset = resetSec();
    const routes = publicRoutes({ [`GET ${R}`]: limited403(reset) });
    const r = await audit(['audit', '--verbose'], { cwd: dir, routes });
    expect(r.code).toBe(3);
    expect(r.out).toContain('Verdict:');
    expect(r.out).toContain('Checks by layer');
    const flatOut = r.out.replace(/\n {2,}/g, ' ');
    expect(flatOut).toContain("GitHub's rate limit was reached, so pipegen couldn't read everything it needs from GitHub.");
    expect(flatOut).toMatch(/GitHub's limit resets by \d\d:\d\d \S+ \(your local time\), within 5[56] minutes\./);
    expect(flatOut).toContain(`set GITHUB_TOKEN to a read-only fine-grained token for this one repo`);
    expect(flatOut).toContain(READ_PERMS);
    expect(flatOut).not.toMatch(/Repo: (public|private)/);
    expect(r.err).toContain('exit code 3');
    // one request, then nothing more is asked of GitHub
    expect(r.calls.filter((c) => c.url.origin === API)).toHaveLength(1);

    const j = JSON.parse((await audit(['audit', '--verbose', '--json'], { cwd: dir, routes })).out) as J;
    expect(j.githubIncomplete).toMatchObject({ reason: 'github-rate-limit', resetsAt: new Date(reset * 1000).toISOString() });
    expect(j.githubIncomplete?.unread).toEqual(expect.arrayContaining(['repo', 'branch-protection', 'environments', 'code-scanning', 'activity']));
    expect(j.profile.private).toBeNull();
    expect(j.profile.defaultBranch).toBeNull();
    // P50 (M5): unread capabilities are null too, never the placeholders
    expect(Object.values((j as unknown as { capabilities: Record<string, unknown> }).capabilities).every((v) => v === null)).toBe(true);
    // depends on the default branch: unknown, saying why. J3a (S5): so does the push row, since "every pull request + every
    // push to the default branch" may cover it (DECISIONS #122), which the placeholder branch can't tell
    expect(cov(j, 'merge', 'unit-tests')).toMatchObject({ status: 'unknown' });
    expect(cov(j, 'merge', 'unit-tests')?.why).toMatch(/GitHub's rate limit/);
    expect(cov(j, 'push', 'unit-tests')).toMatchObject({ status: 'unknown' });
    expect(cov(j, 'push', 'unit-tests')?.why).toMatch(/GitHub's rate limit/);
    // a check that needs nothing from GitHub keeps its answer
    expect(cov(j, 'pre-commit', 'hooks')?.status).toBe('missing');
    expect(j.githubIncomplete?.rows).toBe(j.coverage.filter((c) => /GitHub's rate limit/.test(c.why)).length);
    expect(j.githubIncomplete!.rows).toBeGreaterThan(0);

    // --out writes the report, warning first
    const work = makeTempDir();
    const o = await audit(['audit', '--verbose', '--dir', dir, '--out', 'r.md'], { cwd: work, routes });
    expect(o.code).toBe(3);
    const md = readFileSync(join(work, 'r.md'), 'utf8');
    expect(md).toContain("GitHub's rate limit was reached");
    expect(md).toContain(READ_PERMS);
  });

  it('rate limit mid-run (403 at environments, then 429): what was read stays, the rest is unknown; the default branch is known', async () => {
    const dir = repo({ '.github/workflows/ci.yml': CI });
    for (const limitedReply of [limited403(resetSec()), limited429()]) {
      const routes = publicRoutes({ [`GET ${R}/environments`]: limitedReply });
      const r = await audit(['audit', '--verbose', '--json'], { cwd: dir, routes });
      expect(r.code).toBe(3);
      const j = JSON.parse(r.out) as J;
      expect(j.githubIncomplete?.unread).toEqual(expect.arrayContaining(['environments', 'code-scanning', 'activity']));
      expect(j.githubIncomplete?.unread).not.toContain('repo');
      expect(j.githubIncomplete?.unread).not.toContain('branch-protection');
      expect(j.profile).toMatchObject({ private: false, defaultBranch: 'main' });
      expect((j as unknown as { capabilities: Record<string, unknown> }).capabilities).toMatchObject({ branchProtection: true, environments: null, envRequiredReviewers: null, codeScanning: null });
      expect(cov(j, 'merge', 'unit-tests')?.status).toBe('covered'); // the default branch was read: a real answer
      // no request after the stop
      const asked = r.calls.filter((c) => c.url.origin === API).map((c) => c.url.pathname);
      expect(asked).toEqual(['/repos/o/r', '/repos/o/r/rulesets', '/repos/o/r/environments']);
    }
  });

  it('rate limit at the last call (activity): every check keeps its answer; the minutes say so; still exit 3', async () => {
    const dir = repo({ '.github/workflows/ci.yml': CI });
    const full = JSON.parse((await audit(['audit', '--verbose', '--json'], { cwd: dir })).out) as J;
    const r = await audit(['audit', '--verbose', '--json'], { cwd: dir, routes: publicRoutes({ [`GET ${R}/events`]: limited403(resetSec()) }) });
    expect(r.code).toBe(3);
    const j = JSON.parse(r.out) as J;
    expect(j.githubIncomplete).toMatchObject({ reason: 'github-rate-limit', unread: ['activity'], rows: 0 });
    expect(j.coverage).toEqual(full.coverage);
    expect(full.githubIncomplete).toBeNull();
  });

  it('P51 (M5): with the limit hit, "would add" and the --ai consent screen say they rest on incomplete GitHub data, in every output', async () => {
    const dir = repo({ '.github/workflows/ci.yml': CI });
    const routes = publicRoutes({ [`GET ${R}`]: limited403(resetSec()) });
    const NOTE = 'These picks are based on incomplete GitHub data (rate limit)';
    const t = await audit(['audit', '--verbose'], { cwd: dir, routes });
    expect(t.out.replace(/\n {2,}/g, ' ')).toContain(NOTE);
    const j = JSON.parse((await audit(['audit', '--verbose', '--json'], { cwd: dir, routes })).out) as { wouldAddNote: string | null };
    expect(j.wouldAddNote).toContain(NOTE);
    const work = makeTempDir();
    await audit(['audit', '--verbose', '--dir', dir, '--out', 'r.md'], { cwd: work, routes });
    expect(readFileSync(join(work, 'r.md'), 'utf8').replace(/\n/g, ' ')).toContain(NOTE);
    // a complete run has no such note
    expect((JSON.parse((await audit(['audit', '--verbose', '--json'], { cwd: dir })).out) as { wouldAddNote: unknown }).wouldAddNote).toBeNull();
    // the --ai consent screen (answered No)
    const { env } = aiSetup();
    const ask = prompter(false);
    await audit(['audit', '--verbose', '--ai'], { cwd: dir, env, routes, prompt: ask });
    expect(ask.asked[0]).toContain('Based on incomplete GitHub data (rate limit)');
    const okAsk = prompter(false);
    await audit(['audit', '--verbose', '--ai'], { cwd: dir, env: aiSetup().env, prompt: okAsk });
    expect(okAsk.asked[0]).not.toContain('incomplete GitHub data');
  });

  it('rate limit with a token set: the same report and exit 3, no hint to set one; other failures keep exit 1', async () => {
    const dir = repo({ '.github/workflows/ci.yml': CI });
    const tok = fake.githubPat();
    const routes = privateRoutes({ [`GET ${API}/user`]: limited403(resetSec()) });
    const r = await audit(['audit', '--verbose'], { cwd: dir, routes, env: { [GH_VAR]: tok } });
    expect(r.code).toBe(3);
    const flatOut = r.out.replace(/\n {2,}/g, ' ');
    expect(flatOut).toContain("GitHub's rate limit was reached");
    expect(flatOut).not.toContain('set GITHUB_TOKEN to');
    expect(flatOut).toContain('This limit counts the requests made with your token');
    expect(r.all).not.toContain(tok);
    // a refused token is not a rate limit: unchanged (exit 1, GitHub not read)
    const refused = await audit(['audit', '--verbose'], { cwd: dir, routes: privateRoutes({ [`GET ${API}/user`]: err(401, 'Bad credentials') }), env: { [GH_VAR]: tok } });
    expect(refused.code).toBe(1);
    expect(refused.out).toContain('GitHub: not read');
  });
});

// ---------- Plan J sub-task J5 (DECISIONS #124; rulings B1, S8-S10, S15) ----------

const SWAP_TEXT = 'This repo could change which pipegen runs. Run pipegen from outside the repo, from the npm registry, with:';
const UNSAFE_NPMRC = 'registry=https://registry.example.invalid/\n';

/** A two-service npm workspace: a static Next.js export (`web`) and an express server (`api`). */
function twoServices(files: Record<string, string> = {}): string {
  return repo({
    'package.json': JSON.stringify({ name: 'root', private: true, workspaces: ['apps/*'] }),
    'apps/web/package.json': JSON.stringify({ name: 'web', scripts: { dev: 'next dev', build: 'next build' }, dependencies: { next: '15.0.0' } }),
    'apps/web/next.config.mjs': "export default { output: 'export' };\n",
    'apps/web/pages/index.js': 'export default function Home() { return null; }\n',
    'apps/api/package.json': JSON.stringify({ name: 'api', scripts: { start: 'node index.js' }, dependencies: { express: '4.0.0' } }),
    'apps/api/index.js': "require('express')().listen(process.env.PORT || 3000);\n",
    ...files,
  });
}
/** One static service (a Next.js export) named `site`. */
function staticSite(): string {
  return repo({
    'package.json': JSON.stringify({ name: 'site', scripts: { dev: 'next dev', build: 'next build' }, dependencies: { next: '15.0.0' } }),
    'next.config.mjs': "export default { output: 'export' };\n",
    'pages/index.js': 'export default function Home() { return null; }\n',
  });
}

/** A second static shape: a Vite single-page app named `spa`. */
function viteSpa(): string {
  return repo({
    'package.json': JSON.stringify({ name: 'spa', scripts: { dev: 'vite', build: 'vite build' }, devDependencies: { vite: '7.0.0' } }),
    'index.html': '<div id="app"></div><script type="module" src="/src/main.js"></script>\n',
    'src/main.js': 'document.getElementById("app").textContent = "hi";\n',
  });
}

/** A prompter for the type question: `typeOk` answers "Is this right?", `picks` the selects; it records each question and how many GitHub calls had been made when it was asked. */
function typePrompter(typeOk: boolean | Error, picks: (string | Error)[] = [], calls: () => number = () => 0) {
  const asked: { msg: string; githubCalls: number }[] = [];
  const p: Prompter = {
    confirm: vi.fn(async (msg: string) => {
      asked.push({ msg, githubCalls: calls() });
      if (typeOk instanceof Error) throw typeOk;
      return typeOk;
    }),
    select: vi.fn(async <T extends string>(msg: string) => {
      asked.push({ msg, githubCalls: calls() });
      const next = picks.shift();
      if (next instanceof Error) throw next;
      return next as T;
    }) as Prompter['select'],
    text: async () => { throw new Error('no text question'); },
  };
  return { p, asked };
}
const noPrompt = (): Prompter => ({
  confirm: vi.fn(async () => { throw new Error('no question expected'); }),
  select: vi.fn(async () => { throw new Error('no question expected'); }) as Prompter['select'],
  text: vi.fn(async () => { throw new Error('no question expected'); }),
});

/** A git index (version 2) listing `paths`, with a correct SHA-1 trailer, written by hand (no git process). */
function writeIndex(dir: string, paths: string[]): void {
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('DIRC', 0, 'latin1');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(paths.length, 8);
  parts.push(head);
  for (const p of [...paths].sort()) {
    const fixed = Buffer.alloc(62);
    fixed.writeUInt32BE(0o100644, 24);
    fixed.fill(0xab, 40, 60);
    const name = Buffer.from(p);
    fixed.writeUInt16BE(Math.min(name.length, 0xfff), 60);
    const len = 62 + name.length;
    parts.push(fixed, name, Buffer.alloc(Math.ceil((len + 1) / 8) * 8 - len));
  }
  const body = Buffer.concat(parts);
  writeFileSync(join(dir, '.git/index'), Buffer.concat([body, createHash('sha1').update(body).digest()]));
}
const profileOf = (call: number) => (vi.mocked(renderTerminal).mock.calls[call]?.[0] as AuditReport).profile;

describe('npx pipegen inside the folder: the safe-mode stop (J5, #124, S8, S15)', () => {
  it('inside + unsafe .npmrc → exit 4, no prompt, no GitHub call', async () => {
    // three .npmrc shapes (a registry, node-options, a script shell), each with four ways to start
    for (const [npmrc, argv] of ['registry=https://registry.example.invalid/\n', 'node-options=--require=./x.js\n', '; comment\nscript-shell = ./x.sh\n']
      .flatMap((n) => [[], ['audit'], ['audit', '--dir', '.'], ['--dir', '<dir>']].map((a) => [n, a] as const))) {
      const dir = repo({ '.npmrc': npmrc });
      argv.splice(0, argv.length, ...argv.map((a) => (a === '<dir>' ? dir : a)));
      vi.mocked(buildAudit).mockClear();
      const prompt = noPrompt();
      const r = await audit(argv, { cwd: dir, interactive: true, prompt });
      expect(r.code, argv.join(' ')).toBe(EXIT_UNSAFE_FOLDER);
      expect(EXIT_UNSAFE_FOLDER).toBe(4);
      expect(r.err).toContain(SWAP_TEXT);
      expect(r.err).toContain(RUN_COMMAND);
      expect(r.err).toContain('.npmrc');
      expect(r.out).toBe('');
      expect(r.calls).toEqual([]);
      expect(prompt.confirm).not.toHaveBeenCalled();
      expect(buildAudit).not.toHaveBeenCalled();
      expect(globalFetch).not.toHaveBeenCalled();
    }
  });

  it('outside + unsafe .npmrc → warning, audit runs', async () => {
    const dir = repo({ '.npmrc': UNSAFE_NPMRC });
    const r = await audit(['audit', '--verbose', '--dir', dir], { cwd: makeTempDir() });
    expect(r.code).toBe(0);
    expect(r.out.replace(/\s+/g, ' ')).toContain(SWAP_TEXT); // the terminal wraps the warning
    expect(r.out).toContain(RUN_COMMAND);
    expect(r.out).toContain('pipegen audit: o/r');
    expect(r.calls.length).toBeGreaterThan(0);
    // the parent folder of the repo is outside it too
    const parent = await audit(['--dir', dir.split('/').pop() as string], { cwd: resolve(dir, '..') });
    expect(parent.code).toBe(0);
  });

  it('inspect inside + unsafe .npmrc → exit 4', async () => {
    const dir = repo({ '.npmrc': UNSAFE_NPMRC });
    const r = await audit(['inspect'], { cwd: dir });
    expect(r.code).toBe(EXIT_UNSAFE_FOLDER);
    expect(r.err).toContain(SWAP_TEXT);
    expect(r.out).toBe('');
    expect(r.calls).toEqual([]);
    const outside = await audit(['inspect', '--dir', dir], { cwd: makeTempDir() });
    expect(outside.code).toBe(0);
  });

  it('cwd in a sub-folder with its own .npmrc → exit 4', async () => {
    const dir = repo({ 'packages/tool/.npmrc': UNSAFE_NPMRC, 'packages/tool/package.json': JSON.stringify({ name: 'tool' }), 'packages/tool/src/x.js': '\n' });
    for (const [cwd, dirArg] of [[join(dir, 'packages/tool'), '../..'], [join(dir, 'packages/tool/src'), dir]] as const) {
      const r = await audit(['--dir', dirArg], { cwd });
      expect(r.code, cwd).toBe(EXIT_UNSAFE_FOLDER);
      expect(r.err).toContain('packages/tool');
      expect(r.calls).toEqual([]);
    }
    // a local pipegen in a folder on the way is the same stop
    const bin = repo({ 'packages/tool/node_modules/.bin/pipegen': '#!/bin/sh\n', 'packages/tool/package.json': '{}' });
    writeIndex(bin, ['package.json', 'packages/tool/package.json']);
    const r = await audit(['--dir', bin], { cwd: join(bin, 'packages/tool') });
    expect(r.code).toBe(EXIT_UNSAFE_FOLDER);
    // from the repo's own folder, npm never reads a sub-folder's .npmrc: no stop (and no warning: the root .npmrc is fine)
    const fromRoot = await audit([], { cwd: dir });
    expect(fromRoot.code).toBe(0);
    expect(fromRoot.out).not.toContain(SWAP_TEXT);
  });

  it('committed node_modules folder → exit 4', async () => {
    const files = { 'node_modules/left-pad/index.js': 'module.exports = 1;\n' };
    const committed = repo(files);
    writeIndex(committed, ['index.js', 'node_modules/left-pad/index.js', 'package-lock.json', 'package.json']);
    const r = await audit([], { cwd: committed });
    expect(r.code).toBe(EXIT_UNSAFE_FOLDER);
    expect(r.err).toContain('node_modules');
    expect(r.calls).toEqual([]);
    // a node_modules the index doesn't list (installed, not committed) is normal: the audit runs
    const installed = repo(files);
    writeIndex(installed, ['index.js', 'package-lock.json', 'package.json']);
    expect((await audit([], { cwd: installed })).code).toBe(0);
    // no index pipegen can read: any node_modules folder stops (S8)
    expect((await audit([], { cwd: repo(files) })).code).toBe(EXIT_UNSAFE_FOLDER);
  });

  it('swapRisk: only from inside the folder (by real path); exact node_modules entries in the index; a dangling .bin link counts', async () => {
    const dir = repo({ '.npmrc': UNSAFE_NPMRC });
    expect(await swapRisk(dir, dir)).toBe(true);
    expect(await swapRisk(makeTempDir(), dir)).toBe(false);
    expect(await swapRisk(resolve(dir, '..'), dir)).toBe(false);
    expect(await swapRisk(join(dir, 'nope'), dir)).toBe(false); // a folder that isn't there holds no settings
    // a sibling whose name starts with the repo's name is outside it
    const sib = `${dir}-other`;
    mkdirSync(sib);
    try {
      expect(await swapRisk(sib, dir)).toBe(false);
    } finally {
      rmSync(sib, { recursive: true, force: true });
    }
    // the index lists node_modules itself (a committed link) → committed; node_modules_x or vendor/node_modules elsewhere → not on the path
    const linked = repo();
    writeIndex(linked, ['node_modules', 'package.json']);
    expect(await swapRiskWhy(linked, linked)).toContain('a committed node_modules folder');
    const near = repo();
    writeIndex(near, ['node_modules_x/a.js', 'vendor/node_modules/a.js', 'package.json']);
    expect(await swapRisk(near, near)).toBe(false);
    const dangling = repo();
    writeIndex(dangling, ['package.json']);
    mkdirSync(join(dangling, 'node_modules/.bin'), { recursive: true });
    symlinkSync('/nonexistent/pipegen-target', join(dangling, 'node_modules/.bin/pipegen'));
    expect(await swapRiskWhy(dangling, dangling)).toContain('node_modules/.bin/pipegen');
    // an .npmrc that is a link or a folder can't be read safely: it counts
    const link = repo();
    symlinkSync('/nonexistent/npmrc', join(link, '.npmrc'));
    expect(await swapRisk(link, link)).toBe(true);
    // a safe .npmrc alone is fine
    const safe = repo({ '.npmrc': 'save-exact=true\n' });
    expect(await swapRisk(safe, safe)).toBe(false);
  });

  it('committed Node_Modules in another letter case → exit 4 (macOS and Windows read it as node_modules)', async () => {
    for (const entry of ['Node_Modules/x.js', 'NODE_MODULES/x/package.json']) {
      const dir = repo();
      writeIndex(dir, ['index.js', entry, 'package.json']);
      const r = await audit([], { cwd: dir });
      expect(r.code, entry).toBe(EXIT_UNSAFE_FOLDER);
      expect(r.err).toContain('a committed node_modules folder');
      expect(r.calls).toEqual([]);
    }
    // in a sub-folder on the way too
    const sub = repo({ 'packages/a/package.json': '{}' });
    writeIndex(sub, ['package.json', 'packages/a/package.json', 'packages/A/Node_Modules/y.js']);
    expect((await audit(['--dir', sub], { cwd: join(sub, 'packages/a') })).code).toBe(EXIT_UNSAFE_FOLDER);
  });

  it('the folder pipegen was started in is checked whatever --dir says (npx already obeyed it)', async () => {
    const target = repo();
    // an untrusted clone (its own .git) started from, with --dir pointing at another repo: its .npmrc, or a sub-folder's
    const clone = repo({ '.npmrc': 'node-options=--require=./x.js\n', 'src/a.js': '\n' });
    for (const cwd of [clone, join(clone, 'src')]) {
      const r = await audit(['--dir', target], { cwd });
      expect(r.code, cwd).toBe(EXIT_UNSAFE_FOLDER);
      expect(r.err).toContain('.npmrc');
      expect(r.calls).toEqual([]);
    }
    // a local pipegen in the clone (index known, node_modules not committed)
    const bin = repo({ 'node_modules/.bin/pipegen': '#!/bin/sh\n' });
    writeIndex(bin, ['package.json']);
    expect((await audit(['inspect', '--dir', target], { cwd: bin })).code).toBe(EXIT_UNSAFE_FOLDER);
    // no git: npm's project folder is the nearest one with a package.json or a node_modules, and its .npmrc is read
    const plain = makeTempDir();
    writeIn(plain, 'package.json', '{}');
    writeIn(plain, '.npmrc', UNSAFE_NPMRC);
    writeIn(plain, 'deep/er/x.txt', '\n');
    const deep = await audit(['--dir', target], { cwd: join(plain, 'deep/er') });
    expect(deep.code).toBe(EXIT_UNSAFE_FOLDER);
    expect(deep.err).toContain(plain);
    // a clean start folder: the audit runs
    expect((await audit(['--dir', target], { cwd: makeTempDir() })).code).toBe(0);
    expect((await audit(['--dir', target], { cwd: repo() })).code).toBe(0);
  });

  it('npm\'s project folder above a nested .git is checked too; node_modules/.bin/pipegen in any folder up the way', async () => {
    const target = repo();
    // a nested .git (a folder, or a file as in a submodule) under a parent with package.json and a hostile .npmrc
    for (const nested of ['folder', 'file'] as const) {
      const r = makeTempDir();
      writeIn(r, 'package.json', '{}');
      writeIn(r, '.npmrc', 'node-options=--require=./x.js\n');
      if (nested === 'folder') writeIn(r, 'sub/.git/config', '[core]\n');
      else writeIn(r, 'sub/.git', 'gitdir: ../.git/modules/sub\n');
      const res = await audit(['--dir', target], { cwd: join(r, 'sub') });
      expect(res.code, nested).toBe(EXIT_UNSAFE_FOLDER);
      expect(res.err.replace(/\s+/g, ' ')).toContain(`in .. (${r})`); // N2: the folder, start-relative, with its path
      expect(res.calls).toEqual([]);
    }
    // no .git at all, package.json two levels up
    const p2 = makeTempDir();
    writeIn(p2, 'package.json', '{}');
    writeIn(p2, '.npmrc', 'script-shell=./x.sh\n');
    writeIn(p2, 'a/b/x.txt', '\n');
    const two = await audit(['--dir', target], { cwd: join(p2, 'a/b') });
    expect(two.code).toBe(EXIT_UNSAFE_FOLDER);
    expect(two.err.replace(/\s+/g, ' ')).toContain(`in ../.. (${p2})`);
    // a local pipegen above npm's project folder: still a stop
    const q = makeTempDir();
    writeIn(q, 'node_modules/.bin/pipegen', '#!/bin/sh\n');
    writeIn(q, 'proj/package.json', '{}');
    writeIn(q, 'proj/.git/config', '[core]\n');
    expect((await audit(['--dir', target], { cwd: join(q, 'proj') })).code).toBe(EXIT_UNSAFE_FOLDER);
    // a hostile .npmrc above both the repo top and npm's project folder: npm doesn't read it, no stop
    const above = makeTempDir();
    writeIn(above, '.npmrc', UNSAFE_NPMRC);
    writeIn(above, 'proj/package.json', '{}');
    writeIn(above, 'proj/.git/config', '[core]\n');
    expect((await audit(['--dir', target], { cwd: join(above, 'proj') })).code).toBe(0);
  });

  it('a committed node_modules under a look-alike name a file system could fold (ſ, fullwidth, an invisible character) → exit 4', async () => {
    expect(foldName('node_module\u017f')).toBe('node_modules');
    for (const entry of ['node_module\u017f/x.js', '\uff4e\uff4f\uff44\uff45_\uff4d\uff4f\uff44\uff55\uff4c\uff45\uff53/y/package.json', 'node\u200b_modules/z.js']) {
      const dir = repo();
      writeIndex(dir, ['index.js', entry, 'package.json']);
      const r = await audit([], { cwd: dir });
      expect(r.code, entry).toBe(EXIT_UNSAFE_FOLDER);
      expect(r.err).toContain('a committed node_modules folder');
    }
    // a name no file system folds to node_modules (a Cyrillic letter) is a different folder
    const other = repo();
    writeIndex(other, ['index.js', 'node_modul\u0435s/x.js', 'package.json']);
    expect((await audit([], { cwd: other })).code).toBe(0);
  });

  it('the home folder and the folders above it are never checked (~/.npmrc is the user\'s own npm config)', async () => {
    const target = repo();
    const home = makeTempDir();
    writeIn(home, '.npmrc', UNSAFE_NPMRC);
    writeIn(home, 'work/x.txt', '\n');
    const before = process.env.HOME;
    process.env.HOME = home;
    try {
      expect((await audit(['--dir', target], { cwd: home })).code).toBe(0);
      expect((await audit(['--dir', target], { cwd: join(home, 'work') })).code).toBe(0);
      // a folder below home that is npm's project folder still counts
      writeIn(home, 'work/.npmrc', UNSAFE_NPMRC);
      writeIn(home, 'work/package.json', '{}');
      expect((await audit(['--dir', target], { cwd: join(home, 'work') })).code).toBe(EXIT_UNSAFE_FOLDER);
    } finally {
      process.env.HOME = before;
    }
  });

  it('swapRisk: a symlinked current folder is read by its real path; a worktree\'s .git file is named in the answer', async () => {
    const dir = repo({ 'sub/.npmrc': UNSAFE_NPMRC, 'sub/package.json': '{}' });
    const link = join(makeTempDir(), 'into-sub');
    symlinkSync(join(dir, 'sub'), link);
    expect(await swapRiskWhy(link, dir)).toContain('in sub');
    const linkToRepo = join(makeTempDir(), 'repo-link');
    symlinkSync(dir, linkToRepo);
    expect(await swapRisk(join(linkToRepo, 'sub'), dir)).toBe(true);
    expect(await swapRisk(join(linkToRepo, 'sub'), linkToRepo)).toBe(true);
    // a git worktree or submodule (.git is a file): no index pipegen can read, and the answer says why
    const wt = makeTempDir();
    writeIn(wt, '.git', 'gitdir: /elsewhere/.git/worktrees/wt\n');
    writeIn(wt, 'node_modules/a/index.js', '\n');
    expect(await swapRiskWhy(wt, wt)).toContain('a git worktree or submodule');
  });

  it('worktree → index read, local node_modules not committed → no stop', async () => {
    const { wt } = gitWorktree({});
    writeIn(wt, 'node_modules/a/index.js', '\n');
    expect(await swapRiskWhy(wt, wt)).toBeNull();
  });

  it('worktree with a committed node_modules → stop', async () => {
    const { wt } = gitWorktree({ 'node_modules/left-pad/index.js': 'module.exports = 1;\n' });
    expect(await swapRiskWhy(wt, wt)).toContain('a committed node_modules folder');
  });

  it('stop comes before the --ai checks (no Ollama call)', async () => {
    const dir = repo({ '.npmrc': UNSAFE_NPMRC });
    const r = await audit(['--ai', 'ollama', '--model', 'llama3'], { cwd: dir, env: { OLLAMA_HOST: 'http://127.0.0.1:11434' } });
    expect(r.code).toBe(EXIT_UNSAFE_FOLDER);
    expect(r.calls).toEqual([]);
    expect(makeProvider).not.toHaveBeenCalled();
    expect(globalFetch).not.toHaveBeenCalled();
  });
});

describe('npx pipegen: no command, --help, --type, --verbose and the type question (J5, #124, B1, S9, S10)', () => {
  it('no command → audit of .', async () => {
    const dir = repo();
    const r = await audit([], { cwd: dir });
    expect(r.code).toBe(0);
    expect(r.out).toContain('pipegen audit: o/r');
    expect(vi.mocked(buildAudit).mock.calls[0]?.[0]).toBe(dir);
    // options without a command are the audit's
    const json = await audit(['--json'], { cwd: dir });
    expect((JSON.parse(json.out) as { profile: { repo: string } }).profile.repo).toBe('r');
  });

  it('--help → usage', async () => {
    for (const argv of [['--help'], ['-h'], ['audit', '--help'], ['inspect', '--help']]) {
      vi.mocked(buildAudit).mockClear();
      const r = await audit(argv, { cwd: repo({ '.npmrc': UNSAFE_NPMRC }) }); // --help reads nothing, so it never stops
      expect(r.code, argv.join(' ')).toBe(0);
      expect(r.out).toContain('Usage: pipegen');
      expect(r.out).toContain('npx pipegen');
      expect(r.out).toContain(RUN_COMMAND);
      expect(r.calls).toEqual([]);
      expect(buildAudit).not.toHaveBeenCalled();
    }
  });

  it('--type static-site on a two-service repo → error naming --type <service>=<type>', async () => {
    const dir = twoServices();
    const r = await audit(['--type', 'static-site'], { cwd: dir, interactive: true, prompt: noPrompt() });
    expect(r.code).toBe(1);
    expect(r.err).toContain('--type <service>=<type>');
    expect(r.err).toContain('web');
    expect(r.err).toContain('api');
    expect(r.calls).toEqual([]);
    expect(buildAudit).not.toHaveBeenCalled();
    // an unknown type is refused before anything is read
    const unknown = await audit(['--type', 'web=website'], { cwd: dir });
    expect(unknown.code).toBe(1);
    expect(unknown.err).toContain('static-site, library, cli, server, container');
    expect(unknown.calls).toEqual([]);
    // an unknown service name too, after the local read and before GitHub
    const noSuch = await audit(['--type', 'nope=server'], { cwd: dir });
    expect(noSuch.code).toBe(1);
    expect(noSuch.err).toContain('No service is named nope');
    expect(noSuch.calls).toEqual([]);
  });

  it('--type a=static-site --type b=server accepted; the same service twice refused', async () => {
    const dir = twoServices();
    const ok = await audit(['--type', 'web=static-site', '--type', 'api=server'], { cwd: dir, interactive: true, prompt: noPrompt() });
    expect(ok.code).toBe(0);
    expect(vi.mocked(buildAudit).mock.calls[0]?.[1].typeOverrides).toEqual([{ service: 'web', type: 'static-site' }, { service: 'api', type: 'server' }]);
    const web = profileOf(0).services.find((s) => s.name === 'web');
    expect(web?.projectType).toMatchObject({ types: ['static-site'], overridden: true });
    for (const argv of [['--type', 'web=server', '--type', 'web=cli'], ['audit', '--type', 'api=cli', '--type', 'api=cli']]) {
      vi.mocked(buildAudit).mockClear();
      const twice = await audit(argv, { cwd: dir });
      expect(twice.code, argv.join(' ')).toBe(1);
      expect(twice.err).toContain('was given a type twice');
      expect(twice.calls).toEqual([]);
      expect(buildAudit).not.toHaveBeenCalled();
    }
    const single = await audit(['--type', 'server', '--type', 'cli'], { cwd: repo() });
    expect(single.code).toBe(1);
    expect(single.err).toContain('was given a type twice');
    // --type and --verbose are audit options
    for (const argv of [['inspect', '--type', 'server'], ['inspect', '--verbose']]) {
      const r = await audit(argv, { cwd: dir });
      expect(r.code, argv.join(' ')).toBe(1);
      expect(r.err).toMatch(/^--(type|verbose) works with pipegen audit (and pipegen run )?only\./);
    }
  });

  it('non-TTY → no prompt, report shows types', async () => {
    const dir = twoServices();
    const prompt = noPrompt();
    const r = await audit([], { cwd: dir, prompt }); // CliIO.interactive unset: not a terminal (S9)
    expect(r.code).toBe(0);
    expect(prompt.confirm).not.toHaveBeenCalled();
    expect(prompt.select).not.toHaveBeenCalled();
    expect(vi.mocked(buildAudit).mock.calls[0]?.[1].typeOverrides ?? []).toEqual([]);
    // the report gets the detected types (J4 prints them as the Type lines)
    const services = profileOf(0).services;
    expect(services.find((s) => s.name === 'web')?.projectType).toMatchObject({ types: ['static-site'], unsure: false });
    expect(services.find((s) => s.name === 'api')?.projectType?.types).toContain('server');
    for (const s of services) expect(s.projectType?.overridden).toBeUndefined();
    const off = await audit([], { cwd: dir, prompt, interactive: false });
    expect(off.code).toBe(0);
    expect(prompt.confirm).not.toHaveBeenCalled();
  });

  it('--json → no prompt', async () => {
    const dir = twoServices();
    const prompt = noPrompt();
    const r = await audit(['--json'], { cwd: dir, prompt, interactive: true });
    expect(r.code).toBe(0);
    expect(prompt.confirm).not.toHaveBeenCalled();
    const j = JSON.parse(r.out) as { profile: { services: { name: string; projectType: { types: string[] } }[] } };
    expect(j.profile.services.find((s) => s.name === 'web')?.projectType.types).toEqual(['static-site']);
  });

  it('user says No and picks server → overrides applied, report says "set by you"', async () => {
    // a second static shape (a Vite single-page app): the same question and override
    const spa = viteSpa();
    const spaAsk = typePrompter(false, ['server']);
    expect((await audit([], { cwd: spa, prompt: spaAsk.p, interactive: true })).code).toBe(0);
    expect(spaAsk.asked[0]?.msg).toContain('spa: static-site');
    expect(profileOf(0).services[0]?.projectType?.evidence).toContain('set to server by you');
    vi.mocked(buildAudit).mockClear();
    vi.mocked(renderTerminal).mockClear();
    const dir = staticSite();
    const f = fakeFetch(publicRoutes());
    const ask = typePrompter(false, ['server'], () => f.calls.length);
    const r = await audit([], { cwd: dir, fake: f, prompt: ask.p, interactive: true });
    expect(r.code).toBe(0);
    expect(ask.asked).toHaveLength(2);
    expect(ask.asked[0]?.msg).toContain('site: static-site');
    expect(ask.asked[0]?.msg).toContain('Is this right? (Y/n)');
    expect(ask.asked[1]?.msg).toContain('site');
    for (const q of ask.asked) expect(q.githubCalls).toBe(0); // B1: asked after the local read, before any GitHub call
    expect(vi.mocked(buildAudit).mock.calls[0]?.[1].typeOverrides).toEqual([{ service: 'site', type: 'server' }]);
    const t = profileOf(0).services[0]?.projectType;
    expect(t).toMatchObject({ types: ['server'], overridden: true, unsure: false });
    expect(t?.evidence).toContain('set to server by you');
    // yes keeps the detected type
    vi.mocked(buildAudit).mockClear();
    vi.mocked(renderTerminal).mockClear();
    const yes = typePrompter(true);
    expect((await audit([], { cwd: dir, prompt: yes.p, interactive: true })).code).toBe(0);
    expect(vi.mocked(buildAudit).mock.calls[0]?.[1].typeOverrides).toEqual([]);
    expect(profileOf(0).services[0]?.projectType).toMatchObject({ types: ['static-site'] });
    // --type skips the question
    const skip = noPrompt();
    expect((await audit(['--type', 'server'], { cwd: dir, prompt: skip, interactive: true })).code).toBe(0);
    expect(skip.confirm).not.toHaveBeenCalled();
  });

  it('the type override also reaches the local-only report (GitHub not read)', async () => {
    const dir = staticSite();
    const r = await audit(['--json', '--type', 'server'], { cwd: dir, routes: publicRoutes({ [`GET ${R}`]: err(404, 'Not Found') }) });
    expect(r.code).toBe(1);
    const j = JSON.parse(r.out) as { github: string; profile: { services: { projectType: { types: string[]; evidence: string[] } }[] } };
    expect(j.github).toBe('not read');
    expect(j.profile.services[0]?.projectType.types).toEqual(['server']);
    expect(j.profile.services[0]?.projectType.evidence).toContain('set to server by you');
  });

  it('type cancel → exit 0, no GitHub call, no report', async () => {
    const dir = staticSite();
    // Esc at "Is this right?", or No and then Esc at the select
    for (const cancel of [typePrompter(new PromptCancelledError()), typePrompter(false, [new PromptCancelledError()])]) {
      vi.mocked(buildAudit).mockClear();
      const outFile = join(makeTempDir(), 'r.md');
      const r = await audit(['--out', outFile], { cwd: dir, prompt: cancel.p, interactive: true });
      expect(existsSync(outFile)).toBe(false);
      expect(r.code).toBe(0);
      expect(r.calls).toEqual([]);
      expect(r.out).toBe('');
      expect(r.err).toContain('nothing was read from GitHub');
      expect(buildAudit).not.toHaveBeenCalled();
      expect(renderTerminal).not.toHaveBeenCalled();
    }
  });

  it('--verbose reaches renderTerminal\'s options (the short report is J4\'s)', async () => {
    const dir = repo();
    expect((await audit(['--verbose'], { cwd: dir })).code).toBe(0);
    expect(vi.mocked(renderTerminal).mock.calls[0]?.[1]).toMatchObject({ verbose: true });
    vi.mocked(renderTerminal).mockClear();
    expect((await audit(['audit'], { cwd: dir })).code).toBe(0);
    expect(vi.mocked(renderTerminal).mock.calls[0]?.[1]).toMatchObject({ verbose: false });
    expect((await audit(['--verbose', '--verbose'], { cwd: dir })).code).toBe(1);
  });
});

/** A real `git worktree add` checkout (test-only child process) of a one-commit repo holding `files` plus package.json. */
function gitWorktree(files: Record<string, string>): { main: string; wt: string } {
  const env = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', HOME: '/nonexistent' };
  const git = (cwd: string, ...args: string[]) => childProcess.execFileSync('git', args, { cwd, stdio: 'pipe', env });
  const main = makeTempDir();
  git(main, 'init', '-q');
  for (const [f, body] of Object.entries({ 'package.json': '{}\n', ...files })) writeIn(main, f, body);
  git(main, 'add', '-f', '--', '.');
  git(main, '-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '--no-verify', '-m', 'init');
  const wt = join(makeTempDir(), 'wt');
  git(main, 'worktree', 'add', '-q', wt);
  return { main, wt };
}

