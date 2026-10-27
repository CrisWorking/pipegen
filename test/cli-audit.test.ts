// Plan U Task 4b: `pipegen audit`. The brief's cli tests, adapted to the rulings (B1, B3, S15, S18, S19, S21-S23,
// S30, U10, U18, R10), plus one test per checklist item. Every network call is a fake fetch (CliIO.fetch), the AI is a
// fake provider, gitleaks is the shared stub, and no test starts git or any other process of its own (the child
// process spy would see it). Secret-like strings are built at runtime.
import * as childProcess from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as execa from 'execa';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { makeProvider } from '../src/ai/provider.js';
import { addAiSuggestions, buildAudit, safeRunCommand } from '../src/audit/model.js';
import { run } from '../src/cli/main.js';
import type { CliIO, Prompter } from '../src/cli/io.js';
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

const hooks = vi.hoisted(() => ({ ai: null as AiProvider | null, gitleaks: null as string | null }));

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
// No download: the pinned gitleaks is the stub when a test sets one, else refused.
vi.mock('../src/engine/linters.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/engine/linters.js')>();
  return { ...a, ensurePinnedBinary: vi.fn(async () => { if (hooks.gitleaks === null) throw new a.PinnedBinaryError('No download in tests.'); return hooks.gitleaks; }) };
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
vi.mock('../src/engine/github-rate.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../src/engine/github-rate.js')>();
  return { ...a, withRateLimit: vi.fn(a.withRateLimit) };
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

interface RunOpts { cwd: string; routes?: Routes; env?: NodeJS.ProcessEnv; prompt?: Prompter }
async function audit(argv: string[], o: RunOpts) {
  const f = fakeFetch(o.routes ?? publicRoutes());
  const lines: string[] = [];
  const errs: string[] = [];
  const prompt = o.prompt ?? prompter(false);
  const io: CliIO = { prompt, out: (s) => { lines.push(s); }, err: (s) => { errs.push(s); }, env: o.env ?? {}, cwd: o.cwd, fetch: f.fetch };
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
      const add = [{ id: 'type-check', layer: 'push', category: 'lint', service, why: 'Types catch mistakes.', blocking: false }];
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
  hooks.gitleaks = null;
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

/** --ai with a fake Claude and the gitleaks stub; the env carries the Anthropic key. */
function aiSetup(why?: string, service?: string) {
  const ai = fakeAi(why, service);
  hooks.ai = ai.p;
  const stub = makeStub(CLEAN);
  hooks.gitleaks = stub.bin;
  return { ai, stub, env: { [ANTHROPIC_VAR]: anthropicVal } as NodeJS.ProcessEnv };
}

// ---------- the brief ----------

describe('pipegen audit (brief)', () => {
  it('cli: audit prints report, exit 0, makes no write calls (only GET), report on stdout', async () => {
    const dir = repo();
    const r = await audit(['audit'], { cwd: dir });
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
    const r = await audit(['audit', '--dir', dir, '--out', 'report.md'], { cwd: work });
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
    const r = await audit(['audit', '--json'], { cwd: dir });
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out) as Record<string, unknown> & { profile: { owner: string; repo: string }; coverage: unknown[]; warnings: { text: string }[] };
    expect(j.profile).toMatchObject({ owner: 'o', repo: 'r', private: false });
    expect(Array.isArray(j.coverage)).toBe(true);
    for (const k of ['support', 'wouldAdd', 'estimates', 'permissions', 'limits', 'secretsInTree', 'aiBundle', 'notes', 'reviewedUnavailable']) expect(j).toHaveProperty(k);
    expect(j.permissions).toEqual(permissionsTable('write', { appCreatesRepos: false })); // what the full run would need (B1)
  });

  it('cli: private repo without auth → fine-grained read-only instructions, no gh auth login (S22)', async () => {
    const dir = repo();
    const r = await audit(['audit'], { cwd: dir, routes: publicRoutes({ [`GET ${R}`]: err(404, 'Not Found') }) });
    expect(r.code).toBe(1);
    expect(r.err).toContain("pipegen can't see o/r: it's private or doesn't exist. If it's private, pipegen needs read access to o/r.");
    expect(r.err).toContain('fine-grained token for this one repo');
    for (const row of permissionsTable('read')) expect(r.err).toContain(row.permission);
    expect(r.err).toContain('GitHub App');
    expect(r.err).toContain('pipegen refuses broad classic tokens');
    expect(r.all).not.toMatch(/gh auth login/);
    // with a token that can't see the repo: the same read-only steps
    const withTok = await audit(['audit'], { cwd: dir, env: { [GH_VAR]: fake.githubPat() }, routes: privateRoutes({ [`GET ${R}`]: err(404, 'Not Found') }) });
    expect(withTok.code).toBe(1);
    expect(withTok.err).toContain('pipegen needs read access to o/r. Create a fine-grained token for this one repo');
    expect(withTok.all).not.toMatch(/gh auth login/);
    expect(withTok.all).not.toContain(fake.githubPat());
  });

  it('cli: --ai asks consent first; declined → report without suggestions (no gitleaks, no AI call)', async () => {
    const dir = repo();
    const { ai, env } = aiSetup();
    const ask = prompter(false);
    const r = await audit(['audit', '--ai'], { cwd: dir, env, prompt: ask });
    expect(r.code).toBe(0);
    expect(ask.asked).toHaveLength(1);
    expect(ask.asked[0]).toContain('pipegen audit --ai is about to send part of your code to an AI. Nothing has left this computer yet.');
    expect(ai.complete).not.toHaveBeenCalled();
    expect(ensurePinnedBinary).not.toHaveBeenCalled(); // no gitleaks download without a yes
    expect(addAiSuggestions).not.toHaveBeenCalled();
    expect(r.out).toContain('Nothing was sent to an AI.');
    expect(r.out).not.toContain('What the AI suggests');
    expect(r.err).toContain('You said no: nothing was sent to an AI.');
  });

  it('cli: --ai accepted → suggestions shown, consent had no repo lines and read-only permissions', async () => {
    const dir = repo();
    const { ai, env } = aiSetup();
    const ask = prompter(true);
    const r = await audit(['audit', '--ai'], { cwd: dir, env, prompt: ask });
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
    expect(screen).toMatch(/pipegen sends at most \d+ files? /); // counted before gitleaks (S21)
    expect(screen).toContain('gitleaks 8.30.1, which pipegen downloads (checksum-verified) into its cache');
  });

  it('cli: --dir reads the given folder; default is the current folder', async () => {
    const here = repo();
    const other = repo({ 'package.json': JSON.stringify({ name: 'other-app' }) }, 'https://github.com/o/r2.git');
    const R2 = `${API}/repos/o/r2`;
    const routes = publicRoutes({
      [`GET ${R2}`]: { body: { private: false, default_branch: 'main', owner: { type: 'User', login: 'o' } } },
      [`GET ${R2}/rulesets`]: { body: [] }, [`GET ${R2}/events`]: { body: [] }, [`GET ${R2}/pulls`]: { body: [] },
    });
    const dflt = await audit(['audit', '--json'], { cwd: here, routes });
    expect((JSON.parse(dflt.out) as { profile: { repo: string } }).profile.repo).toBe('r');
    const given = await audit(['audit', '--json', '--dir', other], { cwd: here, routes });
    expect((JSON.parse(given.out) as { profile: { repo: string } }).profile.repo).toBe('r2');
    // a relative --dir is read from the current folder
    const work = makeTempDir();
    const rel = await audit(['audit', '--json', '--dir', join('..', other.split('/').pop() as string)], { cwd: resolve(work), routes });
    expect((JSON.parse(rel.out) as { profile: { repo: string } }).profile.repo).toBe('r2');
  });

  it('cli: --help shows the outside-the-repo command with --registry and an exact version (S30, U18)', async () => {
    const r = await audit(['--help'], { cwd: makeTempDir() });
    expect(r.code).toBe(0);
    expect(r.out).toContain(RUN_COMMAND);
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(r.out).toMatch(/OUTSIDE the repo/);
    for (const flag of ['--dir', '--out', '--force', '--json', '--ai', '--model', '--effort', '--allow-broad-token']) expect(r.out).toContain(flag);
    expect(r.out).toContain('Linux or macOS (WSL works)');
    // no runnable command without the exact version and the registry (ruling U18)
    for (const m of r.out.matchAll(/npx[^\n]*/g)) expect(m[0]).toContain(`--registry=https://registry.npmjs.org pipegen@${VERSION} `);
    expect(r.out).not.toMatch(/npx pipegen/);
    expect(r.out).not.toContain('x.y.z');
  });

  it('cli: no token on a public repo → anonymous Octokit, no-token note, exit 0', async () => {
    const dir = repo();
    const r = await audit(['audit'], { cwd: dir });
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
    const json = await audit(['audit', '--dir', dir, '--json', '--ai', '--out', 'r.md'], { cwd: work, env, routes, prompt: ask });
    expect(json.code).toBe(0);
    const term = await audit(['audit', '--dir', dir], { cwd: work, env, routes });
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
    const r = await audit(['audit', '--out', join(makeTempDir(), 'x.md')], { cwd: dir });
    expect(r.code).toBe(0);
    expect(childCalls()).toEqual([]);
    expect(execaCalls()).toEqual([]);
    expect(ensurePinnedBinary).not.toHaveBeenCalled();
  });

  it('cli: audit --ai starts only the pinned gitleaks binary, right after the yes', async () => {
    const dir = repo();
    const { stub, env } = aiSetup();
    const ask = prompter(true);
    vi.clearAllMocks();
    const r = await audit(['audit', '--ai'], { cwd: dir, env, prompt: ask });
    expect(r.code).toBe(0);
    const calls = childCalls();
    expect(calls.length).toBeGreaterThan(0);
    for (const c of calls) {
      expect(c.fn).toBe('execFile');
      expect(c.args[0]).toBe(stub.bin);
    }
    expect(execaCalls()).toEqual([]);
    expect(ensurePinnedBinary).toHaveBeenCalledTimes(1);
    expect(ensurePinnedBinary).toHaveBeenCalledWith('gitleaks');
    // the download happens after the consent question, never before (S21, B4)
    const asked = vi.mocked(ask.confirm).mock.invocationCallOrder[0] as number;
    expect(vi.mocked(ensurePinnedBinary).mock.invocationCallOrder[0]).toBeGreaterThan(asked);
  });
});

// ---------- the checklist ----------

describe('pipegen audit (flags and help)', () => {
  it('flags: an unknown flag is exit 1 with a cleaned message; audit takes no positional arguments', async () => {
    const cwd = makeTempDir();
    const bad = await audit(['audit', '--evil\u001b[31m\u202e'], { cwd });
    expect(bad.code).toBe(1);
    expect(bad.err).toMatch(/Unknown option/);
    expect(bad.all).not.toMatch(UNSAFE);
    const extra = await audit(['audit', 'stray'], { cwd });
    expect(extra.code).toBe(1);
    expect(extra.err).toContain('pipegen audit takes no arguments');
    const unknownAi = await audit(['audit', '--ai=gemini'], { cwd });
    expect(unknownAi.code).toBe(1);
    expect(unknownAi.err).toContain('Unknown --ai value "gemini". Use claude, openai or ollama.');
    const modelOnly = await audit(['audit', '--model', 'x'], { cwd });
    expect(modelOnly.code).toBe(1);
    expect(modelOnly.err).toContain('--model and --effort only work with --ai.');
    const inspectOut = await audit(['inspect', '--out', 'x.md'], { cwd });
    expect(inspectOut.code).toBe(1);
    expect(inspectOut.err).toContain('--out works with pipegen audit only.');
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

  it('README: the exact-version outside-the-repo command, no bare npx pipegen, and audit --ai needs Linux or macOS (U18, S21, S30)', () => {
    const readme = readFileSync(resolve(import.meta.dirname, '../README.md'), 'utf8');
    expect(readme).toContain(RUN_COMMAND.replace('./repo', './my-repo'));
    const npx = [...readme.matchAll(/npx[^\n`]*/g)].map((m) => m[0]);
    expect(npx.length).toBeGreaterThan(0);
    for (const line of npx) expect(line, line).toMatch(new RegExp(`^npx --registry=https://registry\\.npmjs\\.org pipegen@${VERSION.replace(/\./g, '\\.')} audit `));
    expect(readme).toContain('`audit --ai` needs Linux or macOS for now (WSL works)');
  });
});

describe('pipegen audit (auth and GitHub, ruling B1)', () => {
  it('access, S18: the run uses ONE rate budget for every GitHub call, buildAudit, addAiSuggestions and fetchStats (S18)', async () => {
    const dir = repo();
    const { env } = aiSetup();
    const r = await audit(['audit', '--ai'], { cwd: dir, env, prompt: prompter(true) });
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
    const anon = await audit(['audit'], { cwd: dir });
    expect(anon.calls.some((c) => c.url.pathname === '/user')).toBe(false);
    const withTok = await audit(['audit', '--json'], { cwd: dir, env: { [GH_VAR]: fake.githubPat() }, routes: privateRoutes() });
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
    const refused = await audit(['audit'], { cwd: dir, env, routes: privateRoutes() });
    expect(refused.code).toBe(1);
    expect(refused.err).toContain("pipegen won't use this token");
    expect(refused.err).toContain('it is a classic token, which reaches every repo you have');
    expect(refused.err).toContain('--allow-broad-token');
    expect(refused.all).not.toContain(fake.githubClassic());
    const allowed = await audit(['audit', '--allow-broad-token'], { cwd: dir, env, routes: privateRoutes() });
    expect(allowed.code).toBe(0);
    expect(allowed.all).not.toContain(fake.githubClassic());
  });

  it('access, S21: not a GitHub repo → a friendly message, exit 1 (S21)', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', '{}');
    const r = await audit(['audit'], { cwd: dir });
    expect(r.code).toBe(1);
    expect(r.err).toContain('pipegen audit needs a clone of a GitHub repository');
    expect(r.err).toContain('--dir');
    expect(r.out).toBe('');
  });

  it('access, R10: GitHub can\'t be read (no answer, 5xx) → only the local parts, "GitHub: not read", exit 1 (R10); no guessed GitHub facts', async () => {
    const dir = repo({ 'config/dev.json': JSON.stringify({ id: fake.awsKey() }), '.github/workflows/ci.yml': 'on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n' });
    const down = publicRoutes({ [`GET ${R}`]: err(503, 'Service Unavailable') });
    const r = await audit(['audit'], { cwd: dir, routes: down });
    expect(r.code).toBe(1);
    expect(r.out).toContain('pipegen audit: o/r');
    expect(r.out).toContain('GitHub: not read (the error is on stderr).');
    expect(r.out).toContain('Secret-like text in the files on disk now');
    expect(r.out).toContain('.github/workflows/ci.yml');
    expect(r.out).toContain('What the full setup would send to the AI');
    expect(r.out).not.toMatch(/Verdict|Checks by layer|What your GitHub plan allows|Costs of the full setup|Permissions the full setup needs/);
    expect(r.err).toContain("GitHub: not read: pipegen couldn't reach https://api.github.com to check o/r (HTTP 503");
    // --json: the local parts as JSON, github "not read"
    const j = await audit(['audit', '--json'], { cwd: dir, routes: down });
    expect(j.code).toBe(1);
    expect(JSON.parse(j.out)).toMatchObject({ github: 'not read', profile: { owner: 'o', repo: 'r' } });
    // --out: no half report is written
    const work = makeTempDir();
    const o = await audit(['audit', '--dir', dir, '--out', 'r.md'], { cwd: work, routes: down });
    expect(o.code).toBe(1);
    expect(existsSync(join(work, 'r.md'))).toBe(false);
    expect(o.err).toContain('No report file was written: GitHub could not be read.');
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
  const r = await audit(['audit', '--json'], { cwd: dir });
  expect(r.code).toBe(0);
  const j = JSON.parse(r.out) as { warnings: { text: string }[]; reviewedUnavailable: boolean; wouldAdd: { note: string; tool: unknown }[] };
  expect(j.warnings[0]?.text).toBe(`${B3_PREFIX}${msg.replace(/\.$/, '')}${B3_SUFFIX}`); // one full stop
  expect(j.reviewedUnavailable).toBe(true);
  expect(j.wouldAdd.some((w) => w.note === "pipegen's reviewed tool list couldn't be loaded, so it has no tool to add here")).toBe(true);
  expect(j.wouldAdd.every((w) => w.tool === null || (w.tool as { kind: string }).kind !== 'reviewed')).toBe(true);
  expect(vi.mocked(buildAudit).mock.calls[0]?.[1]).toMatchObject({ reviewed: [], reviewedUnavailable: true });
  const t = await audit(['audit'], { cwd: dir });
  expect(t.code).toBe(0);
  const warnAt = t.out.indexOf('⚠ Warnings');
  expect(t.out.indexOf(B3_PREFIX)).toBeGreaterThan(warnAt);
  expect(t.out.indexOf(B3_PREFIX)).toBeLessThan(t.out.indexOf('What your GitHub plan allows'));
}

describe('pipegen audit --ai (checks before consent)', () => {
  it('platform: an unsupported platform stops --ai before consent (S21)', async () => {
    const dir = repo();
    const { ai, env } = aiSetup();
    const ask = prompter(true);
    const desc = Object.getOwnPropertyDescriptor(process, 'platform') as PropertyDescriptor;
    Object.defineProperty(process, 'platform', { ...desc, value: 'win32' });
    let r: Awaited<ReturnType<typeof audit>>;
    try {
      r = await audit(['audit', '--ai'], { cwd: dir, env, prompt: ask });
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
    const r = await audit(['audit', '--ai'], { cwd: dir, env: {}, prompt: ask });
    expect(r.code).toBe(1);
    expect(r.err).toBe(S15);
    expect(ask.asked).toEqual([]);
    const openai = await audit(['audit', '--ai', 'openai'], { cwd: dir, env: { [OPENAI_VAR]: 'x'.repeat(20) }, prompt: ask });
    expect(openai.code).toBe(1);
    expect(openai.err).toContain('needs a model: pass --model');
  });

  it('unpriced: a model with no price stops before consent with the estimate\'s message (U14)', async () => {
    const dir = repo();
    const ask = prompter(true);
    const r = await audit(['audit', '--ai', 'openai', '--model', 'gpt-5-pro'], { cwd: dir, env: { [OPENAI_VAR]: 'x'.repeat(20) }, prompt: ask });
    expect(r.code).toBe(1);
    expect(r.err).toContain("pipegen doesn't know the price of gpt-5-pro, so it can't keep a hard cost limit. Choose one of: gpt-5, gpt-5-mini, gpt-5.5.");
    expect(ask.asked).toEqual([]);
    expect(addAiSuggestions).not.toHaveBeenCalled();
  });

  it('ollama: OLLAMA_HOST on ollama.com, a cloud model behind a local name, or no answer → refused before consent (fail closed)', async () => {
    const dir = repo();
    const ask = prompter(false);
    const show = (reply: Reply): Routes => publicRoutes({ 'POST http://127.0.0.1:11434/api/show': reply });
    const cloudHost = await audit(['audit', '--ai', 'ollama'], { cwd: dir, env: { OLLAMA_HOST: 'https://ollama.com' }, prompt: ask });
    expect(cloudHost.code).toBe(1);
    expect(cloudHost.err).toContain('OLLAMA_HOST points at ollama.com');
    expect(cloudHost.calls).toEqual([]);
    const sub = await audit(['audit', '--ai', 'ollama'], { cwd: dir, env: { OLLAMA_HOST: 'api.OLLAMA.com:443' }, prompt: ask });
    expect(sub.code).toBe(1);
    const remote = await audit(['audit', '--ai', 'ollama', '--model', 'llama3.1'], { cwd: dir, env: {}, prompt: ask, routes: show({ body: { remote_host: 'https://ollama.com:443', remote_model: 'gpt-oss:120b', details: {} } }) });
    expect(remote.code).toBe(1);
    expect(remote.err).toContain('Ollama cloud models send your code to ollama.com');
    const down = await audit(['audit', '--ai', 'ollama'], { cwd: dir, env: {}, prompt: ask, routes: show({ status: 500, body: {} }) });
    expect(down.code).toBe(1);
    expect(down.err).toContain('pipegen couldn\'t confirm that the Ollama model "llama3.1" runs on 127.0.0.1:11434');
    const notJson = await audit(['audit', '--ai', 'ollama'], { cwd: dir, env: {}, prompt: ask, routes: show({ raw: 'not json' }) });
    expect(notJson.code).toBe(1);
    expect(ask.asked).toEqual([]);
    // a model that runs on that server: the consent screen is shown (and answered No here)
    const ok = await audit(['audit', '--ai', 'ollama'], { cwd: dir, env: {}, prompt: ask, routes: show({ body: { details: { family: 'llama' }, model_info: {} } }) });
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
    const r = await audit(['audit', '--ai'], { cwd: dir, env, routes: privateRoutes(), prompt: ask });
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
    const r = await audit(['audit', '--out', 'report.md'], { cwd: dir });
    expect(r.code).toBe(1);
    expect(r.err).toContain("Don't write the report into the repo you're auditing");
    expect(listTree(dir)).toEqual(before);
    // an existing file is refused without --force; --force replaces it
    const work = makeTempDir();
    writeFileSync(join(work, 'old.md'), 'old\n');
    const exists = await audit(['audit', '--dir', dir, '--out', 'old.md'], { cwd: work });
    expect(exists.code).toBe(1);
    expect(exists.err).toMatch(/already exists/);
    expect(readFileSync(join(work, 'old.md'), 'utf8')).toBe('old\n');
    const forced = await audit(['audit', '--dir', dir, '--out', 'old.md', '--force'], { cwd: work });
    expect(forced.code).toBe(0);
    expect(readFileSync(join(work, 'old.md'), 'utf8')).toMatch(/^# pipegen audit/);
  });

  it('out: --json and --out together: JSON on stdout, Markdown in the file, the "written" line on stderr', async () => {
    const dir = repo();
    const work = makeTempDir();
    const r = await audit(['audit', '--dir', dir, '--json', '--out', 'r.md'], { cwd: work });
    expect(r.code).toBe(0);
    expect(() => JSON.parse(r.out) as unknown).not.toThrow();
    expect(readFileSync(join(work, 'r.md'), 'utf8')).toMatch(/^# pipegen audit: o\/r/);
    expect(r.err).toContain('The Markdown report was written to');
  });

  it('safeRunCommand is what --help prints (one source for the command)', () => {
    expect(safeRunCommand(VERSION)).toBe(RUN_COMMAND);
  });
});
