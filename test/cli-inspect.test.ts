// Plan A Task 8: `pipegen inspect` reads the project, the GitHub context and what GitHub allows, and prints a summary.
// No AI call, no consent, nothing written. Every repo-derived string passes safeText; no token is ever printed.
// GitHub is a fake fetch (CliIO.fetch) here, and a fetch stub preloaded into plain `node` for the built bundle
// (ruling R9: the real-repo run is deferred to the v0.1 definition-of-done run; these tests stay offline).
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'tsup';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { tsupOptions } from '../tsup.config.js';
import { run } from '../src/cli/main.js';
import type { CliIO, Prompter } from '../src/cli/io.js';
import { permissionsTable } from '../src/github/client.js';
import { hostileNames } from './fixtures/hostile-names.js';
import { fakeFetch, type Reply, type Routes } from './helpers/fake-http.js';
import { cleanupRepos, makeRepo, makeTempDir, writeIn } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';

const API = 'https://api.github.com';
const R = `${API}/repos/o/r`;
const GH_REMOTE = 'https://github.com/o/r.git';
/** Env var names, kept out of `NAME: value` shapes so the secret-literal check stays quiet. */
const ENV_VAR = 'GITHUB_TOKEN';
const ANTHROPIC_VAR = 'ANTHROPIC_API_KEY';
const OPENAI_VAR = 'OPENAI_API_KEY';
const err = (status: number, message: string): Reply => ({ status, body: { message } });
const UPGRADE = 'Upgrade to GitHub Pro or make this repository public to enable this feature.';
const NOT_ENABLED = 'Code scanning is not enabled for this repository. Please enable code scanning in the repository settings.';
/** Characters safeText removes: C0 (except the newline between lines), DEL, C1, bidi controls. */
const UNSAFE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/;

/** A public repo read without a token. GitHub answers repo reads, and refuses code scanning (that needs a token). */
const publicRoutes = (over: Routes = {}): Routes => ({
  [`GET ${R}`]: { body: { private: false, default_branch: 'trunk', owner: { type: 'User', login: 'o' } } },
  [`GET ${R}/rulesets`]: { body: [] },
  [`GET ${R}/environments`]: { body: { total_count: 0, environments: [] } },
  [`GET ${R}/code-scanning/analyses`]: err(401, 'Requires authentication'),
  ...over,
});
/** A private Free repo read with a fine-grained token whose login is the owner. */
const privateRoutes = (over: Routes = {}): Routes => ({
  [`GET ${API}/user`]: { body: { login: 'o', plan: { name: 'free' } } },
  [`GET ${R}`]: { body: { private: true, default_branch: 'main', owner: { type: 'User', login: 'o' } } },
  [`GET ${R}/rulesets`]: err(403, UPGRADE),
  [`GET ${R}/environments`]: { body: { total_count: 0, environments: [] } },
  [`GET ${R}/code-scanning/analyses`]: err(403, NOT_ENABLED),
  ...over,
});

const noPrompts: Prompter = {
  confirm: async () => { throw new Error('inspect must not ask anything'); },
  select: async () => { throw new Error('inspect must not ask anything'); },
  text: async () => { throw new Error('inspect must not ask anything'); },
};

async function inspect(dir: string, routes: Routes, env: NodeJS.ProcessEnv = {}, argv: string[] = ['inspect']) {
  const f = fakeFetch(routes);
  const lines: string[] = [];
  const errs: string[] = [];
  const io: CliIO = { prompt: noPrompts, out: (s) => { lines.push(s); }, err: (s) => { errs.push(s); }, env, cwd: dir, fetch: f.fetch };
  const code = await run(argv, io);
  const out = lines.join('\n');
  const err = errs.join('\n');
  return { code, out, err, all: `${out}\n${err}`, calls: f.calls };
}

let globalFetch: ReturnType<typeof vi.fn>;
beforeEach(() => {
  // anything not going through CliIO.fetch (an AI SDK, a stray download) would land here
  globalFetch = vi.fn(async () => { throw new Error('unexpected network call'); });
  vi.stubGlobal('fetch', globalFetch);
});
afterEach(() => {
  vi.unstubAllGlobals();
  cleanupRepos();
});

/** node-express plus a workflow, hooks and an env file, so the summary has something in every section. */
function richRepo(): string {
  const dir = makeRepo('node-express', GH_REMOTE);
  writeIn(dir, 'package.json', JSON.stringify({ name: 'express-app', version: '1.0.0', scripts: { start: 'node src/server.js', test: 'jest' }, dependencies: { express: '^4.19.0', pg: '^8.11.0' }, devDependencies: { jest: '^29.0.0' } }));
  writeIn(dir, '.nvmrc', '20\n');
  writeIn(dir, '.env.example', 'DATABASE_URL=\nREDIS_URL=\n');
  writeIn(dir, 'src/db.js', "const { Pool } = require('pg');\nmodule.exports = new Pool({ connectionString: process.env.DATABASE_URL });\n");
  writeIn(dir, 'test/app.test.js', "test('ok', () => {});\n");
  writeIn(dir, '.husky/pre-commit', 'npm test\n');
  writeIn(dir, '.github/workflows/ci.yml', [
    'on: [push, pull_request]',
    'jobs:',
    '  test:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: npm test',
    '        env:',
    '          HOOK_URL: ${{ secrets.DEPLOY_HOOK }}',
  ].join('\n'));
  return dir;
}

describe('pipegen inspect', () => {
  it('cli: inspect prints services and capabilities, exit 0, no AI call', async () => {
    const dir = richRepo();
    const { code, out, calls } = await inspect(dir, publicRoutes(), { [ANTHROPIC_VAR]: 'probe', [OPENAI_VAR]: 'probe' });
    expect(code).toBe(0);
    // the project
    expect(out).toContain('express-app');
    expect(out).toMatch(/Language: node/);
    expect(out).toMatch(/Package manager: npm/);
    expect(out).toMatch(/Runtime: 20/);
    expect(out).toMatch(/Frameworks: express/);
    expect(out).toMatch(/Env var names: .*DATABASE_URL/);
    expect(out).toMatch(/Dependencies: .*postgres/);
    expect(out).toMatch(/Tests: yes/);
    expect(out).toContain('.github/workflows/ci.yml');
    expect(out).toMatch(/Triggers: push, pull_request/);
    expect(out).toMatch(/Secrets used: DEPLOY_HOOK/);
    expect(out).toMatch(/Hooks: husky/);
    // the GitHub context: the default branch comes from GitHub, not the reader's 'main' stub
    expect(out).toMatch(/Visibility: public/);
    expect(out).toMatch(/Default branch: trunk/);
    // what GitHub allows
    expect(out).toMatch(/Merge rules \(rulesets\): yes/);
    expect(out).toMatch(/Environments: yes/);
    expect(out).toMatch(/Signing: keyless/);
    expect(out).not.toContain('Signing environment rule proven'); // only meaningful on a private repo
    for (const row of permissionsTable('read')) expect(out).toContain(row.permission);
    // no AI call, nothing written: every request is a GET to api.github.com; nothing else was fetched
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((c) => c.method === 'GET' && c.url.origin === API)).toBe(true);
    expect(globalFetch).not.toHaveBeenCalled();
    expect(out).toMatch(/nothing was sent to an AI/);
  });

  it('cli: NotGitHubRepoError → friendly message, exit 1', async () => {
    const noRemote = makeRepo('node-express');
    const r1 = await inspect(noRemote, publicRoutes());
    expect(r1.code).toBe(1);
    expect(r1.err).toContain('pipegen inspect needs a GitHub repository');
    expect(r1.err).toContain('no "origin" remote');
    expect(r1.out).toBe(''); // errors go to stderr (review M4)
    expect(r1.calls).toHaveLength(0);
    const notGit = makeTempDir();
    const r2 = await inspect(notGit, publicRoutes());
    expect(r2.code).toBe(1);
    expect(r2.err).toContain('not a git repository');
    expect(r2.all).not.toMatch(/\bat \S+:\d+:\d+/); // no stack trace
  });

  it('cli: inspect output passes repo strings through safeText (hostile-names fixture)', async () => {
    const dir = makeRepo('node-express', GH_REMOTE);
    writeIn(dir, '.nvmrc', `${hostileNames.screenClear}20${hostileNames.bidiOverride}\n`);
    writeIn(dir, 'Dockerfile', 'FROM node:20\n');
    writeIn(dir, `svc${hostileNames.ansiColour}${hostileNames.bidiIsolates}/Dockerfile`, 'FROM node:20\nEXPOSE 8080\n');
    writeIn(dir, `svc${hostileNames.ansiColour}${hostileNames.bidiIsolates}/index.js`, '1;\n');   // GJ-R4 (N3): a folder with code of its own stays a service
    writeIn(dir, `.github/workflows/ci${hostileNames.bidiOverride}.yml`, 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n');
    const { code, out, all } = await inspect(dir, publicRoutes());
    expect(code).toBe(0);
    expect(all).not.toMatch(UNSAFE);
    expect(out).toContain('red-app'); // the hostile folder, cleaned
    expect(out).toContain('appfdp.exe'); // the .nvmrc runtime, cleaned
  });

  it('cli: hostile values from GitHub (default branch) are cleaned too (review M6)', async () => {
    // 1,000 characters: cut to the cap (a value over 4 KB is hidden whole by redact, checked below)
    const branch = `${hostileNames.osc8Link}${hostileNames.screenClear}${hostileNames.bidiOverride}${hostileNames.newlines}${'a'.repeat(1000)}`;
    const routes = publicRoutes({ [`GET ${R}`]: { body: { private: false, default_branch: branch, owner: { type: 'User', login: 'o' } } } });
    const { code, out, all } = await inspect(richRepo(), routes);
    expect(code).toBe(0);
    expect(all).not.toMatch(UNSAFE);
    expect(out).toMatch(/Default branch: click meapp/);
    expect(out).not.toContain('evil.example');
    expect(out).not.toContain('a'.repeat(200)); // cut
    // no injected line: every line of the summary is one printed line
    expect(out.split('\n').filter((l) => l.startsWith('  Default branch:'))).toHaveLength(1);
    const huge = await inspect(richRepo(), publicRoutes({ [`GET ${R}`]: { body: { private: false, default_branch: `${branch}${hostileNames.veryLong}`, owner: { type: 'User', login: 'o' } } } }));
    expect(huge.out).toContain('Default branch: (value too long to show)');
    expect(huge.all).not.toMatch(UNSAFE);
  });

  it('cli: without any token a public repo is read anonymously, and inspect says what it could not check', async () => {
    const { code, out, calls } = await inspect(richRepo(), publicRoutes());
    expect(code).toBe(0);
    expect(out).toMatch(/Access: no token/);
    expect(out).toMatch(/Plan: unknown/);
    expect(out).toContain("Couldn't check code scanning");
    expect(out).toMatch(/Without a token, pipegen couldn't check the account's GitHub plan/);
    expect(calls.every((c) => !('authorization' in c.headers))).toBe(true);
  });

  it('cli: a private repo without a token → the local summary, the read-only token steps, exit 1', async () => {
    const r = await inspect(richRepo(), { [`GET ${R}`]: err(404, 'Not Found') });
    expect(r.code).toBe(1);
    expect(r.out).toContain('express-app'); // the local part still prints
    expect(r.out).toMatch(/GitHub: not read/);
    expect(r.err).toContain('fine-grained token'); // the steps are an error message: stderr
    expect(r.out).not.toContain('fine-grained token');
  });

  it('cli: private Free repo, deployment branch policies unproven → Signing: decided at setup (DECISIONS #86)', async () => {
    const cred = fake.githubPat();
    const { code, out, calls } = await inspect(richRepo(), privateRoutes(), { [ENV_VAR]: cred });
    expect(code).toBe(0);
    expect(out).toMatch(/Visibility: private/);
    expect(out).toMatch(/Plan: free/);
    expect(out).toMatch(/Merge rules \(rulesets\): no/);
    expect(out).toMatch(/Signing: decided at setup/);
    expect(out).toContain('Signing environment rule proven (default branch only): no');
    expect(out).toMatch(/Access: fine-grained token/);
    expect(calls.some((c) => c.url.pathname === '/user')).toBe(true);
    expect(out).not.toContain(cred);
  });

  it('cli: inspect masks secret-like and known values in names, like the audit report (ruling U10)', async () => {
    const cred = fake.awsKey();
    const known = `kv${'Q7'.repeat(12)}z`; // an AI key redact doesn't recognise: only the known-value scrub catches it
    const dir = richRepo();
    writeIn(dir, `svc-${cred}/package.json`, JSON.stringify({ name: `svc-${cred}`, scripts: { start: 'node .' } }));
    writeIn(dir, `${known}/package.json`, JSON.stringify({ name: `${known}-api`, scripts: { start: 'node .' } }));
    writeIn(dir, `.github/workflows/${known}.yml`, 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n');
    const plain = await inspect(dir, publicRoutes());
    expect(plain.code).toBe(0);
    expect(plain.out).toContain(known); // planted: without the known value it shows
    const { code, all } = await inspect(dir, publicRoutes(), { [ANTHROPIC_VAR]: known });
    expect(code).toBe(0);
    expect(all).not.toContain(cred);
    expect(all).not.toContain(known);
    expect(all).toContain('REDACTED');
    expect(all).toContain('express-app'); // the rest still prints
  });

  it('cli: inspect never prints the token, even when GitHub echoes it back', async () => {
    const cred = fake.githubPat();
    const echo = (c: { headers: Record<string, string> }): Reply => ({ status: 404, body: { message: `Not Found for ${c.headers.authorization ?? ''} ${cred}` } });
    const failing = await inspect(richRepo(), privateRoutes({ [`GET ${R}`]: echo }), { [ENV_VAR]: cred });
    expect(failing.code).toBe(1);
    expect(failing.err).toMatch(/GitHub: not read/);
    expect(failing.all).not.toContain(cred);
    expect(failing.all).not.toContain(cred.slice(0, 20));
    const ok = await inspect(richRepo(), privateRoutes({ [`GET ${R}/rulesets`]: echo }), { [ENV_VAR]: cred });
    expect(ok.all).not.toContain(cred);
  });

  it('cli: a classic token is refused without --allow-broad-token, and accepted with it', async () => {
    const cred = fake.githubClassic();
    const refused = await inspect(richRepo(), privateRoutes(), { [ENV_VAR]: cred });
    expect(refused.code).toBe(1);
    expect(refused.err).toContain('classic token');
    expect(refused.all).not.toContain(cred);
    const allowed = await inspect(richRepo(), privateRoutes(), { [ENV_VAR]: cred }, ['inspect', '--allow-broad-token']);
    expect(allowed.code).toBe(0);
    expect(allowed.all).not.toContain(cred);
  });

  it('cli: --dir points inspect at another folder', async () => {
    const dir = richRepo();
    const f = fakeFetch(publicRoutes());
    const lines: string[] = [];
    const code = await run(['inspect', '--dir', dir], { prompt: noPrompts, out: (s) => { lines.push(s); }, err: () => {}, env: {}, cwd: makeTempDir(), fetch: f.fetch });
    expect(code).toBe(0);
    expect(lines.join('\n')).toContain('express-app');
  });

  it('cli: --help prints the usage; no command runs the audit of .; an unknown command exits 1', async () => {
    const help = await inspect(makeTempDir(), {}, {}, ['--help']);
    expect(help.code).toBe(0);
    expect(help.out).toContain('pipegen inspect');
    expect(help.out).toContain('npx pipegen');
    // no command (DECISIONS #124): `pipegen audit` on the current folder, not the usage
    const none = await inspect(makeTempDir(), {}, {}, []);
    expect(none.code).toBe(1);
    expect(none.out).not.toContain('Usage: pipegen');
    expect(none.err).toContain('pipegen audit needs a clone of a GitHub repository');
    const bad = await inspect(makeTempDir(), {}, {}, ['frobnicate\x1b[2J']);
    expect(bad.code).toBe(1);
    expect(bad.err).toContain('Unknown command');
    expect(bad.err).toContain('Usage: pipegen'); // usage-on-error goes to stderr too
    expect(bad.out).toBe('');
    expect(bad.all).not.toMatch(UNSAFE);
    const flag = await inspect(makeTempDir(), {}, {}, ['inspect', '--nope']);
    expect(flag.code).toBe(1);
    expect(flag.err).toContain('--nope');
    expect(flag.out).toBe('');
  });
});

describe('built bundle (ruling R9)', () => {
  it('dist: node dist/cli/main.js inspect runs on a fixture copy, GitHub stubbed offline, exit 0', async () => {
    // Built with the release options into an installed-package layout (a temp dir, so it can't race the package
    // test's own build of dist/). GitHub is a fetch stub preloaded with --import: the bundle itself is unchanged.
    const pkgDir = makeTempDir();
    writeIn(pkgDir, 'package.json', JSON.stringify({ name: 'pipegen', version: '0.1.0', type: 'module' }));
    await build({ ...tsupOptions, entry: { 'cli/main': 'src/cli/main.ts' }, outDir: join(pkgDir, 'dist'), config: false, silent: true });
    const main = join(pkgDir, 'dist', 'cli', 'main.js');
    expect(readFileSync(main, 'utf8').startsWith('#!/usr/bin/env node\n')).toBe(true);
    const stubDir = makeTempDir();
    const stub = join(stubDir, 'github-stub.mjs');
    writeFileSync(stub, [
      `const routes = ${JSON.stringify(publicRoutes())};`,
      'globalThis.fetch = async (input, init) => {',
      '  const url = new URL(typeof input === "string" ? input : input.url);',
      '  const key = `${(init?.method ?? "GET").toUpperCase()} ${url.origin}${url.pathname}`;',
      '  process.stderr.write(`FETCH ${key}\\n`);',
      '  const r = routes[key] ?? { status: 404, body: { message: "Not Found" } };',
      '  return new Response(JSON.stringify(r.body ?? {}), { status: r.status ?? 200, headers: { "content-type": "application/json" } });',
      '};',
    ].join('\n'));
    const repo = richRepo();
    const env = { PATH: process.env.PATH ?? '', HOME: makeTempDir() }; // no GITHUB_TOKEN, no AI keys
    const res = spawnSync('node', ['--import', pathToFileURL(stub).href, main, 'inspect'], { cwd: repo, env, encoding: 'utf8' });
    if (res.status !== 0) throw new Error(`inspect exited with ${res.status}:\n${res.stdout}\n${res.stderr}`);
    const stdout = res.stdout;
    expect(stdout).toContain('express-app');
    expect(stdout).toMatch(/Default branch: trunk/);
    expect(stdout).toMatch(/Signing: keyless/);
    expect(stdout).not.toMatch(UNSAFE);
    // every request the bundle made (logged by the stub) was a GET to api.github.com
    const fetched = res.stderr.split('\n').filter((l) => l.startsWith('FETCH '));
    expect(fetched.length).toBeGreaterThan(0);
    for (const l of fetched) expect(l).toMatch(/^FETCH GET https:\/\/api\.github\.com\//);
    // the placeholder is gone
    expect(stdout).not.toContain('commands coming soon');
    // the version flag works from the bundle
    expect(execFileSync('node', [main, '--version'], { env, encoding: 'utf8' }).trim()).toBe('pipegen 0.1.0');
  });
});
