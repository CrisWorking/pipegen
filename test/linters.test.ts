// Plan B Task 7b: ensureLinters and runLinters (rulings S19 to S21). The real tools run only in linters-live.test.ts; here
// the linters are stub executables (small sh scripts that record argv, cwd, env and the files they can see, and print
// canned output), passed as the `Linters` closures. Downloads use the fake fetch and a fake tar.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PinnedBinaryError, ensureLinters, loadPinnedBinaries, runLinters, type PinnedBinaries } from '../src/engine/linters.js';
import { loadReviewed } from '../src/engine/reviewed.js';
import type { Linters, RefereeIssue } from '../src/engine/referee.js';
import type { CreatedFile } from '../src/types.js';
import { fakeFetch } from './helpers/fake-http.js';
import { stub, type Rec, type Stub } from './helpers/linter-stub.js';
import { makeTarGz } from './helpers/fake-tar.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

afterEach(() => { cleanupRepos(); vi.unstubAllEnvs(); });

const LOGIN = 'gh-stub';
const WF = '.github/workflows/pipegen.yml';
const file = (path: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path, content: `name: ${path}\n`, part: 'pipeline', reason: 'test', repo: 'app', ...over });

const closures = (a: Stub, z: Stub): Linters => ({ actionlint: async () => a.bin, zizmor: async () => z.bin });

const zizmorFinding = (path: string, row: number, ident = 'template-injection', desc = 'code injection via template expansion') => ({
  ident, desc, url: 'https://docs.zizmor.sh/', determinations: { confidence: 'High', severity: 'High', persona: 'Regular' }, ignored: false,
  locations: [
    { symbolic: { key: { Local: { verbatim_path: path } }, annotation: 'context', kind: 'Related' }, concrete: { location: { start_point: { row: 0, column: 0 } } } },
    { symbolic: { key: { Local: { verbatim_path: path } }, annotation: 'may expand into attacker-controllable code', kind: 'Primary' }, concrete: { location: { start_point: { row, column: 4 } } } },
  ],
});
const actionlintFinding = (path: string, line: number, message = 'property "x" is not defined') => ({ message, filepath: path, line, column: 3, kind: 'expression', snippet: 'x', end_column: 4 });

describe('ensureLinters (S20)', () => {
  /** A pins table whose actionlint and zizmor point at fake archives served by a fake fetch. */
  function pinsFor(bins: { actionlint: Buffer; zizmor: Buffer }): { pins: PinnedBinaries; fetch: typeof fetch; calls: ReturnType<typeof fakeFetch>['calls'] } {
    const real = loadPinnedBinaries();
    const routes: Record<string, { raw: Buffer }> = {};
    const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
    const pins = { ...real } as PinnedBinaries;
    for (const name of ['actionlint', 'zizmor'] as const) {
      const archive = makeTarGz([{ name: 'LICENSE', content: 'MIT' }, { name, content: bins[name] }]);
      const platforms = Object.fromEntries(Object.entries(real[name].platforms).map(([k, p]) => {
        routes[`GET ${p.url.replace(/^(https:\/\/[^/]+)(.*)$/, '$1$2')}`] = { raw: archive };
        return [k, { ...p, archiveSize: archive.length, archiveSha256: sha(archive), binarySize: bins[name].length, binarySha256: sha(bins[name]) }];
      }));
      pins[name] = { ...real[name], platforms } as never;
    }
    const f = fakeFetch(routes);
    return { pins, fetch: f.fetch, calls: f.calls };
  }
  const script = (marker: string) => Buffer.from(`#!/bin/sh\necho ran > '${marker}'\n`);

  it('ensureLinters: zizmor downloaded and verified like actionlint; closures re-verify before each run', async () => {
    const dir = makeTempDir();
    const bins = { actionlint: script(join(dir, 'a-ran')), zizmor: script(join(dir, 'z-ran')) };
    const { pins, fetch, calls } = pinsFor(bins);
    const cache = join(dir, 'tools');
    const linters = ensureLinters(cache, { pins, fetch, platform: 'linux', arch: 'x64', env: {} });
    // nothing is downloaded until a closure is called
    expect(calls).toEqual([]);
    const z = await linters.zizmor();
    const a = await linters.actionlint();
    expect(z).toBe(join(cache, `zizmor-${pins.zizmor.version}`, 'zizmor'));
    expect(a).toBe(join(cache, `actionlint-${pins.actionlint.version}`, 'actionlint'));
    expect(readFileSync(z)).toEqual(bins.zizmor);
    const downloads = calls.length;
    expect(await linters.zizmor()).toBe(z);
    expect(calls.length, 'a cached copy is not downloaded again').toBe(downloads);
    // the cached binary is swapped between two runs: the closure checks it again and refuses it
    writeFileSync(z, '#!/bin/sh\necho evil\n');
    await expect(linters.zizmor()).rejects.toBeInstanceOf(PinnedBinaryError);
    expect(existsSync(z), 'a changed binary is deleted').toBe(false);
    expect(await linters.actionlint()).toBe(a);
  });

  it('linters: actionlint checksum mismatch → error, binary not used', async () => {
    const dir = makeTempDir();
    const bins = { actionlint: script(join(dir, 'a-ran')), zizmor: script(join(dir, 'z-ran')) };
    const { pins, fetch } = pinsFor(bins);
    const bad = { ...pins, actionlint: { ...pins.actionlint, platforms: Object.fromEntries(Object.entries(pins.actionlint.platforms).map(([k, p]) => [k, { ...p, archiveSha256: 'a'.repeat(64) }])) } } as PinnedBinaries;
    const cache = join(dir, 'tools');
    const linters = ensureLinters(cache, { pins: bad, fetch, platform: 'linux', arch: 'x64', env: {} });
    await expect(linters.actionlint()).rejects.toBeInstanceOf(PinnedBinaryError);
    expect(existsSync(join(dir, 'a-ran'))).toBe(false);
    expect(existsSync(join(cache, `actionlint-${pins.actionlint.version}`, 'actionlint'))).toBe(false);
    // runLinters turns it into an issue and never spawns
    const z = stub();
    const issues = await runLinters([file(WF)], linters, LOGIN);
    expect(issues.some((i) => i.check === 'actionlint' && /actionlint/i.test(i.message)), JSON.stringify(issues)).toBe(true);
    expect(existsSync(join(dir, 'a-ran'))).toBe(false);
    void z;
  });
});

describe('runLinters (S19, S21)', () => {
  const run = async (files: CreatedFile[], login: string | null = LOGIN) => {
    const a = stub();
    const z = stub();
    const issues = await runLinters(files, closures(a, z), login);
    return { a, z, issues };
  };
  const reviewedConfig = (id: string) => (loadReviewed().find((t) => t.id === id)?.fixedInputs.config as { content: string }).content;

  it('runLinters: temp copy holds only workflow files; bad paths refused', async () => {
    const good = file(WF);
    const other = file('.github/workflows/other.yaml');
    const bad = [
      '../evil.yml', '/etc/passwd', '.github/workflows/../../evil.yml', '.github/workflows/sub/x.yml', '.github/workflows/a b.yml',
      '.github/workflows/a->b.yml', '.github/workflows/x.yml/../../y.yml', 'package.json', '.github/zizmor.yml', 'zizmor.yml',
      '.github/actionlint.yaml', '.github/workflows/x.txt', '.github/actions/../x/action.yml', '.github/actions/x/action.yml/../../../y.yml',
    ];
    const { a, z, issues } = await run([good, other, ...bad.map((p) => file(p, { content: 'x: 1\n' }))]);
    for (const s of [a, z]) {
      const rec = s.records();
      expect(rec).toHaveLength(1);
      const names = (rec[0] as Rec).files.filter((f) => !/^\.\/(zizmor\.yml|actionlint\.yaml|zizmor-cache\/.*)$/.test(f));
      expect(names).toEqual(['./.github/workflows/other.yaml', `./${WF}`]);
    }
    // every refused path is reported (fail closed: it was not linted), and none of them was written
    for (const p of bad) expect(issues.some((i) => i.message.includes(p.slice(0, 40)) || i.file === p || i.file === p.slice(0, 200)), p).toBe(true);
  });

  it('runLinters: pipegen action files of the central repo are linted by zizmor only (actionlint reads workflows)', async () => {
    const action = file('.github/actions/fetch/action.yml', { repo: 'central' });
    const wfc = file(WF, { repo: 'central' });
    const { a, z } = await run([action, wfc]);
    expect((a.records()[0] as Rec).args.slice(-1)).toEqual([WF]);
    expect((z.records()[0] as Rec).args.slice(-2)).toEqual(['.github/actions/fetch/action.yml', WF]);
  });

  it('linters: repo .github/zizmor.yml and actionlint.yaml are ignored', async () => {
    const hostile = 'rules:\n  template-injection:\n    disable: true\n';
    const { a, z } = await run([file(WF), file('.github/zizmor.yml', { content: hostile }), file('zizmor.yml', { content: hostile }), file('.github/actionlint.yaml', { content: 'paths: {}\n' })]);
    const ra = a.records()[0] as Rec;
    const rz = z.records()[0] as Rec;
    for (const r of [ra, rz]) {
      expect(r.files.some((f) => /zizmor\.yml$/.test(f) && f !== './zizmor.yml')).toBe(false);
      expect(r.files.some((f) => /actionlint\.yaml$/.test(f) && f !== './actionlint.yaml')).toBe(false);
    }
    // the explicit config paths are pipegen's own, in the temp folder, with the reviewed entries' content
    expect(ra.args.slice(0, 2)).toEqual(['-config-file', `${ra.cwd}/actionlint.yaml`]);
    expect(rz.args.slice(0, 2)).toEqual(['--config', `${rz.cwd}/zizmor.yml`]);
    expect(ra.cfg.join('')).toBe(reviewedConfig('actionlint'));
    expect(rz.cfg.join('')).toBe(reviewedConfig('zizmor'));
    expect(rz.cfg.join('')).not.toContain('disable');
  });

  it('runLinters: actionlint flags exactly as ruled', async () => {
    const { a } = await run([file(WF)]);
    const r = a.records()[0] as Rec;
    expect(r.args).toEqual(['-config-file', `${r.cwd}/actionlint.yaml`, '-shellcheck=', '-pyflakes=', '-format', '{{json .}}', WF]);
    expect(r.cwd).toMatch(/pipegen-lint-/);
  });

  it('linters: zizmor runs online with the impostor-commit audit; no token → zizmor issue', async () => {
    const { z } = await run([file(WF)]);
    const r = z.records()[0] as Rec;
    expect(r.args).toEqual(['--config', `${r.cwd}/zizmor.yml`, '--format', 'json', '--cache-dir', `${r.cwd}/zizmor-cache`, WF]);
    expect(r.args).not.toContain('--offline');
    expect(r.args).not.toContain('--no-online-audits');
    // no login: zizmor is never started, and that is an issue, not a skip; actionlint still runs
    const none = await run([file(WF)], null);
    expect(none.z.records()).toEqual([]);
    expect(none.a.records()).toHaveLength(1);
    expect(none.issues.filter((i) => i.check === 'zizmor'), JSON.stringify(none.issues)).toHaveLength(1);
    expect(none.issues[0]?.message).toMatch(/token/i);
  });

  it('runLinters: zizmor env = GH_TOKEN + temp HOME (+ cache dir) only', async () => {
    vi.stubEnv('PIPEGEN_PLANTED', 'planted-value');
    vi.stubEnv(['GITHUB', 'TOKEN'].join('_'), 'ambient-value');
    vi.stubEnv(['GH', 'TOKEN'].join('_'), 'ambient-gh-value');
    vi.stubEnv('LD_PRELOAD', '/tmp/x.so');
    const { a, z } = await run([file(WF)]);
    const rz = z.records()[0] as Rec;
    expect(rz.env).toEqual({ [['GH', 'TOKEN'].join('_')]: LOGIN, HOME: rz.cwd, NO_COLOR: '1' });
    const ra = a.records()[0] as Rec;
    expect(Object.keys(ra.env).sort()).toEqual(['HOME', 'NO_COLOR']);
    expect(JSON.stringify([ra, rz])).not.toContain('planted-value');
    expect(JSON.stringify(ra)).not.toContain(LOGIN);
    expect(JSON.stringify(rz)).not.toContain('ambient');
  });

  it('runLinters: one temp copy per repo, mode 0700, removed afterwards', async () => {
    const { a, z } = await run([file(WF), file(WF, { repo: 'central' })]);
    const ra = a.records();
    expect(ra).toHaveLength(2);
    expect(new Set(ra.map((r) => r.cwd)).size).toBe(2);
    expect(z.records()).toHaveLength(2);
    for (const r of ra) expect(existsSync(r.cwd), 'the temp copy is removed').toBe(false);
  });

  it('runLinters: findings and exit codes mapped', async () => {
    // clean: exit 0 for both (zizmor prints [])
    {
      const a = stub(); const z = stub(); z.set('[]');
      expect(await runLinters([file(WF)], closures(a, z), LOGIN)).toEqual([]);
    }
    // findings: actionlint exit 1 with JSON; zizmor exit 13 with JSON (0-based rows → 1-based lines, the Primary location)
    {
      const a = stub(); a.set(JSON.stringify([actionlintFinding(WF, 7)]), 1);
      const z = stub(); z.set(JSON.stringify([zizmorFinding(WF, 11)]), 13);
      const issues = await runLinters([file(WF), file(WF, { repo: 'central' })], closures(a, z), LOGIN);
      const own = issues.filter((i) => i.repo === 'app');
      expect(own.map((i) => [i.check, i.file, i.line])).toEqual([['actionlint', WF, 7], ['zizmor', WF, 12]]);
      expect(issues.filter((i) => i.repo === 'central')).toHaveLength(2);
      expect(own[1]?.message).toMatch(/template-injection/);
      expect(own[0]?.message).toMatch(/not defined/);
    }
    // errors: bad JSON, a crash, an exit code outside the finding codes, empty output on a failure: never a silent pass
    const cases: [string, number, string][] = [['not json', 1, 'bad json, exit 1'], ['{"a":1}', 1, 'not an array'], ['', 2, 'exit 2 empty'], ['[]', 3, 'exit 3'], ['not json', 0, 'exit 0 with junk']];
    for (const [out, code, label] of cases) {
      const a = stub(); a.set(out, code);
      const z = stub(); z.set(out, code === 1 ? 14 : code);
      const issues = await runLinters([file(WF)], closures(a, z), LOGIN);
      const bad = (check: 'actionlint' | 'zizmor') => issues.filter((i) => i.check === check && i.line === undefined);
      if (!(out === '' && code === 0)) {
        expect(bad('zizmor'), `${label}: zizmor ${JSON.stringify(issues)}`).toHaveLength(1);
      }
      expect(JSON.stringify(issues)).not.toContain(LOGIN);
    }
    // exit 0 with no output at all is clean for actionlint (it prints nothing when there is nothing to say)
    {
      const a = stub(); const z = stub(); z.set('[]');
      expect(await runLinters([file(WF)], closures(a, z), LOGIN)).toEqual([]);
    }
    // a linter that can not be started (the closure throws) is an issue
    const issues = await runLinters([file(WF)], { actionlint: async () => { throw new Error('no binary'); }, zizmor: async () => '/nonexistent/zizmor' }, LOGIN);
    expect(issues.map((i) => i.check).sort()).toEqual(['actionlint', 'zizmor']);
    // and a finding with no usable location is still an issue (no line)
    const a2 = stub(); const z2 = stub();
    z2.set(JSON.stringify([{ ident: 'x', desc: 'y', locations: [] }]), 12);
    const odd = await runLinters([file(WF)], closures(a2, z2), LOGIN);
    expect(odd.filter((i) => i.check === 'zizmor').map((i) => [i.file, i.line])).toEqual([[WF, undefined]]);
  });

  it('runLinters: a long or hostile finding message is cut and cleaned', async () => {
    const a = stub(); a.set(JSON.stringify([actionlintFinding(WF, 1, `x\u001b[31m${'y'.repeat(2000)}\nsecond line`)]), 1);
    const z = stub(); z.set('[]');
    const issues = await runLinters([file(WF)], closures(a, z), LOGIN);
    expect(issues).toHaveLength(1);
    const m = (issues[0] as RefereeIssue).message;
    expect(m.length).toBeLessThanOrEqual(320);
    // eslint-disable-next-line no-control-regex
    expect(m).not.toMatch(/[\u0000-\u001f]/);
  });
});
