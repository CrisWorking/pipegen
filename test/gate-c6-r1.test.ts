// Close the C6 re-review notes (review-C6-r1.md r1-m2, m4, m5, m6). Written first: the survivors of that review's mutants must now die.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse, stringify } from 'yaml';
import { checkCooldown } from '../scripts/release-check.js';
import { runCooldown } from '../scripts/cooldown.js';
import { renderScrub } from '../src/engine/render-step.js';
import { loadReviewed } from '../src/engine/reviewed.js';
import { gateEntry } from './helpers/render.js';

const ROOT = resolve(import.meta.dirname, '..');
const DATA = join(ROOT, 'data/reviewed-tools.yml');
const NOW = new Date('2026-10-30T12:00:00Z');
const API = 'https://api.github.com/repos/crisworking/pipegen';
const real = () => { const t = loadReviewed().find((e) => e.id === 'pipegen-gate'); if (t === undefined) throw new Error('no pipegen-gate entry'); return t; };
const onlyGate = (): string => {
  const doc = parse(readFileSync(DATA, 'utf8')) as { pinnedOn: string; tools: Record<string, any>[] };
  return stringify({ pinnedOn: doc.pinnedOn, tools: [doc.tools.find((t) => t.id === 'pipegen-gate')] });
};
/** The real entry's gate tag (gate-v<version>; gate-v0.2.3 since G15b; gate-v0.2.2 was E9). */
const TAG = `gate-v${real().candidate.version}`;
const stub = (routes: Record<string, unknown>, calls: string[]): typeof fetch => (async (url: string) => {
  calls.push(String(url));
  const body = routes[String(url)];
  return body === undefined ? new Response('{}', { status: 404 }) : new Response(JSON.stringify(body), { status: 200 });
}) as typeof fetch;

describe('r1-m2: checkCooldown is a release check (the gate pin must be on the default branch)', () => {
  const PIN = real().candidate.pin.sha as string;
  const tag = { ref: `refs/tags/${TAG}`, object: { type: 'commit', sha: PIN } };
  it('checkCooldown makes the default-branch compare call for the gate entry, and fails when the pin is not on main', async () => {
    const calls: string[] = [];
    const routes = { [`${API}/git/ref/tags/${TAG}`]: tag, [API]: { default_branch: 'main' }, [`${API}/compare/${PIN}...main?per_page=1`]: { status: 'diverged', behind_by: 1, merge_base_commit: { sha: 'a'.repeat(40) } } };
    const c = await checkCooldown({}, { 'data/reviewed-tools.yml': onlyGate() }, stub(routes, calls), NOW);
    expect(calls.some((u) => u.includes('/compare/'))).toBe(true);
    expect(c.ok).toBe(false);
  });
  it('and passes when it is on main', async () => {
    const calls: string[] = [];
    const routes = { [`${API}/git/ref/tags/${TAG}`]: tag, [API]: { default_branch: 'main' }, [`${API}/compare/${PIN}...main?per_page=1`]: { status: 'ahead', behind_by: 0, merge_base_commit: { sha: PIN } } };
    const c = await checkCooldown({}, { 'data/reviewed-tools.yml': onlyGate() }, stub(routes, calls), NOW);
    expect(c.problems).toEqual([]);
    expect(c.ok).toBe(true);
  });
});

describe('r1-m2: the release run includes the gate-pin check', () => {
  it('the CLI run in a temp repo reports "the gate pin holds the shipped gate bundle" (removing checkGatePin from main would fail this)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-relrun-'));
    execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: dir });
    mkdirSync(join(dir, 'data'));
    writeFileSync(join(dir, 'data/reviewed-tools.yml'), 'tools: []\n');
    const r = spawnSync(process.execPath, [join(ROOT, 'scripts/release-check.ts'), '--tag', 'v9.9.9'], { cwd: dir, encoding: 'utf8', timeout: 120_000, env: { PATH: process.env.PATH ?? '' } });
    expect(r.stdout).toContain('the gate pin holds the shipped gate bundle');
    expect(r.status).toBe(1);
  }, 130_000);
});

describe('r1-m2 and m4: the CI ls-files compare is the exact line, with a C-locale sort', () => {
  const ci = parse(readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8')) as { jobs: Record<string, { steps: { run?: string }[] }> };
  const script = (ci.jobs['gate-dist']?.steps ?? []).map((s) => s.run ?? '').join('\n');
  const line = script.split('\n').map((l) => l.trim()).find((l) => /^test "\$\(git ls-files gate\/dist/.test(l));
  it('is a real test line (a comment can not satisfy it) with LC_ALL=C sort and exactly the three files', () => {
    expect(line).toBe('test "$(git ls-files gate/dist | LC_ALL=C sort | tr \'\\n\' \' \')" = "gate/dist/README.md gate/dist/THIRD_PARTY_NOTICES gate/dist/index.js "');
  });
  // an unknown LC_ALL falls back to C collation, so on a host without en_US.utf8 this test would prove nothing: it is skipped there
  const hasLocale = spawnSync('locale', ['-a'], { encoding: 'utf8' }).stdout?.split('\n').some((l) => /^en_US\.utf-?8$/i.test(l.trim())) === true;
  it.skipIf(!hasLocale)('holds in a non-C locale: the line, run as it stands, exits 0 on this tree', () => {
    const r = spawnSync('bash', ['-c', line as string], { cwd: ROOT, env: { PATH: process.env.PATH ?? '', LC_ALL: 'en_US.UTF-8', LANG: 'en_US.UTF-8' }, encoding: 'utf8' });
    expect(r.status).toBe(0);
  });
});

describe('r1-m5: the tag lookup checks the returned ref name', () => {
  const PIN = real().candidate.pin.sha as string;
  const run = async (answer: unknown): Promise<{ ok: boolean; problems: string }> => {
    const routes = { [`${API}/git/ref/tags/${TAG}`]: answer, [API]: { default_branch: 'main' } };
    const r = await runCooldown({ base: {}, head: { 'data/reviewed-tools.yml': onlyGate() }, fetch: stub(routes, []), now: NOW, maxLookups: 100 });
    return { ok: r.ok, problems: r.findings.map((x) => x.problem).join('\n') };
  };
  it('the right ref name passes; another tag, a branch ref or a missing name fails', async () => {
    expect((await run({ ref: `refs/tags/${TAG}`, object: { type: 'commit', sha: PIN } })).ok).toBe(true);
    for (const ref of [`refs/tags/${TAG}-rc1`, 'refs/tags/gate-v0.2', `refs/heads/${TAG}`, TAG, undefined, 5]) {
      const r = await run({ ...(ref === undefined ? {} : { ref }), object: { type: 'commit', sha: PIN } });
      expect(r.ok, String(ref)).toBe(false);
    }
  });
});

describe('r1-m6: the rendered uses comment names the real tag of pipegen\'s own gate', () => {
  it('# gate-v<version> for the own gate entry (the fixture: gate-v0.2.0; the real entry: its own version)', () => {
    const raw = '${{ runner.temp }}/pipegen-raw/pipegen-out-sast--app/semgrep.sarif';
    expect(renderScrub('pipegen-out-sast--app', raw, 'semgrep', 'sarif', gateEntry()).usesComment).toBe('gate-v0.2.0');
    expect(renderScrub('pipegen-out-sast--app', raw, 'semgrep', 'sarif', real()).usesComment).toBe(`gate-v${real().candidate.version}`);
  });
});
