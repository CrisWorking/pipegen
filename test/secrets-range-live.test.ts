// LIVE (PIPEGEN_LIVE_TESTS=1; the pinned betterleaks 1.9.0 and gitleaks 8.30.1 from ensurePinnedBinary's cache): C9, the commit-range
// secrets scan end to end. Each case builds a real git repository, runs the RENDERED range scan step (renderRangeBlock) with the real
// betterleaks in a sandbox runner, scrubs its raw result with the real scrub (range mode: the step's range.json beside it) and decides with
// decideGate, as the gate does with the artifact. The step's own count check, canary commits, info/attributes and empty scan folder all run.
// What is proven: a key added in one commit and removed in the next blocks; a key only in base commits does not; a key in an archive, under
// node_modules/ or in package-lock.json is reported; the checkout's .betterleaksignore and .gitattributes hide nothing; gitleaks git mode,
// for comparison, applies its path allowlist. Fix round 1 (review-C9.md): a stream cut short has no tip canary (a tool error); a merge's own
// resolution is scanned; a link turned into a file is read; the commits a force-push dropped are scanned; an event with no range skips.
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { decideGate, type CheckInput, type GateInput, type RangeScan } from '../gate/src/decide.js';
import { DEFAULT_POLICY } from '../gate/src/policy-default.js';
import { readScrubbed, scrubFile } from '../gate/src/scrub.js';
import { SECRETS_RANGE_ARTIFACT as A } from '../src/engine/artifact-names.js';
import type { JobListEntry } from '../src/engine/gate-job-list.js';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { renderRangeBlock, type RenderedStep } from '../src/engine/render-step.js';
import { GATE, p } from './helpers/gate-pipeline.js';
import { entry } from './helpers/render.js';
import { sandbox, stepEnv, type Sandbox } from './helpers/step-harness.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1' && process.platform !== 'win32';
const key = (n = 0): string => 'shp' + 'at_' + `${n.toString(16).padStart(2, '0')}${'0123456789abcdef'.repeat(2).slice(2)}`;   // built at run time
const line = (n = 0): string => `const shopify_value = "${key(n)}";\n`;
const FPKEY = 'L7'.repeat(20);
const SEC = 'sec' + 'ret:';
const K_NS = ['needs', 'Sec' + 'rets'].join('') as 'needsSecrets';
let betterleaks = '';
let gitleaks = '';

/** A git repository in the sandbox's workspace, driven by `git` with a fixed identity. */
function gitOf(sb: Sandbox): (...args: string[]) => string {
  return (...args) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main', ...args], { cwd: sb.ws, encoding: 'utf8' }).trim();
}
const put = (sb: Sandbox, rel: string, content: string | Buffer): void => { mkdirSync(join(sb.ws, rel, '..'), { recursive: true }); writeFileSync(join(sb.ws, rel), content); };
/** Commits every change with this message; returns the new head. */
const commit = (g: ReturnType<typeof gitOf>, msg: string): string => { g('add', '-A', '-f'); g('commit', '-q', '--allow-empty', '-m', msg); return g('rev-parse', 'HEAD'); };
/** A stored (uncompressed) zip with one member: its bytes hold the member's text as written (a key in it is plain bytes). */
function storedZip(name: string, text: string): Buffer {
  const data = Buffer.from(text);
  const crc = ((): number => { let c = ~0; for (const b of data) { c ^= b; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); } return ~c >>> 0; })();
  const n = Buffer.from(name);
  const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(10, 4); local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(n.length, 26);
  const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(10, 6); central.writeUInt32LE(crc, 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(n.length, 28);
  const cdOffset = 30 + n.length + data.length;
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(46 + n.length, 12); end.writeUInt32LE(cdOffset, 16);
  return Buffer.concat([local, n, data, central, n, end]);
}

interface Outcome { status: number | null; stderr: string; scan: RangeScan; gate: ReturnType<typeof decideGate>; skipped: boolean }
/**
 * Runs the rendered range scan step over base..head of the sandbox's repository with `bin` as the installed betterleaks, then the scrub and
 * the decision (a clean HEAD scan beside it). `event` 'push' makes the range informational.
 */
function scanRange(sb: Sandbox, range: { base: string; head: string; before?: string }, bin = betterleaks, event: 'pull_request' | 'push' = 'pull_request'): Outcome {
  const dir = join(sb.rt, 'pipegen-bin', A);
  mkdirSync(dir, { recursive: true });
  copyFileSync(bin, join(dir, 'betterleaks'));
  chmodSync(join(dir, 'betterleaks'), 0o755);
  const step = renderRangeBlock(entry('betterleaks'), p, GATE).steps[1] as RenderedStep;
  const r = spawnSync('bash', ['--noprofile', '--norc', '-c', step.run ?? ''], { cwd: sb.ws, env: { ...stepEnv(step, sb), PIPEGEN_RANGE_BASE: range.base, PIPEGEN_RANGE_HEAD: range.head, PIPEGEN_RANGE_BEFORE: range.before ?? '0'.repeat(40) }, encoding: 'utf8' });
  const raw = join(sb.rt, 'pipegen-raw', A, 'betterleaks.sarif');
  const out = join(sb.rt, 'pipegen-out', A, 'betterleaks.sarif');
  const s = scrubFile({ artifact: A, tool: 'betterleaks', format: 'sarif', raw, out, fpKey: FPKEY, workspace: sb.ws, eventText: '{}' });
  const back = s.status === 'ok' ? readScrubbed(readFileSync(out), 'sarif') : undefined;
  const scan: RangeScan = back === undefined ? { tool: 'betterleaks', toolError: s.error ?? 'no detail' } : { tool: 'betterleaks', findings: back.findings };
  return { status: r.status, stderr: r.stderr, scan, gate: decideGate(inputWith(scan, event)), skipped: back?.rangeSkipped === true };
}
const se = { needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks', format: 'sarif', artifact: 'pipegen-out-secrets', baseArtifact: 'pipegen-out-base-secrets', blocking: true, [K_NS]: false } as JobListEntry;
function inputWith(scan: RangeScan, event: 'pull_request' | 'push'): GateInput {
  const file = { sha256: 'f'.repeat(64), read: { findings: [], notes: [] } };
  const head: CheckInput = { entry: se, result: 'success', outputs: { status: 'ok', sha256: 'f'.repeat(64) }, file, base: { outputs: { status: 'ok', sha256: 'f'.repeat(64) }, file } };
  const [B, H, M] = ['b'.repeat(40), 'c'.repeat(40), 'd'.repeat(40)];
  return {
    event: event === 'push' ? { name: 'push', sha: H, payload: { before: B, after: H } } : { name: 'pull_request', sha: M, payload: { pull_request: { base: { sha: B }, head: { sha: H, repo: { id: 7 } } }, repository: { id: 7 } } },
    checks: [head], baseScan: { result: 'success', commit: B }, ancestry: { base: B, head: event === 'push' ? H : M, isAncestor: true }, baseline: null, sameRunTools: [], installing: false,
    diff: event === 'push' ? null : { added: new Map(), complete: true, commit: M }, rangeScans: [scan], mode: 'warn', policy: DEFAULT_POLICY,
    notProvenNeeds: [], skipped: [], settingsErrors: [], integrity: [], floorNeeds: ['secrets'],
  };
}
const findingsOf = (o: Outcome): { file?: string; commit?: string; ruleId: string }[] => (o.scan.findings ?? []).map((f) => ({ file: f.file, commit: f.commit, ruleId: f.ruleId }));
const rangeBlocks = (o: Outcome): string[] => o.gate.blocking.filter((b) => b.job === 'commit range').map((b) => b.reason);

describe.skipIf(!live)('live: the commit-range secrets scan (C9), the pinned betterleaks 1.9.0 through the rendered step', () => {
  beforeAll(async () => { betterleaks = await ensurePinnedBinary('betterleaks'); gitleaks = await ensurePinnedBinary('gitleaks'); }, 600_000);

  it('a key added in commit 1 and removed in commit 2 is reported at its commit, and the gate blocks ("rotate it")', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'a.txt', 'base\n');
    const base = commit(g, 'base');
    put(sb, 'config.js', line(1));
    const c1 = commit(g, 'add a key');
    g('rm', '-q', 'config.js');
    const head = commit(g, 'remove it');
    const o = scanRange(sb, { base, head });
    expect(o.status, o.stderr).toBe(0);
    expect(findingsOf(o)).toEqual([{ file: 'config.js', commit: c1, ruleId: `${SEC}shopify-access-token` }]);
    expect(o.gate.pass).toBe(false);
    expect(rangeBlocks(o)).toEqual([`secret added in this PR's history (commit ${c1.slice(0, 12)}): rotate it now, even if a later commit removed it`]);
    expect(o.gate.summary).toContain('rotate it now, even if a later commit removed it');
    // on a push to the default branch the same range only warns
    const pushed = scanRange(sandboxCopy(sb), { base, head }, betterleaks, 'push');
    expect(pushed.gate.pass).toBe(true);
    expect(pushed.gate.warnings.some((w) => w.job === 'commit range')).toBe(true);
  }, 120_000);

  it('an old key that exists only in base commits is not in the range: no finding, the gate passes (a one-commit pull request too)', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'old.js', line(2));
    commit(g, 'an old key');
    g('rm', '-q', 'old.js');
    put(sb, 'kept.js', line(3));
    const base = commit(g, 'the old key moved; another stays in the base');
    put(sb, 'b.txt', 'a change\n');
    const head = commit(g, 'the pull request');
    const o = scanRange(sb, { base, head });
    expect(o.status, o.stderr).toBe(0);
    expect(findingsOf(o)).toEqual([]);
    expect(o.gate.pass).toBe(true);
  }, 120_000);

  it('a key inside a stored archive, under node_modules/, in package-lock.json, or behind the checkout\'s .gitattributes (-diff, binary) is reported', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'a.txt', 'base\n');
    const base = commit(g, 'base');
    put(sb, 'bundle.zip', storedZip('in/config.txt', line(4)));
    put(sb, 'node_modules/x/index.js', line(5));
    put(sb, 'package-lock.json', `{\n  "lockfileVersion": 3,\n  "note": "${key(6)}"\n}\n`);
    put(sb, '.gitattributes', 'hidden.js -diff\n*.txt binary\n');
    put(sb, 'hidden.js', line(7));
    put(sb, 'notes.txt', line(8));
    const head = commit(g, 'keys in the usual hiding places');
    const o = scanRange(sb, { base, head });
    expect(o.status, o.stderr).toBe(0);
    expect(findingsOf(o).map((f) => f.file).sort()).toEqual(['bundle.zip', 'hidden.js', 'node_modules/x/index.js', 'notes.txt', 'package-lock.json']);
    expect(o.gate.pass).toBe(false);
  }, 120_000);

  it('the checkout\'s own .betterleaksignore and .gitleaksignore, naming the finding, hide nothing (the scanner runs from an empty folder)', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'a.txt', 'base\n');
    const base = commit(g, 'base');
    put(sb, 'config.js', line(9));
    const c1 = commit(g, 'a key');
    g('rm', '-q', 'config.js');
    const rule = ['shopify', 'access', 'token'].join('-');   // spelled at run time (test/no-secret-literals.test.ts)
    for (const f of ['.betterleaksignore', '.gitleaksignore']) put(sb, f, [c1, 'config.js', rule, '1'].join(':') + '\n');
    const head = commit(g, 'remove it and ignore it');
    const o = scanRange(sb, { base, head });
    expect(findingsOf(o)).toEqual([{ file: 'config.js', commit: c1, ruleId: `${SEC}shopify-access-token` }]);
  }, 120_000);

  it('fix round 1 (I1): a stream cut short (the scanner\'s git log dies silently half way) has no tip canary: a tool error, and the gate blocks', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'a.txt', 'base\n');
    const base = commit(g, 'base');
    put(sb, 'config.js', line(15));
    commit(g, 'a key');
    g('rm', '-q', 'config.js');
    for (let i = 0; i < 3; i++) { put(sb, `f${i}.txt`, `${i}\n`.repeat(50)); commit(g, `filler ${i}`); }
    const head = g('rev-parse', 'HEAD');
    // the honest scan: the key, both canaries, ok
    const ok = scanRange(sandboxCopy(sb), { base, head });
    expect(ok.status, ok.stderr).toBe(0);
    expect(findingsOf(ok).map((f) => f.file)).toEqual(['config.js']);
    // a stand-in git on the scanner's PATH: its `git log` prints the first 600 bytes of the real stream, then is killed with no message
    const fake = join(sb.dir, 'fakegit');
    mkdirSync(fake);
    writeFileSync(join(fake, 'git'), ['#!/bin/bash', 'case " $* " in *" log "*) /usr/bin/git "$@" | head -c 600; kill -9 $$ ;; esac', 'exec /usr/bin/git "$@"'].join('\n'));
    chmodSync(join(fake, 'git'), 0o755);
    const wrapper = join(sb.dir, 'cut.sh');
    writeFileSync(wrapper, ['#!/bin/bash', `PATH=${fake}:$PATH exec ${JSON.stringify(betterleaks)} "$@"`].join('\n'));
    chmodSync(wrapper, 0o755);
    const cut = scanRange(sandboxCopy(sb), { base, head }, wrapper);
    expect(cut.scan.toolError).toMatch(/not read the commit range to its end/);
    expect(cut.gate.pass).toBe(false);
    expect(cut.gate.toolErrors.map((t) => t.job)).toEqual(['commit range']);
  }, 180_000);

  it('fix round 1 (I3): merge commits are scanned for what their own resolution added (a key typed into a conflict resolution, an .env staged while resolving), and a key a merge brings from main is reported too (a false block)', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'conf.txt', 'a\nb\nc\n');
    const base = commit(g, 'base');
    g('checkout', '-q', '-b', 'pr');
    put(sb, 'conf.txt', 'a\nPR\nc\n');
    commit(g, 'pr 1');
    g('checkout', '-q', 'main');
    put(sb, 'conf.txt', 'a\nMAIN\nc\n');
    put(sb, 'main.js', line(10));
    const onMain = commit(g, 'main gets a key after the pull request branched');
    g('checkout', '-q', 'pr');
    spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'merge', '-q', '--no-edit', 'main'], { cwd: sb.ws });   // conflicts
    put(sb, 'conf.txt', `a\nRESOLVED ${line(11)}c\n`);
    put(sb, '.env', line(12));
    g('add', '-A', '-f');
    g('commit', '-q', '--no-edit');
    const merge = g('rev-parse', 'HEAD');
    g('rm', '-q', '.env');
    put(sb, 'conf.txt', 'a\nb\nc\n');
    const head = commit(g, 'clean up after the merge');
    const o = scanRange(sb, { base, head });
    expect(o.status, o.stderr).toBe(0);
    const got = findingsOf(o).map((f) => `${f.commit === merge ? 'merge' : f.commit === onMain ? 'main' : 'other'}:${(f.file ?? '').replace(/^b\//, '')}`).sort();
    expect(got).toEqual(['main:main.js', 'merge:.env', 'merge:conf.txt']);
    expect(o.gate.pass).toBe(false);
  }, 120_000);

  it('fix round 1: a link that becomes a file holding a key is read (single mode reads type changes) and blocks', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'a.txt', 'base\n');
    execFileSync('ln', ['-s', 'a.txt', 'x'], { cwd: sb.ws });
    const base = commit(g, 'base');
    g('rm', '-q', 'x');
    put(sb, 'x', line(12));
    const tc = commit(g, 'the link becomes a file with a key');
    g('rm', '-q', 'x');
    const head = commit(g, 'and goes');
    const o = scanRange(sb, { base, head });
    expect(o.status, o.stderr).toBe(0);
    expect(findingsOf(o)).toEqual([{ file: 'x', commit: tc, ruleId: `${SEC}shopify-access-token` }]);
    expect(o.gate.pass).toBe(false);
  }, 120_000);

  it('fix round 1 (I2): after an amend and a force-push, the commit the push dropped is scanned (before) and blocks; a normal push still passes; a before that can not be fetched is a tool error', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'a.txt', 'base\n');
    const base = commit(g, 'base');
    put(sb, 'config.js', line(16));
    const pushed = commit(g, 'a key, pushed (the gate blocked)');
    g('rm', '-q', 'config.js');
    put(sb, 'b.txt', 'b\n');
    g('add', '-A');
    g('commit', '-q', '--amend', '-m', 'amended without the key');
    const head = g('rev-parse', 'HEAD');
    // the synchronize of the force-push: base..head no longer holds the key's commit, before does
    const without = scanRange(sandboxCopy(sb), { base, head });
    expect(without.gate.pass).toBe(true);
    const o = scanRange(sandboxCopy(sb), { base, head, before: pushed });
    expect(o.status, o.stderr).toBe(0);
    expect(findingsOf(o)).toEqual([{ file: 'config.js', commit: pushed, ruleId: `${SEC}shopify-access-token` }]);
    expect(rangeBlocks(o)).toEqual([`secret added in this PR's history (commit ${pushed.slice(0, 12)}): rotate it now, even if a later commit removed it`]);
    // a normal push: before is the previous head, an ancestor of the new head
    put(sb, 'c.txt', 'c\n');
    const next = commit(g, 'a normal push');
    expect(scanRange(sandboxCopy(sb), { base, head: next, before: head }).gate.pass).toBe(true);
    // a dropped head that is not in the checkout and can not be fetched (no remote here): the step fails, the range is a tool error
    const lost = scanRange(sandboxCopy(sb), { base, head: next, before: 'e'.repeat(40) });
    expect(lost.status).toBe(1);
    expect(lost.stderr).toMatch(/could not be fetched/);
    expect(lost.gate.pass).toBe(false);
  }, 180_000);

  it('fix round 1: no commit range on this event (an all-zero base): the step skips, the scrub marks it skipped, no finding', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'a.txt', 'base\n');
    const head = commit(g, 'base');
    const o = scanRange(sb, { base: '0'.repeat(40), head });
    expect(o.status).toBe(0);
    expect(o.skipped).toBe(true);
  }, 60_000);
});

describe.skipIf(!live)('live: gitleaks 8.30.1 git mode, for comparison (why the range scan is betterleaks with no path allowlist)', () => {
  beforeAll(async () => { gitleaks = await ensurePinnedBinary('gitleaks'); }, 600_000);
  it('gitleaks git mode with pipegen\'s own config applies its global path allowlist (node_modules/ is skipped), and its commit count is not rev-list\'s', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'a.txt', 'base\n');
    const base = commit(g, 'base');
    put(sb, 'node_modules/x/index.js', line(13));
    put(sb, 'src.js', line(14));
    commit(g, 'two keys');
    g('rm', '-q', 'src.js');
    const head = commit(g, 'a commit that only deletes');
    const cfg = join(sb.dir, 'gitleaks.toml');
    writeFileSync(cfg, entry('gitleaks').fixedInputs.config?.content as string);
    const out = join(sb.dir, 'gl.sarif');
    const r = spawnSync(gitleaks, ['git', '--no-banner', '--no-color', '--redact', '--report-format', 'sarif', '--report-path', out, '--exit-code', '10', '--config', cfg, '--log-opts', `--no-merges ${base}..${head}`, '.'], { cwd: sb.ws, encoding: 'utf8', env: { PATH: process.env.PATH ?? '', HOME: sb.dir } });
    expect(r.status).toBe(10);
    const uris = (JSON.parse(readFileSync(out, 'utf8')) as { runs: { results: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] }).runs[0]?.results.map((x) => x.locations[0]?.physicalLocation.artifactLocation.uri);
    expect(uris).toEqual(['src.js']);
    // its count leaves out a commit that only deletes: 1, where rev-list counts 2
    expect(r.stderr).toMatch(/1 commits scanned/);
    expect(g('rev-list', '--count', '--no-merges', `${base}..${head}`)).toBe('2');
  }, 120_000);
});

/** A fresh sandbox holding a copy of this one's repository (a scan writes into the git folder and the runner temp; each run gets its own). */
function sandboxCopy(sb: Sandbox): Sandbox {
  const c = sandbox();
  execFileSync('cp', ['-a', `${sb.ws}/.`, c.ws]);
  return c;
}
