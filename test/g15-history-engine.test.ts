// G15a round 4 (b1, P-4): betterleaks over the full history, nightly. The engine half, written first. The history scan is the commit-range
// scan step (C9, render-cli.ts renderRangeScan) with no base: the same install, the same scanner command, the same two canary commits on the
// head and the same order check; its revisions are every ref of the full checkout (`--all`) plus the tip canary, its only outside value is the
// commit the run checked out (github.sha), and it writes the history form of the facts under its own artifact. The LIVE part runs the rendered
// step with the pinned betterleaks 1.9.0 (cached by ensurePinnedBinary) and the real scrub.
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { readScrubbed, scrubFile } from '../gate/src/scrub.js';
import { SECRETS_HISTORY_ARTIFACT as H, SECRETS_RANGE_ARTIFACT as A } from '../src/engine/artifact-names.js';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { renderRangeScan } from '../src/engine/render-cli.js';
import { renderHistoryBlock, renderRangeBlock, type RenderedStep } from '../src/engine/render-step.js';
import { HISTORY_STEP_ENV, historyScanStepId, rangeScanStepId } from '../src/engine/tool-flags.js';
import { GATE, p } from './helpers/gate-pipeline.js';
import { entry } from './helpers/render.js';
import { sandbox, stepEnv, type Sandbox } from './helpers/step-harness.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1' && process.platform !== 'win32';
const SEC = 'sec' + 'ret:';
const FPKEY = 'H5'.repeat(20);
const key = (n = 0): string => 'shp' + 'at_' + `${n.toString(16).padStart(2, '0')}${'0123456789abcdef'.repeat(2).slice(2)}`;   // built at run time
const line = (n = 0): string => `const shopify_value = "${key(n)}";\n`;

describe('the history scan step', () => {
  it('render: the history scan is the range step with no base: every ref of the checkout from the commit the run checked out, its own artifact, step id and facts form', () => {
    const r = renderRangeScan(entry('betterleaks'), 'history');
    const range = renderRangeScan(entry('betterleaks'));
    expect(r.fullHistory).toBe(true);
    expect(r.output).toEqual({ path: `\${{ runner.temp }}/pipegen-raw/${H}/betterleaks.sarif`, format: 'sarif' });
    const [install, scan] = r.steps as [RenderedStep, RenderedStep];
    expect(scan.id).toBe(historyScanStepId);
    expect(historyScanStepId).not.toBe(rangeScanStepId);
    expect(HISTORY_STEP_ENV).toEqual({ PIPEGEN_HISTORY_HEAD: '${{ github.sha }}' });
    expect(Object.keys(scan.env ?? {}).sort()).toEqual(Object.keys(range.steps[1]?.env ?? {}).filter((k) => !k.startsWith('PIPEGEN_RANGE_')).concat('PIPEGEN_HISTORY_HEAD').sort());
    expect(scan.env?.PIPEGEN_HISTORY_HEAD).toBe('${{ github.sha }}');
    expect(scan.env?.PIPEGEN_CONFIG).toBe(range.steps[1]?.env?.PIPEGEN_CONFIG);
    const run = scan.run ?? '';
    expect(run).toContain('"${git[@]}" rev-list --reverse --all "$last" > "$work/order.txt"');
    expect(run).toContain('"${git[@]}" rev-list --min-parents=3 --all "$last" > "$work/octopus.txt"');
    expect(run).toContain('logopts="--reverse --remerge-diff --text --all $last"');
    expect(run).toContain('"pipegenRange":1,"history":true,"head":"%s","commits":%s,');
    for (const gone of ['PIPEGEN_RANGE_', 'merge-base', '"before"', 'skip no-range', '"$base"']) expect(run, gone).not.toContain(gone);
    // the scanner command and the canaries are the range step's own
    const cmd = (s: string): string | undefined => s.split('\n').find((l) => l.includes(' git --no-banner '));
    expect(cmd(run)).toBe(cmd(range.steps[1]?.run ?? ''));
    expect(run).toContain('commit-tree "$tree" -p "$parent"');
    expect(install.run?.replaceAll(H, A)).toBe(range.steps[0]?.run);
  });

  it('render: renderHistoryBlock is the install, the scan, its scrub (no stage) and its upload, all under the history artifact', () => {
    const b = renderHistoryBlock(entry('betterleaks'), p, GATE);
    expect(b.artifact).toBe(H);
    expect(b.scan).toEqual({ stepId: historyScanStepId, fact: expect.objectContaining({ tool: 'betterleaks', format: 'sarif' }) });
    const [, , scrub, upload] = b.steps as RenderedStep[];
    expect(scrub?.with).toMatchObject({ mode: 'scrub', artifact: H, tool: 'betterleaks', format: 'sarif' });
    expect(scrub?.with?.stage).toBeUndefined();
    expect(upload?.with).toMatchObject({ name: H });
    expect(b.steps).toHaveLength(4);
    expect(renderRangeBlock(entry('betterleaks'), p, GATE).artifact).toBe(A);
  });

  it('render: the history scan runs only the reviewed betterleaks entry', () => {
    expect(() => renderRangeScan(entry('gitleaks'), 'history')).toThrow(/betterleaks/);
  });
});

/** A git repository in the sandbox's workspace, driven by `git` with a fixed identity. */
function gitOf(sb: Sandbox): (...args: string[]) => string {
  return (...args) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main', ...args], { cwd: sb.ws, encoding: 'utf8' }).trim();
}
const put = (sb: Sandbox, rel: string, content: string): void => { mkdirSync(join(sb.ws, rel, '..'), { recursive: true }); writeFileSync(join(sb.ws, rel), content); };
const commit = (g: ReturnType<typeof gitOf>, msg: string): string => { g('add', '-A', '-f'); g('commit', '-q', '--allow-empty', '-m', msg); return g('rev-parse', 'HEAD'); };
let betterleaks = '';

function scanHistory(sb: Sandbox, head: string): { status: number | null; stderr: string; stdout: string; scrub: ReturnType<typeof scrubFile>; out: string } {
  const dir = join(sb.rt, 'pipegen-bin', H);
  mkdirSync(dir, { recursive: true });
  copyFileSync(betterleaks, join(dir, 'betterleaks'));
  chmodSync(join(dir, 'betterleaks'), 0o755);
  const step = renderHistoryBlock(entry('betterleaks'), p, GATE).steps[1] as RenderedStep;
  const r = spawnSync('bash', ['--noprofile', '--norc', '-c', step.run ?? ''], { cwd: sb.ws, env: { ...stepEnv(step, sb), PIPEGEN_HISTORY_HEAD: head }, encoding: 'utf8' });
  const raw = join(sb.rt, 'pipegen-raw', H, 'betterleaks.sarif');
  const out = join(sb.rt, 'pipegen-out', H, 'betterleaks.sarif');
  return { status: r.status, stderr: r.stderr, stdout: r.stdout, scrub: scrubFile({ artifact: H, tool: 'betterleaks', format: 'sarif', raw, out, fpKey: FPKEY, workspace: sb.ws, eventText: '{}' }), out };
}

describe.skipIf(!live)('live: the full-history scan, the pinned betterleaks 1.9.0 through the rendered step', () => {
  beforeAll(async () => { betterleaks = await ensurePinnedBinary('betterleaks'); }, 600_000);

  it('live history: a key added and removed in the first commits, and one only on another branch, are reported at their commits; the facts are the history form', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'config.js', line(1));
    const c0 = commit(g, 'the first commit holds a key');
    g('rm', '-q', 'config.js');
    commit(g, 'removed');
    g('checkout', '-q', '-b', 'feature');
    put(sb, 'side.js', line(2));
    const side = commit(g, 'a key on another branch');
    g('checkout', '-q', 'main');
    put(sb, 'a.txt', 'more\n');
    const head = commit(g, 'main moves on');
    const o = scanHistory(sb, head);
    expect(o.status, o.stderr + o.stdout).toBe(0);
    expect(o.scrub.status, o.scrub.error).toBe('ok');
    const back = readScrubbed(readFileSync(o.out), 'sarif');
    expect(back.findings.map((f) => [f.file, f.commit, f.ruleId]).sort()).toEqual([['config.js', c0, `${SEC}shopify-access-token`], ['side.js', side, `${SEC}shopify-access-token`]].sort());
    expect(back.notes.join('\n')).toMatch(new RegExp(`whole history up to ${head.slice(0, 12)} \\(4 commit`));
    const facts = JSON.parse(readFileSync(join(sb.rt, 'pipegen-raw', H, 'range.json'), 'utf8')) as Record<string, unknown>;
    expect(Object.keys(facts).sort()).toEqual(['canaries', 'commits', 'head', 'history', 'pipegenRange']);
    expect(facts).toMatchObject({ pipegenRange: 1, history: true, head, commits: 4 });
  }, 120_000);

  it('live history: a clean history gives no finding; a head that is not a commit sha, or not in the checkout, fails the step', () => {
    const sb = sandbox();
    const g = gitOf(sb);
    g('init', '-q');
    put(sb, 'a.txt', 'clean\n');
    const head = commit(g, 'clean');
    const o = scanHistory(sb, head);
    expect(o.status, o.stderr + o.stdout).toBe(0);
    expect(o.scrub.status === 'ok' && o.scrub.findings).toBe(0);
    for (const bad of ['main', 'HEAD~0', 'e'.repeat(40), '0'.repeat(40)]) {
      const sb2 = sandbox();
      const g2 = gitOf(sb2);
      g2('init', '-q');
      put(sb2, 'a.txt', 'x\n');
      commit(g2, 'x');
      const r = scanHistory(sb2, bad);
      expect(r.status, bad).not.toBe(0);
      expect(r.scrub.status, bad).toBe('tool-error');
    }
  }, 120_000);
});
