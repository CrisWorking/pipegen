// C9 (Plan C final review, Important 2), the engine half, written first (strict test-first): the secrets job also scans the pull
// request's own commits. A second betterleaks run in `git` mode over base..head (the event-switched base and head forms), --no-merges,
// the whole history (fetch-depth 0), pipegen's pinned config with the canary rule and no path allowlist (prefilter false: git mode applies
// it, measured), --max-archive-depth 0, --redact, exit code 10. Its result goes through the same scrub chain under its own artifact
// (resultArtifactName('secrets-range')) with its own job-list entry (`range: true`). The referee and the job rules recognise the exact step
// (kind checker) by its content. Completeness: the scanner's own count of the commits it scanned must equal `git rev-list --count
// --no-merges` of the range, computed in the same step; betterleaks prints that count only in its parallel mode with two commits or more
// (measured), so the step adds two canary commits on the head (local objects, never pushed), whose canary lines also prove the scanner read
// the commits with pipegen's config.
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { resultArtifactName, SECRETS_RANGE_ARTIFACT } from '../src/engine/artifact-names.js';
import { gateJobList, type JobListEntry } from '../src/engine/gate-job-list.js';
import { checkExpressions, checkJobOrder, isKnownHarmless, jobOutputsFor, type ScanFact } from '../src/engine/job-rules.js';
import { RenderError, renderFindingsBlock, renderJobPrelude, renderRangeBlock, type RenderedStep } from '../src/engine/render-step.js';
import { BASE_CHECKOUT_REF, jobListLiteralProblem, RANGE_HEAD_REF, rangeScanStepId, sha16 } from '../src/engine/tool-flags.js';
import { draftOf, editSteps, GATE, jobsOf, p, run, SEC_JOB, show, workflow, type Job } from './helpers/gate-pipeline.js';
import { entry, specFor } from './helpers/render.js';
import { sandbox, stepEnv, type Sandbox } from './helpers/step-harness.js';

const A = SECRETS_RANGE_ARTIFACT;
const ZERO = '0'.repeat(40);
const K_NS = ['needs', 'Sec' + 'rets'].join('') as 'needsSecrets';

describe('the range artifact and the event-switched head form', () => {
  it('the artifact is resultArtifactName("secrets-range"); the head form names each event\'s head, and the all-zero commit on any other event', () => {
    expect(A).toBe(resultArtifactName('secrets-range'));
    expect(A).toBe('pipegen-out-secrets-range');
    for (const part of ["github.event_name == 'pull_request' && github.event.pull_request.head.sha", "github.event_name == 'pull_request_review' && github.event.pull_request.head.sha",
      "github.event_name == 'merge_group' && github.event.merge_group.head_sha", "github.event_name == 'push' && github.event.after", `'${ZERO}'`]) expect(RANGE_HEAD_REF).toContain(part);
    expect(RANGE_HEAD_REF.startsWith('${{ ') && RANGE_HEAD_REF.endsWith(' }}')).toBe(true);
  });
});

describe('renderRangeBlock: install, the range scan (checker), scrub, upload', () => {
  const block = renderRangeBlock(entry('betterleaks'), p, GATE);
  const [install, scan, scrub, upload] = block.steps as [RenderedStep, RenderedStep, RenderedStep, RenderedStep];

  it('four steps tied by the hash of the artifact; the scan is a checker step and known harmless; the scrub has no stage (the history is not staged)', () => {
    expect(block.steps).toHaveLength(4);
    expect(block.artifact).toBe(A);
    expect(install.id).toBe(`tool-install-${sha16(A)}`);
    expect(scan.id).toBe(rangeScanStepId);
    expect(scan.id).toBe(`checker-run-${sha16(A)}`);
    expect(isKnownHarmless(scan)).toBe(true);
    expect(block.scan).toEqual({ stepId: scan.id, fact: { tool: 'betterleaks', format: 'sarif' } });
    expect(scrub.with).toMatchObject({ mode: 'scrub', artifact: A, tool: 'betterleaks', format: 'sarif', raw: `\${{ runner.temp }}/pipegen-raw/${A}/betterleaks.sarif`, out: `\${{ runner.temp }}/pipegen-out/${A}/betterleaks.sarif` });
    expect(Object.hasOwn(scrub.with ?? {}, 'stage')).toBe(false);
    expect(upload.with).toMatchObject({ name: A, path: `\${{ runner.temp }}/pipegen-out/${A}/betterleaks.sarif` });
    expect(block.result.fullHistory).toBe(true);
  });

  it('the scan: the base and head forms in its env (and nothing the job rules would refuse), pipegen\'s config with no path allowlist and the canary rule', () => {
    expect(scan.env?.PIPEGEN_RANGE_BASE).toBe(BASE_CHECKOUT_REF);
    expect(scan.env?.PIPEGEN_RANGE_HEAD).toBe(RANGE_HEAD_REF);
    expect(() => checkExpressions(scan)).not.toThrow();
    const cfg = scan.env?.PIPEGEN_CONFIG ?? '';
    expect(cfg.startsWith("prefilter = '''false'''\n\n[extend]\nuseDefault = true\n")).toBe(true);
    expect(cfg).toContain(entry('betterleaks').fixedInputs.config?.content as string);
    expect(cfg).toContain('id = "pipegen-canary"');
    const r = scan.run ?? '';
    for (const w of ['"$bin/betterleaks" git', '--no-merges', '--git-workers 2', '--max-archive-depth 0', '--redact', '--exit-code 10', '--ignore-gitleaks-allow', '--log-level info', '--no-color', 'rev-list --count --no-merges', '* diff', 'commit-tree', '/usr/bin/env -i']) expect(r, w).toContain(w);
    expect(r).not.toContain('${{');
  });

  it('a step env changed by hand (another base form, an extra expression) is refused by the expression rule', () => {
    expect(() => checkExpressions({ ...scan, env: { ...scan.env, PIPEGEN_RANGE_BASE: '${{ github.event.pull_request.head.sha }}' } })).toThrow(RenderError);
    expect(() => checkExpressions({ ...scan, env: { ...scan.env, PIPEGEN_RANGE_HEAD: BASE_CHECKOUT_REF } })).toThrow(RenderError);
    expect(() => checkExpressions({ ...scan, env: { ...scan.env, PIPEGEN_OTHER: BASE_CHECKOUT_REF } })).toThrow(RenderError);
    // the forms only on the range scan's own step
    expect(() => checkExpressions({ ...scan, id: `checker-run-${sha16('pipegen-out-secrets')}` })).toThrow(RenderError);
  });

  it('only the reviewed betterleaks entry: another tool, an unreviewed copy or a gate entry that fixes an input is refused', () => {
    expect(() => renderRangeBlock(entry('gitleaks'), p, GATE)).toThrow(RenderError);
    expect(() => renderRangeBlock({ ...entry('betterleaks'), candidate: { ...entry('betterleaks').candidate, reviewed: false as never } }, p, GATE)).toThrow(RenderError);
    expect(() => renderRangeBlock(entry('betterleaks'), p, { ...GATE, choices: { mode: ['x'] } })).toThrow(RenderError);
  });
});

// ---------- the scan step itself, run in a sandbox with a stand-in for betterleaks (no network) ----------

const git = (dir: string, ...args: string[]): string => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], { cwd: dir, encoding: 'utf8' }).trim();
/** The workspace: a repository with a base commit and `n` commits after it (one of them a type change when asked). */
function repo(sb: Sandbox, n: number, typeChange = false): { base: string; head: string } {
  git(sb.ws, 'init', '-q', '-b', 'main');
  writeFileSync(join(sb.ws, 'a.txt'), 'base\n');
  if (typeChange) execFileSync('ln', ['-s', 'a.txt', 'x'], { cwd: sb.ws });
  git(sb.ws, 'add', '-A');
  git(sb.ws, 'commit', '-q', '-m', 'base');
  const base = git(sb.ws, 'rev-parse', 'HEAD');
  for (let i = 0; i < n; i++) {
    if (typeChange && i === 0) { execFileSync('rm', ['x'], { cwd: sb.ws }); writeFileSync(join(sb.ws, 'x'), 'now a file\n'); } else writeFileSync(join(sb.ws, `f${i}.txt`), `c${i}\n`);
    git(sb.ws, 'add', '-A');
    git(sb.ws, 'commit', '-q', '-m', `c${i}`);
  }
  return { base, head: git(sb.ws, 'rev-parse', 'HEAD') };
}
/**
 * A stand-in for betterleaks: records its argv, cwd and the folder's names, writes an empty SARIF to --report-path and prints the parallel
 * count line with the number in $RUNNER_TEMP/fake-count (none when that file says `none`); exits with the code in $RUNNER_TEMP/fake-rc.
 */
function fakeBetterleaks(sb: Sandbox, count: string, rc = 10): void {
  const dir = join(sb.rt, 'pipegen-bin', A);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(sb.rt, 'fake-count'), count);
  writeFileSync(join(sb.rt, 'fake-rc'), String(rc));
  const path = join(dir, 'betterleaks');
  writeFileSync(path, [
    '#!/bin/bash',
    'printf "%s\\0" "$@" > "$RUNNER_TEMP/fake-argv"; pwd > "$RUNNER_TEMP/fake-cwd"; ls -A > "$RUNNER_TEMP/fake-ls"',
    'out=""; prev=""; for a in "$@"; do [ "$prev" = --report-path ] && out="$a"; prev="$a"; done',
    'printf \'{"version":"2.1.0","runs":[]}\' > "$out"',
    'c="$(cat "$RUNNER_TEMP/fake-count")"',
    '[ "$c" = none ] || echo "3:04PM INF parallel git scan chunk_size=1 commits=$c workers=2" >&2',
    'echo "3:04PM INF scanned ~1 bytes (1 bytes) in 1ms" >&2',
    'exit "$(cat "$RUNNER_TEMP/fake-rc")"',
  ].join('\n'));
  chmodSync(path, 0o755);
}
function tryScan(sb: Sandbox, range: { base: string; head: string }): { status: number | null; stderr: string } {
  const scan = renderRangeBlock(entry('betterleaks'), p, GATE).steps[1] as RenderedStep;
  const env = { ...stepEnv(scan, sb), PIPEGEN_RANGE_BASE: range.base, PIPEGEN_RANGE_HEAD: range.head };
  const r = spawnSync('bash', ['--noprofile', '--norc', '-c', scan.run ?? ''], { cwd: sb.ws, env, encoding: 'utf8' });
  return { status: r.status, stderr: r.status === 0 ? '' : r.stderr };
}
const rawDir = (sb: Sandbox): string => join(sb.rt, 'pipegen-raw', A);

describe('the range scan step (a stand-in scanner): the count, the canaries, the attributes, the ignore files', () => {
  it('a range of n commits: the scanner is told --no-merges base..<second canary>, from an empty folder naming the checkout\'s git folder; the count n+2 matches; raw result and range.json', () => {
    const sb = sandbox();
    const r = repo(sb, 1);
    fakeBetterleaks(sb, '3');
    expect(tryScan(sb, r)).toEqual({ status: 0, stderr: '' });
    const argv = readFileSync(join(sb.rt, 'fake-argv'), 'utf8').split('\0').slice(0, -1);
    expect(argv[0]).toBe('git');
    const lo = argv[argv.indexOf('--log-opts') + 1] as string;
    const m = /^--no-merges ([0-9a-f]{40})\.\.([0-9a-f]{40})$/.exec(lo);
    expect(m?.[1]).toBe(r.base);
    expect(argv.at(-1)).toBe('.');
    // the scanner's folder holds only the git file: the checkout's .betterleaksignore / .gitleaksignore are never read
    expect(readFileSync(join(sb.rt, 'fake-ls'), 'utf8').trim()).toBe('.git');
    expect(readFileSync(join(sb.rt, 'fake-cwd'), 'utf8').trim().startsWith(join(sb.rt, 'pipegen-work', A))).toBe(true);
    // the two canary commits sit on the head, each adding its canary file; they are local objects only (no ref names them)
    const c2 = m?.[2] as string;
    expect(git(sb.ws, 'rev-parse', `${c2}~2`)).toBe(r.head);
    expect(git(sb.ws, 'show', '--format=', '--name-only', c2)).toContain('pipegen-range-canary-2.txt');
    expect(git(sb.ws, 'show', `${c2}:pipegen-range-canary-2.txt`)).toMatch(/^pipegen-canary-[0-9a-f]{32}$/);
    expect(git(sb.ws, 'for-each-ref', '--contains', c2)).toBe('');
    // every file is text to the diff (the checkout's .gitattributes can not hide one as binary)
    expect(readFileSync(join(sb.ws, '.git', 'info', 'attributes'), 'utf8')).toBe('* diff\n');
    // the raw result and the range facts the scrub reads
    expect(readdirSync(rawDir(sb)).sort()).toEqual(['betterleaks.sarif', 'range.json']);
    const facts = JSON.parse(readFileSync(join(rawDir(sb), 'range.json'), 'utf8')) as Record<string, unknown>;
    expect(facts).toEqual({ pipegenRange: 1, base: r.base, head: r.head, commits: 1, canaries: [{ commit: git(sb.ws, 'rev-parse', `${c2}~1`), path: 'pipegen-range-canary-1.txt' }, { commit: c2, path: 'pipegen-range-canary-2.txt' }] });
  });

  it('a count that differs from the range, or no count at all, fails the step and leaves no raw result (the scrub then reports a tool error)', () => {
    for (const count of ['4', '2', 'none']) {
      const sb = sandbox();
      const r = repo(sb, 1);
      fakeBetterleaks(sb, count);
      const x = tryScan(sb, r);
      expect(x.status, count).toBe(1);
      expect(x.stderr, count).toMatch(count === 'none' ? /did not report how many commits it scanned/ : /scanned \d+ commits, but the range/);
      expect(existsSync(rawDir(sb)), count).toBe(false);
    }
  });

  it('a scanner error exit (1: a partial scan) fails the step with that code; 0 and 10 are a scan that worked', () => {
    const sb = sandbox();
    const r = repo(sb, 2);
    fakeBetterleaks(sb, '4', 1);
    expect(tryScan(sb, r).status).toBe(1);
    expect(existsSync(rawDir(sb))).toBe(false);
    const ok = sandbox();
    fakeBetterleaks(ok, '4', 0);
    expect(tryScan(ok, repo(ok, 2)).status).toBe(0);
  });

  it('no range: the all-zero base (a new branch, another event), a value that is not a commit, or a commit not in the checkout (a shallow clone) fails the step', () => {
    for (const [what, edit] of [
      ['zero base', (r: { base: string; head: string }) => ({ ...r, base: ZERO })],
      ['zero head', (r: { base: string; head: string }) => ({ ...r, head: ZERO })],
      ['not hex', (r: { base: string; head: string }) => ({ ...r, base: 'main' })],
      ['injection', (r: { base: string; head: string }) => ({ ...r, head: `${r.head};id` })],
      ['missing', (r: { base: string; head: string }) => ({ ...r, base: 'e'.repeat(40) })],
    ] as const) {
      const sb = sandbox();
      const r = repo(sb, 1);
      fakeBetterleaks(sb, '3');
      const x = tryScan(sb, edit(r));
      expect(x.status, what).toBe(1);
      expect(existsSync(join(sb.rt, 'fake-argv')), what).toBe(false);
    }
  });

  it('a commit of the range that changes a file\'s type (a link that becomes a file) fails the step: the scanner\'s parallel mode skips type changes (measured)', () => {
    const sb = sandbox();
    const r = repo(sb, 2, true);
    fakeBetterleaks(sb, '4');
    const x = tryScan(sb, r);
    expect(x.status).toBe(1);
    expect(x.stderr).toMatch(/type/);
  });
});

// ---------- the job list ----------

describe('gateJobList and the job list schema: the range entry', () => {
  it('a draft with a secrets result gets the range entry right after it: same need and job, betterleaks, sarif, its own artifact, no base artifact, range: true', () => {
    const list = gateJobList(draftOf());
    const at = list.findIndex((e) => e.needId === 'secrets' && e.range !== true);
    expect(list[at + 1]).toEqual({ needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks', format: 'sarif', artifact: A, blocking: true, [K_NS]: false, range: true });
    expect(list.filter((e) => e.range === true)).toHaveLength(1);
    expect(jobListLiteralProblem(JSON.stringify(list))).toBeNull();
    // with gitleaks as the HEAD scanner, the range is still betterleaks
    const gl = gateJobList(draftOf({ steps: [specFor(entry('gitleaks'), { needId: 'secrets' })] }));
    expect(gl.find((e) => e.range === true)?.tool).toBe('betterleaks');
    // no secrets result, no range
    expect(gateJobList(draftOf({ steps: [specFor(entry('semgrep'), { needId: 'sast', service: 'app' })] })).some((e) => e.range === true)).toBe(false);
  });

  it('the schema: a range entry only once, only beside the secrets entry of its job, only in its own form; any other entry may not name a job twice', () => {
    const list = gateJobList(draftOf());
    const r = list.find((e) => e.range === true) as JobListEntry;
    const others = list.filter((e) => e.range !== true);
    const bad = (l: unknown[]): string | null => jobListLiteralProblem(JSON.stringify(l));
    expect(bad([...list, r])).not.toBeNull();
    expect(bad(others.concat({ ...r, job: 'sast--app' }))).not.toBeNull();
    expect(bad([...others.filter((e) => e.needId !== 'secrets'), r])).not.toBeNull();
    for (const over of [{ range: false }, { artifact: 'pipegen-out-secrets' }, { baseArtifact: 'pipegen-out-base-secrets-range' }, { tool: 'gitleaks' }, { format: 'none' }, { category: 'sast' }, { needId: 'sast' }, { blocking: false }]) {
      expect(bad([...others, { ...r, ...over }]), JSON.stringify(over)).not.toBeNull();
    }
    expect(bad([...others, { ...r, range: undefined }])).not.toBeNull();   // the same job twice without the marker
  });
});

// ---------- the job rules and the referee ----------

describe('the job rules: the range block sits in the secrets job, after a full-history checkout', () => {
  const sec = renderFindingsBlock(specFor(entry('betterleaks'), { needId: 'secrets' }), entry('betterleaks'), p, { profile: draftOf().profile }, GATE);
  const range = renderRangeBlock(entry('betterleaks'), p, GATE);
  const scans = new Map<string, ScanFact>([[sec.scan.stepId, sec.scan.fact], [range.scan.stepId, range.scan.fact]]);
  const job = (depth: '0' | '1', steps?: RenderedStep[]): RenderedStep[] => steps ?? [...renderJobPrelude({ fetchDepth: depth }, p).steps, ...sec.steps, ...range.steps];

  it('the honest job has no problem; its outputs name both results', () => {
    expect(checkJobOrder(job('0'), { id: 'secrets', scans })).toEqual([]);
    expect(Object.keys(jobOutputsFor(job('0')))).toEqual(expect.arrayContaining([`${A}-sha256`, `${A}-status`, `${A}-error`, 'pipegen-out-secrets-sha256']));
  });

  it('a depth-1 checkout, no checkout before the scan, a range scrub with a stage, or the range scan with another tool fact is a problem', () => {
    expect(checkJobOrder(job('1'), { id: 'secrets', scans }).join('\n')).toMatch(/fetch-depth/);
    const noCheckout = [...sec.steps, ...range.steps];
    expect(checkJobOrder(noCheckout, { id: 'secrets', scans }).join('\n')).toMatch(/fetch-depth|checkout/);
    const staged = job('0').map((s) => (s.id === range.steps[2]?.id ? { ...s, with: { ...s.with, stage: `\${{ runner.temp }}/pipegen-stage/${A}` } } : s));
    expect(checkJobOrder(staged, { id: 'secrets', scans }).join('\n')).toMatch(/stage/);
    const other = new Map(scans);
    other.set(range.scan.stepId, { tool: 'gitleaks', format: 'sarif' });
    expect(checkJobOrder(job('0'), { id: 'secrets', scans: other })).not.toEqual([]);
  });
});

describe('the referee: the full pull-request job set with the range block (parity)', () => {
  it('the honest pipeline passes with 0 issues', async () => {
    const d = draftOf();
    expect(show(await run([workflow(jobsOf(d))], d))).toBe('');
  });

  it('without the range block, with the range scan edited (no --no-merges), or with a depth-1 secrets checkout, it is refused', async () => {
    const d = draftOf();
    const none = await run([workflow(jobsOf(d, { range: false }))], d);
    expect(none.ok, show(none)).toBe(false);
    expect(show(none)).toMatch(/secrets-range|range/);
    const all = jobsOf(d);
    const r1 = await run([workflow(editSteps(all, SEC_JOB, (s) => (s.id === rangeScanStepId ? { ...s, run: (s.run ?? '').replace('--no-merges ', '') } : s)))], d);
    expect(r1.ok, show(r1)).toBe(false);
    // the checkout of the secrets job edited to depth 1 (the renderer itself refuses to build it, so it is edited in the file)
    const shallow = await run([workflow(editSteps(all, SEC_JOB, (s) => (s.with?.['fetch-depth'] === '0' ? { ...s, with: { ...s.with, 'fetch-depth': '1' } } : s)))], d);
    expect(shallow.ok, show(shallow)).toBe(false);
    expect(show(shallow)).toMatch(/fetch-depth/);
    // the range block moved to another job
    const moved = jobsOf(d);
    const rangeSteps = ((moved[SEC_JOB] as Job).steps as RenderedStep[]).slice(-4);
    const elsewhere = { ...moved, [SEC_JOB]: { ...(moved[SEC_JOB] as Job), steps: ((moved[SEC_JOB] as Job).steps as RenderedStep[]).slice(0, -4) } };
    elsewhere['sast--app'] = { ...(moved['sast--app'] as Job), steps: [...((moved['sast--app'] as Job).steps as RenderedStep[]), ...rangeSteps] };
    const r2 = await run([workflow(elsewhere)], d);
    expect(r2.ok, show(r2)).toBe(false);
  });
});
