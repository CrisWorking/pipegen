// C9 (Plan C final review, Important 2), the engine half, written first (strict test-first): the secrets job also scans the pull
// request's own commits. A second betterleaks run in `git` mode over the event's range (the event-switched base and head forms), the whole
// history (fetch-depth 0), pipegen's pinned config with the canary rule and no path allowlist (prefilter false: git mode applies it,
// measured), --max-archive-depth 0, --redact, exit code 10. Its result goes through the same scrub chain under its own artifact
// (resultArtifactName('secrets-range')) with its own job-list entry (`range: true`). The referee and the job rules recognise the exact step
// (kind checker) by its content.
// Fix round 1 (review-C9.md, task-C9-fix-round-1.md): ONE ordered stream (betterleaks single mode, `--reverse --remerge-diff --text`): the
// two canary commits on the head are dated last, so the tip canary is the stream's last commit and finding it proves the stream was read to
// its end (I1); merges are in the stream with only what their own resolution added (I3); on a synchronize the commits a force-push dropped
// (`before`) are in it too (I2); an event with no range skips with a note.
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { resultArtifactName, SECRETS_RANGE_ARTIFACT } from '../src/engine/artifact-names.js';
import { gateJobList, type JobListEntry } from '../src/engine/gate-job-list.js';
import { checkExpressions, checkJobOrder, isKnownHarmless, jobOutputsFor, type ScanFact } from '../src/engine/job-rules.js';
import { RenderError, renderFindingsBlock, renderJobPrelude, renderRangeBlock, type RenderedStep } from '../src/engine/render-step.js';
import { BASE_CHECKOUT_REF, jobListLiteralProblem, RANGE_BEFORE_REF, RANGE_HEAD_REF, rangeScanStepId, sha16 } from '../src/engine/tool-flags.js';
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

  it('the scan: the base, head and before forms in its env (and nothing the job rules would refuse), pipegen\'s config with no path allowlist and the canary rule', () => {
    expect(scan.env?.PIPEGEN_RANGE_BASE).toBe(BASE_CHECKOUT_REF);
    expect(scan.env?.PIPEGEN_RANGE_HEAD).toBe(RANGE_HEAD_REF);
    expect(scan.env?.PIPEGEN_RANGE_BEFORE).toBe(RANGE_BEFORE_REF);
    expect(() => checkExpressions(scan)).not.toThrow();
    const cfg = scan.env?.PIPEGEN_CONFIG ?? '';
    expect(cfg.startsWith("prefilter = '''false'''\n\n[extend]\nuseDefault = true\n")).toBe(true);
    expect(cfg).toContain(entry('betterleaks').fixedInputs.config?.content as string);
    expect(cfg).toContain('id = "pipegen-canary"');
    const r = scan.run ?? '';
    // fix round 1 (I1, I3): one ordered stream (single mode), merges with their own resolution, every file as text
    for (const w of ['"$bin/betterleaks" git', '--git-workers 0', '--reverse --remerge-diff --text', '--max-archive-depth 0', '--redact', '--exit-code 10', '--ignore-gitleaks-allow', '--log-level info', '--no-color', 'commit-tree', '/usr/bin/env -i', 'git version']) expect(r, w).toContain(w);
    // the parallel mode's count and its workarounds are gone, and so is --no-merges
    for (const w of ['--no-merges', '--git-workers 2', 'commits=', 'info/attributes', '^T']) expect(r, w).not.toContain(w);
    expect(r).not.toContain('${{');
  });

  it('a step env changed by hand (another base, head or before form, an extra expression) is refused by the expression rule', () => {
    expect(() => checkExpressions({ ...scan, env: { ...scan.env, PIPEGEN_RANGE_BASE: '${{ github.event.pull_request.head.sha }}' } })).toThrow(RenderError);
    expect(() => checkExpressions({ ...scan, env: { ...scan.env, PIPEGEN_RANGE_HEAD: BASE_CHECKOUT_REF } })).toThrow(RenderError);
    expect(() => checkExpressions({ ...scan, env: { ...scan.env, PIPEGEN_RANGE_BEFORE: '${{ github.event.before }}' } })).toThrow(RenderError);
    expect(() => checkExpressions({ ...scan, env: { ...scan.env, PIPEGEN_OTHER: BASE_CHECKOUT_REF } })).toThrow(RenderError);
    // the forms only on the range scan's own step
    expect(() => checkExpressions({ ...scan, id: `checker-run-${sha16('pipegen-out-secrets')}` })).toThrow(RenderError);
  });

  it('the before form: a pull request\'s previous head on synchronize only, else the all-zero commit', () => {
    expect(RANGE_BEFORE_REF).toBe(`\${{ github.event_name == 'pull_request' && github.event.action == 'synchronize' && github.event.before || '${ZERO}' }}`);
  });

  it('only the reviewed betterleaks entry: another tool, an unreviewed copy or a gate entry that fixes an input is refused', () => {
    expect(() => renderRangeBlock(entry('gitleaks'), p, GATE)).toThrow(RenderError);
    expect(() => renderRangeBlock({ ...entry('betterleaks'), candidate: { ...entry('betterleaks').candidate, reviewed: false as never } }, p, GATE)).toThrow(RenderError);
    expect(() => renderRangeBlock(entry('betterleaks'), p, { ...GATE, choices: { mode: ['x'] } })).toThrow(RenderError);
  });
});

// ---------- the scan step itself, run in a sandbox with a stand-in for betterleaks (no network) ----------

const git = (dir: string, ...args: string[]): string => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], { cwd: dir, encoding: 'utf8' }).trim();
/** The workspace: a repository with a base commit and `n` commits after it. */
function repo(sb: Sandbox, n: number): { base: string; head: string } {
  git(sb.ws, 'init', '-q', '-b', 'main');
  writeFileSync(join(sb.ws, 'a.txt'), 'base\n');
  git(sb.ws, 'add', '-A');
  git(sb.ws, 'commit', '-q', '-m', 'base');
  const base = git(sb.ws, 'rev-parse', 'HEAD');
  for (let i = 0; i < n; i++) {
    writeFileSync(join(sb.ws, `f${i}.txt`), `c${i}\n`);
    git(sb.ws, 'add', '-A');
    git(sb.ws, 'commit', '-q', '-m', `c${i}`);
  }
  return { base, head: git(sb.ws, 'rev-parse', 'HEAD') };
}
/** A stand-in for betterleaks: records its argv, cwd and the folder's names, writes an empty SARIF to --report-path; exits with `rc`. */
function fakeBetterleaks(sb: Sandbox, rc = 10): void {
  const dir = join(sb.rt, 'pipegen-bin', A);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(sb.rt, 'fake-rc'), String(rc));
  const path = join(dir, 'betterleaks');
  writeFileSync(path, [
    '#!/bin/bash',
    'printf "%s\\0" "$@" > "$RUNNER_TEMP/fake-argv"; pwd > "$RUNNER_TEMP/fake-cwd"; ls -A > "$RUNNER_TEMP/fake-ls"',
    'out=""; prev=""; for a in "$@"; do [ "$prev" = --report-path ] && out="$a"; prev="$a"; done',
    'printf \'{"version":"2.1.0","runs":[]}\' > "$out"',
    'exit "$(cat "$RUNNER_TEMP/fake-rc")"',
  ].join('\n'));
  chmodSync(path, 0o755);
}
interface Range { base: string; head: string; before?: string }
function tryScan(sb: Sandbox, range: Range): { status: number | null; stdout: string; stderr: string } {
  const scan = renderRangeBlock(entry('betterleaks'), p, GATE).steps[1] as RenderedStep;
  const env = { ...stepEnv(scan, sb), PIPEGEN_RANGE_BASE: range.base, PIPEGEN_RANGE_HEAD: range.head, PIPEGEN_RANGE_BEFORE: range.before ?? ZERO };
  const r = spawnSync('bash', ['--noprofile', '--norc', '-c', scan.run ?? ''], { cwd: sb.ws, env, encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout, stderr: r.status === 0 ? '' : r.stderr };
}
const rawDir = (sb: Sandbox): string => join(sb.rt, 'pipegen-raw', A);
const logOpts = (sb: Sandbox): string => { const argv = readFileSync(join(sb.rt, 'fake-argv'), 'utf8').split('\0').slice(0, -1); return argv[argv.indexOf('--log-opts') + 1] as string; };
const LO_RE = /^--reverse --remerge-diff --text \^([0-9a-f]{40}) ([0-9a-f]{40})(?: ([0-9a-f]{40}))?$/;

describe('the range scan step (a stand-in scanner): one ordered stream, the tip canary last, the dropped commits, the ignore files', () => {
  it('a range of n commits: the scanner reads ^base <tip canary> in one reversed stream, from an empty folder naming the checkout\'s git folder; raw result and range.json', () => {
    const sb = sandbox();
    const r = repo(sb, 1);
    fakeBetterleaks(sb);
    expect(tryScan(sb, r)).toMatchObject({ status: 0, stderr: '' });
    const argv = readFileSync(join(sb.rt, 'fake-argv'), 'utf8').split('\0').slice(0, -1);
    expect(argv[0]).toBe('git');
    expect(argv.at(-1)).toBe('.');
    const m = LO_RE.exec(logOpts(sb));
    expect(m?.[1]).toBe(r.base);
    expect(m?.[3]).toBeUndefined();
    // the scanner's folder holds only the git file: the checkout's .betterleaksignore / .gitleaksignore are never read
    expect(readFileSync(join(sb.rt, 'fake-ls'), 'utf8').trim()).toBe('.git');
    expect(readFileSync(join(sb.rt, 'fake-cwd'), 'utf8').trim().startsWith(join(sb.rt, 'pipegen-work', A))).toBe(true);
    // two canary commits on the head, each adding only its canary file to its parent's tree; local objects only (no ref names them)
    const c2 = m?.[2] as string;
    const c1 = git(sb.ws, 'rev-parse', `${c2}~1`);
    expect(git(sb.ws, 'rev-parse', `${c2}~2`)).toBe(r.head);
    expect(git(sb.ws, 'diff', '--name-status', r.head, c1)).toBe('A\tpipegen-range-canary-1.txt');
    expect(git(sb.ws, 'diff', '--name-status', c1, c2)).toBe('A\tpipegen-range-canary-2.txt');
    expect(git(sb.ws, 'show', `${c2}:pipegen-range-canary-2.txt`)).toMatch(/^pipegen-canary-[0-9a-f]{32}$/);
    expect(git(sb.ws, 'for-each-ref', '--contains', c2)).toBe('');
    // the stream's order: the two canaries come last, the tip canary at the very end
    expect(git(sb.ws, 'rev-list', '--reverse', `^${r.base}`, c2).split('\n').slice(-2)).toEqual([c1, c2]);
    // the raw result and the range facts the scrub reads; no info/attributes any more (--text)
    expect(existsSync(join(sb.ws, '.git', 'info', 'attributes'))).toBe(false);
    expect(readdirSync(rawDir(sb)).sort()).toEqual(['betterleaks.sarif', 'range.json']);
    const facts = JSON.parse(readFileSync(join(rawDir(sb), 'range.json'), 'utf8')) as Record<string, unknown>;
    expect(facts).toEqual({ pipegenRange: 1, base: r.base, head: r.head, before: null, commits: 1, canaries: [{ commit: c1, path: 'pipegen-range-canary-1.txt' }, { commit: c2, path: 'pipegen-range-canary-2.txt' }] });
  });

  it('merges count: a merge inside the range is in the stream (its own resolution, --remerge-diff) and in the commit count', () => {
    const sb = sandbox();
    const r = repo(sb, 1);
    git(sb.ws, 'checkout', '-q', '-b', 'side', r.base);
    writeFileSync(join(sb.ws, 's.txt'), 's\n');
    git(sb.ws, 'add', '-A');
    git(sb.ws, 'commit', '-q', '-m', 'side');
    git(sb.ws, 'checkout', '-q', 'main');
    git(sb.ws, 'merge', '-q', '--no-edit', 'side');
    const head = git(sb.ws, 'rev-parse', 'HEAD');
    fakeBetterleaks(sb);
    expect(tryScan(sb, { base: r.base, head }).status).toBe(0);
    expect((JSON.parse(readFileSync(join(rawDir(sb), 'range.json'), 'utf8')) as { commits: number }).commits).toBe(3);   // c0, side, the merge
  });

  it('a commit dated after the canaries on another line of the stream (a dropped commit) puts the tip canary out of last place: the step fails (fail closed)', () => {
    const sb = sandbox();
    const r = repo(sb, 1);
    writeFileSync(join(sb.ws, 'late.txt'), 'x\n');
    git(sb.ws, 'add', '-A');
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'from the future'], { cwd: sb.ws, env: { ...process.env, GIT_COMMITTER_DATE: '@4200000000 +0000', GIT_AUTHOR_DATE: '@4200000000 +0000' } });
    const future = git(sb.ws, 'rev-parse', 'HEAD');
    git(sb.ws, 'reset', '-q', '--hard', 'HEAD~1');
    fakeBetterleaks(sb);
    const x = tryScan(sb, { ...r, before: future });
    expect(x.status).toBe(1);
    expect(x.stderr).toMatch(/not the last commit/);
    expect(existsSync(join(sb.rt, 'fake-argv'))).toBe(false);
    // on the head's own line a later date can not pass the canaries (a child is never listed after its parent)
    const own = sandbox();
    const r2 = repo(own, 1);
    writeFileSync(join(own.ws, 'late.txt'), 'x\n');
    git(own.ws, 'add', '-A');
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'from the future'], { cwd: own.ws, env: { ...process.env, GIT_COMMITTER_DATE: '@4200000000 +0000', GIT_AUTHOR_DATE: '@4200000000 +0000' } });
    fakeBetterleaks(own);
    expect(tryScan(own, { base: r2.base, head: git(own.ws, 'rev-parse', 'HEAD') }).status).toBe(0);
  });

  it('I2: on a synchronize after a force-push, the commits the push dropped are in the stream (before, read from the checkout); a before that is an ancestor changes nothing', () => {
    const sb = sandbox();
    const r = repo(sb, 1);
    writeFileSync(join(sb.ws, 'k.txt'), 'dropped\n');
    git(sb.ws, 'add', '-A');
    git(sb.ws, 'commit', '-q', '-m', 'pushed, then amended away');
    const dropped = git(sb.ws, 'rev-parse', 'HEAD');
    git(sb.ws, 'reset', '-q', '--hard', 'HEAD~1');
    writeFileSync(join(sb.ws, 'k.txt'), 'amended\n');
    git(sb.ws, 'add', '-A');
    git(sb.ws, 'commit', '-q', '-m', 'the amend');
    const head = git(sb.ws, 'rev-parse', 'HEAD');
    fakeBetterleaks(sb);
    expect(tryScan(sb, { base: r.base, head, before: dropped }).status).toBe(0);
    expect(LO_RE.exec(logOpts(sb))?.[3]).toBe(dropped);
    const facts = JSON.parse(readFileSync(join(rawDir(sb), 'range.json'), 'utf8')) as { before: string; commits: number };
    expect(facts.before).toBe(dropped);
    expect(facts.commits).toBe(3);   // c0, the amend, the dropped commit
    // a normal push: before is the previous head, an ancestor of head: the same commits
    const ok = sandbox();
    const r2 = repo(ok, 2);
    fakeBetterleaks(ok);
    expect(tryScan(ok, { ...r2, before: git(ok.ws, 'rev-parse', 'HEAD~1') }).status).toBe(0);
    expect((JSON.parse(readFileSync(join(rawDir(ok), 'range.json'), 'utf8')) as { commits: number }).commits).toBe(2);
  });

  it('I2: a before that is not in the checkout and can not be fetched fails the step (the gate blocks)', () => {
    const sb = sandbox();
    const r = repo(sb, 1);
    fakeBetterleaks(sb);
    const x = tryScan(sb, { ...r, before: 'e'.repeat(40) });
    expect(x.status).toBe(1);
    expect(x.stderr).toMatch(/could not be fetched/);
    expect(existsSync(rawDir(sb))).toBe(false);
  });

  it('a scanner error exit (1: a partial scan) fails the step with that code; 0 and 10 are a scan that worked', () => {
    const sb = sandbox();
    const r = repo(sb, 2);
    fakeBetterleaks(sb, 1);
    expect(tryScan(sb, r).status).toBe(1);
    expect(existsSync(rawDir(sb))).toBe(false);
    const ok = sandbox();
    fakeBetterleaks(ok, 0);
    expect(tryScan(ok, repo(ok, 2)).status).toBe(0);
  });

  it('no range on this event (an all-zero base or head: a new branch, workflow_dispatch, schedule): the step skips with a note and the facts say so, no scan', () => {
    for (const edit of [(r: Range) => ({ ...r, base: ZERO }), (r: Range) => ({ ...r, head: ZERO })]) {
      const sb = sandbox();
      const r = repo(sb, 1);
      fakeBetterleaks(sb);
      const x = tryScan(sb, edit(r));
      expect(x.status).toBe(0);
      expect(x.stdout + x.stderr).toMatch(/no commit range/);
      expect(existsSync(join(sb.rt, 'fake-argv'))).toBe(false);
      expect(readdirSync(rawDir(sb))).toEqual(['range.json']);
      expect(JSON.parse(readFileSync(join(rawDir(sb), 'range.json'), 'utf8'))).toEqual({ pipegenRange: 1, skipped: 'no-range' });
    }
  });

  it('a value that is not a commit (also 40 characters that git would resolve), or a commit not in the checkout (a shallow clone), fails the step', () => {
    for (const [what, edit] of [
      ['not hex', (r: Range) => ({ ...r, base: 'main' })],
      ['40 characters git resolves', (r: Range) => ({ ...r, base: `HEAD~${'0'.repeat(35)}` })],
      ['injection', (r: Range) => ({ ...r, head: `${r.head};id` })],
      ['before not hex', (r: Range) => ({ ...r, before: `HEAD~${'0'.repeat(35)}` })],
      ['missing', (r: Range) => ({ ...r, base: 'e'.repeat(40) })],
    ] as const) {
      const sb = sandbox();
      const r = repo(sb, 1);
      fakeBetterleaks(sb);
      const x = tryScan(sb, edit(r));
      expect(x.status, what).toBe(1);
      expect(existsSync(join(sb.rt, 'fake-argv')), what).toBe(false);
    }
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

  it('without the range block, with the range scan edited (no --remerge-diff), or with a depth-1 secrets checkout, it is refused', async () => {
    const d = draftOf();
    const none = await run([workflow(jobsOf(d, { range: false }))], d);
    expect(none.ok, show(none)).toBe(false);
    expect(show(none)).toMatch(/secrets-range|range/);
    const all = jobsOf(d);
    const r1 = await run([workflow(editSteps(all, SEC_JOB, (s) => (s.id === rangeScanStepId ? { ...s, run: (s.run ?? '').replace('--remerge-diff ', '') } : s)))], d);
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
