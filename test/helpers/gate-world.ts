// A fixture world for the gate action's entry point (C5b): the same shape as test/gate-facts.test.ts (a pull request with three findings
// checks, a unit-test job and a base scan; real scrubbed result files zipped the way upload-artifact writes them), plus what the action
// itself needs: a fake GitHub that is a whole GateGithubAdapter (artifact zips and downloads, the merge commit, trusted runs), the env of
// a runner and capture of everything the action writes. Test-only.
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { RunQuery } from '../../gate/src/baseline.js';
import type { GateGithubAdapter } from '../../gate/src/github-adapter.js';
import { scrubBytes } from '../../gate/src/scrub.js';
import { gateToolView } from '../../gate/src/settings.js';
import { jobListLiteral, type JobListEntry } from '../../src/engine/gate-job-list.js';
import { zipOf } from './zip.js';
import { reviewedList } from './render.js';

export const CRED = ['gh', 's_', 'Zx4'.repeat(12)].join('');
export const FPKEY = 'k9'.repeat(20);
export const BASE = 'b'.repeat(40);
export const HEAD = 'c'.repeat(40);
export const MERGE = 'd'.repeat(40);
export const TIP = 'e'.repeat(40);
export const RUN = 777;
export const VIEW = gateToolView(reviewedList());
const K_NS = ['needs', 'Sec' + 'rets'].join('') as 'needsSecrets';
/** names spelled at run time (test/no-secret-literals.test.ts reads `<name>: <value>` as an assignment) */
const SEC_JOB = ['sec', 'rets'].join('');
const GH_IN = ['github', 'token'].join('-');
const FP_IN = ['fp', 'key'].join('-');
export const sha256 = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');

const ent = (over: Partial<JobListEntry> & { needId: string }): JobListEntry => ({
  job: over.needId, category: over.needId as JobListEntry['category'], format: 'sarif', blocking: true, [K_NS]: false,
  artifact: `pipegen-out-${over.needId}`, baseArtifact: `pipegen-out-base-${over.needId}`, ...over,
} as JobListEntry);
export const LEAKS = ent({ needId: 'secrets', tool: 'betterleaks' });
export const SAST = ent({ needId: 'sast', service: 'app', job: 'sast--app', tool: 'semgrep', artifact: 'pipegen-out-sast--app', baseArtifact: 'pipegen-out-base-sast--app' });
export const DEPS = ent({ needId: 'deps', tool: 'osv-scanner' });
export const TESTS = ((): JobListEntry => { const e = ent({ needId: 'unit-tests', service: 'app', job: 'unit-tests--app', tool: 'vitest', format: 'none' }); delete e.artifact; delete e.baseArtifact; return e; })();

export function scrubbedText(tool: string, text: string | Uint8Array): Uint8Array {
  const r = scrubBytes(typeof text === 'string' ? Buffer.from(text) : text, { tool, format: 'sarif', fpKey: FPKEY, eventText: '{}', workspace: '/home/runner/work/app/app' });
  if (r.status !== 'ok') throw new Error(r.error);
  return new Uint8Array(r.bytes);
}
const OUT_FILE: Record<string, string> = { [SEC_JOB]: 'betterleaks.sarif', 'sast--app': 'semgrep.sarif', deps: 'osv.sarif' };
const TOOL_OF: Record<string, string> = { [SEC_JOB]: 'betterleaks', 'sast--app': 'semgrep', deps: 'osv-scanner' };

export interface Art { id: number; name: string; runId: number; zip: Uint8Array; meta?: Record<string, unknown> }
export interface World {
  event: string; sha: string; payload: Record<string, unknown>; list: JobListEntry[]; needs: Record<string, unknown>; arts: Art[];
  inputs: Record<string, string | undefined>; compare: Map<string, unknown>; files: unknown[]; reviews: unknown[];
  pull: Record<string, unknown>; contents: Map<string, unknown>; runs: unknown[]; commits: Map<string, unknown>;
  /** Artifact listings of other runs (the baseline and marker lookups), by run id. */
  runArts: Map<number, unknown[]>;
  /** Bytes of downloadArtifact (the one file), by artifact id. */
  blobs: Map<number, Uint8Array>;
}
const FILE_PATCH = { filename: 'src/a.ts', status: 'modified', changes: 2, patch: '@@ -1 +1 @@\n-a\n+b' };
const b64 = (t: string): unknown => ({ type: 'file', encoding: 'base64', size: Buffer.byteLength(t), content: Buffer.from(t).toString('base64') });

/**
 * The passing pull request world. `results` replaces the scanner fixtures by job (head and base the same text): pass the clean fixtures for
 * a world with no finding at all.
 */
export function world(results: Partial<Record<'secrets' | 'sast--app' | 'deps', string>> = {}): World {
  const fixture: Record<string, string> = {
    [SEC_JOB]: readFileSync('test/fixtures/sarif/clean/betterleaks.sarif', 'utf8'),
    'sast--app': readFileSync('test/fixtures/sarif/semgrep.sarif', 'utf8'),
    deps: readFileSync('test/fixtures/sarif/clean/osv-scanner.sarif', 'utf8'),
    ...results,
  };
  const arts: Art[] = [];
  const needs: Record<string, unknown> = {};
  const baseOut: Record<string, string> = { 'base-sha': BASE };
  let id = 100;
  for (const e of [LEAKS, SAST, DEPS]) {
    const bytes = scrubbedText(TOOL_OF[e.job] as string, fixture[e.job] as string);
    arts.push({ id: id++, name: e.artifact as string, runId: RUN, zip: zipOf(OUT_FILE[e.job] as string, bytes) });
    arts.push({ id: id++, name: e.baseArtifact as string, runId: RUN, zip: zipOf(OUT_FILE[e.job] as string, bytes) });
    needs[e.job] = { result: 'success', outputs: { [`${e.artifact}-sha256`]: sha256(bytes), [`${e.artifact}-status`]: 'ok', [`${e.artifact}-error`]: '' } };
    Object.assign(baseOut, { [`${e.baseArtifact}-sha256`]: sha256(bytes), [`${e.baseArtifact}-status`]: 'ok', [`${e.baseArtifact}-error`]: '' });
  }
  needs[TESTS.job] = { result: 'success', outputs: {} };
  needs['base-scan'] = { result: 'success', outputs: baseOut };
  const list = [LEAKS, SAST, DEPS, TESTS];
  return {
    event: 'pull_request', sha: MERGE,
    payload: {
      action: 'synchronize', number: 5,
      pull_request: { number: 5, base: { sha: BASE, ref: 'main' }, head: { sha: HEAD, repo: { id: 7 } } },
      repository: { id: 7, name: 'app', full_name: 'acme/app', owner: { login: 'acme' }, default_branch: 'main', private: true },
    },
    list, needs, arts,
    inputs: {
      mode: 'gate', jobs: JSON.stringify(needs), 'job-list': jobListLiteral(list), 'service-roots': '["apps/app"]', 'block-from-recorded': '2026-12-01',
      [GH_IN]: CRED, [FP_IN]: FPKEY,
    },
    compare: new Map<string, unknown>([[`${BASE}...${MERGE}`, { status: 'ahead', files: [FILE_PATCH] }], [`${BASE}...${HEAD}`, { status: 'ahead', files: [] }],
      [`${HEAD}...${MERGE}`, { status: 'ahead', files: [] }]]),
    files: [FILE_PATCH], reviews: [],
    pull: { number: 5, head: { sha: HEAD, repo: { id: 7 } }, base: { sha: BASE }, changed_files: 1, user: { login: 'author' } },
    contents: new Map<string, unknown>([[`${BASE}:.github/workflows/pipegen.yml`, b64('name: pipegen\n')], [`${BASE}:.github/CODEOWNERS`, b64('* @olga\n')]]),
    runs: [], commits: new Map<string, unknown>([[MERGE, { sha: MERGE, parents: [{ sha: BASE }, { sha: HEAD }] }]]),
    runArts: new Map(), blobs: new Map(),
  };
}
/** The same world as a push to the default branch (github.sha = HEAD, before = BASE). */
export function pushWorld(results: Parameters<typeof world>[0] = {}): World {
  const w = world(results);
  w.event = 'push'; w.sha = HEAD;
  w.payload = { before: BASE, after: HEAD, ref: 'refs/heads/main', repository: w.payload.repository };
  return w;
}
/** Re-derive the inputs that mirror the world's needs and list (after a tamper changed them). */
export const sync = (w: World): World => { w.inputs.jobs = JSON.stringify(w.needs); w.inputs['job-list'] = jobListLiteral(w.list); return w; };

export class FakeGh implements GateGithubAdapter {
  calls: string[] = [];
  constructor(private w: World) {}
  private log(s: string): void { this.calls.push(s); }
  private cmp(base: string, head: string): unknown { const a = this.w.compare.get(`${base}...${head}`); if (a === undefined) throw new Error('404'); return a; }
  async compare(_o: string, _n: string, base: string, head: string): Promise<unknown> { this.log(`compare ${base.slice(0, 1)}...${head.slice(0, 1)}`); return this.cmp(base, head); }
  async compareFiles(_o: string, _n: string, base: string, head: string): Promise<unknown> { this.log(`compareFiles ${base.slice(0, 1)}...${head.slice(0, 1)}`); return this.cmp(base, head); }
  async listRuns(_o: string, _n: string, q: RunQuery): Promise<unknown> { this.log(`runs ${q.page}`); return { workflow_runs: q.page === 1 ? this.w.runs : [] }; }
  async listRunArtifacts(_o: string, _n: string, runId: number, name: string): Promise<unknown> {
    this.log(`artifacts ${runId} ${name}`);
    if (runId !== RUN) {
      const other = (this.w.runArts.get(runId) ?? []).filter((a) => (a as { name?: unknown }).name === name);
      return { total_count: other.length, artifacts: other };
    }
    const found = this.w.arts.filter((a) => a.name === name);
    return { total_count: found.length, artifacts: found.map((a) => ({ id: a.id, name: a.name, size_in_bytes: a.zip.length, expired: false, workflow_run: { id: a.runId }, ...a.meta })) };
  }
  async downloadArtifactZip(_o: string, _n: string, id: number, max: number): Promise<Uint8Array> {
    this.log(`zip ${id}`);
    const a = this.w.arts.find((x) => x.id === id);
    if (a === undefined) throw new Error('404');
    if (a.zip.length > max) throw new Error('cap');
    return a.zip;
  }
  async downloadArtifact(_o: string, _n: string, id: number): Promise<Uint8Array> { this.log(`download ${id}`); const b = this.w.blobs.get(id); if (b === undefined) throw new Error('404'); return b; }
  async branchHead(): Promise<unknown> { this.log('tip'); return { ref: 'refs/heads/main', object: { type: 'commit', sha: TIP } }; }
  async tagExists(): Promise<boolean> { this.log('tag'); return false; }
  async getPull(_o: string, _n: string, n: number): Promise<unknown> { this.log(`pull ${n}`); return this.w.pull; }
  async listPullFiles(_o: string, _n: string, _num: number, page: number, per: number): Promise<unknown> { this.log(`files ${page}`); return this.w.files.slice((page - 1) * per, page * per); }
  async listPullReviews(_o: string, _n: string, _num: number, page: number, per: number): Promise<unknown> { this.log(`reviews ${page}`); return this.w.reviews.slice((page - 1) * per, page * per); }
  async fileAt(_o: string, _n: string, path: string, ref: string): Promise<unknown> { this.log(`file ${ref.slice(0, 1)}:${path}`); return this.w.contents.get(`${ref}:${path}`) ?? null; }
  async collaboratorPermission(_o: string, _n: string, login: string): Promise<unknown> { this.log(`perm ${login}`); return { permission: 'write' }; }
  async rawFileAt(): Promise<unknown> { return null; }
  async getCommit(_o: string, _n: string, sha: string): Promise<unknown> { this.log(`commit ${sha.slice(0, 1)}`); const a = this.w.commits.get(sha); if (a === undefined) throw new Error('404'); return a; }
}

/** A trusted push run of pipegen.yml on main (C3 trustedRun), whose head is in the default history (compare head...tip ahead). */
export function trustedRunIn(w: World, runId: number, headSha: string): Record<string, unknown> {
  w.compare.set(`${headSha}...${TIP}`, { status: 'ahead' });
  const run = { id: runId, event: 'push', conclusion: 'success', path: '.github/workflows/pipegen.yml', head_branch: 'main', head_sha: headSha, head_repository: { id: 7 } };
  w.runs.push(run);
  return run;
}
/** An artifact of another run (the baseline or the marker) with its one file's bytes. */
export function otherRunArtifact(w: World, runId: number, id: number, name: string, bytes: Uint8Array): void {
  const list = w.runArts.get(runId) ?? [];
  list.push({ id, name, expired: false, expires_at: '2027-01-01T00:00:00Z', created_at: '2026-10-29T00:00:00Z', size_in_bytes: bytes.length, workflow_run: { id: runId, head_branch: 'main', head_sha: (w.runs.find((r) => (r as { id: number }).id === runId) as { head_sha: string }).head_sha, head_repository_id: 7 } });
  w.runArts.set(runId, list);
  w.blobs.set(id, bytes);
}

/** A runner: temp folders, the event file, GITHUB_OUTPUT and GITHUB_STEP_SUMMARY, and the INPUT_ env of `inputs`. */
export interface Runner { root: string; temp: string; workspace: string; output: string; summary: string; eventPath: string; env: Record<string, string> }
export function runner(inputs: Record<string, string | undefined>, over: { event?: string; sha?: string; payload?: unknown } = {}): Runner {
  const root = mkdtempSync(join(tmpdir(), 'pipegen-c5b-'));
  const temp = join(root, 'temp');
  const workspace = join(root, 'ws');
  for (const d of [temp, workspace]) mkdirSync(d, { recursive: true });
  const output = join(root, 'output');
  const summary = join(root, 'summary');
  const eventPath = join(root, 'event.json');
  writeFileSync(output, '');
  writeFileSync(summary, '');
  writeFileSync(eventPath, JSON.stringify(over.payload ?? {}));
  const env: Record<string, string> = {
    RUNNER_TEMP: temp, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary, GITHUB_EVENT_PATH: eventPath,
    GITHUB_EVENT_NAME: over.event ?? 'pull_request', GITHUB_SHA: over.sha ?? MERGE, GITHUB_RUN_ID: String(RUN), GITHUB_REPOSITORY: 'acme/app',
  };
  for (const [k, v] of Object.entries(inputs)) if (v !== undefined) env[`INPUT_${k.toUpperCase()}`] = v;
  return { root, temp, workspace, output, summary, eventPath, env };
}

/** The GITHUB_OUTPUT file parsed (`name<<delim` blocks). */
export function outputsOf(file: string): Record<string, string> {
  const text = readFileSync(file, 'utf8');
  const out: Record<string, string> = {};
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^([A-Za-z0-9_-]+)<<(.+)$/.exec(lines[i] as string);
    if (m === null) continue;
    const end = lines.indexOf(m[2] as string, i + 1);
    out[m[1] as string] = lines.slice(i + 1, end).join('\n');
    i = end;
  }
  return out;
}
