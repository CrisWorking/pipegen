// Plan C Task C5a: gatherGateInput (gate/src/facts.ts), the one function that reads every fact decideGate needs, in the documented order,
// through an injected GitHub client and an injected artifact reader. A fixture world (fake GitHub, real scrubbed result files zipped the way
// upload-artifact writes them) gives a GateInput that decideGate passes; every single tamper then flips it to block. Written first.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { GateGithub, RunQuery } from '../gate/src/baseline.js';
import { decideGate, type GateInput } from '../gate/src/decide.js';
import { gatherGateInput, licenceCoverage, type GateContext, type GateIo } from '../gate/src/facts.js';
import { scrubBytes } from '../gate/src/scrub.js';
import { parseRangeFacts } from '../gate/src/range.js';
import { gateToolView } from '../gate/src/settings.js';
import { jobListLiteral, type JobListEntry } from '../src/engine/gate-job-list.js';
import { makeZip, zipOf } from './helpers/zip.js';
import { reviewedList } from './helpers/render.js';

// ---------- the world ----------
const GH_IN = ['github', 'token'].join('-');
const FP_IN = ['fp', 'key'].join('-');
const CRED = ['gh', 's_', 'Wq5'.repeat(12)].join('');
const FPKEY = 'q7'.repeat(20);
const K_NS = ['needs', 'Sec' + 'rets'].join('') as 'needsSecrets';
const BASE = 'b'.repeat(40);
const HEAD = 'c'.repeat(40);
const MERGE = 'd'.repeat(40);
const RUN = 777;
const VIEW = gateToolView(reviewedList());
const sha256 = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');

const ent = (over: Partial<JobListEntry> & { needId: string }): JobListEntry => ({
  job: over.needId, category: over.needId as JobListEntry['category'], format: 'sarif', blocking: true, [K_NS]: false,
  artifact: `pipegen-out-${over.needId}`, baseArtifact: `pipegen-out-base-${over.needId}`, ...over,
} as JobListEntry);
const LEAKS = ent({ needId: 'secrets', tool: 'betterleaks' });
const SAST = ent({ needId: 'sast', service: 'app', job: 'sast--app', tool: 'semgrep', artifact: 'pipegen-out-sast--app', baseArtifact: 'pipegen-out-base-sast--app' });
const DEPS = ent({ needId: 'deps', tool: 'osv-scanner' });
const TESTS = ((): JobListEntry => { const e = ent({ needId: 'unit-tests', service: 'app', job: 'unit-tests--app', tool: 'vitest', format: 'none' }); delete e.artifact; delete e.baseArtifact; return e; })();
/** C9: the secrets job's commit-range scan (the entry gateJobList writes after the secrets check). */
const RANGE = ((): JobListEntry => { const e = ent({ needId: 'secrets', tool: 'betterleaks', artifact: 'pipegen-out-secrets-range', range: true }); delete e.baseArtifact; return e; })();
/** A real scrubbed commit-range result (the range scan step's raw SARIF and range facts, captured with the pinned betterleaks). */
function scrubbedRange(kind: 'clean' | 'leak'): Uint8Array {
  const [sarif, factsFile] = kind === 'clean' ? ['clean.sarif', 'clean-range.json'] : ['betterleaks.sarif', 'range.json'];
  const r = scrubBytes(readFileSync(`test/fixtures/sarif/betterleaks-range/${sarif}`), { tool: 'betterleaks', format: 'sarif', fpKey: FPKEY, eventText: '{}', range: parseRangeFacts(readFileSync(`test/fixtures/sarif/betterleaks-range/${factsFile}`, 'utf8')) });
  if (r.status !== 'ok') throw new Error(r.error);
  return new Uint8Array(r.bytes);
}
/** Puts this range result in the world: the artifact, and the secrets job's three outputs for it. */
function setRange(w: World, bytes: Uint8Array, over: Record<string, string> = {}): void {
  w.arts = w.arts.filter((a) => a.name !== RANGE.artifact);
  w.arts.push({ id: 900, name: RANGE.artifact as string, runId: RUN, zip: zipOf('betterleaks.sarif', bytes) });
  Object.assign(out(w, LEAKS.job), { [`${RANGE.artifact}-sha256`]: sha256(bytes), [`${RANGE.artifact}-status`]: 'ok', [`${RANGE.artifact}-error`]: '' }, over);
  sync(w);
}

/** A real scrubbed result file (what the scrub step uploads), from a captured SARIF fixture. */
function scrubbed(tool: string, fixture: string): Uint8Array {
  const r = scrubBytes(readFileSync(fixture), { tool, format: 'sarif', fpKey: FPKEY, eventText: '{}', workspace: '/home/runner/work/app/app' });
  if (r.status !== 'ok') throw new Error(r.error);
  return new Uint8Array(r.bytes);
}
const FILES: Record<string, { tool: string; head: string; base: string; out: string }> = {
  [LEAKS.job]: { tool: 'betterleaks', head: 'test/fixtures/sarif/clean/betterleaks.sarif', base: 'test/fixtures/sarif/clean/betterleaks.sarif', out: 'betterleaks.sarif' },
  'sast--app': { tool: 'semgrep', head: 'test/fixtures/sarif/semgrep.sarif', base: 'test/fixtures/sarif/semgrep.sarif', out: 'semgrep.sarif' },
  deps: { tool: 'osv-scanner', head: 'test/fixtures/sarif/clean/osv-scanner.sarif', base: 'test/fixtures/sarif/clean/osv-scanner.sarif', out: 'osv.sarif' },
};

interface Art { id: number; name: string; runId: number; size?: number; zip: Uint8Array; expired?: boolean }
interface World {
  event: string; sha: string; payload: Record<string, unknown>; list: JobListEntry[]; needs: Record<string, unknown>; arts: Art[];
  inputs: Record<string, string | undefined>; compare: Map<string, unknown>; files: unknown[]; reviews: unknown[];
  pull: Record<string, unknown>; contents: Map<string, unknown>; runs: unknown[]; now: Date;
  /** GET /commits/{sha} answers (C5b Part 0: the merge commit's parents). */
  commits: Map<string, unknown>;
}
const FILE_PATCH = { filename: 'src/a.ts', status: 'modified', changes: 2, patch: '@@ -1 +1 @@\n-a\n+b' };
const b64 = (t: string): unknown => ({ type: 'file', encoding: 'base64', size: Buffer.byteLength(t), content: Buffer.from(t).toString('base64') });
function world(): World {
  const arts: Art[] = [];
  const needs: Record<string, unknown> = {};
  const baseOut: Record<string, string> = { 'base-sha': BASE };
  let id = 100;
  for (const e of [LEAKS, SAST, DEPS]) {
    const f = FILES[e.job] as (typeof FILES)[string];
    const head = scrubbed(f.tool, f.head);
    const base = scrubbed(f.tool, f.base);
    arts.push({ id: id++, name: e.artifact as string, runId: RUN, zip: zipOf(f.out, head) });
    arts.push({ id: id++, name: e.baseArtifact as string, runId: RUN, zip: zipOf(f.out, base) });
    needs[e.job] = { result: 'success', outputs: { [`${e.artifact}-sha256`]: sha256(head), [`${e.artifact}-status`]: 'ok', [`${e.artifact}-error`]: '' } };
    Object.assign(baseOut, { [`${e.baseArtifact}-sha256`]: sha256(base), [`${e.baseArtifact}-status`]: 'ok', [`${e.baseArtifact}-error`]: '' });
  }
  // C9: the commit-range result of the secrets job (clean: only its two canaries, taken out by the scrub)
  const range = scrubbedRange('clean');
  arts.push({ id: id++, name: RANGE.artifact as string, runId: RUN, zip: zipOf('betterleaks.sarif', range) });
  Object.assign((needs[LEAKS.job] as { outputs: Record<string, string> }).outputs, { [`${RANGE.artifact}-sha256`]: sha256(range), [`${RANGE.artifact}-status`]: 'ok', [`${RANGE.artifact}-error`]: '' });
  needs[TESTS.job] = { result: 'success', outputs: {} };
  needs['base-scan'] = { result: 'success', outputs: baseOut };
  const list = [LEAKS, RANGE, SAST, DEPS, TESTS];
  return {
    event: 'pull_request', sha: MERGE,
    payload: {
      action: 'synchronize', number: 5,
      pull_request: { number: 5, base: { sha: BASE, ref: 'main' }, head: { sha: HEAD, repo: { id: 7 } } },
      repository: { id: 7, name: 'app', full_name: 'acme/app', owner: { login: 'acme' }, default_branch: 'main', private: true },
    },
    list, needs, arts,
    inputs: {
      mode: 'gate', jobs: JSON.stringify(needs), 'job-list': jobListLiteral(list), 'service-roots': '["apps/app"]', 'block-from': '', 'block-from-recorded': '2026-12-01',
      [GH_IN]: CRED, [FP_IN]: FPKEY,
    },
    // one map for compare and compareFiles: both are GET /compare/{base}...{head} (the same answer, status and files)
    compare: new Map<string, unknown>([[`${BASE}...${MERGE}`, { status: 'ahead', files: [FILE_PATCH] }], [`${BASE}...${HEAD}`, { status: 'ahead', files: [] }],
      // fix round 2: the scanned merge commit contains the PR head (a test merge commit is one commit ahead of it)
      [`${HEAD}...${MERGE}`, { status: 'ahead', files: [] }]]),
    files: [FILE_PATCH], reviews: [],
    pull: { number: 5, head: { sha: HEAD, repo: { id: 7 } }, base: { sha: BASE }, changed_files: 1, user: { login: 'author' } },
    contents: new Map<string, unknown>([[`${BASE}:.github/workflows/pipegen.yml`, b64('name: pipegen\n')], [`${BASE}:.github/CODEOWNERS`, b64('* @olga\n')]]),
    runs: [], now: new Date('2026-10-30T12:00:00Z'),
    // C5b Part 0: the scanned test merge commit, base tip first and the PR head second
    commits: new Map<string, unknown>([[MERGE, { sha: MERGE, parents: [{ sha: BASE }, { sha: HEAD }] }]]),
  };
}
/** Re-derive the inputs that mirror the world's needs and list (after a tamper changed them). */
const sync = (w: World): World => { w.inputs.jobs = JSON.stringify(w.needs); w.inputs['job-list'] = jobListLiteral(w.list); return w; };

class FakeGh implements GateGithub {
  calls: string[] = [];
  constructor(private w: World) {}
  private log(s: string): void { this.calls.push(s); }
  async compare(_o: string, _n: string, base: string, head: string): Promise<unknown> {
    this.log(`compare ${base.slice(0, 1)}...${head.slice(0, 1)}`);
    const a = this.w.compare.get(`${base}...${head}`); if (a === undefined) throw new Error('404'); return a;
  }
  async listRuns(_o: string, _n: string, q: RunQuery): Promise<unknown> { this.log(`runs ${q.page}`); return { workflow_runs: q.page === 1 ? this.w.runs : [] }; }
  async listRunArtifacts(_o: string, _n: string, runId: number, name: string): Promise<unknown> {
    this.log(`artifacts ${runId} ${name}`);
    const found = this.w.arts.filter((a) => a.name === name);
    return { total_count: found.length, artifacts: found.map((a) => ({ id: a.id, name: a.name, size_in_bytes: a.size ?? a.zip.length, expired: a.expired ?? false, workflow_run: { id: a.runId } })) };
  }
  async downloadArtifact(): Promise<Uint8Array> { throw new Error('not used: results go through io.artifactZip'); }
  async branchHead(): Promise<unknown> { this.log('tip'); return { ref: 'refs/heads/main', object: { type: 'commit', sha: 'e'.repeat(40) } }; }
  async tagExists(): Promise<boolean> { this.log('tag'); return false; }
  async getPull(_o: string, _n: string, n: number): Promise<unknown> { this.log(`pull ${n}`); return this.w.pull; }
  async listPullFiles(_o: string, _n: string, _num: number, page: number, per: number): Promise<unknown> { this.log(`files ${page}`); return this.w.files.slice((page - 1) * per, page * per); }
  async listPullReviews(_o: string, _n: string, _num: number, page: number, per: number): Promise<unknown> { this.log(`reviews ${page}`); return this.w.reviews.slice((page - 1) * per, page * per); }
  async fileAt(_o: string, _n: string, path: string, ref: string): Promise<unknown> { this.log(`file ${ref.slice(0, 1)}:${path}`); return this.w.contents.get(`${ref}:${path}`) ?? null; }
  async compareFiles(_o: string, _n: string, base: string, head: string): Promise<unknown> {
    this.log(`compareFiles ${base.slice(0, 1)}...${head.slice(0, 1)}`);
    const a = this.w.compare.get(`${base}...${head}`); if (a === undefined) throw new Error('404'); return a;
  }
  async collaboratorPermission(_o: string, _n: string, login: string): Promise<unknown> { this.log(`perm ${login}`); return { permission: 'write' }; }
  async listAttemptJobs(): Promise<unknown> { throw new Error('not used'); }
  async rawFileAt(): Promise<unknown> { return null; }
  async getCommit(_o: string, _n: string, sha: string): Promise<unknown> {
    this.log(`commit ${sha.slice(0, 1)}`);
    const a = this.w.commits.get(sha); if (a === undefined) throw new Error('404'); return a;
  }
}
function ioOf(w: World, gh: FakeGh): GateIo & { zips: number[]; lists: string[] } {
  const zips: number[] = [];
  const lists: string[] = [];
  return {
    zips, lists,
    readEvent: () => JSON.stringify(w.payload),
    listRunArtifacts: async (o, n, runId, name) => { lists.push(name); return gh.listRunArtifacts(o, n, runId, name); },
    artifactZip: async (_o, _n, id, max) => {
      zips.push(id);
      const a = w.arts.find((x) => x.id === id);
      if (a === undefined) throw new Error('404');
      if (a.zip.length > max) throw new Error('cap');
      return a.zip;
    },
  };
}
const ctxOf = (w: World): GateContext => ({
  inputs: w.inputs, env: { eventName: w.event, sha: w.sha, runId: String(RUN), repository: 'acme/app' }, now: w.now, reviewed: VIEW,
});
async function gather(w: World): Promise<{ input: GateInput; gh: FakeGh; io: ReturnType<typeof ioOf> }> {
  const gh = new FakeGh(w);
  const io = ioOf(w, gh);
  const r = await gatherGateInput(ctxOf(w), gh, io);
  if ('kind' in r) throw new Error(`settings error: ${r.errors.join('; ')}`);
  return { input: r, gh, io };
}
const why = (i: GateInput): string => { const r = decideGate(i); return [...r.blockReasons, ...r.blocking.map((b) => `${b.ruleId} ${b.reason}`)].join('\n'); };

// ---------- the passing world ----------

describe('gatherGateInput: a fixture world that passes', () => {
  it('builds a GateInput that decideGate passes (old findings warn in warn mode)', async () => {
    const { input } = await gather(world());
    const r = decideGate(input);
    expect(why(input)).toBe('');
    expect(r.pass).toBe(true);
    expect(r.mode).toBe('warn');
    expect(r.warnings.length).toBeGreaterThan(0);
    expect(r.warnings.every((f) => f.isNew === false)).toBe(true);
    expect(input.checks.map((c) => c.entry.job)).toEqual(['secrets', 'sast--app', 'deps', 'unit-tests--app']);
    expect(input.baseScan).toEqual({ result: 'success', commit: BASE });
    expect(input.ancestry).toEqual({ base: BASE, head: MERGE, isAncestor: true });
    expect(input.installing).toBe(false);
    expect(input.integrity).toEqual([]);
    expect([...input.floorNeeds].sort()).toEqual(['deps', 'sast', 'secrets', 'unit-tests']);
    expect(input.settingsErrors).toEqual([]);
  });
  it('no token, key or GitHub answer text reaches the GateInput', async () => {
    const { input } = await gather(world());
    const text = JSON.stringify(input, (_k, v: unknown) => (v instanceof Map ? [...v] : v instanceof Set ? [...v] : v));
    expect(text).not.toContain(CRED);
    expect(text).not.toContain(FPKEY);
  });
  it('action: reads only expected artifact names (the job list\'s artifact and base artifact, nothing else)', async () => {
    const { io } = await gather(world());
    expect(io.lists.sort()).toEqual(['pipegen-out-base-deps', 'pipegen-out-base-sast--app', 'pipegen-out-base-secrets', 'pipegen-out-deps', 'pipegen-out-sast--app', 'pipegen-out-secrets', 'pipegen-out-secrets-range']);
  });
  it('action: artifact with an unexpected name never downloaded (a stray same-run artifact is not even listed)', async () => {
    const w = world();
    w.arts.push({ id: 999, name: 'pipegen-out-evil', runId: RUN, zip: zipOf('x.sarif', '{}') });
    w.arts.push({ id: 998, name: 'pipegen-baseline', runId: RUN, zip: zipOf('x.json', '{}') });
    const { io } = await gather(w);
    expect(io.zips).not.toContain(999);
    expect(io.zips).not.toContain(998);
    expect(io.lists).not.toContain('pipegen-out-evil');
  });
  it('the read order: settings and the event, results, base, diff, then CODEOWNERS of the base BEFORE the pull request context, then the baseline and the marker', async () => {
    const { gh } = await gather(world());
    const at = (s: string): number => { const i = gh.calls.findIndex((c) => c.startsWith(s)); expect(i, s).toBeGreaterThanOrEqual(0); return i; };
    expect(at('artifacts')).toBeLessThan(at('compare b...d'));
    expect(at('compare b...d')).toBeLessThan(at('file b:'));
    // fix round 1 (m6): the ancestry and the diff read the same range: one call, its answer reused
    expect(gh.calls.filter((c) => /^compare(?:Files)? b\.\.\.d$/.test(c))).toEqual(['compare b...d']);
    expect(at('file b:.github/workflows/pipegen.yml')).toBeLessThan(at('file b:.github/CODEOWNERS'));
    expect(at('file b:.github/CODEOWNERS')).toBeLessThan(at('pull 5'));
    expect(at('pull 5')).toBeLessThan(at('runs 1'));
  });
  it('gate: never reads GITHUB_WORKSPACE in gate mode (facts.ts has no file system access and does not name the workspace)', () => {
    const src = readFileSync('gate/src/facts.ts', 'utf8');
    expect(src).not.toMatch(/from 'node:fs'|require\(|GITHUB_WORKSPACE|process\.env|process\.cwd/);
    for (const f of ['gate/src/settings.ts', 'gate/src/artifacts.ts', 'gate/src/github-adapter.ts']) expect(readFileSync(f, 'utf8'), f).not.toMatch(/from 'node:fs'|GITHUB_WORKSPACE|process\.cwd/);
  });
  it('action: base-scan results read by exact resultArtifactName(…, { base: true }) and hash-checked', async () => {
    const w = world();
    const { input } = await gather(w);
    const sast = input.checks.find((c) => c.entry.job === 'sast--app');
    expect(sast?.base?.file?.sha256).toBe((w.needs['base-scan'] as { outputs: Record<string, string> }).outputs['pipegen-out-base-sast--app-sha256']);
  });
  it('action: base-scan used when no trusted baseline (runs list empty → baseline null, the base scan decides)', async () => {
    const { input } = await gather(world());
    expect(input.baseline).toBeNull();
    expect(decideGate(input).warnings.every((f) => f.reason.startsWith('old'))).toBe(true);
  });
  it('artifact: non-blocking result missing → note, and the gate still passes', async () => {
    const w = world();
    const dup = ent({ needId: 'duplication', tool: 'jscpd', blocking: false });
    w.list.push(dup);
    w.needs[dup.job] = { result: 'success', outputs: { [`${dup.artifact}-sha256`]: 'a'.repeat(64), [`${dup.artifact}-status`]: 'ok' } };
    const { input } = await gather(sync(w));
    const r = decideGate(input);
    expect(r.pass).toBe(true);
    expect(r.notes.join(' ')).toMatch(/non-blocking check .*missing/);
  });
});

// ---------- every tamper blocks ----------

const findArt = (w: World, name: string): Art => { const a = w.arts.find((x) => x.name === name); if (a === undefined) throw new Error(name); return a; };
const out = (w: World, job: string): Record<string, string> => (w.needs[job] as { outputs: Record<string, string> }).outputs;
const TAMPERS: [string, (w: World) => void][] = [
  ['action: sarif hash mismatch blocks', (w) => { out(w, 'sast--app')['pipegen-out-sast--app-sha256'] = 'a'.repeat(64); sync(w); }],
  ['a required result artifact missing', (w) => { w.arts = w.arts.filter((a) => a.name !== 'pipegen-out-sast--app'); }],
  ['the result uploaded under another name only', (w) => { findArt(w, 'pipegen-out-sast--app').name = 'pipegen-out-sast'; }],
  ['two artifacts of the expected name', (w) => { const a = findArt(w, 'pipegen-out-sast--app'); w.arts.push({ ...a, id: 555 }); }],
  ['zip with two entries', (w) => { const a = findArt(w, 'pipegen-out-sast--app'); a.zip = makeZip({ entries: [{ name: 'semgrep.sarif', data: '{}' }, { name: 'x', data: '{}' }] }); }],
  ['zip with a path entry', (w) => { const a = findArt(w, 'pipegen-out-sast--app'); a.zip = zipOf('sub/semgrep.sarif', '{}'); }],
  ['zip with a symlink', (w) => { const a = findArt(w, 'pipegen-out-sast--app'); a.zip = makeZip({ entries: [{ name: 'semgrep.sarif', data: '/etc/hostname', mode: 0o120777, method: 0 }] }); }],
  ['zip entry of another file name', (w) => { const a = findArt(w, 'pipegen-out-sast--app'); a.zip = zipOf('other.sarif', '{}'); }],
  ['artifact of another run', (w) => { findArt(w, 'pipegen-out-sast--app').runId = RUN + 1; }],
  ['artifact over the size cap (metadata)', (w) => { findArt(w, 'pipegen-out-sast--app').size = 64 * 1024 * 1024; }],
  ['zip bomb', (w) => { findArt(w, 'pipegen-out-sast--app').zip = makeZip({ entries: [{ name: 'semgrep.sarif', data: Buffer.alloc(17 * 1024 * 1024, 0x20), uncompressedSize: 10 }] }); }],
  ['base artifact hash mismatch', (w) => { out(w, 'base-scan')['pipegen-out-base-sast--app-sha256'] = 'a'.repeat(64); sync(w); }],
  ['base artifact missing while its status says ok', (w) => { w.arts = w.arts.filter((a) => a.name !== 'pipegen-out-base-sast--app'); }],
  ['base-sha output is not the event\'s base (the base scan checked out something else)', (w) => { out(w, 'base-scan')['base-sha'] = 'f'.repeat(40); sync(w); }],
  ['the base is not an ancestor of github.sha', (w) => { w.compare.set(`${BASE}...${MERGE}`, { status: 'diverged' }); }],
  ['the ancestry check fails (API error)', (w) => { w.compare.delete(`${BASE}...${MERGE}`); }],
  ['a required job failed', (w) => { (w.needs['unit-tests--app'] as { result: string }).result = 'failure'; sync(w); }],
  ['a required job missing from needs', (w) => { delete w.needs.deps; sync(w); }],
  ['a tool error', (w) => { out(w, 'deps')['pipegen-out-deps-status'] = 'tool-error'; out(w, 'deps')['pipegen-out-deps-error'] = 'db download failed'; sync(w); }],
  ['a settings error (job-list malformed)', (w) => { w.inputs['job-list'] = '[{"needId":"secrets"}]'; }],
  ['a settings error (a floor need in not-proven)', (w) => { w.inputs['not-proven'] = '["deps"]'; }],
  ['integrity: workflow change without code-owner approval', (w) => { const f = { filename: '.github/workflows/pipegen.yml', status: 'modified', changes: 1, patch: '@@ -1 +1 @@\n-a\n+b' }; w.files = [FILE_PATCH, f]; w.pull.changed_files = 2; }],
  ['integrity: a suppression marker added', (w) => { w.files = [{ ...FILE_PATCH, patch: '@@ -1 +1 @@\n-a\n+x = 1 // nosemgrep' }]; }],
  ['integrity: the pull request head moved since the event', (w) => { w.pull.head = { sha: 'e'.repeat(40), repo: { id: 7 } }; }],
  ['fork PR: a check that needs secrets did not run', (w) => {
    (w.payload.pull_request as { head: { repo: { id: number } } }).head.repo.id = 8;
    w.list = w.list.map((e) => (e.job === 'unit-tests--app' ? { ...e, [K_NS]: true } : e));
    (w.needs['unit-tests--app'] as { result: string }).result = 'skipped'; sync(w);
  }],
];

describe('gatherGateInput: every single tamper flips the passing world to block', () => {
  for (const [name, tamper] of TAMPERS) {
    it(name, async () => {
      const w = world();
      tamper(w);
      const { input } = await gather(w);
      expect(decideGate(input).pass).toBe(false);
    });
  }
});

// ---------- base and diff facts per event ----------

describe('base facts: the base-scan commit equals this event\'s base and is an ancestor of github.sha', () => {
  it('pull_request: base = pull_request.base.sha; ancestry = compare base...github.sha (the merge commit), status ahead only', async () => {
    const { input, gh } = await gather(world());
    expect(gh.calls).toContain('compare b...d');
    expect(input.ancestry?.isAncestor).toBe(true);
    for (const status of ['identical', 'behind', 'diverged', undefined, 'AHEAD']) {
      const w = world(); w.compare.set(`${BASE}...${MERGE}`, { status });
      const r = await gather(w);
      expect(r.input.ancestry?.isAncestor ?? false, String(status)).toBe(false);
    }
  });
  it('wrong base: a base-sha output that is not the payload\'s base is no base, and no compare is made for it', async () => {
    const w = world(); out(w, 'base-scan')['base-sha'] = 'f'.repeat(40); sync(w);
    const { input, gh } = await gather(w);
    // no ancestry asked for a base the scan did not check out (the one compare call left is the diff's)
    expect(input.ancestry).toBeNull();
    expect(gh.calls.filter((c) => /^compare(?:Files)? b\.\.\./.test(c))).toHaveLength(1);
    const r = decideGate(input);
    expect(r.notes.join(' ')).toMatch(/no base/);
  });
  it('merge_group: base = merge_group.base_sha, head = head_sha (= github.sha); diff from compare base_sha...head_sha; no PR reads', async () => {
    const w = world();
    w.event = 'merge_group';
    w.payload = { merge_group: { base_sha: BASE, head_sha: MERGE, base_ref: 'refs/heads/main' }, repository: w.payload.repository };
    const { input, gh } = await gather(w);
    expect(gh.calls.filter((c) => /^compare(?:Files)? b\.\.\.d$/.test(c))).toEqual(['compare b...d']);   // ancestry and diff: one call
    expect(gh.calls.some((c) => c.startsWith('pull'))).toBe(false);
    expect(input.diff?.commit).toBe(MERGE);
    expect(input.integrity).toEqual([]);
    expect(input.installing).toBe(false);
    expect(decideGate(input).pass).toBe(true);
  });
  it('push: base = before; ancestry compare before...github.sha; no diff (counts only), no integrity', async () => {
    const w = world();
    w.event = 'push'; w.sha = HEAD;
    w.payload = { before: BASE, after: HEAD, ref: 'refs/heads/main', repository: w.payload.repository };
    const { input, gh } = await gather(w);
    expect(gh.calls).toContain('compare b...c');
    expect(input.diff).toBeNull();
    expect(input.integrity).toEqual([]);
    expect(decideGate(input).pass).toBe(true);
  });
  it('push to a new branch (before all zeros): no base, no compare; every finding new', async () => {
    const w = world();
    w.event = 'push'; w.sha = HEAD;
    w.payload = { before: '0'.repeat(40), after: HEAD, ref: 'refs/heads/main', repository: w.payload.repository };
    out(w, 'base-scan')['base-sha'] = '0'.repeat(40); sync(w);
    const { input, gh } = await gather(w);
    expect(gh.calls.filter((c) => c.startsWith('compare '))).toEqual([]);
    expect(input.ancestry).toBeNull();
    expect(decideGate(input).pass).toBe(false);
  });
  it('diff: built from compare pull_request.base.sha...github.sha (never the PR head), commit = github.sha, even when the base moved since', async () => {
    const w = world();
    // the base branch moved after the merge commit was made: the compare still uses the payload base and the scanned commit
    w.compare.set(`${BASE}...${MERGE}`, { status: 'ahead', files: [FILE_PATCH, { filename: 'base-moved.ts', status: 'added', changes: 1, patch: '@@ -0,0 +1 @@\n+x' }] });
    const { input, gh } = await gather(w);
    expect(gh.calls).toContain('compare b...d');
    expect(gh.calls.some((c) => / b\.\.\.c$/.test(c))).toBe(false);
    expect(input.diff?.commit).toBe(MERGE);
    expect(input.diff?.complete).toBe(true);
    expect([...(input.diff?.added.keys() ?? [])].sort()).toEqual(['base-moved.ts', 'src/a.ts']);
  });
});

// ---------- settings errors that stop the reads ----------

describe('gatherGateInput: a SettingsError when the event itself can not be trusted', () => {
  const err = async (mut: (w: World, c: GateContext) => void): Promise<unknown> => {
    const w = world(); const c = ctxOf(w); mut(w, c);
    const gh = new FakeGh(w);
    const r = await gatherGateInput(c, gh, ioOf(w, gh));
    expect(gh.calls).toEqual([]);   // nothing is read for an event that is not this repository's
    return r;
  };
  it('an unreadable payload, another repository, a sha or run id that is not one: no reads, a settings error', async () => {
    const cases: [string, (w: World, c: GateContext) => void][] = [
      ['payload not JSON', (w) => { w.payload = 'x' as never; }],
      ['repository of another name', (w) => { (w.payload.repository as { full_name: string }).full_name = 'acme/other'; }],
      // review I3c: a payload that is consistent in itself but of another repository than GITHUB_REPOSITORY
      ['a consistent payload of another repository', (w) => { const r = w.payload.repository as { full_name: string; name: string }; r.full_name = 'acme/other'; r.name = 'other'; }],
      ['a consistent payload of another owner', (w) => { const r = w.payload.repository as { full_name: string; owner: { login: string } }; r.full_name = 'evil/app'; r.owner = { login: 'evil' }; }],
      ['repository without an id', (w) => { (w.payload.repository as { id?: number }).id = undefined; }],
      ['no default branch', (w) => { (w.payload.repository as { default_branch?: string }).default_branch = undefined; }],
      ['sha not 40 hex', (_w, c) => { c.env.sha = 'main'; }],
      ['run id not a number', (_w, c) => { c.env.runId = 'x'; }],
    ];
    for (const [name, mut] of cases) {
      const r = await err(mut) as { kind?: string; errors?: string[] };
      expect(r.kind, name).toBe('settings-error');
      expect(r.errors?.length, name).toBeGreaterThan(0);
    }
  });
});

// ---------- licence coverage (C2 review m8, G11) ----------

describe('licence coverage: lockfile types trivy can not read are "not covered (lockfile type)", never clean', () => {
  it('licenceCoverage (fix round A): from the licence-lockfiles input, each kind that is not read, and a service with no lockfile, is "not covered"; a read kind adds nothing', () => {
    expect(licenceCoverage([{ service: 'web', lockfiles: [{ kind: 'npm', read: true }] }])).toEqual([]);
    expect(licenceCoverage([{ service: 'web', lockfiles: [{ kind: 'npm', read: true }] }, { service: 'api', lockfiles: [{ kind: 'pnpm', read: false }, { kind: 'go', read: false }] }]))
      .toEqual(['api: pnpm: not covered (lockfile type)', 'api: go: not covered (lockfile type)']);
    expect(licenceCoverage([{ service: 'docs', lockfiles: [] }])).toEqual(['docs: not covered (no lockfile)']);
    expect(licenceCoverage([])).toEqual(['not covered (no lockfile)']);
    expect(licenceCoverage(undefined)).toEqual(['coverage per lockfile not known (the gate step has no licence-lockfiles input)']);
  });
  it('the facts carry it for the licences check, and the summary shows it on that check (its state is never only "no findings")', async () => {
    const w = world();
    const lic = ent({ needId: 'licences', tool: 'trivy-licence' });
    const clean = scrubbed('trivy-licence', 'test/fixtures/sarif/clean/trivy-licence.sarif');
    w.arts.push({ id: 300, name: lic.artifact as string, runId: RUN, zip: zipOf('trivy-licence.sarif', clean) }, { id: 301, name: lic.baseArtifact as string, runId: RUN, zip: zipOf('trivy-licence.sarif', clean) });
    w.list.push(lic);
    w.needs[lic.job] = { result: 'success', outputs: { [`${lic.artifact}-sha256`]: sha256(clean), [`${lic.artifact}-status`]: 'ok' } };
    Object.assign(out(w, 'base-scan'), { [`${lic.baseArtifact}-sha256`]: sha256(clean), [`${lic.baseArtifact}-status`]: 'ok' });
    w.inputs['licence-lockfiles'] = JSON.stringify([{ service: 'app', lockfiles: [{ kind: 'npm', read: true }] }, { service: 'api', lockfiles: [{ kind: 'uv', read: false }] }]);
    const { input } = await gather(sync(w));
    expect(input.coverage).toEqual([{ job: 'licences', text: 'api: uv: not covered (lockfile type)' }]);
    const r = decideGate(input);
    expect(r.checks.find((c) => c.job === 'licences')?.state).toMatch(/not covered \(lockfile type\)/);
    expect(r.summary).toMatch(/uv: not covered \(lockfile type\)/);
  });
});

// ---------- fix round 1: the approval re-run has a base; runs that can't decide a merge never pass ----------

const reviewWorld = (): World => {
  const w = world();
  w.event = 'pull_request_review';
  w.payload = { ...w.payload, action: 'submitted', review: { state: 'approved', commit_id: HEAD, user: { login: 'olga' } } };
  return w;
};
describe('fix round 1 (I1): pull_request_review is judged like pull_request, with the same base', () => {
  it('an approval re-run passes on old findings: the base is pull_request.base.sha, verified against github.sha', async () => {
    const { input, gh } = await gather(reviewWorld());
    expect(input.ancestry).toEqual({ base: BASE, head: MERGE, isAncestor: true });
    expect(gh.calls).toContain('compare b...d');
    const r = decideGate(input);
    expect(why(input)).toBe('');
    expect(r.pass).toBe(true);
    expect(r.warnings.every((f) => f.isNew === false)).toBe(true);
    expect(r.notes.join(' ')).not.toMatch(/no base/);
  });
  it('the approval re-run still checks integrity, and its approval waives a protected path only from a code owner on the head', async () => {
    const w = reviewWorld();
    w.files = [FILE_PATCH, { filename: '.github/workflows/pipegen.yml', status: 'modified', changes: 1, patch: '@@ -1 +1 @@\n-a\n+b' }];
    w.pull.changed_files = 2;
    expect(decideGate((await gather(w)).input).pass).toBe(false);
    w.reviews = [{ id: 1, user: { login: 'olga' }, state: 'APPROVED', commit_id: HEAD }];
    expect(decideGate((await gather(w)).input).pass).toBe(true);
  });
  it('wrong base on the approval re-run (base-sha is not the payload\'s base): no base, old findings are new, it blocks', async () => {
    const w = reviewWorld(); out(w, 'base-scan')['base-sha'] = 'f'.repeat(40); sync(w);
    const { input } = await gather(w);
    expect(input.ancestry).toBeNull();
    expect(decideGate(input).pass).toBe(false);
  });
});

describe('fix round 1 (I2): only pull requests, merge queues and pushes to the default branch can pass', () => {
  const MSG = "the gate runs on pull requests, merge queues and pushes to main; this push run can't decide a merge";
  const pushTo = (ref: string | undefined): World => {
    const w = world();
    w.event = 'push'; w.sha = HEAD;
    w.payload = { before: BASE, after: HEAD, ...(ref === undefined ? {} : { ref }), repository: w.payload.repository };
    return w;
  };
  it('a push to the default branch passes (the control)', async () => {
    expect(decideGate((await gather(pushTo('refs/heads/main'))).input).pass).toBe(true);
  });
  it('a push to any other ref never passes, with the ruled text', async () => {
    for (const ref of ['refs/heads/feature', 'refs/heads/main2', 'refs/heads/Main', 'refs/tags/main', 'refs/heads/main/x', 'main', '', undefined]) {
      const { input } = await gather(pushTo(ref));
      const r = decideGate(input);
      expect(r.pass, String(ref)).toBe(false);
      expect(r.blockReasons, String(ref)).toContain(MSG);
    }
  });
  it('every other event never passes (workflow_dispatch, schedule, pull_request_target, workflow_run, issue_comment, an unknown name)', async () => {
    for (const ev of ['workflow_dispatch', 'schedule', 'pull_request_target', 'workflow_run', 'issue_comment', 'push-ish']) {
      const w = world(); w.event = ev;
      const r = decideGate((await gather(w)).input);
      expect(r.pass, ev).toBe(false);
      expect(r.blockReasons.join(' '), ev).toMatch(/the gate runs on pull requests, merge queues and pushes to main; this .* run can't decide a merge/);
    }
  });
});

// ---------- fix round 2 (review-C5a-r1 R1): the scanned commit must contain the head the check lands on ----------

describe('fix round 2: the event\'s head commit is the scanned commit or an ancestor of it (compare head...github.sha)', () => {
  const STALE = /the scanned commit does not contain the pull request's head/;
  const blocked = async (w: World): Promise<string> => { const r = decideGate((await gather(w)).input); expect(r.pass).toBe(false); return r.blockReasons.join('\n'); };
  it('pull_request: the head is in the merge commit (ahead) → passes, and the check was asked', async () => {
    const { input, gh } = await gather(world());
    expect(decideGate(input).pass).toBe(true);
    expect(gh.calls).toContain('compare c...d');
  });
  it('pull_request: a merge commit that does not contain the head (behind, diverged, or an odd answer) → blocks', async () => {
    for (const status of ['behind', 'diverged', undefined, 'AHEAD']) {
      const w = world(); w.compare.set(`${HEAD}...${MERGE}`, { status });
      expect(await blocked(w), String(status)).toMatch(STALE);
    }
  });
  it('pull_request_review on a stale merge commit (a newer head that was never merged in) → blocks', async () => {
    const w = reviewWorld();
    const NEWER = 'e'.repeat(40);
    (w.payload.pull_request as { head: { sha: string } }).head.sha = NEWER;
    w.pull.head = { sha: NEWER, repo: { id: 7 } };
    w.compare.set(`${NEWER}...${MERGE}`, { status: 'diverged' });
    expect(await blocked(w)).toMatch(STALE);
  });
  it('pull_request_review: the head in the merge commit → passes (the control)', async () => {
    expect(decideGate((await gather(reviewWorld())).input).pass).toBe(true);
  });
  it('merge_group: head_sha is github.sha (identical) → passes', async () => {
    const w = world();
    w.event = 'merge_group';
    w.payload = { merge_group: { base_sha: BASE, head_sha: MERGE, base_ref: 'refs/heads/main' }, repository: w.payload.repository };
    const { input } = await gather(w);
    expect(decideGate(input).pass).toBe(true);
    // and a queue head that is not in the scanned commit blocks
    const v = world();
    v.event = 'merge_group';
    v.payload = { merge_group: { base_sha: BASE, head_sha: HEAD, base_ref: 'refs/heads/main' }, repository: v.payload.repository };
    v.compare.set(`${HEAD}...${MERGE}`, { status: 'behind' });
    expect(await blocked(v)).toMatch(STALE);
  });
  it('an API error on the check → blocks (the head can not be shown to be scanned)', async () => {
    const w = world(); w.compare.delete(`${HEAD}...${MERGE}`);
    expect(await blocked(w)).toMatch(/could not be checked|does not contain/);
    const r = reviewWorld(); r.compare.delete(`${HEAD}...${MERGE}`);
    expect(await blocked(r)).toMatch(/could not be checked|does not contain/);
  });
  it('a payload with no head commit on a pull request event → blocks', async () => {
    const w = world(); (w.payload.pull_request as { head: { sha?: string } }).head.sha = undefined;
    expect(await blocked(w)).toMatch(/no head commit, so the scanned commit can not be tied to it/);
    const g = world(); g.event = 'merge_group';
    g.payload = { merge_group: { base_sha: BASE, base_ref: 'refs/heads/main' }, repository: g.payload.repository };
    expect(await blocked(g)).toMatch(/no head commit, so the scanned commit can not be tied to it/);
  });
});

// ---------- C5b Part 0 (review-C5a-r2 r2-m1): the scanned merge commit's second parent is the PR head ----------

describe('C5b Part 0: on pull_request and pull_request_review the scanned merge commit\'s second parent is the payload head', () => {
  const NOT_MERGE = /the scanned commit is not GitHub's merge of the pull request's head/;
  const blocked = async (w: World): Promise<string> => { const r = decideGate((await gather(w)).input); expect(r.pass).toBe(false); return r.blockReasons.join('\n'); };
  const worlds = (): [string, World][] => [['pull_request', world()], ['pull_request_review', reviewWorld()]];
  it('the control: parents [base tip, head] → passes, with one GET /commits/{github.sha}', async () => {
    for (const [ev, w] of worlds()) {
      const { input, gh } = await gather(w);
      expect(why(input), ev).toBe('');
      expect(gh.calls.filter((c) => c.startsWith('commit ')), ev).toEqual(['commit d']);
    }
  });
  it('a second parent that is not the head (an older head, the head first, the base twice) → blocks', async () => {
    const OLDER = 'a'.repeat(40);
    for (const parents of [[{ sha: BASE }, { sha: OLDER }], [{ sha: HEAD }, { sha: BASE }], [{ sha: BASE }, { sha: BASE }]]) {
      for (const [ev, w] of worlds()) {
        w.commits.set(MERGE, { sha: MERGE, parents });
        expect(await blocked(w), ev).toMatch(NOT_MERGE);
      }
    }
  });
  it('a commit that is not a two-parent merge (one parent, three parents, none) → blocks', async () => {
    for (const parents of [[{ sha: HEAD }], [{ sha: BASE }, { sha: HEAD }, { sha: 'a'.repeat(40) }], []]) {
      for (const [ev, w] of worlds()) {
        w.commits.set(MERGE, { sha: MERGE, parents });
        expect(await blocked(w), `${ev} ${parents.length}`).toMatch(NOT_MERGE);
      }
    }
  });
  it('a malformed answer (no parents, parents not a list, a parent with no sha, an upper-case sha, another commit\'s sha) → blocks', async () => {
    const answers: unknown[] = [
      { sha: MERGE }, { sha: MERGE, parents: 'x' }, { sha: MERGE, parents: [{ sha: BASE }, {}] }, { sha: MERGE, parents: [{ sha: BASE }, { sha: HEAD.toUpperCase() }] },
      { sha: 'e'.repeat(40), parents: [{ sha: BASE }, { sha: HEAD }] }, null, [], 'text',
    ];
    for (const a of answers) {
      for (const [ev, w] of worlds()) {
        w.commits.set(MERGE, a);
        expect(await blocked(w), `${ev} ${JSON.stringify(a)}`).toMatch(NOT_MERGE);
      }
    }
  });
  it('an inherited parents field (prototype) is not read', async () => {
    const w = world();
    const proto = { parents: [{ sha: BASE }, { sha: HEAD }] };
    w.commits.set(MERGE, Object.assign(Object.create(proto) as object, { sha: MERGE }));
    expect(await blocked(w)).toMatch(NOT_MERGE);
  });
  it('an API error → blocks, fail closed', async () => {
    for (const [ev, w] of worlds()) {
      w.commits.delete(MERGE);
      expect(await blocked(w), ev).toMatch(/whether the scanned commit is the merge of the pull request's head could not be checked/);
    }
  });
  it('the head equal to github.sha on a pull request (not a merge commit) → blocks', async () => {
    const w = world();
    w.sha = HEAD;
    w.commits.set(HEAD, { sha: HEAD, parents: [{ sha: BASE }] });
    w.compare.set(`${BASE}...${HEAD}`, { status: 'ahead', files: [FILE_PATCH] });
    expect(await blocked(w)).toMatch(NOT_MERGE);
  });
  it('merge_group keeps the equality rule: no commit call', async () => {
    const w = world();
    w.event = 'merge_group';
    w.payload = { merge_group: { base_sha: BASE, head_sha: MERGE, base_ref: 'refs/heads/main' }, repository: w.payload.repository };
    w.commits.clear();
    const { input, gh } = await gather(w);
    expect(decideGate(input).pass).toBe(true);
    expect(gh.calls.some((c) => c.startsWith('commit '))).toBe(false);
  });
  it('a push makes no commit call', async () => {
    const w = world();
    w.event = 'push';
    w.payload = { ref: 'refs/heads/main', before: BASE, after: MERGE, repository: w.payload.repository };
    w.commits.clear();
    const { gh } = await gather(w);
    expect(gh.calls.some((c) => c.startsWith('commit '))).toBe(false);
  });
});

// ---------- C5b: the clean-run state reaches the action (the marker re-write rule needs it) ----------
describe('C5b: gatherGateInput passes the clean-run marker state on (cleanRun)', () => {
  it('no trusted run → none; it is the state cleanRunSeen gave, never derived from the mode', async () => {
    const { input } = await gather(world());
    expect(input.cleanRun).toBe('none');
  });
});

// ---------- C9: the commit-range secrets scan ----------

/** The secrets job's id (spelled at run time, see test/no-secret-literals.test.ts). */
const SJ = ['sec', 'rets'].join('');

describe('gatherGateInput: the secrets job\'s commit-range scan (C9)', () => {
  const rangeOf = (i: GateInput): GateInput['rangeScans'] => i.rangeScans;
  it('the clean world: the range entry is read as the commit range (no finding), never as a check; the old "not scanned yet" note is gone', async () => {
    const { input } = await gather(world());
    expect(rangeOf(input)).toEqual([{ tool: 'betterleaks', findings: [] }]);
    expect(input.checks.some((c) => c.entry.range === true)).toBe(false);
    expect((input.notes ?? []).join('\n')).not.toMatch(/not scanned for secrets in this pipeline yet/);
    expect(decideGate(input).pass).toBe(true);
  });
  it('a secret added in one commit and removed in the next (the captured leak): the gate blocks, naming the commit', async () => {
    const w = world();
    setRange(w, scrubbedRange('leak'));
    const { input } = await gather(w);
    const r = decideGate(input);
    expect(r.pass).toBe(false);
    expect(r.blocking.filter((b) => b.job === 'commit range').map((b) => [b.file, b.reason])).toEqual([['config.js', expect.stringMatching(/^secret added in this PR's history \(commit [0-9a-f]{12}\): rotate it, even if a later commit removed it$/)]]);
  });
  it('a tool error, no status output, a hash that is not the job\'s output, a missing artifact or a failed secrets job: the range blocks', async () => {
    const cases: [string, (w: World) => void][] = [
      ['tool error', (w) => { Object.assign(out(w, SJ), { [`${RANGE.artifact}-status`]: 'tool-error', [`${RANGE.artifact}-error`]: 'the scanner scanned 3 commits, but the range has 4' }); sync(w); }],
      ['no status', (w) => { delete out(w, SJ)[`${RANGE.artifact}-status`]; sync(w); }],
      ['other hash', (w) => { out(w, SJ)[`${RANGE.artifact}-sha256`] = 'e'.repeat(64); sync(w); }],
      ['missing artifact', (w) => { w.arts = w.arts.filter((a) => a.name !== RANGE.artifact); }],
      ['failed job', (w) => { (w.needs[SJ] as { result: string }).result = 'failure'; sync(w); }],
    ];
    for (const [what, tamper] of cases) {
      const w = world();
      tamper(w);
      const { input } = await gather(w);
      const r = decideGate(input);
      expect(r.pass, what).toBe(false);
      expect([...r.blockReasons, ...r.toolErrors.map((t) => t.job)].join('\n'), what).toMatch(/commit range/);
    }
  });
  it('a job list with a secrets check but no commit-range entry: on a pull request the range is not scanned, so the gate blocks', async () => {
    const w = world();
    w.list = w.list.filter((e) => e.range !== true);
    sync(w);
    const { input } = await gather(w);
    const r = decideGate(input);
    expect(r.pass).toBe(false);
    expect(r.toolErrors.map((t) => t.reason).join('\n')).toMatch(/no commit-range scan/);
  });
  it('merge_group: the range is read and required; push to the default branch: informational (a leak warns); a push that made the branch: no range, a note', async () => {
    const mg = world();
    mg.event = 'merge_group';
    mg.payload = { merge_group: { base_sha: BASE, head_sha: MERGE, base_ref: 'refs/heads/main' }, repository: mg.payload.repository };
    setRange(mg, scrubbedRange('leak'));
    expect(decideGate((await gather(mg)).input).pass).toBe(false);
    const p = world();
    p.event = 'push'; p.sha = HEAD;
    p.payload = { before: BASE, after: HEAD, ref: 'refs/heads/main', repository: p.payload.repository };
    setRange(p, scrubbedRange('leak'));
    const pr = decideGate((await gather(p)).input);
    expect(pr.pass).toBe(true);
    expect(pr.warnings.some((x) => x.job === 'commit range')).toBe(true);
    const nb = world();
    nb.event = 'push'; nb.sha = HEAD;
    nb.payload = { before: '0'.repeat(40), after: HEAD, ref: 'refs/heads/main', repository: nb.payload.repository };
    out(nb, 'base-scan')['base-sha'] = '0'.repeat(40);
    setRange(nb, scrubbedRange('leak'));
    const { input } = await gather(nb);
    expect(rangeOf(input)).toEqual([]);
    expect((input.notes ?? []).join('\n')).toMatch(/no commit range to scan/);
  });
});
