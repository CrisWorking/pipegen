// Plan C Task C3: the trusted baseline, the clean-run marker and the warn/block mode (gate/src/baseline.ts, gate/src/mode.ts).
// The baseline is what makes a finding "old", so a poisoned one pre-approves a future finding. It is read only from a run pipegen
// trusts (trustedRun) AND only when it carries an HMAC under the current PIPEGEN_FP_KEY (ruling B6); any API answer and any
// artifact is hostile. Pure apart from the injected GitHub client (a fake here): no network. Written first (strict test-first).
import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT } from '../src/engine/artifact-names.js';
import {
  buildBaseline, buildCleanRunMarker, cleanRunSeen, inDefaultHistory, loadBaseline, saveBaseline, trustedRun, verifyBaselineArtifact, verifyCleanRunArtifact,
  BASELINE_RETENTION_DAYS, HISTORY_CHECK_CAP, MAX_COUNT_ENTRIES, MAX_RUN_PAGES, MAX_TRUSTED_RUNS, WORKFLOW_PATH, type ArtifactMeta, type ArtifactUploader, type GateGithub, type RepoRef, type RunQuery, type VerifyContext,
} from '../gate/src/baseline.js';
import { countKeyOf } from '../gate/src/decide.js';
import { keyId } from '../gate/src/fingerprint.js';
import { decideMode, resolveMode } from '../gate/src/mode.js';
import type { ScrubbedFinding } from '../gate/src/scrub.js';

// ---------- builders ----------

const KEY = 'test-fp-key-'.repeat(4);   // 48 printable characters
const KEY2 = 'other-fp-key-'.repeat(4);
const NOW = new Date('2026-10-30T12:00:00Z');
const REPO: RepoRef = { owner: 'acme', name: 'app', id: 7, defaultBranch: 'main' };
const SHA = (c: string): string => c.repeat(40);
const S1 = SHA('1');
const TIP = SHA('f');   // the default branch's commit, as the ref answer gives it
const CTX: VerifyContext = { key: KEY, now: NOW };
const FUTURE = '2027-01-20T00:00:00Z';
const PAST = '2026-10-01T00:00:00Z';

const hex = (seed: string): string => createHmac('sha256', 'seed').update(seed).digest('hex');
const SEC = 'sec' + 'ret:';
const fnd = (over: Partial<ScrubbedFinding> = {}): ScrubbedFinding => ({
  tool: 'semgrep', ruleId: 'r1', severity: 'high', file: 'a.js', line: 3, message: 'm', fingerprint: hex(JSON.stringify(over)),
  ['sec' + 'ret']: false, fpBy: 'hash', uriUnmapped: false, pathWithheld: false, ...over,
} as ScrubbedFinding);
const leak = (seed: string): ScrubbedFinding => fnd({ tool: 'betterleaks', ruleId: `${SEC}x`, severity: 'critical', ['sec' + 'ret']: true, fpBy: 'region', fingerprint: `${SEC}${hex(seed)}` } as Partial<ScrubbedFinding>);

/** The MAC spelled out here, independently of baseline.ts: pins the canonical encoding. */
const sortedPairs = (counts: Record<string, number>): [string, number][] => Object.entries(counts).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
const subKey = (key: string): string => createHmac('sha256', key).update('pipegen-artifact-mac-v1').digest('hex');
const macOf = (key: string, runId: number, kid: string, counts: Record<string, number>, format = 'pipegen-baseline-v1'): string =>
  createHmac('sha256', subKey(key)).update(JSON.stringify([format, runId, kid, sortedPairs(counts)])).digest('hex');
const markerMac = (key: string, runId: number, kid: string): string => createHmac('sha256', subKey(key)).update(JSON.stringify(['pipegen-clean-run-v1', runId, kid])).digest('hex');

const COUNTS = { [`fp\0semgrep\0semgrep\0${hex('a')}`]: 2, [`fp\0secrets\0betterleaks\0${SEC}${hex('s')}`]: 1, [`unmapped\0iac\0trivy-config\0AVD-1`]: 3 };
interface Doc { runId: number; keyId: string; counts: Record<string, number>; mac: string }
function goodDoc(over: Partial<Doc> = {}, key = KEY, counts: Record<string, number> = COUNTS): Doc {
  const runId = over.runId ?? 100;
  const kid = over.keyId ?? keyId(key);
  return { runId, keyId: kid, counts, mac: macOf(key, runId, kid, counts), ...over };
}
const bytesOf = (d: unknown): Uint8Array => new TextEncoder().encode(typeof d === 'string' ? d : JSON.stringify(d));
const META = (over: Partial<ArtifactMeta> = {}): ArtifactMeta => ({ runId: 100, name: BASELINE_ARTIFACT, expired: false, expiresAt: FUTURE, ...over });

// ---------- a fake GitHub (every answer is plain data, as the REST API would give) ----------

type Answer = unknown | Error;
const PER_PAGE = 100;
class FakeGh implements GateGithub {
  calls: string[] = [];
  compares = new Map<string, Answer>();      // sha -> compare answer (default: ahead)
  runsAnswer: Answer = [];                   // an array of run objects (paged by the fake) or any hostile answer
  runArtifacts = new Map<number, Answer>();  // run id -> the artifacts answer of that run
  blobs = new Map<number, Answer>();
  fallbackCompare: Answer = { status: 'ahead' };
  tagAnswer: Answer = false;                 // does a tag named like the default branch exist?
  branchAnswer: Answer = { ref: 'refs/heads/main', object: { type: 'commit', sha: SHA('f') } };
  private out(a: Answer): unknown { if (a instanceof Error) throw a; return a; }
  async compare(_o: string, _n: string, base: string, head: string): Promise<unknown> { this.calls.push(`compare ${base}...${head}`); return this.out(this.compares.has(base) ? this.compares.get(base) : this.fallbackCompare); }
  async listRuns(_o: string, _n: string, q: RunQuery): Promise<unknown> {
    this.calls.push(`runs ${q.page}`);
    this.lastQuery = q;
    const a = this.out(this.runsAnswer);
    return Array.isArray(a) ? { workflow_runs: a.slice((q.page - 1) * q.perPage, q.page * q.perPage) } : a;
  }
  lastQuery: RunQuery | undefined;
  async listRunArtifacts(_o: string, _n: string, runId: number, name: string): Promise<unknown> { this.calls.push(`artifacts ${runId} ${name}`); return this.out(this.runArtifacts.has(runId) ? this.runArtifacts.get(runId) : { artifacts: [] }); }
  async downloadArtifact(_o: string, _n: string, id: number): Promise<Uint8Array> { this.calls.push(`download ${id}`); return this.out(this.blobs.has(id) ? this.blobs.get(id) : new Error('404')) as Uint8Array; }
  async branchHead(_o: string, _n: string, branch: string): Promise<unknown> { this.calls.push(`branch ${branch}`); return this.out(this.branchAnswer); }
  async tagExists(_o: string, _n: string, tag: string): Promise<boolean> { this.calls.push(`tag ${tag}`); return this.out(this.tagAnswer) as boolean; }
}
const run = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: 100, event: 'push', conclusion: 'success', path: WORKFLOW_PATH, head_branch: 'main', head_sha: S1, head_repository: { id: 7 }, ...over,
});
const art = (id: number, runId: number, over: Record<string, unknown> = {}, name: string = BASELINE_ARTIFACT): Record<string, unknown> => ({
  id, name, expired: false, expires_at: FUTURE, created_at: `2026-10-${String(10 + id).padStart(2, '0')}T00:00:00Z`, size_in_bytes: 500,
  workflow_run: { id: runId, head_branch: 'main', head_sha: S1, head_repository_id: 7 }, ...over,
});
/** The runs the (loose) server lists, the artifacts of each run (grouped by their workflow_run.id), and the file of each artifact. */
function world(arts: Record<string, unknown>[], runs: Record<string, unknown>[], blobs: [number, unknown][]): FakeGh {
  const gh = new FakeGh();
  gh.runsAnswer = runs;
  for (const a of arts) {
    const rid = ((a.workflow_run as Record<string, unknown> | undefined)?.id ?? 0) as number;
    const cur = (gh.runArtifacts.get(rid) as { artifacts: unknown[] } | undefined) ?? { artifacts: [] };
    gh.runArtifacts.set(rid, { artifacts: [...cur.artifacts, a] });
  }
  for (const [id, b] of blobs) gh.blobs.set(id, b instanceof Error ? b : bytesOf(b));
  return gh;
}
const countsOf = (m: ReadonlyMap<string, number> | undefined): Record<string, number> => Object.fromEntries(m ?? []);

// ---------- inDefaultHistory ----------

describe('inDefaultHistory (compare semantics)', () => {
  it('inDefaultHistory: ahead or identical → true; behind, diverged or API error → false', async () => {
    for (const [status, want] of [['ahead', true], ['identical', true], ['behind', false], ['diverged', false]] as const) {
      const gh = new FakeGh();
      gh.fallbackCompare = { status };
      expect(await inDefaultHistory(gh, REPO, S1), status).toBe(want);
      expect(gh.calls).toEqual(['branch main', `compare ${S1}...${TIP}`]);   // the tip is resolved first; base = the sha, head = the tip commit, never a name
    }
    for (const err of [new Error('404 Not Found'), new Error('500'), new Error('rate limited')]) {
      const gh = new FakeGh();
      gh.fallbackCompare = err;
      expect(await inDefaultHistory(gh, REPO, S1), err.message).toBe(false);
    }
  });
  it('inDefaultHistory: a hostile answer is false (not an object, no status, a status that is not exactly ahead or identical)', async () => {
    for (const a of [null, undefined, 'ahead', 3, [], { status: 'AHEAD' }, { status: ' ahead' }, { status: ['ahead'] }, { status: { toString: () => 'ahead' } }, {}, { total: 'ahead' }, { status: 'ahead ' }]) {
      const gh = new FakeGh();
      gh.fallbackCompare = a;
      expect(await inDefaultHistory(gh, REPO, S1), JSON.stringify(a)).toBe(false);
    }
  });
  it('inDefaultHistory: a sha that is not 40 lower-case hex is false and never reaches the API', async () => {
    for (const s of ['', 'main', 'A'.repeat(40), 'a'.repeat(39), 'a'.repeat(41), `${'a'.repeat(39)}\n`, '../x', 'a'.repeat(40) + ' ']) {
      const gh = new FakeGh();
      expect(await inDefaultHistory(gh, REPO, s), JSON.stringify(s)).toBe(false);
      expect(gh.calls).toEqual([]);
    }
  });
});

// ---------- trustedRun ----------

describe('trustedRun', () => {
  const trusted = async (r: unknown, gh = new FakeGh()): Promise<boolean> => trustedRun(gh, r, REPO);
  it('trustedRun: a push run of the exact workflow in this repo on the default branch, whose sha is in the default history → trusted', async () => {
    expect(await trusted(run())).toBe(true);
  });
  it('trustedRun: event must be push (pull_request, pull_request_target, workflow_dispatch, schedule, workflow_run, merge_group, a missing event → no)', async () => {
    for (const event of ['pull_request', 'pull_request_target', 'workflow_dispatch', 'schedule', 'workflow_run', 'merge_group', 'Push', 'push ', '', undefined, 1]) {
      expect(await trusted(run({ event })), String(event)).toBe(false);
    }
  });
  it('trustedRun: path must equal .github/workflows/pipegen.yml exactly', async () => {
    for (const path of ['.github/workflows/pipegen.yaml', '.github/workflows/Pipegen.yml', '.github/workflows/pipegen.yml@refs/heads/main', ' .github/workflows/pipegen.yml',
      '.github/workflows/pipegen.yml ', 'x/.github/workflows/pipegen.yml', '.github/workflows/other.yml', '.github/workflows/pipegen.yml\n', './.github/workflows/pipegen.yml', '', undefined, null]) {
      expect(await trusted(run({ path })), String(path)).toBe(false);
    }
  });
  it('trustedRun: the head repository id must equal the repo id (a fork run with head_branch main → no); ids compared as numbers, never names', async () => {
    expect(await trusted(run({ head_repository: { id: 8, full_name: 'acme/app' } }))).toBe(false);   // a fork named like the repo
    for (const hr of [{ id: '7' }, { id: 7.5 }, { id: NaN }, {}, null, undefined, 'acme/app', [7], { full_name: 'acme/app' }]) {
      expect(await trusted(run({ head_repository: hr })), JSON.stringify(hr)).toBe(false);
    }
    // the repo name never decides: a head repository with another name but the right id is this repository (renamed)
    expect(await trusted(run({ head_repository: { id: 7, full_name: 'acme/old-name' } }))).toBe(true);
  });
  it('trustedRun: head_branch must be exactly the default branch', async () => {
    for (const head_branch of ['Main', 'main ', 'refs/heads/main', 'master', 'develop', '', undefined, null, ['main']]) {
      expect(await trusted(run({ head_branch })), JSON.stringify(head_branch)).toBe(false);
    }
  });
  it('trustedRun: tag named main → rejected (a push run with head_branch main whose head_sha is not in the default history)', async () => {
    const gh = new FakeGh();
    gh.compares.set(S1, { status: 'diverged' });
    expect(await trusted(run({ head_branch: 'main' }), gh)).toBe(false);
    expect(gh.calls).toContain(`compare ${S1}...${TIP}`);
  });
  it('trustedRun: head_sha not in default history (behind, diverged, API error, hostile answer) → rejected', async () => {
    for (const a of [{ status: 'behind' }, { status: 'diverged' }, new Error('404'), null, {}]) {
      const gh = new FakeGh();
      gh.fallbackCompare = a;
      expect(await trusted(run(), gh)).toBe(false);
    }
  });
  it('trustedRun: a bad head_sha, a bad id or a non-object run is rejected without asking the API', async () => {
    for (const r of [run({ head_sha: 'main' }), run({ head_sha: 'A'.repeat(40) }), run({ head_sha: undefined }), run({ id: 0 }), run({ id: -1 }), run({ id: 1.5 }), run({ id: '100' }), run({ id: undefined }),
      null, undefined, 'run', 5, [], [run()]]) {
      const gh = new FakeGh();
      expect(await trusted(r, gh), JSON.stringify(r)).toBe(false);
      expect(gh.calls).toEqual([]);
    }
  });
  it('trustedRun: the cheap checks come first, so a fork run costs no history call', async () => {
    const gh = new FakeGh();
    expect(await trusted(run({ event: 'pull_request', head_repository: { id: 8 } }), gh)).toBe(false);
    expect(gh.calls).toEqual([]);
  });
  it('trustedRun: inherited fields do not count (a prototype that carries the right values is not the run)', async () => {
    const proto = run();
    const r = Object.create(proto) as Record<string, unknown>;
    expect(await trusted(r)).toBe(false);
  });
});

// ---------- the signed baseline: the pure part ----------

describe('verifyBaselineArtifact (B6, S11)', () => {
  const verify = (d: unknown, meta = META(), ctx = CTX) => verifyBaselineArtifact(bytesOf(d), meta, ctx);
  it('baseline: a baseline signed with the current key, for its own run, is loaded (counts as a Map, tools from the count keys)', () => {
    const r = verify(goodDoc());
    expect(r.note).toBeUndefined();
    expect(countsOf(r.baseline?.counts)).toEqual(COUNTS);
    expect([...(r.baseline?.tools ?? [])].sort()).toEqual(['betterleaks', 'semgrep', 'trivy-config']);
  });
  it('baseline: the MAC is HMAC-SHA256 over the canonical JSON [format, runId, keyId, sorted [key, count] pairs]; the order of the keys in the file does not matter', () => {
    const reversed = Object.fromEntries(Object.entries(COUNTS).reverse());
    const r = verify({ mac: goodDoc().mac, counts: reversed, keyId: keyId(KEY), runId: 100 });
    expect(r.baseline).not.toBeNull();
    // and the counts are bound: a changed count under the old MAC is refused
    expect(verify({ ...goodDoc(), counts: { ...COUNTS, [Object.keys(COUNTS)[0] as string]: 1 } }).baseline).toBeNull();
  });
  it('baseline: MAC wrong or missing → ignored with a note, base-scan used', () => {
    for (const mac of [undefined, '', 'x', '0'.repeat(64), goodDoc().mac.toUpperCase(), goodDoc().mac.slice(1), `${goodDoc().mac}0`, goodDoc().mac.replace(/.$/, (c) => (c === '0' ? '1' : '0')), 5, null, [goodDoc().mac], { v: 1 }]) {
      const d: Record<string, unknown> = { ...goodDoc(), mac };
      if (mac === undefined) delete d.mac;
      const r = verify(d);
      expect(r.baseline, JSON.stringify(mac)).toBeNull();
      expect(r.note, JSON.stringify(mac)).toMatch(/MAC/);
    }
  });
  it('baseline: a MAC made with another key → ignored (its key id differs: the note says so)', () => {
    const r = verify(goodDoc({}, KEY2));
    expect(r.baseline).toBeNull();
    expect(r.note).toMatch(/key id/);
    // a forger who copies the real key id but signs with their own key: the MAC fails
    const f = verify({ ...goodDoc({}, KEY2), keyId: keyId(KEY) });
    expect(f.baseline).toBeNull();
    expect(f.note).toMatch(/MAC/);
  });
  it('baseline: key id differs → ignored (rotated key: every secret fingerprint is under another key; the base scan decides)', () => {
    const r = verify(goodDoc({ keyId: '0123456789abcdef' }));
    expect(r.baseline).toBeNull();
    expect(r.note).toMatch(/key id/);
  });
  it('baseline: swapped run id (a valid artifact of run 99 offered as the artifact of run 100) → ignored', () => {
    const r = verify(goodDoc({ runId: 99 }), META({ runId: 100 }));
    expect(r.baseline).toBeNull();
    expect(r.note).toMatch(/run/);
    // the run id inside the file is bound by the MAC: changing it alone fails
    expect(verify({ ...goodDoc(), runId: 100 }, META({ runId: 99 })).baseline).toBeNull();
    expect(verify({ ...goodDoc({ runId: 99 }), runId: 100 }, META({ runId: 100 })).baseline).toBeNull();
  });
  it('baseline: fork PR (no key) → not verifiable → null with a note, base-scan used', () => {
    for (const key of [undefined, '']) {
      const r = verify(goodDoc(), META(), { key, now: NOW });
      expect(r.baseline).toBeNull();
      expect(r.note).toMatch(/key/i);
    }
    expect(verify(goodDoc(), META(), { key: 'short', now: NOW }).baseline).toBeNull();
  });
  it('baseline: expired → null with a note (the flag, or an expiry time that has passed or is not a time)', () => {
    for (const meta of [META({ expired: true }), META({ expiresAt: PAST }), META({ expiresAt: '2026-10-30T12:00:00Z' }), META({ expiresAt: 'soon' }), META({ expiresAt: undefined }), META({ expiresAt: null })]) {
      const r = verify(goodDoc(), meta);
      expect(r.baseline, JSON.stringify(meta)).toBeNull();
      expect(r.note, JSON.stringify(meta)).toMatch(/expire/);
    }
  });
  it('baseline: the artifact name must be exactly pipegen-baseline', () => {
    for (const name of ['pipegen-baseline ', 'Pipegen-Baseline', 'pipegen-baseline2', CLEAN_RUN_ARTIFACT, '', 'pipegen-out-sast']) {
      expect(verify(goodDoc(), META({ name })).baseline, name).toBeNull();
    }
  });
  it('baseline: counts that are NaN, Infinity, negative, non-integer, unsafe, text or null are refused, even under a MAC that matches them', () => {
    const k = Object.keys(COUNTS)[0] as string;
    // the MAC canonicalises NaN/Infinity as null, so a forger can sign a doc whose JSON text holds 1e999: the values are checked on their own
    const text = (v: string): string => `{"runId":100,"keyId":"${keyId(KEY)}","counts":{${JSON.stringify(k)}:${v}},"mac":"${macOf(KEY, 100, keyId(KEY), { [k]: JSON.parse(v === '1e999' || v === '-1e999' ? 'null' : v) as number })}"}`;
    for (const v of ['1e999', '-1e999', '-1', '1.5', '0.5', '"2"', 'null', 'true', '[]', '{}', '9007199254740992', '1152921504606846976', '-0.0000001']) {
      const r = verify(text(v));
      expect(r.baseline, v).toBeNull();
      expect(r.note, v).toMatch(/count/);
    }
    // and with the true MAC over the JS value (NaN is not valid JSON, so it can only arrive as null)
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, 2 ** 53]) {
      const counts = { [k]: bad };
      const r = verify({ runId: 100, keyId: keyId(KEY), counts, mac: macOf(KEY, 100, keyId(KEY), counts) });
      expect(r.baseline, String(bad)).toBeNull();
    }
    // zero is a count; a whole number up to the safe maximum is fine
    expect(verify(goodDoc({}, KEY, { [k]: 0 })).baseline).not.toBeNull();
    expect(verify(goodDoc({}, KEY, { [k]: Number.MAX_SAFE_INTEGER })).baseline).not.toBeNull();
  });
  it('baseline: count keys must be the gate\'s own forms (fp or unmapped) and counts a plain map', () => {
    for (const counts of [{ 'plain': 1 }, { [`fp\0a\0b`]: 1 }, JSON.parse('{"__proto__":1}') as Record<string, number>, { [`fp\0a\0b\0${'x'.repeat(5000)}`]: 1 }, { [`other\0a\0b\0c`]: 1 }]) {
      expect(verify(goodDoc({}, KEY, counts)).baseline, JSON.stringify(Object.keys(counts))).toBeNull();
    }
    for (const counts of [[], [1], 'x', 5, null, undefined]) {
      expect(verify({ runId: 100, keyId: keyId(KEY), counts, mac: goodDoc().mac }).baseline).toBeNull();
    }
    expect(verify(goodDoc({}, KEY, {})).baseline?.counts.size).toBe(0);   // an empty baseline (a repo with no findings) is a valid one
  });
  it('baseline: the file must be exactly { runId, keyId, counts, mac } — extra fields, wrong types, bad JSON, arrays and an oversize file are refused', () => {
    const g = goodDoc();
    for (const d of [{ ...g, extra: 1 }, { ...g, runId: '100' }, { ...g, runId: 100.5 }, { ...g, runId: 0 }, { ...g, runId: -100 }, { ...g, keyId: 5 }, { ...g, keyId: keyId(KEY).toUpperCase() }, { ...g, keyId: keyId(KEY).slice(1) },
      [], null, 'x', 5, '{', '', '{"runId":100', JSON.stringify(g) + 'x', ` ${JSON.stringify(g)}x`]) {
      expect(verify(d).baseline, JSON.stringify(d)?.slice(0, 60)).toBeNull();
    }
    expect(verifyBaselineArtifact(new Uint8Array(0), META(), CTX).baseline).toBeNull();
    expect(verifyBaselineArtifact(new Uint8Array(9 * 1024 * 1024).fill(32), META(), CTX).baseline).toBeNull();
    // duplicate keys: the last one wins in JSON.parse, which the MAC then fails to match
    expect(verify(`{"runId":100,"runId":99,"keyId":"${keyId(KEY)}","counts":{},"mac":"${g.mac}"}`).baseline).toBeNull();
  });
  it('baseline: the verified result does not alias the input and carries no tool-error marker', () => {
    const r = verify(goodDoc());
    expect(r.baseline?.counts).toBeInstanceOf(Map);
    expect(Object.keys(r)).toEqual(expect.arrayContaining(['baseline']));
  });
});

// ---------- the clean-run marker ----------

describe('verifyCleanRunArtifact', () => {
  const marker = (runId = 100, key = KEY, over: Record<string, unknown> = {}): Record<string, unknown> => ({ runId, keyId: keyId(key), mac: markerMac(key, runId, keyId(key)), ...over });
  const meta = (over: Partial<ArtifactMeta> = {}): ArtifactMeta => META({ name: CLEAN_RUN_ARTIFACT, ...over });
  const seen = (d: unknown, m = meta(), ctx = CTX) => verifyCleanRunArtifact(bytesOf(d), m, ctx);
  it('cleanRun: a marker signed with the current key for its own run is seen', () => {
    expect(seen(marker()).seen).toBe(true);
  });
  it('cleanRun: MAC checked — wrong, missing, another key, a different key id, a swapped run id, a wrong name, expired, no key → not seen', () => {
    expect(seen(marker(100, KEY, { mac: '0'.repeat(64) })).seen).toBe(false);
    const noMac = marker(); delete noMac.mac;
    expect(seen(noMac).seen).toBe(false);
    expect(seen(marker(100, KEY2)).seen).toBe(false);
    expect(seen(marker(100, KEY, { keyId: '0123456789abcdef' })).seen).toBe(false);
    expect(seen(marker(99)).seen).toBe(false);
    expect(seen(marker(100, KEY, { runId: 99 })).seen).toBe(false);
    expect(seen(marker(), meta({ name: BASELINE_ARTIFACT })).seen).toBe(false);
    expect(seen(marker(), meta({ expired: true })).seen).toBe(false);
    expect(seen(marker(), meta({ expiresAt: PAST })).seen).toBe(false);
    // fix round 1 (I2): no usable key (a fork PR) → the marker counts on run trust alone; a bad shape never does
    expect(seen(marker(), meta(), { key: undefined, now: NOW }).seen).toBe(true);
    expect(seen(marker(), meta(), { key: 'short', now: NOW }).seen).toBe(true);
    expect(seen(marker(100, KEY2), meta(), { key: undefined, now: NOW }).seen).toBe(true);   // not checked without a key
    expect(seen({ ...marker(), extra: 1 }, meta(), { key: undefined, now: NOW }).seen).toBe(false);
    expect(seen(marker(99), meta(), { key: undefined, now: NOW }).seen).toBe(false);   // still the artifact's own run
    expect(seen(marker(), meta({ expired: true }), { key: undefined, now: NOW }).seen).toBe(false);
    expect(seen({ ...marker(), extra: 1 }).seen).toBe(false);
    expect(seen('not json').seen).toBe(false);
    expect(seen(marker()).note).toBeUndefined();
    expect(seen(marker(100, KEY2)).note).toMatch(/key id/);
  });
  it('cleanRun: a baseline cannot pass as a marker, and a marker cannot pass as a baseline (separate MAC formats)', () => {
    const b = goodDoc({}, KEY, {});
    expect(seen({ runId: b.runId, keyId: b.keyId, mac: b.mac }).seen).toBe(false);
    const m = marker();
    expect(verifyBaselineArtifact(bytesOf({ ...m, counts: {} }), META(), CTX).baseline).toBeNull();
  });
});

// ---------- loadBaseline / cleanRunSeen with the injected client ----------

describe('loadBaseline (trusted runs only)', () => {
  const load = (gh: GateGithub, ctx: VerifyContext = CTX) => loadBaseline(gh, REPO, ctx);
  const signed = (runId: number, counts: Record<string, number> = COUNTS, key = KEY): Doc => goodDoc({ runId }, key, counts);

  it('baseline: newest trusted artifact used, run id checked (the API order is not trusted)', async () => {
    const older = { [`fp\0a\0t\0${hex('old')}`]: 1 };
    const newer = { [`fp\0a\0t\0${hex('new')}`]: 4 };
    const gh = world([art(1, 100), art(3, 300), art(2, 200)], [run({ id: 100 }), run({ id: 200 }), run({ id: 300 })], [[1, signed(100, older)], [2, signed(200, older)], [3, signed(300, newer)]]);
    const r = await load(gh);
    expect(countsOf(r.baseline?.counts)).toEqual(newer);
    // the artifact of run 300 carries a file signed for run 200: the run id is checked against the artifact's run, so no baseline (and no fall back to run 200)
    const gh2 = world([art(2, 200), art(3, 300)], [run({ id: 200 }), run({ id: 300 })], [[2, signed(200, older)], [3, signed(200, newer)]]);
    const r2 = await load(gh2);
    expect(r2.baseline).toBeNull();
    expect(r2.note).toMatch(/run/);
  });
  it('baseline: fork run with head_branch main rejected (an artifact named pipegen-baseline uploaded by a fork PR; S4)', async () => {
    const forged = { [`fp\0semgrep\0semgrep\0${hex('evil')}`]: 9 };
    const gh = world([art(2, 200)], [run({ id: 200, event: 'pull_request', head_branch: 'main', head_repository: { id: 8 } })], [[2, signed(200, forged)]]);
    const r = await load(gh);
    expect(r.baseline).toBeNull();
    expect(gh.calls.some((c) => c.startsWith('download'))).toBe(false);
    // a same-repo PR run (read access to secrets is not the point: the event is) is rejected too
    const gh2 = world([art(2, 200)], [run({ id: 200, event: 'pull_request', head_branch: 'feature' })], [[2, signed(200, forged)]]);
    expect((await load(gh2)).baseline).toBeNull();
    // a fork run with the right event but another head repository id
    const gh3 = world([art(2, 200)], [run({ id: 200, head_repository: { id: 8 } })], [[2, signed(200, forged)]]);
    expect((await load(gh3)).baseline).toBeNull();
  });
  it('baseline: a newer artifact from an untrusted run does not hide the older trusted one', async () => {
    const real = { [`fp\0a\0t\0${hex('real')}`]: 2 };
    const gh = world([art(1, 100), art(5, 500)], [run({ id: 100 }), run({ id: 500, event: 'pull_request', head_repository: { id: 8 } })], [[1, signed(100, real)], [5, signed(500, {})]]);
    expect(countsOf((await load(gh)).baseline?.counts)).toEqual(real);
  });
  it('baseline: pull_request-event artifact rejected', async () => {
    const gh = world([art(2, 200)], [run({ id: 200, event: 'pull_request' })], [[2, signed(200)]]);
    expect((await load(gh)).baseline).toBeNull();
  });
  it('baseline: a tag named main (sha outside the default history) and a sha not in the default history are ignored', async () => {
    for (const status of ['diverged', 'behind']) {
      const gh = world([art(2, 200)], [run({ id: 200 })], [[2, signed(200)]]);
      gh.fallbackCompare = { status };
      const r = await load(gh);
      expect(r.baseline, status).toBeNull();
      expect(gh.calls.some((c) => c.startsWith('download'))).toBe(false);
    }
    const err = world([art(2, 200)], [run({ id: 200 })], [[2, signed(200)]]);
    err.fallbackCompare = new Error('boom');
    expect((await load(err)).baseline).toBeNull();
  });
  it('baseline: the run is read from the API, never from the artifact listing (a listing that claims push/main for a PR run is not believed)', async () => {
    const a = art(2, 200, { workflow_run: { id: 200, head_branch: 'main', head_sha: S1, head_repository_id: 7, event: 'push' } });
    const gh = world([a], [run({ id: 200, event: 'pull_request' })], [[2, signed(200)]]);
    expect((await load(gh)).baseline).toBeNull();
  });
  it('baseline: an artifact listed under a run must belong to that run (its workflow_run.id)', async () => {
    const gh = world([], [run({ id: 200 })], [[2, signed(200)]]);
    gh.runArtifacts.set(200, { artifacts: [art(2, 999)] });
    expect((await load(gh)).baseline).toBeNull();
    expect(gh.calls.some((c) => c.startsWith('download'))).toBe(false);
  });
  it('baseline: expired → null with note (flag, or past expiry)', async () => {
    for (const over of [{ expired: true }, { expires_at: PAST }, { expires_at: null }]) {
      const gh = world([art(2, 200, over)], [run({ id: 200 })], [[2, signed(200)]]);
      const r = await load(gh);
      expect(r.baseline, JSON.stringify(over)).toBeNull();
      expect(r.note, JSON.stringify(over)).toMatch(/expire/);
      expect(gh.calls.some((c) => c.startsWith('download'))).toBe(false);
    }
  });
  it('baseline: 404 → null, base-scan used (list, run or download fails or the artifact was deleted)', async () => {
    const e = new Error('404 Not Found');
    const a = world([art(2, 200)], [run({ id: 200 })], [[2, signed(200)]]); a.runsAnswer = e;   // the run list fails
    const b = world([art(2, 200)], [], [[2, signed(200)]]);   // the run is gone
    const d = world([art(2, 200)], [run({ id: 200 })], [[2, signed(200)]]); d.runArtifacts.set(200, e);   // the artifact list fails
    const c = world([art(2, 200)], [run({ id: 200 })], [[2, e]]);   // the artifact was deleted
    for (const gh of [a, b, c, d]) {
      const r = await load(gh);
      expect(r.baseline).toBeNull();
      expect(r.note).toBeTruthy();
    }
    const none = await load(world([], [], []));
    expect(none.baseline).toBeNull();
    expect(none.note).toMatch(/no .*baseline/i);
  });
  it('baseline: only an exact-name artifact counts', async () => {
    const gh = world([art(2, 200, {}, 'pipegen-baseline '), art(3, 300, {}, 'PIPEGEN-BASELINE'), art(4, 400, {}, CLEAN_RUN_ARTIFACT)], [run({ id: 200 }), run({ id: 300 }), run({ id: 400 })], [[2, signed(200)], [3, signed(300)], [4, signed(400)]]);
    expect((await load(gh)).baseline).toBeNull();
    expect(gh.calls.some((c) => c.startsWith('download'))).toBe(false);
  });
  it('baseline: hostile listings are null (not an object, artifacts not a list, entries with bad ids, names or dates)', async () => {
    for (const listing of [null, 'x', [], {}, { artifacts: 'x' }, { artifacts: {} }, { artifacts: [null, 1, 'x', []] }, { artifacts: [{ id: 'x', name: BASELINE_ARTIFACT }] },
      { artifacts: [art(0, 100)] }, { artifacts: [art(1.5, 100)] }, { artifacts: [{ ...art(1, 100), workflow_run: null }] }, { artifacts: [{ ...art(1, 100), workflow_run: { id: '100' } }] }, { artifacts: [{ ...art(1, 100), created_at: 'yesterday' }] }]) {
      const gh = world([], [run()], [[1, signed(100)]]);
      gh.runArtifacts.set(100, listing);
      const r = await load(gh);
      expect(r.baseline, JSON.stringify(listing)?.slice(0, 80)).toBeNull();
    }
  });
  it('baseline: hostile run listings are null (not an object, workflow_runs not a list, junk entries)', async () => {
    for (const listing of [null, 'x', 5, {}, { workflow_runs: 'x' }, { workflow_runs: {} }, { workflow_runs: [null, 1, 'x', []] }, { workflow_runs: [{ id: 'x' }] }]) {
      const gh = world([art(2, 200)], [], [[2, signed(200)]]);
      gh.runsAnswer = listing;
      expect((await load(gh)).baseline, JSON.stringify(listing)).toBeNull();
    }
  });
  it('baseline: a forged newest trusted artifact (wrong MAC, missing MAC, another key, swapped run id) gives null — it does not fall back to an older one', async () => {
    const old = { [`fp\0a\0t\0${hex('o')}`]: 1 };
    const forgeries: [string, unknown][] = [
      ['wrong MAC', { ...signed(300), mac: '0'.repeat(64) }],
      ['missing MAC', (() => { const d: Record<string, unknown> = { ...signed(300) }; delete d.mac; return d; })()],
      ['another key', signed(300, COUNTS, KEY2)],
      ['swapped run id', signed(200)],
      ['changed counts', { ...signed(300), counts: { [`fp\0a\0t\0${hex('x')}`]: 1 } }],
      ['not json', 'oops'],
    ];
    for (const [why, forged] of forgeries) {
      const gh = world([art(2, 200), art(3, 300)], [run({ id: 200 }), run({ id: 300 })], [[2, signed(200, old)], [3, forged]]);
      const r = await load(gh);
      expect(r.baseline, why).toBeNull();
      expect(r.note, why).toBeTruthy();
    }
  });
  it('baseline: a fork PR (no key) cannot verify → null and no API call at all', async () => {
    const gh = world([art(2, 200)], [run({ id: 200 })], [[2, signed(200)]]);
    const r = await load(gh, { key: undefined, now: NOW });
    expect(r.baseline).toBeNull();
    expect(r.note).toMatch(/key/i);
    expect(gh.calls).toEqual([]);
  });
  it('baseline: 1,000 untrusted artifacts (PR runs, forks) do not hide the trusted one: runs are listed, artifacts only per trusted run', async () => {
    const real = { [`fp\0a\0t\0${hex('real')}`]: 2 };
    const gh = world([art(1, 100)], [run({ id: 100 })], [[1, signed(100, real)]]);
    // a thousand newer artifacts of the same name, each in a PR run of a fork (they exist in the repo; the loader never lists them)
    for (let i = 0; i < 1000; i++) gh.runArtifacts.set(5000 + i, { artifacts: [art(5000 + i, 5000 + i, { created_at: '2026-10-29T00:00:00Z' })] });
    const r = await load(gh);
    expect(countsOf(r.baseline?.counts)).toEqual(real);
    expect(gh.calls.filter((c) => c.startsWith('artifacts')).every((c) => c.startsWith('artifacts 100 '))).toBe(true);
  });
  it('baseline: the run list asks for push runs of the workflow on the default branch that succeeded, newest first, a bounded number of pages', async () => {
    const gh = world([], [], []);
    await load(gh);
    expect(gh.lastQuery).toMatchObject({ workflow: 'pipegen.yml', branch: 'main', event: 'push', status: 'success', page: 1 });
    // a flood of listed untrusted runs (a loose server) costs at most MAX_RUN_PAGES list calls and no artifact call
    const flood = Array.from({ length: 1000 }, (_, i) => run({ id: 9000 - i, event: 'pull_request', head_repository: { id: 8 } }));
    const g2 = world([], flood, []);
    const r = await load(g2);
    expect(r.baseline).toBeNull();
    expect(g2.calls.filter((c) => c.startsWith('runs')).length).toBeLessThanOrEqual(MAX_RUN_PAGES);
    expect(g2.calls.some((c) => c.startsWith('artifacts'))).toBe(false);
  });
  it('baseline: at most MAX_TRUSTED_RUNS trusted runs are searched for an artifact', async () => {
    const runs = Array.from({ length: 60 }, (_, i) => run({ id: 1000 - i }));
    const gh = world([], runs, []);
    expect((await load(gh)).baseline).toBeNull();
    expect(gh.calls.filter((c) => c.startsWith('artifacts')).length).toBeLessThanOrEqual(MAX_TRUSTED_RUNS);
  });
  it('baseline: a trusted run with no baseline artifact is skipped, the next trusted run is tried', async () => {
    const real = { [`fp\0a\0t\0${hex('real')}`]: 3 };
    const gh = world([art(1, 100)], [run({ id: 100 }), run({ id: 200 })], [[1, signed(100, real)]]);
    expect(countsOf((await load(gh)).baseline?.counts)).toEqual(real);
  });
  it('trustedRun: a tag named like the default branch (the tag exists) makes no run trusted, even for a sha in the history; an error in the tag lookup does too', async () => {
    const gh = new FakeGh(); gh.tagAnswer = true;
    expect(await trustedRun(gh, run(), REPO)).toBe(false);
    expect(gh.calls).toContain('tag main');
    const err = new FakeGh(); err.tagAnswer = new Error('500');
    expect(await trustedRun(err, run(), REPO)).toBe(false);
    for (const odd of [undefined, null, 'true', 1]) { const g = new FakeGh(); g.tagAnswer = odd; expect(await trustedRun(g, run(), REPO), String(odd)).toBe(false); }
    const none = new FakeGh();
    expect(await trustedRun(none, run(), REPO)).toBe(true);
    // fix round 1 (I1): asked fresh for every run, never cached
    await trustedRun(none, run({ id: 101 }), REPO); await trustedRun(none, run({ id: 102 }), REPO);
    expect(none.calls.filter((c) => c.startsWith('tag')).length).toBe(3);
  });
  it('baseline: with a tag named like the default branch, no baseline and no clean-run marker is trusted', async () => {
    const gh = world([art(2, 200)], [run({ id: 200 })], [[2, signed(200)]]); gh.tagAnswer = true;
    expect((await load(gh)).baseline).toBeNull();
    const m = world([art(2, 200, {}, CLEAN_RUN_ARTIFACT)], [run({ id: 200 })], [[2, { runId: 200, keyId: keyId(KEY), mac: markerMac(KEY, 200, keyId(KEY)) }]]); m.tagAnswer = true;
    expect((await cleanRunSeen(m, REPO, CTX)).seen).toBe(false);
  });
  it('baseline: a size over the cap in the listing is not downloaded', async () => {
    const gh = world([art(2, 200, { size_in_bytes: 50 * 1024 * 1024 })], [run({ id: 200 })], [[2, signed(200)]]);
    const r = await load(gh);
    expect(r.baseline).toBeNull();
    expect(gh.calls.some((c) => c.startsWith('download'))).toBe(false);
  });
  it('baseline: a download that is not bytes is null', async () => {
    const gh = world([art(2, 200)], [run({ id: 200 })], []);
    gh.blobs.set(2, 'text' as unknown);
    expect((await load(gh)).baseline).toBeNull();
  });
});

describe('cleanRunSeen (trusted runs only)', () => {
  const marker = (runId: number, key = KEY): Record<string, unknown> => ({ runId, keyId: keyId(key), mac: markerMac(key, runId, keyId(key)) });
  const clean = (gh: GateGithub, ctx: VerifyContext = CTX) => cleanRunSeen(gh, REPO, ctx);
  const cart = (id: number, runId: number, over: Record<string, unknown> = {}) => art(id, runId, over, CLEAN_RUN_ARTIFACT);
  it('cleanRun: a marker from a trusted run, signed with the current key → seen', async () => {
    const gh = world([cart(2, 200)], [run({ id: 200 })], [[2, marker(200)]]);
    expect((await clean(gh)).seen).toBe(true);
    expect(gh.calls).toContain(`artifacts 200 ${CLEAN_RUN_ARTIFACT}`);
  });
  it('cleanRun: marker from untrusted run ignored (pull_request event, fork, tag named main, not in history, wrong path)', async () => {
    for (const r of [run({ id: 200, event: 'pull_request' }), run({ id: 200, head_repository: { id: 8 } }), run({ id: 200, path: '.github/workflows/other.yml' }), run({ id: 200, head_branch: 'feature' })]) {
      const gh = world([cart(2, 200)], [r], [[2, marker(200)]]);
      expect((await clean(gh)).seen).toBe(false);
    }
    const gh = world([cart(2, 200)], [run({ id: 200 })], [[2, marker(200)]]);
    gh.fallbackCompare = { status: 'diverged' };
    expect((await clean(gh)).seen).toBe(false);
  });
  it('cleanRun: MAC checked, forged / other-key / swapped-run / expired / deleted / fork (no key) → not seen', async () => {
    const cases: [string, unknown][] = [['bad mac', { ...marker(200), mac: '0'.repeat(64) }], ['other key', marker(200, KEY2)], ['swapped run', marker(100)]];
    for (const [why, m] of cases) {
      const gh = world([cart(2, 200)], [run({ id: 200 })], [[2, m]]);
      expect((await clean(gh)).seen, why).toBe(false);
    }
    expect((await clean(world([cart(2, 200, { expired: true })], [run({ id: 200 })], [[2, marker(200)]]))).seen).toBe(false);
    expect((await clean(world([cart(2, 200)], [run({ id: 200 })], [[2, new Error('404')]]))).seen).toBe(false);
    // no key (a fork PR): the marker of a trusted run still counts (I2); the API is used
    const gh = world([cart(2, 200)], [run({ id: 200 })], [[2, marker(200)]]);
    expect((await clean(gh, { key: undefined, now: NOW })).seen).toBe(true);
    expect(gh.calls.length).toBeGreaterThan(0);
    const err = new FakeGh(); err.runsAnswer = new Error('500');
    expect((await clean(err)).seen).toBe(false);
  });
  it('cleanRun: 1,000 untrusted markers (PR runs) do not hide the trusted one', async () => {
    const gh = world([cart(2, 200)], [run({ id: 200 })], [[2, marker(200)]]);
    for (let i = 0; i < 1000; i++) gh.runArtifacts.set(5000 + i, { artifacts: [cart(5000 + i, 5000 + i)] });
    expect((await clean(gh)).seen).toBe(true);
    expect(gh.calls.filter((c) => c.startsWith('artifacts')).every((c) => c.startsWith('artifacts 200 '))).toBe(true);
  });
  it('cleanRun: any valid trusted marker counts (not only the newest)', async () => {
    const gh = world([cart(2, 200), cart(3, 300)], [run({ id: 200 }), run({ id: 300, event: 'pull_request' })], [[2, marker(200)], [3, marker(300)]]);
    expect((await clean(gh)).seen).toBe(true);
  });
});

// ---------- building and saving ----------

describe('buildBaseline / saveBaseline (tool errors are never stored)', () => {
  const kid = keyId(KEY);
  type C = Parameters<typeof buildBaseline>[0]['checks'][number];
  const chk = (over: Partial<C> = {}): C => ({ job: 'sast', tool: 'semgrep', status: 'ok', findings: [fnd()], ...over });
  const build = (checks: C[], over: Record<string, unknown> = {}) => buildBaseline({ runId: 100, key: KEY, checks, sameRunTools: ['osv-scanner', 'trivy-image', 'trivy-licence'], ...over });
  const parse = (bytes: Uint8Array): Doc => JSON.parse(new TextDecoder().decode(bytes)) as Doc;

  it('baseline: counts per countKeyOf (extra occurrences count), signed so that verifyBaselineArtifact loads it', () => {
    const a = fnd({ fingerprint: hex('a') });
    const b = fnd({ fingerprint: hex('b'), ruleId: 'r2' });
    const un = fnd({ tool: 'trivy-config', ruleId: 'AVD-1', fingerprint: hex('u'), file: undefined, uriUnmapped: true });
    const built = build([chk({ findings: [a, a, b] }), chk({ job: 'iac', tool: 'trivy-config', findings: [un, un, un] })]);
    const doc = parse(built.bytes);
    expect(Object.keys(doc).sort()).toEqual(['counts', 'keyId', 'mac', 'runId']);
    expect(doc.runId).toBe(100);
    expect(doc.keyId).toBe(kid);
    expect(doc.counts).toEqual({ [countKeyOf('sast', a)]: 2, [countKeyOf('sast', b)]: 1, [countKeyOf('iac', un)]: 3 });
    expect(doc.mac).toBe(macOf(KEY, 100, kid, doc.counts));
    const back = verifyBaselineArtifact(built.bytes, META({ runId: 100 }), CTX);
    expect(countsOf(back.baseline?.counts)).toEqual(doc.counts);
    expect([...(back.baseline?.tools ?? [])].sort()).toEqual(['semgrep', 'trivy-config']);
  });
  it('baseline: deterministic — the same facts in any order give the same bytes', () => {
    const a = fnd({ fingerprint: hex('a') }), b = fnd({ fingerprint: hex('b') });
    const one = build([chk({ findings: [a, b] }), chk({ job: 'x', tool: 'semgrep', findings: [b] })]);
    const two = build([chk({ job: 'x', tool: 'semgrep', findings: [b] }), chk({ findings: [b, a] })]);
    expect(Buffer.from(one.bytes).equals(Buffer.from(two.bytes))).toBe(true);
  });
  it('baseline: tool errors are never stored (a check with status tool-error contributes nothing, even if it lists findings)', () => {
    const built = build([chk({ status: 'tool-error', findings: [fnd({ fingerprint: hex('te') })] }), chk({ job: 'ok', findings: [fnd({ fingerprint: hex('ok') })] })]);
    const keys = Object.keys(parse(built.bytes).counts);
    expect(keys).toHaveLength(1);
    expect(keys[0]).toContain('ok');
    expect(built.skipped.map((s) => s.job)).toEqual(['sast']);
    expect(built.skipped[0]?.reason).toMatch(/tool error/);
  });
  it('baseline: a check with no coverage (gitleaks or nuclei, nothing reported) is not stored; neither is a dependency or image tool (the same-run base scan owns those)', () => {
    const built = build([
      chk({ job: 'secrets', tool: 'gitleaks', noCoverage: true, findings: [] }),
      chk({ job: 'deps', tool: 'osv-scanner', findings: [fnd({ tool: 'osv-scanner', fingerprint: hex('cve') })] }),
      chk({ job: 'img', tool: 'trivy-image', findings: [fnd({ tool: 'trivy-image', fingerprint: hex('img') })] }),
      chk({ job: 'sast', findings: [fnd({ fingerprint: hex('s') })] }),
    ]);
    expect(Object.keys(parse(built.bytes).counts)).toHaveLength(1);
    expect(built.skipped.map((s) => s.job).sort()).toEqual(['deps', 'img', 'secrets']);
  });
  it('baseline: secret fingerprints made under a different key id are ignored (that check is left out; the base scan decides)', () => {
    const s = leak('s1');
    const built = build([
      chk({ job: 'secrets', tool: 'betterleaks', keyId: kid, findings: [s] }),
      chk({ job: 'secrets-2', tool: 'betterleaks', keyId: keyId(KEY2), findings: [leak('s2')] }),
      chk({ job: 'secrets-3', tool: 'betterleaks', findings: [leak('s3')] }),
      chk({ job: 'sast', findings: [fnd({ fingerprint: hex('z') })] }),
    ]);
    const keys = Object.keys(parse(built.bytes).counts);
    expect(keys).toHaveLength(2);
    expect(keys.some((k) => k.includes('secrets-2') || k.includes('secrets-3'))).toBe(false);
    expect(built.skipped.map((x) => x.job).sort()).toEqual(['secrets-2', 'secrets-3']);
  });
  it('baseline: a key that cannot be used, or a run id that is not a positive whole number, is refused (nothing is built)', () => {
    for (const key of [undefined, '', 'short', 'k"'.repeat(30)]) expect(() => build([chk()], { key })).toThrow(/key/i);
    for (const runId of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) expect(() => build([chk()], { runId })).toThrow(/run id/i);
  });
  it('baseline: the key never appears in the bytes', () => {
    expect(Buffer.from(build([chk()]).bytes).toString('utf8')).not.toContain(KEY);
  });
  it('saveBaseline: uploads pipegen-baseline once with retention 90 days; an upload error is not swallowed', async () => {
    const calls: { name: string; bytes: Uint8Array; retentionDays: number }[] = [];
    const up: ArtifactUploader = { async upload(name, bytes, opts) { calls.push({ name, bytes, retentionDays: opts.retentionDays }); } };
    await saveBaseline({ runId: 100, key: KEY, checks: [chk()], sameRunTools: [] }, up);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.name).toBe(BASELINE_ARTIFACT);
    expect(calls[0]?.retentionDays).toBe(BASELINE_RETENTION_DAYS);
    expect(BASELINE_RETENTION_DAYS).toBe(90);
    expect(verifyBaselineArtifact(calls[0]?.bytes as Uint8Array, META({ runId: 100 }), CTX).baseline).not.toBeNull();
    const bad: ArtifactUploader = { async upload() { throw new Error('upload failed'); } };
    await expect(saveBaseline({ runId: 100, key: KEY, checks: [chk()], sameRunTools: [] }, bad)).rejects.toThrow(/upload failed/);
  });
  it('cleanRun: buildCleanRunMarker is signed so that verifyCleanRunArtifact sees it, and saved under pipegen-clean-run', async () => {
    const bytes = buildCleanRunMarker(100, KEY);
    expect(JSON.parse(new TextDecoder().decode(bytes))).toEqual({ runId: 100, keyId: kid, mac: markerMac(KEY, 100, kid) });
    expect(verifyCleanRunArtifact(bytes, META({ name: CLEAN_RUN_ARTIFACT }), CTX).seen).toBe(true);
    expect(() => buildCleanRunMarker(0, KEY)).toThrow();
    expect(() => buildCleanRunMarker(100, 'short')).toThrow();
  });
});

// ---------- the property: nothing that fails a check is ever trusted ----------

describe('property: no artifact or API answer that fails any check is ever returned as a trusted baseline', () => {
  function rng(seed: number): () => number {
    let s = seed >>> 0;
    return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 2 ** 32; };
  }
  // each breaker makes exactly one check fail
  const breakers: { name: string; apply: (w: Scenario) => void }[] = [
    { name: 'wrong mac', apply: (w) => { w.doc.mac = '0'.repeat(64); } },
    { name: 'no mac', apply: (w) => { delete (w.doc as Partial<Doc>).mac; } },
    { name: 'other key', apply: (w) => { w.doc = goodDoc({ runId: w.runId }, KEY2); } },
    { name: 'key id swapped', apply: (w) => { w.doc.keyId = 'f'.repeat(16); } },
    { name: 'run id swapped', apply: (w) => { w.doc.runId = w.runId + 1; } },
    { name: 'counts changed', apply: (w) => { w.doc.counts = { ...w.doc.counts, [`fp\0z\0z\0${hex('z')}`]: 1 }; } },
    { name: 'count NaN', apply: (w) => { w.rawCount = 'null'; } },
    { name: 'count Infinity', apply: (w) => { w.rawCount = '1e999'; } },
    { name: 'count negative', apply: (w) => { w.rawCount = '-3'; } },
    { name: 'count fraction', apply: (w) => { w.rawCount = '2.5'; } },
    { name: 'extra field', apply: (w) => { (w.doc as unknown as Record<string, unknown>).more = 1; } },
    { name: 'truncated', apply: (w) => { w.truncate = true; } },
    { name: 'event pull_request', apply: (w) => { w.run.event = 'pull_request'; } },
    { name: 'event workflow_dispatch', apply: (w) => { w.run.event = 'workflow_dispatch'; } },
    { name: 'wrong path', apply: (w) => { w.run.path = '.github/workflows/pipegen.yml@refs/heads/main'; } },
    { name: 'fork repo id', apply: (w) => { w.run.head_repository = { id: 8 }; } },
    { name: 'other branch', apply: (w) => { w.run.head_branch = 'feature'; } },
    { name: 'tag named like the default branch', apply: (w) => { w.compare = { status: 'diverged' }; } },
    { name: 'sha behind', apply: (w) => { w.compare = { status: 'behind' }; } },
    { name: 'compare error', apply: (w) => { w.compare = new Error('boom'); } },
    { name: 'compare garbage', apply: (w) => { w.compare = 'ahead'; } },
    { name: 'expired flag', apply: (w) => { w.artMeta.expired = true; } },
    { name: 'expired date', apply: (w) => { w.artMeta.expires_at = PAST; } },
    { name: 'wrong name', apply: (w) => { w.artMeta.name = 'pipegen-baseline-x'; } },
    { name: 'run lies about its id', apply: (w) => { w.run.id = w.runId + 5; } },
    { name: 'download fails', apply: (w) => { w.downloadError = true; } },
    { name: 'no key', apply: (w) => { w.ctx = { key: undefined, now: NOW }; } },
    { name: 'short key', apply: (w) => { w.ctx = { key: 'abc', now: NOW }; } },
    { name: 'run missing', apply: (w) => { w.dropRun = true; } },
    { name: 'a tag named like the default branch exists', apply: (w) => { w.tag = true; } },
  ];
  interface Scenario {
    runId: number; doc: Doc; rawCount?: string; truncate?: boolean; run: Record<string, unknown>; compare: Answer; artMeta: Record<string, unknown>;
    downloadError?: boolean; ctx: VerifyContext; dropRun?: boolean; tag?: boolean;
  }
  const fresh = (): Scenario => ({ runId: 100, doc: goodDoc(), run: run({ id: 100 }), compare: { status: 'ahead' }, artMeta: art(7, 100), ctx: CTX });
  async function evaluate(w: Scenario): Promise<ReturnType<typeof loadBaseline> extends Promise<infer R> ? R : never> {
    let text = JSON.stringify(w.doc);
    if (w.rawCount !== undefined) {
      const k = Object.keys(COUNTS)[0] as string;
      text = text.replace(/"counts":\{.*?\},"mac"/s, `"counts":{${JSON.stringify(k)}:${w.rawCount}},"mac"`);
    }
    if (w.truncate) text = text.slice(0, text.length - 7);
    const gh = new FakeGh();
    gh.runsAnswer = w.dropRun ? [] : [w.run];
    gh.runArtifacts.set(w.run.id as number, { artifacts: [w.artMeta] });
    gh.tagAnswer = w.tag ?? false;
    gh.fallbackCompare = w.compare;
    gh.blobs.set(7, w.downloadError ? new Error('404') : bytesOf(text));
    return loadBaseline(gh, REPO, w.ctx);
  }
  it('property: every combination of 1 to 4 failing checks gives null; the untouched scenario loads', async () => {
    const base = await evaluate(fresh());
    expect(base.baseline).not.toBeNull();
    const rand = rng(20261030);
    let n = 0;
    for (let i = 0; i < 1500; i++) {
      const w = fresh();
      const picks = new Set<number>();
      const how = 1 + Math.floor(rand() * 4);
      while (picks.size < how) picks.add(Math.floor(rand() * breakers.length));
      for (const p of picks) (breakers[p] as { apply: (w: Scenario) => void }).apply(w);
      const r = await evaluate(w);
      if (r.baseline !== null) throw new Error(`trusted although [${[...picks].map((p) => breakers[p]?.name).join(', ')}] failed`);
      n++;
    }
    expect(n).toBe(1500);
    // and each breaker alone
    for (const b of breakers) {
      const w = fresh();
      b.apply(w);
      expect((await evaluate(w)).baseline, b.name).toBeNull();
    }
  });
  it('property: trustedRun is true only when every field is right (random field damage never passes)', async () => {
    const rand = rng(7);
    const damages: ((r: Record<string, unknown>) => void)[] = [
      (r) => { r.event = 'pull_request'; }, (r) => { r.path = `${String(r.path)}x`; }, (r) => { r.head_repository = { id: 9 }; }, (r) => { r.head_branch = 'dev'; },
      (r) => { r.head_sha = 'z'.repeat(40); }, (r) => { r.id = -2; }, (r) => { delete r.event; }, (r) => { delete r.head_repository; },
    ];
    for (let i = 0; i < 400; i++) {
      const r = run();
      const k = 1 + Math.floor(rand() * 3);
      for (let j = 0; j < k; j++) (damages[Math.floor(rand() * damages.length)] as (r: Record<string, unknown>) => void)(r);
      expect(await trustedRun(new FakeGh(), r, REPO), JSON.stringify(r)).toBe(false);
    }
  });
  it('property: random byte damage to a signed artifact is never loaded (flip any one byte)', () => {
    const bytes = bytesOf(goodDoc());
    const rand = rng(99);
    let loaded = 0;
    for (let i = 0; i < 600; i++) {
      const copy = Uint8Array.from(bytes);
      const at = Math.floor(rand() * copy.length);
      copy[at] = (copy[at] as number) ^ (1 << Math.floor(rand() * 8));
      if (verifyBaselineArtifact(copy, META(), CTX).baseline !== null) {
        // a flip is only allowed to load when the parsed content is unchanged (e.g. a flipped bit of insignificant text); check the content
        const a = JSON.parse(new TextDecoder().decode(copy)) as Doc;
        expect(a).toEqual(goodDoc());
        loaded++;
      }
    }
    expect(loaded).toBe(0);
  });
});

// ---------- mode ----------

describe('resolveMode (S13, #96)', () => {
  const day = (s: string): Date => new Date(`${s}T10:00:00Z`);
  const TODAY = day('2026-11-05');
  type Row = [name: string, blockFrom: string | undefined, recorded: string | undefined, today: Date, clean: boolean, want: 'warn' | 'block'];
  const rows: Row[] = [
    ['1 nothing set, no clean run → warn', undefined, undefined, TODAY, false, 'warn'],
    ['2 nothing set, trusted clean run → block', undefined, undefined, TODAY, true, 'block'],
    ['3 variable in the past → block', '2026-11-01', undefined, TODAY, false, 'block'],
    ['4 variable is today → block (on the date)', '2026-11-05', undefined, TODAY, false, 'block'],
    ['5 variable tomorrow → warn', '2026-11-06', undefined, TODAY, false, 'warn'],
    ['6 variable unset, recorded date passed → block (a writer deleting the variable gains nothing)', undefined, '2026-11-01', TODAY, false, 'block'],
    ['7 variable unset, recorded date is today → block', undefined, '2026-11-05', TODAY, false, 'block'],
    ['8 variable unset, recorded date in the future → warn', undefined, '2026-12-01', TODAY, false, 'warn'],
    ['9 variable later than recorded, recorded passed → block (recorded wins)', '2027-01-01', '2026-11-01', TODAY, false, 'block'],
    ['10 variable later than recorded, both in the future → warn until the earlier one', '2027-01-01', '2026-12-01', TODAY, false, 'warn'],
    ['11 variable earlier than recorded, passed → block (the earlier date wins; stricter)', '2026-11-01', '2026-12-01', TODAY, false, 'block'],
    ['12 variable earlier than recorded, both in the future → warn', '2026-11-20', '2026-12-01', TODAY, false, 'warn'],
    ['13 both passed → block', '2026-10-01', '2026-10-15', TODAY, false, 'block'],
    ['14 clean run beats future dates → block', '2027-01-01', '2027-02-01', TODAY, true, 'block'],
    ['15 clean run, no dates → block', undefined, undefined, TODAY, true, 'block'],
    ['16 variable not a date, no recorded → warn', 'soon', undefined, TODAY, false, 'warn'],
    ['17 variable not a date, recorded passed → block', 'soon', '2026-11-01', TODAY, false, 'block'],
    ['18 variable passed, recorded not a date → block', '2026-11-01', 'whenever', TODAY, false, 'block'],
    ['19 both not dates → warn', 'x', 'y', TODAY, false, 'warn'],
    ['20 empty variable (GitHub gives "" for an unset variable) → like unset', '', undefined, TODAY, false, 'warn'],
    ['21 empty variable, recorded passed → block', '', '2026-11-01', TODAY, false, 'block'],
    ['22 the day is the UTC day (late evening of the day before in UTC) → warn', undefined, '2026-11-06', new Date('2026-11-05T23:59:59Z'), false, 'warn'],
    ['23 the UTC day after midnight → block', undefined, '2026-11-06', new Date('2026-11-06T00:00:00Z'), false, 'block'],
  ];
  it.each(rows)('mode: %s', (_n, blockFrom, recorded, today, clean, want) => {
    expect(resolveMode(blockFrom, recorded, today, clean)).toBe(want);
  });
  it('mode: dates that only look like dates are not dates (impossible days, other formats, padding, a time, a long text)', () => {
    for (const bad of ['2026-02-30', '2026-13-01', '2026-00-10', '2026-11-00', '2026-1-1', '26-11-01', '2026/11/01', ' 2026-11-01', '2026-11-01 ', '2026-11-01T00:00:00Z', '20261101', '0000-00-00', `2026-11-01${'x'.repeat(5000)}`, '+2026-11-01', '2026-11-01\n']) {
      expect(resolveMode(bad, undefined, TODAY, false), JSON.stringify(bad)).toBe('warn');
      expect(resolveMode(undefined, bad, TODAY, false), JSON.stringify(bad)).toBe('warn');
    }
    // 2028-02-29 is real, 2027-02-29 is not
    expect(resolveMode('2028-02-29', undefined, day('2028-03-01'), false)).toBe('block');
    expect(resolveMode('2027-02-29', undefined, day('2028-03-01'), false)).toBe('warn');
  });
  it('mode: a clock that is not a date fails closed (block)', () => {
    expect(resolveMode(undefined, undefined, new Date(Number.NaN), false)).toBe('block');
    expect(resolveMode('2026-12-01', '2026-12-01', new Date(Number.NaN), false)).toBe('block');
  });
  it('mode: a writer who moves or deletes the variable can never delay blocking past the recorded date (property)', () => {
    const recorded = '2026-11-01';
    for (const v of [undefined, '', '2027-06-01', '9999-12-31', 'never', '2026-11-02', '2026-11-01']) {
      expect(resolveMode(v, recorded, TODAY, false), String(v)).toBe('block');
    }
  });
});

// ---------- fix round 1 (review-C3) ----------

describe('fix round 1, I1: the default history is checked against the branch COMMIT, resolved on every call', () => {
  it('inDefaultHistory: resolves refs/heads/<branch> itself, then compares sha...tip; the name never goes to compare; nothing is cached', async () => {
    const gh = new FakeGh();
    expect(await inDefaultHistory(gh, REPO, S1)).toBe(true);
    expect(await inDefaultHistory(gh, REPO, S1)).toBe(true);
    expect(gh.calls).toEqual(['branch main', `compare ${S1}...${TIP}`, 'branch main', `compare ${S1}...${TIP}`]);
    expect(gh.calls.some((c) => c.endsWith('...main'))).toBe(false);
  });
  it('inDefaultHistory: a ref answer that is not exactly the branch head commit gives false and no compare (tag ref, wrong name, tag object, bad sha, junk, error)', async () => {
    const answers: unknown[] = [
      { ref: 'refs/tags/main', object: { type: 'commit', sha: TIP } }, { ref: 'refs/heads/other', object: { type: 'commit', sha: TIP } }, { ref: 'main', object: { type: 'commit', sha: TIP } },
      { ref: 'refs/heads/main', object: { type: 'tag', sha: TIP } }, { ref: 'refs/heads/main', object: { type: 'commit', sha: 'A'.repeat(40) } }, { ref: 'refs/heads/main', object: { type: 'commit', sha: 'f'.repeat(39) } },
      { ref: 'refs/heads/main' }, { object: { type: 'commit', sha: TIP } }, null, 'x', [], [{ ref: 'refs/heads/main', object: { type: 'commit', sha: TIP } }], new Error('404'),
    ];
    for (const a of answers) {
      const gh = new FakeGh(); gh.branchAnswer = a;
      expect(await inDefaultHistory(gh, REPO, S1), JSON.stringify(a)).toBe(false);
      expect(gh.calls.some((c) => c.startsWith('compare')), JSON.stringify(a)).toBe(false);
    }
  });
  it('inDefaultHistory: a client whose compare resolves the NAME main to a tag commit cannot make a tag commit pass (the tip sha is sent instead)', async () => {
    const gh = new FakeGh();
    gh.compares.set(S1, { status: 'diverged' });   // S1 is the tag commit: not an ancestor of the real tip
    const nameCompare = gh.compare.bind(gh);
    gh.compare = async (o, n, base, head) => (head === 'main' ? { status: 'identical' } : nameCompare(o, n, base, head));   // the tag-first resolution
    expect(await inDefaultHistory(gh, REPO, S1)).toBe(false);
    expect(await trustedRun(gh, run(), REPO)).toBe(false);
  });
  it('trustedRun: the reviewer\'s race — the tag is re-created after an earlier check — is caught, because the tag and the tip are asked fresh per run', async () => {
    const gh = new FakeGh();
    expect(await trustedRun(gh, run({ id: 1 }), REPO)).toBe(true);
    gh.tagAnswer = true;   // the writer pushes the tag again
    gh.compare = async () => ({ status: 'identical' });   // and the name now resolves to the tag commit
    expect(await trustedRun(gh, run({ id: 2 }), REPO)).toBe(false);
    expect(gh.calls.filter((c) => c === 'tag main').length).toBe(2);
    expect(gh.calls.filter((c) => c === 'branch main').length).toBe(1);   // the second run stopped at the tag
  });
  it('inDefaultHistory: ahead or identical still true; behind, diverged, error false (against the tip)', async () => {
    for (const [status, want] of [['ahead', true], ['identical', true], ['behind', false], ['diverged', false]] as const) {
      const gh = new FakeGh(); gh.fallbackCompare = { status };
      expect(await inDefaultHistory(gh, REPO, S1), status).toBe(want);
    }
  });
});

describe('fix round 1, I2: the clean-run marker fails toward block', () => {
  const marker = (runId: number, key = KEY): Record<string, unknown> => ({ runId, keyId: keyId(key), mac: markerMac(key, runId, keyId(key)) });
  const cart = (id: number, runId: number, over: Record<string, unknown> = {}) => art(id, runId, over, CLEAN_RUN_ARTIFACT);
  const clean = (gh: GateGithub, ctx: VerifyContext = CTX) => cleanRunSeen(gh, REPO, ctx);
  const good = (): FakeGh => world([cart(2, 200)], [run({ id: 200 })], [[2, marker(200)]]);
  it('state: a valid trusted marker is seen; a clean lookup that finds none is none', async () => {
    expect((await clean(good())).state).toBe('seen');
    expect((await clean(world([], [run({ id: 200 })], []))).state).toBe('none');
    expect((await clean(world([cart(2, 200)], [run({ id: 200, event: 'pull_request' })], [[2, marker(200)]]))).state).toBe('none');   // untrusted runs are just ignored
  });
  it('state: a fork PR (no key) after a clean run is seen — it does not drop back to warn', async () => {
    expect((await clean(good(), { key: undefined, now: NOW })).state).toBe('seen');
    expect(resolveMode(undefined, undefined, NOW, (await clean(good(), { key: undefined, now: NOW })).seen)).toBe('block');
  });
  it('state: every lookup that errors or cannot be completed is unknown (run list error, malformed list, artifact list error, download error, bad file, tag error, tag exists, history error, cap)', async () => {
    const e = new Error('500');
    const cases: [string, FakeGh][] = [];
    const a = good(); a.runsAnswer = e; cases.push(['run list error', a]);
    const b = good(); b.runsAnswer = { workflow_runs: 'x' }; cases.push(['malformed run list', b]);
    const c = good(); c.runArtifacts.set(200, e); cases.push(['artifact list error', c]);
    const d = good(); d.blobs.set(2, e); cases.push(['download error', d]);
    const f = good(); f.blobs.set(2, bytesOf('{')); cases.push(['bad marker file', f]);
    const g = good(); g.tagAnswer = e; cases.push(['tag lookup error', g]);
    const h = good(); h.tagAnswer = true; cases.push(['a tag named like the branch exists', h]);
    const i = good(); i.fallbackCompare = e; cases.push(['history compare error', i]);
    const j = good(); j.branchAnswer = e; cases.push(['branch ref error', j]);
    const k = good(); k.branchAnswer = { junk: 1 }; cases.push(['malformed branch ref', k]);
    for (const [why, gh] of cases) {
      const r = await clean(gh);
      expect(r.state, why).toBe('unknown');
      expect(r.seen, why).toBe(false);
      expect(r.note, why).toBeTruthy();
      expect(resolveMode(undefined, undefined, NOW, 'unknown'), why).toBe('block');
    }
  });
  it('state: a marker with a wrong MAC (a key is present) is ignored, not seen — but another valid marker still counts', async () => {
    const gh = world([cart(2, 200), cart(3, 300)], [run({ id: 200 }), run({ id: 300 })], [[2, marker(200)], [3, { ...marker(300), mac: '0'.repeat(64) }]]);
    expect((await clean(gh)).state).toBe('seen');
    const bad = world([cart(3, 300)], [run({ id: 300 })], [[3, { ...marker(300), mac: '0'.repeat(64) }]]);
    expect((await clean(bad)).state).toBe('none');
  });
  it('mode table: unknown always blocks, with or without dates', () => {
    const t = new Date('2026-11-05T10:00:00Z');
    for (const [v, r] of [[undefined, undefined], ['2027-01-01', undefined], [undefined, '2027-01-01'], ['2027-01-01', '2027-02-01'], ['soon', 'x'], ['2026-11-01', '2026-11-01']] as const) {
      expect(resolveMode(v, r, t, 'unknown'), `${v} ${r}`).toBe('block');
    }
    expect(resolveMode(undefined, undefined, t, true)).toBe('block');
    expect(resolveMode(undefined, undefined, t, false)).toBe('warn');
    expect(decideMode(undefined, undefined, t, 'unknown').why).toMatch(/could not be checked/);
  });
});

describe('fix round 1: minors', () => {
  it('m1: a clock outside years 1 to 9999 blocks', () => {
    for (const d of ['+010000-01-01T00:00:00Z', '+275000-01-01T00:00:00Z', '-000001-01-01T00:00:00Z']) {
      expect(resolveMode(undefined, '2099-01-01', new Date(d), false), d).toBe('block');
      expect(resolveMode(undefined, undefined, new Date(d), false), d).toBe('block');
    }
    expect(resolveMode(undefined, '2099-01-01', new Date('2026-11-05T00:00:00Z'), false)).toBe('warn');
  });
  it('m3: only a run whose conclusion is success counts (the status filter is checked in code); a stale baseline falls back with a note', async () => {
    const real = { [`fp\0a\0t\0${hex('green')}`]: 1 };
    const red = { [`fp\0a\0t\0${hex('red')}`]: 9 };
    for (const conclusion of ['failure', 'cancelled', 'skipped', 'neutral', undefined, null, 'Success']) {
      const gh = world([art(1, 100), art(2, 200)], [run({ id: 100 }), run({ id: 200, conclusion })], [[1, goodDoc({ runId: 100 }, KEY, real)], [2, goodDoc({ runId: 200 }, KEY, red)]]);
      expect(countsOf((await loadBaseline(gh, REPO, CTX)).baseline?.counts), String(conclusion)).toEqual(real);
    }
    const only = world([art(2, 200)], [run({ id: 200, conclusion: 'failure' })], [[2, goodDoc({ runId: 200 }, KEY, red)]]);
    const r = await loadBaseline(only, REPO, CTX);
    expect(r.baseline).toBeNull();
    expect(r.note).toMatch(/not successful|success/);
    expect(only.calls.some((c) => c.startsWith('artifacts'))).toBe(false);
  });
  it('m4: history checks are capped per lookup (HISTORY_CHECK_CAP); hitting the cap: baseline null with a note, marker unknown', async () => {
    const runs = Array.from({ length: 40 }, (_, i) => run({ id: 1000 - i }));
    const make = (): FakeGh => { const g = world([], runs, []); g.fallbackCompare = { status: 'diverged' }; return g; };
    const gb = make();
    const r = await loadBaseline(gb, REPO, CTX);
    expect(r.baseline).toBeNull();
    expect(r.note).toMatch(/cap/);
    expect(gb.calls.filter((c) => c.startsWith('compare')).length).toBeLessThanOrEqual(HISTORY_CHECK_CAP);
    expect(HISTORY_CHECK_CAP).toBe(20);
    const gm = make();
    expect((await cleanRunSeen(gm, REPO, CTX)).state).toBe('unknown');
    expect(gm.calls.filter((c) => c.startsWith('compare')).length).toBeLessThanOrEqual(HISTORY_CHECK_CAP);
  });
  it('m5: with a tag named like the default branch the note says so', async () => {
    const gh = world([art(2, 200)], [run({ id: 200 })], [[2, goodDoc({ runId: 200 })]]); gh.tagAnswer = true;
    const r = await loadBaseline(gh, REPO, CTX);
    expect(r.baseline).toBeNull();
    expect(r.note).toMatch(/a tag named main exists; no run is trusted until it is deleted/);
  });
  it('m6: the verifiers refuse an artifact whose expired flag is not exactly false (undefined, null, "false", 0)', () => {
    for (const expired of [undefined, null, 'false', 0, ''] as unknown[]) {
      const meta = { ...META(), expired } as unknown as ArtifactMeta;
      expect(verifyBaselineArtifact(bytesOf(goodDoc()), meta, CTX).baseline, String(expired)).toBeNull();
      const cm = { ...META({ name: CLEAN_RUN_ARTIFACT }), expired } as unknown as ArtifactMeta;
      expect(verifyCleanRunArtifact(buildCleanRunMarker(100, KEY), cm, CTX).seen, String(expired)).toBe(false);
    }
  });
  it('m8: buildBaseline refuses to write a baseline the reader would refuse (too many entries, too many bytes, a key over the cap)', () => {
    const many = Array.from({ length: MAX_COUNT_ENTRIES + 1 }, (_, i) => fnd({ fingerprint: `f${i}` }));
    expect(() => buildBaseline({ runId: 100, key: KEY, sameRunTools: [], checks: [{ job: 'sast', tool: 'semgrep', status: 'ok', findings: many }] })).toThrow(/too many/);
    const fat = Array.from({ length: 2900 }, (_, i) => fnd({ tool: 'trivy-config', ruleId: `${i}-${'r'.repeat(3000)}`, fingerprint: 'x', file: undefined, uriUnmapped: true }));
    expect(() => buildBaseline({ runId: 100, key: KEY, sameRunTools: [], checks: [{ job: 'iac', tool: 'trivy-config', status: 'ok', findings: fat }] })).toThrow(/size/);
    const longKey = fnd({ tool: 'trivy-config', ruleId: 'r'.repeat(5000), fingerprint: 'x', file: undefined, uriUnmapped: true });
    expect(() => buildBaseline({ runId: 100, key: KEY, sameRunTools: [], checks: [{ job: 'iac', tool: 'trivy-config', status: 'ok', findings: [longKey] }] })).toThrow(/key/i);
    // a large but allowed baseline round-trips
    const ok = Array.from({ length: 2000 }, (_, i) => fnd({ fingerprint: hex(`n${i}`) }));
    const b = buildBaseline({ runId: 100, key: KEY, sameRunTools: [], checks: [{ job: 'sast', tool: 'semgrep', status: 'ok', findings: ok }] });
    expect(verifyBaselineArtifact(b.bytes, META({ runId: 100 }), CTX).baseline?.counts.size).toBe(2000);
  });
  it('m10: every keyed fingerprint form (region, quoted, file, line) needs the current key id; the MAC key is a derived sub-key, not the fingerprint key', () => {
    for (const fpBy of ['quoted', 'region', 'file', 'line'] as const) {
      const f = fnd({ fpBy, fingerprint: `${SEC}${hex(fpBy)}`, ['sec' + 'ret']: false } as Partial<ScrubbedFinding>);
      const other = buildBaseline({ runId: 100, key: KEY, sameRunTools: [], checks: [{ job: 'j', tool: 'bandit', status: 'ok', keyId: keyId(KEY2), findings: [f] }] });
      expect(other.skipped.map((x) => x.job), fpBy).toEqual(['j']);
      const same = buildBaseline({ runId: 100, key: KEY, sameRunTools: [], checks: [{ job: 'j', tool: 'bandit', status: 'ok', keyId: keyId(KEY), findings: [f] }] });
      expect(same.skipped, fpBy).toEqual([]);
    }
    // a fingerprint-style HMAC of the same key over the same text is NOT the artifact MAC
    const doc = JSON.parse(new TextDecoder().decode(buildBaseline({ runId: 100, key: KEY, sameRunTools: [], checks: [] }).bytes)) as Doc;
    const direct = createHmac('sha256', KEY).update(JSON.stringify(['pipegen-baseline-v1', 100, keyId(KEY), []])).digest('hex');
    expect(doc.mac).not.toBe(direct);
    expect(doc.mac).toBe(macOf(KEY, 100, keyId(KEY), {}));
  });
});

describe('fix round 1: a run list cut at the page cap', () => {
  it('a full last page means the list was cut: the marker lookup is unknown and the baseline note says so', async () => {
    const flood = Array.from({ length: MAX_RUN_PAGES * 100 + 50 }, (_, i) => run({ id: 90000 - i, event: 'pull_request', head_repository: { id: 8 } }));
    const gm = world([], flood, []);
    expect((await cleanRunSeen(gm, REPO, CTX)).state).toBe('unknown');
    const gb = world([], flood, []);
    expect((await loadBaseline(gb, REPO, CTX)).note).toMatch(/cut after/);
  });
});
