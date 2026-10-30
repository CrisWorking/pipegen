// Plan C Task C3: the trusted baseline and the clean-run marker (preflight rulings B6, S11, S13; DECISIONS #78, #82, #110).
//
// The gate compares a PR's findings with a BASELINE: what was already known on the default branch. Whatever is in it counts as
// "old" and does not block, so a poisoned baseline pre-approves a future finding. Two locks, both needed:
//   1. WHERE it came from (trustedRun): a run of this repository's own pipegen.yml, event push, on the default branch, whose
//      commit is in the default branch's history. A fork PR can upload an artifact with the same name (S4); its run has the wrong
//      event and head repository, so it is never read. Facts about a run come from `GET /actions/runs/{id}`, never from the
//      artifact listing, and are compared by repository id, never by name.
//   2. WHO wrote it (B6): any job of a trusted run could upload an artifact called pipegen-baseline, including jobs that run the
//      repository's own code. So the file carries an HMAC under PIPEGEN_FP_KEY, which repo-code steps never get. It is loaded
//      only when the MAC verifies, the key id is the current key's, and its run id is the run of the artifact. A fork PR has no key,
//      so it can't verify anything and uses the same-run base scan (null).
//
// Where the artifacts are looked for matters as much as how they are checked (C3 review): artifacts are NOT listed repo-wide, where
// anyone who can run a PR workflow could flood the list with newer same-name artifacts and push the trusted one out of any budget.
// The RUNS are listed instead (push runs of pipegen.yml on the default branch that succeeded, newest first, a bounded number of
// pages), each run is judged by trustedRun, and artifacts are listed only for a trusted run. An untrusted run never costs more
// than the list entry it came in, and never any artifact call.
//
// A tag named like the default branch: for a tag push `head_branch` is the tag name, so a tag called `main` on an old commit that is in
// the default history would pass every field check. The runs API has no field that tells a branch push from a tag push, so
// trustedRun also refuses every run while a tag with the default branch's name exists (GET /git/ref/tags/{name}; any answer but a
// clear "no" fails closed). Residual: a tag deleted afterwards leaves its runs (same repository, same workflow file, a commit that is
// in the default history, still needing the MAC) trusted. The real fix is Plan G's: the push trigger of pipegen.yml is
// `branches: [<default>]` only, no tags, which the referee checks.
//
// Everything outside this process is hostile: every API answer is `unknown`, read by own properties with exact types, and any
// error, 404 or odd shape means "not trusted" (null / false), never a guess. The module touches the network only through the
// small GateGithub interface below (C5 wires the real client; the tests give a fake). The artifact functions are pure: they take
// the bytes of the one file in the artifact (C5 downloads, checks the zip and the size) with its metadata.
//
// File formats (JSON, exactly these fields, nothing else):
//   pipegen-baseline:  { runId, keyId, counts, mac }      counts: { [countKeyOf(job, finding)]: whole number >= 0 }
//     mac = hex HMAC-SHA256(PIPEGEN_FP_KEY, JSON.stringify(['pipegen-baseline-v1', runId, keyId, [[key, count], ...sorted by key]]))
//   pipegen-clean-run: { runId, keyId, mac }
//     mac = hex HMAC-SHA256(PIPEGEN_FP_KEY, JSON.stringify(['pipegen-clean-run-v1', runId, keyId]))
//   keyId = the public id of the key (fingerprint.ts keyId). The two formats differ in their first element, so one can't pass as
//   the other. JSON.stringify of an array of strings and numbers is an unambiguous encoding (no field can run into the next).
// Tool errors, results with no coverage, and dependency and image findings (always compared with the same-run base scan) are
// never stored. Secret fingerprints made under another key id are never stored.
import { createHmac, timingSafeEqual } from 'node:crypto';
import { BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT } from '../../src/engine/artifact-names.js';
import { countKeyOf, type Baseline } from './decide.js';
import { keyId, keyProblem } from './fingerprint.js';
import type { ScrubbedFinding } from './scrub.js';

export const WORKFLOW_PATH = '.github/workflows/pipegen.yml';
export const BASELINE_RETENTION_DAYS = 90;
/** The run list is read for at most this many pages of 100, and at most this many TRUSTED runs are searched for an artifact. */
export const MAX_RUN_PAGES = 5;
export const RUNS_PER_PAGE = 100;
export const MAX_TRUSTED_RUNS = 20;
/** The cap on the artifact (as listed) and on the file inside it. */
export const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
const MAX_COUNT_ENTRIES = 200_000;
const MAX_COUNT_KEY = 4096;
const BASELINE_FORMAT = 'pipegen-baseline-v1';
const CLEAN_RUN_FORMAT = 'pipegen-clean-run-v1';
const SHA_RE = /^[0-9a-f]{40}$/;
const KEY_ID_RE = /^[0-9a-f]{16}$/;
const MAC_RE = /^[0-9a-f]{64}$/;

// ---------- the client: exactly the REST calls this module needs ----------

/**
 * The GitHub reads this module makes. Every answer is the parsed JSON body (or the bytes), typed `unknown`: it is validated here.
 * Any call may throw (404, 403, 5xx, network): that is treated as "not trusted". C5 wires Octokit to this; owner/name are always
 * the repository the gate runs in.
 */
export interface RunQuery { workflow: string; branch: string; event: 'push'; status: 'success'; page: number; perPage: number }
export interface GateGithub {
  /**
   * `GET /repos/{owner}/{name}/compare/{base}...{head}`; the answer must carry `status`. `head` is the default BRANCH name: the client
   * must resolve it as a branch and never as a tag (for example by `GET /repos/{owner}/{name}/branches/{head}` and comparing with that
   * commit, or `heads/{head}`).
   */
  compare(owner: string, name: string, base: string, head: string): Promise<unknown>;
  /**
   * `GET /repos/{owner}/{name}/actions/workflows/{workflow}/runs?event=push&branch={branch}&status=success&per_page={perPage}&page={page}`
   * → `{ workflow_runs: [...] }`, newest first. The filters narrow the list, they are not trusted: every run is judged by trustedRun.
   */
  listRuns(owner: string, name: string, query: RunQuery): Promise<unknown>;
  /** `GET /repos/{owner}/{name}/actions/runs/{runId}/artifacts?name={artifactName}` → `{ artifacts: [...] }`. */
  listRunArtifacts(owner: string, name: string, runId: number, artifactName: string): Promise<unknown>;
  /** The bytes of the one file in the artifact (`GET .../actions/artifacts/{id}/zip`, then C5's zip checks: one entry, no path, no link). */
  downloadArtifact(owner: string, name: string, artifactId: number): Promise<Uint8Array>;
  /** Whether a tag called `tag` exists: `GET /repos/{owner}/{name}/git/ref/tags/{tag}` (200 → true, 404 → false, any other error is thrown). */
  tagExists(owner: string, name: string, tag: string): Promise<boolean>;
}
/** The write side (C5 wires `@actions/artifact`). */
export interface ArtifactUploader {
  upload(name: string, bytes: Uint8Array, opts: { retentionDays: number }): Promise<void>;
}
export interface RepoRef { owner: string; name: string; id: number; defaultBranch: string }
/** What the verifier needs from the artifact listing. */
export interface ArtifactMeta { runId: number; name: string; expired: boolean; expiresAt?: string | null }
/** `key`: PIPEGEN_FP_KEY (undefined on a fork PR); `now`: the clock. */
export interface VerifyContext { key: string | undefined; now: Date }
export interface LoadResult { baseline: Baseline | null; note?: string }
export interface CleanRunResult { seen: boolean; note?: string }

// ---------- reading hostile data ----------

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
const posInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;

// ---------- inDefaultHistory and trustedRun ----------

/**
 * Whether `sha` is in the default branch's history: compare `sha...defaultBranch` says `ahead` (the branch is ahead of the sha, so
 * the sha is an ancestor) or `identical`. Behind, diverged, 404, any error, any other answer: false (fail closed).
 */
export async function inDefaultHistory(gh: GateGithub, repo: RepoRef, sha: string): Promise<boolean> {
  if (typeof sha !== 'string' || !SHA_RE.test(sha)) return false;
  try {
    const answer = await gh.compare(repo.owner, repo.name, sha, repo.defaultBranch);
    if (!isPlain(answer)) return false;
    const status = own(answer, 'status');
    return status === 'ahead' || status === 'identical';
  } catch {
    return false;
  }
}

/**
 * A run pipegen trusts for baselines and clean-run markers (and, in Task 8, for findGatedRun): event `push`, the exact workflow
 * path, this repository's own head repository (by id), the default branch, and a head_sha in the default branch's history. The cheap
 * checks come first; the history check is one API call. `run` is the answer of `GET /actions/runs/{id}`.
 */
export async function trustedRun(gh: GateGithub, run: unknown, repo: RepoRef): Promise<boolean> {
  if (!isPlain(run)) return false;
  if (!posInt(own(run, 'id'))) return false;
  if (own(run, 'event') !== 'push') return false;
  if (own(run, 'path') !== WORKFLOW_PATH) return false;
  const head = own(run, 'head_repository');
  if (!isPlain(head) || own(head, 'id') !== repo.id) return false;
  if (own(run, 'head_branch') !== repo.defaultBranch) return false;
  const sha = own(run, 'head_sha');
  if (typeof sha !== 'string' || !SHA_RE.test(sha)) return false;
  if (!(await noDefaultBranchTag(gh, repo))) return false;
  return inDefaultHistory(gh, repo, sha);
}

/** True only when the API clearly says no tag has the default branch's name. Asked once per client and branch. */
const TAG_ASKED = new WeakMap<GateGithub, Map<string, Promise<boolean>>>();
function noDefaultBranchTag(gh: GateGithub, repo: RepoRef): Promise<boolean> {
  let per = TAG_ASKED.get(gh);
  if (per === undefined) { per = new Map(); TAG_ASKED.set(gh, per); }
  const k = `${repo.owner}/${repo.name}\0${repo.defaultBranch}`;
  let p = per.get(k);
  if (p === undefined) {
    p = gh.tagExists(repo.owner, repo.name, repo.defaultBranch).then((exists) => exists === false, () => false);
    per.set(k, p);
  }
  return p;
}

// ---------- verifying one artifact (pure) ----------

function expiryProblem(meta: ArtifactMeta, now: Date): string | undefined {
  if (meta.expired !== false) return 'the artifact has expired';
  const t = typeof meta.expiresAt === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(meta.expiresAt) ? Date.parse(meta.expiresAt) : Number.NaN;
  if (Number.isNaN(t) || !(now instanceof Date) || Number.isNaN(now.getTime())) return 'the artifact has no usable expiry time, so it is treated as expired';
  return t <= now.getTime() ? 'the artifact has expired' : undefined;
}

/** The checks both file kinds share, before the file is read. Returns a note when the artifact can't be used. */
function metaProblem(meta: ArtifactMeta, ctx: VerifyContext, name: string): string | undefined {
  if (!isPlain(meta) || meta.name !== name) return `the artifact is not named ${name}`;
  if (!posInt(meta.runId)) return 'the artifact has no valid run id';
  const exp = expiryProblem(meta, ctx.now);
  if (exp !== undefined) return exp;
  return keyNote(ctx.key);
}
function keyNote(key: string | undefined): string | undefined {
  if (key === undefined || key === '') return 'PIPEGEN_FP_KEY is not available (a fork pull request has no secrets), so the file can not be verified';
  return keyProblem(key, false, true) === undefined ? undefined : 'PIPEGEN_FP_KEY can not be used, so the file can not be verified';
}

function parseDoc(bytes: unknown): Record<string, unknown> | string {
  if (!(bytes instanceof Uint8Array)) return 'the artifact is not bytes';
  if (bytes.length === 0 || bytes.length > MAX_ARTIFACT_BYTES) return 'the file is empty or over the size cap';
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return 'the file is not valid JSON'; }
  return isPlain(value) ? value : 'the file is not a JSON object';
}

const hmac = (key: string, text: string): string => createHmac('sha256', key).update(text).digest('hex');
function macMatches(key: string, text: string, mac: string): boolean {
  const a = Buffer.from(hmac(key, text), 'hex');
  const b = Buffer.from(mac, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
const code = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
function canonicalBaseline(runId: number, kid: string, counts: ReadonlyMap<string, number>): string {
  return JSON.stringify([BASELINE_FORMAT, runId, kid, [...counts].sort(([a], [b]) => code(a, b))]);
}
const canonicalMarker = (runId: number, kid: string): string => JSON.stringify([CLEAN_RUN_FORMAT, runId, kid]);

/** Why `counts` is not a baseline's count map, or the map. Every value is checked on its own (a MAC can be made over anything a forger signs). */
function readCounts(v: unknown): Map<string, number> | string {
  if (!isPlain(v)) return 'counts is not a map';
  const entries = Object.entries(v);
  if (entries.length > MAX_COUNT_ENTRIES) return 'counts has too many entries';
  const out = new Map<string, number>();
  for (const [k, n] of entries) {
    if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0) return 'a count is not a whole number of at least 0';
    const parts = k.split('\0');
    if (k.length > MAX_COUNT_KEY || parts.length < 4 || (parts[0] !== 'fp' && parts[0] !== 'unmapped') || !parts[1] || !parts[2]) return 'a count key is not one the gate writes';
    out.set(k, n);
  }
  return out;
}

/**
 * Verify the bytes of a pipegen-baseline artifact. Loaded only when: the artifact is named exactly pipegen-baseline and not expired;
 * a usable key is given; the file has exactly { runId, keyId, counts, mac }; runId is the artifact's run; keyId is the current key's;
 * every count is a whole number >= 0; and the MAC verifies. Otherwise `baseline` is null with a note, and the gate uses the base scan.
 * `tools` is read from the count keys (a tool with no stored finding is not covered, so the base scan decides it).
 */
export function verifyBaselineArtifact(bytes: Uint8Array, meta: ArtifactMeta, ctx: VerifyContext): LoadResult {
  const none = (note: string): LoadResult => ({ baseline: null, note: `no trusted baseline: ${note}` });
  const early = metaProblem(meta, ctx, BASELINE_ARTIFACT);
  if (early !== undefined) return none(early);
  const key = ctx.key as string;
  const doc = parseDoc(bytes);
  if (typeof doc === 'string') return none(doc);
  if (Object.keys(doc).sort().join() !== 'counts,keyId,mac,runId') return none('the file does not have exactly runId, keyId, counts and MAC');
  const runId = own(doc, 'runId');
  if (!posInt(runId)) return none('runId is not a positive whole number');
  const kid = own(doc, 'keyId');
  if (typeof kid !== 'string' || !KEY_ID_RE.test(kid)) return none('keyId is not a key id');
  const mac = own(doc, 'mac');
  if (typeof mac !== 'string' || !MAC_RE.test(mac)) return none('the MAC is missing or not 64 lower-case hex characters');
  if (runId !== meta.runId) return none(`the file is for run ${runId}, not the run of the artifact (${meta.runId})`);
  if (kid !== keyId(key)) return none('its key id is not the current PIPEGEN_FP_KEY\'s (the key changed): secret fingerprints are under another key, so the base scan decides');
  const counts = readCounts(own(doc, 'counts'));
  if (typeof counts === 'string') return none(counts);
  if (!macMatches(key, canonicalBaseline(runId, kid, counts), mac)) return none('the MAC does not match');
  const tools = new Set<string>();
  for (const k of counts.keys()) tools.add(k.split('\0')[2] as string);
  return { baseline: { tools: [...tools].sort(), counts } };
}

/** Verify the bytes of a pipegen-clean-run artifact: the same rules, with the marker's own MAC format. */
export function verifyCleanRunArtifact(bytes: Uint8Array, meta: ArtifactMeta, ctx: VerifyContext): CleanRunResult {
  const no = (note: string): CleanRunResult => ({ seen: false, note: `clean-run marker not trusted: ${note}` });
  const early = metaProblem(meta, ctx, CLEAN_RUN_ARTIFACT);
  if (early !== undefined) return no(early);
  const key = ctx.key as string;
  const doc = parseDoc(bytes);
  if (typeof doc === 'string') return no(doc);
  if (Object.keys(doc).sort().join() !== 'keyId,mac,runId') return no('the file does not have exactly runId, keyId and MAC');
  const runId = own(doc, 'runId');
  const kid = own(doc, 'keyId');
  const mac = own(doc, 'mac');
  if (!posInt(runId)) return no('runId is not a positive whole number');
  if (typeof kid !== 'string' || !KEY_ID_RE.test(kid)) return no('keyId is not a key id');
  if (typeof mac !== 'string' || !MAC_RE.test(mac)) return no('the MAC is missing or not 64 lower-case hex characters');
  if (runId !== meta.runId) return no(`the file is for run ${runId}, not the run of the artifact (${meta.runId})`);
  if (kid !== keyId(key)) return no('its key id is not the current PIPEGEN_FP_KEY\'s');
  if (!macMatches(key, canonicalMarker(runId, kid), mac)) return no('the MAC does not match');
  return { seen: true };
}

// ---------- loading through the client ----------

interface Candidate { id: number; createdMs: number; expired: boolean; expiresAt: string | null; size: number }

/** The listing entries of exactly this name that belong to run `runId` and have a readable shape, newest first. */
function candidatesOf(listing: unknown, artifactName: string, runId: number): Candidate[] {
  if (!isPlain(listing)) return [];
  const list = own(listing, 'artifacts');
  if (!Array.isArray(list)) return [];
  const out: Candidate[] = [];
  for (const a of list) {
    if (!isPlain(a) || own(a, 'name') !== artifactName || !posInt(own(a, 'id'))) continue;
    const wr = own(a, 'workflow_run');
    if (!isPlain(wr) || own(wr, 'id') !== runId) continue;
    const created = own(a, 'created_at');
    const createdMs = typeof created === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(created) ? Date.parse(created) : Number.NaN;
    if (Number.isNaN(createdMs)) continue;
    const exp = own(a, 'expires_at');
    const size = own(a, 'size_in_bytes');
    out.push({
      id: own(a, 'id') as number, createdMs, expired: own(a, 'expired') !== false,
      expiresAt: typeof exp === 'string' ? exp : null, size: typeof size === 'number' && Number.isSafeInteger(size) && size >= 0 ? size : Number.POSITIVE_INFINITY,
    });
  }
  return out.sort((x, y) => y.createdMs - x.createdMs || y.id - x.id);
}

/**
 * Walk the successful push runs of the workflow on the default branch, newest first (by run id), at most MAX_RUN_PAGES pages: judge
 * each with trustedRun and skip the rest at no further cost; for a trusted run list ITS artifacts of this name (at most
 * MAX_TRUSTED_RUNS trusted runs are searched), skip the expired, and hand the bytes of the newest to `use`. `use` returns a result to
 * stop with, or undefined to go on to the next trusted run. An error on one step skips with a note.
 */
async function walk<T>(
  gh: GateGithub, repo: RepoRef, ctx: VerifyContext, artifactName: string,
  use: (bytes: Uint8Array, meta: ArtifactMeta) => T | undefined, notes: string[],
): Promise<T | undefined> {
  let trustedSeen = 0;
  let expired = 0;
  for (let page = 1; page <= MAX_RUN_PAGES; page++) {
    let listing: unknown;
    try {
      listing = await gh.listRuns(repo.owner, repo.name, { workflow: 'pipegen.yml', branch: repo.defaultBranch, event: 'push', status: 'success', page, perPage: RUNS_PER_PAGE });
    } catch { notes.push('the list of workflow runs could not be read'); return undefined; }
    const runs = isPlain(listing) && Array.isArray(own(listing, 'workflow_runs')) ? (own(listing, 'workflow_runs') as unknown[]) : undefined;
    if (runs === undefined) { notes.push('the list of workflow runs is not a list'); return undefined; }
    const ordered = runs.filter((r): r is Record<string, unknown> => isPlain(r) && posInt(own(r, 'id'))).sort((x, y) => (own(y, 'id') as number) - (own(x, 'id') as number));
    for (const r of ordered) {
      if (!(await trustedRun(gh, r, repo))) continue;   // an untrusted run is invisible: no artifact call, no budget
      if (++trustedSeen > MAX_TRUSTED_RUNS) { notes.push('too many runs without a usable artifact'); return undefined; }
      const runId = own(r, 'id') as number;
      let found: Candidate[];
      try { found = candidatesOf(await gh.listRunArtifacts(repo.owner, repo.name, runId, artifactName), artifactName, runId); } catch { notes.push(`the artifacts of run ${runId} could not be read`); continue; }
      const live = found.filter((c) => {
        const gone = expiryProblem({ runId, name: artifactName, expired: c.expired, expiresAt: c.expiresAt }, ctx.now) !== undefined;
        if (gone) expired++;
        return !gone;
      });
      const c = live[0];
      if (c === undefined) continue;
      const meta: ArtifactMeta = { runId, name: artifactName, expired: false, expiresAt: c.expiresAt };
      const stop = (note: string): T | undefined => { notes.push(note); return use(new Uint8Array(0), meta); };
      if (c.size > MAX_ARTIFACT_BYTES) { const x = stop(`the ${artifactName} artifact of run ${runId} is over the size cap`); if (x !== undefined) return x; continue; }
      let bytes: unknown;
      try { bytes = await gh.downloadArtifact(repo.owner, repo.name, c.id); } catch { const x = stop(`the ${artifactName} artifact of run ${runId} could not be downloaded (deleted?)`); if (x !== undefined) return x; continue; }
      if (!(bytes instanceof Uint8Array)) { const x = stop(`the ${artifactName} artifact of run ${runId} is not bytes`); if (x !== undefined) return x; continue; }
      const x = use(bytes, meta);
      if (x !== undefined) return x;
    }
    if (runs.length < RUNS_PER_PAGE) break;
  }
  if (expired > 0 && notes.length === 0) notes.push(`the ${artifactName} artifact has expired`);
  return undefined;
}

/**
 * The newest non-expired `pipegen-baseline` artifact of a trusted run, verified (verifyBaselineArtifact). The first TRUSTED artifact
 * decides: if it does not verify there is no baseline (the base scan is used), and an older one is not tried. Untrusted artifacts
 * (a fork PR's, a PR run's, a tag run's) are skipped. Without a usable key (a fork PR) nothing can be verified: null, and no API call.
 */
export async function loadBaseline(gh: GateGithub, repo: RepoRef, ctx: VerifyContext): Promise<LoadResult> {
  const kn = keyNote(ctx.key);
  if (kn !== undefined) return { baseline: null, note: `no trusted baseline: ${kn}; the base scan decides` };
  const notes: string[] = [];
  const result = await walk<LoadResult>(gh, repo, ctx, BASELINE_ARTIFACT, (bytes, meta) => (bytes.length === 0 ? { baseline: null, note: `no trusted baseline: ${notes[notes.length - 1] ?? 'unreadable'}` } : verifyBaselineArtifact(bytes, meta, ctx)), notes);
  if (result !== undefined) return result;
  return { baseline: null, note: `no trusted baseline: ${notes.join('; ') || `no ${BASELINE_ARTIFACT} artifact from a trusted run`}; the base scan decides` };
}

/** Whether a valid, signed `pipegen-clean-run` marker from a trusted run exists (any one counts). No key: false, no API call. */
export async function cleanRunSeen(gh: GateGithub, repo: RepoRef, ctx: VerifyContext): Promise<CleanRunResult> {
  const kn = keyNote(ctx.key);
  if (kn !== undefined) return { seen: false, note: `clean-run marker not trusted: ${kn}` };
  const notes: string[] = [];
  const result = await walk<CleanRunResult>(gh, repo, ctx, CLEAN_RUN_ARTIFACT, (bytes, meta) => {
    if (bytes.length === 0) return undefined;
    const r = verifyCleanRunArtifact(bytes, meta, ctx);
    if (r.seen) return r;
    if (r.note !== undefined) notes.push(r.note);
    return undefined;
  }, notes);
  return result ?? { seen: false, note: `clean-run marker not trusted: ${notes.join('; ') || 'none from a trusted run'}` };
}

// ---------- building and saving ----------

/** One finished check as the gate saw it on the default branch. */
export interface BaselineCheck {
  job: string;
  tool: string;
  /** `tool-error`: never stored. */
  status: 'ok' | 'tool-error';
  /** The result proves no coverage (gitleaks with its completeness note, nuclei with nothing reported): never stored as clean. */
  noCoverage?: boolean;
  /** The key id the scrub recorded for this result (ScrubbedResult.keyId). */
  keyId?: string;
  findings: readonly ScrubbedFinding[];
}
export interface BaselineInput {
  runId: number;
  /** PIPEGEN_FP_KEY. */
  key: string | undefined;
  checks: readonly BaselineCheck[];
  /** Dependency and image tools: always compared with the same-run base scan, so a baseline never stores them. */
  sameRunTools: readonly string[];
}
export interface BuiltBaseline { bytes: Uint8Array; counts: ReadonlyMap<string, number>; skipped: { job: string; reason: string }[] }

function requireKey(key: string | undefined): string {
  const problem = key === undefined ? 'PIPEGEN_FP_KEY is missing' : keyProblem(key, false, true);
  if (problem !== undefined || key === undefined) throw new Error(`can not sign: ${problem ?? 'PIPEGEN_FP_KEY is missing'}`);
  return key;
}
function requireRunId(runId: number): number {
  if (!posInt(runId)) throw new Error('can not sign: the run id is not a positive whole number');
  return runId;
}

/**
 * The signed baseline file of a trusted run's results. A check is left out (and listed in `skipped`) when it is a tool error, proves
 * no coverage, is a same-run tool, or holds secret fingerprints made under another key id (or with none recorded). Counts are
 * per countKeyOf, so C2 reads them back with the same keys.
 */
export function buildBaseline(input: BaselineInput): BuiltBaseline {
  const key = requireKey(input.key);
  const runId = requireRunId(input.runId);
  const kid = keyId(key);
  const sameRun = new Set(input.sameRunTools);
  const counts = new Map<string, number>();
  const skipped: { job: string; reason: string }[] = [];
  for (const c of input.checks) {
    const skip = (reason: string): void => { skipped.push({ job: c.job, reason }); };
    if (c.status !== 'ok') { skip('tool error: never stored'); continue; }
    if (c.noCoverage === true) { skip('no coverage: not proven clean, so not stored'); continue; }
    if (sameRun.has(c.tool)) { skip('compared with the same-run base scan, never with a stored baseline'); continue; }
    if (c.findings.some((f) => f.secret) && c.keyId !== kid) { skip('its secret fingerprints are not under the current key id'); continue; }
    for (const f of c.findings) { const k = countKeyOf(c.job, f); counts.set(k, (counts.get(k) ?? 0) + 1); }
  }
  const sorted = [...counts].sort(([a], [b]) => code(a, b));
  const mac = hmac(key, canonicalBaseline(runId, kid, counts));
  const bytes = new TextEncoder().encode(JSON.stringify({ runId, keyId: kid, counts: Object.fromEntries(sorted), mac }));
  return { bytes, counts: new Map(sorted), skipped };
}

/** Build the baseline and upload it as `pipegen-baseline` with 90 days of retention. An upload error is thrown, not swallowed. */
export async function saveBaseline(input: BaselineInput, uploader: ArtifactUploader): Promise<BuiltBaseline> {
  const built = buildBaseline(input);
  await uploader.upload(BASELINE_ARTIFACT, built.bytes, { retentionDays: BASELINE_RETENTION_DAYS });
  return built;
}

/** The signed clean-run marker file (uploaded as `pipegen-clean-run` by the gate of a trusted run that found nothing old or new to block on). */
export function buildCleanRunMarker(runId: number, key: string | undefined): Uint8Array {
  const k = requireKey(key);
  const id = requireRunId(runId);
  const kid = keyId(k);
  return new TextEncoder().encode(JSON.stringify({ runId: id, keyId: kid, mac: hmac(k, canonicalMarker(id, kid)) }));
}
