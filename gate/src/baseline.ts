// Plan C Task C3: the trusted baseline and the clean-run marker (preflight rulings B6, S11, S13; DECISIONS #78, #82, #110).
//
// The gate compares a PR's findings with a BASELINE: what was already known on the default branch. Whatever is in it counts as
// "old" and does not block, so a poisoned baseline pre-approves a future finding. Two locks, both needed:
//   1. WHERE it came from (trustedRun): a run of this repository's own pipegen.yml, event push, on the default branch, whose
//      commit is in the default branch's history. A fork PR can upload an artifact with the same name (S4); its run has the wrong
//      event and head repository, so it is never read. Facts about a run come from the run list (never from an artifact's
//      own claims) and are compared by repository id, never by name.
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
// The default history (fix round 1, I1): `inDefaultHistory` resolves the default branch's commit itself on every call (GET
// /git/ref/heads/{branch}: the ref must be exactly refs/heads/<branch>, the object a commit with a 40-hex sha) and compares
// sha...tipSha. The branch NAME is never sent to compare (git resolves an ambiguous name tag-first), and nothing is cached.
//
// A tag named like the default branch: for a tag push `head_branch` is the tag name, so a tag called `main` on an old commit that is in
// the default history would pass every field check. The runs API has no field that tells a branch push from a tag push, so
// trustedRun also refuses every run while a tag with the default branch's name exists (GET /git/ref/tags/{name}, asked fresh for every
// run; any answer but a clear "no" fails closed). Since the tip ref above, this is a belt for the old-commit case below, not the I1 barrier. Residual: a tag deleted afterwards leaves its runs (same repository, same workflow file, a commit that is
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
//     mac = hex HMAC-SHA256(macKey, JSON.stringify(['pipegen-baseline-v1', runId, keyId, [[key, count], ...sorted by key]]))
//   pipegen-clean-run: { runId, keyId, mac }
//     mac = hex HMAC-SHA256(macKey, JSON.stringify(['pipegen-clean-run-v1', runId, keyId]))
//   macKey = hex HMAC-SHA256(PIPEGEN_FP_KEY, 'pipegen-artifact-mac-v1'): a sub-key, so a fingerprint (made with the key itself) can never
//   double as an artifact MAC (review-C3 m10).
//   keyId = the public id of the key (fingerprint.ts keyId). The two formats differ in their first element, so one can't pass as
//   the other. JSON.stringify of an array of strings and numbers is an unambiguous encoding (no field can run into the next).
// The clean-run marker differs in one way (fix round 1, I2): a forged or lost marker can only make the gate STRICTER (block mode is at
// least as strict as warn), so with no usable key (a fork PR) a well-formed marker of a trusted run counts on run trust alone, and
// the MAC and key id are checked only when a key is present. A lookup that can't be completed is `unknown`, and the mode blocks.
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
/** At most this many default-history checks (two API calls each, plus the tag check) per lookup; hitting the cap fails closed. */
export const HISTORY_CHECK_CAP = 20;
/** The cap on the artifact (as listed) and on the file inside it. */
export const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
export const MAX_COUNT_ENTRIES = 200_000;
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
/** `status: 'success'` is the API's filter; the walk checks `conclusion === 'success'` itself. */
export interface RunQuery { workflow: string; branch: string; event: 'push'; status: 'success'; page: number; perPage: number }
export interface GateGithub {
  /** `GET /repos/{owner}/{name}/compare/{base}...{head}`; both are 40-hex commit shas, never a name; the answer must carry `status`. */
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
  /** `GET /repos/{owner}/{name}/git/ref/heads/{branch}` → `{ ref, object: { type, sha } }`; validated here (see inDefaultHistory). */
  branchHead(owner: string, name: string, branch: string): Promise<unknown>;
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
/** seen; none (the lookup finished and found no valid marker); unknown (it could not be completed, so the mode blocks). */
export type CleanRunState = 'seen' | 'none' | 'unknown';
export interface CleanRunResult { state: CleanRunState; seen: boolean; note?: string }

// ---------- reading hostile data ----------

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
const posInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;

// ---------- inDefaultHistory and trustedRun ----------

type History = 'in' | 'out' | 'error';
/** The default history, three-valued: `error` is an API failure or an answer that is not what the API gives. */
async function historyState(gh: GateGithub, repo: RepoRef, sha: string): Promise<History> {
  if (typeof sha !== 'string' || !SHA_RE.test(sha)) return 'out';
  try {
    const ref = await gh.branchHead(repo.owner, repo.name, repo.defaultBranch);
    if (!isPlain(ref) || own(ref, 'ref') !== `refs/heads/${repo.defaultBranch}`) return 'error';
    const obj = own(ref, 'object');
    const tip = isPlain(obj) && own(obj, 'type') === 'commit' ? own(obj, 'sha') : undefined;
    if (typeof tip !== 'string' || !SHA_RE.test(tip)) return 'error';
    const answer = await gh.compare(repo.owner, repo.name, sha, tip);
    const status = isPlain(answer) ? own(answer, 'status') : undefined;
    if (typeof status !== 'string') return 'error';
    return status === 'ahead' || status === 'identical' ? 'in' : 'out';
  } catch {
    return 'error';
  }
}

/**
 * Whether `sha` is in the default branch's history. The branch's commit is resolved here on every call (never cached, never a name
 * sent to compare), then `compare sha...tip` must say `ahead` (the tip is ahead of the sha, so the sha is an ancestor) or `identical`.
 * Behind, diverged, 404, any error, any other answer: false (fail closed).
 */
export async function inDefaultHistory(gh: GateGithub, repo: RepoRef, sha: string): Promise<boolean> {
  return (await historyState(gh, repo, sha)) === 'in';
}

type Judged = { ok: true } | { ok: false; why: 'untrusted' | 'tag' | 'error' | 'cap' };
/**
 * trustedRun with the reason it said no. `untrusted` is a clean no (wrong field, not in the history); `tag`, `error` and `cap` are
 * "could not tell or can't be trusted now" (the marker lookup treats them as unknown). `budget` counts history checks (m4).
 */
async function judgeRun(gh: GateGithub, run: unknown, repo: RepoRef, budget?: { left: number }): Promise<Judged> {
  const no = (why: 'untrusted'): Judged => ({ ok: false, why });
  if (!isPlain(run)) return no('untrusted');
  if (!posInt(own(run, 'id'))) return no('untrusted');
  if (own(run, 'event') !== 'push') return no('untrusted');
  if (own(run, 'path') !== WORKFLOW_PATH) return no('untrusted');
  const head = own(run, 'head_repository');
  if (!isPlain(head) || own(head, 'id') !== repo.id) return no('untrusted');
  if (own(run, 'head_branch') !== repo.defaultBranch) return no('untrusted');
  const sha = own(run, 'head_sha');
  if (typeof sha !== 'string' || !SHA_RE.test(sha)) return no('untrusted');
  if (budget !== undefined) { if (budget.left <= 0) return { ok: false, why: 'cap' }; budget.left--; }
  // a tag named like the default branch (fresh for every run): see the header; anything but a clear "no" fails closed
  let tag: unknown;
  try { tag = await gh.tagExists(repo.owner, repo.name, repo.defaultBranch); } catch { return { ok: false, why: 'error' }; }
  if (tag === true) return { ok: false, why: 'tag' };
  if (tag !== false) return { ok: false, why: 'error' };
  const h = await historyState(gh, repo, sha);
  return h === 'in' ? { ok: true } : { ok: false, why: h === 'out' ? 'untrusted' : 'error' };
}

/**
 * A run pipegen trusts for baselines and clean-run markers (and, in Task 8, for findGatedRun): event `push`, the exact workflow
 * path, this repository's own head repository (by id), the default branch, no tag named like it, and a head_sha in the default
 * branch's history. The cheap checks come first. `run` is an entry of the run list.
 */
export async function trustedRun(gh: GateGithub, run: unknown, repo: RepoRef): Promise<boolean> {
  return (await judgeRun(gh, run, repo)).ok;
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
/** The key the artifact MACs use: a sub-key of PIPEGEN_FP_KEY (review-C3 m10). */
const macKey = (key: string): string => hmac(key, 'pipegen-artifact-mac-v1');
const sign = (key: string, text: string): string => hmac(macKey(key), text);
function macMatches(key: string, text: string, mac: string): boolean {
  const a = Buffer.from(sign(key, text), 'hex');
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

/**
 * Verify the bytes of a pipegen-clean-run artifact. With a usable key: the same rules as the baseline (MAC, key id, run id). With none
 * (a fork PR): the name, expiry, exact fields and run id only, because a marker can only make the gate stricter (I2). `malformed` is
 * true when the file is not a well-formed marker of this artifact (the lookup is then unknown); a MAC or key-id mismatch is a clean "not
 * a marker of ours" (ignored).
 */
export function verifyCleanRunArtifact(bytes: Uint8Array, meta: ArtifactMeta, ctx: VerifyContext): { seen: boolean; malformed: boolean; note?: string } {
  const no = (note: string, malformed: boolean): { seen: false; malformed: boolean; note: string } => ({ seen: false, malformed, note: `clean-run marker not trusted: ${note}` });
  if (!isPlain(meta) || meta.name !== CLEAN_RUN_ARTIFACT) return no(`the artifact is not named ${CLEAN_RUN_ARTIFACT}`, true);
  if (!posInt(meta.runId)) return no('the artifact has no valid run id', true);
  const exp = expiryProblem(meta, ctx.now);
  if (exp !== undefined) return no(exp, false);
  const key = keyNote(ctx.key) === undefined ? (ctx.key as string) : undefined;
  const doc = parseDoc(bytes);
  if (typeof doc === 'string') return no(doc, true);
  if (Object.keys(doc).sort().join() !== 'keyId,mac,runId') return no('the file does not have exactly runId, keyId and MAC', true);
  const runId = own(doc, 'runId');
  const kid = own(doc, 'keyId');
  const mac = own(doc, 'mac');
  if (!posInt(runId)) return no('runId is not a positive whole number', true);
  if (typeof kid !== 'string' || !KEY_ID_RE.test(kid)) return no('keyId is not a key id', true);
  if (typeof mac !== 'string' || !MAC_RE.test(mac)) return no('the MAC is missing or not 64 lower-case hex characters', true);
  if (runId !== meta.runId) return no(`the file is for run ${runId}, not the run of the artifact (${meta.runId})`, true);
  if (key === undefined) return { seen: true, malformed: false };   // no key to check with: run trust alone (a forged marker only blocks sooner)
  if (kid !== keyId(key)) return no('its key id is not the current PIPEGEN_FP_KEY\'s', false);
  if (!macMatches(key, canonicalMarker(runId, kid), mac)) return no('the MAC does not match', false);
  return { seen: true, malformed: false };
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

interface WalkState { incomplete: boolean }
type Use<T> = (input: { bytes: Uint8Array } | { problem: string }, meta: ArtifactMeta, st: WalkState) => T | undefined;

/**
 * Walk the successful push runs of the workflow on the default branch, newest first (by run id), at most MAX_RUN_PAGES pages: skip a
 * run whose `conclusion` is not `success` (the API filter is not trusted, and a red main must not refresh the baseline), judge each
 * of the rest with the trust check (at most HISTORY_CHECK_CAP history checks), and skip the untrusted at no further cost. For a
 * trusted run list ITS artifacts of this name (at most MAX_TRUSTED_RUNS trusted runs are searched), skip the expired, and hand the
 * bytes of the newest to `use`. `use` returns a result to stop with, or undefined to go on. `st.incomplete` is set whenever the walk
 * could not tell (an API error, a malformed answer, a cap, a tag named like the default branch).
 */
async function walk<T>(gh: GateGithub, repo: RepoRef, ctx: VerifyContext, artifactName: string, use: Use<T>, notes: string[], st: WalkState): Promise<T | undefined> {
  const budget = { left: HISTORY_CHECK_CAP };
  let trustedSeen = 0;
  let expired = 0;
  let notSuccess = 0;
  let exhausted = true;
  for (let page = 1; page <= MAX_RUN_PAGES; page++) {
    let listing: unknown;
    try {
      listing = await gh.listRuns(repo.owner, repo.name, { workflow: 'pipegen.yml', branch: repo.defaultBranch, event: 'push', status: 'success', page, perPage: RUNS_PER_PAGE });
    } catch { notes.push('the list of workflow runs could not be read'); st.incomplete = true; return undefined; }
    const runs = isPlain(listing) && Array.isArray(own(listing, 'workflow_runs')) ? (own(listing, 'workflow_runs') as unknown[]) : undefined;
    if (runs === undefined) { notes.push('the list of workflow runs is not a list'); st.incomplete = true; return undefined; }
    const ordered = runs.filter((r): r is Record<string, unknown> => isPlain(r) && posInt(own(r, 'id'))).sort((x, y) => (own(y, 'id') as number) - (own(x, 'id') as number));
    for (const r of ordered) {
      if (own(r, 'conclusion') !== 'success') { notSuccess++; continue; }
      const j = await judgeRun(gh, r, repo, budget);   // an untrusted run is invisible: no artifact call, no trusted-run budget
      if (!j.ok) {
        if (j.why === 'untrusted') continue;
        st.incomplete = true;
        notes.push(j.why === 'tag' ? `a tag named ${repo.defaultBranch} exists; no run is trusted until it is deleted`
          : j.why === 'cap' ? `more than ${HISTORY_CHECK_CAP} runs needed a default-history check (cap)` : 'the default history of a run could not be checked');
        if (j.why === 'tag' || j.why === 'cap') return undefined;
        continue;
      }
      if (++trustedSeen > MAX_TRUSTED_RUNS) { notes.push('too many runs without a usable artifact'); st.incomplete = true; return undefined; }
      const runId = own(r, 'id') as number;
      let found: Candidate[];
      try { found = candidatesOf(await gh.listRunArtifacts(repo.owner, repo.name, runId, artifactName), artifactName, runId); } catch { notes.push(`the artifacts of run ${runId} could not be read`); st.incomplete = true; continue; }
      const live = found.filter((c) => {
        const gone = expiryProblem({ runId, name: artifactName, expired: c.expired, expiresAt: c.expiresAt }, ctx.now) !== undefined;
        if (gone) expired++;
        return !gone;
      });
      const c = live[0];
      if (c === undefined) continue;
      const meta: ArtifactMeta = { runId, name: artifactName, expired: false, expiresAt: c.expiresAt };
      const problem = (note: string): T | undefined => { notes.push(note); st.incomplete = true; return use({ problem: note }, meta, st); };
      if (c.size > MAX_ARTIFACT_BYTES) { const x = problem(`the ${artifactName} artifact of run ${runId} is over the size cap`); if (x !== undefined) return x; continue; }
      let bytes: unknown;
      try { bytes = await gh.downloadArtifact(repo.owner, repo.name, c.id); } catch { const x = problem(`the ${artifactName} artifact of run ${runId} could not be downloaded (deleted?)`); if (x !== undefined) return x; continue; }
      if (!(bytes instanceof Uint8Array)) { const x = problem(`the ${artifactName} artifact of run ${runId} is not bytes`); if (x !== undefined) return x; continue; }
      const x = use({ bytes }, meta, st);
      if (x !== undefined) return x;
    }
    if (runs.length < RUNS_PER_PAGE) { exhausted = false; break; }
  }
  if (exhausted) { notes.push(`the run list was cut after ${MAX_RUN_PAGES} pages`); st.incomplete = true; }
  if (expired > 0 && notes.length === 0) notes.push(`the ${artifactName} artifact has expired`);
  if (notSuccess > 0) notes.push(`${notSuccess} run${notSuccess === 1 ? '' : 's'} did not have conclusion success (a red main does not refresh the baseline)`);
  return undefined;
}

/**
 * The newest non-expired `pipegen-baseline` artifact of a trusted run, verified (verifyBaselineArtifact). The first TRUSTED run that
 * has a live artifact decides: if it does not verify there is no baseline (the base scan is used), and an older one is not tried.
 * Untrusted runs are skipped. Without a usable key (a fork PR) nothing can be verified: null, and no API call.
 */
export async function loadBaseline(gh: GateGithub, repo: RepoRef, ctx: VerifyContext): Promise<LoadResult> {
  const kn = keyNote(ctx.key);
  if (kn !== undefined) return { baseline: null, note: `no trusted baseline: ${kn}; the base scan decides` };
  const notes: string[] = [];
  const st: WalkState = { incomplete: false };
  const result = await walk<LoadResult>(gh, repo, ctx, BASELINE_ARTIFACT, (input, meta) => ('problem' in input ? { baseline: null, note: `no trusted baseline: ${input.problem}` } : verifyBaselineArtifact(input.bytes, meta, ctx)), notes, st);
  if (result !== undefined) return result;
  return { baseline: null, note: `no trusted baseline: ${notes.join('; ') || `no ${BASELINE_ARTIFACT} artifact from a trusted run`}; the base scan decides` };
}

/**
 * Whether a clean-run marker exists (any valid one of a trusted run counts). Three answers (I2): `seen`; `none` (the lookup finished
 * and found no valid marker); `unknown` (it could not be completed, or a trusted run's marker is malformed): the mode blocks on unknown.
 * Works without a key too (a fork PR): see verifyCleanRunArtifact.
 */
export async function cleanRunSeen(gh: GateGithub, repo: RepoRef, ctx: VerifyContext): Promise<CleanRunResult> {
  const notes: string[] = [];
  const st: WalkState = { incomplete: false };
  const result = await walk<CleanRunResult>(gh, repo, ctx, CLEAN_RUN_ARTIFACT, (input, meta, s) => {
    if ('problem' in input) return undefined;   // the walk already marked the lookup incomplete
    const r = verifyCleanRunArtifact(input.bytes, meta, ctx);
    if (r.seen) return { state: 'seen', seen: true };
    if (r.malformed) s.incomplete = true;
    if (r.note !== undefined) notes.push(r.note);
    return undefined;
  }, notes, st);
  if (result !== undefined) return result;
  const why = notes.join('; ');
  return st.incomplete
    ? { state: 'unknown', seen: false, note: `clean-run marker could not be checked: ${why || 'unknown'}` }
    : { state: 'none', seen: false, note: `no clean-run marker from a trusted run${why === '' ? '' : `: ${why}`}` };
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

/** Fingerprint forms made with PIPEGEN_FP_KEY (review-C3 m10): all need the key id of the current key. */
const KEYED_FORMS: readonly string[] = ['region', 'quoted', 'file', 'line'];

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
    if (c.findings.some((f) => f.secret || KEYED_FORMS.includes(f.fpBy)) && c.keyId !== kid) { skip('its secret fingerprints are not under the current key id'); continue; }
    for (const f of c.findings) { const k = countKeyOf(c.job, f); counts.set(k, (counts.get(k) ?? 0) + 1); }
  }
  // the reader's caps (review-C3 m8): never write a baseline the reader would refuse without saying so
  if (counts.size > MAX_COUNT_ENTRIES) throw new Error(`can not write the baseline: too many distinct findings (${counts.size}; the reader takes at most ${MAX_COUNT_ENTRIES})`);
  for (const k of counts.keys()) {
    if (k.length > MAX_COUNT_KEY) throw new Error(`can not write the baseline: a count key is longer than ${MAX_COUNT_KEY} characters (the reader would refuse the file)`);
  }
  const sorted = [...counts].sort(([a], [b]) => code(a, b));
  const mac = sign(key, canonicalBaseline(runId, kid, counts));
  const bytes = new TextEncoder().encode(JSON.stringify({ runId, keyId: kid, counts: Object.fromEntries(sorted), mac }));
  if (bytes.length > MAX_ARTIFACT_BYTES) throw new Error(`can not write the baseline: it is over the size cap (${bytes.length} bytes; the reader takes at most ${MAX_ARTIFACT_BYTES})`);
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
  return new TextEncoder().encode(JSON.stringify({ runId: id, keyId: kid, mac: sign(k, canonicalMarker(id, kid)) }));
}
