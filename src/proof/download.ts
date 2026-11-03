// Plan E E4 (ruling S2; DECISIONS #64 and #111): artifact and job-log downloads from the scratch repo. GitHub answers both
// with a redirect to its artifact store (blob storage), which the CLI's client never follows to another host. So:
//   1. the API call (GET …/actions/artifacts/{id}/zip or …/actions/jobs/{id}/logs) goes through the run's Octokit (the token
//      goes to api.github.com only) asking `redirect: 'manual'`, and must answer a redirect;
//   2. its Location is checked: https, no user, password or port, a host matching the gate's STORE_HOST_RE (a copy, since
//      gate/src is bundled; a test compares the two);
//   3. that URL is fetched ONCE, by hand, WITHOUT the token or any header but a user agent, and must answer 200 (a second
//      redirect is never followed); the body is read within a cap as it streams.
// Artifacts (the gate's own readers, artifacts.ts): only the names the caller asks for; the listing must be whole and each
// artifact of THIS run, not expired, its size within MAX_ARTIFACT_ZIP_BYTES from the listing BEFORE any download
// (pickArtifact); the zip a single regular file within its cap, CRC and sizes right (readZipEntry). Anything else is a
// problem for that artifact (E5 reads it as "report unreadable"), never a guess.
// Job logs: one job at a time, as text; the most recent MAX_LOG_BYTES are kept (the error is near the end); past
// MAX_LOG_READ_BYTES reading stops and no log is kept.
import { createHash } from 'node:crypto';
import type { Octokit } from '@octokit/rest';
import { MAX_RESULT_FILE_BYTES, MAX_RESULT_ZIP_BYTES, pickArtifact, readZipEntry } from '../../gate/src/artifacts.js';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import { safeText } from '../util/safe-text.js';
import { githubRead, requireGuarded, type GuardedRepo } from './target.js';

/** The artifact store hosts GitHub redirects downloads to: the gate's STORE_HOST_RE (gate/src/github-adapter.ts), copied. */
export const STORE_HOST_RE = /^(?:[a-z0-9-]{1,63}\.blob\.core\.windows\.net|[a-z0-9-]{1,63}\.actions\.githubusercontent\.com)$/;
/** An artifact zip, as listed and as read (the gate's cap). */
export const MAX_ARTIFACT_ZIP_BYTES = MAX_RESULT_ZIP_BYTES;
/** The one file inside it, inflated. */
export const MAX_ARTIFACT_FILE_BYTES = MAX_RESULT_FILE_BYTES;
/** Artifacts read per run, and their listed bytes together. */
export const MAX_RUN_ARTIFACTS = 100;
export const MAX_RUN_ARTIFACT_BYTES = 128 * 1024 * 1024;
const ARTIFACT_PAGES = 5;
/** A job log: the most recent bytes kept (ruling S2). */
export const MAX_LOG_BYTES = 8 * 1024 * 1024;
/** A job log longer than this is not read to its end (and none of it is kept). */
export const MAX_LOG_READ_BYTES = 64 * 1024 * 1024;
const TIMEOUT_MS = 60_000;
const NAME_RE = /^[A-Za-z0-9._-]{1,200}$/;

export interface DownloadDeps {
  /** The fetch for the store hop (default the global fetch). The API hop uses the Octokit. */
  fetch?: typeof fetch;
  timeoutMs?: number;
  clock?: RateClock;
}
/** One artifact's single file. `artifact`: the artifact's name; `file`: the entry's name; `sha256` of the bytes. */
export interface ArtifactFile { artifact: string; file: string; bytes: Buffer; sha256: string }
export interface RunArtifacts {
  files: Map<string, ArtifactFile>;
  /** Artifact name (or '(listing)') → why it wasn't read. */
  problems: Map<string, string>;
}
export interface JobLog { log?: string; cut: boolean; problem?: string }

class DownloadProblem extends Error {}

function hard(gh: Octokit, e: unknown): void {
  if (isRateStop(e)) throw e;
  if ((e as { status?: unknown } | null)?.status === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
}
const statusText = (e: unknown): string => {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === 'number' && Number.isInteger(s) ? `HTTP ${s}` : 'no answer';
};

/** Steps 1 and 2: the API call that must redirect, and its checked store URL. */
async function storeUrl(gh: Octokit, r: GuardedRepo, what: 'artifact' | 'log', id: number, clock: RateClock): Promise<URL> {
  let res: { status: number; headers: Record<string, unknown> };
  try {
    res = what === 'artifact'
      ? await withRateLimit(() => gh.request('GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}', { owner: r.owner, repo: r.repo, artifact_id: id, archive_format: 'zip', request: { redirect: 'manual' } }), clock)
      : await withRateLimit(() => gh.request('GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs', { owner: r.owner, repo: r.repo, job_id: id, request: { redirect: 'manual' } }), clock);
  } catch (e) {
    hard(gh, e);
    throw new DownloadProblem(`GitHub refused the download (${statusText(e)})`);
  }
  if (!(res.status >= 300 && res.status < 400)) throw new DownloadProblem('GitHub did not answer with a redirect to its artifact store');
  const loc = res.headers.location;
  let u: URL;
  try {
    u = new URL(typeof loc === 'string' ? loc : '');
  } catch {
    throw new DownloadProblem('the download redirect is not a URL');
  }
  if (u.protocol !== 'https:' || u.username !== '' || u.password !== '' || u.port !== '' || !STORE_HOST_RE.test(u.hostname)) {
    throw new DownloadProblem(`the download redirect goes to a host pipegen does not fetch from (${safeText(u.hostname, 100)})`);
  }
  return u;
}

/** Step 3: one GET of the store URL, no token, no redirect; the body read as it comes. `keep`: 'all' within `max`, or the tail. */
async function fetchStore(u: URL, deps: DownloadDeps, mode: { kind: 'all'; max: number } | { kind: 'tail'; keep: number; max: number }): Promise<{ bytes: Buffer; cut: boolean }> {
  const f = deps.fetch ?? globalThis.fetch;
  let res: Response;
  try {
    // no credential header: the store URL is pre-signed, and the token never leaves api.github.com (DECISIONS #64)
    res = await f(u.href, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(deps.timeoutMs ?? TIMEOUT_MS), headers: { 'user-agent': 'pipegen' } });
  } catch {
    throw new DownloadProblem('the artifact store did not answer');
  }
  if (res.status !== 200) {
    await res.body?.cancel().catch(() => {});
    throw new DownloadProblem(res.status >= 300 && res.status < 400 ? 'the artifact store answered with another redirect, which pipegen does not follow' : `the artifact store answered ${res.status}`);
  }
  const declared = Number(res.headers.get('content-length') ?? 'NaN');
  if (Number.isFinite(declared) && declared > mode.max) {
    await res.body?.cancel().catch(() => {});
    throw new DownloadProblem(`the download is over the size cap (${mode.max} bytes)`);
  }
  if (res.body === null) return { bytes: Buffer.alloc(0), cut: false };
  const reader = res.body.getReader();
  const chunks: Buffer[] = [];
  let held = 0;
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > mode.max) {
      await reader.cancel().catch(() => {});
      throw new DownloadProblem(`the download is over the size cap (${mode.max} bytes)`);
    }
    chunks.push(Buffer.from(value));
    held += value.length;
    if (mode.kind === 'tail') {
      while (chunks.length > 1 && held - (chunks[0] as Buffer).length >= mode.keep) held -= (chunks.shift() as Buffer).length;
    }
  }
  let bytes = Buffer.concat(chunks);
  let cut = false;
  if (mode.kind === 'tail' && bytes.length > mode.keep) {
    bytes = bytes.subarray(bytes.length - mode.keep);
    cut = true;
  }
  if (mode.kind === 'tail' && total > bytes.length) cut = true;
  return { bytes, cut };
}

/** Every artifact of a run (pages read until the total), as one listing object for pickArtifact; null when unreadable. */
async function listArtifacts(gh: Octokit, r: GuardedRepo, runId: number, clock: RateClock): Promise<{ total_count: number; artifacts: unknown[] } | string> {
  const all: unknown[] = [];
  for (let page = 1; page <= ARTIFACT_PAGES; page++) {
    let d: { total_count?: unknown; artifacts?: unknown } | null;
    try {
      d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts', { owner: r.owner, repo: r.repo, run_id: runId, per_page: 100, page }, clock)).data as typeof d;
    } catch (e) {
      hard(gh, e);
      return `the artifact list of run ${runId} could not be read (${statusText(e)})`;
    }
    if (typeof d?.total_count !== 'number' || !Number.isSafeInteger(d.total_count) || d.total_count < 0 || !Array.isArray(d.artifacts)) return `the artifact list of run ${runId} could not be read`;
    all.push(...d.artifacts);
    if (all.length >= d.total_count) return { total_count: d.total_count, artifacts: all };
    if (d.artifacts.length === 0) return `the artifact list of run ${runId} is cut short`;
  }
  return `run ${runId} lists more artifacts than pipegen reads`;
}

/**
 * The artifacts of run `runId` whose names `want` accepts, each its single file (see the file comment). Never throws for a
 * hostile or broken artifact: it is a problem by name. Rate stops and a rejected token pass through.
 */
export async function downloadRunArtifacts(gh: Octokit, scratch: GuardedRepo, runId: number, want: (name: string) => boolean, deps: DownloadDeps = {}): Promise<RunArtifacts> {
  requireGuarded(scratch, 'scratch');
  const clock = deps.clock ?? clockOf(gh);
  const out: RunArtifacts = { files: new Map(), problems: new Map() };
  if (!Number.isSafeInteger(runId) || runId <= 0) { out.problems.set('(listing)', 'the run id is not a number'); return out; }
  const listed = await listArtifacts(gh, scratch, runId, clock);
  if (typeof listed === 'string') { out.problems.set('(listing)', listed); return out; }
  const names = [...new Set(listed.artifacts.map((a) => (a as { name?: unknown } | null)?.name).filter((n): n is string => typeof n === 'string' && NAME_RE.test(n) && want(n)))].sort();
  if (names.length === 0) {
    // the listing must still be whole and of this run: a cut or foreign one is a problem even when nothing matched
    const probe = pickArtifact(listed, { name: '\u0000none', runId });
    if (!probe.ok && !probe.missing) out.problems.set('(listing)', probe.problem);
  }
  let budget = MAX_RUN_ARTIFACT_BYTES;
  for (const [i, name] of names.entries()) {
    if (i >= MAX_RUN_ARTIFACTS) { out.problems.set(name, `more than ${MAX_RUN_ARTIFACTS} artifacts in one run; not read`); continue; }
    const pick = pickArtifact(listed, { name, runId, maxBytes: MAX_ARTIFACT_ZIP_BYTES });
    if (!pick.ok) { out.problems.set(name, pick.problem); continue; }
    if (pick.size > budget) { out.problems.set(name, `the run's artifacts together are over the size cap (${MAX_RUN_ARTIFACT_BYTES} bytes)`); continue; }
    budget -= pick.size;
    try {
      const u = await storeUrl(gh, scratch, 'artifact', pick.id, clock);
      const { bytes } = await fetchStore(u, deps, { kind: 'all', max: Math.min(pick.size, MAX_ARTIFACT_ZIP_BYTES) });
      const entry = readZipEntry(bytes, { maxBytes: MAX_ARTIFACT_FILE_BYTES });
      if (!entry.ok) { out.problems.set(name, entry.problem); continue; }
      const file = Buffer.from(entry.bytes);
      out.files.set(name, { artifact: name, file: entry.name, bytes: file, sha256: createHash('sha256').update(file).digest('hex') });
    } catch (e) {
      if (!(e instanceof DownloadProblem)) throw e;
      out.problems.set(name, e.message);
    }
  }
  return out;
}

/** One job's log as text, the most recent MAX_LOG_BYTES (see the file comment). A problem is returned, never thrown. */
export async function downloadJobLog(gh: Octokit, scratch: GuardedRepo, jobId: number, deps: DownloadDeps = {}): Promise<JobLog> {
  requireGuarded(scratch, 'scratch');
  if (!Number.isSafeInteger(jobId) || jobId <= 0) return { cut: false, problem: 'the job id is not a number' };
  try {
    const u = await storeUrl(gh, scratch, 'log', jobId, deps.clock ?? clockOf(gh));
    const { bytes, cut } = await fetchStore(u, deps, { kind: 'tail', keep: MAX_LOG_BYTES, max: MAX_LOG_READ_BYTES });
    let text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    if (cut) text = text.replace(/^�+/, '');   // a character cut at the start of the kept tail
    return { log: text, cut };
  } catch (e) {
    if (!(e instanceof DownloadProblem)) throw e;
    return { cut: false, problem: e.message };
  }
}
