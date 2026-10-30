// Plan C Task C5a: the gate's GitHub client, the real GateGithub (C3 and C4) over the REST API with Node's global fetch: no new runtime
// dependency (ruling S1 keeps @actions/* out of the CLI; the gate is bundled in C6 with what package.json already has).
//
// The rules (fail closed everywhere):
//   - one host, https://api.github.com; every path built from checked parts (owner and repository names, 40-hex commit shas, positive
//     numbers, logins, ref names, repository paths), each segment percent-encoded; anything else is refused before a request;
//   - the token comes from the action input only, is masked (core.setSecret) before the first request, is sent only to the API host, and
//     never reaches a message (errors name the call and the status, nothing the server or the caller wrote);
//   - `redirect: 'manual'`: an API answer that redirects is an error (a renamed repository is not followed). The one redirect followed is
//     the artifact download's 302 to blob storage, by hand, once, to an allowed https host, WITHOUT the token;
//   - every non-2xx answer is an error, except the documented 404 mappings (fileAt and rawFileAt → null, tagExists → false); a rate limit
//     (429, or 403 with `x-ratelimit-remaining: 0` or `retry-after`) is an error with a note, never a wait;
//   - every body is capped, on its declared length and on the bytes as they stream in; JSON is parsed once, and malformed JSON is an error;
//   - pagination: each caller pages itself (C3, C4) within its own cap; the adapter refuses a page past that cap, and an artifact list cut
//     short of its total_count.
import type { GateGithub, RunQuery } from './baseline.js';
import { MAX_ARTIFACT_BYTES } from './baseline.js';
import { readZipEntry } from './artifacts.js';

export const API_ROOT = 'https://api.github.com';
const API_HOST = 'api.github.com';
const API_VERSION = '2022-11-28';
const TIMEOUT_MS = 30_000;
/** JSON answers: a compare holds up to 300 files with their patches. */
const MAX_JSON_BYTES = 32 * 1024 * 1024;
/** Raw file contents (CODEOWNERS up to GitHub's 3 MiB). */
const MAX_RAW_BYTES = 3 * 1024 * 1024;
/** The page caps of the callers: pull files and reviews (integrity.ts, 3,000 files / 100), runs (baseline.ts MAX_RUN_PAGES). */
const PAGE_CAP = { files: 30, reviews: 31, runs: 5 } as const;
const MAX_PER_PAGE = 100;

/** Blob storage hosts the artifact download redirects to. */
const STORE_HOST_RE = /^(?:[a-z0-9-]{1,63}\.blob\.core\.windows\.net|[a-z0-9-]{1,63}\.actions\.githubusercontent\.com)$/;

export class GitHubApiError extends Error {
  readonly status: number | undefined;
  readonly rateLimited: boolean;
  constructor(message: string, opts: { status?: number; rateLimited?: boolean } = {}) {
    super(message);
    this.name = 'GitHubApiError';
    this.status = opts.status;
    this.rateLimited = opts.rateLimited ?? false;
  }
}

export interface AdapterOptions {
  /** The `github-token` input. */
  token: string;
  /** Node's fetch (injected by tests). */
  fetch?: typeof fetch;
  /** core.setSecret: called with the token before the first request. */
  mask?: (secret: string) => void;
  /** Rate-limit notes are added here (for the summary). */
  notes?: string[];
  timeoutMs?: number;
}
/** GateGithub plus the raw zip of an artifact (artifacts.ts checks it with the expected file name). */
export interface GateGithubAdapter extends GateGithub {
  downloadArtifactZip(owner: string, name: string, artifactId: number, maxBytes: number): Promise<Uint8Array>;
}

// ---------- checked path parts ----------

const fail = (what: string): never => { throw new GitHubApiError(`pipegen will not call GitHub with ${what}`); };
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REF_PART_RE = /^[A-Za-z0-9._+@-]{1,255}$/;
const ARTIFACT_NAME_RE = /^[A-Za-z0-9._-]{1,200}$/;
const WORKFLOW_RE = /^[A-Za-z0-9._-]{1,100}\.ya?ml$/;
const BRANCH_QUERY_RE = /^[A-Za-z0-9._/+@-]{1,255}$/;
const repo = (owner: string, name: string): string => {
  if (typeof owner !== 'string' || !OWNER_RE.test(owner)) fail('an owner that is not a GitHub name');
  if (typeof name !== 'string' || !REPO_RE.test(name) || name === '.' || name === '..') fail('a repository name that is not one');
  return `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;
};
const sha = (s: string): string => (typeof s === 'string' && SHA_RE.test(s) ? s : fail('a commit that is not a 40-hex sha'));
const num = (n: number): string => (typeof n === 'number' && Number.isSafeInteger(n) && n > 0 ? String(n) : fail('a number that is not a positive whole number'));
const page = (p: number, cap: number): string => (typeof p === 'number' && Number.isSafeInteger(p) && p >= 1 && p <= cap ? String(p) : fail(`a page past the cap of ${cap} pages`));
const perPage = (n: number): string => (typeof n === 'number' && Number.isSafeInteger(n) && n >= 1 && n <= MAX_PER_PAGE ? String(n) : fail('a page size over 100'));
/** A ref name (`release/v2`): each part checked and encoded on its own, the slashes kept. */
const refPath = (r: string): string => {
  if (typeof r !== 'string') fail('a ref name that is not text');
  const parts = r.split('/');
  if (parts.some((x) => !REF_PART_RE.test(x) || x === '.' || x === '..' || x.endsWith('.lock'))) fail('a ref name that is not one');
  return parts.map(encodeURIComponent).join('/');
};
/** A repository path: no empty, `.` or `..` segment, no control character; each segment encoded. */
const filePath = (p: string): string => {
  if (typeof p !== 'string' || p === '' || p.length > 4096 || /[\x00-\x1f\x7f]/.test(p)) fail('a file path that is not a repository path');
  const parts = p.split('/');
  if (parts.some((x) => x === '' || x === '.' || x === '..')) fail('a file path that is not a repository path');
  return parts.map(encodeURIComponent).join('/');
};

// ---------- reading a body within a cap ----------

async function readCapped(res: Response, max: number, what: string): Promise<Uint8Array> {
  const declared = res.headers.get('content-length');
  if (declared !== null && Number(declared) > max) { await res.body?.cancel().catch(() => undefined); throw new GitHubApiError(`${what}: the answer is over the size cap`); }
  if (res.body === null) return new Uint8Array();
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) { await reader.cancel().catch(() => undefined); throw new GitHubApiError(`${what}: the answer is over the size cap`); }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.length; }
  return out;
}

// ---------- the adapter ----------

/** The real GateGithub over the REST API. Throws at once for an empty token. */
export function githubAdapter(opts: AdapterOptions): GateGithubAdapter {
  const token = opts.token;
  if (typeof token !== 'string' || token === '' || /[\s\x00-\x1f]/.test(token)) throw new GitHubApiError('the github-token input is empty or not a token');
  const fetchFn = opts.fetch ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? TIMEOUT_MS;
  let masked = false;
  const mask = (): void => { if (!masked) { masked = true; opts.mask?.(token); } };

  type NotFound = 'throw' | 'null';
  async function call(path: string, o: { accept?: string; notFound?: NotFound; max?: number; raw?: boolean } = {}): Promise<{ status: 404 } | { status: 200; body: Uint8Array; res: Response }> {
    mask();
    const url = `${API_ROOT}${path}`;
    const what = `GET ${path.replace(/\?.*$/, '')}`;
    let res: Response;
    try {
      res = await fetchFn(url, {
        method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs),
        headers: { authorization: `Bearer ${token}`, accept: o.accept ?? 'application/vnd.github+json', 'x-github-api-version': API_VERSION, 'user-agent': 'pipegen-gate' },
      });
    } catch {
      throw new GitHubApiError(`${what}: the request failed (network or timeout)`);
    }
    if (res.status >= 300 && res.status < 400) { await res.body?.cancel().catch(() => undefined); throw new GitHubApiError(`${what}: GitHub answered with a redirect, which the gate does not follow`, { status: res.status }); }
    if (res.status === 404 && o.notFound === 'null') { await res.body?.cancel().catch(() => undefined); return { status: 404 }; }
    if (res.status < 200 || res.status >= 300) {
      const remaining = res.headers.get('x-ratelimit-remaining');
      const limited = res.status === 429 || (res.status === 403 && (remaining === '0' || res.headers.get('retry-after') !== null));
      await res.body?.cancel().catch(() => undefined);
      if (limited) {
        const reset = Number(res.headers.get('x-ratelimit-reset'));
        const when = Number.isSafeInteger(reset) && reset > 0 ? ` (it resets at ${new Date(reset * 1000).toISOString()})` : '';
        const note = `GitHub rate limit reached on ${what}${when}: the gate could not read everything it needs, so it fails closed`;
        if (opts.notes !== undefined && !opts.notes.includes(note)) opts.notes.push(note);
        throw new GitHubApiError(`${what}: GitHub rate limit`, { status: res.status, rateLimited: true });
      }
      throw new GitHubApiError(`${what}: GitHub answered ${res.status}`, { status: res.status });
    }
    return { status: 200, body: await readCapped(res, o.max ?? MAX_JSON_BYTES, what), res };
  }
  async function getJson(path: string, notFound: NotFound = 'throw'): Promise<unknown> {
    const r = await call(path, { notFound });
    if (r.status === 404) return null;
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(r.body)) as unknown; } catch { throw new GitHubApiError(`GET ${path.replace(/\?.*$/, '')}: the answer is not JSON`); }
  }

  async function downloadArtifactZip(owner: string, name: string, artifactId: number, maxBytes: number): Promise<Uint8Array> {
    const path = `${repo(owner, name)}/actions/artifacts/${num(artifactId)}/zip`;
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) fail('a size cap that is not one');
    mask();
    const what = `GET ${path}`;
    let res: Response;
    try {
      res = await fetchFn(`${API_ROOT}${path}`, {
        method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs),
        headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': API_VERSION, 'user-agent': 'pipegen-gate' },
      });
    } catch { throw new GitHubApiError(`${what}: the request failed (network or timeout)`); }
    if (res.status === 200) return readCapped(res, maxBytes, what);
    if (res.status !== 302 && res.status !== 301 && res.status !== 307) { await res.body?.cancel().catch(() => undefined); throw new GitHubApiError(`${what}: GitHub answered ${res.status}`, { status: res.status }); }
    await res.body?.cancel().catch(() => undefined);
    const loc = res.headers.get('location') ?? '';
    let u: URL;
    try { u = new URL(loc); } catch { throw new GitHubApiError(`${what}: the download redirect is not a URL`); }
    if (u.protocol !== 'https:' || u.username !== '' || u.password !== '' || u.port !== '' || !STORE_HOST_RE.test(u.hostname) || u.hostname === API_HOST) {
      throw new GitHubApiError(`${what}: the download redirect goes to a host the gate does not fetch from`);
    }
    let blob: Response;
    try {
      // no token: the store URL is pre-signed, and the credential never leaves the API host
      blob = await fetchFn(u.toString(), { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': 'pipegen-gate' } });
    } catch { throw new GitHubApiError(`${what}: the download failed (network or timeout)`); }
    if (blob.status !== 200) { await blob.body?.cancel().catch(() => undefined); throw new GitHubApiError(`${what}: the artifact store answered ${blob.status}`, { status: blob.status }); }
    return readCapped(blob, maxBytes, what);
  }

  return {
    compare: async (owner, name, base, head) => getJson(`${repo(owner, name)}/compare/${sha(base)}...${sha(head)}`),
    compareFiles: async (owner, name, base, head) => getJson(`${repo(owner, name)}/compare/${sha(base)}...${sha(head)}`),
    listRuns: async (owner, name, q: RunQuery) => {
      if (typeof q.workflow !== 'string' || !WORKFLOW_RE.test(q.workflow)) fail('a workflow file name that is not one');
      if (typeof q.branch !== 'string' || !BRANCH_QUERY_RE.test(q.branch)) fail('a branch name that is not one');
      if (q.event !== 'push' || q.status !== 'success') fail('a run filter the gate does not use');
      const query = new URLSearchParams({ event: q.event, branch: q.branch, status: q.status, per_page: perPage(q.perPage), page: page(q.page, PAGE_CAP.runs) });
      return getJson(`${repo(owner, name)}/actions/workflows/${encodeURIComponent(q.workflow)}/runs?${query.toString()}`);
    },
    listRunArtifacts: async (owner, name, runId, artifactName) => {
      if (typeof artifactName !== 'string' || !ARTIFACT_NAME_RE.test(artifactName)) fail('an artifact name that is not one');
      const path = `${repo(owner, name)}/actions/runs/${num(runId)}/artifacts?${new URLSearchParams({ name: artifactName, per_page: String(MAX_PER_PAGE) }).toString()}`;
      const a = await getJson(path);
      // a list cut short of its total is not a finished answer: an artifact on the next page would be invisible
      const total = typeof a === 'object' && a !== null && Object.hasOwn(a, 'total_count') ? (a as { total_count: unknown }).total_count : undefined;
      const list = typeof a === 'object' && a !== null && Object.hasOwn(a, 'artifacts') ? (a as { artifacts: unknown }).artifacts : undefined;
      if (typeof total !== 'number' || !Array.isArray(list) || total > list.length) throw new GitHubApiError(`GET ${path.replace(/\?.*$/, '')}: the artifact list is cut (fewer entries than its total_count) or malformed`);
      return a;
    },
    downloadArtifact: async (owner, name, artifactId) => {
      const zip = await downloadArtifactZip(owner, name, artifactId, MAX_ARTIFACT_BYTES);
      const r = readZipEntry(zip, { maxBytes: MAX_ARTIFACT_BYTES });
      if (!r.ok) throw new GitHubApiError(`the artifact ${artifactId} is refused: ${r.problem}`);
      return r.bytes;
    },
    downloadArtifactZip,
    branchHead: async (owner, name, branch) => getJson(`${repo(owner, name)}/git/ref/heads/${refPath(branch)}`),
    tagExists: async (owner, name, tag) => {
      const r = await call(`${repo(owner, name)}/git/ref/tags/${refPath(tag)}`, { notFound: 'null' });
      return r.status === 200;
    },
    getPull: async (owner, name, n) => getJson(`${repo(owner, name)}/pulls/${num(n)}`),
    listPullFiles: async (owner, name, n, p, per) => getJson(`${repo(owner, name)}/pulls/${num(n)}/files?per_page=${perPage(per)}&page=${page(p, PAGE_CAP.files)}`),
    listPullReviews: async (owner, name, n, p, per) => getJson(`${repo(owner, name)}/pulls/${num(n)}/reviews?per_page=${perPage(per)}&page=${page(p, PAGE_CAP.reviews)}`),
    fileAt: async (owner, name, path, ref) => getJson(`${repo(owner, name)}/contents/${filePath(path)}?ref=${sha(ref)}`, 'null'),
    rawFileAt: async (owner, name, path, ref) => {
      const r = await call(`${repo(owner, name)}/contents/${filePath(path)}?ref=${sha(ref)}`, { accept: 'application/vnd.github.raw+json', notFound: 'null', max: MAX_RAW_BYTES });
      if (r.status === 404) return null;
      try { return new TextDecoder('utf-8', { fatal: true }).decode(r.body); } catch { throw new GitHubApiError('the raw file is not UTF-8 text'); }
    },
    collaboratorPermission: async (owner, name, login) => {
      if (typeof login !== 'string' || !LOGIN_RE.test(login)) fail('a login that is not a GitHub login');
      return getJson(`${repo(owner, name)}/collaborators/${encodeURIComponent(login)}/permission`);
    },
  };
}
