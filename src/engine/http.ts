// Shared HTTP for the tool engine (final review M1): every request deps.fetch makes in stats.ts, pin.ts,
// reviewed.ts (packageExists) and discover.ts (npm search) goes through fetchAllowed, and every body is read through
// readBody / readJson. The rules, the strictest each caller had before:
// - https only, to an allow-listed host only (the caller names them), no port, no user or password in the URL;
// - redirects followed by hand (`redirect: 'manual'`), each hop checked against the same allow-list, at most
//   MAX_REDIRECTS (or the caller's lower cap; 0 = any redirect is an error); a request with a body (POST) never
//   follows one. A redirect to any other host is an error, never a request;
// - no credential: fetchAllowed sends the caller's headers and nothing else (only Octokit, deps.gh, carries the
//   user's credential, ruling S15; pinning passes a registry's own anonymous pull token to that registry only);
// - a timeout on every request, and a byte cap on every body, enforced on the declared length and on the bytes as
//   they stream in (a large body is cancelled at the cap, never read whole first).
import { safeText } from '../util/safe-text.js';

/** Redirect hops followed at most. */
export const MAX_REDIRECTS = 3;
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/** What went wrong, for callers that word their own message (e.g. packageExists on a redirect). */
export type HttpErrorKind = 'host' | 'network' | 'redirect' | 'status' | 'too-large' | 'not-json';

export class HttpError extends Error {
  readonly kind: HttpErrorKind;
  /** The HTTP status, for kind 'status'. */
  readonly status?: number;
  constructor(kind: HttpErrorKind, message: string, options?: { cause?: unknown; status?: number }) {
    super(safeText(message, 400), options);
    this.name = 'HttpError';
    this.kind = kind;
    if (options?.status !== undefined) this.status = options.status;
  }
}

export interface FetchAllowedOptions {
  method: 'GET' | 'HEAD' | 'POST';
  timeoutMs: number;
  /** The hosts the request and every redirect hop may go to. */
  hosts: readonly string[];
  /** Sent as is (accept defaults to application/json). Never a user credential. */
  headers?: Record<string, string>;
  /** A request body (POST); such a request never follows a redirect. */
  body?: string;
  /** Redirect hops followed (default MAX_REDIRECTS, never more); 0 = any redirect is an error. */
  maxRedirects?: number;
  /** 'null': a 404 answer gives null (its body cancelled). */
  notFound?: 'null';
  /** 'any': any final (non-redirect) status is returned and the caller reads `res.status`; default: non-2xx is an HttpError. */
  status?: 'ok' | 'any';
}

/** A fetch with no credential, following redirects by hand to the allowed https hosts only. */
export async function fetchAllowed(fetchFn: typeof fetch, url: string, opts: FetchAllowedOptions & { notFound: 'null' }): Promise<Response | null>;
export async function fetchAllowed(fetchFn: typeof fetch, url: string, opts: FetchAllowedOptions): Promise<Response>;
export async function fetchAllowed(fetchFn: typeof fetch, url: string, opts: FetchAllowedOptions): Promise<Response | null> {
  const hops = opts.body !== undefined || opts.method === 'POST' ? 0 : Math.min(opts.maxRedirects ?? MAX_REDIRECTS, MAX_REDIRECTS);
  let current: URL;
  try {
    current = new URL(url);
  } catch (e) {
    throw new HttpError('host', `pipegen won't fetch "${safeText(url, 120)}": not a URL.`, { cause: e });
  }
  for (let hop = 0; ; hop++) {
    if (current.protocol !== 'https:' || !opts.hosts.includes(current.hostname) || current.port !== '' || current.username !== '' || current.password !== '') {
      throw new HttpError('host', `pipegen won't fetch from ${current.protocol}//${current.host}: not an allowed https host.`);
    }
    const headers: Record<string, string> = { accept: 'application/json', ...opts.headers };
    if (opts.body !== undefined) headers['content-type'] ??= 'application/json';
    let res: Response;
    try {
      res = await fetchFn(current.href, {
        method: opts.method, redirect: 'manual', headers, body: opts.body, signal: AbortSignal.timeout(opts.timeoutMs),
      });
    } catch (e) {
      throw new HttpError('network', `Couldn't reach ${current.host}.`, { cause: e });
    }
    if (REDIRECT_STATUSES.has(res.status)) {
      const location = res.headers.get('location');
      await res.body?.cancel().catch(() => {});
      if (location === null || hop >= hops) throw new HttpError('redirect', `${current.host} redirected too often or nowhere.`);
      try {
        current = new URL(location, current);
      } catch (e) {
        throw new HttpError('redirect', `${current.host} redirected to something that isn't a URL.`, { cause: e });
      }
      continue;
    }
    if (res.status === 404 && opts.notFound === 'null') {
      await res.body?.cancel().catch(() => {});
      return null;
    }
    if (!res.ok && opts.status !== 'any') {
      await res.body?.cancel().catch(() => {});
      throw new HttpError('status', `${current.host} answered HTTP ${res.status} for ${current.pathname}.`, { status: res.status });
    }
    return res;
  }
}

/** Reads a body up to `maxBytes`; anything larger is refused (the declared length, and the bytes as they arrive). */
export async function readBody(res: Response, maxBytes: number, onChunk: (b: Uint8Array) => void, what: string): Promise<void> {
  const tooLarge = () => new HttpError('too-large', `${what} is too large (more than ${maxBytes} bytes).`);
  const declared = res.headers.get('content-length');
  if (declared !== null && Number(declared) > maxBytes) {
    await res.body?.cancel().catch(() => {});
    throw tooLarge();
  }
  if (res.body === null) return;
  const reader = res.body.getReader();
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw tooLarge();
    }
    onChunk(value);
  }
}

/** The whole body (at most `maxBytes`). */
export async function readBytes(res: Response, maxBytes: number, what: string): Promise<Buffer> {
  const chunks: Uint8Array[] = [];
  await readBody(res, maxBytes, (b) => chunks.push(b), what);
  return Buffer.concat(chunks);
}

/** The body as JSON (at most `maxBytes`); anything that isn't JSON is an HttpError. */
export async function readJson(res: Response, maxBytes: number, what: string): Promise<unknown> {
  const bytes = await readBytes(res, maxBytes, what);
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (e) {
    throw new HttpError('not-json', `Couldn't read ${what}: not JSON.`, { cause: e });
  }
}
