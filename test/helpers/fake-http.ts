// A fake `fetch` for tests: answers from a route table and records every request. No test touches the network.
// Used both as the `fetch` a real Octokit is built with (so the real client code runs) and as `deps.fetch`.
import { Octokit } from '@octokit/rest';

export interface Call { method: string; url: URL; headers: Record<string, string>; body?: string }
export interface Reply { status?: number; body?: unknown; headers?: Record<string, string> }
/** Keyed by `METHOD origin+pathname` (no query); a handler sees the whole call, query included. */
export type Routes = Record<string, Reply | ((c: Call) => Reply)>;

/** Unmatched requests get a GitHub-style 404. Redirect replies (with a `location` header) are followed, like fetch. */
export function fakeFetch(routes: Routes): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fn = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const req = input instanceof Request ? input : undefined;
    let url = new URL(req ? req.url : String(input));
    const headers: Record<string, string> = {};
    new Headers(init?.headers ?? req?.headers).forEach((v, k) => { headers[k] = v; });
    const method = (init?.method ?? req?.method ?? 'GET').toUpperCase();
    const body = typeof init?.body === 'string' ? init.body : undefined;
    // Redirects are followed (as fetch does by default) unless the caller asked for 'manual' or 'error'.
    for (let hops = 0; ; hops++) {
      const call: Call = { method, url, headers, body };
      calls.push(call);
      const route = routes[`${method} ${url.origin}${url.pathname}`];
      const reply: Reply = route === undefined ? { status: 404, body: { message: 'Not Found' } } : typeof route === 'function' ? route(call) : route;
      const status = reply.status ?? 200;
      const location = reply.headers?.location;
      if ([301, 302, 307, 308].includes(status) && location !== undefined && init?.redirect !== 'manual' && hops < 5) {
        if (init?.redirect === 'error') throw new TypeError('fetch failed: redirect');
        url = new URL(location, url);
        continue;
      }
      return new Response(JSON.stringify(reply.body ?? {}), { status, headers: { 'content-type': 'application/json', ...reply.headers } });
    }
  };
  return { fetch: fn as typeof fetch, calls };
}

const quiet = { debug() {}, info() {}, warn() {}, error() {} };

/** A real Octokit whose requests go to a fake fetch. `options` is merged in (for example the credential, built at runtime). */
export function fakeOctokit(routes: Routes, options: Record<string, unknown> = {}): { gh: Octokit; calls: Call[] } {
  const { fetch, calls } = fakeFetch(routes);
  return { gh: new Octokit({ ...options, request: { fetch }, log: quiet }), calls };
}
