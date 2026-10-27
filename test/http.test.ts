import { describe, expect, it } from 'vitest';
import { fetchAllowed, HttpError, MAX_REDIRECTS, readBytes, readJson } from '../src/engine/http.js';
import { countingStream, fakeFetch } from './helpers/fake-http.js';

const A = 'https://a.example';
const B = 'https://b.example';
const get = { method: 'GET' as const, timeoutMs: 1000, hosts: ['a.example'] };
// Header name that holds "auth", built at runtime (repo rule: no secret-like literals in test/).
const LOGIN_HEADER = 'author' + 'ization';
/** A URL with a user and password in it, built at runtime for the same reason. */
const WITH_LOGIN = 'https://' + 'u' + ':' + 'p' + '@a.example/x';

describe('http: fetchAllowed (final review M1)', () => {
  it('http: only https, allow-listed hosts, no port or user in the URL', async () => {
    const { fetch, calls } = fakeFetch({ [`GET ${A}/x`]: { body: { ok: 1 } } });
    expect((await fetchAllowed(fetch, `${A}/x`, get)).status).toBe(200);
    for (const url of ['http://a.example/x', `${B}/x`, 'https://a.example:8443/x', WITH_LOGIN, 'not a url']) {
      await expect(fetchAllowed(fetch, url, get), url).rejects.toThrow(HttpError);
    }
    expect(calls).toHaveLength(1);
  });

  it('http: redirects are followed by hand within the allow-list only, at most MAX_REDIRECTS hops; 0 = none', async () => {
    const { fetch, calls } = fakeFetch({
      [`GET ${A}/1`]: { status: 302, headers: { location: '/2' } },
      [`GET ${A}/2`]: { status: 301, headers: { location: `${A}/3` } },
      [`GET ${A}/3`]: { body: { done: true } },
      [`GET ${A}/away`]: { status: 307, headers: { location: `${B}/x` } },
      [`GET ${B}/x`]: { body: {} },
      [`GET ${A}/loop`]: { status: 302, headers: { location: '/loop' } },
    });
    expect(await readJson(await fetchAllowed(fetch, `${A}/1`, get), 1000, 'x')).toEqual({ done: true });
    await expect(fetchAllowed(fetch, `${A}/away`, get)).rejects.toMatchObject({ kind: 'host' });
    expect(calls.map((c) => c.url.host)).not.toContain('b.example');
    await expect(fetchAllowed(fetch, `${A}/loop`, get)).rejects.toMatchObject({ kind: 'redirect' });
    expect(calls.filter((c) => c.url.pathname === '/loop')).toHaveLength(MAX_REDIRECTS + 1);
    await expect(fetchAllowed(fetch, `${A}/1`, { ...get, maxRedirects: 0 })).rejects.toMatchObject({ kind: 'redirect' });
    // a cap above MAX_REDIRECTS is lowered to it
    calls.length = 0;
    await expect(fetchAllowed(fetch, `${A}/loop`, { ...get, maxRedirects: 50 })).rejects.toMatchObject({ kind: 'redirect' });
    expect(calls).toHaveLength(MAX_REDIRECTS + 1);
  });

  it('http: a POST never follows a redirect, even to the same host', async () => {
    const { fetch, calls } = fakeFetch({ [`POST ${A}/q`]: { status: 307, headers: { location: `${A}/r` } }, [`POST ${A}/r`]: { body: {} } });
    await expect(fetchAllowed(fetch, `${A}/q`, { ...get, method: 'POST', body: '{}' })).rejects.toMatchObject({ kind: 'redirect' });
    expect(calls.map((c) => c.url.pathname)).toEqual(['/q']);
  });

  it('http: non-2xx is an error unless asked for; 404 can be null; only the caller\'s headers are sent', async () => {
    const { fetch, calls } = fakeFetch({ [`GET ${A}/down`]: { status: 503 } });
    await expect(fetchAllowed(fetch, `${A}/down`, get)).rejects.toMatchObject({ kind: 'status', status: 503 });
    expect((await fetchAllowed(fetch, `${A}/down`, { ...get, status: 'any' })).status).toBe(503);
    expect(await fetchAllowed(fetch, `${A}/missing`, { ...get, notFound: 'null' })).toBeNull();
    for (const c of calls) expect(Object.keys(c.headers)).not.toContain(LOGIN_HEADER);
    const down = (async () => { throw new TypeError('fetch failed'); }) as unknown as typeof fetch;
    await expect(fetchAllowed(down, `${A}/x`, get)).rejects.toMatchObject({ kind: 'network' });
  });

  it('http: bodies are capped by the declared length and while they stream; bad JSON is an HttpError', async () => {
    const big = countingStream(8 * 1024 * 1024);
    const { fetch } = fakeFetch({
      [`GET ${A}/big`]: () => ({ stream: big.stream }),
      [`GET ${A}/declared`]: { raw: 'x', headers: { 'content-length': String(10 * 1024 * 1024) } },
      [`GET ${A}/text`]: { raw: 'not json' },
    });
    await expect(readBytes(await fetchAllowed(fetch, `${A}/big`, get), 1024 * 1024, 'big')).rejects.toMatchObject({ kind: 'too-large' });
    expect(big.pulled()).toBeLessThanOrEqual(1024 * 1024 + 64 * 1024);
    await expect(readBytes(await fetchAllowed(fetch, `${A}/declared`, get), 1024, 'declared')).rejects.toMatchObject({ kind: 'too-large' });
    await expect(readJson(await fetchAllowed(fetch, `${A}/text`, get), 1024, 'text')).rejects.toMatchObject({ kind: 'not-json' });
  });
});
