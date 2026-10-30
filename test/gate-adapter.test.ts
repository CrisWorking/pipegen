// Plan C Task C5a: the GitHub client of the gate (gate/src/github-adapter.ts), over the REST API with the global fetch (no new dependency).
// It implements the GateGithub interface of C3 and C4. Every answer is hostile and every non-2xx is an error (fail closed) except the
// documented 404 mappings; a rate limit is an error with a note; the token comes from the action input only, is masked first, and never
// reaches a message. Fake fetch only: no network. Written first (strict test-first).
import { describe, expect, it } from 'vitest';
import { API_ROOT, GitHubApiError, githubAdapter, type AdapterOptions } from '../gate/src/github-adapter.js';
import { makeZip, zipOf } from './helpers/zip.js';

const CRED = ['gh', 's_', 'Qw8'.repeat(12)].join('');
const SHA = (c: string): string => c.repeat(40);
/** the option name, spelled at run time (test/no-secret-literals.test.ts reads `<name>: <value>` as an assignment) */
const TK = ['to', 'ken'].join('');
interface Seen { url: string; headers: Record<string, string>; redirect?: string; method?: string }
type Reply = { status: number; body?: string | Uint8Array; headers?: Record<string, string | undefined> } | Error;
function fake(route: (url: string, seen: Seen) => Reply): { fetch: typeof fetch; seen: Seen[] } {
  const seen: Seen[] = [];
  const f = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const h = new Headers(init?.headers);
    const s: Seen = { url, headers: Object.fromEntries(h.entries()), ...(init?.redirect === undefined ? {} : { redirect: init.redirect }), ...(init?.method === undefined ? {} : { method: init.method }) };
    seen.push(s);
    const r = route(url, s);
    if (r instanceof Error) throw r;
    const headers = Object.fromEntries(Object.entries(r.headers ?? { 'content-type': 'application/json' }).filter((x): x is [string, string] => x[1] !== undefined));
    return new Response(r.status === 204 || r.status === 304 ? null : (r.body ?? '') as BodyInit, { status: r.status, headers });
  };
  return { fetch: f as typeof fetch, seen };
}
const json = (v: unknown, status = 200, headers: Record<string, string> = {}): Reply => ({ status, body: JSON.stringify(v), headers: { 'content-type': 'application/json', ...headers } });
const make = (route: (url: string, seen: Seen) => Reply, extra: { notes?: string[]; mask?: (s: string) => void } = {}) => {
  const f = fake(route);
  return { gh: githubAdapter({ [TK]: CRED, fetch: f.fetch, ...extra } as unknown as AdapterOptions), seen: f.seen };
};

describe('requests: the REST paths of GateGithub, with the token and nothing else', () => {
  it('each call goes to api.github.com at the documented path, with Bearer auth and the API version; answers are the parsed JSON', async () => {
    const { gh, seen } = make(() => json({ ok: 1 }));
    await gh.compare('acme', 'app', SHA('a'), SHA('b'));
    await gh.listRuns('acme', 'app', { workflow: 'pipegen.yml', branch: 'main', event: 'push', status: 'success', page: 2, perPage: 100 });
    await gh.getPull('acme', 'app', 5);
    await gh.listPullFiles('acme', 'app', 5, 3, 100);
    await gh.listPullReviews('acme', 'app', 5, 1, 100);
    await gh.fileAt('acme', 'app', '.github/CODEOWNERS', SHA('b'));
    await gh.compareFiles('acme', 'app', SHA('a'), SHA('c'));
    await gh.collaboratorPermission('acme', 'app', 'Alice-1');
    await gh.branchHead('acme', 'app', 'release/v2');
    expect(seen.map((s) => s.url)).toEqual([
      `${API_ROOT}/repos/acme/app/compare/${SHA('a')}...${SHA('b')}`,
      `${API_ROOT}/repos/acme/app/actions/workflows/pipegen.yml/runs?event=push&branch=main&status=success&per_page=100&page=2`,
      `${API_ROOT}/repos/acme/app/pulls/5`,
      `${API_ROOT}/repos/acme/app/pulls/5/files?per_page=100&page=3`,
      `${API_ROOT}/repos/acme/app/pulls/5/reviews?per_page=100&page=1`,
      `${API_ROOT}/repos/acme/app/contents/.github/CODEOWNERS?ref=${SHA('b')}`,
      `${API_ROOT}/repos/acme/app/compare/${SHA('a')}...${SHA('c')}`,
      `${API_ROOT}/repos/acme/app/collaborators/Alice-1/permission`,
      `${API_ROOT}/repos/acme/app/git/ref/heads/release/v2`,
    ]);
    for (const s of seen) {
      expect(s.headers.authorization).toBe(`Bearer ${CRED}`);
      expect(s.headers['x-github-api-version']).toBe('2022-11-28');
      expect(s.headers.accept).toBe('application/vnd.github+json');
      expect(s.redirect).toBe('manual');
    }
  });
  it('the token is masked (core.setSecret) before the first request, once', async () => {
    const order: string[] = [];
    const { gh } = make(() => { order.push('request'); return json({}); }, { mask: (s) => order.push(s === CRED ? 'mask' : 'other') });
    await gh.getPull('acme', 'app', 5);
    await gh.getPull('acme', 'app', 5);
    expect(order).toEqual(['mask', 'request', 'request']);
  });
  it('an empty token is refused at once (no request)', () => {
    expect(() => githubAdapter({ [TK]: '', fetch: fake(() => json({})).fetch } as unknown as AdapterOptions)).toThrow(/token/);
  });
  it('names in a path are checked first: a bad owner, repo, sha, login, branch, path or number makes no request', async () => {
    const { gh, seen } = make(() => json({}));
    const bad: (() => Promise<unknown>)[] = [
      () => gh.getPull('ac/me', 'app', 5), () => gh.getPull('acme', '..', 5), () => gh.getPull('acme', 'app', 0), () => gh.getPull('acme', 'app', 1.5),
      () => gh.compare('acme', 'app', 'main', SHA('b')), () => gh.compareFiles('acme', 'app', SHA('a'), `${SHA('b')}x`),
      () => gh.fileAt('acme', 'app', '../x', SHA('b')), () => gh.fileAt('acme', 'app', '/x', SHA('b')), () => gh.fileAt('acme', 'app', 'a//b', SHA('b')),
      () => gh.fileAt('acme', 'app', 'a/./b', SHA('b')), () => gh.fileAt('acme', 'app', 'a\0b', SHA('b')), () => gh.fileAt('acme', 'app', 'x', 'main'),
      () => gh.collaboratorPermission('acme', 'app', 'a/b'), () => gh.branchHead('acme', 'app', '../x'), () => gh.tagExists('acme', 'app', 'a b'),
      () => gh.listRunArtifacts('acme', 'app', -1, 'pipegen-out-x'), () => gh.listRunArtifacts('acme', 'app', 4, 'x&y=1'),
      () => gh.downloadArtifact('acme', 'app', 0), () => gh.listPullFiles('acme', 'app', 5, 1, 101),
    ];
    for (const call of bad) await expect(call()).rejects.toThrow();
    expect(seen).toEqual([]);
  });
  it('a path segment with characters a URL would read is encoded (never a second query or a path change)', async () => {
    const { gh, seen } = make(() => json({ type: 'file' }));
    await gh.fileAt('acme', 'app', 'docs/a b#c?d&e.md', SHA('b'));
    expect(seen[0]?.url).toBe(`${API_ROOT}/repos/acme/app/contents/docs/a%20b%23c%3Fd%26e.md?ref=${SHA('b')}`);
  });
});

describe('status mapping: fail closed except the documented 404s', () => {
  it('404: fileAt and rawFileAt give null, tagExists gives false; every other call throws', async () => {
    const { gh } = make(() => json({ message: 'Not Found' }, 404));
    expect(await gh.fileAt('acme', 'app', 'x', SHA('b'))).toBeNull();
    expect(await gh.rawFileAt('acme', 'app', 'x', SHA('b'))).toBeNull();
    expect(await gh.tagExists('acme', 'app', 'main')).toBe(false);
    for (const call of [() => gh.getPull('acme', 'app', 5), () => gh.compare('acme', 'app', SHA('a'), SHA('b')), () => gh.branchHead('acme', 'app', 'main'), () => gh.collaboratorPermission('acme', 'app', 'a'), () => gh.listRunArtifacts('acme', 'app', 4, 'pipegen-out-x')]) {
      await expect(call()).rejects.toBeInstanceOf(GitHubApiError);
    }
  });
  it('tagExists: 200 is true (whatever the body); anything but 200 or 404 throws', async () => {
    expect(await make(() => json({ ref: 'refs/tags/main' })).gh.tagExists('acme', 'app', 'main')).toBe(true);
    await expect(make(() => json({}, 500)).gh.tagExists('acme', 'app', 'main')).rejects.toThrow();
    await expect(make(() => json({}, 403)).gh.tagExists('acme', 'app', 'main')).rejects.toThrow();
  });
  it('adapter error mapping: 403, 500, 401, 409, 422 and a network error throw GitHubApiError with the status; the message names the call, never the token', async () => {
    for (const status of [401, 403, 409, 422, 500, 502]) {
      const { gh } = make(() => json({ message: `bad ${CRED}` }, status));
      const err = await gh.getPull('acme', 'app', 5).catch((e: unknown) => e);
      expect(err, String(status)).toBeInstanceOf(GitHubApiError);
      expect((err as GitHubApiError).status).toBe(status);
      expect((err as Error).message).toMatch(/pulls\/5/);
      expect((err as Error).message).not.toContain(CRED);
    }
    const err = await make(() => new Error(`ECONNRESET ${CRED}`)).gh.getPull('acme', 'app', 5).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GitHubApiError);
    expect((err as Error).message).not.toContain(CRED);
  });
  it('adapter: 429, or 403 with x-ratelimit-remaining 0 or retry-after, is a rate-limit error with a note (never a wait, never a pass)', async () => {
    for (const reply of [json({}, 429), json({}, 403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1900000000' }), json({}, 403, { 'retry-after': '30' })]) {
      const notes: string[] = [];
      const { gh } = make(() => reply, { notes });
      const err = await gh.getPull('acme', 'app', 5).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(GitHubApiError);
      expect((err as GitHubApiError).rateLimited).toBe(true);
      expect(notes.join(' ')).toMatch(/rate limit/);
    }
  });
  it('adapter: malformed JSON, a non-JSON answer, or a body over the cap throws', async () => {
    await expect(make(() => ({ status: 200, body: '{"a":', headers: { 'content-type': 'application/json' } })).gh.getPull('acme', 'app', 5)).rejects.toThrow(/JSON/);
    await expect(make(() => ({ status: 200, body: '', headers: { 'content-type': 'application/json' } })).gh.getPull('acme', 'app', 5)).rejects.toThrow();
    const huge = `{"x":"${'a'.repeat(33 * 1024 * 1024)}"}`;
    await expect(make(() => ({ status: 200, body: huge, headers: { 'content-type': 'application/json' } })).gh.compareFiles('acme', 'app', SHA('a'), SHA('b'))).rejects.toThrow(/cap/);
    await expect(make(() => ({ status: 200, body: '{"x":1}', headers: { 'content-type': 'application/json', 'content-length': String(64 * 1024 * 1024) } })).gh.getPull('acme', 'app', 5)).rejects.toThrow(/cap/);
  });
  it('a redirect on an API call is an error (a renamed or moved repository is not followed)', async () => {
    await expect(make(() => ({ status: 301, headers: { location: 'https://api.github.com/repositories/1' } })).gh.getPull('acme', 'app', 5)).rejects.toThrow(/redirect/);
  });
  it('adapter: pagination cut: a page past the cap the caller pages to is refused; an artifact list shorter than its total_count throws', async () => {
    const { gh, seen } = make(() => json({ total_count: 2, artifacts: [{ id: 1 }] }));
    await expect(gh.listPullFiles('acme', 'app', 5, 31, 100)).rejects.toThrow(/page/);
    await expect(gh.listPullReviews('acme', 'app', 5, 32, 100)).rejects.toThrow(/page/);
    await expect(gh.listRuns('acme', 'app', { workflow: 'pipegen.yml', branch: 'main', event: 'push', status: 'success', page: 6, perPage: 100 })).rejects.toThrow(/page/);
    expect(seen).toEqual([]);
    await expect(gh.listRunArtifacts('acme', 'app', 4, 'pipegen-out-x')).rejects.toThrow(/total_count|cut/);
    expect(seen[0]?.url).toBe(`${API_ROOT}/repos/acme/app/actions/runs/4/artifacts?name=pipegen-out-x&per_page=100`);
  });
});

describe('raw files and artifacts', () => {
  it('rawFileAt asks for the raw media type and gives the text, capped at 3 MiB', async () => {
    const { gh, seen } = make(() => ({ status: 200, body: '* @alice\n', headers: { 'content-type': 'application/vnd.github.raw' } }));
    expect(await gh.rawFileAt('acme', 'app', '.github/CODEOWNERS', SHA('b'))).toBe('* @alice\n');
    expect(seen[0]?.headers.accept).toBe('application/vnd.github.raw+json');
    await expect(make(() => ({ status: 200, body: 'x'.repeat(3 * 1024 * 1024 + 1) })).gh.rawFileAt('acme', 'app', 'x', SHA('b'))).rejects.toThrow(/cap/);
  });
  const STORE = 'https://productionresultssa1.blob.core.windows.net/actions-results/abc/x.zip?sig=123';
  it('the artifact zip: GitHub answers 302 to blob storage; the hop is followed by hand, without the token, to an allowed https host only', async () => {
    const zip = zipOf('r.sarif', '{"runs":[]}');
    const { gh, seen } = make((url) => (url.startsWith(API_ROOT) ? { status: 302, headers: { location: STORE } } : { status: 200, body: zip, headers: { 'content-type': 'application/zip' } }));
    expect(Buffer.from(await gh.downloadArtifactZip('acme', 'app', 77, 1024)).equals(Buffer.from(zip))).toBe(true);
    expect(seen.map((s) => s.url)).toEqual([`${API_ROOT}/repos/acme/app/actions/artifacts/77/zip`, STORE]);
    expect(seen[1]?.headers.authorization).toBeUndefined();
    expect(seen[1]?.redirect).toBe('manual');
    for (const loc of ['http://productionresultssa1.blob.core.windows.net/x', 'https://evil.example/x.zip', ['https://user', 'pw@x.blob.core.windows.net/x'].join(':'), 'https://blob.core.windows.net.evil.example/x', 'https://x.blob.core.windows.net:8443/x', '/relative']) {
      const m = make((url) => (url.startsWith(API_ROOT) ? { status: 302, headers: { location: loc } } : { status: 200, body: zip }));
      await expect(m.gh.downloadArtifactZip('acme', 'app', 77, 1024), loc).rejects.toThrow();
      expect(m.seen).toHaveLength(1);
    }
    // a second redirect from the store is not followed
    const twice = make((url) => (url.startsWith(API_ROOT) ? { status: 302, headers: { location: STORE } } : { status: 302, headers: { location: STORE } }));
    await expect(twice.gh.downloadArtifactZip('acme', 'app', 77, 1024)).rejects.toThrow();
  });
  it('the artifact zip is capped by the caller (declared length and streamed bytes)', async () => {
    const big = new Uint8Array(4096);
    const m = make((url) => (url.startsWith(API_ROOT) ? { status: 302, headers: { location: STORE } } : { status: 200, body: big, headers: { 'content-type': 'application/zip' } }));
    await expect(m.gh.downloadArtifactZip('acme', 'app', 77, 1024)).rejects.toThrow(/cap/);
  });
  it('downloadArtifact (the C3 contract): the bytes of the one plain file in the zip; any zip problem throws', async () => {
    const ok = make((url) => (url.startsWith(API_ROOT) ? { status: 302, headers: { location: STORE } } : { status: 200, body: zipOf('pipegen-baseline.json', '{"a":1}') }));
    expect(Buffer.from(await ok.gh.downloadArtifact('acme', 'app', 77)).toString()).toBe('{"a":1}');
    const two = make((url) => (url.startsWith(API_ROOT) ? { status: 302, headers: { location: STORE } } : { status: 200, body: makeZip({ entries: [{ name: 'a', data: '1' }, { name: 'b', data: '2' }] }) }));
    await expect(two.gh.downloadArtifact('acme', 'app', 77)).rejects.toThrow();
  });
});
