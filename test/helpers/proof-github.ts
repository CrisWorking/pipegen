// A small stateful fake of the GitHub REST calls Plan E's repo checks make (E1), with response shapes copied from the
// spike evidence (S1-access.md, S9-scratch-repo.md). It is the `fetch` of a real makeOctokit client, so the real
// guarded client runs. Unknown routes answer 404 like GitHub. No network.
import type { Octokit } from '@octokit/rest';
import { makeOctokit } from '../../src/github/client.js';
import { fakeFetch, type Call, type Reply } from './fake-http.js';
import { fake } from './secret-repo.js';

export const API = 'https://api.github.com';
export const SHA_MAIN = '1'.repeat(40);

export interface FakeRepo {
  private: boolean;
  visibility?: 'public' | 'private' | 'internal';
  default_branch?: string;
  /** branch → head sha; 'empty' = a repo with no commit yet (git refs answer 409). */
  refs?: Record<string, string> | 'empty';
  /** The repo exists but this token can't see it (a private repo outside the token's or installation's list: 404). */
  hidden?: boolean;
  /** GitHub answers for another repo (a renamed or transferred one): the full_name it reports. */
  fullName?: string;
}

export interface WorldOptions {
  owner?: string;
  ownerType?: 'User' | 'Organization';
  repos?: Record<string, FakeRepo>;
  /** GET /user login. */
  login?: string;
  /** GET /orgs/{org} body (null: 403). */
  org?: Record<string, unknown> | null;
  /** GET /repos/{o}/{r}/actions/permissions per repo name (default enabled, all). null: 403. */
  actions?: Record<string, Record<string, unknown> | null>;
  selected?: Record<string, Record<string, unknown> | null>;
  /** GET /repos/{o}/pipelines/actions/permissions/access (default 'none'). */
  access?: string;
  /** Status for PATCH /repos/{o}/{r} (default 200). */
  patchStatus?: number;
  /** Status for PUT …/actions/permissions/access (default 204). */
  accessStatus?: number;
  /** What POST /user/repos and /orgs/{org}/repos make (default private, as asked). */
  createPrivate?: boolean;
  /** Merged into the create answer (GitHub's answer can differ from what it stored). */
  createBody?: Record<string, unknown>;
  /** The create answers this status with a validation error (not "already exists"). */
  createStatus?: number;
  /** The repo the create makes is not visible to this token afterwards. */
  createHidden?: boolean;
  /** Merged into every PATCH /repos/{o}/{r} answer. */
  patchBody?: Record<string, unknown>;
}

export interface World {
  gh: Octokit;
  calls: Call[];
  repos: Record<string, FakeRepo>;
  /** Calls that change something (POST, PUT, PATCH, DELETE). */
  writes: () => Call[];
  /** "METHOD /path" of each call, in order (path decoded). */
  seen: () => string[];
}

const json = (status: number, body: unknown): Reply => ({ status, body });
const notFound = (): Reply => json(404, { message: 'Not Found', documentation_url: 'https://docs.github.com/rest' });

export function world(opts: WorldOptions = {}): World {
  const owner = opts.owner ?? 'CrisWorking';
  const ownerType = opts.ownerType ?? 'User';
  const repos: Record<string, FakeRepo> = structuredClone(opts.repos ?? {});   // each world its own copy: tests share fixtures
  let access = opts.access ?? 'none';
  const body = (name: string, r: FakeRepo) => ({
    id: 1000 + name.length, name, full_name: r.fullName ?? `${owner}/${name}`, private: r.private,
    visibility: r.visibility ?? (r.private ? 'private' : 'public'), default_branch: r.default_branch ?? 'main',
    owner: { login: owner, type: ownerType },
  });
  const refsOf = (r: FakeRepo) => (r.refs ?? { [r.default_branch ?? 'main']: SHA_MAIN });

  const route = (c: Call): Reply => {
    const path = decodeURIComponent(c.url.pathname);
    const parts = path.split('/').filter((p) => p !== '');
    const m = c.method;
    if (m === 'GET' && path === '/user') return json(200, { login: opts.login ?? owner, id: 1 });
    if (m === 'GET' && parts[0] === 'orgs' && parts.length === 2) {
      return opts.org === null ? json(403, { message: 'Resource not accessible by personal access token' }) : json(200, { login: parts[1], ...(opts.org ?? {}) });
    }
    if (m === 'POST' && (path === '/user/repos' || (parts[0] === 'orgs' && parts[2] === 'repos'))) {
      const b = JSON.parse(c.body ?? '{}') as { name: string };
      if (repos[b.name] !== undefined) {
        return json(422, { message: 'Repository creation failed.', errors: [{ resource: 'Repository', code: 'custom', field: 'name', message: 'name already exists on this account' }] });
      }
      if (opts.createStatus !== undefined) return json(opts.createStatus, { message: 'Validation Failed', errors: [{ resource: 'Repository', code: 'invalid', field: 'description' }] });
      const made: FakeRepo = { private: opts.createPrivate ?? true, refs: { main: SHA_MAIN }, ...(opts.createHidden ? { hidden: true } : {}) };
      repos[b.name] = made;
      return json(201, { ...body(b.name, made), ...(opts.createBody ?? {}) });
    }
    if (parts[0] !== 'repos' || parts[1] !== owner) return notFound();
    const name = parts[2] as string;
    const r = repos[name];
    if (r === undefined || r.hidden === true) return notFound();
    const rest = parts.slice(3).join('/');
    if (rest === '') {
      if (m === 'GET') return json(200, body(name, r));
      if (m === 'PATCH') {
        if (opts.patchStatus !== undefined && opts.patchStatus >= 400) return json(opts.patchStatus, { message: 'Resource not accessible by personal access token' });
        const b = JSON.parse(c.body ?? '{}') as { private?: boolean; visibility?: string; default_branch?: string };
        if (b.default_branch !== undefined) {
          const refs = refsOf(r);
          if (refs === 'empty' || refs[b.default_branch] === undefined) return json(422, { message: 'Validation Failed' });
          r.default_branch = b.default_branch;
        }
        if (b.private === true || b.visibility === 'private') { r.private = true; r.visibility = 'private'; }
        return json(200, { ...body(name, r), ...(opts.patchBody ?? {}) });
      }
    }
    if (rest === 'actions/permissions' && m === 'GET') {
      const a = opts.actions?.[name];
      return a === null ? json(403, { message: 'Resource not accessible by personal access token' }) : json(200, a ?? { enabled: true, allowed_actions: 'all', sha_pinning_required: false });
    }
    if (rest === 'actions/permissions/selected-actions' && m === 'GET') {
      const s = opts.selected?.[name];
      return s === null || s === undefined ? json(403, { message: 'Resource not accessible by personal access token' }) : json(200, s);
    }
    if (rest === 'actions/permissions/access') {
      if (m === 'GET') return json(200, { access_level: access });
      if (m === 'PUT') {
        if ((opts.accessStatus ?? 204) >= 400) return json(opts.accessStatus as number, { message: 'Resource not accessible by personal access token' });
        access = (JSON.parse(c.body ?? '{}') as { access_level: string }).access_level;
        return json(200, {});   // GitHub answers 204; a fetch Response can't carry a body with 204
      }
    }
    if (m === 'GET' && parts[3] === 'git' && parts[4] === 'ref' && parts[5] === 'heads') {
      const refs = refsOf(r);
      if (refs === 'empty') return json(409, { message: 'Git Repository is empty.' });
      const branch = parts.slice(6).join('/');
      const sha = refs[branch];
      return sha === undefined ? notFound() : json(200, { ref: `refs/heads/${branch}`, object: { sha, type: 'commit' } });
    }
    if (m === 'POST' && rest === 'git/refs') {
      const refs = refsOf(r);
      if (refs === 'empty') return json(409, { message: 'Git Repository is empty.' });
      const b = JSON.parse(c.body ?? '{}') as { ref: string; sha: string };
      r.refs = { ...refs, [b.ref.replace(/^refs\/heads\//, '')]: b.sha };
      return json(201, { ref: b.ref, object: { sha: b.sha } });
    }
    return notFound();
  };

  const { fetch, calls } = fakeFetch(new Proxy({}, {
    get: (_t, key) => (typeof key === 'string' ? route : undefined),
  }) as never);
  const gh = makeOctokit(fake.githubPat(), { fetch, log: () => {} });
  return {
    gh, calls, repos,
    writes: () => calls.filter((c) => c.method !== 'GET' && c.method !== 'HEAD'),
    seen: () => calls.map((c) => `${c.method} ${decodeURIComponent(c.url.pathname)}`),
  };
}
