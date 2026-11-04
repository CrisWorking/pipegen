// E8: a stateful fake of what the cleanup reads and removes in the scratch repo (and the central proof branch), on top of
// (GitHub answers 204 to the deletes; a fetch Response cannot carry a body with 204, so the fake answers 200, as proof-github.ts does.)
// keysWorld (secrets, variables listing) and proof-github.ts world() (the repo itself). Runs, PRs, proof branches, caches,
// code scanning analyses, Actions variables, the empty commit and the default branch reset, the repo delete. Response
// shapes as GitHub gives them. No network.
import type { Call, Reply } from './fake-http.js';
import type { World, WorldOptions } from './proof-github.js';
import { keysWorld, OWNER, SCRATCH, type KeysFake } from './scratch-secrets.js';

export interface CleanupFake {
  runs: { id: number; status: string }[];
  prs: { number: number; head: string; state: 'open' | 'closed' }[];
  /** Scratch branch names (no refs/heads/). The default branch is `main`. */
  branches: Set<string>;
  central: Set<string>;
  caches: number[];
  /** null: code scanning is off (the list answers 403). */
  analyses: number[] | null;
  /** The default branch head. */
  defaultHead: string;
  deleted: boolean;
  /** Status answers per "METHOD path-suffix" (after /repos/o/r), applied before the fake's own logic. */
  fail: Map<string, number>;
  /** Runs a cancel leaves going (a force-cancel stops them). */
  ignoreCancel: Set<number>;
  /** Branches that come back in the list once after a delete (a push that landed late). */
  lateBranches: string[];
  /** The repo DELETE answers this status. */
  deleteStatus?: number;
  /** The repo DELETE answers OK but the repo stays (GitHub didn't delete it). */
  deleteIgnored?: boolean;
  /** The tree GitHub's answer to the empty commit names (default: the tree sent). */
  commitTree?: string;
  /** Lists answer 403. */
  unreadable: Set<'runs' | 'pulls' | 'refs' | 'caches'>;
  handler: (c: Call) => Reply | undefined;
}

const json = (status: number, body: unknown): Reply => ({ status, body });
const notFound = (): Reply => json(404, { message: 'Not Found' });

export function cleanupFake(scratch = SCRATCH, keys?: KeysFake): CleanupFake {
  const R = `/repos/${OWNER}/${scratch}`;
  const C = `/repos/${OWNER}/pipelines`;
  const f: CleanupFake = {
    runs: [], prs: [], branches: new Set(), central: new Set(), caches: [], analyses: [], defaultHead: '1'.repeat(40), deleted: false,
    fail: new Map(), ignoreCancel: new Set(), lateBranches: [], unreadable: new Set(), handler: () => undefined,
  };
  f.handler = (c) => {
    const path = decodeURIComponent(c.url.pathname);
    if (path.startsWith(`${C}/`)) {
      const rest = path.slice(C.length);
      const m = /^\/git\/refs?\/heads\/(.+)$/.exec(rest);
      if (m) {
        const b = m[1] as string;
        if (c.method === 'DELETE') return f.central.delete(b) ? json(200, {}) : json(422, { message: 'Reference does not exist' });
        if (c.method === 'GET') return f.central.has(b) ? json(200, { ref: `refs/heads/${b}`, object: { sha: '2'.repeat(40) } }) : notFound();
      }
      return undefined;
    }
    if (!path.startsWith(R)) return undefined;
    const rest = path.slice(R.length);
    if (rest === '' && c.method === 'DELETE') {
      if (f.deleteStatus !== undefined) return json(f.deleteStatus, { message: 'Must have admin rights to Repository.' });
      if (f.deleteIgnored !== true) f.deleted = true;
      return json(200, {});
    }
    if (f.deleted) return notFound();
    const failed = f.fail.get(`${c.method} ${rest}`);
    if (failed !== undefined) return json(failed, { message: 'Server Error' });
    const q = c.url.searchParams;
    // runs
    if (rest === '/actions/runs' && c.method === 'GET') {
      if (f.unreadable.has('runs')) return json(403, { message: 'Resource not accessible' });
      const per = Number(q.get('per_page') ?? '30');
      const n = Number(q.get('page') ?? '1');
      return json(200, { total_count: f.runs.length, workflow_runs: f.runs.slice((n - 1) * per, n * per).map((r) => ({ ...r, conclusion: r.status === 'completed' ? 'cancelled' : null })) });
    }
    let m = /^\/actions\/runs\/(\d+)(\/cancel|\/force-cancel)?$/.exec(rest);
    if (m) {
      const id = Number(m[1]);
      const r = f.runs.find((x) => x.id === id);
      if (r === undefined) return notFound();
      if (c.method === 'GET' && m[2] === undefined) return json(200, { id, status: r.status });
      if (c.method === 'POST' && m[2] === '/cancel') {
        if (r.status === 'completed') return json(409, { message: 'Cannot cancel a workflow run that is completed.' });
        if (!f.ignoreCancel.has(id)) r.status = 'completed';
        return json(202, {});
      }
      if (c.method === 'POST' && m[2] === '/force-cancel') {
        if (r.status === 'completed') return json(409, { message: 'completed' });
        r.status = 'completed';
        return json(202, {});
      }
      if (c.method === 'DELETE' && m[2] === undefined) {
        if (r.status !== 'completed') return json(403, { message: 'Cannot delete a run in progress' });
        f.runs = f.runs.filter((x) => x.id !== id);
        return json(200, {});
      }
    }
    // PRs
    if (rest === '/pulls' && c.method === 'GET') {
      if (f.unreadable.has('pulls')) return json(403, { message: 'Resource not accessible' });
      return json(200, f.prs.filter((p) => p.state === (q.get('state') ?? 'open')).map((p) => ({ number: p.number, state: p.state, head: { ref: p.head } })));
    }
    m = /^\/pulls\/(\d+)$/.exec(rest);
    if (m && c.method === 'PATCH') {
      const p = f.prs.find((x) => x.number === Number(m?.[1]));
      if (p === undefined) return notFound();
      p.state = 'closed';
      return json(200, { number: p.number, state: 'closed', head: { ref: p.head } });
    }
    // branches
    if (rest === '/git/matching-refs/heads/proof/' && c.method === 'GET') {
      if (f.unreadable.has('refs')) return json(403, { message: 'Resource not accessible' });
      return json(200, [...f.branches].filter((b) => b.startsWith('proof/')).sort().map((b) => ({ ref: `refs/heads/${b}`, object: { sha: '3'.repeat(40), type: 'commit' } })));
    }
    m = /^\/git\/refs\/heads\/(.+)$/.exec(rest);
    if (m && c.method === 'DELETE') {
      const b = m[1] as string;
      if (!f.branches.delete(b)) return json(422, { message: 'Reference does not exist' });
      const late = f.lateBranches.shift();
      if (late !== undefined) f.branches.add(late);
      return json(200, {});
    }
    if (m && c.method === 'PATCH' && m[1] === 'main') {
      const b = JSON.parse(c.body ?? '{}') as { sha: string; force?: boolean };
      f.defaultHead = b.sha;
      return json(200, { ref: 'refs/heads/main', object: { sha: b.sha } });
    }
    if (rest === '/git/commits' && c.method === 'POST') {
      const b = JSON.parse(c.body ?? '{}') as { tree: string; parents: string[] };
      return json(201, { sha: 'e'.repeat(40), tree: { sha: f.commitTree ?? b.tree }, parents: b.parents.map((sha) => ({ sha })) });
    }
    // caches, code scanning, variables
    if (rest === '/actions/caches' && c.method === 'GET') {
      if (f.unreadable.has('caches')) return json(403, { message: 'Resource not accessible' });
      return json(200, { total_count: f.caches.length, actions_caches: f.caches.map((id) => ({ id, key: `npm-${id}` })) });
    }
    m = /^\/actions\/caches\/(\d+)$/.exec(rest);
    if (m && c.method === 'DELETE') {
      const id = Number(m[1]);
      if (!f.caches.includes(id)) return notFound();
      f.caches = f.caches.filter((x) => x !== id);
      return json(200, {});
    }
    if (rest === '/code-scanning/analyses' && c.method === 'GET') {
      if (f.analyses === null) return json(403, { message: 'Advanced Security must be enabled for this repository to use code scanning.' });
      return json(200, f.analyses.map((id) => ({ id, ref: 'refs/heads/main' })));
    }
    m = /^\/code-scanning\/analyses\/(\d+)$/.exec(rest);
    if (m && c.method === 'DELETE' && f.analyses !== null) {
      const id = Number(m[1]);
      if (q.get('confirm_delete') === null) return json(400, { message: 'confirm_delete needed for the last analysis' });
      f.analyses = f.analyses.filter((x) => x !== id);
      return json(200, { next_analysis_url: null, confirm_delete_url: null });
    }
    m = /^\/actions\/variables\/([A-Za-z0-9_]+)$/.exec(rest);
    if (m && c.method === 'DELETE' && keys !== undefined && keys.variables !== null) {
      const before = keys.variables.length;
      keys.variables = keys.variables.filter((v) => v.name !== m?.[1]);
      return keys.variables.length < before ? json(200, {}) : notFound();
    }
    return undefined;
  };
  return f;
}

/** A world with the scratch repo (its id `repoId`), its secrets and the cleanup fake. */
export function cleanupWorld(w: WorldOptions = {}, keep: Record<string, string> = {}, repoId = 77_001): { g: World; s: KeysFake; f: CleanupFake } {
  let f: CleanupFake | null = null;
  const { g, s } = keysWorld({ ...w, repoIds: { [SCRATCH]: repoId, ...(w.repoIds ?? {}) }, extra: (c) => w.extra?.(c) ?? f?.handler(c) }, keep);
  f = cleanupFake(SCRATCH, s);
  return { g, s, f };
}
