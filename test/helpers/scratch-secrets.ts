// E4: the scratch repo's Actions secrets as a fake (the `extra` routes of test/helpers/proof-github.ts world()): the public
// key (a real libsodium key pair, so a test can open what pipegen sealed), PUT, the list and DELETE. Stored values are kept
// opened, so a test can check what pipegen stored without any value appearing in a request body. No network.
import sodium from 'libsodium-wrappers';
import type { CliIO } from '../../src/cli/io.js';
import { ScratchKeys, type ExcerptEvidence } from '../../src/proof/keys.js';
import { proofTarget, type ProofApp } from '../../src/proof/target.js';
import { SecretVault } from '../../src/create/secrets.js';
import type { Call, Reply } from './fake-http.js';
import { world, type World, type WorldOptions } from './proof-github.js';

await sodium.ready;

const LIST = ['sec', 'rets'].join('');

export interface KeysFake {
  /** Opened values by name, as GitHub holds them now. */
  values: Map<string, string>;
  /** Names whose PUT / DELETE answers this status. */
  failPut: Map<string, number>;
  failDelete: Map<string, number>;
  /** Names that come back in the list after a DELETE answered OK (GitHub didn't delete them). */
  sticky: Set<string>;
  /** The list answers this status (or a raw body). */
  listStatus?: number;
  listBody?: unknown;
  /** Called on each PUT, before it is applied (a test can start a stop here). */
  onPut?: (name: string) => void;
  /** The updated_at GitHub lists per name: a new one on every PUT (and on touch). */
  updated: Map<string, string>;
  /** A change made outside pipegen: the value is set and updated_at moves. */
  touch(name: string, value: string): void;
  /** Organisation secrets visible to the repo (GET …/actions/organization-secrets). null: the list answers 403. */
  orgShared: string[] | null;
  /** Repo Actions variables (GET …/actions/variables). null: 403. */
  variables: { name: string; value: string }[] | null;
  /** Environments (GET …/environments), each with its secret names and variables (a null list: 403). null: the environment list answers 403. */
  environments: Record<string, { held: string[] | null; vars: { name: string; value: string }[] | null }> | null;
  /**
   * Workflow runs as GET …/actions/runs/{id} answers them (fix round 2, R1). A run not listed: completed, attempt 1, started a
   * minute after the server time of that answer. A run set without run_started_at started at the server time it was set.
   * `run_started_at` null: not given.
   */
  runs: Map<number, { status: string; run_attempt: number; run_started_at?: string | null }>;
  /** GitHub's server time (ms): the `date` header of the secrets list (fix round 3, N1). Moves on 1 s per list answer. */
  serverTime: number;
  /** The `date` header of the secrets list: a text to send instead, or null to leave it out. */
  dateHeader?: string | null;
  handler: (c: Call) => Reply | undefined;
}

export function secretsFake(owner: string, repo: string, keep: Record<string, string> = {}): KeysFake {
  const kp = sodium.crypto_box_keypair();
  let clock = 0;
  const stamp = () => new Date(Date.UTC(2026, 10, 3, 10, 0, clock++)).toISOString().replace('.000', '');
  const base = `/repos/${owner}/${repo}/actions/secrets`;
  const f: KeysFake = {
    values: new Map(Object.entries(keep)), failPut: new Map(), failDelete: new Map(), sticky: new Set(),
    updated: new Map(Object.keys(keep).map((k) => [k, stamp()])), orgShared: [], variables: [], environments: {}, runs: new Map(),
    serverTime: Date.UTC(2026, 10, 3, 10, 0, 0),
    touch: (name, value) => { f.values.set(name, value); f.updated.set(name, stamp()); },
    handler: (c) => {
      const path = decodeURIComponent(c.url.pathname);
      if (path === `${base}/public-key` && c.method === 'GET') return { body: { key_id: '3380204578043523366', key: Buffer.from(kp.publicKey).toString('base64') } };
      if (path === base && c.method === 'GET') {
        if (f.listStatus !== undefined) return { status: f.listStatus, body: { message: 'Resource not accessible by personal access token' } };
        if (f.listBody !== undefined) return { body: f.listBody };
        const all = [...f.values.keys()].sort();
        const per = Number(c.url.searchParams.get('per_page') ?? '30');
        const n = Number(c.url.searchParams.get('page') ?? '1');
        f.serverTime += 1000;
        const date = f.dateHeader === undefined ? new Date(f.serverTime).toUTCString() : f.dateHeader;
        return { headers: (date === null ? {} : { date }) as Record<string, string>, body: { total_count: all.length, [LIST]: all.slice((n - 1) * per, n * per).map((name) => ({ name, created_at: '2026-11-03T10:00:00Z', updated_at: f.updated.get(name) ?? '2026-11-03T10:00:00Z' })) } };
      }
      const repoBase = base.slice(0, -'/actions/secrets'.length);
      const forbidden = { status: 403, body: { message: 'Resource not accessible by personal access token' } };
      const runM = new RegExp(`^${repoBase}/actions/runs/(\\d+)$`).exec(path);
      if (runM && c.method === 'GET') {
        const id = Number(runM[1]);
        const r = f.runs.get(id) ?? { status: 'completed', run_attempt: 1 };
        const started = r.run_started_at === undefined ? new Date(f.serverTime + 60_000).toISOString().replace('.000', '') : r.run_started_at;
        return { body: { id, status: r.status, run_attempt: r.run_attempt, ...(started === null ? {} : { run_started_at: started }), conclusion: r.status === 'completed' ? 'failure' : null } };
      }
      if (path === `${repoBase}/environments` && c.method === 'GET') {
        if (f.environments === null) return forbidden;
        const names = Object.keys(f.environments);
        return { body: { total_count: names.length, environments: names.map((name, i) => ({ id: 900 + i, name })) } };
      }
      const envM = new RegExp(`^${repoBase}/environments/([^/]+)/(secrets|variables)$`).exec(path);
      if (envM && c.method === 'GET') {
        const env = f.environments?.[envM[1] as string];
        if (env === undefined) return { status: 404, body: { message: 'Not Found' } };
        if (envM[2] === 'secrets') {
          if (env.held === null) return forbidden;
          return { body: { total_count: env.held.length, [LIST]: env.held.map((name) => ({ name, created_at: '2026-11-03T10:00:00Z', updated_at: '2026-11-03T10:00:00Z' })) } };
        }
        if (env.vars === null) return forbidden;
        return { body: { total_count: env.vars.length, variables: env.vars.map((v) => ({ ...v, created_at: '2026-11-03T10:00:00Z', updated_at: '2026-11-03T10:00:00Z' })) } };
      }
      if (path === `${repoBase}/actions/organization-secrets` && c.method === 'GET') {
        if (f.orgShared === null) return { status: 403, body: { message: 'Resource not accessible by personal access token' } };
        return { body: { total_count: f.orgShared.length, [LIST]: f.orgShared.map((name) => ({ name, created_at: '2026-11-03T10:00:00Z', updated_at: '2026-11-03T10:00:00Z', visibility: 'all' })) } };
      }
      if (path === `${repoBase}/actions/variables` && c.method === 'GET') {
        if (f.variables === null) return { status: 403, body: { message: 'Resource not accessible by personal access token' } };
        return { body: { total_count: f.variables.length, variables: f.variables.map((v) => ({ ...v, created_at: '2026-11-03T10:00:00Z', updated_at: '2026-11-03T10:00:00Z' })) } };
      }
      if (path.startsWith(`${base}/`)) {
        const name = path.slice(base.length + 1);
        if (c.method === 'PUT') {
          f.onPut?.(name);
          const st = f.failPut.get(name);
          if (st !== undefined) return { status: st, body: { message: 'Validation Failed' } };
          const b = JSON.parse(c.body ?? '{}') as { encrypted_value: string; key_id: string };
          f.values.set(name, sodium.to_string(sodium.crypto_box_seal_open(Buffer.from(b.encrypted_value, 'base64'), kp.publicKey, kp.privateKey)));
          f.updated.set(name, stamp());
          return { status: 201, body: {} };
        }
        if (c.method === 'DELETE') {
          const st = f.failDelete.get(name);
          if (st !== undefined) return { status: st, body: { message: 'Server Error' } };
          if (!f.sticky.has(name)) { f.values.delete(name); f.updated.delete(name); }
          return { status: 200, body: {} };
        }
      }
      return undefined;
    },
  };
  // a run a test sets without run_started_at started at the server time it was set (as GitHub would report it)
  const set = f.runs.set.bind(f.runs);
  f.runs.set = (id, r) => set(id, r.run_started_at === undefined ? { ...r, run_started_at: new Date(f.serverTime).toISOString().replace('.000', '') } : r);
  return f;
}

export const OWNER = 'CrisWorking';
export const SCRATCH = 'pipegen-proof-shop';
export const app = (o: Partial<ProofApp> = {}): ProofApp => ({ owner: OWNER, repo: 'shop', private: true, ownerType: 'User', defaultBranch: 'main', ...o });
export const quietIo: Pick<CliIO, 'prompt' | 'out' | 'err'> = {
  prompt: { confirm: async () => false, select: async () => { throw new Error('no select'); }, text: async () => { throw new Error('no text'); } },
  out: () => {}, err: () => {},
};

let nextRepoId = 50_000;
/**
 * A world with the scratch repo and its secrets fake. `more` answers other routes first. Each world's scratch repo gets its own
 * id (ScratchKeys shares its state per repo id), unless `w.repoIds` names one.
 */
export function keysWorld(w: WorldOptions = {}, keep: Record<string, string> = {}): { g: World; s: KeysFake } {
  const s = secretsFake(w.owner ?? OWNER, SCRATCH, keep);
  const g = world({ ...w, repoIds: { [SCRATCH]: nextRepoId++, ...(w.repoIds ?? {}) }, repos: { pipelines: { private: true }, [SCRATCH]: { private: true }, ...(w.repos ?? {}) }, extra: (c) => w.extra?.(c) ?? s.handler(c) });
  return { g, s };
}

/** The run id placeholderEvidence's brand names. */
export const EVIDENCE_RUN = 4242;
/** The attempt of EVIDENCE_RUN the brand names (the fake's default for a run it doesn't list). */
export const EVIDENCE_ATTEMPT = 1;
/**
 * Real excerpt evidence (DECISIONS #113) for tests of errorExcerpt: a ScratchKeys over the fake stores one placeholder, a
 * ticket is taken (the repo listed), and the evidence minted for run EVIDENCE_RUN. Nothing else can make one.
 */
export async function placeholderEvidence(): Promise<ExcerptEvidence> {
  const { g } = keysWorld();
  const keys = new ScratchKeys(g.gh, proofTarget(app()), new SecretVault(), { io: quietIo, readByWorkflows: ['STRIPE_SECRET_KEY'] });
  await keys.placeholders(['STRIPE_SECRET_KEY']);
  const e = await keys.evidence(await keys.ticket(), [EVIDENCE_RUN]);   // the fake answers: completed, attempt EVIDENCE_ATTEMPT
  if (e === null) throw new Error(`no evidence: ${keys.lastRefusal ?? '?'}`);
  return e;
}
