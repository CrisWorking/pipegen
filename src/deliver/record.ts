// v0.2 Plan G G10 (rulings S13, S14; Plan V pre-flight §5 items 1-2, binding): the install record, in one module. It is the only code that
// serializes, hashes, reads or writes a record; deliver (G10), finish and verify (G11), update (G12) and uninstall (Plan V) all use it.
//
// - InstallRecordSchema: strict (no unknown key anywhere), every list and text capped, names, paths and shas validated, `schema: 2` only.
//   parseRecord refuses an unknown version with a plain reason (a newer pipegen wrote it) and anything over MAX_RECORD_BYTES.
// - canonicalRecordJson: keys sorted at every level, no whitespace; recordHash is the sha256 of it. The file in the central repo is the same
//   data pretty-printed, so a reader re-canonicalizes before it compares a hash.
// - recordPath: installs/<centralProjectName(app repo)>.json in the private central repo `<owner>/pipelines`.
// - writeRecord updates all three places in one call: the record (a commit on the central default branch while it takes one, else the
//   central pull request pipegen/update-<name>), the setup pull request body's last line `<!-- pipegen:record-sha256=<hex> -->`, and the
//   local file ~/.config/pipegen/records/<owner>__<repo>.json (0600, outside the proof state folder, which each run rewrites).
// - A matching hash is not proof (the PR body is editable by app writers, the local file may be gone): uninstall checks GitHub's created_at
//   and ids whatever the hash says. The hash tells `verify` that something changed.
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, constants, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeSync, lstatSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { z } from 'zod';
import type { GuardInstallRecord } from '../create/guard.js';
import { centralProjectName } from '../engine/central-path.js';
import type { RateClock } from '../engine/github-rate.js';
import { createdPathProblem } from '../engine/job-rules.js';
import { clockOf } from '../github/client.js';
import { CENTRAL_REPO } from '../proof/target.js';
import type { InstallRecord } from '../types.js';
import { prepareTrustedDir, type TrustedDirKind } from '../util/trusted-dir.js';
import { safeText } from '../util/safe-text.js';
import { commitFiles, DeliverError, ghRead, ghWrite, openOrUpdatePr, readBlobText, readHead, readRepo, readTree, setBranch, statusOf, type RepoRef } from './git-data.js';

export const RECORD_SCHEMA = 2;
/** The largest record pipegen writes or reads (Plan V §4.2). */
export const MAX_RECORD_BYTES = 1024 * 1024;

/** A record pipegen won't read or write: a plain reason. */
export class RecordError extends Error {
  constructor(message: string, options?: { cause?: unknown }) { super(message, options); this.name = 'RecordError'; }
}

// ---------- the schema ----------

const SHA = z.string().regex(/^[0-9a-f]{40}$/);
const SHA256 = z.string().regex(/^[0-9a-f]{64}$/);
const ISO = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/);
const DAY = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const TEXT = z.string().max(500);
const PATH = z.string().max(400).refine((p) => createdPathProblem(p) === null, 'not a plain repository path');
const SECRET_NAME = z.string().regex(/^[A-Z_][A-Z0-9_]{0,127}$/);
const ENV_NAME = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/).refine((n) => n !== '.' && n !== '..' && !n.includes('..'));
const SCOPE_ENV = z.string().regex(/^env:[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/).refine((s) => !s.includes('..')) as unknown as z.ZodType<`env:${string}`>;
const LOGIN = z.string().regex(/^@[A-Za-z0-9](?:[A-Za-z0-9_-]{0,38})$/);
const OWNER = z.string().regex(/^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,38})$/);
const REPO = z.string().regex(/^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/);
const BRANCH = z.string().max(250).regex(/^[A-Za-z0-9._/-]+$/);
const ID = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const PART = z.enum(['pipeline', 'precommit', 'docker', 'compose', 'tests', 'test-migration', 'codeowners', 'deploy-verify', 'docs']);
const REPO_KIND = z.enum(['app', 'central']);
const SHAS = z.array(SHA).max(200);
const JSONISH: z.ZodType<unknown> = z.lazy(() => z.union([z.string().max(10_000), z.number(), z.boolean(), z.null(), z.array(JSONISH).max(200), z.record(z.string().max(200), JSONISH)]));
const API = z.strictObject({
  method: z.enum(['POST', 'PUT']),
  route: z.string().regex(/^\/(?:repos\/\{owner\}\/\{repo\}|orgs\/\{org\})(?:\/[a-z_{}-]+)*$/),
  params: z.record(z.string().regex(/^[a-z_]{1,40}$/), z.string().max(200)),
  body: z.record(z.string().max(200), JSONISH),
});
const ENV_SETTINGS = z.strictObject({
  wait_timer: z.number().int().min(0).max(43_200), prevent_self_review: z.boolean(),
  reviewers: z.array(z.strictObject({ type: z.enum(['User', 'Team']), id: ID })).max(6),
  can_admins_bypass: z.boolean(),
  deployment_branch_policy: z.strictObject({ protected_branches: z.boolean(), custom_branch_policies: z.boolean() }).nullable(),
  branch_policies: z.array(z.strictObject({ name: z.string().max(255), type: z.enum(['branch', 'tag']) })).max(200),
});
const ENV_KEYS = ['wait_timer', 'prevent_self_review', 'reviewers', 'can_admins_bypass', 'deployment_branch_policy', 'branch_policies'] as const;
const EDIT_BASE = { path: PATH, originalSha: SHA, writtenShas: SHAS };
const EDIT = z.discriminatedUnion('kind', [
  z.strictObject({ repo: REPO_KIND, path: PATH, kind: z.enum(['codeowners', 'hooks', 'dependabot']), inserted: z.string().max(256 * 1024), originalSha: SHA.nullable(), writtenShas: SHAS }),
  z.strictObject({ repo: z.literal('app'), ...EDIT_BASE, kind: z.literal('verify-job'), jobs: z.array(z.string().max(100)).min(1).max(50), needs: z.array(z.strictObject({ job: z.string().max(100), added: z.array(z.string().max(100)).max(50) })).max(200) }),
  z.strictObject({ repo: z.literal('app'), ...EDIT_BASE, kind: z.literal('package-json'), add: z.record(z.string().max(214), z.string().max(100)), setTest: z.boolean(), previousTest: z.string().max(10_000).optional(), lock: PATH.optional() }),
  z.strictObject({ repo: z.literal('app'), ...EDIT_BASE, kind: z.literal('package-lock'), json: PATH }),
]);

/** The install record (schema 2): strict, capped, validated. Anything else is refused, never read loosely. */
export const InstallRecordSchema = z.strictObject({
  schema: z.literal(RECORD_SCHEMA),
  pipegenVersion: z.string().regex(/^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.-]{1,40})?$/),
  createdAt: ISO, mergedAt: ISO.optional(),
  centralSha: SHA.nullable(),
  app: z.strictObject({ owner: OWNER, repo: REPO, repoId: ID, defaultBranch: BRANCH, private: z.boolean(), ownerType: z.enum(['User', 'Organization']) }),
  name: z.string().regex(/^[a-z0-9_][a-z0-9._-]{0,99}$/),
  serviceRoots: z.array(z.string().max(400)).max(200),
  files: z.array(z.strictObject({ repo: REPO_KIND, path: PATH, part: PART, shas: SHAS.min(1), aiEdited: z.literal(true).optional() })).max(5000),
  edits: z.array(EDIT).max(500),
  secrets: z.array(z.strictObject({ name: SECRET_NAME, scope: z.union([z.literal('repo'), z.literal('central'), SCOPE_ENV]), created: z.boolean(), overwritten: z.literal(true).optional(), githubCreatedAt: ISO.optional(), unconfirmed: z.literal(true).optional() })).max(500),
  variables: z.array(z.strictObject({ name: SECRET_NAME, scope: z.union([z.literal('repo'), SCOPE_ENV]), created: z.boolean(), previous: z.string().max(10_000).optional(), githubCreatedAt: ISO.optional(), unconfirmed: z.literal(true).optional() })).max(200),
  environments: z.array(z.strictObject({ name: ENV_NAME, created: z.boolean(), githubCreatedAt: ISO.optional(), previous: ENV_SETTINGS.optional(), changed: z.array(z.enum(ENV_KEYS)).max(6), branchPolicyIds: z.array(ID).max(200), unconfirmed: z.literal(true).optional() })).max(100),
  rulesets: z.array(z.strictObject({ kind: z.enum(['gate', 'reviews']), id: ID, name: z.enum(['pipegen', 'pipegen-reviews']), githubCreatedAt: ISO })).max(2),
  classicProtection: z.strictObject({ branch: BRANCH, previous: z.record(z.string().max(200), JSONISH).nullable() }).optional(),
  orgRuleset: z.strictObject({ org: OWNER, id: ID, name: z.string().max(200), githubCreatedAt: ISO }).optional(),
  repoSettings: z.strictObject({
    shaPinningRequired: z.strictObject({ previous: z.boolean() }).optional(), vulnerabilityAlerts: z.strictObject({ previous: z.boolean() }).optional(),
    secretScanning: z.strictObject({ previous: z.boolean() }).optional(), pushProtection: z.strictObject({ previous: z.boolean() }).optional(),
  }).optional(),
  central: z.strictObject({ repoId: ID.optional(), createdByPipegen: z.boolean(), rulesetId: ID.optional(), rulesetCreatedAt: ISO.optional(), codeowners: z.strictObject({ path: PATH, created: z.boolean() }).optional(), actionsAccess: z.strictObject({ previous: z.string().max(40) }).optional() }).optional(),
  scratch: z.strictObject({ repoId: ID.optional(), createdByPipegen: z.boolean() }).optional(),
  planned: z.strictObject({
    rulesets: z.strictObject({ gate: API, reviews: API.optional() }).optional(),
    classic: API.optional(), centralRuleset: API.optional(),
    orgRequiredWorkflow: z.strictObject({ path: PATH, rule: API }).optional(),
    shaPinning: z.strictObject({ request: API, previous: z.boolean() }).optional(),
    signingMode: z.enum(['key-env', 'keyless', 'attest', 'none']),
    environments: z.array(z.strictObject({ name: ENV_NAME, reviewers: z.boolean() })).max(100),
    owners: z.strictObject({ app: z.array(LOGIN).max(50), central: z.array(LOGIN).max(50) }),
    codeOwners: z.array(LOGIN).max(50),
  }),
  protectedPaths: z.array(z.string().max(400)).max(2000),
  cosignPubSha256: SHA256.optional(), blockFrom: DAY.optional(),
}) satisfies z.ZodType<InstallRecord>;

/** A record from its text: size cap, strict JSON, the version first (an unknown one is explained), then the schema. */
export function parseRecord(text: string): InstallRecord {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > MAX_RECORD_BYTES) throw new RecordError(`The install record is larger than pipegen's limit (${MAX_RECORD_BYTES} bytes), so pipegen won't read it.`);
  let data: unknown;
  try { data = JSON.parse(text); } catch (e) { throw new RecordError('The install record is not valid JSON, so pipegen won\'t read it.', { cause: e }); }
  return checkRecord(data);
}

/** A record object checked against the schema (the version first). */
export function checkRecord(data: unknown): InstallRecord {
  const version = typeof data === 'object' && data !== null ? (data as { schema?: unknown }).schema : undefined;
  if (version !== RECORD_SCHEMA) {
    throw new RecordError(typeof version === 'number' && version > RECORD_SCHEMA
      ? `The install record has version ${version}, which a newer pipegen wrote. Update pipegen (npx pipegen@latest), then run it again.`
      : `The install record has no version pipegen knows (it reads version ${RECORD_SCHEMA}), so pipegen won't read it. Run the setup again to write a new one.`);
  }
  const r = InstallRecordSchema.safeParse(data);
  if (!r.success) {
    const at = r.error.issues.slice(0, 3).map((i) => safeText(i.path.join('.') || '(top)', 80)).join(', ');
    throw new RecordError(`The install record doesn't have the form pipegen writes (at ${at}), so pipegen won't read it.`);
  }
  return r.data as InstallRecord;
}

// ---------- serializing and hashing ----------

function sorted(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sorted);
  if (v !== null && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) { const x = (v as Record<string, unknown>)[k]; if (x !== undefined) out[k] = sorted(x); }
    return out;
  }
  if (typeof v === 'number' && !Number.isFinite(v)) throw new RecordError('The install record holds a number that is not finite.');
  return v;
}

/** The one serializer the hash is taken over: keys sorted at every level, no whitespace, undefined fields left out. */
export function canonicalRecordJson(r: InstallRecord): string {
  return JSON.stringify(sorted(r));
}
/** sha256 (hex) of the canonical JSON. */
export function recordHash(r: InstallRecord): string {
  return createHash('sha256').update(canonicalRecordJson(r), 'utf8').digest('hex');
}
/** The file text in the central repo: the same data, keys sorted, pretty-printed. */
export function recordFileText(r: InstallRecord): string {
  return `${JSON.stringify(sorted(r), null, 2)}\n`;
}

/** installs/<centralProjectName(app repo)>.json in the central repo. */
export function recordPath(appRepo: string): string {
  return `installs/${centralProjectName(appRepo)}.json`;
}

/** The central pull request branch of a project (central files and the record once the central default branch takes no direct commit). */
export const centralUpdateBranch = (appRepo: string): string => `pipegen/update-${centralProjectName(appRepo)}`;

// ---------- the PR-body marker ----------

const MARKER_LINE_RE = /^<!-- pipegen:record-sha256=([0-9a-f]{64}) -->$/;
export function recordMarker(hash: string): string {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new RecordError('A record hash is not 64 hex characters.');
  return `<!-- pipegen:record-sha256=${hash} -->`;
}
/** The body with every earlier marker line removed and the marker as its last line. */
export function withRecordMarker(body: string, hash: string): string {
  const kept = String(body ?? '').split('\n').filter((l) => !MARKER_LINE_RE.test(l.trim())).join('\n').replace(/\s+$/, '');
  return `${kept === '' ? '' : `${kept}\n\n`}${recordMarker(hash)}`;
}
/** The hash on the body's last line, or null (no marker there). */
export function recordMarkerOf(body: string | null | undefined): string | null {
  if (typeof body !== 'string') return null;
  const last = body.replace(/\s+$/, '').split('\n').at(-1) ?? '';
  return MARKER_LINE_RE.exec(last.trim())?.[1] ?? null;
}

// ---------- the guard's view ----------

/** The app files pipegen wrote whole, each with the sha it wrote last (the guard's "pipegen's own earlier file"). */
export function guardRecordOf(r: InstallRecord): GuardInstallRecord {
  return { files: r.files.filter((f) => f.repo === 'app').map((f) => ({ path: f.path, part: f.part, sha: f.shas.at(-1) as string, created: true })) };
}

// ---------- the local record file ----------

export interface LocalRecord { recordHash: string; setupPr: number; updatedAt: string }
export interface LocalRecordDeps { home?: string; env?: NodeJS.ProcessEnv; uid?: number }
const LOCAL = z.strictObject({ recordHash: SHA256, setupPr: ID, updatedAt: z.string().max(40) });
const KIND: TrustedDirKind = {
  noun: 'record', keeping: 'its install records', risk: 'change what `pipegen verify` compares against',
  error: (message, cause) => new RecordError(message, cause === undefined ? undefined : { cause }),
};
const localName = (app: RepoRef): string => {
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,38})$/.test(String(app?.owner)) || !/^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/.test(String(app?.repo))) throw new RecordError('The repo name is not one pipegen keeps a record file for.');
  return `${app.owner}__${app.repo}`.toLowerCase();
};
const configBase = (deps: LocalRecordDeps): string => {
  const xdg = (deps.env ?? process.env).XDG_CONFIG_HOME;
  return xdg !== undefined && isAbsolute(xdg) ? xdg : join(deps.home ?? homedir(), '.config');
};
async function recordsDir(deps: LocalRecordDeps): Promise<string> {
  const uid = deps.uid ?? process.getuid?.();
  if (uid === undefined) throw new RecordError('pipegen could not tell which user it runs as, so it keeps no local record file.');
  return prepareTrustedDir(configBase(deps), ['pipegen', 'records'], false, uid, KIND);
}

/** Writes the local record file (0600: a fresh exclusive temp file, never through a link, fsynced, renamed). */
export async function writeLocalRecord(app: RepoRef, v: LocalRecord, deps: LocalRecordDeps = {}): Promise<string> {
  const value = LOCAL.parse(v);
  const dir = await recordsDir(deps);
  const file = join(dir, `${localName(app)}.json`);
  const tmp = join(dir, `.${localName(app)}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
  let fd: number | null = null;
  try {
    fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const buf = Buffer.from(`${JSON.stringify(value, null, 1)}\n`, 'utf8');
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(tmp, file);
  } catch (e) {
    if (fd !== null) try { closeSync(fd); } catch { /* closed */ }
    try { unlinkSync(tmp); } catch { /* gone */ }
    throw new RecordError(`pipegen couldn't save its local record file in ${dir}.`, { cause: e });
  }
  return file;
}

/** The local record file, or null when there is none. A file that is a link, too large or not in pipegen's form is an error. */
export async function readLocalRecord(app: RepoRef, deps: LocalRecordDeps = {}): Promise<LocalRecord | null> {
  const dir = await recordsDir(deps);
  const file = join(dir, `${localName(app)}.json`);
  let info;
  try { info = lstatSync(file); } catch (e) { if ((e as { code?: unknown }).code === 'ENOENT') return null; throw new RecordError(`pipegen couldn't check ${file}.`, { cause: e }); }
  if (!info.isFile() || info.size > 4096) throw new RecordError(`${file} is not pipegen's local record file.`);
  const r = LOCAL.safeParse((() => { try { return JSON.parse(readFileSync(file, 'utf8')); } catch { return null; } })());
  if (!r.success) throw new RecordError(`${file} is not pipegen's local record file.`);
  return r.data;
}

// ---------- reading and writing the record on GitHub ----------

/** The central repo of an app: `<owner>/pipelines`. */
export const centralOf = (app: RepoRef): RepoRef => ({ owner: app.owner, repo: CENTRAL_REPO });

export interface ReadRecordResult { record: InstallRecord; hash: string; blobSha: string; commit: string }
/**
 * The record of `appRepo` in the central repo at `branch` (default: its default branch), read through the git data API, checked
 * (size, version, schema). null when the branch or the file is not there; a link or a submodule at the path is an error.
 */
export async function readRecord(gh: Octokit, central: RepoRef, appRepo: string, opts: { branch?: string; clock?: RateClock } = {}): Promise<ReadRecordResult | null> {
  const clock = opts.clock ?? clockOf(gh);
  let branch = opts.branch;
  if (branch === undefined) {
    const repo = await readRepo(gh, central, clock);
    if (repo === null) return null;
    branch = repo.defaultBranch;
  }
  const head = await readHead(gh, central, branch, clock);
  if (head === null) return null;
  const { entries } = await readTree(gh, central, head, clock);
  const e = entries.get(recordPath(appRepo));
  if (e === undefined) return null;
  if (e.type !== 'blob' || e.mode !== '100644') throw new RecordError(`${recordPath(appRepo)} in ${safeText(`${central.owner}/${central.repo}`, 120)} is not a plain file, so pipegen won't read it.`);
  const record = parseRecord(await readBlobText(gh, central, e.sha, MAX_RECORD_BYTES, clock));
  return { record, hash: recordHash(record), blobSha: e.sha, commit: head };
}

export interface WriteRecordArgs {
  record: InstallRecord;
  /** The app's setup pull request: its body's last line gets the record hash. */
  setupPr: number;
  /** `direct`: a commit on the central default branch (only while it takes one); `pr`: the central pull request pipegen/update-<name>. */
  via: 'direct' | 'pr';
  /** Other central files of this project that go in the same commit (the required workflow, the central CODEOWNERS). */
  files?: readonly { path: string; content: string }[];
  clock?: RateClock; now?: () => Date; local?: LocalRecordDeps;
}
export interface WriteRecordResult { recordHash: string; commit: string; via: 'direct' | 'pr'; centralPr?: { number: number; url: string } }

/**
 * Writes the record to all three places in one call: the central repo (a direct commit, or the central pull request; a direct commit the
 * branch refuses goes through the pull request instead), the setup PR body's marker line, and the local record file. The record is checked
 * against the schema before anything is sent.
 */
export async function writeRecord(gh: Octokit, args: WriteRecordArgs): Promise<WriteRecordResult> {
  const clock = args.clock ?? clockOf(gh);
  const record = checkRecord(JSON.parse(canonicalRecordJson(args.record)));
  const text = recordFileText(record);
  if (Buffer.byteLength(text, 'utf8') > MAX_RECORD_BYTES) throw new RecordError(`The install record is larger than pipegen's limit (${MAX_RECORD_BYTES} bytes).`);
  const hash = recordHash(record);
  const app: RepoRef = { owner: record.app.owner, repo: record.app.repo };
  const central = centralOf(app);
  const extra = args.files ?? [];
  for (const f of extra) if (createdPathProblem(f.path) !== null || f.path === recordPath(app.repo) || !f.path.startsWith('.github/') && !/^(?:docs\/)?CODEOWNERS$/.test(f.path)) throw new RecordError(`${safeText(f.path, 120)} is not a central file pipegen writes with the record.`);

  const repo = await readRepo(gh, central, clock);
  if (repo === null) throw new DeliverError(`pipegen can't see ${safeText(`${central.owner}/${central.repo}`, 120)}, where the install record goes.`);
  if (!repo.private) throw new DeliverError(`${safeText(`${central.owner}/${central.repo}`, 120)} is public; pipegen keeps install records only in a private repo.`);
  const base = await readHead(gh, central, repo.defaultBranch, clock);
  if (base === null) throw new DeliverError(`${safeText(`${central.owner}/${central.repo}`, 120)} has no default branch to write the install record on.`);
  const { tree } = await readTree(gh, central, base, clock);
  const files = [...extra.map((f) => ({ path: f.path, content: f.content, mode: '100644' })), { path: recordPath(app.repo), content: text, mode: '100644' }];
  const message = `pipegen: install record for ${record.app.repo}`;
  const { commit } = await commitFiles(gh, central, { parent: base, baseTree: tree, files, message }, clock);

  let via = args.via;
  let centralPr: { number: number; url: string } | undefined;
  if (via === 'direct') {
    try { await ghWrite(gh, 'PATCH /repos/{owner}/{repo}/git/refs/{ref}', central, { ref: `heads/${repo.defaultBranch}`, sha: commit, force: false }, clock); } catch (e) {
      const s = statusOf(e);
      if (s !== 422 && s !== 409 && s !== 403) throw e;
      via = 'pr';   // the branch takes no direct commit (its rules): the record goes through the central pull request
    }
  }
  if (via === 'pr') {
    const branch = centralUpdateBranch(app.repo);
    await setBranch(gh, central, branch, commit, true, clock);
    const pr = await openOrUpdatePr(gh, central, { head: branch, base: repo.defaultBranch, title: `pipegen: install record for ${record.app.repo}`, body: `pipegen's install record for ${safeText(`${app.owner}/${app.repo}`, 140)} (what it wrote, and what \`pipegen finish\` applies after the setup pull request is merged).\n\nMerge this pull request so \`pipegen finish\`, \`verify\` and uninstall can read it.\n\n${recordMarker(hash)}` }, clock);
    centralPr = { number: pr.number, url: pr.url };
  }

  // the setup pull request's body: every earlier marker removed, the new one on the last line
  const pr = await ghRead(gh, 'GET /repos/{owner}/{repo}/pulls/{pull_number}', app, { pull_number: args.setupPr }, clock) as { body?: unknown } | null;
  const body = typeof pr?.body === 'string' ? pr.body : '';
  await ghWrite(gh, 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}', app, { pull_number: args.setupPr, body: withRecordMarker(body, hash) }, clock);

  await writeLocalRecord(app, { recordHash: hash, setupPr: args.setupPr, updatedAt: (args.now?.() ?? new Date()).toISOString() }, args.local ?? {});
  return { recordHash: hash, commit, via, ...(centralPr === undefined ? {} : { centralPr }) };
}

