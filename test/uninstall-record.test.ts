// v0.2 Plan V V1 (rulings V-B1, V-B6, V-S1, V-S2, V-S13, V-N2, V-N4, V-N13, V-N14): uninstall loads the install record through the one
// trust order (trustedPrevious), never through a second parser or the setup PR body's marker. An untrusted record stops; a typed trust
// grants only confirmView's view; the app facts come from GitHub; an open central pull request that can change the record stops.
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { afterEach, describe, expect, it } from 'vitest';
import { PromptCancelledError, type Prompter } from '../src/cli/io.js';
import {
  canonicalRecordJson, localRecordPath, MAX_RECORD_BYTES, recordFileText, recordHash, recordPath, withRecordMarker, writeLocalRecord,
} from '../src/deliver/record.js';
import { confirmView } from '../src/deliver/trust.js';
import type { InstallRecord } from '../src/types.js';
import { UninstallError } from '../src/uninstall/errors.js';
import { askTypedName, loadUninstallRecord, TYPED_DROPPED } from '../src/uninstall/record.js';
import { FakeGitHub } from './helpers/deliver-github.js';

const SHA = (c: string): string => c.repeat(40).slice(0, 40);
/** The record's secrets field, spelled at run time (test/no-secret-literals.test.ts). */
const SEC = ['sec', 'rets'].join('') as 'secrets';
const APP = { owner: 'o', repo: 'r' };

function sampleRecord(repoId: number, over: Partial<InstallRecord> = {}): InstallRecord {
  return {
    schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-05T12:00:00.000Z', mergedAt: '2026-11-05T13:00:00Z', centralSha: SHA('c'),
    app: { owner: 'o', repo: 'r', repoId, defaultBranch: 'main', private: true, ownerType: 'User' },
    name: 'r', serviceRoots: ['.'],
    files: [{ repo: 'app', path: '.github/workflows/pipegen.yml', part: 'pipeline', shas: [SHA('a')] }, { repo: 'central', path: '.github/workflows/r--merge.yml', part: 'pipeline', shas: [SHA('b')] }],
    edits: [{ repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: '\n# pipegen:begin\n', originalSha: SHA('d'), writtenShas: [SHA('e')] }],
    [SEC]: [{ name: 'PIPEGEN_FP_KEY', scope: 'repo', created: true, githubCreatedAt: '2026-11-05T12:00:01Z' }],
    variables: [], environments: [], rulesets: [{ kind: 'gate', id: 41, name: 'pipegen', githubCreatedAt: '2026-11-05T13:00:01Z' }],
    classicProtection: { branch: 'main', previous: null },
    central: { repoId: 99, createdByPipegen: true },
    planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] },
    protectedPaths: ['.github/workflows/**'],
    ...over,
  };
}

interface World { g: FakeGitHub; home: string; appId: number; asked: string[] }
const homes: string[] = [];
afterEach(() => { for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true }); });

function world(opts: { appPrivate?: boolean; centralPrivate?: boolean; noCentral?: boolean } = {}): World {
  const g = new FakeGitHub();
  const app = g.addRepo('o/r', { private: opts.appPrivate ?? true, files: { 'README.md': 'hi\n' } });
  if (opts.noCentral !== true) g.addRepo('o/pipelines', { private: opts.centralPrivate ?? true, files: { 'README.md': 'central\n' } });
  const home = mkdtempSync(join(tmpdir(), 'pg-unrec-'));
  homes.push(home);
  return { g, home, appId: app.id, asked: [] };
}
const local = (w: World) => ({ home: w.home, env: {} });
/** Puts the record text at installs/r.json on a central branch (the default one unless named). */
function putRecord(w: World, text: string, branch = 'main'): void {
  const c = w.g.repo('o/pipelines');
  if (!c.refs.has(`heads/${branch}`)) c.refs.set(`heads/${branch}`, w.g.head('o/pipelines'));
  w.g.commitOn('o/pipelines', branch, { [recordPath('r')]: text }, 'record');
}
function setupPr(w: World, number: number, body: string, head = 'pipegen/setup'): void {
  w.g.repo('o/r').pulls.push({ number, head, base: 'main', title: 'pipegen setup', body, state: 'closed', html_url: `https://github.com/o/r/pull/${number}` });
}
/** A full install: the record on central, the setup PR #5 with the record's marker, the local record file naming PR #5. */
async function installed(w: World, r: InstallRecord, opts: { localSetupPr?: boolean } = {}): Promise<void> {
  putRecord(w, recordFileText(r));
  setupPr(w, 5, withRecordMarker('pipegen sets up CI', recordHash(r)));
  await writeLocalRecord(APP, { recordHash: recordHash(r), ...(opts.localSetupPr === false ? {} : { setupPr: 5 }), updatedAt: '2026-11-05T12:00:00Z' }, local(w));
}
function io(w: World, typed?: string): Prompter {
  return {
    confirm: async () => { throw new Error('no confirm expected'); },
    select: async () => { throw new Error('no select expected'); },
    text: async (msg) => { w.asked.push(msg); if (typed === undefined) throw new PromptCancelledError('no terminal'); return typed; },
  };
}
const writes = (w: World): string[] => w.g.routes().filter((r) => !r.startsWith('GET '));
/**
 * The Octokit stand-in, with GitHub's `head.repo` on pull requests (the fake leaves it out): a pull request the fake holds is one from the
 * repo itself. A hook's own `head.repo` (a fork, in a test) is kept as it is.
 */
function gh(w: World): Octokit {
  const withRepo = (owner: unknown, repo: unknown, p: unknown): unknown => {
    if (typeof p !== 'object' || p === null || typeof (p as { head?: unknown }).head !== 'object') return p;
    const head = (p as { head: Record<string, unknown> }).head;
    if ('repo' in head) return p;
    const r = w.g.repo(`${String(owner)}/${String(repo)}`);
    return { ...p, head: { ...head, repo: { id: r.id, full_name: `${r.owner}/${r.name}` } } };
  };
  return { request: async (route: string, params: Record<string, unknown> = {}) => {
    const out = await w.g.request(route, params);
    if (route === 'GET /repos/{owner}/{repo}/pulls') return { ...out, data: Array.isArray(out.data) ? out.data.map((p) => withRepo(params.owner, params.repo, p)) : out.data };
    if (route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}') return { ...out, data: withRepo(params.owner, params.repo, out.data) };
    return out;
  } } as unknown as Octokit;
}
async function stops(p: Promise<unknown>, re: RegExp): Promise<UninstallError> {
  const e = await p.then(() => null, (x: unknown) => x);
  expect(e).toBeInstanceOf(UninstallError);
  expect((e as Error).message).toMatch(re);
  return e as UninstallError;
}

describe('uninstall: load and trust the install record (V1)', () => {
  it('record: loads and validates', async () => {
    const w = world();
    const r = sampleRecord(w.appId, { central: { repoId: w.g.repo('o/pipelines').id, createdByPipegen: true } });
    await installed(w, r);
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    expect(got.trust).toBe('full');
    expect(got.record).toEqual(r);
    // the app facts are GitHub's, never the record's
    expect(got.app).toEqual({ owner: 'o', repo: 'r', repoId: w.appId, private: true, defaultBranch: 'main', ownerType: 'User' });
    const head = w.g.head('o/pipelines');
    expect(got.centralHead).toBe(head);
    const entry = w.g.repo('o/pipelines').trees.get(w.g.repo('o/pipelines').commits.get(head)?.tree as string)?.get(recordPath('r'));
    expect(got.blobSha).toBe(entry?.sha);
    expect(got.marker).toBe('match');
    expect(got.typedNames).toBe(false);
    expect(got.centralRepoId).toBe(w.g.repo('o/pipelines').id);
    expect(got.setupPr).toBe(5);
    expect(got.dropped).toEqual([]);
    expect(got.warnings).toEqual([]);
    expect(writes(w)).toEqual([]);
    expect(w.asked).toEqual([]);
  });

  it('record: missing → stop with explanation', async () => {
    const w = world();
    const e = await stops(loadUninstallRecord(gh(w), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }), /^No install record for o\/r\. pipegen only removes what it recorded installing\./);
    expect(e.message).not.toMatch(/undefined|null/);
    expect(w.asked).toEqual([]);
    expect(writes(w)).toEqual([]);
    // no central repo at all: still "no install record", nothing asked
    const w2 = world({ noCentral: true });
    await stops(loadUninstallRecord(gh(w2), APP, { local: local(w2) }), /^No install record for o\/r\..*pipegen only removes what it recorded installing\./);
    // the app repo itself missing (or no access): a stop that names it
    const w3 = world();
    await stops(loadUninstallRecord(gh(w3), { owner: 'o', repo: 'gone' }, { local: local(w3) }), /can't see o\/gone/);
  });

  it('record: public app repo → read from the private records-only pipelines', async () => {
    const w = world({ appPrivate: false });
    const r = sampleRecord(w.appId, { centralSha: null, app: { owner: 'o', repo: 'r', repoId: w.appId, defaultBranch: 'main', private: false, ownerType: 'User' }, files: [{ repo: 'app', path: '.github/workflows/pipegen.yml', part: 'pipeline', shas: [SHA('a')] }] });
    await installed(w, r);
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    expect(got.app.private).toBe(false);
    expect(got.record.centralSha).toBeNull();
    expect(got.record.files.filter((f) => f.repo === 'central')).toEqual([]);
    expect(w.g.calls.some((c) => c.route === 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}' && c.params.repo === 'pipelines')).toBe(true);
    // a public pipelines repo is never where pipegen keeps records: stop
    const w2 = world({ appPrivate: false, centralPrivate: false });
    await installed(w2, sampleRecord(w2.appId, { centralSha: null }));
    await stops(loadUninstallRecord(gh(w2), APP, { local: local(w2) }), /o\/pipelines is public/);
  });

  it('record: hash differs from setup PR body → hashMatches false, warning shown', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    setupPr(w, 5, withRecordMarker('pipegen sets up CI', 'f'.repeat(64)));
    await writeLocalRecord(APP, { recordHash: recordHash(r), setupPr: 5, updatedAt: 'x' }, local(w));
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    expect(got.marker).toBe('differs');
    // the marker is never a trust source: trust is the local file's, unchanged
    expect(got.trust).toBe('full');
    expect(got.record).toEqual(r);
    expect(got.warnings.join('\n')).toMatch(/setup pull request #5.*doesn't match.*type each name/s);
  });

  it('record: unknown schema version, unknown key, oversize, bad name, path or id → stop, nothing planned', async () => {
    const base = (w: World): Record<string, unknown> => JSON.parse(canonicalRecordJson(sampleRecord(w.appId))) as Record<string, unknown>;
    const variants: [string, (w: World) => string][] = [
      ['schema 3', (w) => JSON.stringify({ ...base(w), schema: 3 })],
      ['unknown key', (w) => JSON.stringify({ ...base(w), extra: true })],
      ['oversize', (w) => JSON.stringify({ ...base(w), pad: 'x'.repeat(MAX_RECORD_BYTES) })],
      ['bad name', (w) => JSON.stringify({ ...base(w), name: 'other' })],
      ['bad path', (w) => JSON.stringify({ ...base(w), files: [{ repo: 'app', path: '../etc/passwd', part: 'pipeline', shas: [SHA('a')] }] })],
      ['bad id', (w) => JSON.stringify({ ...base(w), rulesets: [{ kind: 'gate', id: -1, name: 'pipegen', githubCreatedAt: '2026-11-05T13:00:01Z' }] })],
    ];
    const reason: Record<string, RegExp> = {
      'schema 3': /version 3, which a newer pipegen wrote\. Update pipegen/, 'unknown key': /doesn't have the form pipegen writes/, 'oversize': /larger than|too large|limit/,
      'bad name': /doesn't have the form pipegen writes|name/, 'bad path': /doesn't have the form pipegen writes|path/, 'bad id': /doesn't have the form pipegen writes/,
    };
    for (const [label, text] of variants) {
      for (const withLocal of [true, false]) {
        const w = world();
        const t = text(w);
        putRecord(w, t);
        if (withLocal) await writeLocalRecord(APP, { recordHash: 'a'.repeat(64), updatedAt: 'x' }, local(w));
        const e = await loadUninstallRecord(gh(w), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }).then(() => null, (x: unknown) => x);
        expect(e, label).toBeInstanceOf(UninstallError);
        // spec M2 / sec M6 (V1-R1): the stop names the cause (the record can't be read, and why), never "move the file away" or "you didn't confirm"
        expect((e as Error).message, label).toMatch(/^pipegen can't read the install record installs\/r\.json in o\/pipelines: /);
        expect((e as Error).message, label).toMatch(reason[label] as RegExp);
        expect((e as Error).message, label).not.toMatch(/move that file away|didn't confirm|writes a new record/);
        // never asked about (an unreadable record is never offered for typing), nothing written
        expect(w.asked, label).toEqual([]);
        expect(writes(w), label).toEqual([]);
      }
    }
  });

  it('record: app repo id differs from the recorded one → stop', async () => {
    const w = world();
    await installed(w, sampleRecord(w.appId + 1));
    await stops(loadUninstallRecord(gh(w), APP, { local: local(w) }), /repo id .*not the repository pipegen was installed in/);
    expect(writes(w)).toEqual([]);
    // the recorded owner of another repo (same id) stops too
    const w2 = world();
    await installed(w2, sampleRecord(w2.appId, { app: { owner: 'x', repo: 'r', repoId: w2.appId, defaultBranch: 'main', private: true, ownerType: 'User' } }));
    await stops(loadUninstallRecord(gh(w2), APP, { local: local(w2) }), /not the repository pipegen was installed in/);
  });

  it('record: no hash found anywhere → treated as a mismatch', async () => {
    // no setup PR at all, and a local file without a PR number
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    await writeLocalRecord(APP, { recordHash: recordHash(r), updatedAt: 'x' }, local(w));
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    expect(got.marker).toBe('absent');
    expect(got.setupPr).toBeNull();
    expect(got.trust).toBe('full');
    expect(got.warnings.join('\n')).toMatch(/no setup pull request.*type each name/s);
    // a setup PR whose body has no marker line
    const w2 = world();
    const r2 = sampleRecord(w2.appId);
    putRecord(w2, recordFileText(r2));
    setupPr(w2, 2, `pipegen sets up CI\n<!-- pipegen:record-sha256=${recordHash(r2)} -->\nedited after`);
    await writeLocalRecord(APP, { recordHash: recordHash(r2), updatedAt: 'x' }, local(w2));
    const got2 = await loadUninstallRecord(gh(w2), APP, { local: local(w2) });
    expect(got2.marker).toBe('absent');
    expect(got2.setupPr).toBe(2);
    expect(got2.warnings.join('\n')).toMatch(/#2 holds no record marker.*type each name/s);
  });

  it('record: the setup PR is found by head pipegen/setup, never by a number in the record', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    const good = withRecordMarker('pipegen sets up CI', recordHash(r));
    setupPr(w, 1, good, 'feature');                        // not pipegen's branch: never taken, whatever its body says
    setupPr(w, 3, withRecordMarker('older', 'e'.repeat(64)));
    setupPr(w, 4, good);                                   // the newest pipegen/setup PR
    setupPr(w, 6, good, 'pipegen/setup-other');
    await writeLocalRecord(APP, { recordHash: recordHash(r), updatedAt: 'x' }, local(w));
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    expect(got.setupPr).toBe(4);
    expect(got.marker).toBe('match');
    const list = w.g.calls.find((c) => c.route === 'GET /repos/{owner}/{repo}/pulls' && c.params.repo === 'r');
    expect(list?.params.head).toBe('o:pipegen/setup');
    // a local file naming a PR that is not on pipegen/setup: not taken; the lookup by head is
    const w2 = world();
    const r2 = sampleRecord(w2.appId);
    putRecord(w2, recordFileText(r2));
    setupPr(w2, 1, withRecordMarker('x', recordHash(r2)), 'feature');
    setupPr(w2, 2, withRecordMarker('x', recordHash(r2)));
    await writeLocalRecord(APP, { recordHash: recordHash(r2), setupPr: 1, updatedAt: 'x' }, local(w2));
    const got2 = await loadUninstallRecord(gh(w2), APP, { local: local(w2) });
    expect(got2.setupPr).toBe(2);
    expect(got2.warnings.join('\n')).toMatch(/#1\b.*is not pipegen's setup pull request/);
  });

  it('record: an open pipegen/update-<name> central PR → stop: merge or close it first', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    await installed(w, r);
    putRecord(w, recordFileText({ ...r, pipegenVersion: '0.2.1' }), 'pipegen/update-r');
    w.g.repo('o/pipelines').pulls.push({ number: 9, head: 'pipegen/update-r', base: 'main', title: 'pipegen update', body: '', state: 'open', html_url: 'https://github.com/o/pipelines/pull/9' });
    await stops(loadUninstallRecord(gh(w), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }), /#9 .*pipegen\/update-r.*[Mm]erge or close it first/s);
    expect(w.asked).toEqual([]);
    expect(writes(w)).toEqual([]);
    // closed: not a stop; an open app PR on pipegen/update is not a stop either (phase A closes it)
    w.g.repo('o/pipelines').pulls[0]!.state = 'closed';
    w.g.repo('o/r').pulls.push({ number: 7, head: 'pipegen/update', base: 'main', title: 'pipegen update', body: '', state: 'open', html_url: 'https://github.com/o/r/pull/7' });
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    expect(got.record).toEqual(r);
    // GitHub's list answer is checked branch by branch: an open central PR on another branch is not pipegen's update PR, and a listed app PR
    // on another branch is never taken as the setup PR
    w.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}/pulls' ? { status: 200, data: [{ number: 12, state: 'open', head: { ref: 'feature' }, base: { ref: 'main' }, body: '' }] } : undefined));
    const other = await loadUninstallRecord(gh(w), APP, { local: { ...local(w) } });
    expect(other.record).toEqual(r);
    expect(other.setupPr).toBe(5);   // the local file's #5 (on pipegen/setup), not the listed #12
  });

  it('record: a trusted record only on the central pull request branch → stop (the default branch holds another)', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    const newer = { ...r, pipegenVersion: '0.2.1' };
    putRecord(w, recordFileText(newer), 'pipegen/update-r');
    await writeLocalRecord(APP, { recordHash: recordHash(newer), updatedAt: 'x' }, local(w));
    await stops(loadUninstallRecord(gh(w), APP, { local: local(w) }), /pipegen\/update-r.*not on the default branch/s);
    expect(writes(w)).toEqual([]);
  });

  it('record: untrusted record (local file mismatch) → stop with the way on, nothing planned', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    await writeLocalRecord(APP, { recordHash: 'a'.repeat(64), setupPr: 5, updatedAt: 'x' }, local(w));
    const e = await stops(loadUninstallRecord(gh(w), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }), /no install record for o\/r that it trusts/);
    expect(e.message).toContain(localRecordPath(APP, local(w)));
    expect(e.message).toMatch(/[Mm]ove .* away.*run .*again.*type/s);
    // spec M1 (V1-R1): trustedPrevious's note without its deliver clause (uninstall writes no new record)
    expect(e.message).toMatch(/doesn't match the hash in this machine's local record file, so pipegen claims nothing from it\./);
    expect(e.message).not.toMatch(/writes a new record/);
    expect(w.asked).toEqual([]);
    expect(writes(w)).toEqual([]);
  });

  it('record: typed trust → only the confirmView entries; dropped fields reported', async () => {
    const w = world();
    const r = sampleRecord(w.appId, {
      variables: [{ name: 'PIPEGEN_X', scope: 'repo', created: false, previous: 'old' }],
      environments: [{ name: 'pipegen-signing', created: false, previous: { wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] }, changed: ['can_admins_bypass'], branchPolicyIds: [3] }],
      orgRuleset: undefined, scratch: { repoId: 77, createdByPipegen: true }, repoSettings: { vulnerabilityAlerts: { previous: false } },
    });
    putRecord(w, recordFileText(r));
    setupPr(w, 5, withRecordMarker('pipegen sets up CI', recordHash(r)));
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w), io: io(w, 'O/R '), interactive: true });
    expect(w.asked).toHaveLength(1);
    expect(got.trust).toBe('typed');
    const cv = confirmView(r);
    if (!('view' in cv)) throw new Error('refused');
    expect(got.record).toEqual(cv.view);
    expect(got.record.edits).toEqual([]);
    for (const k of ['classicProtection', 'central', 'scratch', 'orgRuleset', 'repoSettings', 'mergedAt'] as const) expect(got.record[k], k).toBeUndefined();
    expect(got.record.variables[0]?.previous).toBeUndefined();
    expect(got.record.environments[0]?.previous).toBeUndefined();
    // the marker is still the full record's (the one the setup PR names)
    expect(got.marker).toBe('match');
    expect(got.dropped).toEqual(TYPED_DROPPED);
    for (const k of ['edits', 'classicProtection', 'central', 'scratch', 'orgRuleset', 'repoSettings', 'environments.previous', 'variables.previous']) expect(got.dropped).toContain(k);
    expect(got.warnings.join('\n')).toMatch(/trusted by typing.*manual steps/s);
    // vouched into the local file as typed: a later non-interactive run gets the same view, and no question
    expect(JSON.parse(readFileSync(localRecordPath(APP, local(w)), 'utf8'))).toMatchObject({ recordHash: recordHash(r), typed: true });
    const again = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    expect(again.trust).toBe('typed');
    expect(again.record).toEqual(cv.view);
    expect(w.asked).toHaveLength(1);
  });

  it('record: typed confirmation only from an interactive terminal; no TTY → stop', async () => {
    for (const deps of [(w: World) => ({ io: io(w, 'o/r'), interactive: false }), (w: World) => ({ io: io(w, 'o/r') }), () => ({ interactive: true })]) {
      const w = world();
      putRecord(w, recordFileText(sampleRecord(w.appId)));
      await stops(loadUninstallRecord(gh(w), APP, { local: local(w), ...deps(w) }), /at a terminal/);
      expect(w.asked).toEqual([]);
      expect(writes(w)).toEqual([]);
    }
    // at a terminal, a wrong name or a cancelled question is a no
    for (const typed of ['o/other', undefined]) {
      const w = world();
      putRecord(w, recordFileText(sampleRecord(w.appId)));
      await stops(loadUninstallRecord(gh(w), APP, { local: local(w), io: io(w, typed), interactive: true }), /didn't confirm/);
      expect(w.asked).toHaveLength(1);
    }
    // the typed-name helper later steps use: no terminal → stop, never asked; at a terminal only the exact name is a yes
    const w = world();
    await expect(askTypedName({ io: io(w, 'X') }, 'X', 'Delete it?')).rejects.toThrow(UninstallError);
    await expect(askTypedName({ io: io(w, 'X'), interactive: false }, 'X', 'Delete it?')).rejects.toThrow(/at a terminal/);
    await expect(askTypedName({ interactive: true }, 'X', 'Delete it?')).rejects.toThrow(/at a terminal/);
    expect(w.asked).toEqual([]);
    expect(await askTypedName({ io: io(w, ' PIPEGEN_X '), interactive: true }, 'PIPEGEN_X', 'Delete it?')).toBe(true);
    expect(await askTypedName({ io: io(w, 'pipegen_x'), interactive: true }, 'PIPEGEN_X', 'Delete it?')).toBe(false);
    expect(await askTypedName({ io: io(w, undefined), interactive: true }, 'PIPEGEN_X', 'Delete it?')).toBe(false);
    expect(w.asked.at(-1)).toMatch(/Delete it\?\nType PIPEGEN_X/);
  });
});

// Fix round 1 (ruling V1-R1): every finding of the security and spec reviews of V1.
describe('uninstall: load and trust the install record, fix round 1 (V1-R1)', () => {
  const swapTo = (w: World, r: InstallRecord): void => { w.g.commitOn('o/pipelines', 'main', { [recordPath('r')]: recordFileText(r) }, 'swap'); };
  const isMainRef = (c: { route: string; params: Record<string, unknown> }): boolean => c.route === 'GET /repos/{owner}/{repo}/git/ref/{ref}' && c.params.repo === 'pipelines' && c.params.ref === 'heads/main';

  it('record: typed trust or a marker that is not a match → typedNames, every name typed one by one (sec I1, probe P10)', async () => {
    // P10: a central writer adds the user's production environment with GitHub's real created_at and sets the setup PR marker to match
    const w = world();
    const r = sampleRecord(w.appId, { environments: [{ name: 'production', created: true, githubCreatedAt: '2026-01-01T00:00:00Z', changed: [], branchPolicyIds: [] }] });
    putRecord(w, recordFileText(r));
    setupPr(w, 5, withRecordMarker('pipegen sets up CI', recordHash(r)));
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w), io: io(w, 'o/r'), interactive: true });
    expect(got.trust).toBe('typed');
    expect(got.marker).toBe('match');
    expect(got.typedNames).toBe(true);
    expect(got.warnings.join('\n')).toMatch(/trusted by typing.*type each name.*one by one/s);
    // full trust and a matching marker: no typed names; full trust and a marker that differs: typed names
    const w2 = world();
    await installed(w2, sampleRecord(w2.appId));
    expect((await loadUninstallRecord(gh(w2), APP, { local: local(w2) })).typedNames).toBe(false);
    w2.g.repo('o/r').pulls[0]!.body = withRecordMarker('edited', 'f'.repeat(64));
    const differs = await loadUninstallRecord(gh(w2), APP, { local: local(w2) });
    expect(differs.marker).toBe('differs');
    expect(differs.typedNames).toBe(true);
    w2.g.repo('o/r').pulls.length = 0;
    expect((await loadUninstallRecord(gh(w2), APP, { local: local(w2) })).typedNames).toBe(true);
  });

  it('record: typed trust, the record changes between the trust read and the re-read → stop "changed while pipegen read it" (sec I2, M8)', async () => {
    // a kept field changed (a new secret name), and a change the view doesn't show (an edit): both stop
    for (const changed of [
      (r: InstallRecord): InstallRecord => ({ ...r, [SEC]: [...r.secrets, { name: 'USER_KEY', scope: 'repo', created: true, githubCreatedAt: '2026-01-01T00:00:00Z' }] }),
      (r: InstallRecord): InstallRecord => ({ ...r, edits: [] }),
    ]) {
      const w = world();
      const r = sampleRecord(w.appId);
      putRecord(w, recordFileText(r));
      const prompter = io(w, 'o/r');
      const ask = prompter.text;
      prompter.text = async (msg) => { swapTo(w, changed(r)); return ask(msg); };   // swapped while the user types
      await stops(loadUninstallRecord(gh(w), APP, { local: local(w), io: prompter, interactive: true }), /changed while pipegen read it/);
      expect(w.asked).toHaveLength(1);
      expect(writes(w)).toEqual([]);
    }
    // typed trust vouched on an earlier run: the record swapped for one with the same view after the trust read → stop
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    await writeLocalRecord(APP, { recordHash: recordHash(r), typed: true, updatedAt: 'x' }, local(w));
    const plain = world();
    putRecord(plain, recordFileText(sampleRecord(plain.appId)));
    await writeLocalRecord(APP, { recordHash: recordHash(sampleRecord(plain.appId)), typed: true, updatedAt: 'x' }, local(plain));
    await loadUninstallRecord(gh(plain), APP, { local: local(plain) });
    const n = plain.g.calls.filter(isMainRef).length;     // the reads of a clean run; the last one is the re-read
    let seen = 0;
    w.g.hooks.push((c) => { if (isMainRef(c) && ++seen === n) swapTo(w, { ...r, edits: [] }); return undefined; });
    await stops(loadUninstallRecord(gh(w), APP, { local: local(w) }), /changed while pipegen read it/);
  });

  it('record: full trust, the record changes between the trust read and the re-read → stop "changed while pipegen read it" (sec I2)', async () => {
    const plain = world();
    await installed(plain, sampleRecord(plain.appId));
    await loadUninstallRecord(gh(plain), APP, { local: local(plain) });
    const n = plain.g.calls.filter(isMainRef).length;
    const w = world();
    const r = sampleRecord(w.appId);
    await installed(w, r);
    let seen = 0;
    w.g.hooks.push((c) => { if (isMainRef(c) && ++seen === n) swapTo(w, { ...r, pipegenVersion: '0.2.9' }); return undefined; });
    await stops(loadUninstallRecord(gh(w), APP, { local: local(w) }), /changed while pipegen read it/);
    expect(writes(w)).toEqual([]);
    // swapped for another repo's record (vouched by the local file) after the first read: the trusted record's id is checked again → stop
    const w4 = world();
    const r4 = sampleRecord(w4.appId);
    putRecord(w4, recordFileText(r4));
    const foreign = sampleRecord(w4.appId + 1);
    await writeLocalRecord(APP, { recordHash: recordHash(foreign), updatedAt: 'x' }, local(w4));
    let seen4 = 0;
    w4.g.hooks.push((c) => { if (isMainRef(c) && ++seen4 === 2) swapTo(w4, foreign); return undefined; });
    await stops(loadUninstallRecord(gh(w4), APP, { local: local(w4) }), /not the repository pipegen was installed in/);
  });

  it('record: a record of another repo id is refused before anything is asked or vouched (sec M1, spec M3, probe P2)', async () => {
    const w = world();
    putRecord(w, recordFileText(sampleRecord(w.appId + 1)));
    await stops(loadUninstallRecord(gh(w), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }), /not the repository pipegen was installed in/);
    expect(w.asked).toEqual([]);
    expect(existsSync(localRecordPath(APP, local(w)))).toBe(false);
    // another owner (same id): the same, before the question
    const w2 = world();
    putRecord(w2, recordFileText(sampleRecord(w2.appId, { app: { owner: 'x', repo: 'r', repoId: w2.appId, defaultBranch: 'main', private: true, ownerType: 'User' } })));
    await stops(loadUninstallRecord(gh(w2), APP, { local: local(w2), io: io(w2, 'o/r'), interactive: true }), /not the repository pipegen was installed in/);
    expect(w2.asked).toEqual([]);
  });

  it('record: a fork pull request on a branch named pipegen/setup is never the setup PR (sec M2, probe P3)', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    setupPr(w, 4, 'pipegen sets up CI (marker removed)');
    await writeLocalRecord(APP, { recordHash: recordHash(r), updatedAt: 'x' }, local(w));
    // GitHub answers an unfiltered list: a newer fork PR #50 whose branch is also pipegen/setup and whose body carries the record's hash
    const fork = { number: 50, state: 'open', head: { ref: 'pipegen/setup', repo: { id: 4242, full_name: 'evil/r' } }, base: { ref: 'main' }, body: withRecordMarker('x', recordHash(r)) };
    w.g.hooks.push((c) => {
      if (c.params.repo !== 'r') return undefined;
      if (c.route === 'GET /repos/{owner}/{repo}/pulls') return { status: 200, data: [fork, { number: 4, state: 'closed', head: { ref: 'pipegen/setup' }, base: { ref: 'main' }, body: 'pipegen sets up CI (marker removed)' }] };
      if (c.route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}' && c.params.pull_number === 50) return { status: 200, data: fork };
      return undefined;
    });
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    expect(got.setupPr).toBe(4);
    expect(got.marker).toBe('absent');
    expect(got.typedNames).toBe(true);
    // the local file naming the fork PR: not taken either
    await writeLocalRecord(APP, { recordHash: recordHash(r), setupPr: 50, updatedAt: 'x' }, local(w));
    const again = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    expect(again.setupPr).toBe(4);
    expect(again.marker).toBe('absent');
    // a pull request whose head repo GitHub no longer knows (a deleted fork: head.repo null) is not taken
    const w2 = world();
    const r2 = sampleRecord(w2.appId);
    putRecord(w2, recordFileText(r2));
    await writeLocalRecord(APP, { recordHash: recordHash(r2), updatedAt: 'x' }, local(w2));
    const gone = { number: 8, state: 'closed', head: { ref: 'pipegen/setup', repo: null }, base: { ref: 'main' }, body: withRecordMarker('x', recordHash(r2)) };
    w2.g.hooks.push((c) => (c.params.repo === 'r' && c.route === 'GET /repos/{owner}/{repo}/pulls' ? { status: 200, data: [gone] } : c.params.repo === 'r' && c.route === 'GET /repos/{owner}/{repo}/pulls/{pull_number}' ? { status: 200, data: gone } : undefined));
    expect((await loadUninstallRecord(gh(w2), APP, { local: local(w2) })).setupPr).toBeNull();
  });

  it('record: askTypedName refuses a blank name, makes the question safe, and never shows a name it can\'t take (sec M3, spec M4, probes P1, P7)', async () => {
    const w = world();
    // P1: an empty or blank expected name is a programming error, never confirmed by an empty answer
    await expect(askTypedName({ io: io(w, ''), interactive: true }, '', 'Delete it?')).rejects.toThrow(/no name/);
    await expect(askTypedName({ io: io(w, '  '), interactive: true }, '   ', 'Delete it?')).rejects.toThrow(/no name/);
    expect(w.asked).toEqual([]);
    // each line of the question goes through safeText (a terminal escape or a bidi control never reaches the prompt)
    expect(await askTypedName({ io: io(w, 'PIPEGEN_X'), interactive: true }, 'PIPEGEN_X', 'Delete \u001b[2Jit\u202e?\nsecond line')).toBe(true);
    const shown = w.asked.at(-1) as string;
    expect(shown).not.toMatch(/[\u001b\u202e]/);
    expect(shown).toMatch(/^Delete .*it.*\?\nsecond line\nType PIPEGEN_X/);
    // a name safeText would change (or cut) can't be typed as shown: no question, false (the caller keeps the object and lists it)
    const before = w.asked.length;
    expect(await askTypedName({ io: io(w, 'A\u200bB'), interactive: true }, 'A\u200bB', 'Delete it?')).toBe(false);
    expect(await askTypedName({ io: io(w, 'x'.repeat(130)), interactive: true }, 'x'.repeat(130), 'Delete it?')).toBe(false);
    expect(w.asked.length).toBe(before);
    // P7: asked mid-apply without a terminal, the stop doesn't claim nothing was changed at all
    const e = await askTypedName({ interactive: false }, 'PIPEGEN_X', 'Delete it?').then(() => null, (x: unknown) => x);
    expect(e).toBeInstanceOf(UninstallError);
    expect((e as Error).message).toMatch(/[Nn]othing more was changed/);
    expect((e as Error).message).not.toMatch(/(^|\. )Nothing was changed/);
  });

  it('record: a created entry with neither or both of githubCreatedAt and unconfirmed counts as unconfirmed (sec M4, probe P9)', async () => {
    const w = world();
    const r = sampleRecord(w.appId, {
      [SEC]: [
        { name: 'PIPEGEN_A', scope: 'repo', created: true },
        { name: 'PIPEGEN_B', scope: 'repo', created: true, githubCreatedAt: '2026-11-05T12:00:01Z', unconfirmed: true },
        { name: 'PIPEGEN_C', scope: 'repo', created: true, githubCreatedAt: '2026-11-05T12:00:01Z' },
        { name: 'USER_D', scope: 'repo', created: false },
      ],
      variables: [{ name: 'PIPEGEN_V', scope: 'repo', created: true, githubCreatedAt: '2026-11-05T12:00:01Z', unconfirmed: true }],
      environments: [{ name: 'production', created: true, changed: [], branchPolicyIds: [] }, { name: 'pipegen-signing', created: true, unconfirmed: true, changed: [], branchPolicyIds: [] }],
    });
    await installed(w, r);
    const got = await loadUninstallRecord(gh(w), APP, { local: local(w) });
    const s = got.record.secrets;
    expect(s[0]).toEqual({ name: 'PIPEGEN_A', scope: 'repo', created: true, unconfirmed: true });
    expect(s[1]).toEqual({ name: 'PIPEGEN_B', scope: 'repo', created: true, unconfirmed: true });
    expect(s[2]).toEqual({ name: 'PIPEGEN_C', scope: 'repo', created: true, githubCreatedAt: '2026-11-05T12:00:01Z' });
    expect(s[3]).toEqual({ name: 'USER_D', scope: 'repo', created: false });
    expect(got.record.variables[0]).toEqual({ name: 'PIPEGEN_V', scope: 'repo', created: true, unconfirmed: true });
    expect(got.record.environments[0]).toMatchObject({ name: 'production', created: true, unconfirmed: true });
    expect(got.record.environments[0]?.githubCreatedAt).toBeUndefined();
    expect(got.record.environments[1]).toMatchObject({ name: 'pipegen-signing', unconfirmed: true });
    expect(got.warnings.join('\n')).toMatch(/PIPEGEN_A, PIPEGEN_B, PIPEGEN_V, production.*typed name/s);
    expect(got.warnings.join('\n')).not.toMatch(/PIPEGEN_C|USER_D|pipegen-signing/);
  });

  it('record: an unreadable record stops with its own reason, with or without a local file, and asks nothing (sec M6, spec M1, probe P5)', async () => {
    for (const withLocal of [true, false]) {
      const w = world();
      putRecord(w, JSON.stringify({ ...JSON.parse(canonicalRecordJson(sampleRecord(w.appId))) as object, schema: 3 }));
      if (withLocal) await writeLocalRecord(APP, { recordHash: 'a'.repeat(64), updatedAt: 'x' }, local(w));
      const e = await stops(loadUninstallRecord(gh(w), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }), /a newer pipegen wrote\. Update pipegen/);
      expect(e.message).not.toMatch(/move that file away|didn't confirm/);
      expect(w.asked).toEqual([]);
    }
  });

  it('record: a record only on the central update branch, with no local file or another hash in it → stop says merge or delete that branch, asks nothing (sec M-r1, probe R-M6b)', async () => {
    for (const interactive of [true, false]) {
      for (const localFile of ['none', 'other'] as const) {
        const w = world();
        putRecord(w, recordFileText(sampleRecord(w.appId)), 'pipegen/update-r');
        if (localFile === 'other') await writeLocalRecord(APP, { recordHash: 'a'.repeat(64), updatedAt: 'x' }, local(w));
        const e = await stops(loadUninstallRecord(gh(w), APP, { local: local(w), ...(interactive ? { io: io(w, 'o/r'), interactive: true } : {}) }),
          /only on the central branch pipegen\/update-r.*Merge that change \(or delete the branch\), then run `npx pipegen uninstall` again/s);
        expect(e.message, `${interactive}/${localFile}`).not.toMatch(/type the repo name|not confirmed by typing|move that file away|didn't confirm/);
        expect(w.asked).toEqual([]);
        expect(writes(w)).toEqual([]);
      }
    }
  });

  it('record: the app is held to GitHub\'s canonical name, owner type and central id (sec M7, probe P6)', async () => {
    // P6: a transferred repo, served through GitHub's redirect for the old name
    const w = world();
    await installed(w, sampleRecord(w.appId));
    const real = w.g.repo('o/r');
    w.g.hooks.push((c) => (c.route === 'GET /repos/{owner}/{repo}' && c.params.repo === 'r'
      ? { status: 200, data: { id: real.id, name: 'r', full_name: 'n/r', private: true, default_branch: 'main', owner: { login: 'n', type: 'User' } } } : undefined));
    await stops(loadUninstallRecord(gh(w), APP, { local: local(w) }), /GitHub now calls it n\/r/);
    expect(writes(w)).toEqual([]);
    // an owner type that changed: a warning; the central repo's id is returned, and one that isn't the recorded one is a warning
    const w2 = world();
    const r2 = sampleRecord(w2.appId, { app: { owner: 'o', repo: 'r', repoId: w2.appId, defaultBranch: 'main', private: true, ownerType: 'Organization' } });
    await installed(w2, r2);
    const got = await loadUninstallRecord(gh(w2), APP, { local: local(w2) });
    expect(got.centralRepoId).toBe(w2.g.repo('o/pipelines').id);
    expect(got.warnings.join('\n')).toMatch(/owned by a user account now; it was owned by an organization/);
    expect(got.warnings.join('\n')).toMatch(/o\/pipelines has the id \d+ now; the install record names 99/);
    // the recorded central id equal: no central warning
    const w3 = world();
    const r3 = sampleRecord(w3.appId);
    await installed(w3, { ...r3, central: { repoId: w3.g.repo('o/pipelines').id, createdByPipegen: true } });
    expect((await loadUninstallRecord(gh(w3), APP, { local: local(w3) })).warnings).toEqual([]);
  });
});
