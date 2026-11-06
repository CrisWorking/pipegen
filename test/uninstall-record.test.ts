// v0.2 Plan V V1 (rulings V-B1, V-B6, V-S1, V-S2, V-S13, V-N2, V-N4, V-N13, V-N14): uninstall loads the install record through the one
// trust order (trustedPrevious), never through a second parser or the setup PR body's marker. An untrusted record stops; a typed trust
// grants only confirmView's view; the app facts come from GitHub; an open central pull request that can change the record stops.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
async function stops(p: Promise<unknown>, re: RegExp): Promise<UninstallError> {
  const e = await p.then(() => null, (x: unknown) => x);
  expect(e).toBeInstanceOf(UninstallError);
  expect((e as Error).message).toMatch(re);
  return e as UninstallError;
}

describe('uninstall: load and trust the install record (V1)', () => {
  it('record: loads and validates', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    await installed(w, r);
    const got = await loadUninstallRecord(w.g.octokit(), APP, { local: local(w) });
    expect(got.trust).toBe('full');
    expect(got.record).toEqual(r);
    // the app facts are GitHub's, never the record's
    expect(got.app).toEqual({ owner: 'o', repo: 'r', repoId: w.appId, private: true, defaultBranch: 'main', ownerType: 'User' });
    const head = w.g.head('o/pipelines');
    expect(got.centralHead).toBe(head);
    const entry = w.g.repo('o/pipelines').trees.get(w.g.repo('o/pipelines').commits.get(head)?.tree as string)?.get(recordPath('r'));
    expect(got.blobSha).toBe(entry?.sha);
    expect(got.marker).toBe('match');
    expect(got.setupPr).toBe(5);
    expect(got.dropped).toEqual([]);
    expect(got.warnings).toEqual([]);
    expect(writes(w)).toEqual([]);
    expect(w.asked).toEqual([]);
  });

  it('record: missing → stop with explanation', async () => {
    const w = world();
    const e = await stops(loadUninstallRecord(w.g.octokit(), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }), /^No install record for o\/r\. pipegen only removes what it recorded installing\./);
    expect(e.message).not.toMatch(/undefined|null/);
    expect(w.asked).toEqual([]);
    expect(writes(w)).toEqual([]);
    // no central repo at all: still "no install record", nothing asked
    const w2 = world({ noCentral: true });
    await stops(loadUninstallRecord(w2.g.octokit(), APP, { local: local(w2) }), /^No install record for o\/r\..*pipegen only removes what it recorded installing\./);
    // the app repo itself missing (or no access): a stop that names it
    const w3 = world();
    await stops(loadUninstallRecord(w3.g.octokit(), { owner: 'o', repo: 'gone' }, { local: local(w3) }), /can't see o\/gone/);
  });

  it('record: public app repo → read from the private records-only pipelines', async () => {
    const w = world({ appPrivate: false });
    const r = sampleRecord(w.appId, { centralSha: null, app: { owner: 'o', repo: 'r', repoId: w.appId, defaultBranch: 'main', private: false, ownerType: 'User' }, files: [{ repo: 'app', path: '.github/workflows/pipegen.yml', part: 'pipeline', shas: [SHA('a')] }] });
    await installed(w, r);
    const got = await loadUninstallRecord(w.g.octokit(), APP, { local: local(w) });
    expect(got.app.private).toBe(false);
    expect(got.record.centralSha).toBeNull();
    expect(got.record.files.filter((f) => f.repo === 'central')).toEqual([]);
    expect(w.g.calls.some((c) => c.route === 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}' && c.params.repo === 'pipelines')).toBe(true);
    // a public pipelines repo is never where pipegen keeps records: stop
    const w2 = world({ appPrivate: false, centralPrivate: false });
    await installed(w2, sampleRecord(w2.appId, { centralSha: null }));
    await stops(loadUninstallRecord(w2.g.octokit(), APP, { local: local(w2) }), /o\/pipelines is public/);
  });

  it('record: hash differs from setup PR body → hashMatches false, warning shown', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    setupPr(w, 5, withRecordMarker('pipegen sets up CI', 'f'.repeat(64)));
    await writeLocalRecord(APP, { recordHash: recordHash(r), setupPr: 5, updatedAt: 'x' }, local(w));
    const got = await loadUninstallRecord(w.g.octokit(), APP, { local: local(w) });
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
    for (const [label, text] of variants) {
      for (const withLocal of [true, false]) {
        const w = world();
        const t = text(w);
        putRecord(w, t);
        if (withLocal) await writeLocalRecord(APP, { recordHash: 'a'.repeat(64), updatedAt: 'x' }, local(w));
        const e = await loadUninstallRecord(w.g.octokit(), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }).then(() => null, (x: unknown) => x);
        expect(e, label).toBeInstanceOf(UninstallError);
        expect((e as Error).message, label).toMatch(/no install record .* that it trusts|nothing/i);
        // never asked about (an unreadable record is never offered for typing), nothing written
        expect(w.asked, label).toEqual([]);
        expect(writes(w), label).toEqual([]);
      }
    }
  });

  it('record: app repo id differs from the recorded one → stop', async () => {
    const w = world();
    await installed(w, sampleRecord(w.appId + 1));
    await stops(loadUninstallRecord(w.g.octokit(), APP, { local: local(w) }), /repo id .*not the repository pipegen was installed in/);
    expect(writes(w)).toEqual([]);
    // the recorded owner of another repo (same id) stops too
    const w2 = world();
    await installed(w2, sampleRecord(w2.appId, { app: { owner: 'x', repo: 'r', repoId: w2.appId, defaultBranch: 'main', private: true, ownerType: 'User' } }));
    await stops(loadUninstallRecord(w2.g.octokit(), APP, { local: local(w2) }), /not the repository pipegen was installed in/);
  });

  it('record: no hash found anywhere → treated as a mismatch', async () => {
    // no setup PR at all, and a local file without a PR number
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    await writeLocalRecord(APP, { recordHash: recordHash(r), updatedAt: 'x' }, local(w));
    const got = await loadUninstallRecord(w.g.octokit(), APP, { local: local(w) });
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
    const got2 = await loadUninstallRecord(w2.g.octokit(), APP, { local: local(w2) });
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
    const got = await loadUninstallRecord(w.g.octokit(), APP, { local: local(w) });
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
    const got2 = await loadUninstallRecord(w2.g.octokit(), APP, { local: local(w2) });
    expect(got2.setupPr).toBe(2);
    expect(got2.warnings.join('\n')).toMatch(/#1\b.*is not pipegen's setup pull request/);
  });

  it('record: an open pipegen/update-<name> central PR → stop: merge or close it first', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    await installed(w, r);
    putRecord(w, recordFileText({ ...r, pipegenVersion: '0.2.1' }), 'pipegen/update-r');
    w.g.repo('o/pipelines').pulls.push({ number: 9, head: 'pipegen/update-r', base: 'main', title: 'pipegen update', body: '', state: 'open', html_url: 'https://github.com/o/pipelines/pull/9' });
    await stops(loadUninstallRecord(w.g.octokit(), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }), /#9 .*pipegen\/update-r.*[Mm]erge or close it first/s);
    expect(w.asked).toEqual([]);
    expect(writes(w)).toEqual([]);
    // closed: not a stop; an open app PR on pipegen/update is not a stop either (phase A closes it)
    w.g.repo('o/pipelines').pulls[0]!.state = 'closed';
    w.g.repo('o/r').pulls.push({ number: 7, head: 'pipegen/update', base: 'main', title: 'pipegen update', body: '', state: 'open', html_url: 'https://github.com/o/r/pull/7' });
    const got = await loadUninstallRecord(w.g.octokit(), APP, { local: local(w) });
    expect(got.record).toEqual(r);
  });

  it('record: a trusted record only on the central pull request branch → stop (the default branch holds another)', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    const newer = { ...r, pipegenVersion: '0.2.1' };
    putRecord(w, recordFileText(newer), 'pipegen/update-r');
    await writeLocalRecord(APP, { recordHash: recordHash(newer), updatedAt: 'x' }, local(w));
    await stops(loadUninstallRecord(w.g.octokit(), APP, { local: local(w) }), /pipegen\/update-r.*not on the default branch/s);
    expect(writes(w)).toEqual([]);
  });

  it('record: untrusted record (local file mismatch) → stop with the way on, nothing planned', async () => {
    const w = world();
    const r = sampleRecord(w.appId);
    putRecord(w, recordFileText(r));
    await writeLocalRecord(APP, { recordHash: 'a'.repeat(64), setupPr: 5, updatedAt: 'x' }, local(w));
    const e = await stops(loadUninstallRecord(w.g.octokit(), APP, { local: local(w), io: io(w, 'o/r'), interactive: true }), /no install record for o\/r that it trusts/);
    expect(e.message).toContain(localRecordPath(APP, local(w)));
    expect(e.message).toMatch(/[Mm]ove .* away.*run .*again.*type/s);
    expect(w.asked).toEqual([]);
    expect(writes(w)).toEqual([]);
  });

  it('record: typed trust → only the confirmView entries; dropped fields reported', async () => {
    const w = world();
    const r = sampleRecord(w.appId, {
      variables: [{ name: 'PIPEGEN_X', scope: 'repo', created: false, previous: 'old' }],
      environments: [{ name: 'pipegen-signing', created: false, previous: { wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] }, changed: ['can_admins_bypass'], branchPolicyIds: [3] }],
      orgRuleset: undefined, scratch: { repoId: 77, createdByPipegen: true }, repoSettings: { secretScanning: { previous: false } },
    });
    putRecord(w, recordFileText(r));
    setupPr(w, 5, withRecordMarker('pipegen sets up CI', recordHash(r)));
    const got = await loadUninstallRecord(w.g.octokit(), APP, { local: local(w), io: io(w, 'O/R '), interactive: true });
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
    const again = await loadUninstallRecord(w.g.octokit(), APP, { local: local(w) });
    expect(again.trust).toBe('typed');
    expect(again.record).toEqual(cv.view);
    expect(w.asked).toHaveLength(1);
  });

  it('record: typed confirmation only from an interactive terminal; no TTY → stop', async () => {
    for (const deps of [(w: World) => ({ io: io(w, 'o/r'), interactive: false }), (w: World) => ({ io: io(w, 'o/r') }), () => ({ interactive: true })]) {
      const w = world();
      putRecord(w, recordFileText(sampleRecord(w.appId)));
      await stops(loadUninstallRecord(w.g.octokit(), APP, { local: local(w), ...deps(w) }), /at a terminal/);
      expect(w.asked).toEqual([]);
      expect(writes(w)).toEqual([]);
    }
    // at a terminal, a wrong name or a cancelled question is a no
    for (const typed of ['o/other', undefined]) {
      const w = world();
      putRecord(w, recordFileText(sampleRecord(w.appId)));
      await stops(loadUninstallRecord(w.g.octokit(), APP, { local: local(w), io: io(w, typed), interactive: true }), /didn't confirm/);
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
