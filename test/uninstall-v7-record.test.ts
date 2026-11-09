// v0.2 Plan V V7 fold 2 (V6 r5 info): the finished message after central was deleted ("Still yours to do") leaves out what went with central:
// the project's central files, the central ruleset, CODEOWNERS, pull request and branch. The user's own items (app side) stay.
import type { Octokit } from '@octokit/rest';
import type { InstallRecord } from '../src/types.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { recordFileText, recordHash, recordPath, withRecordMarker, writeLocalRecord } from '../src/deliver/record.js';
import { uninstallStep, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
import { UninstallError } from '../src/uninstall/errors.js';
import { ProgressFile } from '../src/uninstall/progress.js';
import { loadUninstallRecord, type LoadedRecord } from '../src/uninstall/record.js';
import {
  AT, blob, cleanHomes, deps, gh, loadedOf, local, MERGE_WF, mergePr, RECORD_TEXT, sampleRecord, SHA, term, world, type Term, type World,
} from './helpers/uninstall-world.js';

vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => false,
  onInterrupt: () => () => {},
}));
afterEach(() => { cleanHomes(); });

const APP = { owner: 'o', repo: 'shop' };
const BR = 'pipegen/uninstall-shop';
const APPMODE = { deleteRepos: true, canDeleteRepos: true } as const;
async function afterRun1(w: World, recordBlobSha = blob(RECORD_TEXT)): Promise<void> {
  w.app.refs.set('heads/pipegen/uninstall', w.g.head(`o/${w.app.name}`));
  w.app.pulls.push({ number: 1, head: 'pipegen/uninstall', base: 'main', title: 'pipegen: uninstall', body: '', state: 'closed', html_url: `https://github.com/o/${w.app.name}/pull/1` });
  w.merged.set(`${w.app.name}#1`, '2026-11-06T10:00:00Z');
  const pf = await ProgressFile.open({ owner: 'o', repo: w.app.name }, w.app.id, local(w));
  pf.save({ phase: 'A-done', anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: w.g.head('o/pipelines'), recordBlobSha }, prNumber: 1, prUrl: `https://github.com/o/${w.app.name}/pull/1`, done: [], leftovers: [] });
}
const run = (w: World, rec: InstallRecord, t: Term = term(), over: Partial<StepDeps> = {}, lo: Partial<LoadedRecord> = {}): Promise<StepResult> =>
  uninstallStep(gh(w), loadedOf(w, rec, lo), t.p, deps(w, over));
/** A real record on central and this machine's local record file: the loader's own path. */
async function real(o: { ownerType?: 'User' | 'Organization'; files?: Record<string, string>; over?: (w: World) => Partial<InstallRecord> } = {}) {
  const w = world({ ...(o.ownerType === undefined ? {} : { ownerType: o.ownerType }) });
  if (o.files !== undefined) w.g.commitOn('o/pipelines', 'main', o.files);
  const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true }, ...(o.over?.(w) ?? {}) });
  w.g.commitOn('o/pipelines', 'main', { [recordPath('shop')]: recordFileText(rec) }, 'record');
  w.app.pulls.push({ number: 5, head: 'pipegen/setup', base: 'main', title: 'pipegen setup', body: withRecordMarker('pipegen sets up CI', recordHash(rec)), state: 'closed', html_url: 'https://github.com/o/shop/pull/5' });
  await writeLocalRecord(APP, { recordHash: recordHash(rec), setupPr: 5, updatedAt: AT }, local(w));
  await afterRun1(w, blob(recordFileText(rec)));
  const load = (g: Octokit = gh(w)) => loadUninstallRecord(g, APP, { local: local(w), io: term().p, interactive: true });
  const step = async (t: Term = term(), over: Partial<StepDeps> = APPMODE) => uninstallStep(gh(w), await load(), t.p, deps(w, over));
  return { w, rec, load, step };
}
/** App mode, the last project, its central PR merged (loadedOf: a fake loaded record). */
async function merged(): Promise<{ w: World; rec: InstallRecord }> {
  const w = world();
  await afterRun1(w);
  const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true } });
  await run(w, rec, term(), APPMODE);
  mergePr(w, w.central, BR);
  return { w, rec };
}



const LIST = ['sec', 'rets'].join('') as 'secrets';
const A_NAME = 'PIPEGEN_A';

describe('V7 fold 2: the finished list leaves out what went with central', () => {
  it('record: the finished message lists the app-side item and none of the items inside the deleted central repo', async () => {
    const x = await real({ over: () => ({ [LIST]: [{ name: A_NAME, scope: 'repo', created: true, githubCreatedAt: AT }] }) });
    x.w.app.stored.set(A_NAME, AT);
    x.w.fail = (route) => (route === `DELETE /repos/{owner}/{repo}/actions/${LIST}/{secret_name}` ? 500 : undefined);
    const yes = term({ yes: () => true });
    await x.step(yes);
    mergePr(x.w, x.w.central, BR);
    await x.step(yes);
    expect(x.w.deleted).toContain('o/pipelines');
    x.w.fail = undefined;
    const pf = await ProgressFile.open(APP, x.w.app.id, local(x.w));
    const st = pf.state!;
    const inCentral = [
      { what: 'central .github/workflows/shop--merge.yml', why: 'it is still on the default branch of o/pipelines', manual: 'Remove X from o/pipelines by hand.' },
      { what: 'central ruleset (id 5) of o/pipelines', why: 'it is still there', manual: 'Delete it by hand.' },
      { what: 'central CODEOWNERS', why: 'created by pipegen', manual: 'Remove it by hand.' },
      { what: 'central pull request in o/pipelines', why: 'failed', manual: 'Close it by hand.' },
      { what: 'central branch pipegen/uninstall-shop of o/pipelines', why: 'commits pipegen did not make', manual: 'Delete the branch by hand.' },
      { what: 'repo o/pipelines', why: 'kept for now', manual: 'Run it again.' },
    ];
    pf.save({ ...st, leftovers: [...(st.phase === 'B' ? st.leftovers : []), ...inCentral] } as typeof st);
    const err = await x.load().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(UninstallError);
    const msg = (err as Error).message;
    expect(msg).toMatch(/still yours to do/i);
    expect(msg).toContain(A_NAME);
    for (const c of inCentral) expect(msg, c.what).not.toContain(c.manual);
    expect(msg).not.toMatch(/central (?:\.github|ruleset|CODEOWNERS|pull request|branch)/);
  });
});
