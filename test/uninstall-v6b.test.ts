// v0.2 Plan V V6b: the G17C-R1 carries (VL/progress.md, BINDING) in uninstall.
// - V2 I1/I2: the first original is restored over pipegen's writes only when editWritesChained(edit) proves the writes one unbroken pipegen
//   chain from it (baseShas[0] = originalSha, baseShas[n] = writtenShas[n-1], not ownerEdited). A missing, short or broken baseShas proves
//   nothing: the verify job is stripped, the package pair is manual.
// - m4: a central CODEOWNERS pipegen created is pipegen's whole file only when the chain holds from null; otherwise it is a manual step
//   (an older record may hold the owner's blob in writtenShas: a re-run that wrote nothing appended it).
// - row 24: the central run reverts only the CODEOWNERS edit, with no app owner, so a Dependabot private entry is never pipegen's there.
// - row 34: a record whose blockFrom is not a real calendar day is unreadable: uninstall's reads stop (fail closed).
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { gitBlobSha } from '../src/create/guard.js';
import { buildPackageJson } from '../src/create/package-edit.js';
import { canonicalRecordJson, recordPath } from '../src/deliver/record.js';
import { dependabotEntryText } from '../src/engine/created-builders.js';
import { renderHeadCheckStep } from '../src/engine/deploy-steps.js';
import { insertVerify } from '../src/layers/deploy.js';
import type { Job } from '../src/layers/jobs.js';
import type { InstallEdit, InstallRecord, PipelineDraft } from '../src/types.js';
import { uninstallStep, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
import { UninstallError } from '../src/uninstall/errors.js';
import { ProgressFile } from '../src/uninstall/progress.js';
import { loadUninstallRecord, type LoadedRecord } from '../src/uninstall/record.js';
import { revertEdit, revertEdits, revertPair, type RevertResult } from '../src/uninstall/revert.js';
import {
  blob as blobSha, cleanHomes, deps, gh, loadedOf, local, mergePr, RECORD_TEXT, sampleRecord, SHA, term, world, writes, type Term, type World,
} from './helpers/uninstall-world.js';
import { FakeGitHub } from './helpers/deliver-github.js';

vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => false,
  onInterrupt: () => () => {},
}));
afterEach(() => { cleanHomes(); });

/** An edit as the record holds it, with the base of each write (InstallEdit doesn't name baseShas; the record schema does). */
const withBases = <E extends InstallEdit>(e: E, baseShas: (string | null)[] | undefined): E => {
  const out = { ...e } as E & { baseShas?: (string | null)[] };
  if (baseShas === undefined) delete out.baseShas; else out.baseShas = baseShas;
  return out;
};

const blobs = new Map<string, string>();
const put = (text: string): string => { const sha = gitBlobSha(text); blobs.set(sha, text); return sha; };
const blob = (sha: string): string | null => blobs.get(sha) ?? null;
const cur = (text: string): { text: string; sha: string } => ({ text, sha: gitBlobSha(text) });
const kinds = (r: { json: RevertResult; lock: RevertResult | null }): string[] => [r.json.kind, r.lock?.kind ?? 'none'];

// ---------- V2 I1/I2: the first original only over a proven chain ----------

const VERIFY = { 'runs-on': 'ubuntu-24.04', steps: [renderHeadCheckStep('main'), { id: 'pipegen-find', name: 'pipegen: find', run: 'echo find' }] } as unknown as Job;
const WF = '.github/workflows/deploy.yml';
const CTX = { defaultBranch: 'main' };
const USER_WF = [
  'name: deploy  # the owner\'s comment', 'on:', '  push:', '    branches: [main]', 'jobs:',
  '  build:', '    runs-on: ubuntu-latest', '    steps:', '      - run: npm run build',
  '  deploy:', '    runs-on: ubuntu-latest', '    needs: build', '    steps:', '      - run: ./deploy.sh', '',
].join('\n');

describe('V6b (G17C-R1, V2 I1/I2): the first original is restored over pipegen\'s writes only when editWritesChained holds', () => {
  /** Two pipegen writes of the verify job: W1 = insert(O1); the owner took pipegen's part out (W1 → O'), W2 = insert(O'). */
  function twoWrites(ownerBetween: boolean): { edit: Extract<InstallEdit, { kind: 'verify-job' }>; w1: string; w2: string; o1: string } {
    const o1 = USER_WF;
    const r1 = insertVerify(o1, ['deploy'], VERIFY);
    // a chained second write starts from W1 itself (pipegen's job still there): the second insert is a no-op re-render of the same job.
    // Here the second write is made over the owner's file without pipegen's part, which is what a re-run after the owner's edit records.
    const between = ownerBetween ? o1.replace('jobs:\n', '# Production deploy. Owner: @alice\njobs:\n') : o1;
    const r2 = insertVerify(between, ['deploy'], VERIFY);
    for (const t of [o1, r1.text, between, r2.text]) put(t);
    const edit: Extract<InstallEdit, { kind: 'verify-job' }> = {
      repo: 'app', path: WF, kind: 'verify-job', jobs: [...r1.inserted.jobs], needs: r1.inserted.needs.map((n) => ({ job: n.job, added: [...n.added] })),
      ...((r1.inserted.headCheck ?? []).length > 0 ? { headCheck: r1.inserted.headCheck } : {}), originalSha: gitBlobSha(o1), writtenShas: [gitBlobSha(r1.text), gitBlobSha(r2.text)],
    };
    return { edit, w1: r1.text, w2: r2.text, o1 };
  }

  it('V6b I2: a verify job written once is restored only with its base recorded as the original', () => {
    const r1 = insertVerify(USER_WF, ['deploy'], VERIFY);
    put(USER_WF);
    put(r1.text);
    const e: Extract<InstallEdit, { kind: 'verify-job' }> = {
      repo: 'app', path: WF, kind: 'verify-job', jobs: [...r1.inserted.jobs], needs: r1.inserted.needs.map((n) => ({ job: n.job, added: [...n.added] })),
      ...((r1.inserted.headCheck ?? []).length > 0 ? { headCheck: r1.inserted.headCheck } : {}), originalSha: gitBlobSha(USER_WF), writtenShas: [gitBlobSha(r1.text)],
    };
    expect(revertEdit(withBases(e, [gitBlobSha(USER_WF)]), cur(r1.text), blob, CTX)).toEqual({ kind: 'restore', text: USER_WF });
    // an older record without bases, an empty list, a base that is not the original, a "new file" base: nothing proven, the strip
    for (const b of [undefined, [], [SHA('9')], [null]] as ((string | null)[] | undefined)[]) {
      const r = revertEdit(withBases(e, b), cur(r1.text), blob, CTX);
      expect(r.kind, JSON.stringify(b)).toBe('strip');
    }
    // owner-edited with a perfect chain: never restored (manual, as before)
    expect(revertEdit(withBases({ ...e, ownerEdited: true }, [gitBlobSha(USER_WF)]), cur(r1.text), blob, CTX).kind).toBe('manual');
  });

  it('V6b I2: a verify job written twice is restored to the first original only over a full chain; a short or broken one gives the strip that keeps the owner\'s bytes', () => {
    const t = twoWrites(true);
    // the record's bases say the second write started from the owner's file (not W1): broken chain → the byte-exact strip, comments kept
    const broken = revertEdit(withBases(t.edit, [gitBlobSha(t.o1), gitBlobSha(t.o1.replace('jobs:\n', '# Production deploy. Owner: @alice\njobs:\n'))]), cur(t.w2), blob, CTX);
    expect(broken.kind).toBe('strip');
    expect((broken as { text: string }).text).toContain('# Production deploy. Owner: @alice');
    // short (one base for two writes) and missing: the same strip
    for (const b of [undefined, [gitBlobSha(t.o1)]] as ((string | null)[] | undefined)[]) {
      const r = revertEdit(withBases(t.edit, b), cur(t.w2), blob, CTX);
      expect(r.kind, JSON.stringify(b)).toBe('strip');
      expect((r as { text: string }).text).toContain('# Production deploy. Owner: @alice');
    }
    // a full chain from the original (no owner bytes between): the first original's own bytes back
    const c = twoWrites(false);
    // with no owner change between, the re-run's file is W1 again; a chain [O1, W1] over writtenShas [W1, W2] where W2 = insert(O1) = W1
    const chain = withBases({ ...c.edit, writtenShas: [gitBlobSha(c.w1), gitBlobSha(c.w2)] }, [gitBlobSha(c.o1), gitBlobSha(c.w1)]);
    expect(revertEdit(chain, cur(c.w2), blob, CTX)).toEqual({ kind: 'restore', text: c.o1 });
  });

  it('V6b I1: the package pair after two writes is restored only when both edits are chained; one unchained edit sends both to manual', () => {
    const o1 = '{\n  "name": "app",\n  "version": "1.0.0",\n  "devDependencies": {\n    "typescript": "5.4.0"\n  }\n}\n';
    const w1 = buildPackageJson(o1, { add: { c8: '12.0.0' }, setTest: false }) as string;
    // the second write: pipegen re-rendered the same file over its own first write (setTest only)
    const w2 = buildPackageJson(o1, { add: { c8: '12.0.0' }, setTest: true }) as string;
    const l1 = '{ "lockfileVersion": 3, "n": 1 }\n';
    const lw1 = '{ "lockfileVersion": 3, "n": 2 }\n';
    const lw2 = '{ "lockfileVersion": 3, "n": 3 }\n';
    for (const x of [o1, w1, w2, l1, lw1, lw2]) put(x);
    const json: Extract<InstallEdit, { kind: 'package-json' }> = { repo: 'app', path: 'package.json', kind: 'package-json', add: { c8: '12.0.0' }, setTest: true, lock: 'package-lock.json', originalSha: gitBlobSha(o1), writtenShas: [gitBlobSha(w1), gitBlobSha(w2)] };
    const lk: Extract<InstallEdit, { kind: 'package-lock' }> = { repo: 'app', path: 'package-lock.json', kind: 'package-lock', json: 'package.json', originalSha: gitBlobSha(l1), writtenShas: [gitBlobSha(lw1), gitBlobSha(lw2)] };
    const jc = withBases(json, [gitBlobSha(o1), gitBlobSha(w1)]);
    const lc = withBases(lk, [gitBlobSha(l1), gitBlobSha(lw1)]);
    expect(revertPair({ edit: jc, current: cur(w2) }, { edit: lc, current: cur(lw2) }, blob)).toEqual({ json: { kind: 'restore', text: o1 }, lock: { kind: 'restore', text: l1 } });
    // older records (no bases), short bases, a base that is the owner's blob (m4: a write based on itself): both manual
    const owner = put('{ "lockfileVersion": 3, "n": 99 }\n');
    for (const [j, l] of [
      [withBases(json, undefined), lc], [jc, withBases(lk, undefined)], [withBases(json, [gitBlobSha(o1)]), lc], [jc, withBases(lk, [gitBlobSha(l1)])],
      [jc, withBases(lk, [gitBlobSha(l1), owner])], [withBases(json, [gitBlobSha(o1), gitBlobSha(w2)]), lc],
    ] as [typeof json, typeof lk][]) {
      expect(kinds(revertPair({ edit: j, current: cur(w2) }, { edit: l, current: cur(lw2) }, blob))).toEqual(['manual', 'manual']);
    }
    // one write each: restored only with its base, never from an older record with none
    const one = withBases({ ...json, setTest: false, writtenShas: [gitBlobSha(w1)] }, [gitBlobSha(o1)]);
    const lone = withBases({ ...lk, writtenShas: [gitBlobSha(lw1)] }, [gitBlobSha(l1)]);
    expect(kinds(revertPair({ edit: one, current: cur(w1) }, { edit: lone, current: cur(lw1) }, blob))).toEqual(['restore', 'restore']);
    expect(kinds(revertPair({ edit: withBases(one, undefined), current: cur(w1) }, { edit: lone, current: cur(lw1) }, blob))).toEqual(['manual', 'manual']);
    expect(kinds(revertPair({ edit: one, current: cur(w1) }, { edit: withBases(lone, undefined), current: cur(lw1) }, blob))).toEqual(['manual', 'manual']);
    // a package.json with no lock: the same rule alone
    const solo = { ...one } as typeof one;
    delete (solo as { lock?: string }).lock;
    expect(revertEdit(solo, cur(w1), blob).kind).toBe('restore');
    expect(revertEdit(withBases(solo, undefined), cur(w1), blob).kind).toBe('manual');
  });
});

// ---------- row 24: the central run reverts with no app owner ----------

describe('V6b (G17 row 24): a Dependabot private entry is never pipegen\'s where no app owner is given', () => {
  it('V6b row 24: revertEdits with {} (central.ts) leaves a private Dependabot entry manual; with the app owner it strips', () => {
    const priv = dependabotEntryText({ profile: { private: true }, centralPin: { repo: 'acme/pipelines' } } as unknown as PipelineDraft);
    if (!/acme\/pipelines/.test(priv)) return expect.fail(`test setup: the private entry should name acme/pipelines:\n${priv}`);
    const head = 'version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n';
    const written = `${head}${priv}`;
    put(head);
    put(written);
    const e: InstallEdit = { repo: 'app', path: '.github/dependabot.yml', kind: 'dependabot', inserted: priv, originalSha: gitBlobSha(head), writtenShas: [gitBlobSha(written)] };
    const changed = `# mine\n${written}`;
    expect(revertEdits([e], () => cur(changed), blob, {})[0]?.result.kind).toBe('manual');
    expect(revertEdits([e], () => cur(changed), blob, { appOwner: 'acme' })[0]?.result.kind).toBe('strip');
    // central.ts: the one revertEdits call passes `{}` and takes only the codeowners edit of central
    const src = readFileSync(new URL('../src/uninstall/central.ts', import.meta.url), 'utf8');
    const calls = [...src.matchAll(/revertEdits\(([\s\S]*?)\);/g)].map((m) => m[1] ?? '');
    expect(calls.length).toBe(1);
    expect(calls[0]).toMatch(/,\s*\{\}\s*$/);
    expect(src).toMatch(/x\.repo === 'central' && x\.kind === 'codeowners'/);
  });
});

// ---------- m4: the central CODEOWNERS pipegen created ----------

async function afterRun1(w: World): Promise<void> {
  w.app.refs.set('heads/pipegen/uninstall', w.g.head(`o/${w.app.name}`));
  w.app.pulls.push({ number: 1, head: 'pipegen/uninstall', base: 'main', title: 'pipegen: uninstall', body: '', state: 'closed', html_url: `https://github.com/o/${w.app.name}/pull/1` });
  w.merged.set(`${w.app.name}#1`, '2026-11-06T10:00:00Z');
  const pf = await ProgressFile.open({ owner: 'o', repo: w.app.name }, w.app.id, local(w));
  pf.save({ phase: 'A-done', anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: w.g.head('o/pipelines'), recordBlobSha: blobSha(RECORD_TEXT) }, prNumber: 1, prUrl: `https://github.com/o/${w.app.name}/pull/1`, done: [], leftovers: [] });
}
const run = (w: World, rec: InstallRecord, t: Term = term(), over: Partial<StepDeps> = {}, lo: Partial<LoadedRecord> = {}): Promise<StepResult> =>
  uninstallStep(gh(w), loadedOf(w, rec, lo), t.p, deps(w, over));
const OWNERS_INS = '# pipegen:begin\n/.github/workflows/ @o\n# pipegen:end\n';
const OWNER_ADDS = `${OWNERS_INS}docs/ @bob\n`;
const prBranch = (w: World): string => `pipegen/uninstall-${w.app.name}`;
const filesAtPr = (w: World): Map<string, string> => w.g.filesAt('o/pipelines', w.g.head('o/pipelines', prBranch(w)));

function lastProject(w: World, onCentral: string, edit: InstallEdit): InstallRecord {
  w.g.commitOn('o/pipelines', 'main', { '.github/CODEOWNERS': onCentral });
  return sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true, codeowners: { path: '.github/CODEOWNERS', created: true } }, edits: [edit] });
}
const created = (written: string[], bases: (string | null)[] | undefined): InstallEdit =>
  withBases({ repo: 'central', path: '.github/CODEOWNERS', kind: 'codeowners', inserted: OWNERS_INS, originalSha: null, writtenShas: written }, bases);

describe('V6b (G17C m4): the central CODEOWNERS pipegen created is deleted whole only when its writes chain from null', () => {
  it('V6b m4: an older record holding the owner\'s blob as a write (bases [null, owner]) keeps the file and makes it a manual step', async () => {
    const w = world();
    const rec = lastProject(w, OWNER_ADDS, created([blobSha(OWNERS_INS), blobSha(OWNER_ADDS)], [null, blobSha(OWNER_ADDS)]));
    await afterRun1(w);
    const r = await run(w, rec);
    expect(filesAtPr(w).get('.github/CODEOWNERS')).toBe(OWNER_ADDS);
    expect(w.g.calls.some((c) => c.route === 'POST /repos/{owner}/{repo}/git/commits' && /CODEOWNERS/.test(String((c.params as { message?: unknown }).message)))).toBe(false);
    // central.ts itself makes it the owner's step (never a delete the target guard has to refuse: nothing failed)
    expect(r.manual.some((m) => /CODEOWNERS/.test(m.what) && /doesn't prove every version of this file pipegen created/.test(m.why))).toBe(true);
    expect(r.failed.filter((f) => /CODEOWNERS/.test(`${f.what} ${f.why}`))).toEqual([]);
  });

  it('V6b m4: no bases (an older record) or bases that skip a write: kept, manual, even when the file is exactly pipegen\'s last write', async () => {
    const earlier = blobSha('# earlier\n');
    for (const [written, bases] of [[[blobSha(OWNERS_INS)], undefined], [[earlier, blobSha(OWNERS_INS)], [null, SHA('7')]], [[earlier, blobSha(OWNERS_INS)], [null]]] as [string[], (string | null)[] | undefined][]) {
      const w = world();
      const rec = lastProject(w, OWNERS_INS, created(written, bases));
      await afterRun1(w);
      const r = await run(w, rec);
      expect(filesAtPr(w).get('.github/CODEOWNERS'), JSON.stringify(bases)).toBe(OWNERS_INS);
      expect(r.manual.some((m) => /CODEOWNERS/.test(m.what) && /doesn't prove every version of this file pipegen created/.test(m.why)), JSON.stringify(bases)).toBe(true);
      expect(r.failed.filter((f) => /CODEOWNERS/.test(`${f.what} ${f.why}`)), JSON.stringify(bases)).toEqual([]);
    }
  });

  it('V6b m4: a chain from null (bases [null], or [null, W1] for two writes) removes the file pipegen created', async () => {
    const earlier = '# pipegen:begin\n/.github/workflows/ @old\n# pipegen:end\n';
    for (const [written, bases] of [[[blobSha(OWNERS_INS)], [null]], [[blobSha(earlier), blobSha(OWNERS_INS)], [null, blobSha(earlier)]]] as [string[], (string | null)[]][]) {
      const w = world();
      const rec = lastProject(w, OWNERS_INS, created(written, bases));
      await afterRun1(w);
      await run(w, rec);
      expect(filesAtPr(w).has('.github/CODEOWNERS'), JSON.stringify(bases)).toBe(false);
    }
  });

  it('V6b-R1 m1: chain holds but the owner added a line after pipegen\'s last write: manual with the take-the-block-out step, no delete', async () => {
    const w = world();
    const rec = lastProject(w, OWNER_ADDS, created([blobSha(OWNERS_INS)], [null]));
    await afterRun1(w);
    const r = await run(w, rec);
    expect(filesAtPr(w).get('.github/CODEOWNERS')).toBe(OWNER_ADDS);
    expect(w.g.calls.some((c) => c.route === 'POST /repos/{owner}/{repo}/git/commits' && /CODEOWNERS/.test(String((c.params as { message?: unknown }).message)))).toBe(false);
    const m = r.manual.filter((x) => /CODEOWNERS/.test(x.what));
    expect(m.some((x) => /changed since pipegen last wrote it/.test(x.why) && /Take pipegen's block out of/.test(x.step ?? ''))).toBe(true);
    expect([...r.manual, ...r.failed].some((x) => /make that change by hand/.test(JSON.stringify(x)))).toBe(false);
    expect(r.failed.filter((f) => /CODEOWNERS/.test(`${f.what} ${f.why}`))).toEqual([]);
  });

  it('V6b-R1 L1: an ownerEdited created CODEOWNERS with a perfect chain is not deleted at the uninstall level', async () => {
    const w = world();
    const edit = { ...created([blobSha(OWNERS_INS)], [null]), ownerEdited: true } as InstallEdit;
    const rec = lastProject(w, OWNERS_INS, edit);
    await afterRun1(w);
    const r = await run(w, rec);
    expect(filesAtPr(w).get('.github/CODEOWNERS')).toBe(OWNERS_INS);
    expect(w.g.calls.some((c) => c.route === 'POST /repos/{owner}/{repo}/git/commits' && /CODEOWNERS/.test(String((c.params as { message?: unknown }).message)))).toBe(false);
    expect(r.manual.some((m) => /CODEOWNERS/.test(m.what) && /doesn't prove every version/.test(m.why))).toBe(true);
    expect(r.failed.filter((f) => /CODEOWNERS/.test(`${f.what} ${f.why}`))).toEqual([]);
  });

  it('V6b m4: after the merge, a kept created CODEOWNERS is named, and --delete-repos keeps central (not every file is pipegen\'s)', async () => {
    const w = world();
    const rec = lastProject(w, OWNER_ADDS, created([blobSha(OWNERS_INS), blobSha(OWNER_ADDS)], [null, blobSha(OWNER_ADDS)]));
    await afterRun1(w);
    const t = term();
    await run(w, rec, t, { deleteRepos: true, canDeleteRepos: true });
    mergePr(w, w.central, prBranch(w));
    const r2 = await run(w, rec, t, { deleteRepos: true, canDeleteRepos: true });
    expect(w.deleted).not.toContain('o/pipelines');
    expect([...r2.manual, ...r2.failed].some((m) => /CODEOWNERS/.test(`${m.what} ${m.why}`))).toBe(true);
    expect(w.g.filesAt('o/pipelines', w.g.head('o/pipelines')).get('.github/CODEOWNERS')).toBe(OWNER_ADDS);
    expect(writes(w).filter((x) => x === 'DELETE /repos/{owner}/{repo}')).toEqual([]);
  });
});

// ---------- row 34: blockFrom not a real day → unreadable, uninstall stops ----------

describe('V6b (G17 row 34): a record whose blockFrom is not a real day stops uninstall (fail closed)', () => {
  it('V6b row 34: blockFrom 2026-02-30, 0000-01-01 or a timestamp → stop "(at blockFrom)", nothing asked, nothing written', async () => {
    const SEC = ['sec', 'rets'].join('') as 'secrets';
    for (const bad of ['2026-02-30', '0000-01-01', '2026-11-05T00:00:00Z']) {
      for (const withLocal of [true, false]) {
        const g = new FakeGitHub();
        const app = g.addRepo('o/r', { private: true, files: { 'README.md': 'hi\n' } });
        g.addRepo('o/pipelines', { private: true, files: { 'README.md': 'central\n' } });
        const rec = {
          schema: 2, pipegenVersion: '0.2.0', createdAt: '2026-11-05T12:00:00.000Z', mergedAt: '2026-11-05T13:00:00Z', centralSha: SHA('c'),
          app: { owner: 'o', repo: 'r', repoId: app.id, defaultBranch: 'main', private: true, ownerType: 'User' }, name: 'r', serviceRoots: ['.'],
          files: [], edits: [], [SEC]: [], variables: [], environments: [], rulesets: [],
          planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] }, protectedPaths: [], blockFrom: '2026-11-12',
        } as unknown as InstallRecord;
        const text = canonicalRecordJson(rec).replace('"blockFrom":"2026-11-12"', `"blockFrom":${JSON.stringify(bad)}`);
        expect(text).toContain(bad);
        g.commitOn('o/pipelines', 'main', { [recordPath('r')]: `${text}\n` }, 'record');
        const { mkdtempSync, rmSync } = await import('node:fs');
        const { tmpdir } = await import('node:os');
        const { join } = await import('node:path');
        const home = mkdtempSync(join(tmpdir(), 'pg-v6b-'));
        try {
          if (withLocal) {
            const { writeLocalRecord } = await import('../src/deliver/record.js');
            await writeLocalRecord({ owner: 'o', repo: 'r' }, { recordHash: 'a'.repeat(64), updatedAt: 'x' }, { home, env: {} });
          }
          const asked: string[] = [];
          const io = { confirm: async () => { throw new Error('no confirm'); }, select: async () => { throw new Error('no select'); }, text: async (m: string) => { asked.push(m); return 'o/r'; } };
          const e = await loadUninstallRecord(g as unknown as Parameters<typeof loadUninstallRecord>[0], { owner: 'o', repo: 'r' }, { local: { home, env: {} }, io, interactive: true }).then(() => null, (x: unknown) => x);
          expect(e, `${bad} ${withLocal}`).toBeInstanceOf(UninstallError);
          expect((e as Error).message, bad).toMatch(/can't read the install record/);
          expect((e as Error).message, bad).toMatch(/blockFrom/);
          expect(asked).toEqual([]);
          expect(g.routes().filter((r) => !r.startsWith('GET '))).toEqual([]);
        } finally { rmSync(home, { recursive: true, force: true }); }
      }
    }
  });
});
