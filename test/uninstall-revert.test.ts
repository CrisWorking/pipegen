// v0.2 Plan V, Task V2: the revert engine (rulings V-S7, V-S8, V-N3, V-N11, V-B6; plan m6). Pure functions: texts and shas in, a result out.
import { describe, expect, it } from 'vitest';
import { gitBlobSha } from '../src/create/guard.js';
import { buildPackageJson } from '../src/create/package-edit.js';
import { codeownersBlock, codeownersFile, dependabotEntryText, hookBlock } from '../src/engine/created-builders.js';
import { renderHeadCheckStep } from '../src/engine/deploy-steps.js';
import { insertHeadChecks, insertVerify } from '../src/layers/deploy.js';
import type { Job } from '../src/layers/jobs.js';
import type { InstallEdit, PipelineDraft } from '../src/types.js';
import { revertEdit, revertEdits, revertPair, type RevertResult } from '../src/uninstall/revert.js';

const blobs = new Map<string, string>();
/** Stores a blob the way the repository's history holds it; returns its sha. */
const put = (text: string): string => { const sha = gitBlobSha(text); blobs.set(sha, text); return sha; };
const blob = (sha: string): string | null => blobs.get(sha) ?? null;
const noBlob = (): string | null => null;
const cur = (text: string): { text: string; sha: string } => ({ text, sha: gitBlobSha(text) });
const kind = (r: RevertResult): string => r.kind;
const textOf = (r: RevertResult): string => { if (r.kind !== 'strip' && r.kind !== 'restore') throw new Error(`expected a text, got ${JSON.stringify(r)}`); return r.text; };

type TextEdit = Extract<InstallEdit, { kind: 'codeowners' | 'hooks' | 'dependabot' }>;
/**
 * V6b (G17C-R1): an edit as deliver records it now, with the base of each write chained from the original (editWritesChained). A first
 * original is restored only over such a chain; an edit without bases is an older record that proves nothing.
 */
const based = <E extends InstallEdit>(e: E): E => ({ ...e, baseShas: e.writtenShas.map((_, n) => (n === 0 ? e.originalSha : e.writtenShas[n - 1])) }) as E;
type VerifyEdit = Extract<InstallEdit, { kind: 'verify-job' }>;
/** The record form of a text edit as deliver writes it: inserted = written minus the original prefix. */
function textEdit(kind: TextEdit['kind'], path: string, original: string | null, written: string, extra: Partial<TextEdit> = {}): TextEdit {
  const o = original ?? '';
  if (!written.startsWith(o)) throw new Error('test setup: written must start with the original');
  if (original !== null) put(original);
  put(written);
  return based({ repo: 'app', path, kind, inserted: written.slice(o.length), originalSha: original === null ? null : gitBlobSha(original), writtenShas: [gitBlobSha(written)], ...extra } as TextEdit);
}

const VERIFY = { 'runs-on': 'ubuntu-24.04', steps: [renderHeadCheckStep('main'), { id: 'pipegen-find', name: 'pipegen: find', run: 'echo find' }] } as unknown as Job;
const WF = '.github/workflows/deploy.yml';
/** The record form of a verify-job edit from deploy's own insert (what deliver records). */
function verifyEdit(original: string, gated: string[], needsOnly: string[] = []): { edit: VerifyEdit; written: string } {
  const r = insertVerify(original, gated, VERIFY, needsOnly);
  put(original);
  put(r.text);
  const heads = r.inserted.headCheck ?? [];
  return { written: r.text, edit: based({ repo: 'app', path: WF, kind: 'verify-job', jobs: [...r.inserted.jobs], needs: r.inserted.needs.map((n) => ({ job: n.job, added: [...n.added] })), ...(heads.length > 0 ? { headCheck: heads } : {}), originalSha: gitBlobSha(original), writtenShas: [gitBlobSha(r.text)] } as VerifyEdit) };
}
const CTX = { defaultBranch: 'main' };

const USER_WF = [
  'name: deploy  # the owner\'s comment',
  'on:',
  '  push:',
  '    branches: [main]',
  'jobs:',
  '  lint:',
  '    runs-on: ubuntu-latest',
  '    steps:',
  '      - run: npm run lint',
  '  build:',
  '    runs-on: ubuntu-latest',
  '    needs: lint',
  '    steps:',
  '      - run: npm run build',
  '  test:',
  '    runs-on: ubuntu-latest',
  '    needs: [lint, build]',
  '    steps:',
  '      - run: npm test',
  '  deploy:',
  '    runs-on: ubuntu-latest',
  '    needs:',
  '      - build',
  '      - test',
  '    steps:',
  '      - run: ./deploy.sh   # ship it',
  '',
].join('\n');
const EXTRA_JOB = '  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo extra\n';

describe('V2: the revert engine', () => {
  it('plan: verify job revert only removes pipegen-verify job and needs entries', () => {
    // all four gated without the head check (needs only), so this case is the job and the needs alone
    const { edit, written } = verifyEdit(USER_WF, ['lint', 'build', 'test', 'deploy'], ['lint', 'build', 'test', 'deploy']);
    expect(edit.headCheck).toBeUndefined();
    expect(written).toContain('needs: [pipegen-verify]');   // lint had none
    expect(written).toContain('needs: [lint, pipegen-verify]');   // build's scalar
    expect(written).toContain('needs: [lint, build, pipegen-verify]');
    expect(written).toContain('      - pipegen-verify\n');
    // the owner added a job after pipegen's and changed a line of their own since
    const changed = `${written.replace('npm test', 'npm test -- --ci')}${EXTRA_JOB}`;
    const r = revertEdit(edit, cur(changed), blob, CTX);
    expect(kind(r)).toBe('strip');
    // exactly the owner's file with the owner's two changes: the scalar `needs: lint` and the absent needs come back as they were
    expect(textOf(r)).toBe(`${USER_WF.replace('npm test', 'npm test -- --ci')}${EXTRA_JOB}`);
    // without the original blob the needs keep their list form (the same jobs for GitHub), and nothing else changes
    const blind = textOf(revertEdit(edit, cur(changed), (s) => (s === edit.originalSha ? null : blob(s)), CTX));
    expect(blind).toBe(`${USER_WF.replace('npm test', 'npm test -- --ci').replace('    needs: lint\n', '    needs: [lint]\n')}${EXTRA_JOB}`);
    // the owner made their own job wait for pipegen-verify: not in the record, so the file is left for manual review
    const own = changed.replace(EXTRA_JOB, EXTRA_JOB.replace('    runs-on', '    needs: [pipegen-verify]\n    runs-on'));
    expect(own).toContain('extra:\n    needs: [pipegen-verify]');
    expect(kind(revertEdit(edit, cur(own), blob, CTX))).toBe('manual');
    // the owner changed pipegen's job: it is no longer the job pipegen wrote, so it is not removed
    const job = written.replace('echo find', 'echo find; ./mine.sh');
    expect(kind(revertEdit(edit, cur(`${job}${EXTRA_JOB}`), blob, CTX))).toBe('manual');
    // a needs entry put in another place than pipegen's (first in a flow list) is not pipegen's form: manual
    const moved = changed.replace('needs: [lint, build, pipegen-verify]', 'needs: [pipegen-verify, lint, build]');
    expect(kind(revertEdit(edit, cur(moved), blob, CTX))).toBe('manual');
    // an anchor in a touched job: manual, never cut
    const anchored = changed.replace('    needs: [lint, pipegen-verify]', '    needs: &n [lint, pipegen-verify]');
    expect(kind(revertEdit(edit, cur(anchored), blob, CTX))).toBe('manual');
    // a comment the owner put on pipegen's needs line, or spacing changed inside pipegen's flow entry: the owner's bytes, manual
    expect(kind(revertEdit(edit, cur(changed.replace('      - pipegen-verify\n', '      - pipegen-verify   # keep\n')), blob, CTX))).toBe('manual');
    expect(kind(revertEdit(edit, cur(changed.replace('[lint, build, pipegen-verify]', '[lint, build,  pipegen-verify]')), blob, CTX))).toBe('manual');
    // the owner cut lint down to its needs line alone: taking that line out would leave the job empty, which is not the owner's file minus pipegen's part
    const bare = changed.replace('  lint:\n    needs: [pipegen-verify]\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm run lint\n', '  lint:\n    needs: [pipegen-verify]\n');
    expect(bare).not.toBe(changed);
    expect(kind(revertEdit(edit, cur(bare), blob, CTX))).toBe('manual');
    // a comment the owner put inside pipegen's job is the owner's text: manual
    const commented = changed.replace('runs-on: ubuntu-24.04', 'runs-on: ubuntu-24.04  # mine');
    expect(kind(revertEdit(edit, cur(commented), blob, CTX))).toBe('manual');
    // the version pipegen wrote can't be read: its job can't be compared, so manual
    expect(kind(revertEdit(edit, cur(changed), (s) => (s === edit.writtenShas[0] ? null : blob(s)), CTX))).toBe('manual');
    // CRLF files keep CRLF
    const crlf = verifyEdit(USER_WF.replace(/\n/g, '\r\n'), ['deploy'], ['deploy']);
    const crlfChanged = `${crlf.written}${EXTRA_JOB.replace(/\n/g, '\r\n')}`;
    expect(textOf(revertEdit(crlf.edit, cur(crlfChanged), blob, CTX))).toBe(`${USER_WF}${EXTRA_JOB}`.replace(/\n/g, '\r\n'));
  });

  it('plan: text edit removed only when it occurs once at a line start; else manual review with the exact text', () => {
    const original = '* @alice\n';
    const block = codeownersBlock(['.github/workflows/**', 'trivy.yaml'], ['@secops']);
    const written = codeownersFile(original, block);
    const e = textEdit('codeowners', '.github/CODEOWNERS', original, written);
    expect(e.inserted).toBe(`\n${block}`);
    // the owner added a rule above: pipegen's block alone goes, the owner's rule stays
    expect(textOf(revertEdit(e, cur(`docs/ @bob\n${written}`), blob))).toBe(`docs/ @bob\n${original}`);
    // twice: manual with the exact text
    const twice = revertEdit(e, cur(`${written}${e.inserted}`), blob);
    expect(twice).toEqual({ kind: 'manual', why: expect.stringMatching(/twice|more than once/), remove: e.inserted });
    // gone: manual with the exact text
    expect(revertEdit(e, cur('* @carol\n'), blob)).toMatchObject({ kind: 'manual', remove: e.inserted });
    // not at a line start (the owner's text runs into it): manual
    const rerun = textEdit('codeowners', 'CODEOWNERS', '', block);   // a re-run's in-place form: the block alone
    const replaced: TextEdit = { ...rerun, originalSha: put('x @a\n') };
    expect(revertEdit(replaced, cur(`x @a\nfoo ${block}`), blob)).toMatchObject({ kind: 'manual', remove: block });
    expect(textOf(revertEdit(replaced, cur(`x @a\n${block}y @b\n`), blob))).toBe('x @a\ny @b\n');
    // an original with no newline at its end: the insert starts with the newline; removed only at the end of the file
    const bare = '* @alice';
    const w2 = codeownersFile(bare, block);
    const e2 = textEdit('codeowners', 'CODEOWNERS', bare, w2);
    expect(textOf(revertEdit(e2, cur(`# top\n${w2}`), blob))).toBe(`# top\n${bare}`);
    expect(kind(revertEdit(e2, cur(`${w2}z @c\n`), blob))).toBe('manual');   // removing it would join the owner's two lines
    // hooks (husky) and dependabot, the same rule
    const husky = '#!/usr/bin/env sh\nnpm test\n';
    const hb = hookBlock('husky', [{ id: 'biome', run: 'npx --no --package=@biomejs/biome@1.9.4 biome check --staged' }]);
    const he = textEdit('hooks', '.husky/pre-commit', husky, `${husky}${hb}`);
    expect(textOf(revertEdit(he, cur(`${husky}${hb}echo done\n`), blob))).toBe(`${husky}echo done\n`);
    expect(kind(revertEdit(he, cur(`${husky}${hb}${hb}`), blob))).toBe('manual');
    // pre-commit at indentation 2, and lefthook
    const cmds = [{ id: 'biome', run: 'npx biome check' }, { id: 'pipegen-secrets', run: 'npx --no pipegen hooks secrets' }];
    const pc = 'repos:\n  - repo: https://github.com/x/y\n    rev: v1\n    hooks:\n      - id: z\n';
    const pcb = hookBlock('pre-commit', cmds, '  ');
    const pe = textEdit('hooks', '.pre-commit-config.yaml', pc, `${pc}${pcb}`);
    expect(textOf(revertEdit(pe, cur(`# top\n${pc}${pcb}`), blob))).toBe(`# top\n${pc}`);
    expect(kind(revertEdit({ ...pe, inserted: hookBlock('pre-commit', cmds, '    ') }, cur(`${pc}${hookBlock('pre-commit', cmds, '    ')}x\n`), blob))).toBe('manual');   // not an indentation pipegen writes
    const lh = 'pre-push:\n  commands:\n    t:\n      run: npm test\n';
    const lhb = hookBlock('lefthook', cmds);
    const le = textEdit('hooks', 'lefthook.yml', lh, `${lh}${lhb}`);
    expect(textOf(revertEdit(le, cur(`${lh}${lhb}# mine\n`), blob))).toBe(`${lh}# mine\n`);
    const dep = 'version: 2\nupdates:\n  - package-ecosystem: "npm"\n    directory: "/"\n    schedule:\n      interval: "daily"\n';
    const draft ={ profile: { private: true }, centralPin: { repo: 'acme/pipelines' } } as unknown as PipelineDraft;
    const de = textEdit('dependabot', '.github/dependabot.yml', dep, `${dep}${dependabotEntryText(draft)}`);
    expect(textOf(revertEdit(de, cur(`# mine\n${dep}${dependabotEntryText(draft)}`), blob, { appOwner: 'acme' }))).toBe(`# mine\n${dep}`);   // G17C-R1: the private form needs the app owner
  });

  it("plan: edit not in pipegen's builder form → manual review, never removed", () => {
    const original = '* @alice\n';
    // codeowners without the gate markers, even with the file exactly as recorded
    const noMarks = textEdit('codeowners', 'CODEOWNERS', original, `${original}src/** @evil\n`);
    for (const c of [cur(`${original}src/** @evil\n`), cur(`x\n${original}src/** @evil\n`)]) {
      const r = revertEdit(noMarks, c, blob);
      expect(r.kind).toBe('manual');
      expect(r).not.toHaveProperty('remove');
    }
    const rules = textEdit('codeowners', 'CODEOWNERS', original, `${original}a @x\nb @y\nc @z\n`);
    expect(kind(revertEdit(rules, cur(`q @q\n${original}a @x\nb @y\nc @z\n`), blob))).toBe('manual');
    // codeowners at a path no rule claims
    const block = codeownersBlock(['a.yml'], ['@o']);
    expect(kind(revertEdit(textEdit('codeowners', 'src/CODEOWNERS', original, codeownersFile(original, block)), cur(codeownersFile(original, block)), blob))).toBe('manual');
    // a hooks block that isn't hookBlock's: another command line form, another marker note, a path that is no hook file
    const husky = '#!/usr/bin/env sh\nnpm test\n';
    const forged = '# pipegen:hooks begin: pipegen\'s reviewed hooks; the install record holds this text\nnpm test\n# pipegen:hooks end\n';
    expect(kind(revertEdit(textEdit('hooks', '.husky/pre-commit', husky, `${husky}${forged}`), cur(`${husky}${forged}`), blob))).toBe('manual');
    const hb = hookBlock('husky', [{ id: 'biome', run: 'npx biome check' }]);
    expect(kind(revertEdit(textEdit('hooks', '.husky/pre-commit', husky, `${husky}${hb.replace('reviewed', 'own')}`), cur(`${husky}${hb.replace('reviewed', 'own')}`), blob))).toBe('manual');
    expect(kind(revertEdit(textEdit('hooks', 'scripts/pre-commit', husky, `${husky}${hb}`), cur(`${husky}${hb}`), blob))).toBe('manual');
    // a dependabot entry not dependabotFile's shape
    const dep = 'version: 2\nupdates:\n  - package-ecosystem: "npm"\n    directory: "/"\n';
    const pub = dependabotEntryText({ profile: { private: false } } as unknown as PipelineDraft);
    const odd = pub.replace('"weekly"', '"daily"');
    expect(kind(revertEdit(textEdit('dependabot', '.github/dependabot.yml', dep, `${dep}${odd}`), cur(`${dep}${odd}`), blob))).toBe('manual');
    expect(kind(revertEdit(textEdit('dependabot', '.github/dependabot.yml', dep, `${dep}${pub}`), cur(`${dep}${pub}`), blob))).toBe('restore');   // the real shape: fine
    // verify jobs not named pipegen-verify, or needs entries other than pipegen-verify
    const { edit, written } = verifyEdit(USER_WF, ['deploy'], ['deploy']);
    expect(kind(revertEdit({ ...edit, jobs: ['deploy'] }, cur(written), blob, CTX))).toBe('manual');
    expect(kind(revertEdit({ ...edit, needs: [{ job: 'deploy', added: ['test'] }] }, cur(written), blob, CTX))).toBe('manual');
    expect(kind(revertEdit({ ...edit, path: 'deploy.yml' }, cur(written), blob, CTX))).toBe('manual');
    expect(kind(revertEdit(edit, cur(written), blob, CTX))).toBe('restore');   // the real form: fine
  });

  it('plan: unchanged edited file restored byte-exact from its original blob sha', () => {
    const original = '# owners\r\n*\t@alice   \n\n';   // odd bytes are kept exactly
    const block = codeownersBlock(['trivy.yaml'], ['@o']);
    const e = textEdit('codeowners', '.github/CODEOWNERS', original, codeownersFile(original, block));
    expect(revertEdit(e, cur(codeownersFile(original, block)), blob)).toEqual({ kind: 'restore', text: original });
    // the original blob can't be read, or is not the blob of that sha: no restore (the strip still takes pipegen's text out exactly)
    const lying = (s: string): string | null => (s === e.originalSha ? 'something else\n' : blob(s));
    expect(revertEdit(e, cur(codeownersFile(original, block)), lying)).toEqual({ kind: 'strip', text: original });
    // a record whose originalSha names another blob restores nothing of it: the current text is not that blob plus pipegen's part
    const other: TextEdit = { ...e, originalSha: put('* @mallory\n') };
    expect(revertEdit(other, cur(codeownersFile(original, block)), blob)).toEqual({ kind: 'strip', text: original });
    // the current text is not the blob of the sha the caller gave: manual
    expect(kind(revertEdit(e, { text: codeownersFile(original, block), sha: gitBlobSha('x') }, blob))).toBe('manual');
    // the current sha is not the last one pipegen wrote: never a restore
    const older: TextEdit = { ...e, writtenShas: [e.writtenShas[0] as string, gitBlobSha('later')] };
    expect(kind(revertEdit(older, cur(codeownersFile(original, block)), blob))).toBe('strip');
    // verify-job: the owner's original workflow back, byte for byte
    const { edit, written } = verifyEdit(USER_WF, ['build', 'deploy'], ['build']);
    expect(revertEdit(edit, cur(written), blob, CTX)).toEqual({ kind: 'restore', text: USER_WF });
    const otherWf: VerifyEdit = { ...edit, originalSha: put(USER_WF.replace('./deploy.sh', './steal.sh')) };
    expect(kind(revertEdit(otherWf, cur(written), blob, CTX))).toBe('strip');
    expect(kind(revertEdit(edit, cur(written), (s) => (s === edit.originalSha ? null : blob(s)), CTX))).toBe('strip');
  });

  it('plan: package.json and package-lock.json reverted together or not at all; lock only when its sha is one pipegen wrote', () => {
    const pj = '{\n  "name": "app",\n  "devDependencies": {\n    "vitest": "5.0.5"\n  }\n}\n';
    const pjNew = buildPackageJson(pj, { add: { c8: '12.0.0' }, setTest: false }) as string;
    expect(pjNew).toContain('"c8": "12.0.0"');
    const lock = '{ "lockfileVersion": 3, "packages": {} }\n';
    const lockNew = '{ "lockfileVersion": 3, "packages": { "node_modules/@biomejs/biome": {} } }\n';
    for (const t of [pj, pjNew, lock, lockNew]) put(t);
    const json: Extract<InstallEdit, { kind: 'package-json' }> = based({ repo: 'app', path: 'package.json', kind: 'package-json', add: { c8: '12.0.0' }, setTest: false, lock: 'package-lock.json', originalSha: gitBlobSha(pj), writtenShas: [gitBlobSha(pjNew)] });
    const lk: Extract<InstallEdit, { kind: 'package-lock' }> = based({ repo: 'app', path: 'package-lock.json', kind: 'package-lock', json: 'package.json', originalSha: gitBlobSha(lock), writtenShas: [gitBlobSha(lockNew)] });
    // both unchanged: both restored
    expect(revertPair({ edit: json, current: cur(pjNew) }, { edit: lk, current: cur(lockNew) }, blob)).toEqual({ json: { kind: 'restore', text: pj }, lock: { kind: 'restore', text: lock } });
    // either changed, or gone: both manual
    const bothManual = (r: { json: RevertResult; lock: RevertResult | null }): void => { expect(r.json.kind).toBe('manual'); expect(r.lock?.kind).toBe('manual'); };
    bothManual(revertPair({ edit: json, current: cur(`${pjNew} `) }, { edit: lk, current: cur(lockNew) }, blob));
    bothManual(revertPair({ edit: json, current: cur(pjNew) }, { edit: lk, current: cur(`${lockNew} `) }, blob));
    bothManual(revertPair({ edit: json, current: cur(pjNew) }, { edit: lk, current: null }, blob));
    // the lock's sha is one pipegen wrote earlier, not the last: manual
    const lk2 = { ...lk, writtenShas: [gitBlobSha(lockNew), gitBlobSha('newer')] };
    bothManual(revertPair({ edit: json, current: cur(pjNew) }, { edit: lk2, current: cur(lockNew) }, blob));
    // the pair is not the record's pair: manual
    bothManual(revertPair({ edit: json, current: cur(pjNew) }, { edit: { ...lk, json: 'web/package.json' }, current: cur(lockNew) }, blob));
    // the package.json edit doesn't read as the recorded one: manual
    bothManual(revertPair({ edit: { ...json, add: { other: '1.0.0' } }, current: cur(pjNew) }, { edit: lk, current: cur(lockNew) }, blob));
    // a blob reader that hands back another text for a sha: never restored
    bothManual(revertPair({ edit: json, current: cur(pjNew) }, { edit: lk, current: cur(lockNew) }, (s) => (s === lk.originalSha ? '{}\n' : blob(s))));
    // the lock's original can't be read: manual (never the package.json alone)
    bothManual(revertPair({ edit: json, current: cur(pjNew) }, { edit: lk, current: cur(lockNew) }, (s) => (s === lk.originalSha ? null : blob(s))));
    // a recorded lock that isn't given: manual
    expect(revertPair({ edit: json, current: cur(pjNew) }, null, blob).json.kind).toBe('manual');
    // one at a time through revertEdit: never
    expect(kind(revertEdit(lk, cur(lockNew), blob))).toBe('manual');
    expect(kind(revertEdit(json, cur(pjNew), blob))).toBe('manual');
    // a package.json edit with no lock in the record: alone is its whole pair
    const solo = { ...json, lock: undefined };
    delete solo.lock;
    expect(revertEdit(solo, cur(pjNew), blob)).toEqual({ kind: 'restore', text: pj });
    // revertEdits pairs them from the record
    const all = revertEdits([lk, json], (e) => (e.path === 'package.json' ? cur(pjNew) : cur(lockNew)), blob, CTX);
    expect(all.map((x) => [x.edit.path, x.result.kind])).toEqual([['package-lock.json', 'restore'], ['package.json', 'restore']]);
    const half = revertEdits([lk, json], (e) => (e.path === 'package.json' ? cur(pjNew) : null), blob, CTX);
    expect(half.map((x) => x.result.kind)).toEqual(['manual', 'manual']);
  });

  it('revert: head check removed only from the recorded headCheck jobs and only when it is pipegen\'s step', () => {
    // deploy takes the head check; build waits with needs only
    const { edit, written } = verifyEdit(USER_WF, ['build', 'deploy'], ['build']);
    expect(edit.headCheck).toEqual(['deploy']);
    const changed = `${written}${EXTRA_JOB}`;
    expect(textOf(revertEdit(edit, cur(changed), blob, CTX))).toBe(`${USER_WF}${EXTRA_JOB}`);
    // the owner changed pipegen's step: manual
    const touched = changed.replace('pg_fail "the deployed commit is not a 40-character commit"', 'pg_fail "nope"');
    expect(touched).not.toBe(changed);
    expect(kind(revertEdit(edit, cur(touched), blob, CTX))).toBe('manual');
    // a job the record doesn't list keeps its first step: build's own first step is never taken, even if the record lists it
    const r = revertEdit({ ...edit, headCheck: ['deploy', 'build'] }, cur(changed), blob, CTX);
    expect(kind(r)).toBe('manual');
    // another default branch renders another step: not pipegen's step for this branch, manual
    expect(kind(revertEdit(edit, cur(changed), blob, { defaultBranch: 'trunk' }))).toBe('manual');
    expect(kind(revertEdit(edit, cur(changed), blob, {}))).toBe('manual');
    // V-N11: the record lacks headCheck but the file holds pipegen's head check: manual
    const { headCheck: _h, ...noHead } = edit;
    expect(kind(revertEdit(noHead as VerifyEdit, cur(changed), blob, CTX))).toBe('manual');
    // a called workflow (jobs: []): only the head checks come out
    const called = 'on:\n  workflow_call:\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./ship.sh\n  notify:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./notify.sh\n';
    const c = insertHeadChecks(called, [WF], VERIFY);
    put(called);
    put(c.text);
    const ce: VerifyEdit = based({ repo: 'app', path: '.github/workflows/ship.yml', kind: 'verify-job', jobs: [], needs: [], headCheck: c.inserted.headCheck ?? [], originalSha: gitBlobSha(called), writtenShas: [gitBlobSha(c.text)] });
    expect(ce.headCheck).toEqual(['ship', 'notify']);
    const cc = c.text.replace('./notify.sh', './notify.sh --loud');
    expect(textOf(revertEdit(ce, cur(cc), blob, CTX))).toBe(called.replace('./notify.sh', './notify.sh --loud'));
    expect(revertEdit(ce, cur(c.text), blob, CTX)).toEqual({ kind: 'restore', text: called });
    // the owner deleted their own step: pipegen's step would leave the job with none, manual
    expect(kind(revertEdit(ce, cur(cc.replace('      - run: ./ship.sh\n', '')), blob, CTX))).toBe('manual');
  });

  it('revert: ownerEdited edit → manual review', () => {
    const original = '* @alice\n';
    const block = codeownersBlock(['trivy.yaml'], ['@o']);
    const e = textEdit('codeowners', 'CODEOWNERS', original, codeownersFile(original, block), { ownerEdited: true });
    // unchanged by sha, and pipegen's text right there: still manual
    expect(revertEdit(e, cur(codeownersFile(original, block)), blob)).toMatchObject({ kind: 'manual', remove: e.inserted });
    const { edit, written } = verifyEdit(USER_WF, ['deploy']);
    expect(kind(revertEdit({ ...edit, ownerEdited: true }, cur(written), blob, CTX))).toBe('manual');
    const newFile = textEdit('codeowners', 'CODEOWNERS', null, block, { ownerEdited: true });
    expect(kind(revertEdit(newFile, cur(block), blob))).toBe('manual');
    const pj = '{\n  "name": "a"\n}\n';
    const pjNew = buildPackageJson(pj, { add: { c8: '12.0.0' }, setTest: false }) as string;
    put(pj); put(pjNew);
    const json: Extract<InstallEdit, { kind: 'package-json' }> = based({ repo: 'app', path: 'package.json', kind: 'package-json', add: { c8: '12.0.0' }, setTest: false, originalSha: gitBlobSha(pj), writtenShas: [gitBlobSha(pjNew)] });
    expect(revertEdit(json, cur(pjNew), blob).kind).toBe('restore');
    expect(revertEdit({ ...json, ownerEdited: true }, cur(pjNew), blob).kind).toBe('manual');
  });

  it('revert: new file (originalSha null) unchanged → deleted; changed → manual', () => {
    const block = codeownersBlock(['trivy.yaml'], ['@o']);
    const e = textEdit('codeowners', '.github/CODEOWNERS', null, block);
    expect(e.originalSha).toBeNull();
    expect(revertEdit(e, cur(block), blob)).toEqual({ kind: 'delete' });
    // changed: manual, even when pipegen's text is still found once at a line start
    expect(revertEdit(e, cur(`docs/ @bob\n${block}`), blob)).toMatchObject({ kind: 'manual', remove: block });
    // a new husky script (pipegen wrote the shebang too) and a new dependabot file, the same
    const hb = hookBlock('husky', [{ id: 'biome', run: 'npx biome check' }]);
    const h = textEdit('hooks', '.husky/pre-commit', null, `#!/usr/bin/env sh\n${hb}`);
    expect(revertEdit(h, cur(`#!/usr/bin/env sh\n${hb}`), blob)).toEqual({ kind: 'delete' });
    expect(kind(revertEdit(h, cur(`#!/usr/bin/env sh\n${hb}echo mine\n`), blob))).toBe('manual');
    const pre = hookBlock('pre-commit', [{ id: 'biome', run: 'npx biome check' }]);
    expect(revertEdit(textEdit('hooks', '.pre-commit-config.yaml', null, `repos:\n${pre}`), cur(`repos:\n${pre}`), blob)).toEqual({ kind: 'delete' });
    const dep = `version: 2\nupdates:\n${dependabotEntryText({ profile: { private: false } } as unknown as PipelineDraft)}`;
    expect(revertEdit(textEdit('dependabot', '.github/dependabot.yaml', null, dep), cur(dep), blob)).toEqual({ kind: 'delete' });
    // the last version pipegen wrote is not the recorded text alone (a record that doesn't match the file): manual, never deleted
    const grown = `${block}x @y\n`;
    expect(kind(revertEdit({ ...e, writtenShas: [put(grown)] }, cur(grown), blob))).toBe('manual');
    // the current sha is an older one pipegen wrote: changed, manual
    expect(kind(revertEdit({ ...e, writtenShas: [gitBlobSha(block), gitBlobSha('x')] }, cur(block), blob))).toBe('manual');
  });

  // ---------- fix round 1 (V2-R1): the reviewers' probes ----------

  it('V2-R1 1: the package pair is restored only after one write each and when the package.json is the original rebuilt with the recorded edit', () => {
    const o1 = '{\n  "name": "app",\n  "version": "1.0.0",\n  "devDependencies": {\n    "typescript": "5.4.0"\n  }\n}\n';
    const w1 = buildPackageJson(o1, { add: { c8: '12.0.0' }, setTest: false }) as string;
    // P1: the owner uninstalled c8, bumped the version, added express; the re-run added c8 again on top
    const owner = '{\n  "name": "app",\n  "version": "2.3.0",\n  "dependencies": {\n    "express": "5.0.0"\n  },\n  "devDependencies": {\n    "typescript": "5.6.0"\n  }\n}\n';
    const w2 = buildPackageJson(owner, { add: { c8: '12.0.0' }, setTest: false }) as string;
    const l1 = '{ "lockfileVersion": 3, "n": 1 }\n';
    const lw1 = '{ "lockfileVersion": 3, "n": 2 }\n';
    const lw2 = '{ "lockfileVersion": 3, "n": 3 }\n';
    for (const t of [o1, w1, owner, w2, l1, lw1, lw2]) put(t);
    const json: Extract<InstallEdit, { kind: 'package-json' }> = { repo: 'app', path: 'package.json', kind: 'package-json', add: { c8: '12.0.0' }, setTest: false, lock: 'package-lock.json', originalSha: gitBlobSha(o1), writtenShas: [gitBlobSha(w1), gitBlobSha(w2)] };
    const lk: Extract<InstallEdit, { kind: 'package-lock' }> = { repo: 'app', path: 'package-lock.json', kind: 'package-lock', json: 'package.json', originalSha: gitBlobSha(l1), writtenShas: [gitBlobSha(lw1), gitBlobSha(lw2)] };
    const r = revertPair({ edit: json, current: cur(w2) }, { edit: lk, current: cur(lw2) }, blob);
    expect([r.json.kind, r.lock?.kind]).toEqual(['manual', 'manual']);
    // one write each, but the record's original isn't the file the current one was built from (it differs outside devDependencies)
    const older = '{\n  "name": "app",\n  "version": "0.9.0",\n  "devDependencies": {\n    "typescript": "5.4.0"\n  }\n}\n';
    const one = { ...json, originalSha: put(older), writtenShas: [gitBlobSha(w1)] };
    const r2 = revertPair({ edit: one, current: cur(w1) }, { edit: { ...lk, writtenShas: [gitBlobSha(lw1)] }, current: cur(lw1) }, blob);
    expect([r2.json.kind, r2.lock?.kind]).toEqual(['manual', 'manual']);
    // the honest single-write pair: restored
    // V6b (G17C-R1): with the base of its one write recorded (deliver's record today)
    const r3 = revertPair({ edit: based({ ...json, writtenShas: [gitBlobSha(w1)] }), current: cur(w1) }, { edit: based({ ...lk, writtenShas: [gitBlobSha(lw1)] }), current: cur(lw1) }, blob);
    expect(r3).toEqual({ json: { kind: 'restore', text: o1 }, lock: { kind: 'restore', text: l1 } });
    // only the package.json was written twice: both manual
    const r4 = revertPair({ edit: { ...json, writtenShas: [gitBlobSha(w2), gitBlobSha(w1)] }, current: cur(w1) }, { edit: { ...lk, writtenShas: [gitBlobSha(lw1)] }, current: cur(lw1) }, blob);
    expect([r4.json.kind, r4.lock?.kind]).toEqual(['manual', 'manual']);
  });

  it('V2-R1 2: a verify-job file written twice is stripped, never restored to the first original', () => {
    // P2: the owner took pipegen's part out by hand, added comments and moved keys; the re-run inserted again
    const ownerWf = USER_WF.replace('jobs:\n', '# Production deploy. Owner: @alice\njobs:\n').replace('      - run: ./deploy.sh   # ship it\n', '      - run: ./deploy.sh   # deploys to prod; see RUNBOOK.md\n');
    const first = verifyEdit(USER_WF, ['deploy']);
    const second = insertVerify(ownerWf, ['deploy'], VERIFY);
    put(second.text);
    const e: VerifyEdit = { ...first.edit, writtenShas: [gitBlobSha(first.written), gitBlobSha(second.text)] };
    const r = revertEdit(e, cur(second.text), blob, CTX);
    expect(r).toEqual({ kind: 'strip', text: ownerWf });
  });

  it("V2-R1 3: a YAML hook or Dependabot strip that would re-parent the owner's lines is manual", () => {
    const cmds = [{ id: 'biome', run: 'npx biome check' }];
    // P3 lefthook: the owner's command under pipegen's pre-commit key would become a pre-push command
    const lh = 'pre-push:\n  commands:\n    t:\n      run: npm test\n';
    const lhb = hookBlock('lefthook', cmds);
    const le = textEdit('hooks', 'lefthook.yml', lh, `${lh}${lhb}`);
    expect(revertEdit(le, cur(`${lh}${lhb}    typecheck:\n      run: tsc\n`), blob)).toMatchObject({ kind: 'manual', remove: lhb });
    // P5 pre-commit: the owner's local hook under pipegen's repo would become a hook of the remote repo
    const pc = 'repos:\n  - repo: https://github.com/x/y\n    rev: v1\n    hooks:\n      - id: z\n';
    const pcb = hookBlock('pre-commit', cmds, '  ');
    const pe = textEdit('hooks', '.pre-commit-config.yaml', pc, `${pc}${pcb}`);
    const mine = '      - id: mine\n        name: mine\n        entry: ./mine.sh\n        language: system\n';
    expect(revertEdit(pe, cur(`${pc}${pcb}${mine}`), blob)).toMatchObject({ kind: 'manual', remove: pcb });
    // P4a dependabot: pipegen added `updates:`; the owner's npm entry under it would dangle after the strip
    const pub = dependabotEntryText({ profile: { private: false } } as unknown as PipelineDraft);
    const v2 = 'version: 2\n';
    const de = textEdit('dependabot', '.github/dependabot.yml', v2, `${v2}updates:\n${pub}`);
    const npmEntry = '  - package-ecosystem: "npm"\n    directory: "/"\n    schedule:\n      interval: "daily"\n';
    expect(revertEdit(de, cur(`${v2}updates:\n${pub}${npmEntry}`), blob)).toMatchObject({ kind: 'manual', remove: `updates:\n${pub}` });
    expect(textOf(revertEdit(de, cur(`# top\n${v2}updates:\n${pub}`), blob))).toBe(`# top\n${v2}`);
    // P4b: the owner's keys on pipegen's entry would move onto the owner's npm entry
    const dep = `${v2}updates:\n${npmEntry}`;
    const de2 = textEdit('dependabot', '.github/dependabot.yml', dep, `${dep}${pub}`);
    expect(revertEdit(de2, cur(`${dep}${pub}    labels: ["deps"]\n    open-pull-requests-limit: 0\n`), blob)).toMatchObject({ kind: 'manual', remove: pub });
    // the owner's own new entry after pipegen's is a sibling: the strip keeps it as one
    expect(textOf(revertEdit(de2, cur(`${dep}${pub}${npmEntry.replace('"/"', '"/web"')}`), blob))).toBe(`${dep}${npmEntry.replace('"/"', '"/web"')}`);
  });

  it('V2-R1 4: revertEdits pairs a lock that names a package.json even when that package.json names no lock', () => {
    const pj = '{\n  "name": "b"\n}\n';
    const pjNew = buildPackageJson(pj, { add: { c8: '12.0.0' }, setTest: false }) as string;
    const lock = '{ "l": 1 }\n';
    const lockNew = '{ "l": 2 }\n';
    for (const t of [pj, pjNew, lock, lockNew]) put(t);
    const json: Extract<InstallEdit, { kind: 'package-json' }> = based({ repo: 'app', path: 'package.json', kind: 'package-json', add: { c8: '12.0.0' }, setTest: false, originalSha: gitBlobSha(pj), writtenShas: [gitBlobSha(pjNew)] });
    const lk: Extract<InstallEdit, { kind: 'package-lock' }> = { repo: 'app', path: 'package-lock.json', kind: 'package-lock', json: 'package.json', originalSha: gitBlobSha(lock), writtenShas: [gitBlobSha(lockNew)] };
    const r = revertEdits([json, lk], (e) => (e.path === 'package.json' ? cur(pjNew) : cur(lockNew)), blob, CTX);
    expect(r.map((x) => [x.edit.path, x.result.kind])).toEqual([['package.json', 'manual'], ['package-lock.json', 'manual']]);
  });

  it("V2-R1 5: pipegen's markers left after a strip → manual", () => {
    const original = '* @alice\n';
    const block = codeownersBlock(['trivy.yaml'], ['@o']);
    const written = codeownersFile(original, block);
    const e = textEdit('codeowners', 'CODEOWNERS', original, written);
    // the block once more without its separator (an owner copy) at the top: which one is pipegen's is unclear
    expect(revertEdit(e, cur(`${block}${written}`), blob)).toMatchObject({ kind: 'manual', remove: e.inserted });
    expect(revertEdit(e, cur(`# pipegen:begin\n${written}`), blob)).toMatchObject({ kind: 'manual', remove: e.inserted });
    const husky = '#!/usr/bin/env sh\nnpm test\n';
    const hb = hookBlock('husky', [{ id: 'biome', run: 'npx biome check' }]);
    const he = textEdit('hooks', '.husky/pre-commit', husky, `${husky}${hb}`);
    expect(revertEdit(he, cur(`# pipegen:hooks old\n${husky}${hb}`), blob)).toMatchObject({ kind: 'manual', remove: hb });
  });

  it('V2-R1 6: an ownerEdited edit offers its text to remove only when it is in builder form', () => {
    const original = '* @alice\n';
    const bad = textEdit('codeowners', 'CODEOWNERS', original, `${original}\x1b[2J\x1b[31m\n`, { ownerEdited: true });
    const r = revertEdit(bad, cur(`${original}\x1b[2J\x1b[31m\n`), blob);
    expect(r.kind).toBe('manual');
    expect(r).not.toHaveProperty('remove');
    const block = codeownersBlock(['trivy.yaml'], ['@o']);
    const good = textEdit('codeowners', 'CODEOWNERS', original, codeownersFile(original, block), { ownerEdited: true });
    expect(revertEdit(good, cur(codeownersFile(original, block)), blob)).toMatchObject({ kind: 'manual', remove: good.inserted });
  });

  it('V2-R1b m1: a lock related to more than one package.json goes manual with all of them, in any order', () => {
    const pj = '{\n  "name": "c"\n}\n';
    const pjNew = buildPackageJson(pj, { add: { c8: '12.0.0' }, setTest: false }) as string;
    const lock = '{ "m": 1 }\n';
    const lockNew = '{ "m": 2 }\n';
    for (const t of [pj, pjNew, lock, lockNew]) put(t);
    const pj1: Extract<InstallEdit, { kind: 'package-json' }> = { repo: 'app', path: 'package.json', kind: 'package-json', add: { c8: '12.0.0' }, setTest: false, lock: 'package-lock.json', originalSha: gitBlobSha(pj), writtenShas: [gitBlobSha(pjNew)] };
    const lk: Extract<InstallEdit, { kind: 'package-lock' }> = { repo: 'app', path: 'package-lock.json', kind: 'package-lock', json: 'package.json', originalSha: gitBlobSha(lock), writtenShas: [gitBlobSha(lockNew)] };
    const pj2: Extract<InstallEdit, { kind: 'package-json' }> = { ...pj1, path: 'web/package.json' };
    const read = (e: InstallEdit): { text: string; sha: string } => (e.kind === 'package-lock' ? cur(lockNew) : cur(pjNew));
    for (const order of [[pj1, lk, pj2], [pj2, lk, pj1], [lk, pj2, pj1]]) {
      expect(revertEdits(order, read, blob, CTX).map((x) => x.result.kind), order.map((e) => e.path).join(',')).toEqual(['manual', 'manual', 'manual']);
    }
  });

  it('V2-R1b m3: a husky strip after an owner line that continues onto the next is manual', () => {
    const husky = '#!/usr/bin/env sh\nfoo \\\n';
    const hb = hookBlock('husky', [{ id: 'biome', run: 'npx biome check' }]);
    const he = textEdit('hooks', '.husky/pre-commit', husky, `${husky}${hb}`);
    expect(revertEdit(he, cur(`${husky}${hb}bar\n`), blob)).toMatchObject({ kind: 'manual', remove: hb });
    expect(revertEdit(he, cur(`${husky}\n${hb}bar\n`), blob)).toMatchObject({ kind: 'manual', remove: hb });   // a blank line between: still the same command
    const plain = textEdit('hooks', '.husky/pre-commit', '#!/usr/bin/env sh\nfoo\n', `#!/usr/bin/env sh\nfoo\n${hb}`);
    expect(textOf(revertEdit(plain, cur(`#!/usr/bin/env sh\nfoo\n${hb}bar\n`), blob))).toBe('#!/usr/bin/env sh\nfoo\nbar\n');
  });
});

// ---------- G17 group C ----------

describe('G17C rows 24, 25: the Dependabot private form names the app owner\'s pipelines repo; one husky shebang', () => {
  const dep = 'version: 2\nupdates:\n  - package-ecosystem: "npm"\n    directory: "/"\n    schedule:\n      interval: "daily"\n';
  const priv = (repo: string): PipelineDraft => ({ profile: { private: true }, centralPin: { repo } }) as unknown as PipelineDraft;
  it('row 24: the private entry is pipegen\'s only for <app owner>/pipelines; another central repo name is manual', () => {
    for (const [repo, ctx, want] of [
      ['acme/pipelines', { appOwner: 'acme' }, 'strip'], ['Acme/pipelines', { appOwner: 'acme' }, 'strip'],
      ['evil/pipelines', { appOwner: 'acme' }, 'manual'], ['acme/other', { appOwner: 'acme' }, 'manual'],
      // G17C-R1 (F2, m3): without the app owner the private form is never pipegen's (only the public form is)
      ['acme/other', {}, 'manual'], ['acme/pipelines', {}, 'manual'], ['acme/pipelines', { defaultBranch: 'main' }, 'manual'], ['acme/pipelines', { appOwner: '' }, 'manual'],
    ] as const) {
      const de = textEdit('dependabot', '.github/dependabot.yml', dep, `${dep}${dependabotEntryText(priv(repo))}`);
      expect(kind(revertEdit(de, cur(`# mine\n${dep}${dependabotEntryText(priv(repo))}`), blob, ctx as never)), `${repo} ${JSON.stringify(ctx)}`).toBe(want);
    }
  });
  it('G17C-R1 (F2, m3): through revertEdits, the private entry of evil/pipelines is kept for manual review; acme/pipelines is stripped', () => {
    const one = (repo: string, ctx: { defaultBranch?: string; appOwner?: string }): string => {
      const de = textEdit('dependabot', '.github/dependabot.yml', dep, `${dep}${dependabotEntryText(priv(repo))}`);
      const [r] = revertEdits([de], () => cur(`# mine\n${dep}${dependabotEntryText(priv(repo))}`), blob, ctx);
      return kind((r as { result: RevertResult }).result);
    };
    expect(one('evil/pipelines', { defaultBranch: 'main', appOwner: 'acme' })).toBe('manual');
    expect(one('acme/pipelines', { defaultBranch: 'main', appOwner: 'acme' })).toBe('strip');
    expect(one('acme/pipelines', { defaultBranch: 'main' })).toBe('manual');
  });
  it('row 25: revert.ts reads the husky shebang from created-builders.ts (no copy of its own)', async () => {
    const { readFileSync } = await import('node:fs');
    const cb = await import('../src/engine/created-builders.js');
    expect((cb as unknown as { HUSKY_SHEBANG?: string }).HUSKY_SHEBANG).toBe('#!/usr/bin/env sh\n');
    const src = readFileSync(new URL('../src/uninstall/revert.ts', import.meta.url), 'utf8');
    expect(src).not.toMatch(/const HUSKY_SHEBANG\s*=/);
    expect(src).toMatch(/\bHUSKY_SHEBANG\b.*from '\.\.\/engine\/created-builders\.js'|import \{[^}]*\bHUSKY_SHEBANG\b[^}]*\} from '\.\.\/engine\/created-builders\.js'/s);
  });
});
