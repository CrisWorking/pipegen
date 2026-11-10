// v0.2 Plan V V9a (ruling V8-R1, the Plan V final review's fix round): the V8 security probes P1-P4 as tests, and the I1 cases a/b/c.
// - sec I1: a pre-existing environment pipegen narrowed is never widened while a secret pipegen stored in it is still there (target.ts
//   restoreEnvironment lists its secrets right before the PUT; phase-b.ts holds the restore back when a secret delete of it was not done).
// - sec M1: under typedNames the central Actions access goes back only after its typed name (`central-access`).
// - sec M2: v0.2 never deletes or prints a delete for a repo the user created; the final message lists them as the user's to delete.
// - sec M3: a scratch repo answering 404 is named ("gone, or this token can't see it").
// - sec M4: the CLI takes the app's lease before it loads the record.
// - sec i1, i2, i6; spec minor (the consent screen's create command).
// No network: the GitHub stand-in of the phase-B tests.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { CliIO, Prompter } from '../src/cli/io.js';
import { uninstallCommand, type UninstallCommandDeps } from '../src/cli/uninstall.js';
import { StateStore } from '../src/proof/state.js';
import type { InstallRecord } from '../src/types.js';
import { uninstallStep, type StepDeps, type StepResult } from '../src/uninstall/apply.js';
import { ProgressFile } from '../src/uninstall/progress.js';
import type { LoadedRecord } from '../src/uninstall/record.js';
import { UninstallApi, UninstallRefusal } from '../src/uninstall/target.js';
import type { Env } from './helpers/deliver-github.js';
import { entryImportProblems } from './helpers/import-scan.js';
import { ACCESS_ROUTE, AT, blob, cleanHomes, deps, gh, loadedOf, local, mergePr, RECORD_TEXT, sampleRecord, SEC, SHA, term, world, type Term, type World } from './helpers/uninstall-world.js';

const h = vi.hoisted(() => ({ stop: { now: false } }));
vi.mock('../src/util/exit-hooks.js', async (orig) => ({ ...(await orig<typeof import('../src/util/exit-hooks.js')>()), interrupting: () => h.stop.now, onInterrupt: () => () => {} }));
afterEach(() => { cleanHomes(); h.stop.now = false; });

async function afterRun1(w: World): Promise<void> {
  w.app.refs.set('heads/pipegen/uninstall', w.g.head(`o/${w.app.name}`));
  w.app.pulls.push({ number: 1, head: 'pipegen/uninstall', base: 'main', title: 'pipegen: uninstall', body: '', state: 'closed', html_url: `https://github.com/o/${w.app.name}/pull/1` });
  w.merged.set(`${w.app.name}#1`, '2026-11-06T10:00:00Z');
  const pf = await ProgressFile.open({ owner: 'o', repo: w.app.name }, w.app.id, local(w));
  pf.save({ phase: 'A-done', anchors: { appHead: SHA('a'), appTree: SHA('b'), centralHead: w.g.head('o/pipelines'), recordBlobSha: blob(RECORD_TEXT) }, prNumber: 1, prUrl: `https://github.com/o/${w.app.name}/pull/1`, done: [], leftovers: [] });
}
const run = (w: World, rec: InstallRecord, t: Term = term(), over: Partial<StepDeps> = {}, lo: Partial<LoadedRecord> = {}): Promise<StepResult> =>
  uninstallStep(gh(w), loadedOf(w, rec, lo), t.p, deps(w, over));
const KEY = ['PIPEGEN_COSIGN', 'KEY'].join('_');
const ENV_PUT = 'PUT /repos/{owner}/{repo}/environments/{environment_name}';
const ENV_ITEM_DELETE = `DELETE /repos/{owner}/{repo}/environments/{environment_name}/${SEC}/{secret_name}`;
const ENV_ITEM_LIST = `GET /repos/{owner}/{repo}/environments/{environment_name}/${SEC}`;
const narrowed = (): Env => ({ id: 9, created_at: AT, wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true,
  deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, policies: [{ id: 3, name: 'main', type: 'branch' }], stored: new Map([[KEY, AT]]) });
const envEntry = { name: 'pipegen-signing', created: false, githubCreatedAt: AT, changed: ['deployment_branch_policy' as const], branchPolicyIds: [3],
  previous: { wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: null, branch_policies: [] } };
const allText = (w: World, r: StepResult): string => [...w.out, ...r.lines, ...r.skipped.map((s) => `${s.what} ${s.why}`), ...r.manual.map((m) => `${m.what} ${m.why} ${m.step ?? ''}`), ...(r.notes ?? [])].join('\n');

describe('V9a sec I1: an environment pipegen narrowed is not widened while its secret is still there', () => {
  /** The PUT is never sent, the environment keeps the default-branch rule and the key, and a manual step names the key. */
  const held = (w: World, r: StepResult): void => {
    const e = w.app.envs.get('pipegen-signing');
    expect(w.g.calls.some((c) => c.route === ENV_PUT)).toBe(false);
    expect(e?.stored.has(KEY)).toBe(true);
    expect(e?.deployment_branch_policy).toEqual({ protected_branches: false, custom_branch_policies: true });
    expect(r.manual.some((m) => m.what === 'environment pipegen-signing' && `${m.why} ${m.step ?? ''}`.includes(KEY))).toBe(true);
  };

  it('phase B: an environment pipegen narrowed is not widened while a secret pipegen stored in it is still there (a: the delete answers 500)', async () => {
    const w = world();
    await afterRun1(w);
    w.app.envs.set('pipegen-signing', narrowed());
    w.g.hooks.unshift((c) => (c.route === ENV_ITEM_DELETE ? { status: 500 } : undefined));
    const rec = sampleRecord(w, { [SEC]: [{ name: KEY, scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT }], environments: [envEntry] });
    const r = await run(w, rec);
    held(w, r);
    // phase B holds it back itself (the delete of its secret was not done in this run): no list read, no restore attempt
    expect(r.manual.find((m) => m.what === 'environment pipegen-signing')?.why).toMatch(/was not deleted in this run/);
    expect(w.g.calls.some((c) => c.route === ENV_ITEM_LIST)).toBe(false);
    // the branch rule pipegen added stays too (the environment is put back whole, in a later run)
    expect(w.app.envs.get('pipegen-signing')?.policies.map((p) => p.id)).toEqual([3]);
    expect(r.status).toBe('b-partial');
  });

  it('phase B: an environment pipegen narrowed is not widened while a secret pipegen stored in it is still there (b: an overwritten key)', async () => {
    const w = world();
    await afterRun1(w);
    w.app.envs.set('pipegen-signing', narrowed());
    const rec = sampleRecord(w, { [SEC]: [{ name: KEY, scope: 'env:pipegen-signing', created: false, overwritten: true }], environments: [envEntry] });
    const r = await run(w, rec);
    held(w, r);
    // target.ts's own check, right before the PUT: the key the record names is still listed
    const m = r.manual.find((x) => x.what === 'environment pipegen-signing');
    expect(m?.why).toMatch(/is still in the environment pipegen-signing/);
    expect(m?.step).toContain(`gh secret delete ${KEY} --env pipegen-signing --repo o/shop`);
    expect(m?.step).toMatch(/run `pipegen uninstall` again/);
  });

  it('phase B: an environment pipegen narrowed is not widened while a secret pipegen stored in it is still there (c: its name declined)', async () => {
    const w = world();
    await afterRun1(w);
    w.app.envs.set('pipegen-signing', narrowed());
    const rec = sampleRecord(w, { [SEC]: [{ name: KEY, scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT }], environments: [envEntry] });
    const t = term({ type: (_q, exp) => (exp === KEY ? 'no' : exp) });
    const r = await run(w, rec, t, {}, { typedNames: true, marker: 'differs' });
    held(w, r);
    expect(r.manual.find((m) => m.what === 'environment pipegen-signing')?.why).toMatch(/was not deleted in this run/);
    expect(w.g.calls.some((c) => c.route === ENV_ITEM_LIST)).toBe(false);
  });

  it('phase B: control: the key deleted in this run, the environment\'s earlier settings go back', async () => {
    const w = world();
    await afterRun1(w);
    w.app.envs.set('pipegen-signing', narrowed());
    const rec = sampleRecord(w, { [SEC]: [{ name: KEY, scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT }], environments: [envEntry] });
    const r = await run(w, rec);
    const e = w.app.envs.get('pipegen-signing');
    expect(e?.stored.has(KEY)).toBe(false);
    expect(w.g.calls.filter((c) => c.route === ENV_PUT)).toHaveLength(1);
    expect(e?.deployment_branch_policy).toBeNull();
    // the list was read right before the PUT
    const list = w.g.calls.findIndex((c) => c.route === ENV_ITEM_LIST);
    expect(list).toBeGreaterThan(-1);
    expect(list).toBeLessThan(w.g.calls.findIndex((c) => c.route === ENV_PUT));
    expect(r.done).toContain('environment pipegen-signing: put back as it was before pipegen');
  });

  it('target: restoreEnvironment keeps the environment when its secrets can\'t be listed whole (a 403, or more than one page)', async () => {
    for (const answer of [{ status: 403 }, { status: 200, data: { total_count: 101, [SEC]: [] } }]) {
      const w = world();
      w.app.envs.set('pipegen-signing', narrowed());
      w.app.envs.get('pipegen-signing')?.stored.clear();
      w.g.hooks.unshift((c) => (c.route === ENV_ITEM_LIST ? answer : undefined));
      const api = new UninstallApi(gh(w), { owner: 'o', repo: 'shop', repoId: w.app.id }, { askName: async () => true });
      const t = await api.confirm({ kind: 'environment-restore', entry: envEntry });
      const shown = { wait_timer: 0, prevent_self_review: false, reviewers: [], can_admins_bypass: true, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } };
      const o = await api.restoreEnvironment(envEntry, shown, [{ name: KEY }], t ?? undefined);
      expect(o.status, String(answer.status)).toBe('kept');
      expect(o).toMatchObject({ why: expect.stringMatching(/couldn't list every secret/) });
      expect(w.g.calls.some((c) => c.route === ENV_PUT)).toBe(false);
    }
  });
});

describe('V9a sec M1: the central Actions access under typedNames', () => {
  const setup = async (): Promise<{ w: World; rec: InstallRecord }> => {
    const w = world();
    await afterRun1(w);
    w.settings.access = 'user';
    return { w, rec: sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: false, actionsAccess: { previous: 'none' } } }) };
  };

  it('central: typedNames → the Actions access goes back only after its typed name', async () => {
    // declined: nothing sent, kept with the manual step
    const a = await setup();
    const no = term({ type: () => 'no' });
    const r = await run(a.w, a.rec, no, {}, { typedNames: true, marker: 'differs' });
    expect(a.w.g.calls.filter((c) => c.route === ACCESS_ROUTE)).toHaveLength(0);
    expect(a.w.settings.access).toBe('user');
    expect(no.typed.some((q) => /Actions access level of o\/pipelines/.test(q) && /Type pipelines to go on/.test(q))).toBe(true);
    expect(r.manual.some((m) => m.what === 'central Actions access of o/pipelines')).toBe(true);
    expect(r.done.join('\n')).not.toMatch(/central Actions access/);
    // typed: put back
    const b = await setup();
    const yes = term();
    const r2 = await run(b.w, b.rec, yes, {}, { typedNames: true, marker: 'differs' });
    expect(b.w.g.calls.filter((c) => c.route === ACCESS_ROUTE)).toHaveLength(1);
    expect(b.w.settings.access).toBe('none');
    expect(r2.done).toContain('central Actions access of o/pipelines: done');
    // no typed-names run: no question, as before
    const c = await setup();
    const plain = term();
    await run(c.w, c.rec, plain);
    expect(plain.typed.some((q) => /Actions access level/.test(q))).toBe(false);
    expect(c.w.settings.access).toBe('none');
  });

  it('target: write() refuses the central Actions access without its token when typedNames', async () => {
    const w = world();
    w.settings.access = 'user';
    const api = new UninstallApi(gh(w), { owner: 'o', repo: 'shop', repoId: w.app.id }, { askName: async () => true, typedNames: true });
    const params = { owner: 'o', repo: 'pipelines', access_level: 'none' };
    await expect(api.write(ACCESS_ROUTE, params, { pipegenSet: 'user' })).rejects.toThrow(UninstallRefusal);
    // a token for another object doesn't count
    const other = await api.confirm({ kind: 'classic', branch: 'main' });
    await expect(api.write(ACCESS_ROUTE, params, { pipegenSet: 'user', typed: other ?? undefined })).rejects.toThrow(/another object/);
    expect(w.g.calls.filter((c) => c.route === ACCESS_ROUTE)).toHaveLength(0);
    const t = await api.confirm({ kind: 'central-access' });
    expect(await api.write(ACCESS_ROUTE, params, { pipegenSet: 'user', typed: t ?? undefined })).toEqual({ status: 'done' });
    expect(w.settings.access).toBe('none');
  });
});

describe('V9a sec M2: v0.2 never deletes or prints a delete for a repo the user created', () => {
  it('phase B: a v0.2 token-mode record with --delete-repos prints no gh repo delete; the final message lists both repos as yours to delete by hand', async () => {
    const w = world();
    await afterRun1(w);
    const rec = sampleRecord(w, { central: { createdByPipegen: false }, scratch: { createdByPipegen: false } });
    await run(w, rec, term(), { deleteRepos: true, canDeleteRepos: false });
    expect(w.out.join('\n')).toMatch(/o\/pipegen-proof-shop: you created it/);
    mergePr(w, w.central, 'pipegen/uninstall-shop');
    const r = await run(w, rec, term(), { deleteRepos: true, canDeleteRepos: false });
    const all = allText(w, r);
    expect(all).not.toMatch(/gh repo delete/);
    expect(r.status).toBe('b-done');
    const notes = (r.notes ?? []).join('\n');
    expect(notes).toMatch(/o\/pipegen-proof-shop: you created it[^\n]*holds nothing of pipegen's[^\n]*delete it by hand/);
    expect(notes).toMatch(/o\/pipelines: you created it[^\n]*holds nothing of pipegen's[^\n]*delete it by hand/);
    expect(r.lines.join('\n')).toMatch(/^Notes:/m);
    // no text calls those repos pipegen's own
    for (const l of all.split('\n').filter((x) => /pipelines|pipegen-proof/.test(x))) expect(l, l.slice(0, 160)).not.toMatch(/pipegen (?:created|made)\b/);
    // nothing left that needs the user: no kept item, no manual step (a clean exit 0 through the CLI)
    expect(r.skipped).toEqual([]);
    expect(r.manual).toEqual([]);
    expect(r.failed).toEqual([]);
  });

  it('phase B: the scratch repo\'s kept default branch is a note, not a kept item; pipelines is listed only once nothing of pipegen\'s is left', async () => {
    const w = world();
    await afterRun1(w);
    const rec = sampleRecord(w, { central: { createdByPipegen: false }, scratch: { createdByPipegen: false } });
    const r = await run(w, rec);
    expect(r.status).toBe('b-waiting');
    expect(r.skipped.some((s) => /default branch/.test(s.what))).toBe(false);
    expect((r.notes ?? []).join('\n')).toMatch(/pipegen-proof-shop: you created it/);
    // the central pull request is not merged yet: pipelines still holds this project's record, so it is not listed as yours to delete
    expect((r.notes ?? []).join('\n')).not.toMatch(/o\/pipelines: you created it/);
  });

  it('phase B: the central PR body and the texts never promise a gh repo delete for the repos the user created', async () => {
    const w = world();
    await afterRun1(w);
    const rec = sampleRecord(w, { central: { createdByPipegen: false }, scratch: { createdByPipegen: false } });
    await run(w, rec, term(), { deleteRepos: true });
    const pr = w.central.pulls.find((p) => p.head === 'pipegen/uninstall-shop');
    expect(pr?.body).toBeDefined();
    expect(pr?.body).not.toMatch(/gh repo delete|repos pipegen made/);
  });
});

describe('V9a sec M2: the record says pipegen created the repos (App-shaped records)', () => {
  it('phase B: a repo the record says pipegen created is never listed as "you created it"; its kept default branch is a note either way', async () => {
    const w = world();
    await afterRun1(w);
    // the record names the repos as pipegen's, the scratch repo with another id than GitHub's: not the one the record names
    const rec = sampleRecord(w, { central: { repoId: w.central.id, createdByPipegen: true }, scratch: { createdByPipegen: true, repoId: 999_999 } });
    await run(w, rec, term(), { deleteRepos: true, canDeleteRepos: false });
    mergePr(w, w.central, 'pipegen/uninstall-shop');
    const r = await run(w, rec, term(), { deleteRepos: true, canDeleteRepos: false });
    const notes = (r.notes ?? []).join('\n');
    expect(notes).not.toMatch(/you created it/);
    expect(notes).toMatch(/the default branch main of scratch repo o\/pipegen-proof-shop keeps the copy of your code/);
    expect(r.skipped.some((x) => /default branch/.test(x.what))).toBe(false);
    // without --delete-repos too (no repo step there): pipelines the record says pipegen created is not "yours"
    const w2 = world();
    await afterRun1(w2);
    const rec2 = sampleRecord(w2, { central: { repoId: w2.central.id, createdByPipegen: true }, scratch: { createdByPipegen: true, repoId: w2.scratch?.id ?? 0 } });
    await run(w2, rec2);
    mergePr(w2, w2.central, 'pipegen/uninstall-shop');
    const r2 = await run(w2, rec2);
    expect(r2.status).toBe('b-done');
    expect((r2.notes ?? []).join('\n')).not.toMatch(/you created it/);
  });
});

describe('V9a sec M3: a scratch repo answering 404', () => {
  const WORDS = /gone, or this token can't see it/;

  it('plan and phase B: a scratch 404 is named in the preview and the final message', async () => {
    const w = world();
    await afterRun1(w);
    w.g.hooks.unshift((c) => (String(c.params.repo).startsWith('pipegen-proof-') ? { status: 404 } : undefined));
    const rec = sampleRecord(w, { scratch: { createdByPipegen: false } });
    await run(w, rec);
    mergePr(w, w.central, 'pipegen/uninstall-shop');
    w.out.length = 0;
    const r = await run(w, rec, term(), { deleteRepos: true });
    const preview = w.out.join('\n');
    expect(preview).toMatch(/pipegen-proof-shop/);
    expect(preview).toMatch(WORDS);
    expect(r.skipped.some((s) => s.what === 'scratch repo o/pipegen-proof-shop' && WORDS.test(s.why))).toBe(true);
    expect(r.lines.join('\n')).toMatch(WORDS);
  });

  it('phase B: a scratch repo that answers 404 only at apply time is not "already gone"', async () => {
    const w = world();
    await afterRun1(w);
    const rec = sampleRecord(w, { scratch: { createdByPipegen: false } });
    let hide = false;
    w.g.hooks.unshift((c) => (hide && String(c.params.repo).startsWith('pipegen-proof-') ? { status: 404 } : undefined));
    const t = term({ go: true });
    const p = t.p;
    t.p = { ...p, confirm: async (m, d) => { if (m.startsWith('Go ahead')) hide = true; return p.confirm(m, d); } };
    const r = await run(w, rec, t);
    expect(r.done.join('\n')).not.toMatch(/pipegen-proof-shop: already gone/);
    expect(r.skipped.some((s) => s.what === 'scratch repo o/pipegen-proof-shop' && WORDS.test(s.why))).toBe(true);
  });
});

describe('V9a sec i1: run 1 names the time the signing environment is open', () => {
  it('apply: run 1\'s final message says to merge soon while pipegen\'s environment still holds its secrets', async () => {
    const w = world();
    w.app.envs.set('pipegen-signing', narrowed());
    const rec = sampleRecord(w, { [SEC]: [{ name: KEY, scope: 'env:pipegen-signing', created: true, githubCreatedAt: AT }], environments: [envEntry] });
    const r = await run(w, rec);
    expect(r.status).toBe('a-done');
    expect(r.lines.join('\n')).toMatch(/until the second run, anyone who can push to main can use pipegen's environment pipegen-signing/);
    // nothing stored in an environment: no such line
    const w2 = world();
    const r2 = await run(w2, sampleRecord(w2));
    expect(r2.lines.join('\n')).not.toMatch(/anyone who can push/);
  });
});

describe('V9a sec M4: the lease before the record is loaded', () => {
  type TestIO = CliIO & { lines: string[]; errs: string[] };
  const mkio = (): TestIO => {
    const lines: string[] = [];
    const errs: string[] = [];
    const prompt: Prompter = { confirm: async () => true, select: async () => { throw new Error('no'); }, text: async () => { throw new Error('no'); } };
    return { prompt, out: (s) => { lines.push(s); }, err: (s) => { errs.push(s); }, env: {}, lines, errs, interactive: true };
  };
  const TK_KEY = ['to', 'ken'].join('');

  it('cli: uninstall takes the app\'s lease before it loads the record, hands it to the step and gives it back', async () => {
    const w = world();
    const state = local(w);
    const seen: string[] = [];
    let handed: unknown;
    const tryLease = async (): Promise<string> => {
      const s = await StateStore.openForLease({ owner: 'o', repo: 'shop' }, state);
      try { s.acquireLease('probe-1', 'finish'); s.releaseLease(); return 'free'; } catch { return 'held'; }
    };
    const d: UninstallCommandDeps = {
      dir: '/x', allowBroad: false, deleteRepos: false, state,
      connect: (async () => ({ app: { owner: 'o', repo: 'shop' }, [TK_KEY]: 'x', g: { gh: {} as Octokit, login: 'o', local: state } })) as never,
      load: (async () => { seen.push(`load: ${await tryLease()}`); return { app: { owner: 'o', repo: 'shop', repoId: 7 } }; }) as never,
      step: (async (_g: unknown, _l: unknown, _p: unknown, sd: StepDeps) => { handed = sd.lease; seen.push(`step: ${await tryLease()}`); return { status: 'b-done', phase: 'B', done: [], failed: [], skipped: [], manual: [], lines: [] }; }) as never,
    };
    expect(await uninstallCommand(mkio(), d)).toBe(0);
    expect(seen).toEqual(['load: held', 'step: held']);
    expect(handed).toBeInstanceOf(StateStore);
    expect(await tryLease()).toBe('free');
    // another pipegen holds it: a stop before the record is loaded
    const other = await StateStore.openForLease({ owner: 'o', repo: 'shop' }, state);
    other.acquireLease('finish-x', 'finish');
    seen.length = 0;
    const io = mkio();
    expect(await uninstallCommand(io, d)).toBe(2);
    expect(seen).toEqual([]);
    expect(io.errs.join('\n')).toMatch(/^pipegen uninstall stopped: /m);
    other.releaseLease();
  });

  it('apply: uninstallStep refuses a lease store that doesn\'t hold this app\'s lease', async () => {
    const w = world();
    const store = await StateStore.open({ owner: 'o', repo: 'shop' }, local(w));
    await expect(run(w, sampleRecord(w), term(), { lease: store })).rejects.toThrow(/lease/);
    expect(w.g.calls).toHaveLength(0);
  });
});

describe('V9a sec i2 and spec minor', () => {
  it('scan: only src/cli/uninstall.ts may import uninstallStep, loadUninstallRecord and holdUninstallLease', () => {
    for (const [name, mod] of [['uninstallStep', './uninstall/apply.js'], ['loadUninstallRecord', './uninstall/record.js'], ['holdUninstallLease', './uninstall/apply.js']]) {
      const src = `import { ${name} } from '${mod}';\nexport async function x(): Promise<void> { await ${name}({} as never, {} as never); }\n`;
      expect(entryImportProblems('src/other.ts', src).join('\n'), name).toMatch(new RegExp(`${name} imported in src/other.ts`));
    }
    // E's writers in a file that isn't allowed them (V7 spec I2's negative case)
    const e = `import { cleanupWrite } from './proof/cleanup.js';\nexport async function x(): Promise<void> { await cleanupWrite({} as never); }\n`;
    expect(entryImportProblems('src/deliver/other.ts', e).join('\n')).toMatch(/cleanupWrite imported in src\/deliver\/other\.ts/);
    // the real file passes
    const cli = readFileSync(join(import.meta.dirname, '..', 'src', 'cli', 'uninstall.ts'), 'utf8');
    expect(entryImportProblems('src/cli/uninstall.ts', cli)).toEqual([]);
  });
});

describe('V9a docs (V8-R1 sec M2, M4, M5, i1, i6; spec minors)', () => {
  const read = (rel: string): string => readFileSync(join(import.meta.dirname, '..', rel), 'utf8');

  it('docs: v0.2 truth: no doc, help or smoke row promises a gh repo delete for the repos the user created; T55 and T56 are v0.2 threats and say what the code does', () => {
    const readme = read('README.md');
    const design = read('docs/design.md');
    const s14 = design.slice(design.indexOf('## 14. Uninstall'), design.indexOf('## 15.'));
    const smoke = read('docs/smoke-test.md');
    const un = smoke.slice(smoke.indexOf('## Uninstall (V-live)'), smoke.indexOf('## Release'));
    const help = read('src/cli/main.ts');
    // one --delete-repos paragraph in design §14
    expect(s14.split('\n').filter((l) => /--delete-repos/.test(l))).toHaveLength(1);
    // nothing says the command is printed, or calls the helper repos pipegen's own
    for (const [f, text] of [['README.md', readme], ['design §14', s14], ['smoke UN', un], ['main.ts', help]] as const) {
      expect(text, f).not.toMatch(/prints? the `?gh repo delete`? commands?|print the gh repo delete|the printed (?:`gh repo delete` )?commands|repos pipegen made/);
    }
    for (const l of [readme, design, un].join('\n').split('\n').filter((x) => /pipegen-proof-<repo>|`pipelines`/.test(x))) expect(l, l.slice(0, 140)).not.toMatch(/pipegen (?:created|made) (?:them|it|these)/);
    expect(un).toMatch(/UN-7 [^\n]*no `gh repo delete` command is printed[^\n]*yours to delete by hand[^\n]*exit 0/);
    // README: the stale "will be shown here" is gone; uninstall needs no Members: read; notes don't make the exit code 2
    expect(readme).not.toMatch(/will be shown here/);
    const sec = readme.slice(readme.indexOf('## Uninstall (v0.2)'), readme.indexOf('## Install safely'));
    expect(sec).not.toMatch(/Members: read is optional too/);
    expect(sec).toMatch(/a finished uninstall with only notes exits `0`/);
    // the threat model: T55 and T56 in the v0.2 list; T56 as the code is (y/N for adopted, names shown escaped, the scratch emptied without the record)
    const tm = read('docs/threat-model.md');
    expect(tm).toMatch(/\*\*v0\.2 \(full run\):\*\*[^\n]*T52–T56/);
    const t56 = tm.split('\n').find((l) => l.startsWith('| T56 |')) as string;
    expect(t56).toMatch(/`adopted` files get a yes\/no question \(default keep\)/);
    expect(t56).toMatch(/shown in the preview and the questions, escaped/);
    expect(t56).toMatch(/scratch repo is emptied without a record entry/);
    expect(t56).not.toMatch(/nothing the repo or the record says is put into a question/);
    expect(t56).not.toMatch(/prints `gh repo delete`/);
    // sec i1: the residual between the two runs, in T56 and T10
    expect(t56).toMatch(/Between the first and the second run the merge locks are off/);
    expect(tm.split('\n').find((l) => l.startsWith('| T10 |'))).toMatch(/Between uninstall's first and second run/);
  });
});
