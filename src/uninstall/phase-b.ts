// v0.2 Plan V V6 (rulings V-B2, V-B4, V-B5, V-S3, V-S4, V-S5, V-S6, V-S9, V-S10, V-S14, V-N5, V-N8, V-N9, V-N10, V-N13): run 2 of uninstall
// (phase B), on a fresh confirmed plan and its phase-bound api (apply.ts's takeApi). Every write goes through that api (target.ts, or E's
// scratch functions behind it); each object is read again right before its write; the progress is saved before the first write and after
// the run, and on Ctrl-C no new step starts.
//
// In order:
//   1. the scratch repo: a saved proof state's leftovers first (E's cleanupLeftovers, never the repo delete), then `<owner>/pipegen-proof-<repo>`
//      read again (exact name, pipegen's marker, the id the preview showed) and emptied only through E's cleanup writes and its scratch secret delete:
//      its proof/ branches, secrets, variables, workflow runs and caches (V-S14);
//   2. secrets (app, environment, central), then variables (deleted, or put back to `previous`), then environments (created: deleted whole,
//      only while they hold nothing but pipegen's (V-S5); pre-existing: the `changed` fields put back, the branch rules pipegen added
//      deleted (V-N10)), then the settings the user chose to turn off (V-S6). With pipegen's workflow still live (the user kept it in run 1)
//      none of these goes: the gate still needs them;
//   3. central (central.ts): the last-project locks first, then one central PR with this project's exact files and the record last;
//   4. --delete-repos (V-S3): App mode only (Auth.canDeleteRepos): the scratch repo (its name typed; E's scratch repo delete: name, marker,
//      recorded id) and, last project with the central PR merged and the org rule gone (M-r1-5), the central repo (deleteCentralRepo's
//      checks and typed names; pipegen's own central branches go with it, never before it: V6-R1 sec M2). Token mode: the `gh repo delete`
//      commands only after the same gates, read only (V6-R1 sec I1), nothing deleted;
//   5. the local files (V-N5): the local record file, `.finish-pending.json`, the leftovers file (each of its entries handled: gone on GitHub,
//      or put back now) and the progress file, only when nothing is left over;
//   6. the final message: done, kept, manual steps, and how to remove the pipegen App from the repo (F9).
import { randomBytes } from 'node:crypto';
import { unlinkSync } from 'node:fs';
import type { Octokit } from '@octokit/rest';
import type { Prompter } from '../cli/io.js';
import { DeliverError, statusOf, type RepoRef } from '../deliver/git-data.js';
import { localFinishPendingPath, localRecordPath, readLocalLeftovers, readLocalRecord, type Leftover } from '../deliver/record.js';
import { isRateStop } from '../engine/github-rate.js';
import { GitHubAccessError } from '../github/client.js';
import { assertScratch, githubRead, proofTarget, ProofStopError, SCRATCH_MARKER, ScratchGuardError, validBranchName, type GuardedRepo } from '../proof/target.js';
import { interrupting, onInterrupt } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import type { PhaseApi, PhaseBContext, PhasePlan, StepResult } from './apply.js';
import { runCentral, type CentralOutcome, type Report } from './central.js';
import { UninstallError } from './errors.js';
import { UninstallRefusal, uninstallBranch, type CentralDeleteResult, type DeleteOutcome } from './target.js';

/**
 * Run 2's statuses (V7 maps them): `b-done` everything done and the local files removed; `b-waiting` the central pull request is open
 * (merge it, then run again); `b-partial` a step failed or something is left over (run again, or the manual steps). Ctrl-C: `interrupted`.
 */
export type PhaseBStatus = 'b-done' | 'b-waiting' | 'b-partial';

const show = (s: unknown, n = 200): string => safeText(String(s), n);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const posId = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const NOT_TYPED = 'kept: its name was not typed';
const LIVE = 'pipegen\'s workflow is still on the app\'s default branch (you kept it) and needs it, so pipegen leaves it';
const DONE_WORDS: Readonly<Record<string, string>> = { deleted: 'deleted', gone: 'already gone', restored: 'put back as it was before pipegen', closed: 'closed', 'not-open': 'already closed', done: 'done' };
/** GitHub's answers to a scratch cleanup write for something already gone (E's cleanup takes the same). */
const SCRATCH_GONE = new Set([404, 409, 410, 422]);
const APP_STEP = (full: string): string => `v0.2 installs no pipegen GitHub App (it uses your fine-grained token), so there is no App to remove from ${full}. When you are done, delete the token on GitHub (Settings → Developer settings → Fine-grained personal access tokens) or take ${full} out of its access. pipegen's own GitHub App login is planned next.`;

/** Phase B (run 2) of a confirmed plan; apply.ts's dispatcher calls it with the plan's phase-B api. */
export async function applyPhaseB(gh: Octokit, plan: PhasePlan, api: PhaseApi, ctx: PhaseBContext): Promise<StepResult> {
  const loaded = ctx.loaded;
  const rec = loaded.record;
  const appRef: RepoRef = { owner: plan.app.owner, repo: plan.app.repo };
  const full = `${appRef.owner}/${appRef.repo}`;
  const r: StepResult = { status: 'b-done', phase: 'B', done: [], failed: [], skipped: [], manual: [], lines: [] };
  const live = ctx.workflowsLive;
  const interactive = ctx.deps.interactive === true && ctx.io !== undefined;
  const prior = ctx.progress.state;
  // V6-R1 sec M1: the head pipegen set the central uninstall branch to in an earlier run 2 (read before this run saves over the file)
  let centralHead = prior?.phase === 'B' ? prior.centralUninstallHead : undefined;
  // V6-R3 sec M1: set right before pipegen's own repo DELETE of central (a later run that finds central gone can finish)
  let deleteSent = prior?.phase === 'B' ? prior.centralDeleteSent : undefined;

  // V-S9: the record as the preview read it (or this project's central PR that removed it, merged), before anything is sent
  await recheck();

  const save = (): void => {
    ctx.progress.save({
      phase: 'B', anchors: { ...plan.base },
      ...(prior?.prNumber === undefined ? {} : { prNumber: prior.prNumber, ...(prior.prUrl === undefined ? {} : { prUrl: prior.prUrl }) }),
      ...(prior?.unfinished === true ? { unfinished: true as const } : {}),
      ...(centralHead === undefined ? {} : { centralUninstallHead: centralHead }),
      ...(deleteSent === undefined ? {} : { centralDeleteSent: deleteSent }),
      done: [...r.done], leftovers: [...r.failed, ...r.manual.map((m) => ({ what: m.what, why: m.why, ...(m.step === undefined ? {} : { manual: m.step }) }))],
    });
  };
  save();   // before the first write: a stop from here on is resumed as run 2 (with the run-1 PR and the record's blob kept)

  const report: Report = {
    done: (what) => { r.done.push(what); },
    skip: (what, why) => { r.skipped.push({ what, why }); },
    manual: (what, why, step) => { r.manual.push({ what, why, ...(step === undefined ? {} : { step }) }); },
    fail: (what, why, manual) => { r.failed.push({ what, why, ...(manual === undefined ? {} : { manual }) }); },
    leftovers: () => [...r.failed.map((f) => `${f.what}: ${f.why}`), ...r.manual.map((m) => `${m.what}: ${m.why}`)],
  };
  /** One write through the api; false when it didn't happen (failed). A 401 or a rate stop ends the run (progress saved). */
  const attempt = async (what: string, manual: string | undefined, fn: () => Promise<DeleteOutcome>): Promise<boolean> => {
    let o: DeleteOutcome;
    try { o = await fn(); } catch (e) {
      if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
      r.failed.push({ what, why: interrupting() ? 'not done: pipegen was stopped (Ctrl-C)' : reasonOf(e), ...(manual === undefined ? {} : { manual }) });
      return false;
    }
    switch (o.status) {
      case 'deleted': case 'gone': case 'restored': case 'closed': case 'not-open': case 'done':
        r.done.push(`${what}: ${DONE_WORDS[o.status]}`);
        if (o.status === 'restored' && o.manual !== undefined) r.manual.push({ what, why: 'put back, but one part needs your hand', step: o.manual });
        return true;
      case 'kept':
        r.skipped.push({ what, why: o.why });
        if (o.manual !== undefined) r.manual.push({ what, why: o.why, step: o.manual });
        return true;
      case 'ask':
        r.failed.push({ what, why: `not done: GitHub's answer changed since the preview (${o.why}); run \`pipegen uninstall\` again and type its name when asked` });
        return false;
      case 'leftover':
        r.failed.push({ what, why: o.why, manual: o.manual });
        return false;
    }
  };
  /** A plan item that needed a typed name it doesn't hold is never sent. */
  const named = (x: { confirmedByName: boolean }): boolean => !plan.typedNames || x.confirmedByName;
  /** Spec M1 (V6-R1): a name the user didn't type is kept AND a leftover, so the record's question lists it (the record is how pipegen comes back). */
  const notTyped = (what: string): void => {
    r.skipped.push({ what, why: NOT_TYPED });
    r.manual.push({ what, why: NOT_TYPED, step: `Delete it by hand on GitHub if it is pipegen's, or run \`pipegen uninstall\` again and type its name.` });
  };
  const typedOf = <T extends { typed?: unknown }>(x: T): { typed?: NonNullable<T['typed']> } => (x.typed === undefined ? {} : { typed: x.typed as NonNullable<T['typed']> });

  // spec M1 (V6-R1): the names the user declined to type at the preview are leftovers too (the objects are still there)
  for (const x of plan.skipped) if (x.why.startsWith(NOT_TYPED)) r.manual.push({ what: x.what, why: x.why, step: 'Delete it by hand on GitHub if it is pipegen\'s, or run `pipegen uninstall` again and type its name.' });

  const steps: (() => Promise<void>)[] = [];
  // ---------- 1. the scratch repo ----------
  if (plan.proofCleanup || plan.scratch !== undefined) steps.push(scratchStep);
  // ---------- 2. secrets, variables, environments, settings ----------
  const scopeText = (scope: string): string => (scope === 'repo' ? '' : scope === 'central' ? ` (${appRef.owner}/pipelines)` : ` (environment ${show(scope.slice(4), 100)})`);
  const restoredEnvs = new Set<string>();
  for (const s of plan.deleteSecrets) {
    const what = `secret ${show(s.secret.name, 100)}${scopeText(s.secret.scope)}`;
    steps.push(async () => {
      if (live) { r.skipped.push({ what, why: LIVE }); return; }
      if (!named(s)) { notTyped(what); return; }
      await attempt(what, undefined, () => api.deleteIfPipegens({ kind: 'secret', entry: s.secret }, typedOf(s)));
    });
  }
  for (const v of plan.deleteVariables) {
    const what = `variable ${show(v.name, 100)}${scopeText(v.scope)}`;
    steps.push(async () => {
      if (live) { r.skipped.push({ what, why: LIVE }); return; }
      if (!named(v)) { notTyped(what); return; }
      await attempt(what, undefined, () => api.deleteIfPipegens({ kind: 'variable', entry: v.entry }, typedOf(v)));
    });
  }
  for (const v of plan.restoreVariables) {
    const what = `variable ${show(v.name, 100)}`;
    steps.push(async () => {
      if (live) { r.skipped.push({ what, why: LIVE }); return; }
      if (v.confirmedByName !== true || v.typed === undefined) { notTyped(what); return; }
      await attempt(what, undefined, () => api.restoreVariable(v.entry, v.pipegenValue, v.typed));
    });
  }
  for (const e of plan.deleteEnvironments) {
    const what = `environment ${show(e.name, 100)}`;
    steps.push(async () => {
      if (live) { r.skipped.push({ what, why: LIVE }); return; }
      if (!named(e)) { notTyped(what); return; }
      await attempt(what, undefined, () => api.deleteIfPipegens(e.owned, typedOf(e)));
    });
  }
  for (const e of plan.restoreEnvironments) {
    const what = `environment ${show(e.name, 100)}`;
    steps.push(async () => {
      if (live) { r.skipped.push({ what, why: LIVE }); return; }
      if (e.confirmedByName !== true || e.typed === undefined) { notTyped(what); return; }
      if (e.diff !== '' && await attempt(what, undefined, () => api.restoreEnvironment(e.entry, e.shown, e.typed))) restoredEnvs.add(e.name);
      for (const p of e.deleteBranchPolicies) {
        if (plan.typedNames && p.typed === undefined) { notTyped(`branch rule ${p.id} of ${what}`); continue; }
        await attempt(`branch rule ${p.id} of ${what}`, undefined, () => api.deleteBranchPolicy(e.entry, p.id, p.typed));
      }
      if (e.diff === '') restoredEnvs.add(e.name);
    });
  }
  const off = plan.settings.filter((s) => s.turnOff && named(s));
  if (off.length > 0) steps.push(settingsStep);
  const offNotTyped = plan.settings.filter((s) => s.turnOff && !named(s));
  if (offNotTyped.length > 0) steps.push(async () => { for (const s of offNotTyped) notTyped(`setting ${show(s.key, 60)}`); });
  // ---------- 3. central ----------
  let central: CentralOutcome | null = null;
  steps.push(async () => {
    try {
      central = await runCentral({
        gh, api, plan, rec, centralRepoId: rec.central?.repoId ?? loaded.centralRepoId, ownerType: loaded.app.ownerType, live, io: ctx.io, interactive, report,
        outcome: (what, manual, fn) => attempt(what, manual, fn),
        branch: { head: centralHead, set: (sha) => { centralHead = sha; save(); } },
      });
    } catch (e) {
      if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
      const step = statusOf(e) === 403
        ? `Give the token Contents: write and Pull requests: write on ${appRef.owner}/pipelines (or open the central pull request by hand), then run \`pipegen uninstall\` again.`
        : 'Run `pipegen uninstall` again.';
      r.failed.push({ what: `central pull request in ${appRef.owner}/pipelines`, why: reasonOf(e), manual: step });
    }
  });
  // ---------- 4. --delete-repos ----------
  for (const d of plan.deleteRepos) steps.push(() => repoStep(d));

  // Ctrl-C: no new step; the one in flight settles, then the progress is saved
  let current: Promise<void> = Promise.resolve();
  let stopped = false;
  const offHook = onInterrupt(async (ictx) => {
    await current.catch(() => undefined);
    try { save(); } catch { ictx.leftover('the uninstall progress (not saved)'); }
  }, { label: 'saving the uninstall progress', deadlineMs: 60_000 });
  try {
    for (const s of steps) {
      if (interrupting()) { stopped = true; break; }
      current = s();
      await current;
    }
    if (interrupting()) stopped = true;
  } catch (e) {
    try { save(); } catch { /* the error that stopped the run is the one to report */ }
    throw e;
  } finally {
    offHook();
  }
  for (const s of plan.skipped) r.skipped.push(s);
  for (const m of plan.manual) r.manual.push(m);
  if (stopped) {
    save();
    r.status = 'interrupted';
    r.lines = [`pipegen stopped (Ctrl-C). What it did is saved in ${ctx.progress.path}; run \`pipegen uninstall\` again to finish the second run.`, ...summary(r)];
    return r;
  }

  // ---------- 5. the local files, only when nothing is left over ----------
  const c = central as CentralOutcome | null;
  const merged = c !== null && c.merged;
  const unhandled = r.failed.length === 0 && merged ? await unhandledLeftovers() : [];
  const clean = r.failed.length === 0 && merged && unhandled.length === 0;
  for (const u of unhandled) r.manual.push(u);
  if (clean) {
    const gone: string[] = [];
    for (const p of [localRecordPath(appRef, ctx.deps.local ?? {}), localFinishPendingPath(appRef, ctx.deps.local ?? {}), leftoversPath()]) {
      try { unlinkSync(p); gone.push(p); } catch (e) {
        if ((e as { code?: unknown } | null)?.code !== 'ENOENT') r.manual.push({ what: p, why: 'pipegen couldn\'t remove it', step: `Remove ${p} by hand.` });
      }
    }
    if (gone.length > 0) r.done.push(`local files removed: ${gone.map((g) => show(g, 300)).join(', ')}`);
    ctx.progress.remove();
  } else save();

  r.status = r.failed.length > 0 ? 'b-partial' : !merged ? (c?.pr !== undefined ? 'b-waiting' : 'b-partial') : clean ? 'b-done' : 'b-partial';
  r.lines = [...summary(r), ...nextOf(c)];
  return r;

  // ---------- the steps ----------

  /** V-S9: the record blob at the central head now is the preview's, or the central PR that removed it merged; else a stop, nothing sent. */
  async function recheck(): Promise<void> {
    const ref: RepoRef = { owner: appRef.owner, repo: 'pipelines' };
    const changed = (what: string): never => {
      throw new UninstallError(`${what} changed since the preview, so pipegen sent nothing. Run \`pipegen uninstall\` again to see the new plan. Nothing was changed.`);
    };
    let repo: unknown;
    try { repo = (await api.read('GET /repos/{owner}/{repo}', { ...ref })).data; } catch (e) {
      // V6-R1 (sec M4, spec M2): the preview read the record there, so a 404 now is "can't tell" (deleted, or no access): a stop
      if (statusOf(e) === 404) throw new UninstallError(`pipegen can't see ${appRef.owner}/pipelines now (deleted, or this login has no access to it), where the preview read the install record, so it sent nothing. Check it on GitHub (and the token's access to it), then run \`pipegen uninstall\` again. Nothing was changed.`);
      throw e;
    }
    // V6-R4 Info 2: GitHub shows central alive with the id a "delete sent" marker names: the marker is disproved, drop it
    if (deleteSent !== undefined && isObj(repo) && repo.id === deleteSent.repoId) deleteSent = undefined;
    const def = isObj(repo) ? repo.default_branch : undefined;
    if (typeof def !== 'string') changed(`The central repo ${appRef.owner}/pipelines`);
    const head = (await api.read('GET /repos/{owner}/{repo}/git/ref/{ref}', { ...ref, ref: `heads/${String(def)}` })).data;
    const sha = isObj(head) && isObj(head.object) ? head.object.sha : undefined;
    const c = typeof sha === 'string' ? (await api.read('GET /repos/{owner}/{repo}/git/commits/{commit_sha}', { ...ref, commit_sha: sha })).data : undefined;
    const tree = isObj(c) && isObj(c.tree) ? c.tree.sha : undefined;
    const t = typeof tree === 'string' ? (await api.read('GET /repos/{owner}/{repo}/git/trees/{tree_sha}', { ...ref, tree_sha: tree, recursive: '1' })).data : undefined;
    if (!isObj(t) || t.truncated !== false || !Array.isArray(t.tree)) changed(`The default branch of ${appRef.owner}/pipelines`);
    const rp = plan.centralFiles[plan.centralFiles.length - 1];
    const at = (t as { tree: unknown[] }).tree.find((e) => isObj(e) && e.path === rp);
    if (isObj(at) && at.sha === plan.base.recordBlobSha) return;
    if (at === undefined) {
      // gone: only this project's own central uninstall PR of this uninstall (its head the one pipegen set), merged, may have removed it
      const branch = uninstallBranch({ owner: appRef.owner, repo: appRef.repo, repoId: plan.app.repoId }, 'central');
      const prs = (await api.read('GET /repos/{owner}/{repo}/pulls', { ...ref, head: `${appRef.owner}:${branch}`, state: 'closed', per_page: 100 })).data;
      const cid = rec.central?.repoId ?? loaded.centralRepoId;
      if (Array.isArray(prs) && prs.some((p) => isObj(p) && isObj(p.head) && p.head.ref === branch && isObj(p.head.repo) && p.head.repo.id === cid && isObj(p.base) && p.base.ref === def && typeof p.merged_at === 'string' && p.merged_at !== ''
        && centralHead !== undefined && p.head.sha === centralHead)) return;   // V6-R2 sec M1: this cycle's PR, at the head pipegen set
    }
    changed(`The install record ${String(rp)} in ${appRef.owner}/pipelines`);
  }

  /** 1: a saved proof's leftovers, then the scratch repo emptied (exact name, marker, the id the preview showed) through E's functions. */
  async function scratchStep(): Promise<void> {
    if (plan.proofCleanup) {
      const what = 'what the saved proof left in GitHub';
      try {
        const res = await api.proofLeftovers(ctx.store, { prompt: ctx.io as Prompter, out: ctx.out, err: ctx.out });
        r.done.push(`${what}: cleaned (as \`pipegen cleanup\` does)`);
        for (const l of res.leftovers) r.manual.push({ what, why: show(l, 400) });
      } catch (e) {
        if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
        r.failed.push({ what, why: reasonOf(e), manual: 'Run `pipegen cleanup`.' });
      } finally {
        // cleanupLeftovers gives the app's lease back when it ends: uninstall takes it again for the rest of its run
        ctx.store.acquireLease(`uninstall-${randomBytes(6).toString('hex')}`);
      }
    }
    const sc = plan.scratch;
    if (sc === undefined) return;
    const what = `scratch repo ${show(sc.repo, 140)}`;
    let s: GuardedRepo;
    try {
      const t = proofTarget({ owner: appRef.owner, repo: appRef.repo, private: loaded.app.private, ownerType: loaded.app.ownerType, defaultBranch: loaded.app.defaultBranch });
      s = assertScratch(t, appRef);
    } catch (e) {
      if (!(e instanceof ProofStopError || e instanceof ScratchGuardError)) throw e;
      r.manual.push({ what, why: `pipegen can't name its scratch repo safely (${show(e.message, 200)})`, step: 'Check it on GitHub and empty or delete it by hand.' });
      return;
    }
    // the marker and the id again, right before the first write
    let d: unknown;
    try { d = (await githubRead(gh, 'GET /repos/{owner}/{repo}', { owner: s.owner, repo: s.repo }, api.clock)).data; } catch (e) {
      if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
      if (statusOf(e) === 404) { r.done.push(`${what}: already gone`); return; }
      r.failed.push({ what, why: reasonOf(e) });
      return;
    }
    if (!isObj(d) || d.full_name !== s.fullName || d.description !== SCRATCH_MARKER || d.id !== sc.id) {
      r.skipped.push({ what, why: 'it doesn\'t carry pipegen\'s marker (or it is not the repo the preview showed), so pipegen leaves it' });
      return;
    }
    const def = typeof d.default_branch === 'string' ? d.default_branch : s.target.defaultBranch;
    // V6-R1 sec I1: `gh repo delete` only for the scratch repo the record says pipegen created (its id recorded and equal to GitHub's)
    const recorded = rec.scratch?.createdByPipegen === true && rec.scratch.repoId === sc.id;
    const orDelete = recorded ? `, or delete the repo: gh repo delete ${s.fullName}` : '';
    let left = 0;
    const one = async (item: string, fn: () => Promise<unknown>): Promise<void> => {
      try { await fn(); } catch (e) {
        if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
        const st = statusOf(e);
        if (typeof st === 'number' && SCRATCH_GONE.has(st)) return;
        left += 1;
        r.failed.push({ what: `${item} of ${what}`, why: reasonOf(e), manual: `Delete it in ${s.fullName} by hand${orDelete}` });
      }
    };
    const list = async (route: string, key: string | null, params: Record<string, unknown> = {}): Promise<unknown[] | null> => {
      try {
        const x = (await githubRead(gh, route, { owner: s.owner, repo: s.repo, per_page: 100, ...params }, api.clock)).data;
        const items = key === null ? x : isObj(x) ? x[key] : undefined;
        if (!Array.isArray(items)) throw new UninstallError('unreadable');
        if (key !== null && isObj(x) && typeof x.total_count === 'number' && x.total_count > items.length) {
          r.manual.push({ what: `${key.replace(/_/g, ' ')} of ${what}`, why: 'there are more than pipegen reads at once', step: `Run \`pipegen uninstall\` again${orDelete}` });
        }
        return items;
      } catch (e) {
        if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
        left += 1;
        r.failed.push({ what: `${key ?? 'the proof branches'} of ${what}`, why: 'pipegen couldn\'t list them', manual: `Check them in ${s.fullName}.` });
        return null;
      }
    };
    for (const x of await list('GET /repos/{owner}/{repo}/git/matching-refs/{ref}', null, { ref: 'heads/proof/' }) ?? []) {
      const b = isObj(x) && typeof x.ref === 'string' && x.ref.startsWith('refs/heads/proof/') ? x.ref.slice('refs/heads/'.length) : null;
      if (b === null || b === def || !validBranchName(b)) { left += 1; r.manual.push({ what: `a branch of ${what}`, why: 'its name is not one pipegen sends', step: `Delete it in ${s.fullName} by hand.` }); continue; }
      await one(`branch ${show(b, 120)}`, () => api.scratchCleanup(s, { op: 'delete-branch', branch: b }));
    }
    for (const x of await list('GET /repos/{owner}/{repo}/actions/secrets', 'secrets') ?? []) {
      const n = isObj(x) && typeof x.name === 'string' ? x.name : null;
      if (n !== null) await one(`secret ${show(n, 100)}`, () => api.scratchSecretDelete(s, n));
    }
    for (const x of await list('GET /repos/{owner}/{repo}/actions/variables', 'variables') ?? []) {
      const n = isObj(x) && typeof x.name === 'string' ? x.name : null;
      if (n !== null) await one(`variable ${show(n, 100)}`, () => api.scratchCleanup(s, { op: 'delete-variable', name: n }));
    }
    for (const x of await list('GET /repos/{owner}/{repo}/actions/runs', 'workflow_runs') ?? []) {
      const id = isObj(x) ? x.id : undefined;
      if (posId(id)) await one(`run ${id}`, () => api.scratchCleanup(s, { op: 'delete-run', runId: id }));
    }
    for (const x of await list('GET /repos/{owner}/{repo}/actions/caches', 'actions_caches') ?? []) {
      const id = isObj(x) ? x.id : undefined;
      if (posId(id)) await one(`cache ${id}`, () => api.scratchCleanup(s, { op: 'delete-cache', cacheId: id }));
    }
    if (left === 0) r.done.push(`${what}: emptied (its proof/ branches, secrets, variables, workflow runs and caches)`);
    if (!plan.deleteRepos.some((x) => x.kind === 'scratch' && x.how === 'delete')) {
      r.skipped.push({ what: `the default branch ${show(def, 100)} of ${what}`, why: recorded
        ? `it keeps the copy of your code the proof used (pipegen removes only what the proof added): delete the repo when you don't need it (gh repo delete ${s.fullName}, or run \`pipegen uninstall --delete-repos\` to print the command)`
        : 'it keeps the copy of your code the proof used (pipegen removes only what the proof added); the install record holds no id of this repo, so check it is the one pipegen made before you delete it' });
    }
  }

  /** 2: the settings the user chose to turn off (V-S6), each read first by target.ts and changed only while it is still as pipegen set it. */
  async function settingsStep(): Promise<void> {
    const keys = new Set(off.map((s) => s.key));
    if (keys.has('shaPinningRequired')) await attempt('setting: the full-length commit sha pin for actions', undefined, () => api.write('PUT /repos/{owner}/{repo}/actions/permissions', { ...appRef, enabled: true, sha_pinning_required: false }));
    if (keys.has('vulnerabilityAlerts')) await attempt('setting: Dependabot alerts', undefined, () => api.write('DELETE /repos/{owner}/{repo}/vulnerability-alerts', { ...appRef }));
    const sa: Record<string, { status: 'disabled' }> = {};
    if (keys.has('pushProtection')) sa.secret_scanning_push_protection = { status: 'disabled' };
    if (keys.has('secretScanning')) sa.secret_scanning = { status: 'disabled' };
    if (Object.keys(sa).length > 0) await attempt(`setting: ${keys.has('secretScanning') ? 'secret scanning' : ''}${keys.has('secretScanning') && keys.has('pushProtection') ? ' and ' : ''}${keys.has('pushProtection') ? 'push protection' : ''}`, undefined, () => api.write('PATCH /repos/{owner}/{repo}', { ...appRef, security_and_analysis: sa }));
  }

  /**
   * 4: one repo of --delete-repos (V-S3). App mode deletes (typed name, every check). Token mode (V6-R1 sec I1) prints `gh repo delete` only
   * after the same gates: the scratch repo read now (exact name, pipegen's marker, the recorded id); the central repo only as the last
   * project, with the org rule gone, the central PR merged and deleteCentralRepo's own checks passed (read only). Otherwise the reason.
   */
  async function repoStep(d: PhasePlan['deleteRepos'][number]): Promise<void> {
    const what = `repo ${show(d.repo, 140)}`;
    const command = `gh repo delete ${d.repo}`;
    const tokenMode = d.how !== 'delete' || ctx.deps.canDeleteRepos !== true;
    const noApp = '--delete-repos: a fine-grained token can\'t delete repos in v0.2 (pipegen\'s own GitHub App login, which can, is planned next), so pipegen deleted nothing';
    const hardStop = (e: unknown): void => { if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e; };
    if (d.kind === 'scratch') {
      let s: GuardedRepo;
      try { s = assertScratch(proofTarget({ owner: appRef.owner, repo: appRef.repo, private: loaded.app.private, ownerType: loaded.app.ownerType, defaultBranch: loaded.app.defaultBranch }), appRef); } catch (e) {
        if (!(e instanceof ProofStopError || e instanceof ScratchGuardError)) throw e;
        r.manual.push({ what, why: show(e.message, 200), step: 'Check it on GitHub; delete it by hand only if it is the scratch repo pipegen made.' });
        return;
      }
      if (s.fullName !== d.repo) { r.manual.push({ what, why: 'it is not the scratch repo of this app', step: 'Check it on GitHub.' }); return; }
      if (tokenMode) {
        const recId = rec.scratch?.createdByPipegen === true ? rec.scratch.repoId : undefined;
        let x: unknown;
        try { x = (await githubRead(gh, 'GET /repos/{owner}/{repo}', { owner: s.owner, repo: s.repo }, api.clock)).data; } catch (e) {
          hardStop(e);
          if (statusOf(e) === 404) { r.done.push(`${what}: already gone`); return; }
          r.failed.push({ what, why: reasonOf(e), manual: 'Run `pipegen uninstall --delete-repos` again.' });
          return;
        }
        if (!isObj(x) || x.full_name !== s.fullName || x.description !== SCRATCH_MARKER || !posId(recId) || x.id !== recId) {
          r.skipped.push({ what, why: 'it is not the scratch repo the install record says pipegen created (the exact name, pipegen\'s marker and the recorded id), so pipegen doesn\'t tell you to delete it' });
          return;
        }
        r.manual.push({ what, why: noApp, step: command });
        return;
      }
      let res;
      try { res = await api.scratchRepoDelete(s, rec.scratch?.repoId); } catch (e) {
        hardStop(e);
        r.failed.push({ what, why: reasonOf(e), manual: 'Run `pipegen uninstall --delete-repos` again.' });
        return;
      }
      if (res.deleted) r.done.push(`${what}: deleted`);
      else { r.skipped.push({ what, why: show(res.why ?? 'not deleted', 400) }); r.manual.push({ what, why: show(res.why ?? 'not deleted', 400), step: 'Check it on GitHub; delete it by hand only if it is the scratch repo pipegen made.' }); }
      return;
    }
    // the central repo: last project now, the org rule gone (M-r1-5), its PR merged (the record gone from central)
    const c = central as CentralOutcome | null;
    if (c === null) { r.failed.push({ what, why: 'not done: the central part of this run did not finish', manual: 'Run `pipegen uninstall --delete-repos` again.' }); return; }
    if (!c.last) { r.skipped.push({ what, why: `${c.lastWhy}, so pipegen keeps it` }); return; }
    if (!c.merged) {
      const url = c.pr === undefined ? '' : ` #${c.pr.number} (${show(c.pr.url, 300)})`;
      r.manual.push({ what, why: 'the central pull request that removes the install record is not merged yet, so the repo stays for now', step: `Merge the central pull request${url}, then run \`pipegen uninstall --delete-repos\` again.` });
      return;
    }
    // V6-R3 sec M2: the advice is to change something and come back, so the local files stay (r.failed) and the re-run can load
    if (c.orgRule !== null) { r.failed.push({ what, why: `${c.orgRule}, so pipegen keeps ${d.repo} for now`, manual: 'Delete the org rule in the organisation\'s settings (Rulesets), then run `pipegen uninstall --delete-repos` again.' }); return; }
    // hook-1, V6-R2 sec M3 (both modes): the heads pipegen recorded for its own central branches (the central uninstall branch it set)
    const known: Record<string, string> = centralHead === undefined ? {} : { [uninstallBranch({ owner: appRef.owner, repo: appRef.repo, repoId: plan.app.repoId }, 'central')]: centralHead };
    /** V6-R2 sec I1: a refusal never advises `gh repo delete`; one a later run may not meet keeps the local files (r.failed). */
    const refused = (res: CentralDeleteResult): void => {
      const why = show(res.why ?? 'pipegen\'s checks did not pass', 400);
      if (res.retry === true) { r.failed.push({ what, why, manual: res.step ?? 'Run `pipegen uninstall --delete-repos` again.' }); return; }
      r.skipped.push({ what, why });
      // spec M3 (V6-R3): this run removes the record, so no later run can come back to it
      r.manual.push({ what, why, step: res.step ?? `Check it on GitHub; pipegen doesn't tell you to delete it while it holds that, and it can't delete it for you after this run (the install record goes with this run): what to do with ${d.repo} is yours to decide.` });
    };
    if (tokenMode) {
      let res: CentralDeleteResult;
      try { res = await api.checkCentralRepo(rec, known); } catch (e) {
        hardStop(e);
        r.failed.push({ what, why: reasonOf(e), manual: 'Run `pipegen uninstall --delete-repos` again.' });
        return;
      }
      const ownNames = (res.own ?? []).map((b) => `${show(b.branch, 120)} (at ${b.sha.slice(0, 12)})`).join(' and ');
      if (res.ready !== true) { refused(res); return; }
      const prs = (res.prs ?? []).length > 0 ? `; check its pull requests ${(res.prs ?? []).map((n) => `#${n}`).join(', ')} are pipegen's first` : '';
      const unread = (res.unchecked ?? []).length > 0 ? `; pipegen couldn't read ${show((res.unchecked ?? []).join(' or '), 200)}` : '';
      const branchesToo = ownNames === '' ? '' : `; pipegen's own branches ${ownNames} go with it`;
      r.manual.push({ what, why: `${noApp}. pipegen checked it holds nothing but pipegen's${branchesToo}${prs}${unread}`, step: command });
      return;
    }
    // V6-R1 sec M2: pipegen's own central branches go with the repo, inside deleteCentralRepo (named in its question): never before it
    let res;
    // V6-R3 sec M1, hook-3: the marker is pending right before the DELETE, confirmed only once GitHub accepts it; any other way out clears it
    const vouched = await readLocalRecord(appRef, ctx.deps.local ?? {}).catch(() => null);
    let attempted = false;
    let accepted = false;
    const repoId = rec.central?.repoId ?? loaded.centralRepoId;
    const marker = vouched === null ? undefined : {
      beforeDelete: () => { attempted = true; deleteSent = { repoId, recordHash: vouched.recordHash, confirmed: false }; save(); },
      deleteAccepted: () => { accepted = true; deleteSent = { repoId, recordHash: vouched.recordHash, confirmed: true }; save(); },
    };
    try {
      try { res = await api.removeCentralRepo(rec, known, marker); } catch (e) {
        hardStop(e);
        r.failed.push({ what, why: reasonOf(e), manual: 'Run `pipegen uninstall --delete-repos` again.' });
        return;
      }
    } finally {
      if (attempted && !accepted) { deleteSent = undefined; save(); }
    }
    if (res.deleted) {
      r.done.push(`${what}: deleted${res.progressNotSaved === true ? ', but the progress file could not be saved' : ''}`);
      // V6-R3 sec M1: what was left inside central went with it (GitHub answered 404 after the DELETE)
      const inRepo = new Set(c.inRepo ?? []);
      for (const f of r.failed.filter((x) => inRepo.has(x.what))) r.done.push(`${f.what}: went with the repo`);
      r.failed = r.failed.filter((x) => !inRepo.has(x.what));
      for (const u of res.unchecked ?? []) r.manual.push({ what, why: `deleted without pipegen reading ${show(u, 200)}`, step: 'Nothing to do now; the token could not show them before the delete.' });
    } else if (res.command !== undefined) {
      // every check passed and the user declined `pipelines`: the command is theirs to run
      r.skipped.push({ what, why: show(res.why ?? 'not deleted', 400) });
      r.manual.push({ what, why: show(res.why ?? 'not deleted', 400), step: res.command });
    } else refused(res);
  }

  /** V-N5: the leftovers file's entries for this repo not handled yet (still on GitHub, or not put back now); any other repo's keeps it. */
  async function unhandledLeftovers(): Promise<{ what: string; why: string; step?: string }[]> {
    let items: Leftover[];
    try { items = await readLocalLeftovers(appRef, ctx.deps.local ?? {}); } catch (e) {
      return [{ what: leftoversPath(), why: `pipegen couldn't read it (${show(e instanceof Error ? e.message : 'unreadable', 200)}), so it keeps it`, step: 'Check it, then remove it by hand.' }];
    }
    const out: { what: string; why: string; step?: string }[] = [];
    const still = async (route: string, params: Record<string, unknown>): Promise<boolean> => {
      try { const d = (await api.read(route, { ...appRef, ...params })).data; return !(isObj(d) && d.state === 'closed'); } catch (e) {
        if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
        return statusOf(e) !== 404;
      }
    };
    for (const x of items) {
      const what = `${x.kind} ${show(x.name, 100)} (leftovers file)`;
      if (x.repo.toLowerCase() !== full.toLowerCase()) { out.push({ what, why: `it is listed for another repo (${show(x.repo, 140)}), so pipegen keeps the leftovers file` }); continue; }
      let open = true;
      try {
        if (x.kind === 'secret') {
          const scope = x.scope ?? 'repo';
          open = scope === 'repo' ? await still('GET /repos/{owner}/{repo}/actions/secrets/{secret_name}', { secret_name: x.name })
            : /^env:.+$/.test(scope) ? await still('GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', { environment_name: scope.slice(4), secret_name: x.name }) : true;
        } else if (x.kind === 'environment') {
          open = x.previous === undefined ? await still('GET /repos/{owner}/{repo}/environments/{environment_name}', { environment_name: x.name }) : !restoredEnvs.has(x.name);
        } else if (x.kind === 'branch') {
          open = await still('GET /repos/{owner}/{repo}/git/ref/{ref}', { ref: `heads/${x.name}` });
        } else {
          const n = /^#?([1-9][0-9]{0,9})$/.exec(x.name)?.[1];
          open = n === undefined ? true : await still('GET /repos/{owner}/{repo}/pulls/{pull_number}', { pull_number: Number(n) });
        }
      } catch (e) {
        if (!(e instanceof UninstallRefusal)) throw e;
        open = true;
      }
      if (open) out.push({ what, why: 'it is still there on GitHub (or pipegen can\'t tell it is handled), so pipegen keeps the leftovers file and the local record', step: `Handle it by hand, then remove ${leftoversPath()}.` });
    }
    return out;
  }

  function leftoversPath(): string { return localRecordPath(appRef, ctx.deps.local ?? {}).replace(/\.json$/, '.leftovers.json'); }

  /** What to do next (the final message's end). */
  function nextOf(c: CentralOutcome | null): string[] {
    const again = `pipegen uninstall${ctx.deps.deleteRepos === true ? ' --delete-repos' : ''}`;
    const out: string[] = [];
    if (r.failed.length > 0) out.push(`Some steps were not done (above). Run \`${again}\` again: it plans the second run again and does what is left.`);
    if (c !== null && !c.merged && c.pr !== undefined) out.push(`Merge the central pull request #${c.pr.number} (${show(c.pr.url, 300)}) in ${appRef.owner}/pipelines, then run \`${again}\` again to finish (the local files go then).`);
    if (r.status === 'b-done') out.push(`pipegen is uninstalled from ${full}.`);
    out.push(APP_STEP(full));
    return out;
  }
}

/** Done, not done, kept and manual steps, as lines (names only). */
function summary(r: StepResult): string[] {
  const out: string[] = [];
  const list = (title: string, items: string[]): void => { if (items.length > 0) out.push(title, ...items); };
  list('Done:', r.done.map((d) => `  - ${show(d, 300)}`));
  list('Not done (the next run tries again):', r.failed.map((f) => `  - ${show(f.what, 200)}: ${show(f.why, 400)}${f.manual === undefined ? '' : `\n    ${show(f.manual, 300)}`}`));
  list('Kept:', r.skipped.map((s) => `  - ${show(s.what, 200)}: ${show(s.why, 400)}`));
  list('Manual steps (pipegen doesn\'t do these):', r.manual.map((m) => `  - ${show(m.what, 200)}: ${show(m.why, 400)}${m.step === undefined ? '' : `\n    ${show(m.step, 400)}`}`));
  return out;
}

/** Why a step failed, for the message (names only; an unknown error's text is cut and made safe). */
function reasonOf(e: unknown): string {
  if (e instanceof UninstallRefusal || e instanceof UninstallError || e instanceof DeliverError || e instanceof ScratchGuardError || e instanceof ProofStopError) return show(e.message, 300);
  const s = statusOf(e);
  if (s !== undefined) return `GitHub answered HTTP ${s}`;
  return `an unexpected error (${show(e instanceof Error ? e.name : typeof e, 60)})`;
}
