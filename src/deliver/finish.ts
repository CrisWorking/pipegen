// v0.2 Plan G Task 7, finish (sub-task G11; rulings S10, S11, S13, S18, S24; rows S-7, P-7): after the setup pull request is merged,
// `pipegen finish` applies what must not exist before the merge, and records it. This file is the orchestrator (`finish`, the order of
// the nine steps, the block date, the pending file and the stop handling); the other steps live in their own modules:
//   finish-base (types, errors, shared helpers), finish-rulesets (ruleset upsert), finish-settings (steps 1-3), finish-signing (steps 4-5),
//   finish-central (steps 7 and 9, the central CODEOWNERS), finish-probe (the live probe); step 8 is writeRecord in record.ts.
//
// Inputs: ONLY the install record (read through the one trust order, trust.ts) and GitHub as it is now. finish takes the app's name and
// nothing of the run that delivered it (Review Focus 11). It re-probes and calls planLocks again: the requests it sends are the ones
// planned NOW, for the items the record planned. A planned item GitHub no longer allows is skipped with a plain reason; a route in the
// record's `planned` that pipegen never makes stops finish before anything is sent. A record trusted by typing (G10-R5) carries no
// `planned`, merge time, block date or public key: finish re-derives what it can and says what it couldn't.
//
// Every refused or failed write is named to the user and left out of the record (G8-R3). A setting pipegen turns on records the value it
// had, once; each such value is saved to a local 0600 pending file BEFORE the write that changes it, so a run that stops before its record
// is written loses nothing (the next finish records it). The central ruleset is switched on LAST.
//
// `--print` applies nothing: it prints the exact `gh api` commands (never a secret value). A later `finish` finds what they made.
import type { Octokit } from '@octokit/rest';
import { COSIGN_KEY_SECRET } from '../create/secrets.js';
import { centralWorkflowFile } from '../engine/central-path.js';
import { CALLER_WORKFLOW } from '../engine/job-rules.js';
import { clockOf } from '../github/client.js';
import { readOrgAdmin, readShaPinning, readWriters } from '../github/lock-probes.js';
import { signingMode } from '../github/signing-mode.js';
import { CENTRAL_RULESET, LockError, planLocks, type LockPlan } from '../layers/locks.js';
import { CENTRAL_REPO } from '../proof/target.js';
import { emptyRepoFiles } from '../read/quality.js';
import { PROTECTED_PATHS_BASE, type CreatedFile, type ExistingWorkflow, type InstallPlanned, type InstallRecord, type RepoProfile } from '../types.js';
import { coCaseProblem } from './co-case.js';
import { plannedOfLocks, SETUP_BRANCH } from './deliver.js';
import { DeliverError, isoAt, readBlobText, readHead, readRepo, readTree, type RepoRef } from './git-data.js';
import { holdAppLease, isLeaseStop, stateDepsOf, type ReleaseLease } from '../proof/lease.js';
import { centralOf, centralUpdateBranch, recordPath, protectedPathsOfRecord, readFinishPending, readLocalRecord, RecordError, writeFinishPending, writeRecord, type FinishPending } from './record.js';
import { holdsWanted, isObj, PLANNED_ROUTES, SettingsApi } from './settings-api.js';
import { trustedPrevious } from './trust.js';
import { BLOCK_FROM_VAR, COSIGN_PUB_VAR, SIGNING_SCOPE, DAY_MS, MAX_TEXT, show, FinishError, CoCaseError, StepError, type FinishOpts, type FinishDeps, type FinishResult, type Ctx, isStop, whyOf, step, earliestBlockFrom, pendingPath, centralParams, ownersOf, coFacts } from './finish-base.js';
import { getRuleset } from './finish-rulesets.js';
import { appLocks, shaPinning, securitySettings, actionsAccess, orgRequired } from './finish-settings.js';
import { environments, setVariable, signing } from './finish-signing.js';
import { centralRuleset, centralCodeowners } from './finish-central.js';
export { FINISH_WRITE_ROUTES } from './settings-api.js';
/** G-COCASE-R1/R2: shared with setup and deliver (co-case.ts, no import cycle). */
export { coCaseProblem } from './co-case.js';
export { CoCaseError, FinishError, coFacts, earliestBlockFrom } from './finish-base.js';
export type { CoFacts, FinishDeps, FinishOpts, FinishProbe, FinishProbeResult, FinishResult } from './finish-base.js';
export { githubFinishProbe } from './finish-probe.js';

// ---------- the record ----------

function buildRecord(x: Ctx, mergedAt: string, blockFrom: string): InstallRecord {
  const r = x.rec;
  const handled = new Set(x.rulesets.keys());
  return {
    ...r, mergedAt, blockFrom, files: x.files, edits: x.edits,
    secrets: [...r.secrets.filter((s) => !x.secrets.some((n) => n.name === s.name && n.scope === s.scope)), ...x.secrets],
    variables: [...r.variables.filter((v) => !x.variables.some((n) => n.name === v.name && n.scope === v.scope)), ...x.variables],
    environments: [...r.environments.filter((e) => !x.environments.has(e.name)), ...x.environments.values()],
    rulesets: [...r.rulesets.filter((s) => !handled.has(s.kind)), ...x.rulesets.values()],
    ...(x.classic ?? r.classicProtection) === undefined ? {} : { classicProtection: x.classic ?? r.classicProtection },
    ...(x.orgRuleset ?? r.orgRuleset) === undefined ? {} : { orgRuleset: x.orgRuleset ?? r.orgRuleset },
    ...(Object.keys({ ...r.repoSettings, ...x.repoSettings }).length === 0 ? {} : { repoSettings: { ...r.repoSettings, ...x.repoSettings } }),
    central: { ...(r.central ?? { createdByPipegen: false }), ...x.centralRec },
    planned: x.typed ? x.planned : appliedPlanned(x.planned, x.fresh),
    ...(x.cosign === undefined ? {} : { cosignPubSha256: x.cosign.sha, cosignPub: x.cosign.pub }),
  };
}

/**
 * G17 row 44 (G11 r1 sec): the `planned` finish records is the plan it applied: each lock request the record planned, as planLocks makes it NOW
 * (the request finish sent), so verify's baseline (the review count, code-owner review, last-push approval) is never a weaker plan planted in
 * the record. A planned lock planLocks can't plan now (finish skipped it, with a reason) keeps the record's request, so verify still reports it
 * missing. The rest (signing mode, environments, owners) is the record's, as finish applied it.
 */
function appliedPlanned(p: InstallPlanned, f: LockPlan): InstallPlanned {
  const out: InstallPlanned = structuredClone(p);
  if (p.rulesets !== undefined && f.rulesets !== undefined) {
    out.rulesets = { gate: structuredClone(f.rulesets.gate), ...(p.rulesets.reviews === undefined ? {} : { reviews: structuredClone(f.rulesets.reviews ?? p.rulesets.reviews) }) };
  }
  if (p.classic !== undefined && f.classic !== undefined) out.classic = structuredClone(f.classic);
  if (p.centralRuleset !== undefined && f.centralRuleset !== undefined) out.centralRuleset = structuredClone(f.centralRuleset);
  if (p.orgRequiredWorkflow !== undefined && f.orgRequiredWorkflow !== undefined) out.orgRequiredWorkflow = { path: f.orgRequiredWorkflow.file.path, rule: structuredClone(f.orgRequiredWorkflow.rule) };
  if (p.shaPinning !== undefined && f.shaPinning !== undefined) out.shaPinning = structuredClone(f.shaPinning);
  return out;
}

// ---------- the setup pull request ----------

async function setupPr(x: { api: SettingsApi; app: RepoRef; branch: string }, local: number | undefined): Promise<{ number: number; mergedAt: string | null; state: string }> {
  let num = local;
  if (num === undefined) {
    const d = (await x.api.read('GET /repos/{owner}/{repo}/pulls', { owner: x.app.owner, repo: x.app.repo, head: `${x.app.owner}:${SETUP_BRANCH}`, state: 'all', per_page: 100 })).data;
    const list = Array.isArray(d) ? d.filter(isObj).filter((p) => isObj(p.head) && p.head.ref === SETUP_BRANCH && isObj(p.base) && p.base.ref === x.branch && Number.isSafeInteger(p.number)) : [];
    num = list.map((p) => p.number as number).sort((a, b) => b - a)[0];
    if (num === undefined) throw new FinishError(`pipegen can't find its setup pull request (branch ${SETUP_BRANCH}) in ${show(`${x.app.owner}/${x.app.repo}`)}, so it applies nothing. Run pipegen first.`);
  }
  const d = (await x.api.read('GET /repos/{owner}/{repo}/pulls/{pull_number}', { owner: x.app.owner, repo: x.app.repo, pull_number: num })).data;
  if (!isObj(d) || !isObj(d.head) || d.head.ref !== SETUP_BRANCH) throw new FinishError(`Pull request #${num} of ${show(`${x.app.owner}/${x.app.repo}`)} is not pipegen's setup pull request, so pipegen applies nothing.`);
  // m9: only a merge into the default branch is the merge finish waits for
  if (!isObj(d.base) || d.base.ref !== x.branch) throw new FinishError(`The setup pull request #${num} of ${show(`${x.app.owner}/${x.app.repo}`)} is not merged into the default branch ${show(x.branch, 100)} (it targets ${isObj(d.base) && typeof d.base.ref === 'string' ? show(d.base.ref, 100) : 'another branch'}), so pipegen applies nothing. Run \`npx pipegen run\` again to open a new one.`);
  const merged = isoAt(d.merged_at) ? d.merged_at : null;
  return { number: num, mergedAt: merged, state: typeof d.state === 'string' ? d.state : '' };
}

/** A record's `planned` request that pipegen never makes (each slot has one route), or null. */
function plannedRouteProblem(p: InstallPlanned): string | null {
  const slots: [string, { method: string; route: string } | undefined][] = [
    [PLANNED_ROUTES.rulesets, p.rulesets?.gate], [PLANNED_ROUTES.rulesets, p.rulesets?.reviews], [PLANNED_ROUTES.classic, p.classic],
    [PLANNED_ROUTES.centralRuleset, p.centralRuleset], [PLANNED_ROUTES.orgRequiredWorkflow, p.orgRequiredWorkflow?.rule], [PLANNED_ROUTES.shaPinning, p.shaPinning?.request],
  ];
  for (const [want, r] of slots) if (r !== undefined && `${r.method} ${r.route}` !== want) return `${r.method} ${r.route}`;
  return null;
}

// ---------- finish ----------

/**
 * `pipegen finish` for the app `app` (see the header). Throws FinishError, with nothing applied, when the record can't be trusted, the
 * setup pull request isn't merged, or the locks can't be planned again.
 */
/**
 * Plan V M5: finish holds the app's lease for its whole run (the same lease as run, cleanup and uninstall), taken before its first GitHub
 * call: another pipegen working on this repo on this machine (an uninstall's phase A, an update) is a stop, nothing read or applied. run
 * passes its own lease down (`deps.lease`). Given back on every exit path.
 */
export async function finish(gh: Octokit, app: RepoRef, opts: FinishOpts, deps: FinishDeps): Promise<FinishResult> {
  let release: ReleaseLease;
  try {
    release = await holdAppLease(app, 'finish', { held: deps.lease, state: stateDepsOf(deps.local) });
  } catch (e) {
    if (isLeaseStop(e)) throw new FinishError(`${e.message} Nothing was applied.`, { cause: e });
    throw e;
  }
  try {
    return await finishHeld(gh, app, opts, deps);
  } finally {
    release();
  }
}

async function finishHeld(gh: Octokit, app: RepoRef, opts: FinishOpts, deps: FinishDeps): Promise<FinishResult> {
  const clock = deps.clock ?? clockOf(gh);
  const notes: string[] = [];
  const stop = (e: unknown): never => {
    if (isStop(e) || e instanceof FinishError) throw e;
    if (e instanceof DeliverError || e instanceof RecordError || e instanceof LockError) throw new FinishError(`${e.message} Nothing was applied.`, { cause: e });
    throw e;
  };
  const api = new SettingsApi(gh, app, clock);
  const central = centralOf(app);
  let x: Ctx;
  let pr: { number: number; mergedAt: string };
  let blockFrom: string;
  try {
    // 1. the repos and the record (the one trust order)
    const appRepo = await readRepo(gh, app, clock);
    if (appRepo === null) throw new FinishError(`pipegen can't see ${show(`${app.owner}/${app.repo}`)}, so it applies nothing.`);
    const centralRepo = await readRepo(gh, central, clock);
    if (centralRepo === null || !centralRepo.private) throw new FinishError(`pipegen can't see the private ${show(`${central.owner}/${central.repo}`)}, where the install record is, so it applies nothing.`);
    const update = centralUpdateBranch(app.repo);
    const updateExists = await readHead(gh, central, update, clock) !== null;
    const trusted = await trustedPrevious(gh, app, central, centralRepo.defaultBranch, updateExists ? update : null, deps.local ?? {}, clock, notes, deps.io === undefined ? undefined : { io: deps.io, interactive: deps.interactive === true });
    if (trusted.record === null) {
      // PL-E7: a hand-committed record whose block date is no real day: name the date and the file to fix
      if (trusted.badBlockDate !== undefined) throw new FinishError(`The install record's block date ${show(trusted.badBlockDate)} is not a real day (a day looks like 2026-11-08, and the gate reads no other), so finish stops and applies nothing; fix the date in ${recordPath(app.repo)} in ${show(`${central.owner}/${central.repo}`)} (on the branch that holds the bad date), then run \`npx pipegen finish\` again.${notes.length > 0 ? ` ${notes.join(' ')}` : ''}`);
      throw new FinishError(`${trusted.exists ? `pipegen found no install record for ${show(`${app.owner}/${app.repo}`)} that it trusts` : `There is no install record for ${show(`${app.owner}/${app.repo}`)}`}, so it applies nothing: finish reads what to apply only from the record. ${!trusted.exists ? 'Run pipegen first.' : trusted.why === 'unreadable' ? 'Remove or fix that local record file, then run `npx pipegen finish` again at a terminal to confirm the record by typing the repo name.' : 'Run finish on the machine that set it up, or interactively to confirm the record by typing the repo name.'}${notes.length > 0 ? ` ${notes.join(' ')}` : ''}`);
    }
    const rec = trusted.record;
    const local = await readLocalRecord(app, deps.local ?? {}).catch((e: unknown) => { if (e instanceof RecordError) return null; throw e; });
    const typed = local?.typed === true;
    if (rec.app.repoId !== appRepo.id || rec.app.owner.toLowerCase() !== app.owner.toLowerCase() || rec.app.repo.toLowerCase() !== app.repo.toLowerCase()) throw new FinishError('The install record is not this repository\'s (another repo id or name), so pipegen applies nothing.');
    if (rec.app.private !== appRepo.private || rec.app.defaultBranch !== appRepo.defaultBranch) throw new FinishError(`${show(`${app.owner}/${app.repo}`)} changed since pipegen set it up (${rec.app.private !== appRepo.private ? `it is ${appRepo.private ? 'private' : 'public'} now` : `its default branch is ${show(appRepo.defaultBranch, 100)} now`}), so pipegen applies nothing; run \`npx pipegen run\` again.`);
    // G10 re-review r2: a request pipegen never makes stops everything before anything is sent
    const badRoute = typed ? null : plannedRouteProblem(rec.planned);
    if (badRoute !== null) throw new FinishError(`The install record plans a request pipegen never makes (${show(badRoute, 120)}), so pipegen applies nothing. The record was changed by someone else; run \`npx pipegen run\` again to write a new one.`);
    if (opts.rotateKey === true && !typed && rec.planned.signingMode !== 'key-env') throw new FinishError('--rotate-key works only in key-env signing mode (a cosign key kept in the pipegen-signing environment); this repo signs another way, so pipegen applies nothing.');

    // 2. the setup pull request must be merged
    const p = await setupPr({ api, app, branch: appRepo.defaultBranch }, local?.setupPr);
    if (p.mergedAt === null) {
      throw new FinishError(p.state === 'closed'
        ? `The setup pull request #${p.number} was closed without being merged, so pipegen applies nothing. Run \`npx pipegen run\` again to open a new one.`
        : `The setup pull request #${p.number} is not merged yet, so pipegen applies nothing: the settings come after the merge, or the pull request could not merge. Merge it, then run \`npx pipegen finish\`.`);
    }
    pr = { number: p.number, mergedAt: p.mergedAt };

    // 3. re-probe (S10, G8 carry) and plan the locks again
    const probed = await deps.probe(gh, app, { private: appRepo.private, ownerType: appRepo.ownerType, defaultBranch: appRepo.defaultBranch, centralDefaultBranch: centralRepo.defaultBranch }, notes, clock);
    const writers = await readWriters(gh, app.owner, app.repo, CENTRAL_REPO, clock, 'finish');
    const orgAdmin = await readOrgAdmin(gh, app.owner, appRepo.ownerType, notes, clock);
    const shaRead = await readShaPinning(gh, app.owner, app.repo, notes, clock);
    const appHead = await readHead(gh, app, appRepo.defaultBranch, clock);
    const centralHead = await readHead(gh, central, centralRepo.defaultBranch, clock);
    if (appHead === null || centralHead === null) throw new FinishError('A default branch of the app or the central repo is missing, so pipegen applies nothing.');
    const appTree = (await readTree(gh, app, appHead, clock)).entries;
    const centralTree = (await readTree(gh, central, centralHead, clock)).entries;
    // G-COCASE-R1: a CODEOWNERS case variant in either repo stops finish here, before its first write
    const caseStop = coCaseProblem([{ label: `${app.owner}/${app.repo}`, paths: appTree.keys() }, { label: `${central.owner}/${central.repo}`, paths: centralTree.keys() }], 'npx pipegen finish');
    if (caseStop !== null) throw new CoCaseError(caseStop);
    const appCo = await coFacts(gh, app, appTree, clock);
    const centralCo = await coFacts(gh, central, centralTree, clock);
    const files: CreatedFile[] = [];
    for (const [repo, ref, tree, path] of [['app', app, appTree, CALLER_WORKFLOW], ['central', central, centralTree, centralWorkflowFile(app.repo, 'merge')]] as const) {
      const e = tree.get(path);
      if (e !== undefined && e.type === 'blob') files.push({ path, content: await readBlobText(gh, ref, e.sha, MAX_TEXT, clock), part: 'pipeline', reason: 'on the default branch', repo });
    }
    const pins = probed.workflowPins;
    const existingWorkflows: ExistingWorkflow[] = pins.tagPinned > 0 || pins.unchecked ? [{ path: '.github/workflows', triggers: [], deploys: false, secretsUsed: [], jobs: [], ...(pins.tagPinned > 0 ? { tagPinned: pins.tagPinned } : {}), ...(pins.unchecked ? { usesUnchecked: true as const } : {}) }] : [];
    const profile: RepoProfile = {
      owner: app.owner, repo: app.repo, defaultBranch: appRepo.defaultBranch, private: appRepo.private, ownerType: appRepo.ownerType, plan: probed.plan, monorepo: 'none',
      services: [], terraformDirs: [], hasCompose: false, existingWorkflows, precommit: null, repoFiles: { ...emptyRepoFiles(), codeowners: appCo.path },
    };
    // the inputs from the record (a typed record carries none: re-derived from the CODEOWNERS block on the default branch)
    const owners = typed ? ownersOf(appCo.block) : rec.planned.owners.app;
    const protectedPaths = rec.protectedPaths.length > 0 ? protectedPathsOfRecord(rec.protectedPaths) : [...PROTECTED_PATHS_BASE];
    const coEdit = rec.edits.find((e) => e.repo === 'app' && e.kind === 'codeowners' && e.path === appCo.path) as { inserted: string } | undefined;
    const inserted = coEdit !== undefined && appCo.text.split(coEdit.inserted).length === 2 ? coEdit.inserted : appCo.block;
    const fresh = planLocks({
      profile, caps: probed.caps,
      central: { repo: `${central.owner}/${central.repo}`, sha: rec.centralSha ?? centralHead, branchProtection: probed.centralBranchProtection, codeowners: { path: centralCo.path, original: centralCo.text, isSymlink: centralCo.isSymlink, inserted: centralCo.block } },
      writers, owners, orgAdmin, shaPinning: shaRead, protectedPaths,
      appCodeowners: { original: appCo.text, isSymlink: appCo.isSymlink, inserted }, ids: { app: appRepo.id, central: centralRepo.id }, files,
      command: 'finish', version: rec.pipegenVersion,   // PL-D1-R1: the required workflow's header names the version that delivered it, so its text (and blob sha) is the one in the central repo
    });
    let planned = rec.planned;
    if (typed) {
      const mode = rec.secrets.some((s) => s.scope === SIGNING_SCOPE && s.name === COSIGN_KEY_SECRET) ? 'key-env' : signingMode(profile, { ...probed.caps, deploymentBranchPolicies: false });
      planned = plannedOfLocks(fresh, mode, []);
      notes.push('The install record was confirmed by typing, so pipegen planned the locks again from GitHub (the code owners from the CODEOWNERS block on the default branch). pipegen couldn\'t re-derive the environments the setup planned (that record doesn\'t carry them): run `npx pipegen run` again to set them up.');
    }
    if (opts.rotateKey === true && planned.signingMode !== 'key-env') throw new FinishError('--rotate-key works only in key-env signing mode (a cosign key kept in the pipegen-signing environment); this repo signs another way, so pipegen applies nothing.');
    // I1: what an earlier run saved before it stopped (an unreadable file stops here, nothing applied; it is never overwritten)
    const pending = await readFinishPending(app, appRepo.id, deps.local ?? {});
    // I2 (S18: never looser): the earliest of the merge day + 7, the date the record vouches, and the variable's own date when it is a real
    // day. Fix round 2: the variable counts for every record, typed or vouched (a re-delivery after a typed trust writes a vouched record
    // with no blockFrom; a finish that set the variable may have stopped before its record was written)
    const mergeDay = new Date(Date.parse(`${p.mergedAt.slice(0, 10)}T00:00:00Z`) + 7 * DAY_MS).toISOString().slice(0, 10);
    // G11-R3 (R2-6): a typed run also counts the blockFrom of the record behind the typed view (unvouched: it can only make the date earlier;
    // N3-1: only a day the gate reads as a date, so year 0000 never turns the block date off)
    const unvouched = typed ? trusted.unvouchedBlockFrom ?? '' : '';
    const v = await api.readOr404('GET /repos/{owner}/{repo}/actions/variables/{name}', { owner: app.owner, repo: app.repo, name: BLOCK_FROM_VAR });
    const varDay = isObj(v) && typeof v.value === 'string' ? v.value : '';
    blockFrom = earliestBlockFrom(mergeDay, [rec.blockFrom, unvouched, varDay]);
    if (blockFrom !== mergeDay) notes.push(`${BLOCK_FROM_VAR} stays ${blockFrom}, the earlier date: a later merge never moves the end of the warn period later.`);
    x = {
      gh, api, app, central, clock, deps, print: opts.print === true, rotate: opts.rotateKey === true,
      rec, typed, planned, fresh, profile, caps: probed.caps, shaRead, pending, repoId: appRepo.id, branch: appRepo.defaultBranch, ownerType: appRepo.ownerType, private: appRepo.private,
      centralHead, centralBranch: centralRepo.defaultBranch, centralTree, centralCo,
      applied: [], skipped: [], notes, commands: [],
      rulesets: new Map(), repoSettings: {}, centralRec: {}, environments: new Map(), variables: [], secrets: [],
      centralFiles: [], files: rec.files.map((f) => ({ ...f, shas: [...f.shas] })), edits: rec.edits.map((e) => structuredClone(e)),
    };
  } catch (e) {
    return stop(e);
  }

  const mergedAt = pr.mergedAt;
  const day = blockFrom;

  // 4. the settings, in order (each named when refused); the central ruleset last. I1: a stop here (a rate limit, a rejected token, an
  // error no step expects) prints what was applied and what the pending file keeps before it passes through
  try {
    await appLocks(x);
    await shaPinning(x);
    await securitySettings(x);
    await actionsAccess(x);
    await orgRequired(x);
    await environments(x);
    await signing(x);
    await step(x, `${BLOCK_FROM_VAR} = ${day}`, () => setVariable(x, 'repo', BLOCK_FROM_VAR, day, `${BLOCK_FROM_VAR} = ${day} (the end of the warn period)`));
    await centralRuleset(x);
    centralCodeowners(x);
  } catch (e) {
    report(x, deps.out, x.print ? 'print' : 'unrecorded', stopWhy(e));
    throw e;
  }

  if (x.print) {
    deps.out(`pipegen finish --print for ${x.app.owner}/${x.app.repo}: nothing is applied. Review these commands, run them yourself, then run \`npx pipegen finish\` to record what they made:`);
    for (const c of x.commands) deps.out(c);
    report(x, deps.out, 'print');
    return { applied: [], skipped: x.skipped, notes: x.notes, commands: x.commands };
  }

  // 5. the record (the central CODEOWNERS with it), then the central ruleset switched on, last
  const record = buildRecord(x, mergedAt, day);
  let written: Awaited<ReturnType<typeof writeRecord>>;
  try {
    // the central rule is on already (reused, or made by an earlier finish): the record goes through the central pull request; a new rule
    // is still switched off here, so the record commit goes straight to the default branch (a refused direct move falls back to the PR)
    const via = x.centralRec.rulesetId !== undefined && x.activate === undefined ? 'pr' : 'direct';
    written = await writeRecord(gh, { record, setupPr: pr.number, via, files: x.centralFiles, base: x.centralHead, clock, command: 'finish', ...(deps.now === undefined ? {} : { now: deps.now }), ...(deps.local === undefined ? {} : { local: deps.local }) });
  } catch (e) {
    report(x, deps.out, 'unrecorded', stopWhy(e));
    if (isStop(e)) throw e;
    const kept = hasPending(x) ? ` What the settings were before pipegen changed them is kept in ${pendingPath(x)}, and that run records it.` : '';
    throw new FinishError(`pipegen applied ${x.applied.length === 0 ? 'nothing' : x.applied.join(', ')}, but couldn't write the install record (${whyOf(e)}); run \`npx pipegen finish\` again to record it.${kept}${x.activate === undefined ? '' : ' The central merge rule was made but is not switched on yet.'}${x.newKey === true ? ' Run it with --rotate-key: the record still names the old public key.' : ''}`, { cause: e });
  }
  x.notes.push(...written.notes);
  // m1: what verify checks after a key rotation depends on where the record went
  if (x.newKey === true) {
    x.notes.push(written.via === 'pr'
      ? '`npx pipegen verify` reports the key as changed until the central pull request with the new install record is merged.'
      : `The install record on ${x.central.owner}/${x.central.repo} names the new key now, so \`npx pipegen verify\` checks ${COSIGN_PUB_VAR} against the new key.`);
  }
  // I1: what the record now holds leaves the pending file (the rest stays for the next run)
  await prunePending(x, record);
  if (x.centralFiles.length > 0) x.applied.push(`the central CODEOWNERS (${x.centralFiles.map((f) => f.path).join(', ')})`);
  x.applied.push(written.via === 'direct' ? `the install record on ${x.central.owner}/${x.central.repo}` : `the install record in the central pull request ${written.centralPr?.url ?? ''} (merge it)`);
  if (x.activate !== undefined) {
    const a = x.activate;
    try {
      await x.api.write('PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}', { ...centralParams(x), ruleset_id: a.id, ...a.body });
      const back = await getRuleset(x, { kind: 'repo', repo: x.central }, a.id);
      if (back === null || !holdsWanted(a.body, back)) throw new StepError('The central ruleset doesn\'t read back as switched on.');
      x.applied.push(a.what);
    } catch (e) {
      // m4: the record lists this ruleset (its id), so the report names it apart from what the record doesn't list
      x.activationFailed = { id: a.id, why: isStop(e) ? stopWhy(e) : whyOf(e) };
      x.skipped.push({ what: a.what, why: x.activationFailed.why });
      if (isStop(e)) { report(x, deps.out, 'recorded'); throw e; }
    }
  }
  report(x, deps.out, 'recorded');
  return { applied: x.applied, skipped: x.skipped, notes: x.notes, recordHash: written.recordHash, ...(written.centralPr === undefined ? {} : { centralPrUrl: written.centralPr.url }) };
}

const hasPending = (x: Ctx): boolean => x.pending.environments.length > 0 || x.pending.variables.length > 0 || Object.keys(x.pending.repoSettings).length > 0 || x.pending.classicProtection !== undefined || x.pending.actionsAccess !== undefined;
/** Why a run stopped, in plain words (a stop's own message; else what whyOf says). */
const stopWhy = (e: unknown): string => (isStop(e) || e instanceof FinishError) && e instanceof Error ? show(e.message, 300) : whyOf(e);

/** I1: drops from the pending file what `record` now holds as saved (the same entry, or the same previous value); the rest stays. */
async function prunePending(x: Ctx, record: InstallRecord): Promise<void> {
  if (!hasPending(x)) return;
  const same = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);
  const p = x.pending;
  const held = <T extends { previous?: unknown; created: boolean }>(e: T, list: readonly T[], key: (v: T) => boolean): boolean => list.some((r) => key(r) && r.created === e.created && same(r.previous, e.previous));
  const rs = record.repoSettings ?? {};
  const left: FinishPending = {
    environments: p.environments.filter((e) => !held(e, record.environments, (r) => r.name === e.name)),
    variables: p.variables.filter((v) => !held(v, record.variables, (r) => r.name === v.name && r.scope === v.scope)),
    repoSettings: Object.fromEntries(Object.entries(p.repoSettings).filter(([k, v]) => !same(rs[k as keyof typeof rs], v))),
    ...(p.classicProtection === undefined || same(record.classicProtection, p.classicProtection) ? {} : { classicProtection: p.classicProtection }),
    ...(p.actionsAccess === undefined || same(record.central?.actionsAccess, p.actionsAccess) ? {} : { actionsAccess: p.actionsAccess }),
  };
  try {
    await writeFinishPending(x.app, x.repoId, left, (x.deps.now ?? (() => new Date()))(), x.deps.local ?? {});
    x.pending = left;
  } catch (e) {
    x.notes.push(`pipegen couldn't tidy its pending file (${e instanceof RecordError ? e.message : 'an error'}); the install record holds what it kept, so the file can be removed.`);
  }
}

/**
 * The user's summary: what was applied, what was not (each by name, with why), and the notes. `recorded`: after the install record was
 * written; `unrecorded`: the run stopped before it (I1: what was applied, what the pending file keeps, a central rule left switched off);
 * `print`: nothing was applied.
 */
function report(x: Ctx, out: (s: string) => void, mode: 'recorded' | 'unrecorded' | 'print', why?: string): void {
  const repo = `${x.app.owner}/${x.app.repo}`;
  if (mode === 'recorded') out(`pipegen finish for ${repo}:`);
  if (mode === 'unrecorded') out(`pipegen finish for ${repo} stopped before it wrote the install record${why === undefined ? '' : ` (${why})`}. ${x.applied.length === 0 ? 'Nothing was applied.' : 'It had applied:'}`);
  if (mode === 'print' && why !== undefined) out(`pipegen finish --print for ${repo} stopped (${why}).`);
  if (mode !== 'print') for (const a of x.applied) out(`  done: ${a}`);
  const failedOn = x.activate?.what;
  const listed = x.skipped.filter((s) => !(x.activationFailed !== undefined && s.what === failedOn));
  if (listed.length > 0) {
    out(`These were not applied${mode === 'recorded' ? ', and the install record doesn\'t list them' : ''}:`);
    for (const s of listed) out(`  - ${s.what}: ${s.why}`);
  }
  // m4: the one item the record lists although it is not in force
  if (x.activationFailed !== undefined) out(`The install record lists the central merge rule (ruleset ${CENTRAL_RULESET}, id ${x.activationFailed.id}), but it is switched off: ${x.activationFailed.why} Run \`npx pipegen finish\` again to switch it on.`);
  if (mode === 'unrecorded') {
    if (x.activate !== undefined) out(`The central merge rule was made switched off (ruleset ${CENTRAL_RULESET}, id ${x.activate.id}); the next \`npx pipegen finish\` records it and switches it on.`);
    if (hasPending(x)) out(`What these settings were before pipegen changed them is kept in ${pendingPath(x)}; the next \`npx pipegen finish\` records it.`);
  }
  if (x.halfKey === true) out(`Signing is broken: the new ${COSIGN_KEY_SECRET} is stored but its password is not. Run \`npx pipegen finish --rotate-key\` again to store a new pair.`);
  for (const n of x.notes) out(n);
}

