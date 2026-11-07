// v0.2 Plan V V6 (rulings V-B4, V-B5, V-N9, V-N13; V3-hook1, V4-R1 / V4-R1b M-r1-5, V2-R1 carry): the central part of run 2 (phase B).
// Everything here reads through the phase-bound api (PhaseApi) and sends through it, so target.ts stays the only writer.
//
// - centralNow: `<owner>/pipelines` as GitHub shows it right now: its default branch, head, files, and this project's central uninstall PR
//   (exact branch `pipegen/uninstall-<name>`, from the recorded central repo itself).
// - lastProjectNow: re-computed now from the records AND the files AND the open pull requests: no other `installs/*.json`, no other
//   project's `<name>--{merge,push,nightly,sign,required}.yml` on the default branch, no open central PR but this project's own (exact
//   branch and head repo id). target.ts checks the records and files again right before each shared write (V3-hook1).
// - orgRuleNow (M-r1-5): the org required-workflow rule `pipegen-required--<name>` (the recorded id, or any rule GitHub shows requiring this
//   project's `<name>--required.yml`) still there → that file stays in central and the central repo is not deleted.
// - runCentral: when last (and the plan holds the central locks), the central ruleset deleted by its recorded id (name `pipegen`, created_at
//   equal; no date → its name typed now) and the Actions access put back (V-N9), BEFORE the central PR, so it can merge. Then one central PR
//   on `pipegen/uninstall-<name>`: this project's exact files (the plan's list, V-B4: never a glob), each only at a version pipegen wrote;
//   when last, the central CODEOWNERS (removed when pipegen created it, else only pipegen's block taken out through V2); the install record
//   LAST, only with nothing left over or the user's yes to the listed ones. A public app (records only, V-N13): only the record.
// V6-R1: central answering 404 is "can't tell" (never merged, never the last project); the central uninstall branch moves only while it is
// where pipegen set it (sec M1); after the merge, a project that joined once the locks came off is named (sec M5); an org rule pipegen
// can't read is still there (sec M3).
import type { Octokit } from '@octokit/rest';
import type { Prompter } from '../cli/io.js';
import { readBlobText, statusOf, type RepoRef, type TreeEntry } from '../deliver/git-data.js';
import { centralUpdateBranch, recordPath } from '../deliver/record.js';
import { centralFilesOf } from '../deliver/update.js';
import { centralProjectName, centralWorkflowFile } from '../engine/central-path.js';
import { isRateStop } from '../engine/github-rate.js';
import { GitHubAccessError } from '../github/client.js';
import { requiredRulesetName } from '../layers/locks.js';
import { CENTRAL_REPO } from '../proof/target.js';
import type { InstallEdit, InstallRecord } from '../types.js';
import { safeText } from '../util/safe-text.js';
import type { PhaseApi, PhasePlan } from './apply.js';
import { revertEdits } from './revert.js';
import { UninstallRefusal, uninstallBranch, type DeleteOutcome, type TypedName } from './target.js';

const show = (s: unknown, n = 200): string => safeText(String(s), n);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const posId = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const SHA_RE = /^[0-9a-f]{40}$/;
/** The central workflow of some project, by the layers pipegen writes: `<project>--<layer>.yml` (the brief's lastProject rule). */
const CENTRAL_LAYER_RE = /^\.github\/workflows\/.+--(?:merge|push|nightly|sign|required)\.ya?ml$/;
const RECORD_RE = /^installs\/[^/]+\.json$/;
const MAX_PR_PAGES = 10;
const MAX_BLOB = 1024 * 1024;
const NOT_TYPED = 'kept: its name was not typed';

/** Where run 2 puts what happened (phase-b.ts's result). */
export interface Report {
  done(what: string): void;
  skip(what: string, why: string): void;
  manual(what: string, why: string, step?: string): void;
  fail(what: string, why: string, manual?: string): void;
  /** What is left over so far (failed and manual steps): the record's question lists them. */
  leftovers(): string[];
}

export interface CentralNow {
  ref: RepoRef; defaultBranch: string; head: string; tree: string; entries: Map<string, TreeEntry>;
  /** This project's central uninstall PR (the newest on its exact branch from the recorded central repo), as GitHub shows it now. */
  pr: { number: number; url: string; merged: boolean; open: boolean; headSha: string | null } | null;
}

/** The head of `branch` of `ref` now, or null (no such branch). */
async function branchHead(api: PhaseApi, ref: RepoRef, branch: string): Promise<string | null> {
  try {
    const d = (await api.read('GET /repos/{owner}/{repo}/git/ref/{ref}', { ...ref, ref: `heads/${branch}` })).data;
    const sha = isObj(d) && isObj(d.object) ? d.object.sha : undefined;
    if (typeof sha !== 'string' || !SHA_RE.test(sha)) throw new UninstallRefusal(`GitHub's answer about the branch ${show(branch, 120)} of ${ref.owner}/${ref.repo} could not be read.`);
    return sha;
  } catch (e) {
    if (statusOf(e) === 404) return null;
    throw e;
  }
}

/** `<owner>/pipelines` now (null: GitHub answers 404 for it). Errors other than 404 pass through. */
export async function centralNow(api: PhaseApi, app: RepoRef, centralRepoId: number): Promise<CentralNow | null> {
  const ref: RepoRef = { owner: app.owner, repo: CENTRAL_REPO };
  let repo: unknown;
  try { repo = (await api.read('GET /repos/{owner}/{repo}', { ...ref })).data; } catch (e) {
    if (statusOf(e) === 404) return null;
    throw e;
  }
  const def = isObj(repo) ? repo.default_branch : undefined;
  if (typeof def !== 'string' || def === '') throw new UninstallRefusal(`GitHub doesn't say which is the default branch of ${app.owner}/${CENTRAL_REPO}.`);
  const r = (await api.read('GET /repos/{owner}/{repo}/git/ref/{ref}', { ...ref, ref: `heads/${def}` })).data;
  const head = isObj(r) && isObj(r.object) ? r.object.sha : undefined;
  if (typeof head !== 'string' || !SHA_RE.test(head)) throw new UninstallRefusal(`GitHub's answer about the default branch of ${app.owner}/${CENTRAL_REPO} could not be read.`);
  const c = (await api.read('GET /repos/{owner}/{repo}/git/commits/{commit_sha}', { ...ref, commit_sha: head })).data;
  const tree = isObj(c) && isObj(c.tree) ? c.tree.sha : undefined;
  if (typeof tree !== 'string' || !SHA_RE.test(tree)) throw new UninstallRefusal(`GitHub's answer about the head of ${app.owner}/${CENTRAL_REPO} could not be read.`);
  const t = (await api.read('GET /repos/{owner}/{repo}/git/trees/{tree_sha}', { ...ref, tree_sha: tree, recursive: '1' })).data;
  if (!isObj(t) || t.truncated !== false || !Array.isArray(t.tree)) throw new UninstallRefusal(`GitHub's list of the files of ${app.owner}/${CENTRAL_REPO} could not be read whole.`);
  const entries = new Map<string, TreeEntry>();
  for (const e of t.tree) {
    if (!isObj(e) || typeof e.path !== 'string' || typeof e.sha !== 'string' || typeof e.mode !== 'string' || typeof e.type !== 'string') throw new UninstallRefusal(`GitHub's list of the files of ${app.owner}/${CENTRAL_REPO} could not be read.`);
    if (e.type !== 'tree') entries.set(e.path, { sha: e.sha, mode: e.mode, type: e.type });
  }
  const branch = uninstallBranch({ owner: app.owner, repo: app.repo, repoId: 1 }, 'central');
  const prs = (await api.read('GET /repos/{owner}/{repo}/pulls', { ...ref, head: `${app.owner}:${branch}`, state: 'all', per_page: 100 })).data;
  let pr: CentralNow['pr'] = null;
  for (const p of Array.isArray(prs) ? prs : []) {
    if (!isObj(p) || !posId(p.number) || !isObj(p.head) || p.head.ref !== branch || !isObj(p.head.repo) || p.head.repo.id !== centralRepoId) continue;
    if (pr !== null && pr.number > p.number) continue;
    const merged = typeof p.merged_at === 'string' && p.merged_at !== '' && isObj(p.base) && p.base.ref === def;
    pr = { number: p.number, url: typeof p.html_url === 'string' ? p.html_url : '', merged, open: p.state === 'open', headSha: typeof p.head.sha === 'string' && SHA_RE.test(p.head.sha) ? p.head.sha : null };
  }
  return { ref, defaultBranch: def, head, tree, entries, pr };
}

/**
 * Whether this is the last project of central right now: no other install record, no other project's central workflow (the layers), no
 * open central PR but this project's own (exact branch, from the recorded central repo). `why` names what keeps it otherwise.
 */
export async function lastProjectNow(api: PhaseApi, app: RepoRef, now: CentralNow, centralRepoId: number): Promise<{ last: boolean; why: string }> {
  const own = centralFilesOf(app.repo);
  const rp = recordPath(app.repo);
  const full = `${app.owner}/${CENTRAL_REPO}`;
  const records = [...now.entries.keys()].filter((p) => RECORD_RE.test(p) && p !== rp);
  if (records.length > 0) return { last: false, why: `other projects use ${full} (their install records: ${show(records.slice(0, 5).join(', '), 300)})` };
  const files = [...now.entries.keys()].filter((p) => CENTRAL_LAYER_RE.test(p) && !own.includes(p));
  if (files.length > 0) return { last: false, why: `other projects use ${full} (their central workflows: ${show(files.slice(0, 5).join(', '), 300)})` };
  const mine = new Set([centralUpdateBranch(app.repo), `pipegen/uninstall-${centralProjectName(app.repo)}`]);
  for (let page = 1; page <= MAX_PR_PAGES; page += 1) {
    let d: unknown;
    try { d = (await api.read('GET /repos/{owner}/{repo}/pulls', { ...now.ref, state: 'open', per_page: 100, page })).data; } catch (e) {
      if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
      return { last: false, why: `pipegen couldn't list the open pull requests of ${full}, so it can't tell no other project is on its way there` };
    }
    if (!Array.isArray(d)) return { last: false, why: `GitHub's list of the open pull requests of ${full} could not be read` };
    const others = d.filter((p) => !(isObj(p) && isObj(p.head) && typeof p.head.ref === 'string' && mine.has(p.head.ref) && isObj(p.head.repo) && p.head.repo.id === centralRepoId));
    if (others.length > 0) return { last: false, why: `other projects may be on their way to ${full} (open pull requests: ${show(others.slice(0, 5).map((p) => `#${isObj(p) ? String(p.number) : '?'}`).join(', '), 200)})` };
    if (d.length < 100) return { last: true, why: '' };
  }
  return { last: false, why: `${full} has more open pull requests than pipegen reads, so it can't tell no other project is on its way there` };
}

/**
 * M-r1-5: the org required-workflow rule of this project, still there (why, naming it), or null (gone, or there is none). It is the
 * recorded id, or any org rule GitHub shows by its name or requiring this project's `<name>--required.yml`. V6-R1 (sec M3, spec I2): what
 * pipegen can't read (the list, 100 or more rules, one rule's detail) counts as still there. Only a user account whose fully trusted record
 * lists no org rule has none, and nothing is read then (a typed trust never vouches that there is none).
 */
export async function orgRuleNow(api: PhaseApi, rec: InstallRecord, app: RepoRef & { ownerType: 'User' | 'Organization' }, trust: 'full' | 'typed'): Promise<string | null> {
  const name = requiredRulesetName(app.repo);
  const path = centralWorkflowFile(app.repo, 'required');
  const recorded = rec.orgRuleset;
  if (app.ownerType !== 'Organization' && recorded === undefined && trust === 'full') return null;
  const present = `the org required-workflow rule ${name} of ${show(app.owner, 40)} still requires ${path}`;
  const cant = (what: string): string => `pipegen can't read ${what}, so it can't tell the org required-workflow rule ${name} (it requires ${path}) is gone`;
  let list: unknown;
  try { list = (await api.read('GET /orgs/{org}/rulesets', { org: app.owner, per_page: 100 })).data; } catch (e) {
    if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
    return cant(`the rulesets of ${show(app.owner, 40)}`);
  }
  if (!Array.isArray(list) || list.length >= 100) return cant(`every ruleset of ${show(app.owner, 40)}`);
  for (const x of list) {
    if (!isObj(x)) continue;
    if (x.name === name || (recorded !== undefined && x.id === recorded.id)) return present;
    if (!posId(x.id)) return cant(`every ruleset of ${show(app.owner, 40)}`);
    let d: unknown;
    try { d = (await api.read('GET /orgs/{org}/rulesets/{ruleset_id}', { org: app.owner, ruleset_id: x.id })).data; } catch (e) {
      if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
      return cant(`the org ruleset ${x.id}`);
    }
    const rules = isObj(d) && Array.isArray(d.rules) ? d.rules : [];
    if (rules.some((r) => isObj(r) && isObj(r.parameters) && Array.isArray(r.parameters.workflows) && r.parameters.workflows.some((w) => isObj(w) && w.path === path))) return present;
  }
  return null;
}

export interface CentralOutcome {
  /** The central PR that removed the record merged: the repo deletes and the local files may go on. Central not seen: false (can't tell). */
  merged: boolean;
  /** The central PR this run opened or updated. */
  pr?: { number: number; url: string };
  last: boolean; lastWhy: string; orgRule: string | null;
}

/** The central part of run 2 (see the header). `outcome` maps an api answer onto the report (phase-b.ts's attempt). */
export async function runCentral(o: {
  gh: Octokit; api: PhaseApi; plan: PhasePlan; rec: InstallRecord; centralRepoId: number; ownerType: 'User' | 'Organization';
  live: boolean; io: Prompter | undefined; interactive: boolean; report: Report;
  outcome: (what: string, manual: string | undefined, fn: () => Promise<DeleteOutcome>) => Promise<boolean>;
  /** V6-R1 sec M1: the head pipegen last set the central uninstall branch to (the progress file), and where to save a new one. */
  branch: { head: string | undefined; set: (sha: string) => void };
}): Promise<CentralOutcome> {
  const { api, plan, rec, report } = o;
  const app: RepoRef = { owner: plan.app.owner, repo: plan.app.repo };
  const full = `${app.owner}/${CENTRAL_REPO}`;
  const rp = recordPath(app.repo);
  const now = await centralNow(api, app, o.centralRepoId);
  if (now === null) {
    // V6-R1 (sec M4, spec M2): a 404 is "can't tell" (deleted, or no access now): never merged, never the last project, the local files stay
    report.manual(full, `pipegen can't see ${full} now (deleted, or this login has no access to it), so it can't tell what of this project is left there`, `Check ${full} on GitHub (and the token's access to it), then run \`pipegen uninstall\` again.`);
    return { merged: false, last: false, lastWhy: `pipegen can't see ${full}`, orgRule: null };
  }
  const orgRule = await orgRuleNow(api, rec, { ...app, ownerType: o.ownerType }, plan.trust);
  const lp = await lastProjectNow(api, app, now, o.centralRepoId);
  // V6-R2 sec M1: this cycle's PR only (its head the one pipegen set), and this project's files and locks must be gone from central now
  if (now.pr?.merged === true && !now.entries.has(rp) && now.pr.headSha !== null && now.pr.headSha === o.branch.head) {
    report.done(`central pull request #${now.pr.number} in ${full}: merged; this project's install record is gone from ${full}`);
    await stillThere();
    if (!lp.last) await joinedSince();
    return { merged: true, last: lp.last, lastWhy: lp.why, orgRule };
  }
  // V6-R1 sec M1 (as V5-R1 M2): the central uninstall branch is moved only while it is absent or where pipegen set it
  const branchName = uninstallBranch({ owner: app.owner, repo: app.repo, repoId: 1 }, 'central');
  const at = await branchHead(api, now.ref, branchName);
  if (at !== null && at !== o.branch.head) {
    report.fail(`central branch ${branchName} of ${full}`, `it has commits pipegen didn't make (or this uninstall didn't set it), so pipegen doesn't move it`, `Look at ${branchName} in ${full}, keep what you need, then delete it (gh api -X DELETE repos/${full}/git/refs/heads/${branchName}) and run \`pipegen uninstall\` again.`);
    return { merged: false, ...(now.pr?.open === true ? { pr: { number: now.pr.number, url: now.pr.url } } : {}), last: lp.last, lastWhy: lp.why, orgRule };
  }

  // ---------- the central locks: only the last project, and only those the plan holds (full trust); BEFORE the central PR ----------
  const locks = plan.centralLocks;
  // the names of the locks the record holds (full trust), to say why they stay; only the plan's own are ever written
  const named = locks ?? (plan.trust === 'full' ? rec.central : undefined);
  const lockNames: string[] = [];
  if (named?.rulesetId !== undefined) lockNames.push('central ruleset');
  if (named?.codeowners !== undefined) lockNames.push('central CODEOWNERS block');
  if (named?.actionsAccess !== undefined) lockNames.push('central Actions access');
  if (!lp.last || o.live) {
    const why = o.live ? 'pipegen\'s workflow is still on the app\'s default branch and runs through it, so pipegen leaves it' : `${lp.why}; it is shared by every project there, so pipegen leaves it`;
    for (const n of lockNames) report.skip(`${n} of ${full}`, why);
  } else if (locks !== undefined) {
    if (posId(locks.rulesetId)) {
      // spec M1 (V6-R1): a name not typed is a leftover: the record's question lists it
      const rulesetStep = `Delete the central ruleset ${locks.rulesetId} of ${full} by hand (Settings → Rules → Rulesets) if it is pipegen's, or run \`pipegen uninstall\` again and type its name.`;
      const target = { kind: 'central-ruleset' as const, id: locks.rulesetId, ...(locks.rulesetCreatedAt === undefined ? {} : { createdAt: locks.rulesetCreatedAt }) };
      await o.outcome(`central ruleset (id ${locks.rulesetId}) of ${full}`, `gh api -X DELETE repos/${full}/rulesets/${locks.rulesetId}`, async () => {
        const first = await api.deleteIfPipegens(target);
        if (first.status !== 'ask') return first;
        // V-N2: a central ruleset with no creation date (or a typed-names run): its name typed now, for that very ruleset
        let t: TypedName | null;
        try { t = await api.confirm(target); } catch (e) {
          if (e instanceof UninstallRefusal) return { status: 'kept', why: `${NOT_TYPED} (${show(e.message, 200)})`, manual: rulesetStep };
          throw e;
        }
        if (t === null) return { status: 'kept', why: NOT_TYPED, manual: rulesetStep };
        return api.deleteIfPipegens(target, { typed: t });
      });
    }
    const prev = locks.actionsAccess?.previous;
    if (prev !== undefined) {
      await o.outcome(`central Actions access of ${full}`, undefined, async () => {
        try {
          return await api.write('PUT /repos/{owner}/{repo}/actions/permissions/access', { owner: app.owner, repo: CENTRAL_REPO, access_level: prev }, { pipegenSet: o.ownerType === 'Organization' ? 'organization' : 'user' });
        } catch (e) {
          if (e instanceof UninstallRefusal) return { status: 'kept', why: `the recorded access level can't be put back (${show(e.message, 200)})`, manual: `Check Settings → Actions → Access of ${full}.` };
          throw e;
        }
      });
    }
  }

  // ---------- the central PR on the head now ----------
  let parent = now.head;
  let baseTree = now.tree;
  let changed = 0;
  const body: string[] = [];
  const commit = async (c: { files: { path: string; content: string; mode: string }[]; deletes: string[]; message: string }): Promise<boolean> => {
    try {
      const made = await api.commitUninstall('central', { parent, baseTree, ...c, recordEdits: rec.edits });
      parent = made.commit;
      baseTree = made.tree;
      changed += 1;
      return true;
    } catch (e) {
      if (!(e instanceof UninstallRefusal)) throw e;
      report.manual(`central commit (${show(c.message, 120)})`, `pipegen didn't make it: ${show(e.message, 300)}`, `Check ${full} and make that change by hand if it is still needed.`);
      return false;
    }
  };
  // this project's exact files (V-B4): the plan's list, each again one of this project's central files, at a version pipegen wrote
  const own = centralFilesOf(app.repo);
  const required = centralWorkflowFile(app.repo, 'required');
  const deletes: string[] = [];
  for (const p of plan.centralFiles) {
    if (p === rp) continue;
    if (!own.includes(p)) { report.manual(`central ${show(p)}`, 'it is not one of this project\'s central files (the exact list), so pipegen leaves it'); continue; }
    const e = now.entries.get(p);
    if (e === undefined) { report.done(`central ${show(p)}: already gone`); continue; }
    const f = rec.files.find((x) => x.repo === 'central' && x.path === p);
    if (f === undefined || f.adopted === true || f.ownerEdited === true || e.type !== 'blob' || !f.shas.includes(e.sha)) {
      report.manual(`central ${show(p)}`, 'it changed since pipegen wrote it (or pipegen found it there), so pipegen leaves it', `Review ${p} in ${full} and remove it by hand if it is this project's.`);
      continue;
    }
    if (p === required && orgRule !== null) {
      report.manual(`central ${show(p)}`, `${orgRule} (from the org rulesets), and removing the file would block every pull request of the app; pipegen keeps it`, `Delete the org rule ${requiredRulesetName(app.repo)} in the organisation's settings (Rulesets), then delete ${p} from ${full} by hand.`);
      continue;
    }
    if (o.live && /^\.github\/workflows\//.test(p)) {
      report.skip(`central ${show(p)}`, 'pipegen\'s workflow is still on the app\'s default branch and calls it, so pipegen leaves it');
      continue;
    }
    deletes.push(p);
  }
  if (deletes.length > 0 && await commit({ files: [], deletes, message: `pipegen uninstall: remove ${show(rec.name, 100)}'s central workflows` })) {
    for (const p of deletes) body.push(`- removes ${show(p)}`);
  }
  // the central CODEOWNERS: only the last project, only the one the record names
  if (lp.last && !o.live && locks?.codeowners !== undefined) await codeowners(locks.codeowners);

  // the record, LAST: only with nothing left over, or the user's yes to the listed ones
  if (!now.entries.has(rp)) report.done(`${rp}: already gone from ${full}`);
  else if (o.live) report.manual(rp, 'pipegen\'s workflow is still on the app\'s default branch, so pipegen keeps this project\'s install record', 'Remove pipegen\'s workflow from the app, then run `pipegen uninstall` again.');
  else if (await recordMayGo()) {
    if (await commit({ files: [], deletes: [rp], message: `pipegen uninstall: remove ${show(rec.name, 100)}'s install record (last)` })) body.push(`- removes ${rp} (this project's install record, last)`);
  } else report.manual(rp, 'pipegen keeps this project\'s install record: some steps above were not done, and it is what lets `pipegen uninstall` come back to them', 'Do the steps above, then run `pipegen uninstall` again.');

  if (changed === 0) {
    if (now.pr?.merged === true) report.done(`central pull request #${now.pr.number} in ${full}: merged`);
    return { merged: !now.entries.has(rp), last: lp.last, lastWhy: lp.why, orgRule };
  }
  await api.setUninstallBranch('central', parent);
  o.branch.set(parent);
  const text = [
    `pipegen uninstall: this pull request removes ${show(`${app.owner}/${app.repo}`, 140)} from ${full}.`, '', ...body.slice(0, 300), '',
    ...(lp.last && !o.live ? [`This was the last project in ${full}, so pipegen took its central locks off. Merge it only while no other project uses ${full}; if one joined since, close this pull request and run \`pipegen uninstall\` again.`, ''] : []),
    'After you merge it, run `pipegen uninstall` again to finish (and, with --delete-repos, to delete the repos pipegen made).',
  ].join('\n');
  const pr = await api.openUninstallPr('central', { base: now.defaultBranch, title: `pipegen: uninstall ${show(rec.name, 100)}`, body: text });
  report.done(`central pull request #${pr.number} in ${full}: ${pr.opened ? 'opened' : 'updated'}`);
  return { merged: false, pr: { number: pr.number, url: pr.url }, last: lp.last, lastWhy: lp.why, orgRule };

  /**
   * V6-R2 sec M1: after the merge, what of this project is still on central's default branch (the plan's exact files) and, when last, the
   * central locks the plan holds: each is a failed leftover (the local files stay), with its step. A read that fails is one too.
   */
  async function stillThere(): Promise<void> {
    if (now === null) return;
    const own = centralFilesOf(app.repo);
    for (const p of plan.centralFiles) {
      if (p === rp || !own.includes(p) || !now.entries.has(p)) continue;
      report.fail(`central ${show(p)}`, `it is still on the default branch of ${full} after the central pull request merged`, `Remove ${p} from ${full} by hand if it is this project's${p === centralWorkflowFile(app.repo, 'required') ? ' (once the org rule that requires it is gone)' : ''}, then run \`pipegen uninstall\` again.`);
    }
    const locks = plan.centralLocks;
    if (!lp.last || locks === undefined) return;
    if (posId(locks.rulesetId)) {
      let there = true;
      try { await api.read('GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', { ...now.ref, ruleset_id: locks.rulesetId }); } catch (e) {
        if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
        there = statusOf(e) !== 404;
      }
      if (there) report.fail(`central ruleset (id ${locks.rulesetId}) of ${full}`, 'it is still there (or pipegen can\'t tell it is gone) after the central pull request merged', `Delete it by hand (gh api -X DELETE repos/${full}/rulesets/${locks.rulesetId}) if it is pipegen's, then run \`pipegen uninstall\` again.`);
    }
    if (locks.codeowners?.created === true && now.entries.has(locks.codeowners.path)) {
      report.fail(`central ${show(locks.codeowners.path)}`, 'the CODEOWNERS pipegen created is still on the default branch after the central pull request merged', `Remove it from ${full} by hand if it holds only pipegen's block, then run \`pipegen uninstall\` again.`);
    }
  }

  /**
   * V6-R1 sec M5: after the merge, another project is there, and the locks the record holds are gone (the central ruleset reads 404, or
   * the CODEOWNERS pipegen created is gone): this project took them off as the last one, and the newcomer needs them back.
   */
  async function joinedSince(): Promise<void> {
    const held = plan.trust === 'full' ? rec.central : undefined;
    if (held === undefined || now === null) return;
    let off = held.codeowners?.created === true && !now.entries.has(held.codeowners.path);
    if (!off && posId(held.rulesetId)) {
      try { await api.read('GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', { ...now.ref, ruleset_id: held.rulesetId }); } catch (e) {
        if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
        off = statusOf(e) === 404;
      }
    }
    if (off) report.manual(`central locks of ${full}`, `pipegen took them off when this was the last project, but ${lp.why} now`, `Run \`pipegen finish\` in each of those projects to lock ${full} again (its central ruleset, CODEOWNERS block and Actions access).`);
  }

  /** The central CODEOWNERS pipegen created → removed; one it edited → only pipegen's block out (V2); else a manual step. */
  async function codeowners(co: NonNullable<NonNullable<InstallRecord['central']>['codeowners']>): Promise<void> {
    const what = `central ${show(co.path)}`;
    const eds = rec.edits.filter((x): x is Extract<InstallEdit, { kind: 'codeowners' | 'hooks' | 'dependabot' }> => x.repo === 'central' && x.kind === 'codeowners');
    const edit = eds.length === 1 && eds[0]?.path === co.path ? eds[0] : undefined;
    if (edit === undefined) { report.manual(what, 'the install record doesn\'t name exactly this one central CODEOWNERS pipegen edited, so pipegen leaves it', `Take pipegen's block out of ${co.path} in ${full} by hand.`); return; }
    const e = now?.entries.get(co.path);
    if (e === undefined) { report.done(`${what}: already gone`); return; }
    if (co.created && edit.originalSha === null && edit.ownerEdited !== true) {
      if (await commit({ files: [], deletes: [co.path], message: `pipegen uninstall: remove the central CODEOWNERS pipegen created (${show(co.path, 100)})` })) body.push(`- removes ${show(co.path)} (pipegen created it)`);
      return;
    }
    const blobs = new Map<string, string | null>();
    const read = async (sha: string | null | undefined): Promise<void> => {
      if (typeof sha !== 'string' || !SHA_RE.test(sha) || blobs.has(sha)) return;
      try { blobs.set(sha, await readBlobText(o.gh, now?.ref as RepoRef, sha, MAX_BLOB, api.clock)); } catch (x) {
        if (isRateStop(x) || x instanceof GitHubAccessError || statusOf(x) === 401) throw x;
        blobs.set(sha, null);
      }
    };
    await read(e.sha);
    await read(edit.originalSha);
    for (const s of edit.writtenShas) await read(s);
    const text = blobs.get(e.sha);
    const [res] = revertEdits([edit], () => (typeof text === 'string' ? { text, sha: e.sha } : null), (sha) => blobs.get(sha) ?? null, {});
    const r = res?.result;
    if (r === undefined || r.kind === 'manual') { report.manual(what, r?.kind === 'manual' ? r.why : 'pipegen couldn\'t read it', `Take pipegen's block out of ${co.path} in ${full} by hand.`); return; }
    const ok = r.kind === 'delete'
      ? await commit({ files: [], deletes: [co.path], message: `pipegen uninstall: remove the central CODEOWNERS pipegen created (${show(co.path, 100)})` })
      : await commit({ files: [{ path: co.path, content: r.text, mode: e.mode === '100755' ? '100755' : '100644' }], deletes: [], message: `pipegen uninstall: take pipegen's block out of the central CODEOWNERS (${show(co.path, 100)})` });
    if (ok) body.push(r.kind === 'delete' ? `- removes ${show(co.path)} (pipegen made it)` : `- ${show(co.path)}: pipegen's block taken out`);
  }

  /**
   * Nothing left over (what this run failed to do or had to leave to the user; the preview's own manual steps were agreed to and need no
   * record), or the user's yes at the terminal (default no; no terminal: no) after the list.
   */
  async function recordMayGo(): Promise<boolean> {
    const left = report.leftovers();
    if (left.length === 0) return true;
    if (!o.interactive || o.io === undefined) return false;
    const shown = left.slice(0, 15).map((l) => `  - ${show(l, 200)}`).join('\n');
    try {
      return (await o.io.confirm(`Remove the install record ${rp} anyway? These are not done (or are steps for you):\n${shown}${left.length > 15 ? `\n  - and ${left.length - 15} more` : ''}\nWithout the record, pipegen can't come back to them. (y/N)`, false)) === true;
    } catch { return false; }
  }
}
