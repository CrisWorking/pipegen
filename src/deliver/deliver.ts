// v0.2 Plan G Task 7, deliver (sub-task G10; rulings S11, S13, S14, S17, S26; carries CF-1, D-m6, E-b15, F-8, G1 → G10, G28; Plan V pre-flight
// §5 items 1-7, binding): the proven, judged draft goes out as ONE setup pull request in the app repo (plus the central pull request when
// the layout is central), the secrets pipegen needs before the merge are stored, and the install record is written.
//
// The order:
//   1. deliverCentral (private apps, before the final assemble): this project's central workflows on the central default branch. The
//      first run commits them there; a later run (an install record exists, the branch has rules, or the central PR branch exists) opens
//      or updates the central pull request pipegen/update-<name> and STOPS: "merge the central PR, then run pipegen again" (S26). Unchanged
//      files: the commit pinned before, while it is still on the default branch.
//   2. deliver: the needsConfirm question (its own yes), then only reads: the app and central repos (the records repo must be private),
//      the earlier record, the pin (a commit on the central default branch whose tree holds every central workflow that was judged, S26;
//      every app file calls the central workflows only at that commit), and the app's base tree (an edited file must still be exactly
//      the original it was made from; a symbolic link is never written through, G28; a file pipegen writes whole replaces only pipegen's
//      own earlier file). Nothing is written before every check passed.
//   3. key-env only (S11, N4): the environment pipegen-signing with the default-branch deployment policy, read back, and only then the
//      signing key (the key whose public half the verify workflow checks). Nothing else is applied before the merge: no ruleset, no
//      other environment, no variable (finish does those).
//   4. The repo secrets: PIPEGEN_FP_KEY (kept when it exists: old fingerprints must stay valid) and the runtime/step secrets from the
//      vault. An existing secret of the same name is replaced only after its own question (Plan V §5 item 3); GitHub's created_at is read
//      back after each PUT (a failed read-back is recorded `unconfirmed`, so uninstall asks instead of deleting).
//   5. The app branch pipegen/setup: one commit per non-empty part in PART_ORDER, through the git data API only (CF-1).
//   6. The setup pull request, opened or updated (never a second one).
//   7. writeRecord (src/deliver/record.ts): the record (a direct central commit on the first run, else the central pull request), the PR
//      body's marker line, the local record file.
//   The vault is wiped at the end, whatever happened.
//
// Never delivered (F-8, spec §19): pipegen-planted/ at any depth, the proof harness, the compat copies.
import type { Octokit } from '@octokit/rest';
import type { Prompter } from '../cli/io.js';
import { gitBlobSha } from '../create/guard.js';
import { editOf } from '../create/package-edit.js';
import { generateFpKey, storeEnvSecret, storeSecrets, type SecretVault } from '../create/secrets.js';
import { isPlantedPath } from '../debate/planted.js';
import { centralProjectName } from '../engine/central-path.js';
import { CREATED_RULES } from '../engine/created-files.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { createdPathProblem } from '../engine/job-rules.js';
import { SIGNING_ENVIRONMENT } from '../engine/referee.js';
import { pubKeySha256 } from '../engine/signing.js';
import { clockOf } from '../github/client.js';
import type { ApiRequest, LockPlan } from '../layers/locks.js';
import { COMPAT_PREFIX, HARNESS_PATH } from '../proof/harness.js';
import { CENTRAL_REPO } from '../proof/target.js';
import { isCompatCopy } from '../proof/workflow-check.js';
import type { CreatedFile, EnvSettings, InstallEdit, InstallPlanned, InstallRecord, Part, PipelineDraft, RepoProfile } from '../types.js';
import { packageVersion } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import {
  commitFiles, compareStatus, DeliverError, ghRead, ghWrite, openOrUpdatePr, readHead, readRepo, readTree, setBranch, statusOf, type RepoRef, type TreeEntry,
} from './git-data.js';
import { centralUpdateBranch, readLocalRecord, readRecord, RecordError, writeRecord, type LocalRecordDeps } from './record.js';

export { DeliverError };

export const SETUP_BRANCH = 'pipegen/setup';
/** The order of the setup pull request's commits, one per non-empty part. */
export const PART_ORDER: readonly Part[] = Object.freeze(['pipeline', 'precommit', 'docker', 'compose', 'tests', 'test-migration', 'codeowners', 'deploy-verify', 'docs']);
const PART_TITLE: Readonly<Record<Part, string>> = {
  pipeline: 'the security pipeline', precommit: 'the pre-commit hooks', docker: 'the Docker files', compose: 'the test services (docker compose)',
  tests: 'the test tools and starter tests', 'test-migration': 'the test runner change', codeowners: 'the code owners of the pipeline files',
  'deploy-verify': 'the image check before each deploy', docs: 'PIPEGEN.md, what pipegen set up',
};
const FP_KEY = 'PIPEGEN_FP_KEY';
const SIGNING_SECRETS = ['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD'] as const;
const SHA_RE = /^[0-9a-f]{40}$/;
const MAX_DIFF_LINES = 40;
const show = (s: string, n = 140): string => safeText(s, n);

// ---------- the plan ----------

export interface DeliveryInput {
  /** The final, judged draft (its centralPin is the commit deliverCentral returned; its signing plan holds the key's public hash). */
  draft: PipelineDraft;
  /** Every judged file, app and central (the referee's batch). */
  files: readonly CreatedFile[];
  /** G8's lock plan: persisted into the record's `planned`; its CODEOWNERS and required-workflow files must be among `files`. */
  locks: LockPlan;
  /** The vault names stored as repo secrets (runtime and step secrets). PIPEGEN_FP_KEY is always handled. */
  secretNames: readonly string[];
  /** The effective protected paths (codeownersProtectedPaths). */
  protectedPaths: readonly string[];
  /** The environments `finish` applies (with reviewers or not). */
  environments?: readonly { name: string; reviewers: boolean }[];
  /** ProofRepos.createdIds / RunState.scratchRepoId, as the run recorded them (Plan V §5 item 5). */
  proofRepos?: { central?: { repoId?: number; createdByPipegen: boolean }; scratch?: { repoId?: number; createdByPipegen: boolean } };
}

export interface DeliveryPlan {
  draft: PipelineDraft;
  /** This project's central files (the central layout's workflows; the required workflow and central CODEOWNERS go with the record). */
  centralFiles: CreatedFile[];
  /** The app commits, one per non-empty part, in PART_ORDER (needsConfirm files included: deliver drops them on a no). */
  appCommits: { part: Part; message: string; files: CreatedFile[] }[];
  /** The changes that run code (scripts, dependencies): their own preview section and their own yes. */
  needsConfirm: { path: string; diff: string; why: string }[];
  secretNames: string[];
  locks: LockPlan;
  environments: { name: string; reviewers: boolean }[];
  protectedPaths: string[];
  /** Files never delivered (planted, harness, compat copies), with why. */
  excluded: { path: string; why: string }[];
  /** Files an AI fix answer wrote (CreatedFile.aiEdited, E-b15). */
  aiWritten: string[];
  proofRepos?: DeliveryInput['proofRepos'];
}

/** Why a file is never delivered, or null. */
function neverDelivered(f: CreatedFile): string | null {
  if (isPlantedPath(f.path)) return 'a planted file of the proof (pipegen-planted/)';
  const lower = f.path.toLowerCase();
  if (lower === HARNESS_PATH) return 'the proof harness';
  if (lower.startsWith(COMPAT_PREFIX) || isCompatCopy(f)) return 'a compat copy of the proof';
  return null;
}

const isWorkflow = (path: string): boolean => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path);
const requiredFileOf = (locks: LockPlan): string | undefined => locks.orgRequiredWorkflow?.file.path;

/** A short line diff (lines removed and added between the common head and tail), for the preview. */
function lineDiff(before: string, after: string): string {
  const a = before === '' ? [] : before.split('\n');
  const b = after.split('\n');
  let head = 0;
  while (head < a.length && head < b.length && a[head] === b[head]) head++;
  let tail = 0;
  while (tail < a.length - head && tail < b.length - head && a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++;
  const lines = [...a.slice(head, a.length - tail).map((l) => `- ${show(l, 200)}`), ...b.slice(head, b.length - tail).map((l) => `+ ${show(l, 200)}`)];
  return lines.length <= MAX_DIFF_LINES ? lines.join('\n') : [...lines.slice(0, MAX_DIFF_LINES), `… and ${lines.length - MAX_DIFF_LINES} more changed lines`].join('\n');
}

/** Groups the judged files into what goes out, refusing a batch pipegen can't deliver as it is. Pure. */
export function planDelivery(i: DeliveryInput): DeliveryPlan {
  const excluded: { path: string; why: string }[] = [];
  const kept: CreatedFile[] = [];
  const seen = new Set<string>();
  for (const f of i.files) {
    if (typeof f?.path !== 'string' || (f.repo !== 'app' && f.repo !== 'central')) throw new DeliverError('A delivered file has no path or no repo.');
    const why = neverDelivered(f);
    if (why !== null) { excluded.push({ path: f.path, why }); continue; }
    const problem = createdPathProblem(f.path);
    if (problem !== null) throw new DeliverError(`${show(f.path)} can't be delivered: ${problem}.`);
    const key = `${f.repo}:${f.path.toLowerCase()}`;
    if (seen.has(key)) throw new DeliverError(`${show(f.path)} is in the delivery twice.`);
    seen.add(key);
    if (!PART_ORDER.includes(f.part)) throw new DeliverError(`${show(f.path)} has no part pipegen delivers.`);
    kept.push(f);
  }
  const central = i.draft.centralPin !== undefined;
  if (i.draft.profile.private === true && !central) throw new DeliverError('A private repository calls its central workflows at a pinned commit, and the draft pins none.');
  const centralFiles = kept.filter((f) => f.repo === 'central');
  if (!central && centralFiles.some((f) => isWorkflow(f.path))) throw new DeliverError('A public repository keeps its workflows in the app repo; its central repo holds install records only, so no central workflow is delivered.');
  if (central && i.draft.profile.private !== true) throw new DeliverError('Only a private repository calls central workflows.');
  const own = `${centralProjectName(i.draft.profile.repo)}--`;
  for (const f of centralFiles) if (isWorkflow(f.path) && !f.path.slice('.github/workflows/'.length).startsWith(own)) throw new DeliverError(`${show(f.path)} is not a central workflow of this project.`);
  // the lock plan's files must be in the judged batch (never dropped on the way)
  const has = (f: CreatedFile): boolean => kept.some((k) => k.repo === f.repo && k.path === f.path && k.content === f.content);
  if (i.locks.codeowners !== undefined && !has(i.locks.codeowners.file)) throw new DeliverError(`The lock plan's ${show(i.locks.codeowners.file.path)} is not among the judged files.`);
  if (i.locks.orgRequiredWorkflow !== undefined && !has(i.locks.orgRequiredWorkflow.file)) throw new DeliverError(`The lock plan's required workflow ${show(i.locks.orgRequiredWorkflow.file.path)} is not among the judged files.`);
  const app = kept.filter((f) => f.repo === 'app');
  const appCommits = PART_ORDER.flatMap((part) => {
    const files = app.filter((f) => f.part === part);
    return files.length === 0 ? [] : [{ part, message: `pipegen: add ${PART_TITLE[part]} (${part})`, files }];
  });
  const needsConfirm = kept.filter((f) => f.needsConfirm === true).map((f) => ({ path: f.path, diff: lineDiff(f.edited?.original ?? f.inserted?.original ?? '', f.content), why: f.reason }));
  const names = [...new Set(i.secretNames.map((n) => String(n).toUpperCase()))];
  for (const n of names) if (!/^[A-Z_][A-Z0-9_]{0,127}$/.test(n) || /^(?:PIPEGEN|GITHUB)_/.test(n)) throw new DeliverError(`${show(n, 80)} is not a secret name pipegen stores for you.`);
  return {
    draft: i.draft, centralFiles, appCommits, needsConfirm, secretNames: names, locks: i.locks, environments: [...(i.environments ?? [])].map((e) => ({ name: e.name, reviewers: e.reviewers === true })),
    protectedPaths: [...i.protectedPaths], excluded, aiWritten: kept.filter((f) => f.aiEdited === true).map((f) => f.path),
    ...(i.proofRepos === undefined ? {} : { proofRepos: i.proofRepos }),
  };
}

// ---------- what finish applies (the record's `planned`) ----------

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
/** Whether a planned ruleset or classic protection requires code-owner review. */
function codeOwnerRule(r: ApiRequest | undefined): boolean {
  if (r === undefined) return false;
  const rules = Array.isArray(r.body.rules) ? r.body.rules : [];
  if (rules.some((x) => isObj(x) && x.type === 'pull_request' && isObj(x.parameters) && x.parameters.require_code_owner_review === true)) return true;
  const classic = r.body.required_pull_request_reviews;
  return isObj(classic) && classic.require_code_owner_reviews === true;
}
const copy = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** The record's `planned`: the lock plan's requests, the signing mode, the environments, and the code owners only where their rule is planned (G8-R3). */
function plannedOf(d: DeliveryPlan): InstallPlanned {
  const l = d.locks;
  const app = codeOwnerRule(l.rulesets?.reviews) || codeOwnerRule(l.classic) ? [...l.owners.app] : [];
  const central = codeOwnerRule(l.centralRuleset) ? [...l.owners.central] : [];
  return copy({
    ...(l.rulesets === undefined ? {} : { rulesets: { gate: l.rulesets.gate, reviews: l.rulesets.reviews } }),
    ...(l.classic === undefined ? {} : { classic: l.classic }),
    ...(l.centralRuleset === undefined ? {} : { centralRuleset: l.centralRuleset }),
    ...(l.orgRequiredWorkflow === undefined ? {} : { orgRequiredWorkflow: { path: l.orgRequiredWorkflow.file.path, rule: l.orgRequiredWorkflow.rule } }),
    ...(l.shaPinning === undefined ? {} : { shaPinning: l.shaPinning }),
    signingMode: d.draft.signing?.mode ?? 'none', environments: d.environments, owners: { app, central }, codeOwners: app,
  }) as InstallPlanned;
}

// ---------- the preview ----------

/** Files per commit, the central changes, the AI-written files, secret NAMES only, what comes before and after the merge, and the changes that run code in their own section. */
export function previewText(d: DeliveryPlan): string {
  const p = d.draft.profile;
  const out: string[] = [];
  const confirm = new Set(d.needsConfirm.map((n) => n.path));
  out.push(`pipegen opens one pull request in ${show(`${p.owner}/${p.repo}`)} (branch ${SETUP_BRANCH}), one commit per part:`);
  d.appCommits.forEach((c, n) => {
    const files = c.files.filter((f) => !confirm.has(f.path));
    if (files.length === 0) return;
    out.push(`  ${n + 1}. ${PART_TITLE[c.part]} (${c.part})`);
    for (const f of files) out.push(`       ${show(f.path)}${f.edited !== undefined || f.inserted !== undefined ? ' (pipegen adds to your file)' : ''}`);
  });
  if (d.centralFiles.length > 0) {
    out.push('', `In the private central repo ${show(`${p.owner}/${CENTRAL_REPO}`)}:`);
    for (const f of d.centralFiles) out.push(`  ${show(f.path)}`);
  }
  out.push('', `The install record goes to ${show(`${p.owner}/${CENTRAL_REPO}`)} (private), installs/${centralProjectName(p.repo)}.json. On a later run, or once that repo has its merge rule, it goes through a central pull request, which must be merged too.`);
  if (d.aiWritten.length > 0) {
    out.push('', 'Written by the AI (pipegen\'s fix loop changed them; read them closely):');
    for (const path of d.aiWritten) out.push(`  ${show(path)}`);
  }
  out.push('', 'Secrets pipegen stores in the app repo now (names only; values never shown):', `  ${FP_KEY} (the key for secret fingerprints; kept if it already exists)`);
  for (const n of d.secretNames) out.push(`  ${n} (asked before replacing one that already exists)`);
  if (d.draft.signing?.mode === 'key-env') out.push('', `Created now, before the merge: the environment ${SIGNING_ENVIRONMENT} (default branch only), and the signing key in it (${SIGNING_SECRETS.join(', ')}). It blocks nothing: it only lets default-branch jobs sign and verify images.`);
  const planned = plannedOf(d);
  const after: string[] = [];
  if (planned.rulesets !== undefined) after.push('the merge locks on the default branch (rulesets pipegen and pipegen-reviews; classic branch protection where rulesets are not offered)');
  if (planned.centralRuleset !== undefined) after.push(`the merge rule on ${show(`${p.owner}/${CENTRAL_REPO}`)}`);
  if (planned.orgRequiredWorkflow !== undefined) after.push('the org required workflow');
  if (planned.shaPinning !== undefined) after.push('the Actions setting that requires actions pinned by commit sha');
  for (const e of planned.environments) after.push(`the environment ${show(e.name, 100)}${e.reviewers ? ' with required reviewers' : ''}`);
  after.push('the repo variable PIPEGEN_BLOCK_FROM (the end of the warn period)');
  out.push('', 'Applied after you merge, by `npx pipegen finish` (none of it before, or the pull request could not merge):', ...after.map((a) => `  - ${a}`));
  if (planned.codeOwners.length > 0) out.push(`  Code owners of the pipeline files: ${planned.codeOwners.map((o) => show(o, 40)).join(' ')}`);
  if (d.excluded.length > 0) out.push('', `${d.excluded.length} file${d.excluded.length === 1 ? '' : 's'} of the proof (planted files, the harness, compat copies) ${d.excluded.length === 1 ? 'is' : 'are'} never delivered.`);
  if (d.needsConfirm.length > 0) {
    out.push('', 'Changes that run code (scripts or dependencies). They need their own yes; without it they are left out and the rest is delivered:');
    for (const n of d.needsConfirm) out.push(`  ${show(n.path)}: ${show(n.why, 300)}`, ...n.diff.split('\n').map((l) => `      ${l}`));
  }
  return out.join('\n');
}

// ---------- the central commit (step 1) ----------

export type CentralResult = { kind: 'pinned'; sha: string; done: string[] } | { kind: 'central-pr'; url: string; message: string };

async function centralRepoOf(gh: Octokit, p: RepoProfile, clock: RateClock): Promise<{ ref: RepoRef; defaultBranch: string }> {
  const ref = { owner: p.owner, repo: CENTRAL_REPO };
  const repo = await readRepo(gh, ref, clock);
  if (repo === null) throw new DeliverError(`pipegen can't see ${show(`${p.owner}/${CENTRAL_REPO}`)}; it must exist (pipegen made or checked it before the proof).`);
  if (!repo.private) throw new DeliverError(`${show(`${p.owner}/${CENTRAL_REPO}`)} is public; pipegen keeps its central workflows and install records only in a private repo. Make it private, then run pipegen again.`);
  return { ref, defaultBranch: repo.defaultBranch };
}

/** Whether the central default branch has rules (a direct commit may be refused): unreadable counts as yes, which only means a pull request. */
async function centralHasRules(gh: Octokit, c: RepoRef, branch: string, clock: RateClock): Promise<boolean> {
  try {
    const d = await ghRead(gh, 'GET /repos/{owner}/{repo}/rules/branches/{branch}', c, { branch }, clock);
    return !Array.isArray(d) || d.length > 0;
  } catch (e) {
    if (statusOf(e) === undefined) throw e;
    return true;
  }
}

/** Whether `sha` is on the default branch and its tree holds every file exactly. */
async function holds(gh: Octokit, c: RepoRef, branch: string, sha: string, files: readonly CreatedFile[], clock: RateClock): Promise<{ onDefault: boolean; missing: string[] }> {
  const status = await compareStatus(gh, c, branch, sha, clock).catch((e: unknown) => { if (statusOf(e) === 404) return 'missing'; throw e; });
  if (status !== 'identical' && status !== 'behind') return { onDefault: false, missing: [] };
  const { entries } = await readTree(gh, c, sha, clock);
  return { onDefault: true, missing: files.filter((f) => entries.get(f.path)?.sha !== gitBlobSha(f.content) || entries.get(f.path)?.mode !== '100644').map((f) => f.path) };
}

/**
 * Step 1 (private apps): puts this project's central workflows on the central default branch and returns the commit the app must pin, or
 * opens/updates the central pull request and stops (S26). `files`: the central workflows to pin (never the required workflow, which names
 * this commit). Only this project's own central files are accepted.
 */
export async function deliverCentral(gh: Octokit, p: RepoProfile, files: readonly CreatedFile[], deps: { clock?: RateClock } = {}): Promise<CentralResult> {
  const clock = deps.clock ?? clockOf(gh);
  if (p.private !== true) throw new DeliverError('A public repository has no central workflows.');
  const own = `.github/workflows/${centralProjectName(p.repo)}--`;
  if (files.length === 0) throw new DeliverError('There is no central workflow to deliver.');
  for (const f of files) {
    if (f.repo !== 'central' || !isWorkflow(f.path) || !f.path.startsWith(own) || f.path.endsWith('--required.yml') || createdPathProblem(f.path) !== null) throw new DeliverError(`${show(f.path)} is not a central workflow of this project that the app pins.`);
  }
  const { ref: c, defaultBranch } = await centralRepoOf(gh, p, clock);
  const head = await readHead(gh, c, defaultBranch, clock);
  if (head === null) throw new DeliverError(`${show(`${p.owner}/${CENTRAL_REPO}`)} has no default branch yet.`);
  const { tree, entries } = await readTree(gh, c, head, clock);
  for (const f of files) {
    const e = entries.get(f.path);
    if (e !== undefined && e.mode !== '100644') throw new DeliverError(`${show(f.path)} in ${show(`${p.owner}/${CENTRAL_REPO}`)} is a symbolic link or not a plain file; pipegen won't write through it.`);
  }
  const changed = files.filter((f) => entries.get(f.path)?.sha !== gitBlobSha(f.content));
  // an earlier record that can't be read counts as a later run (a pull request, never a direct commit); a rate stop stops
  let unreadable = false;
  const prev = await readRecord(gh, c, p.repo, { branch: defaultBranch, clock }).catch((e: unknown) => { if (isRateStop(e) || !(e instanceof RecordError || e instanceof DeliverError)) throw e; unreadable = true; return null; });
  if (changed.length === 0) {
    // the commit pinned before, while it is still on the default branch and holds these files: the app's pin doesn't move for nothing
    const was = prev?.record.centralSha;
    if (typeof was === 'string' && SHA_RE.test(was)) {
      const h = await holds(gh, c, defaultBranch, was, files, clock);
      if (h.onDefault && h.missing.length === 0) return { kind: 'pinned', sha: was, done: [] };
    }
    return { kind: 'pinned', sha: head, done: [] };
  }
  const branch = centralUpdateBranch(p.repo);
  const later = prev !== null || unreadable || await centralHasRules(gh, c, defaultBranch, clock) || await readHead(gh, c, branch, clock) !== null;
  const { commit } = await commitFiles(gh, c, { parent: head, baseTree: tree, files: changed.map((f) => ({ path: f.path, content: f.content, mode: '100644' })), message: `pipegen: central workflows for ${p.repo}` }, clock);
  if (!later) {
    try {
      await ghWrite(gh, 'PATCH /repos/{owner}/{repo}/git/refs/{ref}', c, { ref: `heads/${defaultBranch}`, sha: commit, force: false }, clock);
      return { kind: 'pinned', sha: commit, done: [`central workflows committed to ${p.owner}/${CENTRAL_REPO} ${defaultBranch}`] };
    } catch (e) {
      const s = statusOf(e);
      if (s !== 422 && s !== 409 && s !== 403) throw e;
    }
  }
  await setBranch(gh, c, branch, commit, true, clock);
  const pr = await openOrUpdatePr(gh, c, { head: branch, base: defaultBranch, title: `pipegen: central workflows for ${p.repo}`, body: `pipegen's central workflows for ${show(`${p.owner}/${p.repo}`)}. The setup pull request in that repo pins a commit on this repo's default branch only, so merge this pull request first, then run pipegen again.` }, clock);
  return { kind: 'central-pr', url: pr.url, message: `pipegen ${pr.opened ? 'opened' : 'updated'} the central pull request ${pr.url}. Merge the central PR, then run pipegen again: the setup pull request pins only a central commit on the default branch.` };
}

// ---------- the N4 signing environment (S11) ----------

type EnvEntry = InstallRecord['environments'][number];
interface EnvRead { createdAt: string | null; settings: Omit<EnvSettings, 'branch_policies'>; policies: { id: number; name: string; type: 'branch' | 'tag' }[] }

async function readEnv(gh: Octokit, app: RepoRef, clock: RateClock): Promise<EnvRead | null> {
  let d: unknown;
  try { d = await ghRead(gh, 'GET /repos/{owner}/{repo}/environments/{environment_name}', app, { environment_name: SIGNING_ENVIRONMENT }, clock); } catch (e) {
    if (statusOf(e) === 404) return null;
    throw new DeliverError(`pipegen couldn't read the environment ${SIGNING_ENVIRONMENT} (HTTP ${statusOf(e) ?? '?'}), so it stores no signing key.`, { cause: e });
  }
  const env = isObj(d) ? d : {};
  const rules = Array.isArray(env.protection_rules) ? env.protection_rules.filter(isObj) : [];
  const wait = rules.find((r) => r.type === 'wait_timer');
  const rev = rules.find((r) => r.type === 'required_reviewers');
  const dbp = env.deployment_branch_policy;
  const reviewers = (Array.isArray(rev?.reviewers) ? rev.reviewers : []).filter(isObj).map((r) => ({ type: r.type === 'Team' ? 'Team' as const : 'User' as const, id: isObj(r.reviewer) && Number.isSafeInteger(r.reviewer.id) ? r.reviewer.id as number : 0 }));
  if (reviewers.some((r) => r.id <= 0) || (dbp !== null && !(isObj(dbp) && typeof dbp.protected_branches === 'boolean' && typeof dbp.custom_branch_policies === 'boolean'))) {
    throw new DeliverError(`GitHub's answer about the environment ${SIGNING_ENVIRONMENT} could not be read, so pipegen stores no signing key.`);
  }
  const settings = {
    wait_timer: Number.isSafeInteger(wait?.wait_timer) ? wait?.wait_timer as number : 0, prevent_self_review: rev?.prevent_self_review === true, reviewers,
    can_admins_bypass: env.can_admins_bypass !== false, deployment_branch_policy: dbp === null ? null : { protected_branches: (dbp as { protected_branches: boolean }).protected_branches, custom_branch_policies: (dbp as { custom_branch_policies: boolean }).custom_branch_policies },
  };
  let policies: EnvRead['policies'] = [];
  if (settings.deployment_branch_policy?.custom_branch_policies === true) {
    const pd = await ghRead(gh, 'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies', app, { environment_name: SIGNING_ENVIRONMENT, per_page: 100 }, clock);
    const list = isObj(pd) && Array.isArray(pd.branch_policies) ? pd.branch_policies.filter(isObj) : null;
    if (list === null || !isObj(pd) || (typeof pd.total_count === 'number' && pd.total_count > list.length)) throw new DeliverError(`pipegen couldn't read all branch rules of the environment ${SIGNING_ENVIRONMENT}, so it stores no signing key.`);
    policies = list.map((x) => ({ id: Number.isSafeInteger(x.id) ? x.id as number : 0, name: typeof x.name === 'string' ? x.name : '', type: x.type === 'tag' ? 'tag' as const : 'branch' as const }));
  }
  return { createdAt: typeof env.created_at === 'string' ? env.created_at : null, settings, policies };
}

const defaultOnly = (e: EnvRead, branch: string): boolean => e.settings.deployment_branch_policy?.protected_branches === false && e.settings.deployment_branch_policy.custom_branch_policies === true
  && e.policies.length === 1 && e.policies[0]?.name === branch && e.policies[0].type === 'branch';

/**
 * The N4 environment pipegen-signing with the default-branch deployment policy (S11, DEC #86): created when missing, or an existing one
 * narrowed to the default branch (its other settings kept; refused when it allows any other branch or tag), then READ BACK: only an
 * environment that reads back default-branch only is returned. `known`: its entry in an earlier record (kept when GitHub's created_at
 * still matches: `previous` is captured once, never pipegen's own settings).
 */
export async function ensureSigningEnvironment(gh: Octokit, app: RepoRef, defaultBranch: string, known: EnvEntry | undefined, clock: RateClock = clockOf(gh), notes: string[] = []): Promise<EnvEntry> {
  const params = { environment_name: SIGNING_ENVIRONMENT };
  const cur = await readEnv(gh, app, clock);
  const ids: number[] = [];
  const changed: (keyof EnvSettings)[] = [];
  const addPolicy = async (): Promise<void> => {
    const d = await ghWrite(gh, 'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies', app, { ...params, name: defaultBranch, type: 'branch' }, clock);
    if (isObj(d) && Number.isSafeInteger(d.id)) ids.push(d.id as number);
  };
  if (cur === null) {
    await ghWrite(gh, 'PUT /repos/{owner}/{repo}/environments/{environment_name}', app, { ...params, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } }, clock);
    await addPolicy();
  } else {
    const others = cur.policies.filter((x) => !(x.name === defaultBranch && x.type === 'branch'));
    if (others.length > 0) throw new DeliverError(`The environment ${SIGNING_ENVIRONMENT} already allows other branches or tags (${others.map((x) => show(x.name, 60)).join(', ')}); pipegen keeps its signing key only where the default branch alone can use it. Remove those rules, then run pipegen again.`);
    const dbp = cur.settings.deployment_branch_policy;
    if (!(dbp?.protected_branches === false && dbp.custom_branch_policies === true)) {
      // G10-R-sec 2: GitHub resets every setting a PUT leaves out, so all of them are sent back as read (can_admins_bypass included)
      const { wait_timer, prevent_self_review, reviewers, can_admins_bypass } = cur.settings;
      await ghWrite(gh, 'PUT /repos/{owner}/{repo}/environments/{environment_name}', app, { ...params, wait_timer, prevent_self_review, reviewers, can_admins_bypass, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } }, clock);
      changed.push('deployment_branch_policy');
    }
    if (!cur.policies.some((x) => x.name === defaultBranch && x.type === 'branch')) { await addPolicy(); changed.push('branch_policies'); }
  }
  const back = await readEnv(gh, app, clock);
  if (back === null || !defaultOnly(back, defaultBranch)) throw new DeliverError(`The environment ${SIGNING_ENVIRONMENT} doesn't read back as usable from the default branch only, so pipegen stores no signing key there.`);
  // G10-R-sec 2: every setting but the branch rule must read back as it was; a change is reported and recorded (uninstall restores `previous`)
  if (cur !== null) {
    for (const k of ['wait_timer', 'prevent_self_review', 'reviewers', 'can_admins_bypass'] as const) {
      if (JSON.stringify(back.settings[k]) !== JSON.stringify(cur.settings[k])) {
        notes.push(`GitHub changed the setting ${k} of the environment ${SIGNING_ENVIRONMENT} when pipegen narrowed it to the default branch; check it in the repository settings (uninstall puts the old value back).`);
        changed.push(k);
      }
    }
  }
  const policyIds = ids.length > 0 ? ids : cur === null ? back.policies.map((x) => x.id).filter((x) => x > 0) : [];
  const own = known !== undefined && known.githubCreatedAt !== undefined && known.githubCreatedAt === back.createdAt;
  if (own) return { ...known, changed: [...new Set([...known.changed, ...changed])], branchPolicyIds: [...new Set([...known.branchPolicyIds, ...policyIds])] };
  const at = back.createdAt !== null && /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(back.createdAt) ? { githubCreatedAt: back.createdAt } : { unconfirmed: true as const };
  if (cur === null) return { name: SIGNING_ENVIRONMENT, created: true, ...at, changed: [], branchPolicyIds: policyIds };
  return { name: SIGNING_ENVIRONMENT, created: false, ...at, previous: { ...cur.settings, branch_policies: cur.policies.map((x) => ({ name: x.name, type: x.type })) }, changed, branchPolicyIds: policyIds };
}

// ---------- secrets (steps 3-4) ----------

type SecretEntry = InstallRecord['secrets'][number];
type Scope = SecretEntry['scope'];
const ISO_RE = /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/;

/** GitHub's created_at of a secret, null when it is not there (404); anything else unreadable stops (pipegen won't store blind). */
async function secretAt(gh: Octokit, app: RepoRef, scope: Scope, name: string, clock: RateClock): Promise<string | null> {
  const route = scope === 'repo' ? 'GET /repos/{owner}/{repo}/actions/secrets/{secret_name}' : 'GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}';
  const params = scope === 'repo' ? { secret_name: name } : { environment_name: scope.slice(4), secret_name: name };
  let d: unknown;
  try { d = await ghRead(gh, route, app, params, clock); } catch (e) {
    if (statusOf(e) === 404) return null;
    throw e;
  }
  return isObj(d) && typeof d.created_at === 'string' ? d.created_at : '';
}

interface SecretCtx { gh: Octokit; app: RepoRef; io: Prompter; clock: RateClock; prev: InstallRecord | null; skipped: { what: string; why: string }[] }

/**
 * Stores one secret: an existing one only after its own question (and never PIPEGEN_FP_KEY, which is kept); GitHub's created_at read back.
 * An existing secret is pipegen's own only when the earlier record says pipegen created it AND GitHub's created_at still matches.
 */
async function storeOne(x: SecretCtx, scope: Scope, name: string, put: () => Promise<void>, opts: { keepExisting?: boolean } = {}): Promise<SecretEntry> {
  const at = await secretAt(x.gh, x.app, scope, name, x.clock);
  const was = x.prev?.secrets.find((s) => s.name === name && s.scope === scope);
  const own = at !== null && was?.created === true && was.githubCreatedAt !== undefined && was.githubCreatedAt === at;
  const readBack = async (): Promise<Pick<SecretEntry, 'githubCreatedAt' | 'unconfirmed'>> => {
    try {
      const back = await secretAt(x.gh, x.app, scope, name, x.clock);
      return back !== null && ISO_RE.test(back) ? { githubCreatedAt: back } : { unconfirmed: true };
    } catch { return { unconfirmed: true }; }
  };
  if (at === null) {
    await put();
    return { name, scope, created: true, ...await readBack() };
  }
  const kept: SecretEntry = own ? { name, scope, created: true, githubCreatedAt: at } : { name, scope, created: false };
  if (opts.keepExisting === true) return kept;
  const where = scope === 'repo' ? `The repository ${show(`${x.app.owner}/${x.app.repo}`)}` : `The environment ${show(scope.slice(4), 100)} of ${show(`${x.app.owner}/${x.app.repo}`)}`;
  const yes = await x.io.confirm(`${where} already has a secret named ${name}${own ? ' (pipegen stored it on an earlier run)' : ''}. Replace its value with the one pipegen has now? The old value can't be recovered${own ? '' : ', and uninstalling pipegen will not delete it'}.`, false);
  if (!yes) { x.skipped.push({ what: `secret ${name}`, why: 'it already exists and you kept its value' }); return kept; }
  await put();
  if (own) return { name, scope, created: true, ...await readBack() };
  return { name, scope, created: false, overwritten: true, ...await readBack() };
}

// ---------- the record (step 7) ----------

const RULE_KIND: Readonly<Record<string, 'codeowners' | 'hooks' | 'dependabot' | 'package-json' | 'package-lock'>> = {
  codeowners: 'codeowners', 'codeowners-central': 'codeowners', dependabot: 'dependabot', 'hooks-pre-commit': 'hooks', 'hooks-husky': 'hooks', 'hooks-lefthook': 'hooks',
  'package-json': 'package-json', 'package-lock': 'package-lock',
};
const sibling = (path: string, name: string): string => (path.includes('/') ? `${path.slice(0, path.lastIndexOf('/'))}/${name}` : name);
const appendSha = (shas: readonly string[], sha: string): string[] => (shas.at(-1) === sha ? [...shas] : [...shas, sha]);

/** The record form of an edit (one form per kind, Plan V §5), the first original kept from an earlier record. */
function editOfFile(f: CreatedFile, d: DeliveryPlan, delivered: readonly CreatedFile[], prev: InstallEdit | undefined): InstallEdit {
  const sha = gitBlobSha(f.content);
  if (f.inserted !== undefined) {
    if (f.repo !== 'app') throw new DeliverError(`${show(f.path)}: only an app workflow takes pipegen's inserted jobs.`);
    const originalSha = prev?.kind === 'verify-job' ? prev.originalSha : gitBlobSha(f.inserted.original);
    return { repo: 'app', path: f.path, kind: 'verify-job', jobs: [...f.inserted.jobs], needs: f.inserted.needs.map((n) => ({ job: n.job, added: [...n.added] })), originalSha, writtenShas: appendSha(prev?.writtenShas ?? [], sha) };
  }
  const original = (f.edited as { original: string }).original;
  const rule = CREATED_RULES.find((r) => r.repo === f.repo && r.mode === 'edit' && r.match(f.path, d.draft));
  const kind = rule === undefined ? undefined : RULE_KIND[rule.id];
  if (kind === undefined) throw new DeliverError(`${show(f.path)} is an edit of a file no created-file rule claims, so pipegen can't record how to undo it.`);
  const written = appendSha(prev?.writtenShas ?? [], sha);
  if (kind === 'package-json' || kind === 'package-lock') {
    if (f.repo !== 'app' || original === '') throw new DeliverError(`${show(f.path)}: pipegen edits only an existing package.json and its lockfile.`);
    const originalSha = prev?.kind === kind ? prev.originalSha : gitBlobSha(original);
    const pair = sibling(f.path, kind === 'package-json' ? 'package-lock.json' : 'package.json');
    const pairDelivered = delivered.some((x) => x.repo === 'app' && x.path === pair);
    if (kind === 'package-lock') {
      if (!pairDelivered) throw new DeliverError(`${show(f.path)} goes out only with its package.json.`);
      return { repo: 'app', path: f.path, kind, json: pair, originalSha, writtenShas: written };
    }
    let before: unknown;
    let after: unknown;
    try { before = JSON.parse(original); after = JSON.parse(f.content); } catch { throw new DeliverError(`${show(f.path)} is not JSON.`); }
    if (!isObj(before) || !isObj(after)) throw new DeliverError(`${show(f.path)} is not a JSON object.`);
    const e = editOf(before, after);
    const test = isObj(before.scripts) ? before.scripts.test : undefined;
    return { repo: 'app', path: f.path, kind, add: { ...e.add }, setTest: e.setTest, ...(e.setTest && typeof test === 'string' ? { previousTest: test } : {}), ...(pairDelivered ? { lock: pair } : {}), originalSha, writtenShas: written };
  }
  let inserted: string;
  if (f.content.startsWith(original)) inserted = f.content.slice(original.length);
  else if (kind === 'codeowners' && d.locks.codeowners?.edit?.path === f.path && f.repo === 'app') inserted = d.locks.codeowners.edit.inserted;   // a re-run swapped the old block in place
  else if (kind === 'codeowners' && d.locks.centralCodeowners?.edit?.path === f.path && f.repo === 'central') inserted = d.locks.centralCodeowners.edit.inserted;
  else throw new DeliverError(`${show(f.path)} is not the original file with pipegen's text added, so pipegen can't record how to undo it.`);
  const originalSha = prev !== undefined && prev.kind === kind ? prev.originalSha : original === '' ? null : gitBlobSha(original);
  return { repo: f.repo, path: f.path, kind, inserted, originalSha, writtenShas: written };
}

interface RecordCtx {
  d: DeliveryPlan; prev: InstallRecord | null; delivered: readonly CreatedFile[]; appRepo: { id: number; defaultBranch: string; private: boolean; ownerType: 'User' | 'Organization' };
  centralSha: string | null; secrets: SecretEntry[]; env: EnvEntry | null; now: Date; version: string;
}

function buildRecord(x: RecordCtx): InstallRecord {
  const { d, prev } = x;
  const p = d.draft.profile;
  const files = prev === null ? [] : prev.files.map((f) => ({ ...f, shas: [...f.shas] }));
  const edits: InstallEdit[] = prev === null ? [] : prev.edits.map((e) => copy(e));
  for (const f of x.delivered) {
    if (f.edited !== undefined || f.inserted !== undefined) {
      const at = edits.findIndex((e) => e.repo === f.repo && e.path === f.path);
      const e = editOfFile(f, d, x.delivered, at < 0 ? undefined : edits[at]);
      if (at < 0) edits.push(e); else edits[at] = e;
      continue;
    }
    const at = files.findIndex((r) => r.repo === f.repo && r.path === f.path);
    const sha = gitBlobSha(f.content);
    const aiEdited = f.aiEdited === true || (at >= 0 && files[at]?.aiEdited === true);
    const entry = { repo: f.repo, path: f.path, part: f.part, shas: appendSha(at < 0 ? [] : files[at]?.shas ?? [], sha), ...(aiEdited ? { aiEdited: true as const } : {}) };
    if (at < 0) files.push(entry); else files[at] = entry;
  }
  const secrets = (prev?.secrets ?? []).filter((s) => !x.secrets.some((n) => n.name === s.name && n.scope === s.scope)).concat(x.secrets);
  const environments = (prev?.environments ?? []).filter((e) => x.env === null || e.name !== x.env.name).concat(x.env === null ? [] : [x.env]);
  const pc = d.proofRepos?.central;
  const central = {
    ...(prev?.central ?? {}),
    createdByPipegen: prev?.central?.createdByPipegen === true || pc?.createdByPipegen === true,
    ...(pc?.repoId !== undefined ? { repoId: pc.repoId } : prev?.central?.repoId !== undefined ? { repoId: prev.central.repoId } : {}),
  };
  const scratch = d.proofRepos?.scratch ?? prev?.scratch;
  const cosign = d.draft.signing?.cosignPubSha256 ?? prev?.cosignPubSha256;
  return {
    schema: 2, pipegenVersion: x.version, createdAt: prev?.createdAt ?? x.now.toISOString(), ...(prev?.mergedAt === undefined ? {} : { mergedAt: prev.mergedAt }),
    centralSha: x.centralSha,
    app: { owner: p.owner, repo: p.repo, repoId: x.appRepo.id, defaultBranch: x.appRepo.defaultBranch, private: x.appRepo.private, ownerType: x.appRepo.ownerType },
    name: centralProjectName(p.repo), serviceRoots: p.services.map((s) => s.path),
    files, edits, secrets, variables: prev?.variables ?? [], environments, rulesets: prev?.rulesets ?? [],
    ...(prev?.classicProtection === undefined ? {} : { classicProtection: prev.classicProtection }),
    ...(prev?.orgRuleset === undefined ? {} : { orgRuleset: prev.orgRuleset }),
    ...(prev?.repoSettings === undefined ? {} : { repoSettings: prev.repoSettings }),
    central, ...(scratch === undefined ? {} : { scratch: { ...scratch } }),
    planned: plannedOf(d), protectedPaths: [...d.protectedPaths],
    ...(cosign === undefined ? {} : { cosignPubSha256: cosign }), ...(prev?.blockFrom === undefined ? {} : { blockFrom: prev.blockFrom }),
  };
}

// ---------- deliver ----------

export interface SigningKey { key: string; password: string; pub: string }
export interface DeliverDeps {
  /** The needsConfirm question and the same-name secret questions. */
  io: Prompter;
  clock?: RateClock;
  now?: () => Date;
  local?: LocalRecordDeps;
  /** key-env: the key pair pipegen made before the setup PR (B3 c); its public half must hash to draft.signing.cosignPubSha256. */
  signingKey?: () => Promise<SigningKey>;
  /** Default: this pipegen's version (package.json). */
  pipegenVersion?: string;
}
export interface DeliverResult {
  prUrl: string; prNumber: number; centralSha: string | null; recordHash: string; centralPrUrl?: string;
  done: string[]; skipped: { what: string; why: string }[];
  /** Plain lines for the user (a setting GitHub changed, an earlier record pipegen didn't trust). */
  notes: string[];
}

/**
 * The earlier install record pipegen builds on (G10-R-sec, G10-R-sec2). The one on the central default branch is trusted (its rules guard
 * it once `finish` ran; it is what pipegen itself committed or merged). A record found only on the central pull request branch, which anyone
 * with write on the central repo can push to, is used only when this machine's local record file exists and holds its hash. The setup PR
 * body's marker is never a trust source here (any app writer can edit it). Otherwise pipegen claims nothing from it (null) and says so.
 */
async function trustedPrevious(gh: Octokit, app: RepoRef, central: RepoRef, centralBranch: string, updateBranch: string | null, local: LocalRecordDeps, clock: RateClock, notes: string[]): Promise<InstallRecord | null> {
  const onDefault = await readRecord(gh, central, app.repo, { branch: centralBranch, clock });
  if (onDefault !== null) return onDefault.record;
  if (updateBranch === null) return null;
  const onBranch = await readRecord(gh, central, app.repo, { branch: updateBranch, clock });
  if (onBranch === null) return null;
  const file = await readLocalRecord(app, local).catch((e: unknown) => { if (e instanceof RecordError) return null; throw e; });
  if (file !== null && file.recordHash === onBranch.hash) return onBranch.record;
  notes.push(file === null
    ? `The install record on ${show(updateBranch, 100)} (the central pull request branch) can't be checked from this machine (no local record file), so pipegen claims nothing from it: it writes a new record, and treats every existing file and secret as not its own.`
    : `The install record on ${show(updateBranch, 100)} (the central pull request branch) doesn't match the hash in this machine's local record file, so pipegen claims nothing from it: it writes a new record, and treats every existing file and secret as not its own.`);
  return null;
}

/** Base-tree checks of the app files (step 2): what changes, and the mode each file keeps. Throws before anything is written. */
function checkBase(files: readonly CreatedFile[], entries: ReadonlyMap<string, TreeEntry>, prev: InstallRecord | null, repo: 'app' | 'central'): Map<CreatedFile, string> {
  const changed = new Map<CreatedFile, string>();
  const keys = [...entries.keys()].map((k) => k.toLowerCase());
  for (const f of files) {
    const e = entries.get(f.path);
    const lower = f.path.toLowerCase();
    if (e === undefined && keys.some((k) => k === lower || lower.startsWith(`${k}/`) || k.startsWith(`${lower}/`))) throw new DeliverError(`${show(f.path)} clashes with a file of another letter case, a file where its folder would be, or a folder of that name.`);
    if (e !== undefined && (e.mode === '120000' || e.type !== 'blob')) throw new DeliverError(`${show(f.path)} is a symbolic link or not a plain file in your repository; pipegen won't write through it.`);
    const original = f.inserted?.original ?? f.edited?.original;
    if (original !== undefined) {
      if (original === '' ? e !== undefined : e?.sha !== gitBlobSha(original)) throw new DeliverError(`${show(f.path)} changed since pipegen read it (it is not the file pipegen's edit was made from); run pipegen again.`);
    } else if (e !== undefined) {
      const mine = prev?.files.find((r) => r.repo === repo && r.path === f.path)?.shas.includes(e.sha) === true;
      if (!mine) throw new DeliverError(`${show(f.path)} already exists in ${repo === 'app' ? 'your repository' : 'the central repo'} and pipegen didn't write it; pipegen never overwrites your files.`);
    }
    if (e?.sha !== gitBlobSha(f.content)) changed.set(f, e?.mode === '100755' ? '100755' : '100644');
  }
  return changed;
}

/** The central pin (S26): a commit on the central default branch whose tree holds every central workflow that was judged; every app call uses it. */
async function checkPin(gh: Octokit, d: DeliveryPlan, c: RepoRef, defaultBranch: string, pinned: readonly CreatedFile[], app: readonly CreatedFile[], clock: RateClock): Promise<string> {
  const pin = d.draft.centralPin;
  if (pin === undefined || !SHA_RE.test(pin.sha) || pin.repo.toLowerCase() !== `${c.owner}/${c.repo}`.toLowerCase()) throw new DeliverError(`The draft doesn't pin a commit of ${show(`${c.owner}/${c.repo}`)}.`);
  const callRe = /([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/\.github\/workflows\/[^@\s'"]+@([^\s'"]+)/g;
  for (const f of app) {
    for (const m of f.content.matchAll(callRe)) {
      if ((m[1] as string).toLowerCase() === pin.repo.toLowerCase() && m[2] !== pin.sha) throw new DeliverError(`${show(f.path)} calls the central workflows at another central commit than the pinned one.`);
    }
  }
  const h = await holds(gh, c, defaultBranch, pin.sha, pinned, clock);
  if (!h.onDefault) throw new DeliverError(`The central commit the app pins (${pin.sha.slice(0, 12)}) is not on the default branch of ${show(`${c.owner}/${c.repo}`)}. Merge the central pull request, then run pipegen again.`);
  if (h.missing.length > 0) throw new DeliverError(`The pinned central commit doesn't hold the central workflows that were checked (${h.missing.map((x) => show(x)).join(', ')}); run pipegen again.`);
  return pin.sha;
}

/** The setup pull request's body (the record's marker line is added by writeRecord). */
function prBody(d: DeliveryPlan, commits: readonly { part: Part; files: CreatedFile[] }[], left: number): string {
  const lines = ['pipegen sets up the security checks of this repository. One commit per part:', ''];
  for (const c of commits) lines.push(`- ${PART_TITLE[c.part]} (${c.part}): ${c.files.length} file${c.files.length === 1 ? '' : 's'}`);
  if (d.aiWritten.length > 0) lines.push('', `Written by the AI (read them closely): ${d.aiWritten.map((x) => `\`${show(x)}\``).join(', ')}`);
  if (left > 0) lines.push('', `${left} change${left === 1 ? '' : 's'} that run code (scripts or dependencies) ${left === 1 ? 'was' : 'were'} left out, as you chose.`);
  lines.push('', 'After you merge it, run `npx pipegen finish`: it turns on the merge locks and the settings pipegen planned (none of them comes before the merge, or this pull request could not merge).');
  return lines.join('\n');
}

/**
 * Steps 2-7 (see the header). `p` is the app (the draft's profile). Throws DeliverError (a plain reason) and writes nothing when a check
 * fails before the first write. The vault is wiped at the end, whatever happened.
 */
export async function deliver(gh: Octokit, p: RepoProfile, d: DeliveryPlan, vault: SecretVault, deps: DeliverDeps): Promise<DeliverResult> {
  try {
    const clock = deps.clock ?? clockOf(gh);
    const now = deps.now?.() ?? new Date();
    const version = deps.pipegenVersion ?? packageVersion();
    if (version === null) throw new DeliverError('pipegen could not read its own version, which the install record needs.');
    const dp = d.draft.profile;
    if (dp.owner.toLowerCase() !== p.owner.toLowerCase() || dp.repo.toLowerCase() !== p.repo.toLowerCase()) throw new DeliverError('The delivery plan is for another repository.');
    const app: RepoRef = { owner: p.owner, repo: p.repo };
    const done: string[] = [];
    const skipped: { what: string; why: string }[] = [];
    const notes: string[] = [];

    // the changes that run code: their own yes, asked before anything else
    let all = [...d.appCommits.flatMap((c) => c.files), ...d.centralFiles];
    let left = 0;
    if (d.needsConfirm.length > 0) {
      const paths = d.needsConfirm.map((n) => show(n.path)).join(', ');
      const yes = await deps.io.confirm(`Deliver the ${d.needsConfirm.length} changes that run code (${paths}), listed under "Changes that run code" above? Without them, the rest is delivered.`, false);
      if (!yes) {
        const out = new Set(d.needsConfirm.map((n) => n.path));
        all = all.filter((f) => !(f.repo === 'app' && out.has(f.path) && f.needsConfirm === true));
        for (const n of d.needsConfirm) skipped.push({ what: n.path, why: 'a change that runs code, and you said no' });
        left = d.needsConfirm.length;
      }
    }
    const appFiles = all.filter((f) => f.repo === 'app');

    // reads and checks: nothing is written before all of them passed
    const appRepo = await readRepo(gh, app, clock);
    if (appRepo === null) throw new DeliverError(`pipegen can't see ${show(`${p.owner}/${p.repo}`)}.`);
    if (appRepo.private !== p.private) throw new DeliverError(`${show(`${p.owner}/${p.repo}`)} is ${appRepo.private ? 'private' : 'public'} now, but the plan was made for a ${p.private ? 'private' : 'public'} repo; run pipegen again.`);
    if (appRepo.defaultBranch !== p.defaultBranch) throw new DeliverError(`The default branch of ${show(`${p.owner}/${p.repo}`)} is ${show(appRepo.defaultBranch, 100)} now, not ${show(p.defaultBranch, 100)}; run pipegen again.`);
    const { ref: central, defaultBranch: centralBranch } = await centralRepoOf(gh, p, clock);
    const updateBranch = centralUpdateBranch(p.repo);
    const updateExists = await readHead(gh, central, updateBranch, clock) !== null;
    const prev = await trustedPrevious(gh, app, central, centralBranch, updateExists ? updateBranch : null, deps.local ?? {}, clock, notes);
    if (prev !== null && (prev.app.repoId !== appRepo.id || prev.app.owner.toLowerCase() !== p.owner.toLowerCase() || prev.app.repo.toLowerCase() !== p.repo.toLowerCase())) {
      throw new DeliverError(`The install record at ${show(`installs/${centralProjectName(p.repo)}.json`)} is not this repository's (another repo id or name), so pipegen won't build on it. Move it away, then run pipegen again.`);
    }
    const required = requiredFileOf(d.locks);
    const pinned = d.centralFiles.filter((f) => isWorkflow(f.path) && f.path !== required);
    const follow = all.filter((f) => f.repo === 'central' && !pinned.includes(f));
    if (!p.private && d.draft.centralPin !== undefined) throw new DeliverError('A public repository pins no central commit.');
    const centralSha = p.private ? await checkPin(gh, d, central, centralBranch, pinned, appFiles, clock) : null;
    // the central files that go with the record (the required workflow, the central CODEOWNERS): checked against the central default branch too
    const centralHead = await readHead(gh, central, centralBranch, clock);
    if (centralHead === null) throw new DeliverError(`${show(`${p.owner}/${CENTRAL_REPO}`)} has no default branch to write the install record on.`);
    const followChanged = checkBase(follow, (await readTree(gh, central, centralHead, clock)).entries, prev, 'central');
    const base = await readHead(gh, app, appRepo.defaultBranch, clock);
    if (base === null) throw new DeliverError(`${show(`${p.owner}/${p.repo}`)} has no default branch to open the setup pull request on.`);
    const baseTree = await readTree(gh, app, base, clock);
    const changed = checkBase(appFiles, baseTree.entries, prev, 'app');
    const commits = d.appCommits.map((c) => ({ part: c.part, message: c.message, files: c.files.filter((f) => changed.has(f)) })).filter((c) => c.files.length > 0);
    if (commits.length === 0) throw new DeliverError('Every file pipegen would deliver is already on the default branch, so there is no setup pull request to open. Run `npx pipegen finish` if you haven\'t.');

    // key-env (S11, N4): the environment, read back, then the key that the verify workflow checks
    const secrets: SecretEntry[] = [];
    const sctx: SecretCtx = { gh, app, io: deps.io, clock, prev, skipped };
    let env: EnvEntry | null = null;
    if (d.draft.signing?.mode === 'key-env') {
      const want = d.draft.signing.cosignPubSha256;
      if (deps.signingKey === undefined || typeof want !== 'string') throw new DeliverError('key-env signing needs the key pair pipegen made before the setup pull request, and its public key hash.');
      const key = await deps.signingKey();
      if (pubKeySha256(key.pub) !== want) throw new DeliverError('The signing key is not the one whose public key the verify workflow checks, so pipegen stores no key.');
      env = await ensureSigningEnvironment(gh, app, appRepo.defaultBranch, prev?.environments.find((e) => e.name === SIGNING_ENVIRONMENT), clock, notes);
      done.push(`environment ${SIGNING_ENVIRONMENT} (default branch only)`);
      const scope = `env:${SIGNING_ENVIRONMENT}` as const;
      const values: Record<(typeof SIGNING_SECRETS)[number], string> = { PIPEGEN_COSIGN_KEY: key.key, PIPEGEN_COSIGN_PASSWORD: key.password };
      for (const name of SIGNING_SECRETS) secrets.push(await storeOne(sctx, scope, name, () => storeEnvSecret(gh, app, SIGNING_ENVIRONMENT, name, values[name], clock)));
    }

    // the repo secrets: the fingerprint key (kept when it exists), then the vault's names
    secrets.push(await storeOne(sctx, 'repo', FP_KEY, async () => {
      if (!vault.has(FP_KEY)) generateFpKey(vault);
      await storeSecrets(gh, app, vault, [FP_KEY], clock);
    }, { keepExisting: true }));
    for (const name of d.secretNames) {
      if (!vault.has(name)) { skipped.push({ what: `secret ${name}`, why: 'no value was given; set it yourself in the repository settings' }); continue; }
      secrets.push(await storeOne(sctx, 'repo', name, async () => { await storeSecrets(gh, app, vault, [name], clock); }));
    }
    done.push(`secrets: ${secrets.map((s) => s.name).join(', ')}`);

    // the app branch: one commit per non-empty part, in order (git data API only)
    let parent = base;
    let tree = baseTree.tree;
    for (const c of commits) {
      const r = await commitFiles(gh, app, { parent, baseTree: tree, files: c.files.map((f) => ({ path: f.path, content: f.content, mode: changed.get(f) as string })), message: c.message }, clock);
      parent = r.commit;
      tree = r.tree;
    }
    await setBranch(gh, app, SETUP_BRANCH, parent, true, clock);
    const pr = await openOrUpdatePr(gh, app, { head: SETUP_BRANCH, base: appRepo.defaultBranch, title: 'pipegen: set up the security pipeline', body: prBody(d, commits, left) }, clock);
    done.push(`${pr.opened ? 'opened' : 'updated'} the setup pull request ${pr.url}`);

    // the record, to all three places
    const delivered = [...commits.flatMap((c) => c.files), ...appFiles.filter((f) => !changed.has(f)), ...pinned, ...follow];
    const record = buildRecord({ d, prev, delivered, appRepo, centralSha, secrets, env, now, version });
    const via = prev !== null || updateExists || await centralHasRules(gh, central, centralBranch, clock) ? 'pr' : 'direct';
    const w = await writeRecord(gh, { record, setupPr: pr.number, via, files: follow.filter((f) => followChanged.has(f)).map((f) => ({ path: f.path, content: f.content })), clock, now: () => now, ...(deps.local === undefined ? {} : { local: deps.local }) });
    done.push(w.via === 'direct' ? `install record committed to ${p.owner}/${CENTRAL_REPO}` : `install record in the central pull request ${w.centralPr?.url ?? ''}`);
    return { prUrl: pr.url, prNumber: pr.number, centralSha, recordHash: w.recordHash, ...(w.centralPr === undefined ? {} : { centralPrUrl: w.centralPr.url }), done, skipped, notes };
  } finally {
    vault.wipe();
  }
}
