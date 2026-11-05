// v0.2 Plan G Task 7, verify (sub-task G11; rows G26, G29; Plan V pre-flight §5 G11 item 4): `pipegen verify` is read-only and reports
// drift between the repos and the install record on the central default branch. It reads the record with readRecord (the same reader and
// hash comparison uninstall uses, S2) and checks:
//   - every file pipegen wrote whole (its blob on the default branch is one of the recorded shas) and every edit (pipegen's inserted text
//     still there; the other edit kinds: the blob is one pipegen wrote), protected paths marked;
//   - the record hash against this machine's local record file and the setup pull request body's marker;
//   - PIPEGEN_BLOCK_FROM against record.blockFrom, the sha256 of PIPEGEN_COSIGN_PUB against record.cosignPubSha256;
//   - fix round 1 (I3): every lock finish planned is in force once finish ran (a refused one is drift; a same-name ruleset finish updated
//     but couldn't record is checked by name), and each one's live contents match: enforcement active, no bypass actors, pipegen's rules
//     (the required check `pipegen / gate` from the GitHub Actions app 15368; the review rules: dismiss stale reviews, approval after the
//     last push, code-owner review, the approval count), classic branch protection too when it stands in;
//   - the pinned central commit (record.centralSha) on the central default branch's history.
// It also warns (G29) about CODEOWNERS rules after pipegen's block that name only teams (the workflow's own token can't read a team's
// members, so the gate can't check those approvals), and says (G26) that a key rotation resets the baseline.
import type { Octokit } from '@octokit/rest';
import { CENTRAL_PROTECTED_PATHS, CODEOWNERS_END } from '../engine/created-builders.js';
import type { RateClock } from '../engine/github-rate.js';
import { protectedMatcher } from '../engine/protected-match.js';
import { SIGNING_ENVIRONMENT } from '../engine/referee.js';
import { pubKeySha256 } from '../engine/signing.js';
import { clockOf } from '../github/client.js';
import { CENTRAL_RULESET, CO_PLACES, GATE_RULESET, REVIEWS_RULESET } from '../layers/locks.js';
import { GATE_CHECK_INTEGRATION_ID, GATE_CHECK_NAME, PROTECTED_PATHS_BASE, type InstallRecord } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { SETUP_BRANCH } from './deliver.js';
import { compareStatus, readBlobText, readHead, readRepo, readTree, statusOf, type RepoRef, type TreeEntry } from './git-data.js';
import { centralOf, readLocalRecord, readRecord, RecordError, recordMarkerOf, recordPath, type LocalRecordDeps } from './record.js';
import { classicPutForm, holdsWanted, isObj, SettingsApi } from './settings-api.js';

export interface VerifyDrift { what: string; expected: string; actual: string | null }
export interface VerifyResult { drift: VerifyDrift[]; warnings: string[]; notes: string[] }
export interface VerifyDeps { clock?: RateClock; local?: LocalRecordDeps }

const show = (s: string, n = 140): string => safeText(s, n);
const MAX_TEXT = 512 * 1024;
/** Which recorded paths are protected: the record's own list for the app (the built-in one if it holds none), the central list for central. */
const protectedListOf = (r: InstallRecord, repo: 'app' | 'central'): readonly string[] => (repo === 'app' ? (r.protectedPaths.length > 0 ? r.protectedPaths : PROTECTED_PATHS_BASE) : CENTRAL_PROTECTED_PATHS);

/** `pipegen verify` for the app (read-only; see the header). */
export async function verify(gh: Octokit, app: RepoRef, deps: VerifyDeps = {}): Promise<VerifyResult> {
  const clock = deps.clock ?? clockOf(gh);
  const api = new SettingsApi(gh, app, clock);
  const central = centralOf(app);
  const drift: VerifyDrift[] = [];
  const warnings: string[] = [];
  const notes: string[] = [];
  const out = (): VerifyResult => ({ drift, warnings, notes });

  let found: Awaited<ReturnType<typeof readRecord>>;
  try { found = await readRecord(gh, central, app.repo, { clock }); } catch (e) {
    if (!(e instanceof RecordError)) throw e;
    drift.push({ what: 'install record', expected: `${recordPath(app.repo)} as pipegen writes it`, actual: show(e.message, 200) });
    return out();
  }
  if (found === null) {
    drift.push({ what: 'install record', expected: `${recordPath(app.repo)} on the default branch of ${central.owner}/${central.repo}`, actual: null });
    return out();
  }
  const r = found.record;
  const hash = found.hash;

  // the record hash: this machine's local record file, and the setup pull request body
  const local = await readLocalRecord(app, deps.local ?? {}).catch((e: unknown) => { if (e instanceof RecordError) return null; throw e; });
  if (local?.recordHash !== hash) drift.push({ what: 'install record hash (local record file)', expected: hash, actual: local?.recordHash ?? null });
  const prNumber = local?.setupPr ?? await findSetupPr(api, app);
  const body = prNumber === undefined ? null : await api.readOr404('GET /repos/{owner}/{repo}/pulls/{pull_number}', { owner: app.owner, repo: app.repo, pull_number: prNumber });
  const marker = isObj(body) ? recordMarkerOf(typeof body.body === 'string' ? body.body : '') : null;
  if (marker !== hash) drift.push({ what: 'install record hash (setup pull request body)', expected: hash, actual: marker });

  // the files and edits, on each default branch
  const trees: Record<'app' | 'central', Map<string, TreeEntry> | null> = { app: await treeOf(gh, app, clock), central: await treeOf(gh, central, clock) };
  const prot = { app: protectedMatcher(protectedListOf(r, 'app')), central: protectedMatcher(protectedListOf(r, 'central')) };
  const label = (repo: 'app' | 'central', path: string): string => `${repo} file ${show(path)}${prot[repo](path) ? ' (protected)' : ''}`;
  for (const f of r.files) {
    const e = trees[f.repo]?.get(f.path);
    if (e?.sha === undefined || !f.shas.includes(e.sha)) drift.push({ what: label(f.repo, f.path), expected: f.shas.at(-1) as string, actual: e?.sha ?? null });
  }
  for (const ed of r.edits) {
    const e = trees[ed.repo]?.get(ed.path);
    if (e !== undefined && ed.writtenShas.includes(e.sha)) continue;
    if (ed.kind === 'codeowners' || ed.kind === 'hooks' || ed.kind === 'dependabot') {
      const text = e === undefined || e.type !== 'blob' ? '' : await readBlobText(gh, ed.repo === 'app' ? app : central, e.sha, MAX_TEXT, clock);
      if (text.split(ed.inserted).length !== 2) drift.push({ what: `pipegen's lines in ${label(ed.repo, ed.path)}`, expected: 'pipegen\'s inserted text, once', actual: e === undefined ? null : 'changed or missing' });
    } else {
      drift.push({ what: label(ed.repo, ed.path), expected: ed.writtenShas.at(-1) ?? 'the file pipegen wrote', actual: e?.sha ?? null });
    }
  }

  // the variables
  if (r.blockFrom !== undefined) {
    const v = await api.readOr404('GET /repos/{owner}/{repo}/actions/variables/{name}', { owner: app.owner, repo: app.repo, name: 'PIPEGEN_BLOCK_FROM' });
    const actual = isObj(v) && typeof v.value === 'string' ? v.value : null;
    if (actual !== r.blockFrom) drift.push({ what: 'PIPEGEN_BLOCK_FROM', expected: r.blockFrom, actual: actual === null ? null : show(actual, 40) });
  }
  if (r.cosignPubSha256 !== undefined) {
    const v = await api.readOr404('GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}', { owner: app.owner, repo: app.repo, environment_name: SIGNING_ENVIRONMENT, name: 'PIPEGEN_COSIGN_PUB' });
    const actual = isObj(v) && typeof v.value === 'string' ? pubKeySha256(v.value) : null;
    if (actual !== r.cosignPubSha256) drift.push({ what: 'PIPEGEN_COSIGN_PUB (sha256)', expected: r.cosignPubSha256, actual });
  }

  // the locks (I3): each planned one in force once finish ran, and its live contents as pipegen set them
  await locks(api, app, central, r, drift, notes);

  // the pinned central commit: on the central default branch's history
  if (r.centralSha !== null) {
    const repo = await readRepo(gh, central, clock);
    let status: string | null = null;
    if (repo !== null) {
      try { status = await compareStatus(gh, central, repo.defaultBranch, r.centralSha, clock); } catch (e) {
        if (statusOf(e) !== 404 && statusOf(e) !== 422) throw e;
      }
    }
    if (status !== 'identical' && status !== 'behind') drift.push({ what: 'pinned central commit', expected: `${r.centralSha} on the central default branch`, actual: status });
  }

  // G29: team-only CODEOWNERS rules that override pipegen's block
  const tree = trees.app;
  for (const path of CO_PLACES) {
    const e = tree?.get(path);
    if (e === undefined) continue;
    if (e.type === 'blob' && e.mode !== '120000') warnings.push(...teamOnly(await readBlobText(gh, app, e.sha, MAX_TEXT, clock), r, path));
    break;
  }
  // G26
  if (r.planned.signingMode === 'key-env' || r.cosignPubSha256 !== undefined) {
    notes.push('A signing key rotation (`npx pipegen finish --rotate-key`) resets the baseline: images signed with the old key no longer verify, and the gate\'s marker and baseline start again from the next default-branch run.');
  }
  return out();
}

type Obj = Record<string, unknown>;
type Lock = 'gate' | 'reviews' | 'central' | 'org';
const REPO_ONE = 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}';
const ORG_ONE = 'GET /orgs/{org}/rulesets/{ruleset_id}';

/** The pull_request rule's settings pipegen sets, as GitHub names them, and how each may differ (never weaker). */
function reviewDrift(want: Obj | undefined, got: Obj | undefined): string[] {
  const w = isObj(want?.parameters) ? want.parameters : {};
  const g = isObj(got?.parameters) ? got.parameters : null;
  if (g === null) return ['the pull request rule'];
  const out: string[] = [];
  if (g.dismiss_stale_reviews_on_push !== true) out.push('dismiss stale reviews');
  if (w.require_last_push_approval === true && g.require_last_push_approval !== true) out.push('approval after the last push');
  if (w.require_code_owner_review === true && g.require_code_owner_review !== true) out.push('code-owner review');
  const n = typeof w.required_approving_review_count === 'number' ? w.required_approving_review_count : 0;
  if (typeof g.required_approving_review_count !== 'number' || g.required_approving_review_count < n) out.push(`${n} approving review${n === 1 ? '' : 's'}`);
  return out;
}
const ruleOf = (rules: unknown, type: string): Obj | undefined => (Array.isArray(rules) ? rules.filter(isObj).find((x) => x.type === type) : undefined);

/**
 * What differs between a live ruleset and the one pipegen planned (the same rules finish's read-back checks), each as drift: enforcement
 * active, no bypass actors, the planned rules held (lists of the same length) and conditions, then the fixed rules whatever the record plans:
 * the gate's one required check from the GitHub Actions app, and the review settings never weaker.
 */
function rulesetDrift(what: string, kind: Lock, want: Obj | undefined, got: Obj | null): VerifyDrift[] {
  if (got === null) return [{ what, expected: 'there, as pipegen set it', actual: null }];
  const out: VerifyDrift[] = [];
  const state = typeof got.enforcement === 'string' ? got.enforcement : null;
  if (state !== 'active') out.push({ what, expected: 'enforcement active', actual: state === null ? null : show(state, 40) });
  const by = got.bypass_actors;
  if (!Array.isArray(by) || by.length > 0) out.push({ what, expected: 'no bypass actors', actual: Array.isArray(by) ? `${by.length} bypass actor${by.length === 1 ? '' : 's'}` : 'not shown' });
  // the org rule is pinned to the central head finish found then, not the planned sha
  const w = want === undefined ? undefined : kind === 'org' ? stripSha(want) : want;
  if (w !== undefined && (!holdsWanted(w.rules, got.rules) || !holdsWanted(w.conditions, got.conditions))) out.push({ what, expected: 'pipegen\'s rules', actual: 'changed' });
  if (kind === 'gate') {
    const checks = ruleOf(got.rules, 'required_status_checks')?.parameters;
    const list = isObj(checks) && Array.isArray(checks.required_status_checks) ? checks.required_status_checks : [];
    const ok = list.length === 1 && isObj(list[0]) && list[0].context === GATE_CHECK_NAME && list[0].integration_id === GATE_CHECK_INTEGRATION_ID;
    if (!ok) out.push({ what, expected: `the one required check ${GATE_CHECK_NAME} from the GitHub Actions app (${GATE_CHECK_INTEGRATION_ID})`, actual: list.length === 0 ? null : show(JSON.stringify(list), 160) });
  }
  if (kind === 'reviews' || kind === 'central') {
    const weaker = reviewDrift(ruleOf(w?.rules, 'pull_request'), ruleOf(got.rules, 'pull_request'));
    if (weaker.length > 0) out.push({ what, expected: `the review rules: ${weaker.join(', ')}`, actual: 'weaker or missing' });
  }
  return out;
}
function stripSha(want: Obj): Obj {
  const c = structuredClone(want);
  for (const rule of Array.isArray(c.rules) ? c.rules.filter(isObj) : []) {
    const wfs = isObj(rule.parameters) && Array.isArray(rule.parameters.workflows) ? rule.parameters.workflows : [];
    for (const wf of wfs) if (isObj(wf)) delete wf.sha;
  }
  return c;
}

/** I3: every lock the record plans, in force once finish ran, with its live contents as planned (see rulesetDrift). */
async function locks(api: SettingsApi, app: RepoRef, central: RepoRef, r: InstallRecord, drift: VerifyDrift[], notes: string[]): Promise<void> {
  const P = r.planned;
  const finished = r.mergedAt !== undefined;
  const get = async (route: string, params: Obj): Promise<Obj | null> => { const d = await api.readOr404(route, params); return isObj(d) ? d : null; };
  const byName = async (route: string, params: Obj, name: string): Promise<number | null> => {
    const d = await api.readOr404(route, { ...params, per_page: 100 });
    const hits = Array.isArray(d) ? d.filter(isObj).filter((x) => x.name === name && Number.isSafeInteger(x.id)) : [];
    return hits.length === 1 ? hits[0]?.id as number : null;
  };
  const appP = { owner: app.owner, repo: app.repo };
  const centralP = { owner: central.owner, repo: central.repo };
  /** A planned ruleset the record doesn't list: the same-name one (finish updated it but couldn't record it, ruling 8), or drift. */
  const unrecorded = async (what: string, kind: Lock, want: Obj | undefined, list: string, one: string, params: Obj, name: string): Promise<void> => {
    const id = await byName(list, kind === 'org' ? params : { ...params, includes_parents: false }, name);
    if (id === null) { drift.push({ what, expected: 'applied by finish', actual: null }); return; }
    const d = rulesetDrift(what, kind, want, await get(one, { ...params, ruleset_id: id }));
    drift.push(...d);
    if (d.length === 0) notes.push(`The ${what.replace(/^the /, '')} (id ${id}) holds pipegen's rules but is not in the install record (it was there before pipegen; uninstall leaves it).`);
  };

  // the app's rulesets (or classic branch protection standing in for them)
  if (r.classicProtection !== undefined) {
    const what = `classic branch protection on ${show(r.classicProtection.branch, 100)}`;
    const got = await api.readOr404('GET /repos/{owner}/{repo}/branches/{branch}/protection', { ...appP, branch: r.classicProtection.branch });
    if (got === null) drift.push({ what, expected: 'pipegen\'s rules', actual: null });
    else if (P.classic !== undefined && !holdsWanted(P.classic.body, classicPutForm(got))) drift.push({ what, expected: 'pipegen\'s rules', actual: 'changed' });
  } else if (P.rulesets !== undefined || r.rulesets.length > 0) {
    const planned: ['gate' | 'reviews', string, Obj | undefined][] = [['gate', GATE_RULESET, P.rulesets?.gate.body], ['reviews', REVIEWS_RULESET, P.rulesets?.reviews?.body]];
    for (const [kind, name, want] of planned) {
      const what = `ruleset ${name}`;
      const rec = r.rulesets.find((x) => x.kind === kind);
      if (rec !== undefined) drift.push(...rulesetDrift(what, kind, want, await get(REPO_ONE, { ...appP, ruleset_id: rec.id })));
      else if (finished && want !== undefined) await unrecorded(what, kind, want, 'GET /repos/{owner}/{repo}/rulesets', REPO_ONE, appP, name);
    }
  }
  // the central merge rule: recorded either way once finish made or reused it
  const cWhat = `the central merge rule (ruleset ${CENTRAL_RULESET} on ${central.owner}/${central.repo})`;
  if (r.central?.rulesetId !== undefined) drift.push(...rulesetDrift(cWhat, 'central', P.centralRuleset?.body, await get(REPO_ONE, { ...centralP, ruleset_id: r.central.rulesetId })));
  else if (finished && P.centralRuleset !== undefined) drift.push({ what: cWhat, expected: 'applied by finish', actual: null });
  // the org required workflow rule
  const oName = typeof P.orgRequiredWorkflow?.rule.body.name === 'string' ? P.orgRequiredWorkflow.rule.body.name : r.orgRuleset?.name ?? '';
  const oWhat = `the org required workflow rule (${show(r.orgRuleset?.name ?? oName, 100)})`;
  if (r.orgRuleset !== undefined) drift.push(...rulesetDrift(oWhat, 'org', P.orgRequiredWorkflow?.rule.body, await get(ORG_ONE, { org: r.orgRuleset.org, ruleset_id: r.orgRuleset.id })));
  else if (finished && P.orgRequiredWorkflow !== undefined) await unrecorded(oWhat, 'org', P.orgRequiredWorkflow.rule.body, 'GET /orgs/{org}/rulesets', ORG_ONE, { org: app.owner }, oName);
}

async function treeOf(gh: Octokit, r: RepoRef, clock: RateClock): Promise<Map<string, TreeEntry> | null> {
  const repo = await readRepo(gh, r, clock);
  if (repo === null) return null;
  const head = await readHead(gh, r, repo.defaultBranch, clock);
  return head === null ? null : (await readTree(gh, r, head, clock)).entries;
}

async function findSetupPr(api: SettingsApi, app: RepoRef): Promise<number | undefined> {
  const d = await api.readOr404('GET /repos/{owner}/{repo}/pulls', { owner: app.owner, repo: app.repo, head: `${app.owner}:${SETUP_BRANCH}`, state: 'all', per_page: 100 });
  const list = Array.isArray(d) ? d.filter(isObj).filter((p) => isObj(p.head) && p.head.ref === SETUP_BRANCH && Number.isSafeInteger(p.number)) : [];
  return list.map((p) => p.number as number).sort((a, b) => b - a)[0];
}

/**
 * G29: rules after pipegen's block (they win over it, the last matching rule counts) whose owners are only teams and whose pattern covers a
 * protected path. Before the block, pipegen's lines override them.
 */
function teamOnly(text: string, r: InstallRecord, path: string): string[] {
  const lines = text.split(/\r?\n/);
  const end = lines.findIndex((l) => l.trim() === CODEOWNERS_END);
  const isProt = protectedMatcher([...new Set([...r.protectedPaths, ...PROTECTED_PATHS_BASE])]);
  const out: string[] = [];
  for (const raw of lines.slice(end < 0 ? 0 : end + 1)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const [pattern, ...owners] = line.split(/\s+/) as [string, ...string[]];
    if (owners.length === 0 || !owners.every((o) => /^@[^/\s]+\/\S+$/.test(o))) continue;
    const sample = pattern.replace(/^\//, '').replace(/\/$/, '/x').replace(/\*\*/g, 'x').replace(/[*?]/g, 'x');
    if (!isProt(sample)) continue;
    out.push(`${show(path)}: the rule for ${show(pattern, 100)} (after pipegen's block, so it wins) names only teams (${owners.map((o) => show(o, 60)).join(' ')}). The workflow's own token can't read a team's members, so the gate can't check their approval of changes to that protected path: name users (@login) there.`);
  }
  return out;
}
