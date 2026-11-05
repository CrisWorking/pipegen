// v0.2 Plan G Task 7, verify (sub-task G11; rows G26, G29; Plan V pre-flight §5 G11 item 4): `pipegen verify` is read-only and reports
// drift between the repos and the install record on the central default branch. It reads the record with readRecord (the same reader and
// hash comparison uninstall uses, S2) and checks:
//   - every file pipegen wrote whole (its blob on the default branch is one of the recorded shas) and every edit (pipegen's inserted text
//     still there; the other edit kinds: the blob is one pipegen wrote), protected paths marked;
//   - the record hash against this machine's local record file and the setup pull request body's marker;
//   - PIPEGEN_BLOCK_FROM against record.blockFrom, the sha256 of PIPEGEN_COSIGN_PUB against record.cosignPubSha256;
//   - the recorded rulesets (app, central, org) still there and switched on, and the planned merge locks not missing after finish;
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
import { PROTECTED_PATHS_BASE, type InstallRecord } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { SETUP_BRANCH } from './deliver.js';
import { compareStatus, readBlobText, readHead, readRepo, readTree, statusOf, type RepoRef, type TreeEntry } from './git-data.js';
import { centralOf, readLocalRecord, readRecord, RecordError, recordMarkerOf, recordPath, type LocalRecordDeps } from './record.js';
import { SettingsApi } from './settings-api.js';

export interface VerifyDrift { what: string; expected: string; actual: string | null }
export interface VerifyResult { drift: VerifyDrift[]; warnings: string[]; notes: string[] }
export interface VerifyDeps { clock?: RateClock; local?: LocalRecordDeps }

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const show = (s: string, n = 140): string => safeText(s, n);
const MAX_TEXT = 512 * 1024;
const CO_PLACES: readonly string[] = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'];
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

  // the rulesets: recorded ones still there and on; the planned merge locks not missing once finish ran
  const active = async (route: string, params: Record<string, unknown>, what: string): Promise<void> => {
    const d = await api.readOr404(route, params);
    const state = isObj(d) && typeof d.enforcement === 'string' ? d.enforcement : null;
    if (state !== 'active') drift.push({ what, expected: 'active', actual: state });
  };
  for (const s of r.rulesets) await active('GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', { owner: app.owner, repo: app.repo, ruleset_id: s.id }, `ruleset ${s.name}`);
  if (r.central?.rulesetId !== undefined) await active('GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', { owner: central.owner, repo: central.repo, ruleset_id: r.central.rulesetId }, `the central merge rule (ruleset pipegen on ${central.owner}/${central.repo})`);
  if (r.orgRuleset !== undefined) await active('GET /orgs/{org}/rulesets/{ruleset_id}', { org: r.orgRuleset.org, ruleset_id: r.orgRuleset.id }, `the org required workflow rule (${show(r.orgRuleset.name, 100)})`);
  if (r.mergedAt !== undefined && r.planned.rulesets !== undefined && r.rulesets.length === 0 && r.classicProtection === undefined) drift.push({ what: 'the merge locks', expected: 'rulesets pipegen and pipegen-reviews (or classic branch protection)', actual: null });

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
