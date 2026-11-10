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
//   - fix round 2 (G11-R2, G11-R-sec1): each ruleset's target; classic protection AND the recorded rulesets when the record holds both; the org
//     required workflow rule's every workflow entry pinned to record.orgRuleset.pinnedSha, that commit on the central default branch; a lock
//     stricter than pipegen set it (more approvals, a review switch on that pipegen leaves off) is a note ("stricter"), not drift;
//   - the pinned central commit (record.centralSha) on the central default branch's history.
//   - G13 (carry 62): key-env only, the signing environment pipegen-signing is still limited to the default branch (one custom branch rule).
// It also warns (G29) about CODEOWNERS rules after pipegen's block that name only teams (the workflow's own token can't read a team's
// members, so the gate can't check those approvals), and says (G26) that a key rotation resets the baseline.
import type { Octokit } from '@octokit/rest';
import { validDate } from '../../gate/src/date.js';
import picomatch from 'picomatch';
import { codeOwners, ownersLookup, PIPEGEN_BLOCK_BEGIN, PIPEGEN_BLOCK_END, pipegenBlockOwners, type CodeownersRule } from '../../gate/src/integrity.js';
import { gitBlobSha } from '../create/guard.js';
import { centralWorkflowFile } from '../engine/central-path.js';
import { CENTRAL_PROTECTED_PATHS, CODEOWNERS_END } from '../engine/created-builders.js';
import type { RateClock } from '../engine/github-rate.js';
import { protectedMatcher } from '../engine/protected-match.js';
import { SIGNING_ENVIRONMENT } from '../engine/referee.js';
import { pubKeySha256 } from '../engine/signing.js';
import { clockOf } from '../github/client.js';
import { CENTRAL_RULESET, CO_PLACES, coKey, GATE_RULESET, REVIEWS_RULESET } from '../layers/locks.js';
import { GATE_CHECK_INTEGRATION_ID, GATE_CHECK_NAME, PROTECTED_PATHS_BASE, type InstallRecord } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { readEnv, SETUP_BRANCH } from './deliver.js';
import { parseYamlLimited } from '../read/limits.js';
import { compareStatus, DeliverError, readBlobText, readHead, readRepo, readTree, statusOf, type RepoRef, type TreeEntry } from './git-data.js';
import { centralUpdateBranch, centralOf, protectedPathsOfRecord, readLocalRecord, readRecord, RecordError, recordMarkerOf, recordPath, type LocalRecordDeps } from './record.js';
import { classicPutForm, holdsWanted, isObj, SettingsApi } from './settings-api.js';

export interface VerifyDrift { what: string; expected: string; actual: string | null }
export interface VerifyResult { drift: VerifyDrift[]; warnings: string[]; notes: string[] }
export interface VerifyDeps { clock?: RateClock; local?: LocalRecordDeps }

const show = (s: string, n = 140): string => safeText(s, n);
const MAX_TEXT = 512 * 1024;
/** Which recorded paths are protected: the record's own list for the app (the built-in one if it holds none), the central list for central. */
const protectedListOf = (r: InstallRecord, repo: 'app' | 'central'): readonly string[] => (repo === 'app' ? (r.protectedPaths.length > 0 ? protectedPathsOfRecord(r.protectedPaths) : PROTECTED_PATHS_BASE) : CENTRAL_PROTECTED_PATHS);

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
  // G-COCASE-R2 M4: the setup pull request merged but the record names no merge: finish never completed, so no lock it plans is checked
  // below (they are judged only once finish ran) and none may be in force. G-COCASE-R3 N1: or finish ran with the central ruleset on, and
  // its record waits in the central pull request until someone merges it
  if (r.mergedAt === undefined && isObj(body) && typeof body.merged_at === 'string' && body.merged_at !== '') {
    drift.push({ what: 'finish (the locks after the merge)', expected: 'the install record names the setup pull request\'s merge (finish ran to the end)', actual: `finish has not completed, or the install record it wrote waits in the central pull request \`${centralUpdateBranch(app.repo)}\`: merge it, else run \`npx pipegen finish\`` });
  }

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
    const readText = async (): Promise<string> => (e === undefined || e.type !== 'blob' ? '' : await readBlobText(gh, ed.repo === 'app' ? app : central, e.sha, MAX_TEXT, clock));
    // G-FINREC-R1 (sec M1): in every CODEOWNERS pipegen created or edited (app or central, its own write included), a rule after pipegen's
    // block wins over it; one that takes a protected path from the block's owners is drift (inserted text alone can't show that)
    // G-FINREC-R3 i-b: a CODEOWNERS that isn't a plain file (a link, a submodule) is drift even when its sha is the one pipegen wrote
    if (ed.kind === 'codeowners' && e !== undefined && (e.type !== 'blob' || (e.mode !== '100644' && e.mode !== '100755'))) {
      drift.push({ what: `pipegen's lines in ${label(ed.repo, ed.path)}`, expected: 'pipegen\'s inserted text, once', actual: 'it is a link or not a plain file, so it can\'t be read' });
      continue;
    }
    let coText: string | null = null;
    if (ed.kind === 'codeowners' && e !== undefined && e.type === 'blob' && e.mode !== '120000') {
      try { coText = await readText(); } catch (err) {
        // an unreadable CODEOWNERS is drift, never a crash (G-FINREC-R2 i1 review)
        if (!(err instanceof DeliverError) && statusOf(err) !== 404 && statusOf(err) !== 422) throw err;
        drift.push({ what: `pipegen's lines in ${label(ed.repo, ed.path)}`, expected: 'pipegen\'s inserted text, once', actual: 'it can\'t be read' });
        continue;
      }
      // the text must be the blob GitHub reads: a file that isn't UTF-8 decodes with replacements, and nothing is judged on that text
      if (gitBlobSha(coText) !== e.sha) {
        drift.push({ what: `pipegen's lines in ${label(ed.repo, ed.path)}`, expected: 'pipegen\'s inserted text, once', actual: 'it can\'t be read as UTF-8 text, so pipegen can\'t check it' });
        continue;
      }
    }
    if (coText !== null) {
      const over = overrides(coText, ed.repo === 'app' ? [...new Set([...protectedListOf(r, 'app'), ...PROTECTED_PATHS_BASE])] : CENTRAL_PROTECTED_PATHS);
      // markers missing with the inserted text gone too: the check below names it once
      if (over === null ? coText.split((ed as { inserted: string }).inserted).length === 2 : over.length > 0) {
        // G-FINREC-R2 N3: what to do, and what each rule takes
        drift.push(over === null
          ? { what: `a CODEOWNERS rule after pipegen's block in ${label(ed.repo, ed.path)}`, expected: 'keep exactly one `# pipegen:begin` and one `# pipegen:end` line', actual: 'pipegen\'s begin or end line is missing or repeated, so nothing can say where its block ends' }
          : { what: `a CODEOWNERS rule after pipegen's block in ${label(ed.repo, ed.path)}`, expected: 'rules after `# pipegen:end` win over pipegen\'s block: move them above `# pipegen:begin`, or give them only pipegen\'s owners', actual: show(over.map((o) => `${o.line} (${o.covers})`).join(' | '), 600) });
      }
    }
    if (e !== undefined && ed.writtenShas.includes(e.sha)) continue;
    if (ed.kind === 'codeowners' || ed.kind === 'hooks' || ed.kind === 'dependabot') {
      const text = coText ?? await readText();
      if (text.split(ed.inserted).length !== 2) drift.push({ what: `pipegen's lines in ${label(ed.repo, ed.path)}`, expected: 'pipegen\'s inserted text, once', actual: e === undefined ? null : 'changed or missing' });
    } else {
      drift.push({ what: label(ed.repo, ed.path), expected: ed.writtenShas.at(-1) ?? 'the file pipegen wrote', actual: e?.sha ?? null });
    }
  }

  // G-FINREC-R2 N2: GitHub (and the gate) read the first of CO_PLACES that is there; one ahead of the file pipegen edited shadows its block
  for (const repo of ['app', 'central'] as const) {
    const edited = new Set([...r.edits.filter((e) => e.repo === repo && e.kind === 'codeowners').map((e) => e.path), ...r.files.filter((f) => f.repo === repo && f.part === 'codeowners').map((f) => f.path)]);
    if (edited.size === 0) continue;
    // G-FINREC-R3 i-a, G-COCASE-R2 M3: names compared by coKey (letter case and look-alike letters; fail closed: a variant GitHub might
    // read first counts as present)
    const paths = [...(trees[repo]?.keys() ?? [])];
    const at = CO_PLACES.map((p) => paths.filter((x) => coKey(x) === coKey(p))).find((m) => m.length > 0);
    const first = at?.find((x) => !edited.has(x));
    if (first === undefined) continue;
    const ours = [...edited].map((p) => show(p)).join(', ');
    drift.push({ what: `the CODEOWNERS GitHub reads in the ${repo === 'app' ? 'app' : 'central'} repo`, expected: `${ours} (the file with pipegen's block) read first`, actual: `${show(first)} is the CODEOWNERS GitHub reads, so pipegen's block in ${ours} has no effect: take ${show(first)} out, or move its rules into ${ours} above \`# pipegen:begin\`` });
  }
  // G-FINREC-R2 i1 (and its review): code-owner review planned on central (finish ran) needs, in the CODEOWNERS central reads, pipegen's
  // block with exactly the planned owners and no rule after it that takes a protected path (finish may have skipped writing it, or reused a
  // block it recorded no edit for). Unreadable is drift too.
  if (r.mergedAt !== undefined && r.planned.owners.central.length > 0 && trees.central !== null) {
    const what = 'pipegen\'s block in the central CODEOWNERS';
    // G-COCASE: names compared by coKey, like N2 (fail closed): two files GitHub might read is drift; a lone variant (not exactly a
    // CO_PLACES entry) is drift too (G-COCASE-R2 I1), and its content is still checked
    const cands = coCandidates(trees.central.keys());
    const first = cands.length === 1 ? cands[0] : undefined;
    const e = first === undefined ? undefined : trees.central.get(first);
    const where = show(first ?? '.github/CODEOWNERS');
    let text: string | null = null;
    let why: string | null = null;
    if (cands.length > 1) why = `the central repo holds ${cands.map((p) => show(p)).join(', ')}: GitHub may read either, so pipegen's block may have no effect: keep only the one with pipegen's block`;
    else if (first === undefined) why = null;
    else if (e === undefined || e.type !== 'blob' || e.mode === '120000') why = 'it is a link or not a plain file, so it can\'t be read';
    else {
      try {
        text = await readBlobText(gh, central, e.sha, MAX_TEXT, clock);
        if (gitBlobSha(text) !== e.sha) { text = null; why = 'it can\'t be read as UTF-8 text'; }
      } catch (err) {
        if (!(err instanceof DeliverError) && statusOf(err) !== 404 && statusOf(err) !== 422) throw err;
        why = 'it can\'t be read';
      }
    }
    // G-COCASE-R2 I1: a lone candidate that isn't exactly a CO_PLACES entry: a case-sensitive GitHub reads no CODEOWNERS there (its content
    // is still checked below)
    const exact = first === undefined ? undefined : CO_PLACES.find((p) => coKey(p) === coKey(first));
    if (first !== undefined && exact !== first) drift.push({ what: `the central CODEOWNERS name (${show(first)})`, expected: `${exact ?? '.github/CODEOWNERS'}, exactly the name GitHub reads`, actual: `${show(first)} differs from ${exact ?? '.github/CODEOWNERS'} only in letter case (or by a look-alike letter), so GitHub may not read it: rename it to ${exact ?? '.github/CODEOWNERS'}` });
    const want = [...new Set(r.planned.owners.central.map((o) => o.replace(/^@/, '').toLowerCase()))].sort();
    const got = text === null ? [] : pipegenBlockOwners(text);
    const planned = `pipegen's block in ${where} with the planned owners ${want.map((o) => `@${o}`).join(' ')} (the central ruleset asks for code-owner review)`;
    if (cands.length > 1) drift.push({ what, expected: `one CODEOWNERS file in the central repo: ${planned}`, actual: show(why as string, 600) });
    else if (first === undefined) drift.push({ what, expected: planned, actual: null });
    else if (text === null) drift.push({ what, expected: planned, actual: why });
    else if (got.length === 0) drift.push({ what, expected: planned, actual: 'no pipegen block: run `npx pipegen finish` again (it says why it left the file)' });
    else if (got.join(' ') !== want.join(' ')) drift.push({ what, expected: planned, actual: `the block names ${got.map((o) => `@${o}`).join(' ')}: another project's block is in force with other owners; give every project sharing this central repo the same code owners, then run \`npx pipegen finish\` in each` });
    // an override after the block: the per-edit check already read a file pipegen recorded an edit for
    if (text !== null && got.length > 0 && !r.edits.some((x) => x.repo === 'central' && x.kind === 'codeowners' && x.path === first)) {
      const over = overrides(text, CENTRAL_PROTECTED_PATHS);
      if (over === null) drift.push({ what: `a CODEOWNERS rule after pipegen's block in ${label('central', first as string)}`, expected: 'keep exactly one `# pipegen:begin` and one `# pipegen:end` line', actual: 'pipegen\'s begin or end line is missing or repeated, so nothing can say where its block ends' });
      else if (over.length > 0) drift.push({ what: `a CODEOWNERS rule after pipegen's block in ${label('central', first as string)}`, expected: 'rules after `# pipegen:end` win over pipegen\'s block: move them above `# pipegen:begin`, or give them only pipegen\'s owners', actual: show(over.map((o) => `${o.line} (${o.covers})`).join(' | '), 600) });
    }
  }

  // the variables
  if (r.blockFrom !== undefined) {
    const v = await api.readOr404('GET /repos/{owner}/{repo}/actions/variables/{name}', { owner: app.owner, repo: app.repo, name: 'PIPEGEN_BLOCK_FROM' });
    const actual = isObj(v) && typeof v.value === 'string' ? v.value : null;
    if (actual !== r.blockFrom) drift.push({ what: 'PIPEGEN_BLOCK_FROM', expected: r.blockFrom, actual: actual === null ? null : show(actual, 40) });
    // G11-R3 N3-1: a recorded date the gate reads as no date (year 0000) leaves the gate in warn mode even when the variable matches it
    else if (validDate(r.blockFrom) !== r.blockFrom) drift.push({ what: 'PIPEGEN_BLOCK_FROM', expected: 'a real calendar date the gate reads', actual: show(actual, 40) });
  }
  if (r.cosignPubSha256 !== undefined) {
    const v = await api.readOr404('GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}', { owner: app.owner, repo: app.repo, environment_name: SIGNING_ENVIRONMENT, name: 'PIPEGEN_COSIGN_PUB' });
    const actual = isObj(v) && typeof v.value === 'string' ? pubKeySha256(v.value) : null;
    if (actual !== r.cosignPubSha256) drift.push({ what: 'PIPEGEN_COSIGN_PUB (sha256)', expected: r.cosignPubSha256, actual });
  }

  // G13 (carry 62): key-env signing is safe only while pipegen-signing stays usable from the default branch alone (S11, DEC #86): one custom
  // branch rule naming the default branch, nothing else. A missing environment or policy, protected branches, another rule: drift.
  if (r.planned.signingMode === 'key-env' || r.cosignPubSha256 !== undefined) {
    const what = `environment ${SIGNING_ENVIRONMENT} (default branch only)`;
    const expected = `only ${show(r.app.defaultBranch, 100)} may use it`;
    let actual: string | null;
    try {
      const e = await readEnv(gh, app, clock);
      const dbp = e?.settings.deployment_branch_policy;
      if (e === null || e === undefined) actual = null;
      else if (dbp === null || dbp === undefined) actual = 'any branch';
      else if (dbp.custom_branch_policies !== true || dbp.protected_branches !== false) actual = dbp.protected_branches ? 'protected branches' : 'no branch rule';
      else {
        const only = e.policies.length === 1 && e.policies[0]?.type === 'branch' && e.policies[0].name === r.app.defaultBranch;
        actual = only ? '' : e.policies.length === 0 ? 'no branch rule' : e.policies.map((x) => `${x.type} ${show(x.name, 60)}`).join(', ');
      }
    } catch (err) {
      if (!(err instanceof DeliverError)) throw err;
      actual = `unreadable (${show(err.message, 160)})`;
    }
    if (actual !== '') drift.push({ what, expected, actual });
  }

  // a commit on the central default branch's history: compare says the branch is the commit or ahead of it (null: GitHub can't compare)
  const centralRepo = await readRepo(gh, central, clock);
  const statusOnDefault = async (sha: string): Promise<string | null> => {
    if (centralRepo === null) return null;
    try { return await compareStatus(gh, central, centralRepo.defaultBranch, sha, clock); } catch (e) {
      if (statusOf(e) !== 404 && statusOf(e) !== 422) throw e;
      return null;
    }
  };

  // G17 rows 40 and 46: the org rule's required workflow as it is at a commit the rule names (undefined: GitHub doesn't show that commit)
  const reqPath = centralWorkflowFile(r.app.repo, 'required');
  const requiredAt = async (sha: string): Promise<RequiredAt | undefined> => {
    try {
      const e = (await readTree(gh, central, sha, clock)).entries.get(reqPath);
      if (e === undefined || e.type !== 'blob') return { path: reqPath, blob: e?.sha ?? null, text: null };
      return { path: reqPath, blob: e.sha, text: await readBlobText(gh, central, e.sha, MAX_TEXT, clock) };
    } catch (err) {
      if (!(err instanceof DeliverError) && statusOf(err) !== 404 && statusOf(err) !== 422) throw err;
      return undefined;
    }
  };

  // the locks (I3): each planned one in force once finish ran, and its live contents as pipegen set them
  await locks(api, app, central, r, drift, notes, statusOnDefault, requiredAt);

  // the pinned central commit: on the central default branch's history
  if (r.centralSha !== null) {
    const status = await statusOnDefault(r.centralSha);
    if (!onDefaultBranch(status)) drift.push({ what: 'pinned central commit', expected: `${r.centralSha} on the central default branch`, actual: status });
  }

  // G29: team-only CODEOWNERS rules that override pipegen's block
  // G-COCASE: every file GitHub might read (names compared by coKey, fail closed)
  const tree = trees.app;
  for (const path of coCandidates(tree?.keys() ?? [])) {
    const e = tree?.get(path);
    if (e === undefined) continue;
    if (e.type === 'blob' && e.mode !== '120000') {
      const named = r.edits.some((x) => x.repo === 'app' && x.kind === 'codeowners' && x.path === path);
      let text: string;
      try { text = await readBlobText(gh, app, e.sha, MAX_TEXT, clock); } catch (err) {
        // G-FINREC-R3 m2: unreadable is drift like the other two reads, never a crash (the per-edit check already named a file pipegen edited)
        if (!(err instanceof DeliverError) && statusOf(err) !== 404 && statusOf(err) !== 422) throw err;
        if (!named) drift.push({ what: `the CODEOWNERS GitHub reads in the app repo (${label('app', path)})`, expected: 'UTF-8 text pipegen can check', actual: 'it can\'t be read' });
        continue;
      }
      // G-FINREC-R2: only text that hashes back to the blob is judged; the per-edit check already named a file pipegen edited
      if (gitBlobSha(text) === e.sha) warnings.push(...teamOnly(text, r, path));
      else if (!named) drift.push({ what: `the CODEOWNERS GitHub reads in the app repo (${label('app', path)})`, expected: 'UTF-8 text pipegen can check', actual: 'it can\'t be read as UTF-8 text, so pipegen can\'t check it' });
    }
  }
  // G26
  if (r.planned.signingMode === 'key-env' || r.cosignPubSha256 !== undefined) {
    notes.push('A signing key rotation (`npx pipegen finish --rotate-key`) resets the baseline: images signed with the old key no longer verify, and the gate\'s marker and baseline start again from the next default-branch run.');
  }
  return out();
}

/**
 * G-COCASE: the CODEOWNERS paths in `paths` GitHub might read, names compared by coKey (letter case and look-alike letters; fail closed,
 * like N2): each CO_PLACES entry's matches in order, up to the first entry there in its exact spelling (GitHub reads that one or a variant
 * of it, never a later one). More than one: GitHub may read any of them (drift). One that isn't exactly a CO_PLACES entry: a
 * case-sensitive GitHub may read none (drift, G-COCASE-R2 I1).
 */
function coCandidates(paths: Iterable<string>): string[] {
  const all = [...paths];
  const out: string[] = [];
  for (const p of CO_PLACES) {
    const m = all.filter((x) => coKey(x) === coKey(p));
    out.push(...m);
    if (m.includes(p)) break;
  }
  return out;
}

type Obj = Record<string, unknown>;
type Lock = 'gate' | 'reviews' | 'central' | 'org';
/** The required workflow at one commit: its path, its blob (null: not there as a file) and its text (null: not there). */
interface RequiredAt { path: string; blob: string | null; text: string | null }

/** The commit at which the required workflow `text` calls the project's merge workflow `<central>/<merge>@<sha>` (null: no such one call). */
function mergeCallOf(text: string, central: RepoRef, merge: string): string | null {
  let doc: unknown;
  try { doc = parseYamlLimited(text); } catch { return null; }
  const jobs = isObj(doc) && isObj(doc.jobs) ? Object.values(doc.jobs).filter(isObj) : [];
  const prefix = `${central.owner}/${central.repo}/${merge}@`.toLowerCase();
  const shas = jobs.map((j) => j.uses).filter((u): u is string => typeof u === 'string' && u.toLowerCase().startsWith(prefix)).map((u) => u.slice(prefix.length));
  return shas.length === 1 && SHA_RE.test(shas[0] as string) ? shas[0] as string : null;
}
const onDefaultBranch = (status: string | null): boolean => status === 'identical' || status === 'behind';
/** A sha GitHub's compare may be asked about (40 hex), as the org rule names it. */
const SHA_RE = /^[0-9a-f]{40}$/;
/** G11-R3 (R2-5): the keys of an org rule's workflow entry, sorted and joined. */
const ENTRY_KEYS = 'path,repository_id,sha';
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

/** G11-R2 e: the review settings a lock may hold stricter than pipegen sets them (a higher count; a switch on that pipegen leaves off). */
const STRICTER_WORDS: Readonly<Record<string, string>> = {
  required_approving_review_count: 'approving reviews', dismiss_stale_reviews_on_push: 'dismiss stale reviews', dismiss_stale_reviews: 'dismiss stale reviews',
  require_code_owner_review: 'code-owner review', require_code_owner_reviews: 'code-owner review', require_last_push_approval: 'approval after the last push',
  required_review_thread_resolution: 'resolved review threads', strict: 'branches up to date before merging',
};
/**
 * G11-R2 e: `got` with each setting that is stricter than `want` set back to want's value (so the rest is still compared exactly), and the
 * words for what is stricter. Only the listed counts (higher) and switches (on where pipegen leaves them off) count as stricter.
 */
function relaxStricter(want: Obj, got: Obj, counts: readonly string[], flags: readonly string[]): { got: Obj; stricter: string[] } {
  const g = { ...got };
  const stricter: string[] = [];
  for (const k of counts) {
    const w = want[k];
    const v = g[k];
    if (typeof w === 'number' && typeof v === 'number' && v > w) { stricter.push(`${v} ${STRICTER_WORDS[k] ?? k} (pipegen sets ${w})`); g[k] = w; }
  }
  for (const k of flags) if (want[k] === false && g[k] === true) { stricter.push(`${STRICTER_WORDS[k] ?? k} required (pipegen leaves it off)`); g[k] = false; }
  return { got: g, stricter };
}
const RULESET_COUNTS = ['required_approving_review_count'] as const;
const RULESET_FLAGS = ['dismiss_stale_reviews_on_push', 'require_code_owner_review', 'require_last_push_approval', 'required_review_thread_resolution'] as const;
const CLASSIC_COUNTS = ['required_approving_review_count'] as const;
const CLASSIC_FLAGS = ['dismiss_stale_reviews', 'require_code_owner_reviews', 'require_last_push_approval'] as const;
/** The org rule's workflow entries, as GitHub lists them (every `workflows` parameter of every rule). */
function workflowEntries(rules: unknown): Obj[] {
  const out: Obj[] = [];
  for (const rule of Array.isArray(rules) ? rules.filter(isObj) : []) {
    const wfs = isObj(rule.parameters) && Array.isArray(rule.parameters.workflows) ? rule.parameters.workflows : [];
    for (const wf of wfs) out.push(isObj(wf) ? wf : {});
  }
  return out;
}

interface LockDiff { drift: VerifyDrift[]; stricter: string[] }
/**
 * What differs between a live ruleset and the one pipegen planned (the same rules finish's read-back checks), each as drift: enforcement
 * active, no bypass actors, the planned target, rules (lists of the same length) and conditions, then the fixed rules whatever the record
 * plans: the gate's one required check from the GitHub Actions app, and the review settings never weaker. A review setting stricter than
 * planned is not drift: it comes back in `stricter` (G11-R2 e). The org rule (G11-R-sec1): its planned workflow entries are held to
 * `pinnedSha` (the commit finish pinned and recorded), and every live entry must name it; with no recorded pin (a same-name rule found by
 * name) the sha is left out of the comparison, an entry naming no commit (a branch ref) is drift, and each live entry's commit is checked
 * on the central default branch by the caller. Either way each entry holds only path, repository_id and sha (G11-R3).
 */
function rulesetDrift(what: string, kind: Lock, want: Obj | undefined, got: Obj | null, pinnedSha?: string): LockDiff {
  if (got === null) return { drift: [{ what, expected: 'there, as pipegen set it', actual: null }], stricter: [] };
  const out: VerifyDrift[] = [];
  const stricter: string[] = [];
  const state = typeof got.enforcement === 'string' ? got.enforcement : null;
  if (state !== 'active') out.push({ what, expected: 'enforcement active', actual: state === null ? null : show(state, 40) });
  const by = got.bypass_actors;
  if (!Array.isArray(by) || by.length > 0) out.push({ what, expected: 'no bypass actors', actual: Array.isArray(by) ? `${by.length} bypass actor${by.length === 1 ? '' : 's'}` : 'not shown' });
  const w = want === undefined ? undefined : kind === 'org' ? pinTo(want, pinnedSha) : want;
  // G11-R2 e: the live pull_request rule with its stricter settings set back to pipegen's, so only a looser or other change is drift
  let gotRules = got.rules;
  const wantPr = ruleOf(w?.rules, 'pull_request');
  if (isObj(wantPr?.parameters) && Array.isArray(got.rules)) {
    const wp = wantPr.parameters;
    gotRules = got.rules.map((rule) => {
      if (!isObj(rule) || rule.type !== 'pull_request' || !isObj(rule.parameters)) return rule;
      const x = relaxStricter(wp, rule.parameters, RULESET_COUNTS, RULESET_FLAGS);
      stricter.push(...x.stricter);
      return { ...rule, parameters: x.got };
    });
  }
  if (w !== undefined && (!holdsWanted(w.target, got.target) || !holdsWanted(w.rules, gotRules) || !holdsWanted(w.conditions, got.conditions))) out.push({ what, expected: 'pipegen\'s rules', actual: 'changed' });
  if (kind === 'org') {
    const entries = workflowEntries(got.rules);
    // G11-R3 (R2-5): an entry names its workflow by path, repository_id and sha only (an added ref is drift, whichever GitHub would run)
    for (const e of entries) {
      const keys = Object.keys(e).sort();
      if (keys.join(',') !== ENTRY_KEYS) out.push({ what, expected: 'each required workflow named by path, repository_id and sha only', actual: show(keys.join(', '), 160) });
    }
    if (pinnedSha !== undefined) {
      // G11-R-sec1: every workflow the rule runs is pinned to the commit finish recorded (a repointed or added entry is drift)
      if (entries.length === 0) out.push({ what, expected: `the required workflow pinned to ${pinnedSha}`, actual: null });
      for (const e of entries) if (e.sha !== pinnedSha) out.push({ what, expected: `every required workflow pinned to ${pinnedSha}`, actual: typeof e.sha === 'string' ? show(e.sha, 64) : null });
    } else {
      // G11-R3 (R2-1): no recorded pin; an entry that names no commit (a branch ref, or a sha that is no commit id) is drift; the commits
      // the entries do name are checked on the central default branch by the caller
      for (const e of entries) {
        if (typeof e.sha === 'string' && SHA_RE.test(e.sha)) continue;
        const named = typeof e.sha === 'string' ? e.sha : typeof e.ref === 'string' ? e.ref : null;
        out.push({ what, expected: 'every required workflow pinned to a commit', actual: named === null ? null : show(named, 64) });
      }
    }
  }
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
  return { drift: out, stricter };
}
/**
 * The planned org rule with each workflow entry's sha set to the commit finish pinned (G11-R-sec1); with no recorded pin, the sha left out
 * (the caller checks each live entry's commit on the central default branch instead).
 */
function pinTo(want: Obj, pinnedSha: string | undefined): Obj {
  const c = structuredClone(want);
  for (const rule of Array.isArray(c.rules) ? c.rules.filter(isObj) : []) {
    const wfs = isObj(rule.parameters) && Array.isArray(rule.parameters.workflows) ? rule.parameters.workflows : [];
    for (const wf of wfs) {
      if (!isObj(wf)) continue;
      if (pinnedSha === undefined) delete wf.sha;
      else wf.sha = pinnedSha;
    }
  }
  return c;
}

/**
 * I3: every lock the record plans, in force once finish ran, with its live contents as planned (see rulesetDrift). Fix round 2: classic
 * protection and the recorded rulesets are both checked when the record holds both (G11-R2 c); the org rule's pinned commit must be on the
 * central default branch (G11-R-sec1); stricter settings are notes.
 */
async function locks(api: SettingsApi, app: RepoRef, central: RepoRef, r: InstallRecord, drift: VerifyDrift[], notes: string[], statusOnDefault: (sha: string) => Promise<string | null>, requiredAt: (sha: string) => Promise<RequiredAt | undefined>): Promise<void> {
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
  const stricterNote = (what: string, stricter: readonly string[]): void => {
    if (stricter.length > 0) notes.push(`The ${what.replace(/^the /, '')} is stricter than pipegen set it (${stricter.join('; ')}); that is not drift.`);
  };
  /** One live lock compared: its drift recorded, its stricter settings noted; the org rule's commits checked on the central default branch. */
  const check = async (what: string, kind: Lock, want: Obj | undefined, got: Obj | null, pinnedSha?: string): Promise<VerifyDrift[]> => {
    const d = rulesetDrift(what, kind, want, got, pinnedSha);
    if (kind === 'org' && got !== null) {
      // G11-R-sec1: the recorded pin (else each commit the live rule names) must be on the central default branch
      const shas = pinnedSha !== undefined ? [pinnedSha] : [...new Set(workflowEntries(got.rules).map((e) => e.sha).filter((x): x is string => typeof x === 'string'))].slice(0, 10);
      for (const sha of shas) {
        const status = SHA_RE.test(sha) ? await statusOnDefault(sha) : null;
        if (!onDefaultBranch(status)) d.drift.push({ what, expected: `the pinned commit ${show(sha, 64)} on the central default branch`, actual: status });
        if (!SHA_RE.test(sha)) continue;
        const at = await requiredAt(sha);
        // G17 row 40 (G11 R2-2): with no recorded pin, a commit on the default branch is not enough: the file the rule runs there must be
        // one pipegen wrote (its blob one of the recorded shas of that central file); an older commit without it, or another file, is drift
        if (pinnedSha === undefined) {
          const wrote = r.files.filter((f) => f.repo === 'central' && f.path === at?.path).flatMap((f) => f.shas);
          if (at === undefined || at.blob === null || !wrote.includes(at.blob)) d.drift.push({ what, expected: `${at?.path ?? 'the required workflow'} at ${sha} as pipegen wrote it`, actual: at === undefined ? 'unreadable' : at.blob });
        }
        // G17 row 46: after `pipegen update` re-pinned the app to a new central commit, the rule still runs the required workflow that
        // calls the merge workflow at the old one (a stale pin): named plainly, with the way on
        const call = at?.text === null || at === undefined || r.centralSha === null ? null : mergeCallOf(at.text, central, centralWorkflowFile(r.app.repo, 'merge'));
        if (call !== null && call !== r.centralSha) {
          d.drift.push({ what, expected: `the required workflow at the pinned commit ${sha} calling the merge workflow at the app's central commit ${r.centralSha}`, actual: `it calls it at ${call} (a stale pin)` });
          notes.push(`The org required workflow rule still runs the merge workflow at the central commit ${call.slice(0, 12)}, not at ${(r.centralSha as string).slice(0, 12)}, the one the app calls since \`pipegen update\`. Merge the central pull request that updates ${show(at?.path ?? 'the required workflow')} (run \`pipegen update\` again if there is none), then run \`npx pipegen finish\`: it pins the rule to the new commit.`);
        }
      }
    }
    drift.push(...d.drift);
    stricterNote(what, d.stricter);
    return d.drift;
  };
  /** A planned ruleset the record doesn't list: the same-name one (finish updated it but couldn't record it, ruling 8), or drift. */
  const unrecorded = async (what: string, kind: Lock, want: Obj | undefined, list: string, one: string, params: Obj, name: string): Promise<void> => {
    const id = await byName(list, kind === 'org' ? params : { ...params, includes_parents: false }, name);
    if (id === null) { drift.push({ what, expected: 'applied by finish', actual: null }); return; }
    const d = await check(what, kind, want, await get(one, { ...params, ruleset_id: id }));
    if (d.length === 0) notes.push(`The ${what.replace(/^the /, '')} (id ${id}) holds pipegen's rules but is not in the install record (it was there before pipegen; uninstall leaves it).`);
  };

  // classic branch protection (standing in for the rulesets GitHub refused)
  if (r.classicProtection !== undefined) {
    const what = `classic branch protection on ${show(r.classicProtection.branch, 100)}`;
    const got = await api.readOr404('GET /repos/{owner}/{repo}/branches/{branch}/protection', { ...appP, branch: r.classicProtection.branch });
    if (got === null) drift.push({ what, expected: 'pipegen\'s rules', actual: null });
    else if (P.classic !== undefined) {
      const want = P.classic.body;
      const form = classicPutForm(got);
      const stricter: string[] = [];
      // G11-R2 e: stricter review settings, and branches required up to date, set back to pipegen's before the exact comparison
      if (isObj(want.required_pull_request_reviews) && isObj(form.required_pull_request_reviews)) {
        const x = relaxStricter(want.required_pull_request_reviews, form.required_pull_request_reviews, CLASSIC_COUNTS, CLASSIC_FLAGS);
        form.required_pull_request_reviews = x.got;
        stricter.push(...x.stricter);
      }
      if (isObj(want.required_status_checks) && isObj(form.required_status_checks)) {
        const x = relaxStricter(want.required_status_checks, form.required_status_checks, [], ['strict']);
        form.required_status_checks = x.got;
        stricter.push(...x.stricter);
      }
      if (!holdsWanted(want, form)) drift.push({ what, expected: 'pipegen\'s rules', actual: 'changed' });
      stricterNote(what, stricter);
    }
  }
  // the app's rulesets: every recorded one compared, with or without classic protection (G11-R2 c); a planned one the record lacks is
  // looked up by name only when classic protection doesn't stand in for it
  if (P.rulesets !== undefined || r.rulesets.length > 0) {
    const planned: ['gate' | 'reviews', string, Obj | undefined][] = [['gate', GATE_RULESET, P.rulesets?.gate.body], ['reviews', REVIEWS_RULESET, P.rulesets?.reviews?.body]];
    for (const [kind, name, want] of planned) {
      const what = `ruleset ${name}`;
      const rec = r.rulesets.find((x) => x.kind === kind);
      if (rec !== undefined) await check(what, kind, want, await get(REPO_ONE, { ...appP, ruleset_id: rec.id }));
      else if (finished && want !== undefined && r.classicProtection === undefined) await unrecorded(what, kind, want, 'GET /repos/{owner}/{repo}/rulesets', REPO_ONE, appP, name);
    }
  }
  // the central merge rule: recorded either way once finish made or reused it
  const cWhat = `the central merge rule (ruleset ${CENTRAL_RULESET} on ${central.owner}/${central.repo})`;
  if (r.central?.rulesetId !== undefined) await check(cWhat, 'central', P.centralRuleset?.body, await get(REPO_ONE, { ...centralP, ruleset_id: r.central.rulesetId }));
  else if (finished && P.centralRuleset !== undefined) drift.push({ what: cWhat, expected: 'applied by finish', actual: null });
  // the org required workflow rule, held to the commit finish pinned (G11-R-sec1)
  const oName = typeof P.orgRequiredWorkflow?.rule.body.name === 'string' ? P.orgRequiredWorkflow.rule.body.name : r.orgRuleset?.name ?? '';
  const oWhat = `the org required workflow rule (${show(r.orgRuleset?.name ?? oName, 100)})`;
  if (r.orgRuleset !== undefined) await check(oWhat, 'org', P.orgRequiredWorkflow?.rule.body, await get(ORG_ONE, { org: r.orgRuleset.org, ruleset_id: r.orgRuleset.id }), r.orgRuleset.pinnedSha);
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

const WILD = /[*?[\\]/;
const fixedPrefix = (p: string): string => { const i = p.search(WILD); return (i < 0 ? p : p.slice(0, i)).toLowerCase(); };
const globMatch = (glob: string, name: string): boolean => { try { return picomatch(glob, { nocase: true, dot: true })(name); } catch { return true; } };

/**
 * G-FINREC-R1 (sec M1, review): whether a CODEOWNERS rule can match a path a protected pattern (the gate's form) stands for, decided at the
 * pattern level and failing closed (anything undecided covers):
 * - a folder rule (the gate's `ancestors`: a trailing '/', or a last part with no wildcard) can name a folder holding any file;
 * - a rule with no '/' but a trailing one matches by name at any depth: it covers every protected folder, a protected file whose name (or
 *   folder name) it matches, and (a folder rule) any protected file named anywhere;
 * - an anchored rule covers a protected folder when its fixed prefix (before the first wildcard) and the folder overlap, either way; an
 *   anchored protected file by the gate's own lookup; a protected name at any depth unless its last part is a wildcard glob that doesn't
 *   match the name.
 * A protected pattern with a wildcard outside a trailing `/**` is compared by its fixed prefix the same way. Returns the protected pattern
 * covered (G-FINREC-R2 N3: named in the drift), or null.
 */
function ruleCovers(rule: CodeownersRule, protectedPaths: readonly string[]): string | null {
  // the gate's `ancestors`: a trailing '/', or a last part with no (unescaped) wildcard, can name a folder and so every file under it
  const folderRule = rule.pattern.endsWith('/') || !/(^|[^\\])[*?]/.test(rule.pattern.replace(/\/$/, '').split('/').at(-1) as string);
  const body = rule.pattern.replace(/^\//, '').replace(/\/$/, '');
  if (body === '') return 'every path';
  const anchored = rule.pattern.startsWith('/') || body.includes('/');
  const last = body.split('/').at(-1) as string;
  const prefix = fixedPrefix(body);
  const overlaps = (dir: string): boolean => prefix.startsWith(dir) || dir.startsWith(prefix);
  for (const raw of protectedPaths) {
    const rooted = /^\.?\//.test(raw);
    let q = raw.replace(/^\.?\//, '');
    const anyDepth = !rooted && (!q.includes('/') || q.startsWith('**/'));
    q = q.replace(/^\*\*\//, '');
    const at = anyDepth ? `${q} at any depth` : raw.replace(/^\.\//, '/');
    if (q === '' || q.split('/').some((x) => x === '..')) return at;
    const subtree = q.endsWith('/**');
    const target = subtree ? q.slice(0, -3) : q;
    if (WILD.test(target)) {
      // a wildcard inside the protected pattern: by its fixed prefix (folder part), any-depth names always
      if (!anchored || anyDepth) return at;
      const fixed = fixedPrefix(target);
      if (overlaps(fixed.slice(0, fixed.lastIndexOf('/') + 1))) return at;
      continue;
    }
    if (subtree) {
      if (!anchored || anyDepth) return at;
      if (overlaps(`${target.toLowerCase()}/`)) return at;
      continue;
    }
    const name = target.split('/').at(-1) as string;
    if (!anchored) {
      if (folderRule && anyDepth) return at;
      if (globMatch(body, name) || target.split('/').slice(0, -1).some((d) => globMatch(body, d))) return at;
      continue;
    }
    if (anyDepth) {
      if (folderRule || globMatch(last, name)) return at;
      continue;
    }
    const m = ownersLookup([rule], target);
    if ('unresolved' in m || m.owners !== undefined) return at;
    const ml = ownersLookup([{ ...rule, pattern: rule.pattern.toLowerCase() }], target.toLowerCase());
    if ('unresolved' in ml || ml.owners !== undefined) return at;
  }
  return null;
}

/**
 * G-FINREC-R1 (sec M1): the rules after pipegen's block (they win over it: the last matching rule counts) that cover a protected path and
 * name no owner, or an owner outside the block's (a team, an e-mail, another login). "Covers" is decided at the pattern level (ruleCovers,
 * failing closed). A line
 * GitHub skips owns nothing; a line the gate can't read counts. Lines before the block lose to it. null: not exactly one begin line and one
 * end line after it (nothing can say where the block ends). pipegen's own output has nothing after its block but what the owner wrote.
 */
export function overridingRules(text: string, protectedPaths: readonly string[]): string[] | null {
  return overrides(text, protectedPaths)?.map((o) => o.line) ?? null;
}

/** overridingRules with what each rule covers (G-FINREC-R2 N3), or why it counts without one (N1: a line the gate's parser can't read). */
function overrides(text: string, protectedPaths: readonly string[]): { line: string; covers: string }[] | null {
  const lines = text.split(/\r?\n/);
  const begins = lines.flatMap((l, i) => (l === PIPEGEN_BLOCK_BEGIN ? [i] : []));
  const ends = lines.flatMap((l, i) => (l === PIPEGEN_BLOCK_END ? [i] : []));
  if (begins.length !== 1 || ends.length !== 1 || (ends[0] as number) < (begins[0] as number)) return null;
  const owners = new Set(pipegenBlockOwners(text));
  const out: { line: string; covers: string }[] = [];
  const unreadable = "a line the gate can't read: fix it or take it out";
  for (const raw of lines.slice((ends[0] as number) + 1)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    // G-FINREC-R2 N1: a line the gate's parser drops (or a lone CR GitHub may split on) may still be read by GitHub's own parser: it counts
    const rule = raw.includes('\r') ? undefined : codeOwners(raw)[0];
    if (rule === undefined || rule.unreadable !== undefined) { out.push({ line: line.slice(0, 200), covers: unreadable }); continue; }
    const named = line.split(/\s+/).length - 1;
    if (named > 0 && rule.owners.length === named && rule.owners.every((o) => owners.has(o))) continue;
    const covers = ruleCovers(rule, protectedPaths);
    if (covers !== null) out.push({ line, covers: `covers ${covers}` });
  }
  return out;
}

/**
 * G29: rules after pipegen's block (they win over it, the last matching rule counts) whose owners are only teams and whose pattern covers a
 * protected path. Before the block, pipegen's lines override them.
 */
function teamOnly(text: string, r: InstallRecord, path: string): string[] {
  const lines = text.split(/\r?\n/);
  const end = lines.findIndex((l) => l.trim() === CODEOWNERS_END);
  const isProt = protectedMatcher([...new Set([...protectedPathsOfRecord(r.protectedPaths), ...PROTECTED_PATHS_BASE])]);
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
