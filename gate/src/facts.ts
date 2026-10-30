// Plan C Task C5a: gatherGateInput, the one function that reads every fact decideGate needs (C2's raw-facts GateInput). All I/O goes
// through the injected GitHub client (`gh`: the REST adapter, or a fake) and the injected reader (`io`: the event payload and the result
// artifacts); there is no file system access here, and the workspace (the PR's own code on pull_request) is never read (ruling S21).
//
// The read order (each step only after the one before):
//   0. The event and the repository (the payload, checked against GITHUB_REPOSITORY, GITHUB_SHA and GITHUB_RUN_ID): if they can not be
//      trusted nothing is read and the answer is a SettingsError (the gate blocks).
//   1. Settings (resolveSettings) and the job mapping (mapJobs): pure.
//   2. The result artifacts, by their exact names from the trusted job list, only for a check whose job succeeded with status `ok`:
//      first the head result, then its base-scan twin when the base-scan job reports one (`ok`). Hash and zip checks: artifacts.ts.
//      2b (C9). The secrets job's commit-range result (the job list's `range` entry), the same way, as the commit range (rangeScans): required
//      on a pull request and in the merge queue (a list with a secrets check but no range entry is a tool error), informational on a push to
//      the default branch, none on the push that made the branch. Fix round 1: a range scan that found no commit range on its event (its
//      facts say `skipped`) is not applicable off the pull request events (a note), and a tool error on them.
//   3. The base (CF3b): the base computed from THIS event's payload (pull_request base.sha, merge_group base_sha, push before); only when
//      the base-scan job's `base-sha` output equals it is the ancestry asked (compare base...github.sha, status `ahead` only).
//   4. The diff the "new" rule reads (C2 review I1, r3): compare pull_request.base.sha...github.sha (the scanned merge commit), merge_group
//      base_sha...head_sha; commit = the scanned commit. No diff on a push (counts only).
//   5. Integrity, on a pull request event only: the base's install state (baseHasInstall), CODEOWNERS of the BASE commit, and only then the
//      pull request context (approvals are filtered by those code owners, C4 r1), the shared config sections, the findings.
//   6. The trusted baseline (C3 loadBaseline), then the clean-run marker (cleanRunSeen) and the mode (decideMode).
// The licence check's coverage per lockfile type (G11; the `licence-lockfiles` input, fix round A) is added as `coverage`, never as "clean".
//
// Which runs may decide a merge (fix round 1, I2): pull_request, pull_request_review (the approval re-run), merge_group and a push to the
// default branch. Any other run (a push to another branch or a tag, workflow_dispatch, schedule, pull_request_target, …) sees no pull request
// and so no integrity check: it gets a settings error and never reports pass, because its same-named check could otherwise stand in for the
// pull request's. (Plan G keeps the gate job out of such runs; this is the belt.)
//
// The head (fix round 2): on pull_request, pull_request_review and merge_group, the event's head commit must be github.sha or an ancestor of
// it (compare head...github.sha: ahead or identical), else a settings error: the check lands on the head, so the head must have been scanned.
// The exact binding (C5b Part 0, review-C5a-r2 r2-m1): on pull_request and pull_request_review, github.sha must also be GitHub's test merge
// of exactly that head: GET /commits/{github.sha} has two parents and the second is the payload head. `ahead` alone accepts a merge of a
// NEWER head C that merely contains the payload head B, so B would get a green check from a scan of C. merge_group keeps the equality rule.
//
// One range is compared once (fix round 1, m6): the ancestry and the diff both read GET /compare/{base}...{github.sha} on a pull request, so
// the answer is fetched once and both read it.
import { expectedBaseOf, fileState, type CheckInput, type GateEvent, type GateInput, type JobOutputs, type JobResult, type PrDiff, type RangeScan } from './decide.js';
import { RANGE_TOOL } from '../../src/engine/tool-flags.js';
import { cleanRunSeen, loadBaseline, type GateGithub, type RepoRef } from './baseline.js';
import { downloadResult, type ResultIo } from './artifacts.js';
import { baseHasInstall, buildPrDiff, integrityFindings, loadCodeowners, readConfigSections, readPrContext } from './integrity.js';
import { decideMode } from './mode.js';
import { mapJobs, resolveSettings, type GateToolView } from './settings.js';
import type { ScrubFormat } from './scrub.js';
import type { LicenceLockfiles } from '../../src/engine/licence-lockfiles.js';
import type { Finding } from '../../src/types.js';

export interface GateContext {
  /** The gate step's inputs by name (an empty value is unset). */
  inputs: Readonly<Record<string, string | undefined>>;
  /** GITHUB_EVENT_NAME, GITHUB_SHA, GITHUB_RUN_ID and GITHUB_REPOSITORY (owner/name), as the runner sets them. */
  env: { eventName: string; sha: string; runId: string; repository: string };
  now: Date;
  /** The built-in reviewed list's gate view. */
  reviewed: readonly GateToolView[];
  /** Notes the client adds while reading (rate limits): read at the end and passed on. */
  clientNotes?: readonly string[];
}
/** The reads besides the GitHub client: the event payload text (GITHUB_EVENT_PATH) and the result artifacts of this run. */
export interface GateIo extends ResultIo { readEvent(): string }
/** The event can not be trusted: nothing was read, and the gate blocks with these reasons. */
export interface SettingsError { kind: 'settings-error'; errors: string[] }

const SHA_RE = /^[0-9a-f]{40}$/;
const PR_EVENTS: ReadonlySet<string> = new Set(['pull_request', 'pull_request_review']);
/** The text of the settings error for a run that can not decide a merge (fix round 1, I2). */
export const notAMergeRun = (defaultBranch: string, event: string): string =>
  `the gate runs on pull requests, merge queues and pushes to ${defaultBranch}; this ${/^[a-z_]{1,40}$/.test(event) ? event : 'other'} run can't decide a merge`;

/** The client with GET /compare/{base}...{head} asked once per range (compare and compareFiles are the same endpoint). */
function compareOnce(gh: GateGithub): GateGithub {
  const seen = new Map<string, Promise<unknown>>();
  const once = (owner: string, name: string, base: string, head: string): Promise<unknown> => {
    const k = `${owner}/${name}\0${base}\0${head}`;
    let p = seen.get(k);
    if (p === undefined) { p = gh.compare(owner, name, base, head); seen.set(k, p); }
    return p;
  };
  return new Proxy(gh, {
    get(target, prop, receiver) {
      if (prop === 'compare' || prop === 'compareFiles') return once;
      const v: unknown = Reflect.get(target, prop, receiver);
      return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  });
}
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
function at(o: unknown, ...path: string[]): unknown {
  let v = o;
  for (const k of path) { if (!isPlain(v) || !Object.hasOwn(v, k)) return undefined; v = v[k]; }
  return v;
}
const sha40 = (v: unknown): string | undefined => (typeof v === 'string' && SHA_RE.test(v) ? v : undefined);

/**
 * The licence check's coverage texts (G11, final review fix round A ruling 2), from the `licence-lockfiles` input: per service, every lockfile
 * kind the licence scan does not read is "<service>: <kind>: not covered (lockfile type)", and a service with no lockfile is "<service>: not
 * covered (no lockfile)". A kind that is read adds nothing. Unset input: coverage not known. The texts are only ever added to the check's
 * state (never "clean"); they never make a check pass.
 */
export function licenceCoverage(list: readonly LicenceLockfiles[] | undefined): string[] {
  if (list === undefined) return ['coverage per lockfile not known (the gate step has no licence-lockfiles input)'];
  if (list.length === 0) return ['not covered (no lockfile)'];
  return [...new Set(list.flatMap((e) => (e.lockfiles.length === 0 ? [`${e.service}: not covered (no lockfile)`] : e.lockfiles.filter((l) => !l.read).map((l) => `${e.service}: ${l.kind}: not covered (lockfile type)`))))];
}

const ZERO_SHA = '0'.repeat(40);
/**
 * C9: what the commit-range result of a run says (the same B7 file rules as a check's result, decide.ts fileState): its findings when the job
 * succeeded and the file is the job's own and readable; else a tool error with the reason; no status output at all is "no result". The file is
 * downloaded only for a job that succeeded with status ok.
 */
async function rangeScanOf(tool: string, result: JobResult, outputs: JobOutputs, fileOf: () => Promise<CheckInput['file']>): Promise<RangeScan> {
  if (result !== 'success') {
    return { tool, toolError: outputs.status === 'tool-error' ? (outputs.error ?? 'no detail') : `the secrets job did not succeed (${result}), so its commit-range scan has no result` };
  }
  const st = fileState(outputs, outputs.status === 'ok' ? await fileOf() : undefined);
  switch (st.kind) {
    case 'ok': return st.read.rangeSkipped !== undefined ? { tool, skipped: st.read.rangeSkipped } : { tool, findings: st.read.findings };
    case 'absent': return { tool };
    case 'tool-error': return { tool, toolError: st.why };
    case 'tampered': return { tool, toolError: `the commit-range result is not the one the job made: ${st.why}` };
    case 'missing-file': return { tool, toolError: 'the commit-range result artifact is missing' };
  }
}

/** The repository of this run, from the payload, checked against GITHUB_REPOSITORY (a text: why not). The action's baseline-check mode reads it too. */
export function repoOf(payload: unknown, repository: string): (RepoRef & { private: boolean | undefined }) | string {
  const r = at(payload, 'repository');
  const id = at(r, 'id');
  const name = at(r, 'name');
  const owner = at(r, 'owner', 'login');
  const full = at(r, 'full_name');
  const def = at(r, 'default_branch');
  if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) return 'the event payload has no repository id';
  if (typeof name !== 'string' || typeof owner !== 'string' || typeof full !== 'string' || full !== `${owner}/${name}`) return 'the event payload has no repository name';
  if (typeof repository !== 'string' || full.toLowerCase() !== repository.toLowerCase()) return 'the event payload is not of the repository this run belongs to';
  if (typeof def !== 'string' || def === '') return 'the event payload has no default branch';
  const priv = at(r, 'private');
  return { owner, name, id, defaultBranch: def, private: typeof priv === 'boolean' ? priv : undefined };
}

/**
 * Every fact decideGate needs, read in the order above. A SettingsError only when the event itself can not be trusted (no read is
 * made then); every other problem is a settings error, a note or a fail-closed fact inside the GateInput.
 */
export async function gatherGateInput(ctx: GateContext, client: GateGithub, io: GateIo): Promise<GateInput | SettingsError> {
  const gh = compareOnce(client);
  // 0. the event and the repository
  let payload: unknown;
  try { payload = JSON.parse(io.readEvent()) as unknown; } catch { return { kind: 'settings-error', errors: ['the event payload could not be read'] }; }
  if (!isPlain(payload)) return { kind: 'settings-error', errors: ['the event payload is not an object'] };
  const repo = repoOf(payload, ctx.env.repository);
  if (typeof repo === 'string') return { kind: 'settings-error', errors: [repo] };
  const sha = ctx.env.sha;
  if (typeof sha !== 'string' || !SHA_RE.test(sha)) return { kind: 'settings-error', errors: ['GITHUB_SHA is not a commit sha'] };
  const runId = /^[1-9][0-9]{0,15}$/.test(ctx.env.runId) ? Number(ctx.env.runId) : Number.NaN;
  if (!Number.isSafeInteger(runId)) return { kind: 'settings-error', errors: ['GITHUB_RUN_ID is not a run id'] };
  const event: GateEvent = { name: ctx.env.eventName, sha, payload };
  const notes: string[] = [];
  if (repo.private === undefined) notes.push('the event payload does not say whether the repository is private, so the public rules apply');

  // 1. settings and the job mapping
  const settings = resolveSettings(ctx.inputs, { private: repo.private === true, reviewed: ctx.reviewed });
  notes.push(...settings.notes);
  // only runs that see the pull request (or the queue, or the default branch itself) may decide a merge (I2)
  const pushToDefault = event.name === 'push' && at(payload, 'ref') === `refs/heads/${repo.defaultBranch}`;
  if (!(PR_EVENTS.has(event.name) || event.name === 'merge_group' || pushToDefault)) settings.errors.push(notAMergeRun(repo.defaultBranch, event.name));
  // the scanned commit must contain the head the check lands on (fix round 2, review-C5a-r1 R1): on pull_request_review, github.sha is the
  // PR's LAST merge commit, which can lag behind the head (a conflicted push makes no new one), so a review run could scan an old merge and
  // put a green check on a head that was never scanned. head...github.sha must be `ahead` (a test merge is one commit past the head) or
  // `identical` (a merge queue's head_sha is github.sha itself); anything else, or an error, blocks.
  const eventHead = PR_EVENTS.has(event.name) ? at(payload, 'pull_request', 'head', 'sha') : event.name === 'merge_group' ? at(payload, 'merge_group', 'head_sha') : undefined;
  if (PR_EVENTS.has(event.name) || event.name === 'merge_group') {
    const head = sha40(eventHead);
    const stale = 'the scanned commit does not contain the pull request\'s head: re-run the gate after GitHub has updated the merge commit';
    if (head === undefined) settings.errors.push('the event payload has no head commit, so the scanned commit can not be tied to it');
    else if (head !== sha) {
      try {
        const a = await gh.compare(repo.owner, repo.name, head, sha);
        const status = isPlain(a) && Object.hasOwn(a, 'status') ? a.status : undefined;
        if (status !== 'ahead' && status !== 'identical') settings.errors.push(stale);
      } catch { settings.errors.push('whether the scanned commit contains the pull request\'s head could not be checked, so the gate fails closed'); }
    }
    if (head !== undefined && PR_EVENTS.has(event.name)) {
      const notMerge = 'the scanned commit is not GitHub\'s merge of the pull request\'s head (its second parent must be the head): re-run the gate after GitHub has updated the merge commit';
      try {
        const c = await gh.getCommit(repo.owner, repo.name, sha);
        const parents = isPlain(c) && Object.hasOwn(c, 'parents') ? c.parents : undefined;
        const ok = isPlain(c) && at(c, 'sha') === sha && Array.isArray(parents) && parents.length === 2 && sha40(at(parents[1], 'sha')) === head;
        if (!ok) settings.errors.push(notMerge);
      } catch { settings.errors.push('whether the scanned commit is the merge of the pull request\'s head could not be checked, so the gate fails closed'); }
    }
  }
  const mapped = mapJobs(settings.needs, settings.jobList);
  notes.push(...mapped.notes);
  const outputFile = new Map(ctx.reviewed.flatMap((t) => (t.outputFile === undefined ? [] : [[t.id, t.outputFile] as const])));

  // 2. the result artifacts, by exact name
  const checks: CheckInput[] = [];
  // C9: the commit-range entry is no check of its own (it is read as the range below), so it never counts as the secrets check
  for (const m of mapped.checks.filter((x) => x.entry.range !== true)) {
    const e = m.entry;
    const c: CheckInput = { entry: e, result: m.result, outputs: m.outputs };
    if ((e.format === 'sarif' || e.format === 'zap-json') && e.artifact !== undefined) {
      const fileOf = async (name: string): Promise<CheckInput['file']> => {
        const expectedFile = e.tool === undefined ? undefined : outputFile.get(e.tool);
        const d = await downloadResult(io, { owner: repo.owner, repo: repo.name, runId, name, format: e.format as ScrubFormat, ...(expectedFile === undefined ? {} : { expectedFile }) });
        return d.kind === 'file' ? d.file : undefined;
      };
      if (m.result === 'success' && m.outputs.status === 'ok') { const f = await fileOf(e.artifact); if (f !== undefined) c.file = f; }
      if (m.baseOutputs !== undefined && e.baseArtifact !== undefined) {
        const base: NonNullable<CheckInput['base']> = { outputs: m.baseOutputs };
        if (m.baseOutputs.status === 'ok') { const f = await fileOf(e.baseArtifact); if (f !== undefined) base.file = f; }
        c.base = base;
      }
    }
    checks.push(c);
  }

  // 2b. C9: the secrets job's commit-range scan, read as the commit range (decide.ts rule 7), never as a check. On a pull request and in the
  // merge queue it is required: a job list with a secrets check but no range entry, a failed job, a tool error, no result or a result that is
  // not the job's own all block. On a push to the default branch it is informational; a push that made the branch has no range at all.
  const rangeScans: RangeScan[] = [];
  const prLike = PR_EVENTS.has(event.name) || event.name === 'merge_group';
  const before = pushToDefault ? sha40(at(payload, 'before')) : undefined;
  if (pushToDefault && (before === undefined || before === ZERO_SHA)) {
    if (settings.jobList.some((e) => e.range === true)) notes.push('the push made the default branch (it has no previous commit), so there is no commit range to scan for secrets');
  } else if (prLike || pushToDefault) {
    const ranges = mapped.checks.filter((m) => m.entry.range === true);
    if (ranges.length === 0 && settings.jobList.some((e) => e.category === 'secrets' && e.range !== true)) {
      const why = 'the job list has no commit-range scan for the secrets check, so the commits of the pull request are not scanned (render the pipeline again with pipegen update)';
      if (prLike) rangeScans.push({ tool: RANGE_TOOL, toolError: why }); else notes.push(why);
    }
    for (const m of ranges) {
      const art = m.entry.artifact as string;
      const fileOf = async (): Promise<CheckInput['file']> => {
        const d = await downloadResult(io, { owner: repo.owner, repo: repo.name, runId, name: art, format: 'sarif', ...(outputFile.has(RANGE_TOOL) ? { expectedFile: outputFile.get(RANGE_TOOL) as string } : {}) });
        return d.kind === 'file' ? d.file : undefined;
      };
      const rs = await rangeScanOf(m.entry.tool ?? RANGE_TOOL, m.result, m.outputs, fileOf);
      // fix round 1: "no commit range on this event" is not applicable only off the pull request events; on them it is a range not scanned
      if (rs.skipped !== undefined) {
        if (prLike) rangeScans.push({ tool: rs.tool, toolError: 'the range scan found no commit range on this pull request event (an all-zero base or head, or a base it could not place), so the commits of the pull request are not scanned' });
        // fix round 2 (m2): a push that rewrote the default branch with its old head gone: not scanned, which is said as a warning (decide.ts:
        // a tool error of the range on a push only warns)
        else if (rs.skipped === 'no-merge-base') rangeScans.push({ tool: rs.tool, toolError: 'this push rewrote the history of the default branch and its old head is not in the checkout, so its commit range was not scanned' });
        else notes.push('the range scan found no commit range on this event, so no commit range was scanned');
      } else rangeScans.push(rs);
    }
  }

  // 3. the base: this event's own base, then (only if the base-scan job checked it out) its ancestry against github.sha
  const exp = expectedBaseOf(event);
  let ancestry: GateInput['ancestry'] = null;
  if (exp.base !== undefined && mapped.baseScan?.commit === exp.base) {
    try {
      const a = await gh.compare(repo.owner, repo.name, exp.base, sha);
      const status = isPlain(a) && Object.hasOwn(a, 'status') ? a.status : undefined;
      ancestry = { base: exp.base, head: sha, isAncestor: status === 'ahead' };
    } catch { notes.push('the ancestry of the base commit could not be checked'); }
  }

  // 4. the diff of the scanned tree
  let diff: PrDiff | null = null;
  if (PR_EVENTS.has(event.name)) {
    const base = sha40(at(payload, 'pull_request', 'base', 'sha'));
    diff = base === undefined ? { added: new Map(), complete: false, commit: sha } : await buildPrDiff(gh, repo, base, sha);
  } else if (event.name === 'merge_group') {
    const base = sha40(at(payload, 'merge_group', 'base_sha'));
    const head = sha40(at(payload, 'merge_group', 'head_sha'));
    diff = base === undefined || head === undefined ? { added: new Map(), complete: false, commit: sha } : await buildPrDiff(gh, repo, base, head);
  }

  // 5. integrity (pull request events): install state and CODEOWNERS of the base, then the pull request
  let installing = false;
  let integrity: Finding[] = [];
  if (PR_EVENTS.has(event.name)) {
    const number = at(payload, 'pull_request', 'number');
    const baseSha = sha40(at(payload, 'pull_request', 'base', 'sha'));
    const headSha = sha40(at(payload, 'pull_request', 'head', 'sha'));
    if (typeof number !== 'number' || !Number.isSafeInteger(number) || number <= 0 || baseSha === undefined || headSha === undefined) {
      settings.errors.push('the pull request in the event payload has no number, base or head commit, so its changes can not be checked');
    } else {
      installing = !(await baseHasInstall(gh, repo, baseSha));
      const co = await loadCodeowners(gh, repo, baseSha);
      if (co.problem !== undefined) notes.push(co.problem);
      const pr = await readPrContext(gh, repo, number, { expectHeadSha: headSha, codeowners: co.rules });
      notes.push(...pr.problems);
      const sections = await readConfigSections(gh, repo, pr, settings.protectedSections, settings.protectedPaths);
      integrity = integrityFindings(pr, settings.protectedPaths, co.rules, { sectionChanges: sections, codeowners: { found: co.found, ...(co.problem === undefined ? {} : { problem: co.problem }) } });
    }
  }

  // 6. the trusted baseline, the clean-run marker and the mode
  const verify = { key: settings.fpKey, now: ctx.now };
  const loaded = await loadBaseline(gh, repo, verify);
  if (loaded.note !== undefined) notes.push(loaded.note);
  const marker = await cleanRunSeen(gh, repo, verify);
  if (marker.note !== undefined) notes.push(marker.note);
  const mode = decideMode(settings.blockFrom, settings.blockFromRecorded, ctx.now, marker.state === 'seen' ? true : marker.state === 'none' ? false : 'unknown');
  notes.push(mode.why);

  // the licence check's coverage per lockfile type
  const coverage = settings.jobList.filter((e) => e.category === 'licences').flatMap((e) => licenceCoverage(settings.licenceLockfiles).map((text) => ({ job: e.job, text })));
  notes.push(...(ctx.clientNotes ?? []));

  return {
    event, checks, baseScan: mapped.baseScan, ancestry, baseline: loaded.baseline, sameRunTools: settings.sameRunTools, installing, diff,
    rangeScans, mode: mode.mode, policy: settings.policy, notProvenNeeds: settings.notProven, skipped: settings.skipped,
    settingsErrors: settings.errors, integrity, floorNeeds: settings.floorNeeds, notes: [...new Set(notes)], coverage, cleanRun: marker.state,
  };
}

