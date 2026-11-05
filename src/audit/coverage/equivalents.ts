// Coverage mapper (see ../coverage.ts for the rules): credit what the repo already has that does the job of a check by
// other means (DECISIONS #122). Called once from mapCoverage, after every adjuster, so each credit reads the rows'
// final status. A false "covered" is the worst error pipegen can make (U23): every credit lists all the evidence it
// needs, and a row missing any piece keeps the status it has.
//
// Each rule here states the property it checks, not a repo layout:
// - push-default: a push-layer row is partial only because its workflow has no every-push trigger, the same tool run
//   (same id, same job) covers the pull-request row, and the workflow also runs on every push to the default branch.
//   Pushes to other branches without a pull request are still not checked (the report says so).
// - hooks-ci: the pre-commit config is readable, non-empty and every hook in it is recognised, and every tool the
//   hooks run also runs in CI, unconditionally and in the same folder, on this row's own trigger.
// - signing: a release (no image) signed in CI by cosign. ciCoverage already covers the row from the `cosign sign` and
//   `cosign sign-blob` signatures; this only says so in the report.
// - deploy-verify (J3b, ruling B3): every workflow that deploys passes deployGateOf (./deploy-gate.ts: a guarded
//   workflow_run deploy with a commit check, or a deploy job inside the CI workflow that needs every CI job and runs only
//   on a push to the default branch), and no workflow was unreadable. Worked out once by deployGates (it reads files),
//   passed in as `opts.deployGates`; every deploy-verify row is then covered, or none.
import type { RepoProfile } from '../../types.js';
import { safeText } from '../../util/safe-text.js';
import type { Coverage } from '../coverage.js';
import { DEPLOY_VERIFY_WHY, type Decide } from './decide.js';
import type { DeployGates } from './deploy-gate.js';
import type { Hooks } from './hooks.js';
import { UNKNOWN_PREFIX } from './settings.js';
import type { Ctx, Found, Hit } from './types.js';

export interface CreditOptions {
  /** DoD run 2026-10-29: the default branch is a placeholder (rate limit); see BranchGuess. Only `narrowest` may credit. */
  branchGuess?: 'widest' | 'narrowest';
  /** J3b: deployGates' answer for this repo (null or absent: no deploy-verify credit). */
  deployGates?: DeployGates | null;
}

export const PUSH_CREDIT_WARNING = "Pushes to branches without a pull request aren't checked.";
const WORKFLOW_PATH = /^(\.github\/workflows\/[A-Za-z0-9._-]{1,200}\.ya?ml) \(job /;
const MAX_TOOLS_SHOWN = 10;

const isReal = (c: string) => !c.startsWith(UNKNOWN_PREFIX);

/** Credit 1. Undefined when any piece of the evidence is missing. */
function pushDefaultCredit(r: Coverage, rows: readonly Coverage[], p: RepoProfile, opts: CreditOptions): Coverage | undefined {
  // Under a guess the default branch is a placeholder. The narrowest bound never credits; the widest may, so that the
  // two answers differ and the audit says unknown for the row (model.ts bothWorlds), never a guessed covered.
  if (opts.branchGuess === 'narrowest') return undefined;
  const branch = p.defaultBranch;
  if (branch === '' || r.status !== 'partial' || r.trigger?.kind !== 'not-every-push' || r.why !== r.trigger.why) return undefined;
  if (r.need.layer !== 'push' || r.by === undefined || r.where === undefined || r.credit !== undefined) return undefined;
  const merge = rows.find((m) => m.need.layer === 'merge' && m.need.category === r.need.category && m.need.service === r.need.service);
  if (merge === undefined || merge.status !== 'covered' || merge.credit !== undefined || merge.lastRun !== undefined) return undefined;
  if (merge.by !== r.by || merge.where !== r.where) return undefined;
  const b = safeText(branch, 100);
  const subject = r.trigger.why.replace(/ runs, but not on every push\.$/, '');
  if (subject === r.trigger.why) return undefined;
  const { trigger: _t, ...rest } = r;
  void _t;
  return {
    ...rest, status: 'covered', why: `${subject} runs on every pull request into ${b} and on every push to ${b}.`,
    credit: `runs on every pull request into ${b} and every push to ${b}`, creditKind: 'push-default',
  };
}

/**
 * The CI run that runs hook tool `f` on `layer`: the same tool, no condition, nothing unplaced, and the same folder
 * (a run given a path was already moved to that folder by scopeToPaths, so a run narrowed to `src` is not the hook's `.`).
 */
function ciRunOf(f: Found, layer: 'push' | 'merge', hits: readonly Hit[]): Hit | undefined {
  return hits.find((h) => !h.opaque && h.reason === null && h.by === f.by && h.fit[layer] && h.unplaced === undefined
    && h.dir !== null && h.dir === f.dir && h.categories.some((c) => isReal(c) && f.categories.includes(c)));
}

/** Credit 2. Undefined when any piece of the evidence is missing. */
function hooksCiCredit(r: Coverage, d: Decide, hooks: Hooks): Coverage | undefined {
  if (r.need.category !== 'hooks-ci' || r.status === 'covered' || (r.need.layer !== 'push' && r.need.layer !== 'merge')) return undefined;
  // Read for the pre-commit framework only: husky and lefthook run free shell, where one unread command can't be seen.
  if (hooks.manager !== 'pre-commit' || !hooks.readable || hooks.unrecognised.length > 0) return undefined;
  const tools = hooks.found.filter((f) => f.categories.some(isReal));
  if (tools.length === 0 || hooks.found.some((f) => f.categories.some((c) => !isReal(c)))) return undefined;
  const runs: Hit[] = [];
  for (const f of tools) {
    const run = ciRunOf(f, r.need.layer, d.ci.hits);
    if (run === undefined) return undefined;
    runs.push(run);
  }
  // One workflow holds them all, so a failing last run of it (applyLastRuns) is seen for every tool
  const files = new Set(runs.map((h) => WORKFLOW_PATH.exec(h.where)?.[1]));
  if (files.size !== 1 || files.has(undefined)) return undefined;
  const names = [...new Set(tools.map((f) => f.by))].sort();
  const shown = names.slice(0, MAX_TOOLS_SHOWN).join(', ') + (names.length > MAX_TOOLS_SHOWN ? ` and ${names.length - MAX_TOOLS_SHOWN} more` : '');
  const when = r.need.layer === 'push' ? 'on every push' : 'on every pull request';
  return {
    need: r.need, status: 'covered', by: 'pre-commit', where: (runs[0] as Hit).where,
    why: `CI runs the same tools as your hooks (${shown}) ${when}.`, credit: `CI runs the same tools as your hooks: ${shown}`, creditKind: 'hooks-ci',
  };
}

/** Credit 4. The row is covered already (cosign sign / sign-blob); this adds the report line. */
function signingCredit(r: Coverage, d: Decide): Coverage | undefined {
  if (r.need.category !== 'signing' || r.status !== 'covered' || r.by !== 'cosign' || r.credit !== undefined || !d.noImage(r.need)) return undefined;
  return { ...r, credit: 'CI signs the release artifacts with cosign (sign-blob)', creditKind: 'signing' };
}

/** Credit 3 (J3b). The row is pipegen's own "missing" deploy check; every deploying workflow passed deployGateOf. */
function deployGateCredit(r: Coverage, p: RepoProfile, gates: DeployGates | null | undefined): Coverage | undefined {
  if (gates === null || gates === undefined || gates.paths.length === 0 || p.defaultBranch === '') return undefined;
  if (r.need.category !== 'deploy-verify' || r.status !== 'missing' || r.why !== DEPLOY_VERIFY_WHY || r.credit !== undefined) return undefined;
  const b = safeText(p.defaultBranch, 100);
  const shown = gates.paths.slice(0, 3).join(', ') + (gates.paths.length > 3 ? ` and ${gates.paths.length - 3} more` : '');
  const ev = gates.evidence.slice(0, 3).join('; ') + (gates.evidence.length > 3 ? `; and ${gates.evidence.length - 3} more` : '');
  return {
    need: r.need, status: 'covered', where: shown,
    why: `Every deploy runs only after CI passed on ${b}, for the commit CI tested, and never for a fork's run: ${ev}.`,
    credit: `deploys run only after CI passed on ${b}, for the commit CI tested, never for a fork's run`, creditKind: 'deploy-gate',
  };
}

/**
 * One pass over the final rows. `rows` is returned in order, a credited row with `status: 'covered'`, `credit` and
 * `creditKind`; the internal `trigger` mark is removed from every row.
 */
export function creditEquivalents(rows: Coverage[], d: Decide, _ctx: Ctx, p: RepoProfile, hooks: Hooks, opts: CreditOptions = {}): Coverage[] {
  return rows.map((r) => {
    const credited = pushDefaultCredit(r, rows, p, opts) ?? hooksCiCredit(r, d, hooks) ?? signingCredit(r, d) ?? deployGateCredit(r, p, opts.deployGates)
      ?? unrecognisedHooksWhy(r, hooks);
    const { trigger: _t, ...clean } = credited;
    void _t;
    return clean;
  });
}

/**
 * Hooks whose rows got a hooks-ci why of "missing": names the hooks pipegen couldn't place (B4), so the report says
 * why the row is not covered. Pure text on the row; the status is unchanged.
 */
export function unrecognisedHooksWhy(r: Coverage, hooks: Hooks): Coverage {
  if (r.need.category !== 'hooks-ci' || r.status !== 'missing' || hooks.manager !== 'pre-commit' || hooks.unrecognised.length === 0) return r;
  const names = [...new Set(hooks.unrecognised)];
  return { ...r, why: `${r.why} Not counted from the hooks: pipegen can't tell what ${names.slice(0, 5).join(', ')}${names.length > 5 ? ` and ${names.length - 5} more` : ''} run.` };
}
