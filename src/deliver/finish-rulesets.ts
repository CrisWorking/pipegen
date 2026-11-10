// PL-E1: split out of finish.ts (a pure move, by step); see finish.ts for the whole story.
import type { ApiRequest } from '../layers/locks.js';
import { isoAt, type RepoRef } from './git-data.js';
import { holdsWanted, isObj } from './settings-api.js';
import { show, StepError, type Ctx, atOf, apiCmd } from './finish-base.js';

// ---------- rulesets ----------

export type Target = { kind: 'repo'; repo: RepoRef } | { kind: 'org'; org: string };
export const tParams = (t: Target): Record<string, string> => (t.kind === 'repo' ? { owner: t.repo.owner, repo: t.repo.repo } : { org: t.org });
export const tRoute = (t: Target, one: boolean): string => (t.kind === 'repo' ? '/repos/{owner}/{repo}/rulesets' : '/orgs/{org}/rulesets') + (one ? '/{ruleset_id}' : '');

export async function listRulesets(x: Ctx, t: Target): Promise<{ id: number; name: string }[]> {
  const d = (await x.api.read(`GET ${tRoute(t, false)}`, { ...tParams(t), per_page: 100, ...(t.kind === 'repo' ? { includes_parents: false } : {}) })).data;
  if (!Array.isArray(d)) throw new StepError('GitHub\'s list of rulesets could not be read.');
  return d.filter(isObj).filter((r) => Number.isSafeInteger(r.id) && typeof r.name === 'string').map((r) => ({ id: r.id as number, name: r.name as string }));
}
export const getRuleset = async (x: Ctx, t: Target, id: number): Promise<Record<string, unknown> | null> => {
  const d = await x.api.readOr404(`GET ${tRoute(t, true)}`, { ...tParams(t), ruleset_id: id });
  return isObj(d) ? d : null;
};
export interface Upserted { id: number; createdAt: string | null; wrote: 'created' | 'updated' | 'none' }
/** The ruleset `name` as `want`: an existing one (by name) kept when it already holds it, else updated by id; a new one created. Read back. */
export async function upsertRuleset(x: Ctx, t: Target, name: string, want: Record<string, unknown>, existing: readonly { id: number; name: string }[]): Promise<Upserted> {
  const same = existing.filter((r) => r.name === name);
  if (same.length > 1) throw new StepError(`There is more than one ruleset named ${show(name, 100)}; remove the extra ones, then run finish again.`);
  let id: number;
  let wrote: Upserted['wrote'];
  if (same[0] !== undefined) {
    id = same[0].id;
    const cur = await getRuleset(x, t, id);
    if (cur !== null && holdsWanted(want, cur)) wrote = 'none';
    else { await x.api.write(`PUT ${tRoute(t, true)}`, { ...tParams(t), ruleset_id: id, ...want }); wrote = 'updated'; }
  } else {
    const d = await x.api.write(`POST ${tRoute(t, false)}`, { ...tParams(t), ...want });
    if (!isObj(d) || !Number.isSafeInteger(d.id) || (d.id as number) <= 0) throw new StepError(`GitHub's answer to the new ruleset ${show(name, 100)} could not be read.`);
    id = d.id as number;
    wrote = 'created';
  }
  const back = await getRuleset(x, t, id);
  if (back === null || !holdsWanted(want, back)) throw new StepError(`The ruleset ${show(name, 100)} doesn't read back as pipegen set it.`);
  return { id, createdAt: isoAt(back.created_at) ? back.created_at : null, wrote };
}
/**
 * How a ruleset finish wrote is recorded: an earlier entry for it kept (captured once); one pipegen made now recorded with GitHub's created_at,
 * or `unconfirmed` when the read-back had none (m6); one already holding pipegen's rules recorded only with its created_at (ruling 8); one
 * pipegen had to update, never (uninstall leaves it). undefined: not recorded (a note says why).
 */
export function recordedRuleset(x: Ctx, r: Upserted, prior: { githubCreatedAt?: string; unconfirmed?: true } | undefined, named: string, already: string): { githubCreatedAt: string } | { unconfirmed: true } | undefined {
  if (prior !== undefined) return prior.githubCreatedAt !== undefined ? { githubCreatedAt: prior.githubCreatedAt } : { unconfirmed: true };
  if (r.wrote === 'created') {
    if (r.createdAt === null) x.notes.push(`pipegen made ${named}, but GitHub didn't say when, so the install record lists it as unconfirmed (uninstall asks before it removes it).`);
    return atOf(r.createdAt);
  }
  if (r.wrote === 'none' && r.createdAt !== null) return { githubCreatedAt: r.createdAt };
  x.notes.push(`${already} now holds pipegen's rules, but pipegen can't show it made it, so it is not recorded (uninstall leaves it).`);
  return undefined;
}
export async function printRuleset(x: Ctx, t: Target, name: string, req: ApiRequest, existing: readonly { id: number; name: string }[]): Promise<void> {
  const ex = existing.find((r) => r.name === name);
  if (ex === undefined) { x.commands.push(apiCmd(req.method, req.route, req.params, req.body)); return; }
  const cur = await getRuleset(x, t, ex.id);
  if (cur !== null && holdsWanted(req.body, cur)) { x.commands.push(`# ruleset ${name} is already as pipegen sets it`); return; }
  x.commands.push(apiCmd('PUT', tRoute(t, true), { ...tParams(t), ruleset_id: ex.id }, req.body));
}
