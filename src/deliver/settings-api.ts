// v0.2 Plan G G11 (G10 re-review r2, G8 carries): the GitHub settings calls `finish` and `verify` make, and only those. Writes are a fixed
// list (FINISH_WRITE_ROUTES, the exact set G8's lock plan and finish produce); reads are GETs under /repos/{owner}/{repo}, the org rulesets
// and /users/{username}, never the contents API. Every call names the app, its central repo `<owner>/pipelines` or the app's own
// organisation: anything else is refused before it is sent. Requests are sent as `gh.request(\`${method} ${route}\`, { ...params, ...body })`
// (G8 carry), through the run's rate clock; a rejected token stops the run. File writes (the git data API) stay in git-data.ts, secrets
// in src/create/secrets.ts.
import type { Octokit } from '@octokit/rest';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { githubTokenRejected, isAnonymousClient } from '../github/client.js';
import { CENTRAL_REPO } from '../proof/target.js';
import { safeText } from '../util/safe-text.js';
import { DeliverError, statusOf, type RepoRef } from './git-data.js';

/** Every settings write `finish` sends (the git data API, pull requests and secrets go through their own modules). */
export const FINISH_WRITE_ROUTES: ReadonlySet<string> = new Set([
  'POST /repos/{owner}/{repo}/rulesets', 'PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}',
  'PUT /repos/{owner}/{repo}/branches/{branch}/protection',
  'PUT /repos/{owner}/{repo}/actions/permissions',
  'PUT /repos/{owner}/{repo}/actions/permissions/access',
  'PUT /repos/{owner}/{repo}/vulnerability-alerts',
  'PATCH /repos/{owner}/{repo}',
  'POST /orgs/{org}/rulesets', 'PUT /orgs/{org}/rulesets/{ruleset_id}',
  'PUT /repos/{owner}/{repo}/environments/{environment_name}',
  'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies',
  'POST /repos/{owner}/{repo}/actions/variables', 'PATCH /repos/{owner}/{repo}/actions/variables/{name}',
  'POST /repos/{owner}/{repo}/environments/{environment_name}/variables', 'PATCH /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}',
]);

/** The one request each slot of a record's `planned` may hold (anything else there is refused, never sent). */
export const PLANNED_ROUTES = {
  rulesets: 'POST /repos/{owner}/{repo}/rulesets',
  classic: 'PUT /repos/{owner}/{repo}/branches/{branch}/protection',
  centralRuleset: 'POST /repos/{owner}/{repo}/rulesets',
  orgRequiredWorkflow: 'POST /orgs/{org}/rulesets',
  shaPinning: 'PUT /repos/{owner}/{repo}/actions/permissions',
} as const;

const READ_RE = /^GET (?:\/repos\/\{owner\}\/\{repo\}(?:\/[A-Za-z0-9_{}/.-]*)?|\/orgs\/\{org\}\/rulesets(?:\/\{ruleset_id\})?|\/users\/\{username\})$/;
const NAME_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;

/** The settings calls of one app (and its central repo and organisation). */
export class SettingsApi {
  constructor(readonly gh: Octokit, readonly app: RepoRef, readonly clock: RateClock) {}

  /** The params name the app, its central repo or its organisation, and every path part is a plain name. */
  #target(route: string, params: Record<string, unknown>): void {
    const lower = (v: unknown): string => String(v).toLowerCase();
    if (route.includes('{owner}') && lower(params.owner) !== lower(this.app.owner)) throw new DeliverError(`"${safeText(route, 120)}" names another owner than ${safeText(this.app.owner, 40)}.`);
    if (route.includes('{repo}') && lower(params.repo) !== lower(this.app.repo) && lower(params.repo) !== CENTRAL_REPO) throw new DeliverError(`"${safeText(route, 120)}" names a repo other than the app and its central repo.`);
    if (route.includes('{org}') && lower(params.org) !== lower(this.app.owner)) throw new DeliverError(`"${safeText(route, 120)}" names another organisation than ${safeText(this.app.owner, 40)}.`);
    for (const m of route.matchAll(/\{([a-z_]+)\}/g)) {
      const k = m[1] as string;
      const v = params[k];
      const ok = k === 'ruleset_id' || k === 'pull_number' ? Number.isSafeInteger(v) && (v as number) > 0 : k === 'branch' ? typeof v === 'string' && /^[A-Za-z0-9._/-]{1,250}$/.test(v) && !v.includes('..') : typeof v === 'string' && NAME_RE.test(v);
      if (!ok) throw new DeliverError(`"${safeText(route, 120)}" has a path part that is not a plain name.`);
    }
  }

  async #send(route: string, params: Record<string, unknown>): Promise<{ status: number; data: unknown }> {
    try {
      const res = await withRateLimit(() => this.gh.request(route, params), this.clock);
      return { status: res.status, data: res.data };
    } catch (e) {
      if (isRateStop(e)) throw e;
      if (statusOf(e) === 401 && !isAnonymousClient(this.gh)) throw githubTokenRejected();
      throw e;
    }
  }

  /** A GET (see the header). Errors pass through: the caller decides what a 404 means. */
  async read(route: string, params: Record<string, unknown>): Promise<{ status: number; data: unknown }> {
    if (!READ_RE.test(route) || route.includes('/contents')) throw new DeliverError(`"${safeText(route, 120)}" is not a read finish makes.`);
    this.#target(route, params);
    return this.#send(route, params);
  }

  /** One of FINISH_WRITE_ROUTES; anything else is refused before it is sent. */
  async write(route: string, params: Record<string, unknown>): Promise<unknown> {
    if (!FINISH_WRITE_ROUTES.has(route)) throw new DeliverError(`"${safeText(route, 120)}" is not a write finish makes.`);
    this.#target(route, params);
    return (await this.#send(route, params)).data;
  }

  /** A GET, or null on a 404. */
  async readOr404(route: string, params: Record<string, unknown>): Promise<unknown> {
    try { return (await this.read(route, params)).data; } catch (e) {
      if (statusOf(e) === 404) return null;
      throw e;
    }
  }
}

// ---------- comparing what GitHub holds with what pipegen wants ----------

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Whether `got` (GitHub's answer) holds everything `want` says: every key of an object (GitHub adds its own: ids, urls, defaults), every
 * element of a list matched by a different element (lists of the same length, order free), and equal values.
 */
export function holdsWanted(want: unknown, got: unknown): boolean {
  if (Array.isArray(want)) {
    if (!Array.isArray(got) || got.length !== want.length) return false;
    const used = new Set<number>();
    return want.every((w) => {
      const i = got.findIndex((g, j) => !used.has(j) && holdsWanted(w, g));
      if (i < 0) return false;
      used.add(i);
      return true;
    });
  }
  if (isObj(want)) return isObj(got) && Object.keys(want).every((k) => holdsWanted(want[k], got[k]));
  return want === got;
}

/** A refusal that means GitHub doesn't offer rulesets on this repo (its plan), the one case classic protection stands in for (G8 carry). */
export function refusedAsUnavailable(e: unknown): boolean {
  const s = statusOf(e);
  if (s !== 403 && s !== 404) return false;
  const m = String((e as { response?: { data?: { message?: unknown } } })?.response?.data?.message ?? (e as Error)?.message ?? '');
  return /upgrade to github|not available|make this repository public/i.test(m);
}

const enabled = (v: unknown): boolean => isObj(v) && v.enabled === true;
const names = (v: unknown, key: 'login' | 'slug'): string[] => (Array.isArray(v) ? v.filter(isObj).map((x) => x[key]).filter((x): x is string => typeof x === 'string') : []);

/**
 * Classic branch protection as GitHub's GET gives it, in the PUT form (what uninstall sends back, Plan V §5 item 2): the status checks
 * (strict, checks with their app ids), enforce_admins, the review rules, the push restrictions (logins and slugs) and the switches.
 */
export function classicPutForm(get: unknown): Record<string, unknown> {
  const g = isObj(get) ? get : {};
  const rsc = isObj(g.required_status_checks) ? g.required_status_checks : null;
  const checks = rsc === null ? [] : Array.isArray(rsc.checks) ? rsc.checks.filter(isObj).map((c) => ({ context: String(c.context), app_id: Number.isSafeInteger(c.app_id) ? c.app_id as number : null }))
    : (Array.isArray(rsc.contexts) ? rsc.contexts : []).map((c) => ({ context: String(c), app_id: null }));
  const rpr = isObj(g.required_pull_request_reviews) ? g.required_pull_request_reviews : null;
  const out: Record<string, unknown> = {
    required_status_checks: rsc === null ? null : { strict: rsc.strict === true, checks },
    enforce_admins: enabled(g.enforce_admins),
    required_pull_request_reviews: rpr === null ? null : {
      dismiss_stale_reviews: rpr.dismiss_stale_reviews === true, require_code_owner_reviews: rpr.require_code_owner_reviews === true,
      required_approving_review_count: Number.isSafeInteger(rpr.required_approving_review_count) ? rpr.required_approving_review_count : 0,
      require_last_push_approval: rpr.require_last_push_approval === true,
      ...(isObj(rpr.dismissal_restrictions) ? { dismissal_restrictions: { users: names(rpr.dismissal_restrictions.users, 'login'), teams: names(rpr.dismissal_restrictions.teams, 'slug') } } : {}),
    },
    restrictions: isObj(g.restrictions) ? { users: names(g.restrictions.users, 'login'), teams: names(g.restrictions.teams, 'slug'), apps: names(g.restrictions.apps, 'slug') } : null,
    allow_force_pushes: enabled(g.allow_force_pushes), allow_deletions: enabled(g.allow_deletions),
  };
  for (const k of ['required_linear_history', 'required_conversation_resolution', 'block_creations', 'lock_branch', 'allow_fork_syncing'] as const) if (isObj(g[k])) out[k] = enabled(g[k]);
  return out;
}
