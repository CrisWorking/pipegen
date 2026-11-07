// Coverage mapper (see ../coverage.ts for the rules): workflow triggers (ruling S6): `on:`, branch and path filters, globs.
import { regexSafe } from '../../read/limits.js';
import { asObj } from '../../read/manifest.js';
import { TRIGGER_RE } from '../../read/workflows.js';
import { MAX_FILTER_PATTERNS, MAX_GLOB } from './bounds.js';
import { strs } from './helpers.js';
import type { Fit, Obj } from './types.js';

// ---------- triggers (ruling S6) ----------

type Tok = { kind: 'star' | 'dstar' } | { kind: 'char'; test: (c: string) => boolean; q: '' | '?' | '+' };

/** GitHub filter glob → tokens: * (not /), ** (anything), [a-z0-9] classes, ? and + after a character, \ escapes. */
function globTokens(pattern: string): Tok[] | null {
  const toks: Tok[] = [];
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i] as string;
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        toks.push({ kind: 'dstar' });
        i++;
      } else toks.push({ kind: 'star' });
    } else if ((c === '?' || c === '+') && toks.length > 0 && toks[toks.length - 1]?.kind === 'char') {
      const last = toks[toks.length - 1] as Extract<Tok, { kind: 'char' }>;
      if (last.q !== '') return null;
      last.q = c;
    } else if (c === '[') {
      const close = pattern.indexOf(']', i + 1);
      if (close < 0) return null;
      const body = pattern.slice(i + 1, close);
      const ranges: [string, string][] = [];
      for (let k = 0; k < body.length; k++) {
        if (body[k + 1] === '-' && k + 2 < body.length) {
          ranges.push([body[k] as string, body[k + 2] as string]);
          k += 2;
        } else ranges.push([body[k] as string, body[k] as string]);
      }
      toks.push({ kind: 'char', test: (x) => ranges.some(([a, b]) => x >= a && x <= b), q: '' });
      i = close;
    } else {
      const lit = c === '\\' && i + 1 < pattern.length ? (pattern[++i] as string) : c;
      toks.push({ kind: 'char', test: (x) => x === lit, q: '' });
    }
  }
  return toks;
}

/** GitHub branch-filter glob match, simulated over the tokens (O(pattern × name), no backtracking regex). */
function globMatch(pattern: string, name: string): boolean {
  if (pattern.length > MAX_GLOB || name.length > MAX_GLOB) return false;
  return compileGlob(pattern)(name);
}

/** A glob tokenised once, as a matcher (a pattern that can't be read matches nothing). Names over MAX_GLOB never match. */
export function compileGlob(pattern: string): (name: string) => boolean {
  const toks = globTokens(pattern);
  if (toks === null) return () => false;
  return (name) => (name.length > MAX_GLOB ? false : simulateGlob(toks, name));
}

function simulateGlob(toks: Tok[], name: string): boolean {
  const close = (set: Set<number>) => {
    for (const i of set) {
      const t = toks[i];
      if (t && (t.kind !== 'char' || t.q === '?')) set.add(i + 1); // Set iteration visits added items too
    }
    return set;
  };
  let cur = close(new Set([0]));
  for (const ch of name) {
    const next = new Set<number>();
    for (const i of cur) {
      const t = toks[i];
      if (!t) continue;
      if (t.kind === 'dstar' || (t.kind === 'star' && ch !== '/')) next.add(i);
      else if (t.kind === 'char' && t.test(ch)) {
        next.add(i + 1);
        if (t.q === '+') next.add(i);
      }
    }
    cur = close(next);
    if (cur.size === 0) return false;
  }
  return cur.has(toks.length);
}

/** `branches` semantics: patterns in order, a later match wins, `!` excludes. */
function branchesInclude(patterns: string[], name: string): boolean {
  let included = false;
  for (const p of patterns.slice(0, MAX_FILTER_PATTERNS)) {
    const negated = p.startsWith('!');
    if (globMatch(negated ? p.slice(1) : p, name)) included = !negated;
  }
  return included;
}

const isSet = (cfg: Obj, key: string) => key in cfg && cfg[key] !== null;

/** Whether a push or pull_request filter lets `name` through (`branches` and `branches-ignore` together are invalid). */
export function branchFilter(cfg: Obj): (name: string) => boolean {
  const hasB = isSet(cfg, 'branches');
  const hasBi = isSet(cfg, 'branches-ignore');
  if (hasB && hasBi) return () => false;
  if (hasB) return (n) => branchesInclude(strs(cfg.branches), n);
  if (hasBi) return (n) => !strs(cfg['branches-ignore']).slice(0, MAX_FILTER_PATTERNS).some((p) => globMatch(p, n));
  return () => true;
}

/** Event names → their config, from the three YAML forms of `on:` (string, list, map). */
export function parseOn(on: unknown): Map<string, Obj> {
  const events = new Map<string, Obj>();
  const add = (name: string, cfg: unknown) => {
    if (regexSafe(name) && TRIGGER_RE.test(name)) events.set(name, asObj(cfg));
  };
  if (typeof on === 'string') {
    add(on, null);
  } else if (Array.isArray(on)) {
    for (const n of on.slice(0, MAX_FILTER_PATTERNS)) if (typeof n === 'string') add(n, null);
  } else {
    for (const [n, cfg] of Object.entries(asObj(on))) add(n, cfg);
  }
  return events;
}

/** Branch names a developer's push would use; a push trigger must let both through to count for the push layer. */
const FEATURE_BRANCHES = ['pipegen-feature', 'feature/pipegen-feature'];
/** A `paths` or `paths-ignore` filter: the event doesn't run on every change, so it isn't the right trigger (review I2). */
const pathFiltered = (cfg: Obj) => isSet(cfg, 'paths') || isSet(cfg, 'paths-ignore');

const MONTH_DAYS = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
/**
 * Fix round 1 (review SC2): whether some `schedule:` cron of `on` can fire. A cron whose day of the month is a list of
 * plain numbers that no listed month has (`0 0 31 2 *`, day-of-week `*`) never fires; anything pipegen doesn't read
 * this way is taken to fire. Bounded: at most MAX_FILTER_PATTERNS crons, fields of up to 64 characters.
 */
export function scheduleFires(on: unknown): boolean {
  const crons = asObj(on).schedule;
  if (!Array.isArray(crons)) return true;
  if (crons.length === 0) return false;
  return crons.slice(0, MAX_FILTER_PATTERNS).some((e) => {
    const cron = asObj(e).cron;
    if (typeof cron !== 'string' || cron.length > 256) return true;
    const f = cron.trim().split(/\s+/);
    if (f.length !== 5 || f[4] !== '*') return true;
    const days = (f[2] as string).split(',');
    const months = (f[3] as string).split(',');
    if (![...days, ...months].every((x) => x.length <= 64)) return true;
    if (!days.every((d) => /^[0-9]{1,2}$/.test(d))) return true;
    const monthNums = months.map((m) => (/^[0-9]{1,2}$/.test(m) ? Number(m) : MONTHS.indexOf(m.toLowerCase()) + 1));
    if (!monthNums.every((m) => m >= 1 && m <= 12)) return true;
    return days.some((d) => monthNums.some((m) => Number(d) >= 1 && Number(d) <= (MONTH_DAYS[m - 1] as number)));
  });
}

/**
 * DoD run 2026-10-29: the default branch when GitHub couldn't be read (rate limit). `widest`: every branch filter that
 * can let some branch through lets the default branch through; `narrowest`: only a trigger without a branch filter
 * does. The real answer lies between the two, so a row both give alike doesn't depend on the default branch.
 */
export interface BranchGuess { guess: 'widest' | 'narrowest' }

/** Whether `cfg`'s branch filter lets the default branch through (the real name, or a BranchGuess bound). */
function takesDefault(cfg: Obj, defaultBranch: string | BranchGuess, tagOnly = false): boolean {
  if (tagOnly) return false;
  if (typeof defaultBranch === 'string') return branchFilter(cfg)(defaultBranch);
  const hasB = isSet(cfg, 'branches');
  const hasBi = isSet(cfg, 'branches-ignore');
  if (hasB && hasBi) return false;
  if (!hasB && !hasBi) return true;
  return defaultBranch.guess === 'widest';
}

export function fitOf(events: Map<string, Obj>, defaultBranch: string | BranchGuess, deploys: boolean, scheduleLive = true): Fit {
  let everyPush = false;
  let pushDefault = false;
  let pushTags = false;
  const push = events.get('push');
  if (push && !pathFiltered(push)) {
    const branchesSet = isSet(push, 'branches') || isSet(push, 'branches-ignore');
    pushTags = isSet(push, 'tags') || isSet(push, 'tags-ignore');
    // A push trigger with only a tag filter never runs for branch pushes.
    const includes = !branchesSet && pushTags ? () => false : branchFilter(push);
    everyPush = FEATURE_BRANCHES.every(includes);
    pushDefault = takesDefault(push, defaultBranch, !branchesSet && pushTags);
  }
  const pr = events.get('pull_request');
  const types = pr ? strs(pr.types) : [];
  const merge = pr !== undefined && !pathFiltered(pr) && takesDefault(pr, defaultBranch) && (types.length === 0 || types.includes('synchronize'));
  // Plan P Task 3: a scheduled check runs on `schedule`, or on every push to the default branch (no paths filter)
  return { pushDefault, push: everyPush, merge, deploy: deploys || pushDefault || pushTags || events.has('release'), scheduled: (events.has('schedule') && scheduleLive) || pushDefault };
}
