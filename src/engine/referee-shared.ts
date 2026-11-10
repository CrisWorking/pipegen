// PL-E5: the three things pipegen's deploy layer (src/layers/deploy.ts) and src/engine/deploy-gating.ts take from the referee, in a leaf of
// their own so the referee <-> deploy layer import cycle is gone. The referee re-exports them; this file imports only render-error.ts.
import { EXPR } from './render-error.js';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);

/** The environment `pipegen-verify` runs in when the plan has environments (design §19): only default-branch deploys pass. */
export const SIGNING_ENVIRONMENT = 'pipegen-signing';

/**
 * Any status-function call (success(), always(), failure(), cancelled()): GitHub adds its implicit `success() && (…)` only when
 * an if holds none. Over-approximated on purpose (review-7a-r2): no \b, so `x-success(` matches; a name inside a string literal
 * matches too (refusing it is only stricter, and a quote stripper that lexes differently from GitHub's could hide a real call).
 * Non-ASCII is refused before this runs, so JS \s covers every whitespace GitHub's lexer skips.
 */
const STATUS_CALL_RE = /(?:success|always|failure|cancelled)\s*\(/i;

/** Parentheses never below zero and back to zero at the end, and every single-quoted string closed ('' is an escape). */
function balanced(e: string): boolean {
  let depth = 0;
  for (let i = 0; i < e.length; i++) {
    const c = e[i];
    if (c === "'") {
      let closed = false;
      for (i++; i < e.length; i++) if (e[i] === "'") { if (e[i + 1] === "'") i++; else { closed = true; break; } }
      if (!closed) return false;
    } else if (c === '(') depth++;
    else if (c === ')' && --depth < 0) return false;
  }
  return depth === 0;
}

/** Whether an expression holds `||` outside parentheses and quoted strings. */
function topLevelOr(e: string): boolean {
  let depth = 0;
  for (let i = 0; i < e.length; i++) {
    const c = e[i];
    if (c === "'") {
      for (i++; i < e.length; i++) if (e[i] === "'") { if (e[i + 1] === "'") i++; else break; }
    } else if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === '|' && e[i + 1] === '|' && depth === 0) return true;
  }
  return false;
}

/**
 * Ruling 1 (fix round 2), loosened after review-7a-r2: the `if:` of a user job pipegen gated with `needs:` may be absent, an
 * expression with no status-function call at all (GitHub runs it as `success() && (…)`, so it still respects the needs),
 * exactly `success()`, or `success() && <expr>` where <expr> holds no status call and no `||` at its top level. Anything else
 * can run the job although pipegen's job failed (`success() || …`, `!success()`, `always()`, `!cancelled()`).
 * Refused first: non-ASCII (U+0085 is whitespace to GitHub's .NET lexer but not to JS \s; U+017F folds to 'S' in .NET only),
 * more than one `${{ }}` or text outside it, whitespace included (read by GitHub as a truthy string; a value with no `${{` may be trimmed), any `{` or `}` left after the unwrap (GitHub
 * ends the expression at the first `}}`, so `${{ x }}}` is a truthy string template; expressions have no brace syntax, so braces
 * inside string literals are refused too, which is only stricter), an empty condition, and unbalanced
 * parentheses or quotes (GitHub refuses the workflow; the referee says so itself). A YAML boolean is not a string: refused.
 */
export function gatedIfAllowed(cond: unknown): boolean {
  if (cond === undefined) return true;
  if (typeof cond !== 'string' || !/^[\t\n\r\x20-\x7e]*$/.test(cond)) return false;
  let e = cond;
  if (cond.includes(EXPR)) {
    // the wrapper is judged on the untrimmed value: whitespace outside it is literal text, which GitHub reads as a (truthy) string template
    const wrapped = /^\$\{\{([\s\S]*)\}\}$/.exec(cond);
    if (wrapped === null) return false;
    e = (wrapped[1] as string).trim();
  } else e = cond.trim();
  if (e === '' || e.includes(EXPR) || /[{}]/.test(e) || !balanced(e)) return false;
  if (!STATUS_CALL_RE.test(e)) return true;
  if (/^success\(\s*\)$/i.test(e)) return true;
  const m = /^success\(\s*\)\s*&&([\s\S]+)$/i.exec(e);
  if (m === null) return false;
  const rest = m[1] as string;
  return rest.trim() !== '' && !STATUS_CALL_RE.test(rest) && !topLevelOr(rest);
}

/** The event names of an `on:` value (a name, a list of names, or a map by name); null when it is none of those. */
export function triggersOf(on: unknown): string[] | null {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.every((x) => typeof x === 'string') ? (on as string[]) : null;
  if (isObj(on)) return Object.keys(on);
  return null;
}
