// Coverage mapper (see ../coverage.ts for the rules): small helpers shared by the readers (lists, `where` text, directories).
import { posix } from 'node:path';
import { regexSafe } from '../../read/limits.js';
import { asObj } from '../../read/manifest.js';
import { safeText } from '../../util/safe-text.js';
import { MAX_DIR, MAX_WHERE } from './bounds.js';
import type { Obj } from './types.js';

// ---------- small helpers ----------

export const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
export const strs = (v: unknown): string[] => (typeof v === 'string' ? [v] : list(v).filter((x): x is string => typeof x === 'string'));

export function cut(s: string): string {
  const chars = Array.from(s);
  return chars.length <= MAX_WHERE ? s : `${chars.slice(0, MAX_WHERE - 1).join('')}…`;
}

const REF_RE = /^[A-Za-z0-9_./-]+(?:@[A-Za-z0-9_./-]+)?$/;
/** A repo `uses:` value kept raw for `by`, or undefined when it doesn't pass REF_RE. */
export const validRef = (u: string): string | undefined => (u.length <= 200 && REF_RE.test(u) && safeText(u) === u ? u : undefined);

/** True for continue-on-error values that let the step or job fail without failing the run (true, or an expression). */
export function allowedToFail(v: unknown): boolean {
  if (v === true) return true;
  if (typeof v !== 'string') return false;
  const t = v.trim();
  return t !== '' && t !== 'false';
}

/** `base` joined with `rel` inside the repo ('.' = root), or null when it can't be known or leaves the repo. */
export function resolveDir(base: string | null, rel: string): string | null {
  if (base === null || base.length + rel.length > MAX_DIR) return null;
  const joined = posix.normalize(posix.join(base, rel)).replace(/\/+$/, '');
  if (joined === '' || joined === '.') return '.';
  if (joined === '..' || joined.startsWith('../') || posix.isAbsolute(joined)) return null;
  return joined;
}

const WORKSPACE_PREFIX = /^(?:\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?)(?:\/|$)/;
/** A working-directory value: undefined = not set, null = can't be resolved (an expression, a variable, absolute). */
export function workingDir(v: unknown): string | null | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'string' || !regexSafe(v)) return null;
  const s = v.trim().replace(WORKSPACE_PREFIX, '');
  if (/[$`~\\]/.test(s) || s.startsWith('/')) return null;
  return resolveDir('.', s === '' ? '.' : s);
}

export const defaultsDir = (doc: Obj) => workingDir(asObj(asObj(doc.defaults).run)['working-directory']);
export const firstSet = (...dirs: (string | null | undefined)[]): string | null => {
  for (const d of dirs) if (d !== undefined) return d;
  return '.';
};
