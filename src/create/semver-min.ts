// A minimal semver range check (D1 fix rounds 1-2), with no dependency, built as an ALLOWLIST GRAMMAR: anything outside it gives `null`, and the
// caller refuses the edge. Nothing is guessed or dropped, so a range this module reads is read as npm reads it.
//   version  plain MAJOR.MINOR.PATCH, digits only (no leading zero, no prerelease, no build tag)
//   range    sets joined by " || "; the empty range means "any"
//   set      comparators joined by a single space, or one hyphen range "X.Y.Z - A.B.C"
//   compare  [op]X.Y.Z with op one of ^ ~ >= > <= < = (or none), attached to the version; or an x-range: X, X.x, X.Y.x, X.*, X.Y.*, *, x, X
//            (nothing follows a wildcard)
// No prerelease or build tag is accepted anywhere in a range, not even as an exact match: the reviewed closure has none.
type V = [number, number, number];
const N = '(0|[1-9]\\d{0,14})';
const VERSION = new RegExp(`^${N}\\.${N}\\.${N}$`);
const FULL = new RegExp(`^(\\^|~|>=|>|<=|<|=)?${N}\\.${N}\\.${N}$`);
const MAJOR_X = new RegExp(`^${N}(?:\\.[xX*])?$`);
const MINOR_X = new RegExp(`^${N}\\.${N}\\.[xX*]$`);
const HYPHEN = new RegExp(`^${N}\\.${N}\\.${N} - ${N}\\.${N}\\.${N}$`);

const cmp = (a: V, b: V): number => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
const tuple = (m: RegExpExecArray, at: number): V => [Number(m[at]), Number(m[at + 1]), Number(m[at + 2])];

/** Whether the tuple `v` satisfies one comparator; null if the comparator is outside the grammar. */
function comparator(v: V, tok: string): boolean | null {
  if (tok === '*' || tok === 'x' || tok === 'X') return true;
  let m = FULL.exec(tok);
  if (m !== null) {
    const op = m[1] ?? '';
    const t = tuple(m, 2);
    const c = cmp(v, t);
    switch (op) {
      case '': case '=': return c === 0;
      case '>': return c > 0;
      case '>=': return c >= 0;
      case '<': return c < 0;
      case '<=': return c <= 0;
      case '~': return c >= 0 && cmp(v, [t[0], t[1] + 1, 0]) < 0;
      default: {   // ^
        const up: V = t[0] > 0 ? [t[0] + 1, 0, 0] : t[1] > 0 ? [0, t[1] + 1, 0] : [0, 0, t[2] + 1];
        return c >= 0 && cmp(v, up) < 0;
      }
    }
  }
  m = MAJOR_X.exec(tok);
  if (m !== null) return v[0] === Number(m[1]);
  m = MINOR_X.exec(tok);
  if (m !== null) return v[0] === Number(m[1]) && v[1] === Number(m[2]);
  return null;
}

/** Whether `version` satisfies `range`; null when either is outside the grammar. */
export function satisfies(version: string, range: string): boolean | null {
  if (typeof version !== 'string' || typeof range !== 'string' || range.length > 200) return null;
  const vm = VERSION.exec(version);
  if (vm === null) return null;
  const v = tuple(vm, 1);
  if (range === '') return true;
  let any = false;
  for (const set of range.split(' || ')) {
    const h = HYPHEN.exec(set);
    if (h !== null) {
      if (cmp(v, tuple(h, 1)) >= 0 && cmp(v, tuple(h, 4)) <= 0) any = true;
      continue;
    }
    let ok = true;
    for (const tok of set.split(' ')) {
      const r = comparator(v, tok);
      if (r === null) return null;
      if (!r) ok = false;
    }
    if (ok) any = true;
  }
  return any;
}
