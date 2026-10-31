// A minimal semver range check (D1 fix round 1), with no dependency: enough to hold a lock edge to its range. It reads exact versions, `^`, `~`,
// comparators (`>= > <= < =`), partial versions and `x`/`*`, hyphen ranges and `||`. A prerelease version satisfies only a range that names that
// exact version. A range it can not read gives `null` (the caller refuses: fail closed).
type V = [number, number, number];
const NUM = /^(?:0|[1-9]\d{0,14})$/;
const WILD = (s: string | undefined): boolean => s === undefined || s === '' || s === 'x' || s === 'X' || s === '*';

/** `1.2.3` to a tuple (a build suffix ignored); null if it is not a plain version, `pre` true for a prerelease. */
function parseVersion(v: string): { t: V; pre: boolean } | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.exec(v);
  if (m === null || ![m[1], m[2], m[3]].every((x) => NUM.test(x as string))) return null;
  return { t: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] !== undefined };
}
const cmp = (a: V, b: V): number => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];

/** A possibly partial version (`1`, `1.2`, `1.x`) as its parts, undefined for a wildcard part; null if unreadable. */
function parsePartial(s: string): (number | undefined)[] | null {
  const m = /^v?([0-9xX*]+)(?:\.([0-9xX*]+))?(?:\.([0-9xX*]+))?(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.exec(s);
  if (m === null) return null;
  const out: (number | undefined)[] = [];
  for (const p of [m[1], m[2], m[3]]) {
    if (WILD(p)) out.push(undefined);
    else if (NUM.test(p as string)) out.push(Number(p));
    else return null;
  }
  return out;
}
const fill = (p: (number | undefined)[]): V => [p[0] ?? 0, p[1] ?? 0, p[2] ?? 0];

/** A comparator as [min inclusive, max exclusive] bounds (either may be absent). */
function bounds(op: string, raw: string): { lo?: V; loIncl?: boolean; hi?: V; hiIncl?: boolean } | null {
  const p = parsePartial(raw);
  if (p === null) return null;
  const [a, b, c] = p;
  if (a === undefined) return op === '' || op === '=' || op === '>=' || op === '<=' ? {} : null;
  const lowT = fill(p);
  const upTilde: V = b === undefined ? [a + 1, 0, 0] : [a, b + 1, 0];
  if (op === '^') {
    if (b === undefined) return { lo: lowT, loIncl: true, hi: [a + 1, 0, 0] };
    const up: V = a > 0 ? [a + 1, 0, 0] : c === undefined ? [0, b + 1, 0] : b > 0 ? [0, b + 1, 0] : [0, 0, c + 1];
    return { lo: lowT, loIncl: true, hi: up };
  }
  if (op === '~') return { lo: lowT, loIncl: true, hi: upTilde };
  if (op === '' || op === '=') return c !== undefined ? { lo: lowT, loIncl: true, hi: lowT, hiIncl: true } : { lo: lowT, loIncl: true, hi: upTilde };
  if (op === '>=') return { lo: lowT, loIncl: true };
  if (op === '>') return c !== undefined ? { lo: lowT, loIncl: false } : { lo: upTilde, loIncl: true };
  if (op === '<') return { hi: lowT, hiIncl: false };
  if (op === '<=') return c !== undefined ? { hi: lowT, hiIncl: true } : { hi: upTilde, hiIncl: false };
  return null;
}

/** Whether `version` satisfies `range`; null when the range can not be read. */
export function satisfies(version: string, range: string): boolean | null {
  const v = parseVersion(version);
  if (v === null || typeof range !== 'string' || range.length > 200) return null;
  let readable = true;
  let any = false;
  for (const alt of range.split('||')) {
    let text = alt.trim().replace(/([<>=~^])\s+/g, '$1');
    const hy = /^(\S+)\s+-\s+(\S+)$/.exec(text);
    if (hy !== null) text = `>=${hy[1]} <=${hy[2]}`;
    let ok = true;
    for (const tok of text === '' ? ['*'] : text.split(/\s+/)) {
      const m = /^(\^|~>?|>=|<=|>|<|=)?(.*)$/.exec(tok);
      const b = bounds(m?.[1] === '~>' ? '~' : (m?.[1] ?? ''), m?.[2] ?? '');
      if (b === null) { readable = false; ok = false; break; }
      if (v.pre && !(range.includes(version))) ok = false;
      if (b.lo !== undefined && (b.loIncl ? cmp(v.t, b.lo) < 0 : cmp(v.t, b.lo) <= 0)) ok = false;
      if (b.hi !== undefined && (b.hiIncl ? cmp(v.t, b.hi) > 0 : cmp(v.t, b.hi) >= 0)) ok = false;
    }
    if (ok) any = true;
  }
  return readable ? any : null;
}
