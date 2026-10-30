// Plan C Task C3 fix round 1 (review-C3 m2): the ONE definition of a calendar date `YYYY-MM-DD`. The engine (the renderer row and the
// referee check of `block-from-recorded`) and the gate (mode.ts) both use it, so a literal the referee accepts is never silently
// treated as absent by the gate. A leaf: imports nothing.

/** A real calendar date `YYYY-MM-DD` (year 0001 to 9999), as the same text; otherwise undefined. */
export function validDate(text: string | undefined): string | undefined {
  if (typeof text !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(text)) return undefined;
  const [y, m, d] = text.split('-').map(Number) as [number, number, number];
  if (y < 1) return undefined;
  const t = new Date(Date.UTC(y, m - 1, d));
  t.setUTCFullYear(y);   // years 0 to 99 would otherwise map to 1900 to 1999
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d ? text : undefined;
}
