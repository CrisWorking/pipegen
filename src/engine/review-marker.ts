// The human-review marker shared by pipegen's two trust-root files, data/reviewed-tools.yml (reviewed.ts) and
// data/pinned-binaries.yml (linters.ts), so both apply exactly the same rules (ruling S21, final review I2):
// - until the owner reviews an entry it says `reviewedBy: PENDING` and `reviewedAt: PENDING`; once reviewed it
//   carries a printable name and a real date on or after the day the entry was pinned;
// - a release build refuses a file while any entry is PENDING. The bundled dist defines
//   process.env.PIPEGEN_RELEASE (tsup `define`), and NODE_ENV=production counts too. Tests and dev runs (src, no
//   define) load PENDING entries so the lists can be built, tested and reviewed.

export const PENDING = 'PENDING';

/** A reviewer's name: printable letters and digits, spaces, `.`, `'` and `-` only (no zero-width or control characters). */
export const REVIEWER_RE = /^[\p{L}\p{N} .'-]{2,80}$/u;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** True in a release build: the bundled dist (tsup defines PIPEGEN_RELEASE, ruling S21) or NODE_ENV=production. */
export function isReleaseBuild(): boolean {
  // written out in full so tsup's `define` replaces it in the bundle
  return process.env.PIPEGEN_RELEASE === '1' || process.env.NODE_ENV === 'production';
}

/** A YYYY-MM-DD date that exists in the calendar. */
export function isRealDate(s: string): boolean {
  if (!DATE_RE.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

/**
 * Every problem with one entry's review marker: `reviewedBy` is PENDING exactly or a printable name (checked by
 * REVIEWER_RE, plus at least two non-space characters); `reviewedAt` is PENDING exactly when `reviewedBy` is, else a
 * real date not before `pinnedDay` (the YYYY-MM-DD the pins were made: a review must cover the pins as they are).
 */
export function reviewMarkerProblems(reviewedBy: string, reviewedAt: string, pinnedDay: string | null): { message: string; field: 'reviewedBy' | 'reviewedAt' }[] {
  const out: { message: string; field: 'reviewedBy' | 'reviewedAt' }[] = [];
  if (reviewedBy !== PENDING && (reviewedBy.trim().toUpperCase() === PENDING || pendingLookAlike(reviewedBy))) out.push({ field: 'reviewedBy', message: 'reviewedBy must be PENDING exactly (upper case, no spaces) or a name' });
  else if (reviewedBy !== PENDING && !(REVIEWER_RE.test(reviewedBy) && reviewedBy.trim().length >= 2)) {
    out.push({ field: 'reviewedBy', message: 'reviewedBy must be PENDING or a printable name (letters, digits, spaces, . \' -; 2 to 80 characters)' });
  }
  if ((reviewedBy === PENDING) !== (reviewedAt === PENDING)) out.push({ field: 'reviewedAt', message: 'reviewedBy and reviewedAt must both be PENDING, or a name and a date' });
  if (reviewedAt !== PENDING) {
    if (!isRealDate(reviewedAt)) out.push({ field: 'reviewedAt', message: 'reviewedAt must be a real date (YYYY-MM-DD)' });
    else if (pinnedDay !== null && reviewedAt < pinnedDay) out.push({ field: 'reviewedAt', message: `reviewedAt is before pinnedOn (${pinnedDay}): the review must cover the pins as they are` });
  }
  return out;
}

/**
 * A name that reads as PENDING but isn't (`PENDlNG`, `PEND1NG`, `Pend ing`, `PENDING.`): NFKC-folded, lower case,
 * only letters and digits kept, and l, 1, | and ! read as i, 0 as o. Such a marker must not count as a reviewer.
 */
function pendingLookAlike(s: string): boolean {
  const folded = s.normalize('NFKC').toLowerCase().replace(/[l1|!]/g, 'i').replace(/0/g, 'o').replace(/[^a-z0-9]/g, '');
  return folded === 'pending';
}

/** "a, b and 3 more" for an error message. */
export function listPending(ids: string[]): string {
  return ids.length > 6 ? `${ids.slice(0, 6).join(', ')} and ${ids.length - 6} more` : ids.join(', ');
}
