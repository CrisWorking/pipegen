// Amounts in pipegen's own wording, shared by the audit report, the consent screen and the audit's AI step (Plan U
// final review M8: one copy each, so the screens can't drift apart). A value that isn't a finite number reads as 0.

const finite = (n: number) => (Number.isFinite(n) ? n : 0);

/** A whole number with thousands separators: 1,234. */
export const num = (n: number): string => finite(n).toLocaleString('en-US');

/** US dollars with cents: $1.50. */
export const usd = (n: number): string => `$${finite(n).toFixed(2)}`;

/** "1 file", "2 files", "1,000 files". */
export const plural = (n: number, one: string, many: string): string => `${num(n)} ${n === 1 ? one : many}`;

/** A byte count as "about N KB" (at least 1 KB) or "about N.N MB". */
export const size = (bytes: number): string => {
  const b = finite(bytes);
  return b >= 1024 * 1024 ? `about ${(b / (1024 * 1024)).toFixed(1)} MB` : `about ${Math.max(1, Math.round(b / 1024))} KB`;
};
