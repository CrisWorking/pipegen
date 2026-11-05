// The one rule for a planted secret's value (v0.2 Plan F ruling S15, fix-round rulings F5-R1 and F5-R2). Plan E's C1b placements
// (snapshot.ts plantedSecretPlacements, 32 characters) and Plan F's planted secret (src/debate/planted.ts, 40 characters) both
// draw from here, so the two can't drift. A leaf: it imports nothing of pipegen's.
//
// The value must be caught by the reviewed secrets scanners' generic rule (gitleaks' `generic-api-key`, and betterleaks' copy of
// it), which drops a value holding one of its stopwords. A random base62 value holds a dictionary word now and then: measured on
// the pinned gitleaks 8.30.1 and betterleaks 1.9.0, about 1 in 100 of the old 32-character C1b values was dropped (22 and 34 of
// 3000), so a proof with ten placements failed at random. So:
//   - base62 by rejection sampling (a byte at or above 248 = 4 × 62 is dropped, so every character is equally likely);
//   - after two letters the next character is a digit (drawn the same way, below 250 = 25 × 10): no run of 3 letters, so no
//     stopword of 3 or more letters can appear;
//   - a digit, an upper and a lower letter; Shannon entropy at least 4;
//   - none of the stopwords that rule leaves reachable (REACHABLE_STOPWORDS: md5 in any case, six zeros; measured on both
//     pinned scanners against every stopword with no 3-letter run).
// Every rule is met by drawing again, never by editing the value. No provider prefix can form (no `_` or `-`, no 3 letters in a
// row). A source that gives no bytes, or nothing that passes within 64 KiB, throws PlantedError: never a weak value.

/** A planted file or value pipegen refuses to make (the message holds no repo text). */
export class PlantedError extends Error {}

/**
 * The scanners' stopwords that a value with no 3-letter run can still hold. Re-measure when a pinned secrets scanner changes
 * (see the F5 report's probe).
 */
export const REACHABLE_STOPWORDS = /md5|000000/i;

const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const DIGITS = '0123456789';
/** Largest multiple of 62 (and of 10) under 256: a byte at or above it is dropped, so every character is equally likely. */
const B62_LIMIT = 248;
const DIGIT_LIMIT = 250;
/** A source that keeps failing the rules is broken (or not random): stop rather than loop. */
const MAX_BYTES = 1 << 16;
const MIN_ENTROPY = 4;

const isLetter = (c: string): boolean => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

/** A planted key value of `length` base62 characters from `random` (callers pass node:crypto randomBytes or a test source). */
export function plantedKeyValue(length: number, random: (n: number) => Uint8Array): string {
  let used = 0;
  for (;;) {
    let v = '';
    let letters = 0;
    while (v.length < length) {
      const bytes = random(64);
      if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new PlantedError('The random source for a planted secret gave no bytes.');
      used += bytes.length;
      if (used > MAX_BYTES) throw new PlantedError('The random source for a planted secret never met its rules; it is not random.');
      for (const b of bytes) {
        if (v.length >= length) break;
        if (letters >= 2) {
          if (b >= DIGIT_LIMIT) continue;
          v += DIGITS[b % 10];
          letters = 0;
        } else {
          if (b >= B62_LIMIT) continue;
          const c = B62[b % 62] as string;
          v += c;
          letters = isLetter(c) ? letters + 1 : 0;
        }
      }
    }
    if (/[0-9]/.test(v) && /[A-Z]/.test(v) && /[a-z]/.test(v) && !REACHABLE_STOPWORDS.test(v) && entropy(v) >= MIN_ENTROPY) return v;
  }
}
