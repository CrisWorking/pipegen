// v0.2 Plan F, F5 fix round 1 (ruling F5-R2): Plan E's C1b placements and Plan F's planted secret draw their values from ONE
// rule (src/proof/planted-value.ts): base62 by rejection sampling, a digit, an upper and a lower letter, no run of 3 letters
// (the scanners' stopword filter), none of the stopwords that rule leaves reachable (md5, six zeros), entropy at least 4.
// Measured on the pinned gitleaks 8.30.1 and betterleaks 1.9.0: the old C1b values were dropped about 1 in 100.
import { describe, expect, it } from 'vitest';
import { plantedSecret } from '../src/debate/planted.js';
import { plantedKeyValue, REACHABLE_STOPWORDS } from '../src/proof/planted-value.js';
import { plantedSecretPlacements } from '../src/proof/snapshot.js';

const seq = (seed = 1) => {
  let x = seed;
  return (n: number) => { const b = new Uint8Array(n); for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; b[i] = (x >>> 16) & 0xff; } return b; };
};
const replay = (bytes: number[], fallback = seq(7)) => {
  const q = [...bytes];
  return (n: number) => { const b = new Uint8Array(n); const f = fallback(n); for (let i = 0; i < n; i++) b[i] = q.length > 0 ? (q.shift() as number) : (f[i] as number); return b; };
};
const valueOf = (content: string | Uint8Array): string => /"([A-Za-z0-9]+)"/.exec(Buffer.from(content).toString('utf8'))?.[1] ?? '';

describe('C1b placement values', () => {
  it('C1b: every placement value follows the planted-value rule (no 3-letter run, no md5 or six zeros), the one rule plantedSecret uses', () => {
    let n = 0;
    for (let seed = 1; seed <= 300; seed++) {
      const r = plantedSecretPlacements(new Set(), { random: seq(seed) });
      for (const e of r.expected) {
        if (e.kind !== 'secret') continue;
        const f = r.files.find((x) => Buffer.from(typeof x.path === 'string' ? Buffer.from(x.path) : x.path).equals(Buffer.from(e.pathBytes)));
        const v = valueOf(f?.content as string | Uint8Array);
        expect(v).toMatch(/^[A-Za-z0-9]{32}$/);
        expect(v).toMatch(/[0-9]/);
        expect(v).toMatch(/[A-Z]/);
        expect(v).toMatch(/[a-z]/);
        expect(v).not.toMatch(/[A-Za-z]{3}/);
        expect(REACHABLE_STOPWORDS.test(v)).toBe(false);
        n++;
      }
    }
    expect(n).toBe(300 * 10);
    // one shared rule: the first placement's value is plantedKeyValue(32) of the same bytes, and plantedSecret is plantedKeyValue(40)
    for (let seed = 1; seed <= 20; seed++) {
      const first = plantedSecretPlacements(new Set(), { random: seq(seed) }).files[0];
      expect(valueOf(first?.content as string)).toBe(plantedKeyValue(32, seq(seed)));
      expect(plantedSecret(seq(seed))).toBe(plantedKeyValue(40, seq(seed)));
    }
    // bytes that spell md5 (and six zeros) first are drawn again in a C1b value too
    for (const head of [[38, 29, 5], [12, 3, 5], [52, 52, 52, 52, 52, 52]]) {
      const v = valueOf(plantedSecretPlacements(new Set(), { random: replay(head) }).files[0]?.content as string);
      expect(v).not.toMatch(/md5|000000/i);
      expect(plantedKeyValue(32, replay(head))).toBe(v);
    }
    // the stopword set, pinned
    for (const w of ['md5', 'MD5', 'Md5', 'mD5', '000000', 'x000000y']) expect(REACHABLE_STOPWORDS.test(w), w).toBe(true);
    for (const w of ['md6', 'm5d', '00000', 'a3t', 'fm1']) expect(REACHABLE_STOPWORDS.test(w), w).toBe(false);
  });
});
