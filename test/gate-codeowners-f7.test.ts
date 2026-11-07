// G15b (review-G17G-r1 F7, binding before the gate-v0.2.3 tag): the gate's CODEOWNERS matcher against a hostile pull request.
// Rules come from the BASE CODEOWNERS (the author cannot add a slow rule), but the author picks the paths: up to 3,000 files of 256-part
// paths built from a literal segment of a base rule with two or more interior `**`. The old matcher ran a fresh memoised DP per path
// prefix (about segs x n^3 per rule; measured n^2.8, a 46-rule file cost about 21 minutes for one such PR). The matcher is now one DP over
// all prefixes per rule (O(segments x parts)), a rule has at most MAX_RULE_SEGMENTS segments, and a step budget fails closed: an owner
// lookup the gate cannot finish is "unresolved", which waives nothing and says why. Written first.
import { describe, expect, it } from 'vitest';
import {
  codeOwners, integrityFindings, MAX_RULE_SEGMENTS, OWNERS_STEP_BUDGET, ownersLookup, ownersOf, OwnersUnresolvedError,
  type CodeownersRule, type PrContext, type PrFile,
} from '../gate/src/integrity.js';
import { expectScaling } from './helpers/scaling.js';

const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const ctx = (files: PrFile[], approvals: string[] = []): PrContext => ({
  number: 5, headSha: HEAD, baseSha: BASE, isFork: false, files, filesComplete: true, approvals, approvalsComplete: true, problems: [],
});
const suppression = (filename: string): PrFile => ({ filename, status: 'modified', changes: 2, patch: '@@ -1 +1 @@\n-a\n+x() // nosemgrep' });

/** The reviewer's plain 46-rule CODEOWNERS: 35 anchored literals, 10 `**\/genN/`, 5 `/apps/**\/src/**\/genN/`, plus a catch-all owner. */
const FILE46 = [
  '* @root',
  ...Array.from({ length: 35 }, (_, i) => `/lit${i}/ @lit${i}`),
  ...Array.from({ length: 10 }, (_, i) => `**/gen${i}/ @gen${i}`),
  ...Array.from({ length: 5 }, (_, i) => `/apps/**/src/**/gen${i}/ @app${i}`),
].join('\n');
/** `apps/` + (n - 2) x `src` + `.eslintrc.json`: n parts. */
const appsPath = (n: number): string => ['apps', ...Array.from({ length: n - 2 }, () => 'src'), '.eslintrc.json'].join('/');
/** `times` lookups, in ms. A slow matcher (the old one, a mutant) stops after 3 s and the time is extrapolated, so a failing run stays short. */
const timeLookups = (rules: CodeownersRule[], path: string, times: number): number => {
  const t = performance.now();
  for (let i = 0; i < times; i++) {
    ownersOf(rules, path);
    const ms = performance.now() - t;
    if (ms > 3000) return (ms * times) / (i + 1);
  }
  return performance.now() - t;
};

describe('F7: the matcher is linear in the path length (one DP over all prefixes per rule)', () => {
  it('F7: the 46-rule CODEOWNERS against apps/src/.../.eslintrc.json grows linearly from 32 to 256 parts', async () => {
    const rules = codeOwners(FILE46);
    expect(ownersOf(rules, appsPath(256))).toEqual(['root']);
    // 8x the path: linear about 8, the old matcher about 340 (n^2.8)
    await expectScaling('F7 46 rules', (size) => timeLookups(rules, appsPath(size === 'small' ? 32 : 256), 500), 24);
  });
  it('F7: /apps/**/src/**/generated/ against apps/ + src x n + file grows linearly from 32 to 256 parts', async () => {
    const rules = codeOwners('/apps/**/src/**/generated/ @g\n');
    expect(ownersOf(rules, appsPath(256))).toBeUndefined();
    expect(ownersOf(rules, 'apps/src/x/src/generated/a.ts')).toEqual(['g']);
    await expectScaling('F7 one interior ** pair', (size) => timeLookups(rules, appsPath(size === 'small' ? 32 : 256), 5000), 24);
  });
  it('F7: a rule of n `**` segments against a 255-part path grows linearly in n (8 vs 32, max 9)', async () => {
    const rule = (n: number): CodeownersRule[] => codeOwners(`${Array.from({ length: n }, () => '**').join('/')}/z @o\n`);
    const path = [...Array.from({ length: 254 }, () => 'a'), '.eslintrc.json'].join('/');
    const r8 = rule(8); const r32 = rule(32);
    expect(ownersOf(r32, path)).toBeUndefined();
    expect(ownersOf(r32, `${path.replace(/\.eslintrc\.json$/, 'z')}`)).toEqual(['o']);
    await expectScaling('F7 ** count', (size) => timeLookups(size === 'small' ? r8 : r32, path, 1000), 9);
  });
  it('F7: absolute ceiling, a 3,000-file pull request of 256-part paths under the 46-rule file finishes in seconds, not minutes', () => {
    const rules = codeOwners(FILE46);
    const files = Array.from({ length: 3000 }, (_, i) => suppression(`${appsPath(255)}/f${i}.ts`));
    const t = performance.now();
    const out = integrityFindings(ctx(files, ['root']), [], rules);
    const ms = performance.now() - t;
    // the old matcher: about 21 minutes; normal is well under a second here, the ceiling is far above that
    expect(ms).toBeLessThan(30_000);
    expect(out).toEqual([]);   // every lookup resolved inside the default budget: the owner `root` waived each suppression
  });
});

describe('F7: a cap on rule segments, failing closed', () => {
  const long = (n: number): string => `/${Array.from({ length: n - 1 }, (_, i) => `d${i}`).join('/')}/x`;
  it('a rule of exactly MAX_RULE_SEGMENTS segments is matched as before', () => {
    const rules = codeOwners(`${long(MAX_RULE_SEGMENTS)} @deep\n`);
    expect(ownersLookup(rules, long(MAX_RULE_SEGMENTS).slice(1))).toEqual({ owners: ['deep'] });
  });
  it('a rule over MAX_RULE_SEGMENTS that would decide the owner leaves the lookup unresolved (never skipped, never "no owner")', () => {
    const over = long(MAX_RULE_SEGMENTS + 1);
    const rules = codeOwners(`* @root\n${over} @deep\n`);
    expect(ownersLookup(rules, over.slice(1))).toEqual({ unresolved: 'segments' });
    expect(ownersLookup(rules, 'src/a.ts')).toEqual({ unresolved: 'segments' });   // the over-cap rule comes later than `*`, so it could decide
    expect(() => ownersOf(rules, 'src/a.ts')).toThrow(OwnersUnresolvedError);
  });
  it('an over-cap rule does not matter when a later rule matches (the last matching rule wins)', () => {
    const rules = codeOwners(`${long(MAX_RULE_SEGMENTS + 1)} @deep\n/src/ @src\n`);
    expect(ownersLookup(rules, 'src/a.ts')).toEqual({ owners: ['src'] });
  });
  it('in the gate an unresolved lookup waives nothing (not even by pipegen\'s block owners) and says why', () => {
    const rules = codeOwners(`* @root\n${long(MAX_RULE_SEGMENTS + 1)} @deep\n`);
    const out = integrityFindings(ctx([suppression('src/a.ts')], ['root', 'blk']), ['src/a.ts'], rules, { codeowners: { found: '.github/CODEOWNERS', blockOwners: ['blk'] } });
    expect(out.map((f) => f.ruleId).sort()).toEqual(['integrity:protected-path', 'integrity:suppression']);
    for (const f of out) expect(f.message).toMatch(/could not work out the code owners of this path.*over 64 segments.*nobody can approve/);
  });
});

describe('F7: a step budget, failing closed', () => {
  it('a lookup that runs out of steps is unresolved', () => {
    const rules = codeOwners(FILE46);
    expect(ownersLookup(rules, appsPath(256), { left: 50 })).toEqual({ unresolved: 'budget' });
    expect(ownersLookup(rules, appsPath(256), { left: OWNERS_STEP_BUDGET })).toEqual({ owners: ['root'] });
  });
  it('the budget is shared by one gate run: once spent, the remaining files are unresolved, waive nothing, and say why', () => {
    const rules = codeOwners(FILE46);
    // forty files whose lookups cost the same (names of one length)
    const files = Array.from({ length: 40 }, (_, i) => suppression(`${appsPath(255)}/f${i + 10}.ts`));
    const steps = { left: OWNERS_STEP_BUDGET };
    ownersLookup(rules, `${appsPath(255)}/f10.ts`, steps);
    const one = OWNERS_STEP_BUDGET - steps.left;
    expect(one).toBeGreaterThan(0);
    const out = integrityFindings(ctx(files, ['root']), [], rules, { ownerSteps: one * 10 + 1 });
    expect(out.length).toBe(30);
    for (const f of out) {
      expect(f.ruleId).toBe('integrity:suppression');
      expect(f.message).toMatch(/could not work out the code owners of this path within its step budget.*nobody can approve/);
    }
  });
  it('a path is looked up once per gate run (waived and the message share the answer)', () => {
    const rules = codeOwners(FILE46);
    const steps = { left: OWNERS_STEP_BUDGET };
    ownersLookup(rules, `${appsPath(255)}/f0.ts`, steps);
    const one = OWNERS_STEP_BUDGET - steps.left;
    // one lookup's worth of steps is enough for a file that is both checked for a waiver and given a message
    const out = integrityFindings(ctx([suppression(`${appsPath(255)}/f0.ts`)], []), [], rules, { ownerSteps: one });
    expect(out.length).toBe(1);
    expect(out[0]?.message).toMatch(/A code owner of this path/);
  });
});

// ---------- differential: the new matcher equals the old one (copied here as the oracle) on random rules and paths ----------

type Seg = { kind: 'globstar' } | { kind: 'globstar+' } | { kind: 'glob'; toks: string[] };
function oracleCompile(pattern: string): { segs: Seg[]; dirOnly: boolean; ancestors: boolean } {
  let p = pattern;
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.startsWith('/') || p.includes('/');
  if (p.startsWith('/')) p = p.slice(1);
  let parts = p.split('/');
  if (!anchored) parts = ['**', ...parts];
  const segs: Seg[] = parts.map((part, idx) => {
    if (part === '**') return idx === parts.length - 1 ? { kind: 'globstar+' } : { kind: 'globstar' };
    const toks: string[] = [];
    for (let i = 0; i < part.length; i++) {
      const c = part[i] as string;
      if (c === '\\' && i + 1 < part.length) { toks.push(part[++i] as string); continue; }
      if (c === '*') { if (toks[toks.length - 1] !== '*') toks.push('*'); continue; }
      toks.push(c === '?' ? '?' : c);
    }
    return { kind: 'glob', toks };
  });
  return { segs, dirOnly, ancestors: dirOnly || !/[*?]/.test(parts[parts.length - 1] as string) };
}
function oracleSeg(toks: readonly string[], s: string): boolean {
  let t = 0; let i = 0; let star = -1; let mark = 0;
  while (i < s.length) {
    const k = toks[t];
    if (k === '*') { star = t++; mark = i; } else if (k !== undefined && (k === '?' || k === s[i])) { t++; i++; } else if (star >= 0) { t = star + 1; i = ++mark; } else return false;
  }
  while (toks[t] === '*') t++;
  return t === toks.length;
}
function oracleOwnersOf(rules: readonly CodeownersRule[], path: string): string[] | undefined {
  const parts = path.split('/');
  if (parts.length > 256 || parts.includes('')) return undefined;
  let owners: string[] | undefined;
  for (const r of rules) {
    const c = oracleCompile(r.pattern);
    const prefix = (end: number): boolean => {
      const memo = new Map<number, boolean>();
      const go = (pi: number, si: number): boolean => {
        const key = pi * (end + 1) + si; const hit = memo.get(key); if (hit !== undefined) return hit;
        let res: boolean; const seg = c.segs[pi];
        if (seg === undefined) res = si === end;
        else if (seg.kind === 'globstar+') res = si < end;
        else if (seg.kind === 'globstar') { res = false; for (let j = si; j <= end && !res; j++) res = go(pi + 1, j); }
        else res = si < end && oracleSeg(seg.toks, parts[si] as string) && go(pi + 1, si + 1);
        memo.set(key, res); return res;
      };
      return go(0, 0);
    };
    let m = false;
    for (let k = 1; k <= parts.length && !m; k++) m = k === parts.length ? !c.dirOnly && prefix(k) : c.ancestors && prefix(k);
    if (m) owners = r.owners;
  }
  return owners;
}

describe('F7: the new matcher gives the old matcher\'s answers', () => {
  it('2,000 random rule sets and paths (seeded): same owners', () => {
    let seed = 0x5eed;
    const rnd = (n: number): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const pick = <T>(xs: readonly T[]): T => xs[rnd(xs.length)] as T;
    const names = ['a', 'b', 'ab', 'src', 'x.js', '.github'];
    const segPat = ['a', 'b', '*', '?', 'a*', '*b', '**', 'src', '*.js', 'a?', '\\*', 'x.js'];
    let differ = 0;
    for (let round = 0; round < 2000; round++) {
      const rules: string[] = [];
      for (let r = 0, nr = 1 + rnd(4); r < nr; r++) {
        const segs = Array.from({ length: 1 + rnd(4) }, () => pick(segPat)).join('/');
        rules.push(`${rnd(2) === 0 ? '/' : ''}${segs}${rnd(3) === 0 ? '/' : ''} @o${r}`);
      }
      const parsed = codeOwners(rules.join('\n'));
      for (let q = 0; q < 6; q++) {
        const path = Array.from({ length: 1 + rnd(6) }, () => pick(names)).join('/');
        const want = oracleOwnersOf(parsed, path);
        const got = ownersOf(parsed, path);
        if (JSON.stringify(got) !== JSON.stringify(want)) { differ++; expect({ rules, path, got }).toEqual({ rules, path, got: want }); }
      }
    }
    expect(differ).toBe(0);
  });
});
