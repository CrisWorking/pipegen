// Plan C Task C4: pipeline integrity (gate/src/integrity.ts). A PR can attack the gate by changing the pipeline itself: a workflow, a tool
// config, an ignore file, a suppression comment, or by hiding its changes from the file list. Such changes block unless a code owner
// approved the exact head commit. Every GitHub answer and every patch is hostile. Pure apart from the injected client (a fake here): no
// network. Written first (strict test-first). The CODEOWNERS glob table follows GitHub's documented examples (gitignore rules, with
// the documented exceptions); see the open point in task-C4-report.md.
import { describe, expect, it } from 'vitest';
import type { GateGithub } from '../gate/src/baseline.js';
import {
  addedLinesOf, baseHasInstall, buildPrDiff, codeOwners, integrityFindings, loadCodeowners, ownersOf, parseConfigDoc, readConfigSections, readPrContext as readPrContextStrict,
  type CodeownersRule, type PrContext, type PrFile,
} from '../gate/src/integrity.js';
import { PROTECTED_PATHS_BASE } from '../src/types.js';
import { BigInteger, NonFinite } from '../gate/src/integrity.js';
/** Non-finite numbers are typed tags in the parsed document; the oracle writes them as {"$num": kind}. TOML integers are BigInteger (C5a CF4); the oracle writes them as JSON numbers. */
const plain = (v: unknown): unknown => (v instanceof NonFinite ? { $num: v.kind } : v instanceof BigInteger ? Number(v.digits) : Array.isArray(v) ? v.map(plain) : typeof v === 'object' && v !== null && !(v instanceof Date) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)])) : v);

// ---------- builders ----------
const SHA = (c: string): string => c.repeat(40);
const HEAD = SHA('a');
const BASE = SHA('b');
const REPO = { owner: 'acme', name: 'app', id: 7 };
const WF = '.github/workflows/pipegen.yml';
const PROTECTED = ['.github/workflows/**', '.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS', '.gitleaksignore', '.semgrepignore', '.trivyignore', '.trivyignore.yaml', '.gitleaks.toml', '.hadolint.yaml', 'knip.json', 'biome.json', 'eslint.config.*', '.prettierrc*', 'renovate.json', '.betterleaks.toml'];
const PATCH = '@@ -1 +1 @@\n-a\n+b';
const file = (filename: string, over: Partial<PrFile> = {}): PrFile => ({ filename, status: 'modified', changes: 2, patch: PATCH, ...over });
const ctx = (over: Partial<PrContext> = {}): PrContext => ({
  number: 5, headSha: HEAD, baseSha: BASE, isFork: false, files: [file('src/a.ts')], filesComplete: true, approvals: [], approvalsComplete: true, problems: [], ...over,
});
const owners = (text: string): CodeownersRule[] => codeOwners(text);
const ids = (fs: { ruleId: string }[]): string[] => fs.map((f) => f.ruleId);

type Answer = unknown | Error;
const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64').replace(/(.{60})/g, '$1\n');
const contentOf = (text: string): unknown => ({ type: 'file', encoding: 'base64', size: Buffer.byteLength(text), content: b64(text) });

class Gh implements GateGithub {
  calls: string[] = [];
  pull: Answer = { number: 5, head: { sha: HEAD, repo: { id: 7 } }, base: { sha: BASE }, changed_files: 1 };
  files: Answer = [];            // an array (paged by the fake) or any hostile answer
  reviews: Answer = [];
  contents = new Map<string, Answer>();   // `${ref}:${path}` -> answer; absent -> null (404)
  cmp: Answer = { status: 'ahead', files: [] };   // an object whose files the fake pages, or any hostile answer
  private out(a: Answer): unknown { if (a instanceof Error) throw a; return a; }
  async getPull(_o: string, _n: string, n: number): Promise<unknown> { this.calls.push(`pull ${n}`); return this.out(this.pull); }
  perms = new Map<string, Answer>();   // login -> permission answer (default: write)
  raw = new Map<string, Answer>();     // `${ref}:${path}` -> raw text (default: 404)
  async collaboratorPermission(_o: string, _n: string, login: string): Promise<unknown> {
    this.calls.push(`perm ${login}`);
    return this.out(this.perms.has(login) ? this.perms.get(login) : { permission: 'write' });
  }
  async rawFileAt(_o: string, _n: string, path: string, ref: string): Promise<unknown> {
    this.calls.push(`raw ${ref.slice(0, 1)}:${path}`);
    const k = `${ref}:${path}`;
    return this.raw.has(k) ? this.out(this.raw.get(k)) : null;
  }
  async listPullFiles(_o: string, _n: string, _num: number, page: number, perPage: number): Promise<unknown> {
    this.calls.push(`files ${page}`); const a = this.out(this.files); return Array.isArray(a) ? a.slice((page - 1) * perPage, page * perPage) : a;
  }
  async listPullReviews(_o: string, _n: string, _num: number, page: number, perPage: number): Promise<unknown> {
    this.calls.push(`reviews ${page}`); const a = this.out(this.reviews); return Array.isArray(a) ? a.slice((page - 1) * perPage, page * perPage) : a;
  }
  async fileAt(_o: string, _n: string, path: string, ref: string): Promise<unknown> {
    this.calls.push(`file ${ref.slice(0, 1)}:${path}`);
    const k = `${ref}:${path}`;
    return this.contents.has(k) ? this.out(this.contents.get(k)) : null;
  }
  // GitHub's REST "Compare two commits": "the list of changed files is only shown on the first page of results, and it includes up to
  // 300 changed files for the entire comparison" (page/per_page page the COMMITS). The adapter makes one call and never pages the files.
  async compareFiles(_o: string, _n: string, base: string, head: string): Promise<unknown> {
    this.calls.push(`compare ${base.slice(0, 1)}...${head.slice(0, 1)}`);
    return this.out(this.cmp);
  }
  // GateGithub members the integrity code never uses
  async compare(): Promise<unknown> { throw new Error('not used'); }
  async listRuns(): Promise<unknown> { throw new Error('not used'); }
  async listRunArtifacts(): Promise<unknown> { throw new Error('not used'); }
  async downloadArtifact(): Promise<Uint8Array> { throw new Error('not used'); }
  async branchHead(): Promise<unknown> { throw new Error('not used'); }
  async tagExists(): Promise<boolean> { throw new Error('not used'); }
  async getCommit(): Promise<unknown> { throw new Error('not used'); }
}

// ---------- CODEOWNERS: syntax and GitHub's glob semantics ----------

describe('codeowners: parsing', () => {
  it('reads patterns and user owners; comments, blank lines, CRLF and inline comments are handled; team and e-mail owners are dropped', () => {
    const rules = codeOwners('# a comment\r\n\r\n*.js @JS-Owner\r\n*.txt @octo-org/octocats\n*.go docs@example.com\n/docs/ @a @b # trailing comment\n/x/ @c\t@d\n');
    expect(rules).toEqual([
      { pattern: '*.js', owners: ['js-owner'] },
      { pattern: '*.txt', owners: [] },
      { pattern: '*.go', owners: [] },
      { pattern: '/docs/', owners: ['a', 'b'] },
      { pattern: '/x/', owners: ['c', 'd'] },
    ]);
  });
  it('null or empty text gives no rules; lines GitHub rejects (negation, character ranges, an escaped #) are skipped', () => {
    expect(codeOwners(null)).toEqual([]);
    expect(codeOwners('')).toEqual([]);
    expect(codeOwners('!x @a\n/y[ab] @a\n\\#z @a\n/ok @a\n')).toEqual([{ pattern: '/ok', owners: ['a'] }]);
  });
  it('a line with any owner token that is not a valid login, team or e-mail is skipped whole, as GitHub does (fix round 1, review 14)', () => {
    for (const bad of ['@-bad', '@bad-', '@a_b', '@' + 'x'.repeat(40), 'plain', '@']) expect(codeOwners(`/a @ok ${bad} @fine-1\n`), bad).toEqual([]);
    expect(codeOwners('/a @fine-1 @org/team user@example.com\n')).toEqual([{ pattern: '/a', owners: ['fine-1'] }]);
  });
  it('a hostile huge file is bounded: only the first 100,000 rules count and a line over 4096 characters is skipped', () => {
    const rules = codeOwners(`${'/' + 'a'.repeat(5000)} @a\n` + Array.from({ length: 100_050 }, (_, i) => `/p${i} @a`).join('\n'));
    expect(rules.length).toBe(100_000);
  });
});

describe("codeowners: GitHub's documented glob examples (rule, path, owned?)", () => {
  // each row: a one-rule file, then the paths that rule owns and the paths it does not
  const table: [string, string[], string[]][] = [
    ['*', ['a.txt', 'x/y/z.md', '.github/workflows/ci.yml'], []],
    ['*.js', ['a.js', 'src/deep/b.js'], ['a.jsx', 'a.js.map', 'ajs', 'src/a.ts']],
    ['/build/logs/', ['build/logs/a.log', 'build/logs/x/y.log'], ['src/build/logs/a.log', 'build/logsx/a.log', 'build/logs']],
    ['docs/*', ['docs/getting-started.md'], ['docs/build-app/troubleshooting.md', 'x/docs/a.md', 'docs']],
    ['apps/', ['apps/a', 'apps/a/b', 'src/apps/a', 'x/y/apps/z/w'], ['apps', 'apps.txt', 'myapps/a']],
    ['/docs/', ['docs/a', 'docs/a/b'], ['x/docs/a', 'docs', 'docs2/a']],
    ['/scripts/', ['scripts/run.sh', 'scripts/a/b.sh'], ['src/scripts/run.sh']],
    ['**/logs', ['logs/a', 'build/logs/a', 'deeply/nested/logs/x', 'logs'], ['logsx/a', 'x/mylogs/a']],
    ['/apps/', ['apps/x', 'apps/github/y'], ['x/apps/y']],
    ['/foo', ['foo', 'foo/x'], ['a/foo', 'foo2']],
    ['foo', ['foo', 'a/foo', 'foo/x', 'a/foo/x'], ['foobar', 'a/foobar/x']],
    ['/a/**', ['a/b', 'a/b/c'], ['a', 'x/a/b']],
    ['a/**/b', ['a/b', 'a/x/b', 'a/x/y/b', 'a/b/c'], ['a/x', 'x/a/b']],
    ['**/docs/**', ['docs/a', 'x/docs/a/b'], ['docs', 'x/docs']],
    ['/src/*.ts', ['src/a.ts'], ['src/x/a.ts', 'src/a.tsx', 'a/src/a.ts']],
    ['/f?le.txt', ['file.txt', 'fale.txt'], ['fle.txt', 'f/le.txt', 'fiile.txt']],
    ['/Docs/', ['Docs/a'], ['docs/a', 'DOCS/a']],   // CODEOWNERS paths are case sensitive
    ['/a*b*c', ['abc', 'aXbYc'], ['ac', 'a/b/c']],
    ['*.min.js', ['x.min.js', 'a/b/x.min.js'], ['x.js']],
    ['/.github/workflows/', ['.github/workflows/ci.yml'], ['.github/workflow/ci.yml']],
  ];
  for (const [rule, yes, no] of table) {
    it(`rule ${rule}`, () => {
      const rules = codeOwners(`${rule} @o\n`);
      for (const p of yes) expect(ownersOf(rules, p), `${rule} should own ${p}`).toEqual(['o']);
      for (const p of no) expect(ownersOf(rules, p), `${rule} should not own ${p}`).toBeUndefined();
    });
  }
  it('the documented example file: the last matching pattern wins, and /apps/github with no owner clears ownership', () => {
    const rules = codeOwners('* @global\n*.js @js\n**/logs @logs\n/build/logs/ @doc\ndocs/* @docs\n/apps/ @octo\n/apps/github\n');
    expect(ownersOf(rules, 'README.md')).toEqual(['global']);
    expect(ownersOf(rules, 'src/a.js')).toEqual(['js']);
    expect(ownersOf(rules, 'build/logs/a.js')).toEqual(['doc']);
    expect(ownersOf(rules, 'docs/x.md')).toEqual(['docs']);
    expect(ownersOf(rules, 'apps/web/a.js')).toEqual(['octo']);
    expect(ownersOf(rules, 'apps/github/a.js')).toEqual([]);   // cleared, even though * and *.js matched earlier
    expect(ownersOf(rules, 'apps/github')).toEqual([]);
    expect(ownersOf(rules, 'x/logs/a.js')).toEqual(['logs']);
  });
  it('a team-only rule still takes ownership from an earlier rule, and leaves no user approver', () => {
    const rules = codeOwners('* @alice\n/ci/ @org/ci-team\n');
    expect(ownersOf(rules, 'ci/x.yml')).toEqual([]);
    expect(ownersOf(rules, 'src/x.ts')).toEqual(['alice']);
  });
  it('a path no rule matches has no owners (undefined)', () => {
    expect(ownersOf(codeOwners('/a/ @x\n'), 'b/c')).toBeUndefined();
  });
  it('matching is bounded: many ** segments against a long path finish quickly', () => {
    const rules = codeOwners(`${Array.from({ length: 30 }, () => '**').join('/')}/z @o\n`);
    const t = Date.now();
    ownersOf(rules, Array.from({ length: 200 }, () => 'a').join('/'));
    expect(Date.now() - t).toBeLessThan(1000);
  });
});

describe('loadCodeowners: from the BASE commit, .github/ then root then docs/', () => {
  const at = (g: Gh, ref: string, path: string, text: string): void => { g.contents.set(`${ref}:${path}`, contentOf(text)); };
  it('reads only at the base sha, never the head; the first of the three places that exists wins', async () => {
    const g = new Gh();
    at(g, BASE, 'docs/CODEOWNERS', '* @docs-owner\n'); at(g, BASE, 'CODEOWNERS', '* @root-owner\n'); at(g, BASE, '.github/CODEOWNERS', '* @github-owner\n');
    at(g, HEAD, '.github/CODEOWNERS', '* @attacker\n');
    const r = await loadCodeowners(g, REPO, BASE);
    expect(ownersOf(r.rules, 'x')).toEqual(['github-owner']);
    expect(r.found).toBe('.github/CODEOWNERS');
    expect(g.calls).toEqual([`file b:.github/CODEOWNERS`]);
  });
  it('falls through to the root file, then docs/', async () => {
    const g = new Gh(); at(g, BASE, 'CODEOWNERS', '* @root\n');
    expect(ownersOf((await loadCodeowners(g, REPO, BASE)).rules, 'x')).toEqual(['root']);
    const h = new Gh(); at(h, BASE, 'docs/CODEOWNERS', '* @docs\n');
    const r = await loadCodeowners(h, REPO, BASE);
    expect(ownersOf(r.rules, 'x')).toEqual(['docs']);
    expect(h.calls).toEqual(['file b:.github/CODEOWNERS', 'file b:CODEOWNERS', 'file b:docs/CODEOWNERS']);
  });
  it('none of the three exists → no rules, no problem', async () => {
    const r = await loadCodeowners(new Gh(), REPO, BASE);
    expect(r).toEqual({ rules: [], found: null });
  });
  it('an API error other than 404, a malformed answer, a directory, or a file over 1 MiB → no rules and a problem (never a guess)', async () => {
    for (const bad of [new Error('500'), 'x', { type: 'dir' }, [], { type: 'file', encoding: 'none', size: 2_000_000, content: '' }, { type: 'file', encoding: 'base64', size: 5, content: 5 }]) {
      const g = new Gh(); g.contents.set(`${BASE}:.github/CODEOWNERS`, bad);
      const r = await loadCodeowners(g, REPO, BASE);
      expect(r.rules, JSON.stringify(bad)).toEqual([]);
      expect(r.problem, JSON.stringify(bad)).toBeTypeOf('string');
    }
  });
  it('a sha that is not 40 lower-case hex is refused without a call', async () => {
    const g = new Gh();
    const r = await loadCodeowners(g, REPO, 'main');
    expect(r.problem).toBeTypeOf('string');
    expect(g.calls).toEqual([]);
  });
});

// ---------- readPrContext: the pull, its files (paged), its reviews (paged) ----------

/**
 * C5a CF3: `codeowners` is required. Most tests here are about the reading itself, so they model "every reviewer is a code owner" (a
 * CODEOWNERS rule `*` naming each login that reviewed); the owner filter has its own tests below, with explicit lists.
 */
const everyReviewer = (g: Gh): CodeownersRule[] => {
  const list = Array.isArray(g.reviews) ? (g.reviews as unknown[]) : [];
  const logins = list.flatMap((r) => { const l = (r as { user?: { login?: unknown } } | null)?.user?.login; return typeof l === 'string' ? [l.toLowerCase()] : []; });
  return [{ pattern: '*', owners: [...new Set(logins)] }];
};
const readPrContext = (g: Gh, repo: typeof REPO, n: number, opts: { expectHeadSha?: string; codeowners?: readonly CodeownersRule[] } = {}): Promise<PrContext> =>
  readPrContextStrict(g, repo, n, { ...opts, codeowners: opts.codeowners ?? everyReviewer(g) });

const review = (id: number, login: string, state: string, commit = HEAD): Record<string, unknown> => ({ id, user: { login }, state, commit_id: commit });
const many = (n: number, mk: (i: number) => unknown): unknown[] => Array.from({ length: n }, (_, i) => mk(i));
const ghWith = (files: unknown[], over: Record<string, unknown> = {}): Gh => {
  const g = new Gh();
  g.pull = { number: 5, head: { sha: HEAD, repo: { id: 7 } }, base: { sha: BASE }, user: { login: 'author' }, changed_files: files.length, ...over };
  g.files = files;
  return g;
};

describe('readPrContext: files', () => {
  it('reads the pull and every page of files; the list is complete when it has exactly pull.changed_files entries', async () => {
    const g = ghWith(many(250, (i) => file(`src/f${i}.ts`)));
    const pr = await readPrContext(g, REPO, 5);
    expect(pr.files.length).toBe(250);
    expect(pr.filesComplete).toBe(true);
    expect(pr.headSha).toBe(HEAD); expect(pr.baseSha).toBe(BASE); expect(pr.number).toBe(5); expect(pr.isFork).toBe(false);
    expect(g.calls.filter((c) => c.startsWith('files')).length).toBe(3);
  });
  it('a PR that changes pull.changed_files against the list: a shorter list is incomplete (hidden files), and so is a longer one', async () => {
    const g = ghWith(many(10, (i) => file(`src/f${i}.ts`)), { changed_files: 11 });
    expect((await readPrContext(g, REPO, 5)).filesComplete).toBe(false);
    const h = ghWith(many(10, (i) => file(`src/f${i}.ts`)), { changed_files: 9 });
    expect((await readPrContext(h, REPO, 5)).filesComplete).toBe(false);
    const j = ghWith(many(10, (i) => file(`src/f${i}.ts`)), { changed_files: '10' });
    expect((await readPrContext(j, REPO, 5)).filesComplete).toBe(false);
  });
  it('3,000 files is the API cap: incomplete even when changed_files is also 3,000, and the pages are bounded', async () => {
    const g = ghWith(many(3000, (i) => file(`src/f${i}.ts`)));
    const pr = await readPrContext(g, REPO, 5);
    expect(pr.filesComplete).toBe(false);
    expect(g.calls.filter((c) => c.startsWith('files')).length).toBeLessThanOrEqual(31);
    const h = ghWith(many(5000, (i) => file(`src/f${i}.ts`)), { changed_files: 5000 });
    expect((await readPrContext(h, REPO, 5)).filesComplete).toBe(false);
    expect(h.calls.filter((c) => c.startsWith('files')).length).toBeLessThanOrEqual(31);
  });
  it('an error, a non-array page, or a malformed entry makes the list incomplete (never a partial list used as complete)', async () => {
    const e = ghWith([file('a')]); e.files = new Error('500');
    const n = ghWith([file('a')]); n.files = { not: 'a list' };
    const m = ghWith([file('a'), { filename: 5 }]);
    const m2 = ghWith([file('a'), { filename: 'b', status: 'modified', changes: 'x' }]);
    const m3 = ghWith([file('a'), 'str']);
    for (const g of [e, n, m, m2, m3]) {
      const pr = await readPrContext(g, REPO, 5);
      expect(pr.filesComplete).toBe(false);
      expect(pr.problems.length).toBeGreaterThan(0);
    }
  });
  it('an unreadable or malformed pull is incomplete too; a bad head or base sha, or a bad number is refused', async () => {
    const bads: unknown[] = [new Error('404'), null, 'x', { head: {}, base: {}, changed_files: 0 }, { number: 5, head: { sha: 'abc', repo: { id: 7 } }, base: { sha: BASE }, changed_files: 0 },
      { number: 5, head: { sha: HEAD, repo: { id: 7 } }, base: { sha: 'X'.repeat(40) }, changed_files: 0 }, { number: 6, head: { sha: HEAD, repo: { id: 7 } }, base: { sha: BASE }, changed_files: 0 }];
    for (const bad of bads) {
      const g = new Gh(); g.pull = bad as never;
      const pr = await readPrContext(g, REPO, 5);
      expect(pr.filesComplete, JSON.stringify(bad)).toBe(false);
      expect(pr.approvals, JSON.stringify(bad)).toEqual([]);
    }
  });
  it('isFork: the head repository id differs from the repository, or the head repository is gone', async () => {
    expect((await readPrContext(ghWith([], { head: { sha: HEAD, repo: { id: 8 } } }), REPO, 5)).isFork).toBe(true);
    expect((await readPrContext(ghWith([], { head: { sha: HEAD, repo: null } }), REPO, 5)).isFork).toBe(true);
    expect((await readPrContext(ghWith([], { head: { sha: HEAD, repo: { id: '7' } } }), REPO, 5)).isFork).toBe(true);
    expect((await readPrContext(ghWith([], { head: { sha: HEAD, repo: { id: 7 } } }), REPO, 5)).isFork).toBe(false);
  });
  it('keeps previous_filename, patch and status exactly as given; a non-string patch is dropped', async () => {
    const g = ghWith([{ filename: 'b', previous_filename: 'a', status: 'renamed', changes: 0 }, { filename: 'c', status: 'modified', changes: 1, patch: 5 }]);
    const pr = await readPrContext(g, REPO, 5);
    expect(pr.files[0]).toMatchObject({ filename: 'b', previous_filename: 'a', status: 'renamed' });
    expect(pr.files[1]?.patch).toBeUndefined();
  });
});

describe('readPrContext: approvals', () => {
  const approvalsOf = async (reviews: unknown[], opts?: { expectHeadSha?: string }): Promise<PrContext> => { const g = ghWith([]); g.reviews = reviews; return readPrContext(g, REPO, 5, opts); };
  it('an APPROVED review on the head commit counts; logins are lower-cased', async () => {
    expect((await approvalsOf([review(1, 'Alice', 'APPROVED')])).approvals).toEqual(['alice']);
  });
  it('approvals: a review on an older commit does not count', async () => {
    expect((await approvalsOf([review(1, 'alice', 'APPROVED', SHA('c'))])).approvals).toEqual([]);
  });
  it('approvals: the latest non-COMMENTED review per user decides: a later COMMENTED does not revoke, a later CHANGES_REQUESTED or DISMISSED does', async () => {
    expect((await approvalsOf([review(1, 'a', 'APPROVED'), review(2, 'a', 'COMMENTED')])).approvals).toEqual(['a']);
    expect((await approvalsOf([review(1, 'a', 'APPROVED'), review(2, 'a', 'CHANGES_REQUESTED')])).approvals).toEqual([]);
    expect((await approvalsOf([review(1, 'a', 'APPROVED'), review(2, 'a', 'DISMISSED')])).approvals).toEqual([]);
    expect((await approvalsOf([review(1, 'a', 'CHANGES_REQUESTED'), review(2, 'a', 'APPROVED')])).approvals).toEqual(['a']);
    expect((await approvalsOf([review(1, 'a', 'APPROVED'), review(2, 'a', 'PENDING')])).approvals).toEqual(['a']);
  });
  it('approvals: the order is by review id, not by the order of the list', async () => {
    expect((await approvalsOf([review(2, 'a', 'CHANGES_REQUESTED'), review(1, 'a', 'APPROVED')])).approvals).toEqual([]);
  });
  it('approvals: a login in different letter case is the same user', async () => {
    expect((await approvalsOf([review(1, 'Bob', 'APPROVED'), review(2, 'bob', 'CHANGES_REQUESTED')])).approvals).toEqual([]);
  });
  it('approvals: a review with a missing user, a bad state or a bad commit is ignored', async () => {
    expect((await approvalsOf([{ id: 1, user: null, state: 'APPROVED', commit_id: HEAD }, review(2, 'a', 'approved'), { id: 3, user: { login: 'b' }, state: 'APPROVED' }, { user: { login: 'c' }, state: 'APPROVED', commit_id: HEAD }, 'x'])).approvals).toEqual([]);
  });
  it('approvals: reviews are paged; an approval on page 2 counts, and the later revoke on page 3 wins', async () => {
    const filler = many(100, (i) => review(i + 1, `u${i}`, 'COMMENTED'));
    const pr = await approvalsOf([...filler, ...many(99, (i) => review(200 + i, `v${i}`, 'COMMENTED')), review(300, 'alice', 'APPROVED')]);
    expect(pr.approvals).toEqual(['alice']);
    expect(pr.approvalsComplete).toBe(true);
    const revoked = await approvalsOf([...filler, review(300, 'alice', 'APPROVED'), ...many(98, (i) => review(400 + i, `w${i}`, 'COMMENTED')), review(600, 'alice', 'CHANGES_REQUESTED')]);
    expect(revoked.approvals).toEqual([]);
  });
  it('approvals: an incomplete page (an error, a non-array, or the page cap) is fail closed: no approvals at all', async () => {
    const e = ghWith([]); e.reviews = new Error('500');
    const n = ghWith([]); n.reviews = { x: 1 };
    const big = ghWith([]); big.reviews = many(5000, (i) => review(i + 1, `u${i}`, 'APPROVED'));
    for (const g of [e, n, big]) {
      const pr = await readPrContext(g, REPO, 5);
      expect(pr.approvals).toEqual([]);
      expect(pr.approvalsComplete).toBe(false);
    }
    expect(big.calls.filter((c) => c.startsWith('reviews')).length).toBeLessThanOrEqual(31);
  });
  it('approvals: when the pull head is not the commit the caller expects (the head moved), nothing is approved', async () => {
    const moved = await approvalsOf([review(1, 'a', 'APPROVED')], { expectHeadSha: SHA('d') });
    expect(moved.approvals).toEqual([]);
    expect(moved.filesComplete).toBe(false);   // fix round 1 (7): the files are another commit's, so the list cannot be judged complete
    expect(ids(integrityFindings(moved, PROTECTED, OWNER_RULES))).toContain('integrity:incomplete-list');
    expect((await approvalsOf([review(1, 'a', 'APPROVED')], { expectHeadSha: HEAD })).approvals).toEqual(['a']);
  });
});

// ---------- integrityFindings ----------

const OWNER_RULES = owners('* @alice\n/.github/ @alice @bob\n/docs/ @org/team\n');
describe('integrityFindings: protected paths', () => {
  it('integrity: workflow change without codeowner approval blocks', () => {
    const f = integrityFindings(ctx({ files: [file(WF)] }), PROTECTED, OWNER_RULES);
    expect(ids(f)).toEqual(['integrity:protected-path']);
    expect(f[0]).toMatchObject({ tool: 'pipegen', severity: 'critical', file: WF });
    expect(f[0]?.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
  it('integrity: same change approved by codeowner on head commit → no finding', () => {
    expect(integrityFindings(ctx({ files: [file(WF)], approvals: ['bob'] }), PROTECTED, OWNER_RULES)).toEqual([]);
  });
  it('integrity: approval on an older commit ignored (readPrContext leaves it out of approvals)', async () => {
    const g = ghWith([file(WF)]); g.reviews = [review(1, 'alice', 'APPROVED', SHA('c'))];
    const pr = await readPrContext(g, REPO, 5);
    expect(ids(integrityFindings(pr, PROTECTED, OWNER_RULES))).toEqual(['integrity:protected-path']);
  });
  it('integrity: approval from a non-owner, or from an owner listed only by team, ignored', () => {
    expect(ids(integrityFindings(ctx({ files: [file(WF)], approvals: ['mallory'] }), PROTECTED, OWNER_RULES))).toEqual(['integrity:protected-path']);
    const teamOnly = owners('* @org/team\n');
    expect(ids(integrityFindings(ctx({ files: [file(WF)], approvals: ['org', 'team', 'alice'] }), PROTECTED, teamOnly))).toEqual(['integrity:protected-path']);
  });
  it('integrity: no CODEOWNERS on the base → a protected path always blocks, and the message says how to approve', () => {
    const f = integrityFindings(ctx({ files: [file(WF)], approvals: ['alice'] }), PROTECTED, []);
    expect(ids(f)).toEqual(['integrity:protected-path']);
    expect(f[0]?.message).toMatch(/CODEOWNERS/);
  });
  it('integrity: CODEOWNERS read from base, PR edit to CODEOWNERS ignored: the PR cannot make its own author an owner', () => {
    // the base rules name alice only; the PR edits CODEOWNERS to add mallory (not visible here by design) and mallory approves
    const base = owners('* @alice\n');
    const f = integrityFindings(ctx({ files: [file('.github/CODEOWNERS'), file(WF)], approvals: ['mallory'] }), PROTECTED, base);
    expect(f.map((x) => x.file)).toEqual(['.github/CODEOWNERS', WF]);
  });
  it('each protected file needs an owner of THAT path: an owner of one path does not cover another', () => {
    const rules = owners('/.github/workflows/ @wf-owner\n/knip.json @knip-owner\n');
    const pr = ctx({ files: [file(WF), file('knip.json')], approvals: ['wf-owner'] });
    expect(integrityFindings(pr, PROTECTED, rules).map((f) => f.file)).toEqual(['knip.json']);
  });
  it('integrity: rename out of a protected path (previous_filename) blocks', () => {
    const f = integrityFindings(ctx({ files: [file('src/moved.yml', { status: 'renamed', previous_filename: WF, changes: 0, patch: undefined })] }), PROTECTED, OWNER_RULES);
    expect(ids(f)).toEqual(['integrity:protected-path']);
    expect(f[0]?.file).toBe(WF);
  });
  it('a rename INTO a protected path blocks, and a rename between two protected paths gives one finding per path', () => {
    expect(ids(integrityFindings(ctx({ files: [file(WF, { status: 'renamed', previous_filename: 'src/x.yml', changes: 0, patch: undefined })] }), PROTECTED, OWNER_RULES))).toEqual(['integrity:protected-path']);
    const both = integrityFindings(ctx({ files: [file('.github/workflows/b.yml', { status: 'renamed', previous_filename: WF, changes: 0, patch: undefined })] }), PROTECTED, OWNER_RULES);
    expect(both.map((f) => f.file)).toEqual(['.github/workflows/b.yml', WF]);
  });
  it('a rename out of a protected path is approved by the owner of the PREVIOUS path', () => {
    const rules = owners('/src/ @src-owner\n/.github/ @gh-owner\n');
    const pr = (who: string): PrContext => ctx({ approvals: [who], files: [file('src/moved.yml', { status: 'renamed', previous_filename: WF, changes: 0, patch: undefined })] });
    expect(integrityFindings(pr('src-owner'), PROTECTED, rules).length).toBe(1);
    expect(integrityFindings(pr('gh-owner'), PROTECTED, rules)).toEqual([]);
  });
  it('integrity: change to a declared tool config file (.gitleaks.toml) blocks, also biome.json, eslint.config.mjs, .prettierrc.json, .hadolint.yaml', () => {
    for (const f of ['.gitleaks.toml', 'biome.json', 'eslint.config.mjs', '.prettierrc.json', '.hadolint.yaml', 'knip.json', 'renovate.json', '.betterleaks.toml']) {
      expect(ids(integrityFindings(ctx({ files: [file(f)] }), PROTECTED, OWNER_RULES)), f).toContain('integrity:protected-path');
    }
  });
  it('protected paths match case-insensitively (a checkout on a case-folding file system loads them)', () => {
    for (const f of ['.GitHub/Workflows/Evil.YML', '.GITLEAKSIGNORE', 'Knip.JSON', 'codeowners']) {
      expect(ids(integrityFindings(ctx({ files: [file(f)] }), PROTECTED, OWNER_RULES)), f).toContain('integrity:protected-path');
    }
  });
  it('a file that is not protected gives no finding', () => {
    expect(integrityFindings(ctx({ files: [file('src/a.ts'), file('docs/readme.md')] }), PROTECTED, OWNER_RULES)).toEqual([]);
  });
  it('the CODEOWNERS lookup is case sensitive even though the protected match is not: a differently-cased path has no owner', () => {
    const f = integrityFindings(ctx({ files: [file('.GitHub/Workflows/x.yml')], approvals: ['alice'] }), PROTECTED, owners('/.github/ @alice\n'));
    expect(ids(f)).toEqual(['integrity:protected-path']);
  });
  it('the same file listed twice gives one finding per path', () => {
    expect(integrityFindings(ctx({ files: [file(WF), file(WF)] }), PROTECTED, OWNER_RULES).length).toBe(1);
  });
});

describe('integrityFindings: an incomplete list fails closed with no approval exception', () => {
  it('integrity: 3,000 files → fail closed (incomplete-list, critical), approved or not', () => {
    for (const approvals of [[], ['alice', 'bob']]) {
      const f = integrityFindings(ctx({ filesComplete: false, approvals }), PROTECTED, OWNER_RULES);
      expect(ids(f)).toContain('integrity:incomplete-list');
      expect(f.find((x) => x.ruleId === 'integrity:incomplete-list')?.severity).toBe('critical');
      expect(f.find((x) => x.ruleId === 'integrity:incomplete-list')?.message).toMatch(/split/i);
    }
  });
  it('an incomplete list still reports what it can see', () => {
    expect(ids(integrityFindings(ctx({ filesComplete: false, files: [file(WF)] }), PROTECTED, OWNER_RULES))).toEqual(['integrity:incomplete-list', 'integrity:protected-path']);
  });
  it('incomplete approvals: the approvals are already empty, so owners cannot waive anything', () => {
    expect(ids(integrityFindings(ctx({ approvalsComplete: false, approvals: [], files: [file(WF)] }), PROTECTED, OWNER_RULES))).toEqual(['integrity:protected-path']);
  });
});

describe('integrityFindings: patches', () => {
  it('integrity: text file without patch → fail closed; binary file without patch → no finding', () => {
    const noPatch = integrityFindings(ctx({ files: [file('src/big.ts', { changes: 5000, patch: undefined })] }), PROTECTED, OWNER_RULES);
    expect(ids(noPatch)).toEqual(['integrity:no-patch']);
    expect(noPatch[0]?.severity).toBe('critical');
    for (const f of ['logo.png', 'a/b/photo.JPG', 'font.woff2', 'x.zip', 'doc.pdf', 'lib.wasm', 'a.tar.gz']) {
      expect(integrityFindings(ctx({ files: [file(f, { changes: 0, patch: undefined })] }), PROTECTED, OWNER_RULES), f).toEqual([]);
      expect(integrityFindings(ctx({ files: [file(f, { changes: 9, patch: undefined })] }), PROTECTED, OWNER_RULES), f).toEqual([]);
    }
  });
  it('a lockfile without a patch is exempt; any other text file with changes and no patch fails closed; no changes and no patch (pure rename) is fine', () => {
    for (const f of ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'poetry.lock', 'uv.lock', 'Cargo.lock', 'go.sum', 'composer.lock', 'Gemfile.lock', 'sub/dir/package-lock.json']) {
      expect(integrityFindings(ctx({ files: [file(f, { changes: 4000, patch: undefined })] }), PROTECTED, OWNER_RULES), f).toEqual([]);
    }
    expect(ids(integrityFindings(ctx({ files: [file('lock.txt', { changes: 1, patch: undefined })] }), PROTECTED, OWNER_RULES))).toEqual(['integrity:no-patch']);
    expect(integrityFindings(ctx({ files: [file('b.ts', { status: 'renamed', previous_filename: 'a.ts', changes: 0, patch: undefined })] }), PROTECTED, OWNER_RULES)).toEqual([]);
    expect(ids(integrityFindings(ctx({ files: [file('x.ts', { changes: 1, patch: '' })] }), PROTECTED, OWNER_RULES))).toEqual(['integrity:no-patch']);
  });
  it('a no-patch file is waived by a code owner of that path (the approval exception)', () => {
    const f = file('src/big.ts', { changes: 5000, patch: undefined });
    expect(integrityFindings(ctx({ files: [f], approvals: ['alice'] }), PROTECTED, OWNER_RULES)).toEqual([]);
    expect(integrityFindings(ctx({ files: [f], approvals: ['bob'] }), PROTECTED, OWNER_RULES).length).toBe(1);
  });
});

describe('integrityFindings: suppressions', () => {
  const add = (text: string, over: Partial<PrFile> = {}): PrFile => file(over.filename ?? 'src/a.ts', { patch: `@@ -1,2 +1,3 @@\n keep\n+${text}\n keep2`, ...over });
  const found = (text: string, name = 'src/a.ts'): string[] => ids(integrityFindings(ctx({ files: [add(text, { filename: name })] }), PROTECTED, OWNER_RULES));
  it('integrity: added nosem → suppression finding; added nosemgrep → suppression finding', () => {
    expect(found('x() // nosem')).toEqual(['integrity:suppression']);
    expect(found('x() // nosemgrep: rule.id')).toEqual(['integrity:suppression']);
    expect(found('x() # NOSEMGREP')).toEqual(['integrity:suppression']);
  });
  it('the other markers: gitleaks:allow, trivy:ignore, noqa: S, eslint-disable, config comments, hadolint, kube-linter, mypy, nosec, checkov, tfsec', () => {
    for (const t of ['key = "x" # gitleaks:allow', '#trivy:ignore:AVD-DS-0002', 'x = 1  # noqa: S101', 'x = 1  # noqa: E501, S608', 'x = 1  # noqa', '// eslint-disable-next-line no-eval',
      '/* eslint-disable */', '/* eslint no-eval: 0 */', '# hadolint global ignore=DL3008', '# hadolint ignore=DL3008', 'ignore-check.kube-linter.io/privileged: "x"', '# mypy: ignore-errors',
      'x = 1  # nosec', '#checkov:skip=CKV_AWS_1', '#tfsec:ignore:aws-s3-x']) {
      expect(found(t), t).toEqual(['integrity:suppression']);
    }
  });
  it('things that are not suppressions give nothing: a plain line, noqa: E501, eslint-config in prose, a removed or context line with the marker', () => {
    expect(found('const a = 1;')).toEqual([]);
    expect(found('x = 1  # noqa: E501')).toEqual([]);
    const removed = file('src/a.ts', { patch: '@@ -1,3 +1,2 @@\n keep\n- // nosemgrep\n keep2' });
    const context = file('src/a.ts', { patch: '@@ -1,2 +1,3 @@\n keep\n+new\n // nosemgrep' });
    expect(integrityFindings(ctx({ files: [removed, context] }), PROTECTED, OWNER_RULES)).toEqual([]);
  });
  it('a suppression hidden deep in a multi-line patch hunk is found, with its new-file line number', () => {
    const body = Array.from({ length: 60 }, (_, i) => ` ctx${i}`).join('\n');
    const patch = `@@ -10,60 +10,61 @@\n${body}\n+  eval(x) // nosemgrep\n`;
    const f = integrityFindings(ctx({ files: [file('src/a.ts', { patch })] }), PROTECTED, OWNER_RULES);
    expect(ids(f)).toEqual(['integrity:suppression']);
    expect(f[0]).toMatchObject({ severity: 'high', file: 'src/a.ts', line: 70 });
  });
  it('a marker on an added line whose content starts with ++ or -- is still an added line (the patch has no file headers)', () => {
    expect(found('++ nosemgrep')).toEqual(['integrity:suppression']);
    const p = file('src/a.ts', { patch: '@@ -1,2 +1,2 @@\n keep\n-- nosemgrep\n+ok' });   // a removed line whose text starts with -
    expect(integrityFindings(ctx({ files: [p] }), PROTECTED, OWNER_RULES)).toEqual([]);
  });
  it('a malformed patch is still scanned line by line for markers, and is itself a finding', () => {
    const f = integrityFindings(ctx({ files: [file('src/a.ts', { patch: 'garbage\n+x // nosemgrep\n@@ nonsense' })] }), PROTECTED, OWNER_RULES);
    expect(ids(f)).toContain('integrity:suppression');
    expect(ids(f)).toContain('integrity:no-patch');
  });
  it('integrity: new line in .gitleaksignore → suppression finding (plus the protected-path finding); nested and other ignore files too', () => {
    const f = integrityFindings(ctx({ files: [add('src/a.ts:some-rule:4', { filename: '.gitleaksignore' })] }), PROTECTED, OWNER_RULES);
    expect(ids(f).sort()).toEqual(['integrity:protected-path', 'integrity:suppression']);
    for (const n of ['.semgrepignore', '.trivyignore', '.trivyignore.yaml']) expect(ids(integrityFindings(ctx({ files: [add('CVE-2024-1', { filename: n })] }), PROTECTED, OWNER_RULES)), n).toContain('integrity:suppression');
    // removing a line from an ignore file adds no suppression
    const removed = file('.gitleaksignore', { patch: '@@ -1,2 +1 @@\n-x\n keep' });
    expect(ids(integrityFindings(ctx({ files: [removed] }), PROTECTED, OWNER_RULES))).toEqual(['integrity:protected-path']);
  });
  it('a suppression is waived by a code owner of that file, with the same exception as a protected path', () => {
    expect(integrityFindings(ctx({ files: [add('x // nosemgrep')], approvals: ['alice'] }), PROTECTED, OWNER_RULES)).toEqual([]);
    expect(integrityFindings(ctx({ files: [add('x // nosemgrep')], approvals: ['mallory'] }), PROTECTED, OWNER_RULES).length).toBe(1);
  });
  it('one finding per file and kind however many lines match, and the message never repeats repo text', () => {
    const lines = Array.from({ length: 40 }, () => '+x // nosemgrep <script>alert(1)</script>').join('\n');
    const f = integrityFindings(ctx({ files: [file('src/a.ts', { patch: `@@ -1 +1,40 @@\n${lines}\n-old`.replace('+1,40', '+1,40') })] }), PROTECTED, OWNER_RULES);
    expect(f.filter((x) => x.ruleId === 'integrity:suppression').length).toBe(1);
    expect(JSON.stringify(f)).not.toMatch(/script/);
  });
  it('the findings are the same for the same input (deterministic fingerprints)', () => {
    const pr = ctx({ files: [file(WF), add('x // nosemgrep')] });
    expect(integrityFindings(pr, PROTECTED, OWNER_RULES)).toEqual(integrityFindings(pr, PROTECTED, OWNER_RULES));
  });
});

// ---------- baseHasInstall ----------

describe('baseHasInstall', () => {
  it("baseHasInstall: decided by the base commit's files, not the branch name", async () => {
    const g = new Gh();
    g.contents.set(`${BASE}:${WF}`, contentOf('name: pipegen\n'));
    expect(await baseHasInstall(g, REPO, BASE)).toBe(true);
    expect(g.calls).toEqual([`file b:${WF}`]);
    // the head has the file and the base does not (the setup PR): false, whatever the branch is called
    const h = new Gh();
    h.contents.set(`${HEAD}:${WF}`, contentOf('name: pipegen\n'));
    expect(await baseHasInstall(h, REPO, BASE)).toBe(false);
    expect(h.calls).toEqual([`file b:${WF}`]);
  });
  it('baseHasInstall: API error other than 404 → true (fail closed)', async () => {
    for (const e of [new Error('500'), new Error('rate limited')]) {
      const g = new Gh(); g.contents.set(`${BASE}:${WF}`, e);
      expect(await baseHasInstall(g, REPO, BASE)).toBe(true);
    }
  });
  it('a 404 (null) is false; any other answer, even a malformed one, is true; a bad sha is true without a call', async () => {
    expect(await baseHasInstall(new Gh(), REPO, BASE)).toBe(false);
    for (const a of ['x', {}, [], { type: 'dir' }, 5]) {
      const g = new Gh(); g.contents.set(`${BASE}:${WF}`, a);
      expect(await baseHasInstall(g, REPO, BASE), JSON.stringify(a)).toBe(true);
    }
    const g = new Gh();
    expect(await baseHasInstall(g, REPO, 'main')).toBe(true);
    expect(g.calls).toEqual([]);
  });
});

// ---------- addedLines and the PR diff ----------

const HUNKS = '@@ -3,4 +3,5 @@ fn\n ctx3\n-old4\n+new4\n+new5\n ctx6\n ctx7\n@@ -20,2 +21,3 @@\n c21\n+n22\n c23';
describe('addedLines', () => {
  it('addedLines: maps + lines from patch hunks to new line numbers', () => {
    const r = addedLinesOf([file('a.ts', { patch: HUNKS })]);
    expect(r.complete).toBe(true);
    expect([...(r.added.get('a.ts') ?? [])]).toEqual([4, 5, 22]);
  });
  it('"\\ No newline at end of file" lines and a leading hunk at line 0 are handled; counts default to 1', () => {
    const r = addedLinesOf([file('a.ts', { patch: '@@ -0,0 +1,2 @@\n+l1\n+l2\n\\ No newline at end of file' }), file('b.ts', { patch: '@@ -1 +1 @@\n-x\n+y\n\\ No newline at end of file' })]);
    expect([...(r.added.get('a.ts') ?? [])]).toEqual([1, 2]);
    expect([...(r.added.get('b.ts') ?? [])]).toEqual([1]);
    expect(r.complete).toBe(true);
  });
  it('lines that look like hunk headers or file headers inside a hunk body are content, counted by the hunk header', () => {
    const r = addedLinesOf([file('a.ts', { patch: '@@ -1,2 +1,3 @@\n keep\n+@@ -9 +9 @@\n+++ b/x\n-gone\n' })]);
    // +@@... is added line 2, +++ b/x is added line 3; -gone removed
    expect([...(r.added.get('a.ts') ?? [])]).toEqual([2, 3]);
    expect(r.complete).toBe(true);
  });
  it('a patch that does not match its hunk counts, or has junk before a header, makes the result incomplete (never a guess)', () => {
    for (const patch of ['@@ -1,2 +1,2 @@\n a', '@@ -1 +1,5 @@\n+a\n+b', 'junk\n@@ -1 +1 @@\n+a', '@@ bad @@\n+a', '@@ -1 +1 @@\n+a\n+b', '@@ -1 +1 @@\n\n+a']) {
      expect(addedLinesOf([file('a.ts', { patch })]).complete, patch).toBe(false);
    }
  });
  it('a text file with changes and no patch makes it incomplete; a binary file does not; a removed file adds nothing', () => {
    expect(addedLinesOf([file('big.ts', { changes: 9, patch: undefined })]).complete).toBe(false);
    expect(addedLinesOf([file('logo.png', { changes: 0, patch: undefined })]).complete).toBe(true);
    expect(addedLinesOf([file('logo.png', { changes: 9, patch: undefined })]).complete).toBe(false);   // the name is the author's choice (review 16)
    expect(addedLinesOf([file('huge.ts', { status: 'removed', changes: 90000, patch: undefined })]).complete).toBe(true);
    const r = addedLinesOf([file('gone.ts', { status: 'removed', patch: '@@ -1,2 +0,0 @@\n-a\n-b' })]);
    expect(r.complete).toBe(true);
    expect(r.added.get('gone.ts')).toBeUndefined();
  });
  it('a renamed file is keyed by its new name; a file seen twice merges its lines', () => {
    const r = addedLinesOf([file('new.ts', { status: 'renamed', previous_filename: 'old.ts', patch: '@@ -1 +1 @@\n-a\n+b' }), file('new.ts', { patch: '@@ -5 +5 @@\n-a\n+b' })]);
    expect([...(r.added.get('new.ts') ?? [])]).toEqual([1, 5]);
    expect(r.added.has('old.ts')).toBe(false);
  });
  it('a hostile patch is bounded: an over-long patch is incomplete, not parsed', () => {
    expect(addedLinesOf([file('a.ts', { patch: `@@ -1 +1,3000000 @@\n${'+a\n'.repeat(3_000_000)}` })]).complete).toBe(false);
  });
});

describe('buildPrDiff: the diff of the scanned commit, from the compare API', () => {
  const entry = (name: string, patch: string | null = '@@ -1 +1,2 @@\n a\n+b'): Record<string, unknown> => ({ filename: name, status: 'modified', changes: 1, ...(patch === null ? {} : { patch }) });
  it('compares base...github.sha, takes the lines of THAT compare, and sets commit = the head sha', async () => {
    const g = new Gh(); g.cmp = { status: 'ahead', files: [entry('a.ts')] };
    const d = await buildPrDiff(g, REPO, BASE, HEAD);
    expect(g.calls).toEqual(['compare b...a']);
    expect(d.commit).toBe(HEAD);
    expect(d.complete).toBe(true);
    expect([...(d.added.get('a.ts') ?? [])]).toEqual([2]);
  });
  it('merge_group: the same call with base_sha and head_sha', async () => {
    const g = new Gh(); g.cmp = { status: 'ahead', files: [entry('a.ts')] };
    const d = await buildPrDiff(g, REPO, SHA('c'), SHA('d'));
    expect(g.calls).toEqual(['compare c...d']);
    expect(d.commit).toBe(SHA('d'));
  });
  it('one call only: the API shows the files on the first page, up to 300; 299 files are complete and the compare is never paged', async () => {
    const g = new Gh(); g.cmp = { status: 'ahead', files: many(299, (i) => entry(`f${i}.ts`)) };
    const d = await buildPrDiff(g, REPO, BASE, HEAD);
    expect(d.complete).toBe(true);
    expect(d.added.size).toBe(299);
    expect(g.calls.length).toBe(1);
  });
  it('300 files or more is the API cap: incomplete (a truncation cannot pass as complete)', async () => {
    for (const n of [300, 301, 3000]) {
      const g = new Gh(); g.cmp = { status: 'ahead', files: many(n, (i) => entry(`f${i}.ts`)) };
      const d = await buildPrDiff(g, REPO, BASE, HEAD);
      expect(d.complete, String(n)).toBe(false);
      expect(g.calls.length, String(n)).toBe(1);
    }
  });
  it('missing patches, a malformed file, a non-array, an error, a missing status, or a head that is not ahead of the base → incomplete', async () => {
    const cases: unknown[] = [
      { status: 'ahead', files: [entry('big.ts', null)] }, { status: 'ahead', files: [{ filename: 5 }] }, { status: 'ahead', files: 'x' }, { status: 'ahead' },
      new Error('500'), { files: [entry('a.ts')] }, { status: 'diverged', files: [entry('a.ts')] }, { status: 'behind', files: [] }, 'x', null,
    ];
    for (const c of cases) {
      const g = new Gh(); g.cmp = c as never;
      const d = await buildPrDiff(g, REPO, BASE, HEAD);
      expect(d.complete, JSON.stringify(c)).toBe(false);
      expect(d.commit, JSON.stringify(c)).toBe(HEAD);
    }
  });
  it('identical (no changes) is complete and empty; a base or head that is not 40-hex is refused without a call', async () => {
    const g = new Gh(); g.cmp = { status: 'identical', files: [] };
    const d = await buildPrDiff(g, REPO, BASE, HEAD);
    expect(d.complete).toBe(true); expect(d.added.size).toBe(0);
    const h = new Gh();
    expect((await buildPrDiff(h, REPO, 'main', HEAD)).complete).toBe(false);
    expect(h.calls).toEqual([]);
  });
  it("the PR's own patches are never the source: readPrContext files carry patches in head numbering, buildPrDiff ignores them", async () => {
    const g = new Gh(); g.cmp = { status: 'ahead', files: [entry('a.ts', '@@ -1 +40,2 @@\n a\n+b')] };
    const d = await buildPrDiff(g, REPO, BASE, HEAD);
    expect([...(d.added.get('a.ts') ?? [])]).toEqual([41]);
  });
});

// ---------- configSections ----------

describe('configSections: a change inside a section of a shared file is protected, a change elsewhere is not', () => {
  const SECTIONS = ['pyproject.toml:tool.mypy', 'setup.cfg:mypy', 'setup.cfg:mypy-*', 'setup.cfg:coverage:*', 'package.json:prettier', 'package.json:c8'];
  const put = (g: Gh, ref: string, path: string, text: string): void => { g.contents.set(`${ref}:${path}`, contentOf(text)); };
  const run = (g: Gh, files: PrFile[]) => readConfigSections(g, REPO, ctx({ files }), SECTIONS, PROTECTED);
  const PY0 = '[project]\nname = "x"\n\n[tool.mypy]\nstrict = true\n\n[tool.ruff]\nline-length = 100\n';
  it('integrity: a change inside [tool.mypy] of pyproject.toml → one change; a change elsewhere in that file → none', async () => {
    const g = new Gh(); put(g, BASE, 'pyproject.toml', PY0); put(g, HEAD, 'pyproject.toml', PY0.replace('strict = true', 'strict = false'));
    const r = await run(g, [file('pyproject.toml')]);
    expect(r).toEqual([{ file: 'pyproject.toml', section: 'tool.mypy' }]);
    const h = new Gh(); put(h, BASE, 'pyproject.toml', PY0); put(h, HEAD, 'pyproject.toml', PY0.replace('line-length = 100', 'line-length = 120').replace('name = "x"', 'name = "y"'));
    expect(await run(h, [file('pyproject.toml')])).toEqual([]);
  });
  it('a sub-table of the section counts; removing or adding the section counts; reformatting or comments do not', async () => {
    const sub = new Gh(); put(sub, BASE, 'pyproject.toml', PY0); put(sub, HEAD, 'pyproject.toml', PY0 + '\n[tool.mypy.overrides]\nignore_errors = true\n');
    expect((await run(sub, [file('pyproject.toml')])).map((c) => c.section)).toEqual(['tool.mypy']);
    const rm = new Gh(); put(rm, BASE, 'pyproject.toml', PY0); put(rm, HEAD, 'pyproject.toml', '[project]\nname = "x"\n');
    expect((await run(rm, [file('pyproject.toml')])).length).toBe(1);
    const add = new Gh(); put(add, BASE, 'pyproject.toml', '[project]\nname = "x"\n'); put(add, HEAD, 'pyproject.toml', PY0);
    expect((await run(add, [file('pyproject.toml')])).length).toBe(1);
    const fmt = new Gh(); put(fmt, BASE, 'pyproject.toml', PY0); put(fmt, HEAD, 'pyproject.toml', '# note\n' + PY0.replace('strict = true', 'strict   =   true  # same'));
    expect(await run(fmt, [file('pyproject.toml')])).toEqual([]);
  });
  it('package.json: a change to the prettier key counts, to scripts does not; setup.cfg sections match with * (mypy-*, coverage:*)', async () => {
    const g = new Gh();
    put(g, BASE, 'package.json', '{"name":"x","scripts":{"a":"b"},"prettier":{"semi":true}}'); put(g, HEAD, 'package.json', '{"name":"x","scripts":{"a":"c"},"prettier":{"semi":false}}');
    expect((await run(g, [file('package.json')])).map((c) => c.section)).toEqual(['prettier']);
    const h = new Gh();
    put(h, BASE, 'package.json', '{"name":"x","scripts":{"a":"b"},"prettier":{"semi":true}}'); put(h, HEAD, 'package.json', '{"name":"x","scripts":{"a":"c"},"prettier":{"semi":true}}');
    expect(await run(h, [file('package.json')])).toEqual([]);
    const c = new Gh();
    put(c, BASE, 'setup.cfg', '[metadata]\nname = x\n[mypy-foo.*]\nignore_errors = False\n[coverage:run]\nbranch = True\n[flake8]\nmax = 1\n');
    put(c, HEAD, 'setup.cfg', '[metadata]\nname = y\n[mypy-foo.*]\nignore_errors = True\n[coverage:run]\nbranch = False\n[flake8]\nmax = 2\n');
    expect((await run(c, [file('setup.cfg')])).map((x) => x.section).sort()).toEqual(['coverage:run', 'mypy-foo.*']);
    const d = new Gh();
    put(d, BASE, 'setup.cfg', '[metadata]\nname = x\n[flake8]\nmax = 1\n'); put(d, HEAD, 'setup.cfg', '[metadata]\nname = y\n[flake8]\nmax = 2\n');
    expect(await run(d, [file('setup.cfg')])).toEqual([]);
  });
  it('an unparsable file (either side) is a change with a problem, never a pass', async () => {
    const g = new Gh(); put(g, BASE, 'pyproject.toml', PY0); put(g, HEAD, 'pyproject.toml', '[tool.mypy\nstrict = true');
    const r = await run(g, [file('pyproject.toml')]);
    expect(r.length).toBe(1);
    expect(r[0]?.problem).toBeTypeOf('string');
    const h = new Gh(); put(h, BASE, 'package.json', '{'); put(h, HEAD, 'package.json', '{"prettier":{}}');
    expect((await run(h, [file('package.json')]))[0]?.problem).toBeTypeOf('string');
  });
  it('an API error, a file over 1 MiB, or an unknown file type is a change with a problem', async () => {
    const e = new Gh(); put(e, BASE, 'pyproject.toml', PY0); e.contents.set(`${HEAD}:pyproject.toml`, new Error('500'));
    expect((await run(e, [file('pyproject.toml')]))[0]?.problem).toBeTypeOf('string');
    const big = new Gh(); put(big, BASE, 'pyproject.toml', PY0); big.contents.set(`${HEAD}:pyproject.toml`, { type: 'file', encoding: 'none', size: 2_000_000, content: '' });
    expect((await run(big, [file('pyproject.toml')]))[0]?.problem).toBeTypeOf('string');
  });
  it('a file that matches no section file is not fetched; a file already protected as a whole is not fetched either', async () => {
    const g = new Gh();
    await readConfigSections(g, REPO, ctx({ files: [file('src/a.ts'), file('mypy.ini'), file('pyproject.toml')] }), ['pyproject.toml:tool.mypy'], ['pyproject.toml']);
    expect(g.calls).toEqual([]);
  });
  it('a rename OUT of the place a tool reads a shared config file from is a finding even when the file is unchanged; the new path is compared as an addition (fix round 1, review 6)', async () => {
    const g = new Gh(); put(g, BASE, 'pyproject.toml', PY0); put(g, HEAD, 'other/p.toml', '[project]\nname="x"\n');
    const r = await run(g, [file('other/p.toml', { status: 'renamed', previous_filename: 'pyproject.toml', changes: 0, patch: undefined })]);
    expect(r).toEqual([{ file: 'pyproject.toml', section: '(file moved)' }]);
    const same = new Gh(); put(same, BASE, 'setup.cfg', '[mypy]\nstrict = True\n'); put(same, HEAD, 'old/setup.cfg', '[mypy]\nstrict = True\n');
    const r2 = await run(same, [file('old/setup.cfg', { status: 'renamed', previous_filename: 'setup.cfg', changes: 0, patch: undefined })]);
    expect(r2.map((c) => [c.file, c.section]).sort()).toEqual([['old/setup.cfg', 'mypy'], ['setup.cfg', '(file moved)']]);
    const d = new Gh(); put(d, BASE, 'pyproject.toml', PY0);
    expect((await run(d, [file('pyproject.toml', { status: 'removed' })])).length).toBe(1);
    expect(d.calls).toEqual(['file b:pyproject.toml']);
  });
  it('a renamed config file with a change needs BOTH owners: the owner of the new path alone does not waive it', async () => {
    const same = new Gh(); put(same, BASE, 'setup.cfg', '[mypy]\nstrict = True\n'); put(same, HEAD, 'old/setup.cfg', '[mypy]\nignore_errors = True\n');
    const files = [file('old/setup.cfg', { status: 'renamed', previous_filename: 'setup.cfg' })];
    const changes = await run(same, files);
    const rules = owners('/old/ @mallory\n/setup.cfg @admin\n');
    const by = (who: string[]) => integrityFindings(ctx({ files, approvals: who }), PROTECTED, rules, { sectionChanges: changes }).map((f) => f.file);
    expect(by(['mallory'])).toEqual(['setup.cfg']);
    expect(by(['admin'])).toEqual(['old/setup.cfg']);
    expect(by(['admin', 'mallory'])).toEqual([]);
  });
  it('a mutation hidden by the matching being case-insensitive: PyProject.TOML is checked too', async () => {
    const g = new Gh(); put(g, BASE, 'PyProject.TOML', PY0); put(g, HEAD, 'PyProject.TOML', PY0.replace('true', 'false'));
    expect((await run(g, [file('PyProject.TOML')])).length).toBe(1);
  });
  it('the section changes become integrity:protected-path findings, waived by an owner of the file', () => {
    const changes = [{ file: 'pyproject.toml', section: 'tool.mypy' }, { file: 'package.json', section: 'prettier', problem: 'unparsable' }];
    const f = integrityFindings(ctx({ files: [file('pyproject.toml'), file('package.json')] }), PROTECTED, OWNER_RULES, { sectionChanges: changes });
    expect(f.map((x) => [x.ruleId, x.file])).toEqual([['integrity:protected-path', 'pyproject.toml'], ['integrity:protected-path', 'package.json']]);
    expect(integrityFindings(ctx({ files: [], approvals: ['alice'] }), PROTECTED, OWNER_RULES, { sectionChanges: changes })).toEqual([]);
    expect(f[0]?.message).toMatch(/tool\.mypy/);
  });
});

describe('hostile input never throws', () => {
  it('random file names, patches and CODEOWNERS text give findings or nothing, never an exception', () => {
    let seed = 12345;
    const rnd = (n: number): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const alphabet = ['a', '/', '.', '*', '?', '\\', '@', ' ', '\n', '+', '-', '#', '[', '!', '\u0000', 'Ω', '%'];
    const junk = (n: number): string => Array.from({ length: rnd(n) }, () => alphabet[rnd(alphabet.length)]).join('');
    for (let i = 0; i < 300; i++) {
      const rules = codeOwners(`${junk(40)}\n${junk(40)} @a ${junk(10)}\n`);
      const files = [file(junk(30) || 'x', { patch: `@@ -1 +1 @@\n${junk(50)}`, previous_filename: junk(10) || undefined })];
      expect(() => integrityFindings(ctx({ files, approvals: ['a'] }), PROTECTED, rules)).not.toThrow();
      expect(() => ownersOf(rules, junk(30))).not.toThrow();
      expect(() => addedLinesOf(files)).not.toThrow();
    }
  });
});

// ======================= fix round 1 (review-C4.md, rulings in task-C4-fix-round-1.md) =======================
import { readFileSync } from 'node:fs';

describe('fix round 1 (1): a slashless protected name is protected at any depth', () => {
  const P = [...PROTECTED, '.bandit', 'mypy.ini', '.coveragerc', 'ruff.toml'];
  it('tests/fixtures/.bandit, services/api/mypy.ini and the rest are protected', () => {
    for (const f of ['tests/fixtures/.bandit', '.bandit', 'services/api/mypy.ini', 'a/b/c/.coveragerc', 'x/.gitleaksignore', 'x/Eslint.Config.mjs', 'web/.prettierrc.json', 'a/Knip.JSON']) {
      expect(ids(integrityFindings(ctx({ files: [file(f)] }), P, OWNER_RULES)), f).toContain('integrity:protected-path');
    }
  });
  it('an entry with a slash stays anchored: x/.github/workflows/a.yml is not the workflow folder; .gitignore is not in the list', () => {
    expect(integrityFindings(ctx({ files: [file('x/.github/workflows/a.yml'), file('src/.gitignore')] }), P, OWNER_RULES)).toEqual([]);
  });
  it('the shared-file part of a configSection also matches at any depth', async () => {
    const g = new Gh();
    g.contents.set(`${BASE}:services/api/pyproject.toml`, contentOf('[tool.mypy]\nstrict = true\n'));
    g.contents.set(`${HEAD}:services/api/pyproject.toml`, contentOf('[tool.mypy]\nstrict = false\n'));
    const r = await readConfigSections(g, REPO, ctx({ files: [file('services/api/pyproject.toml')] }), ['pyproject.toml:tool.mypy'], []);
    expect(r).toEqual([{ file: 'services/api/pyproject.toml', section: 'tool.mypy' }]);
  });
  it('the base list protects the Renovate files (review 15)', () => {
    for (const f of ['renovate.json', 'renovate.json5', '.renovaterc', '.renovaterc.json', '.renovaterc.json5', '.github/renovate.json', '.github/renovate.json5']) {
      expect(ids(integrityFindings(ctx({ files: [file(f)] }), PROTECTED_PATHS_BASE, OWNER_RULES)), f).toContain('integrity:protected-path');
    }
  });
});

describe('fix round 1 (2, 17): an approval counts only from a user with write access, never from the author', () => {
  const run = async (perm: Answer, who = 'alice'): Promise<PrContext> => {
    const g = ghWith([]); g.reviews = [review(1, who, 'APPROVED')]; g.perms.set(who, perm);
    return readPrContext(g, REPO, 5);
  };
  it('write, admin and maintain count', async () => {
    expect((await run({ permission: 'write' })).approvals).toEqual(['alice']);
    expect((await run({ permission: 'admin' })).approvals).toEqual(['alice']);
    expect((await run({ permission: 'read', role_name: 'maintain' })).approvals).toEqual(['alice']);
  });
  it('a read-only owner, a non-collaborator (a renamed-owner squatter), triage and a malformed answer do not', async () => {
    for (const a of [{ permission: 'read' }, { permission: 'none' }, { permission: 'read', role_name: 'triage' }, {}, 'write', null, { permission: 'WRITE' }]) {
      expect((await run(a)).approvals, JSON.stringify(a)).toEqual([]);
    }
  });
  it('an API error (404, 403, 5xx) means the approval does not count', async () => {
    for (const e of [new Error('404'), new Error('403'), new Error('500')]) expect((await run(e)).approvals).toEqual([]);
  });
  it('end to end: the squatter approves the workflow change and it still blocks', async () => {
    const g = ghWith([file(WF)]); g.reviews = [review(1, 'alice', 'APPROVED')]; g.perms.set('alice', { permission: 'none' });
    const pr = await readPrContext(g, REPO, 5);
    expect(ids(integrityFindings(pr, PROTECTED, OWNER_RULES))).toEqual(['integrity:protected-path']);
  });
  it('each approver is checked once, only approvers are checked, and no check is made when the reviews are incomplete', async () => {
    const g = ghWith([]); g.reviews = [review(1, 'a', 'APPROVED'), review(2, 'a', 'COMMENTED'), review(3, 'b', 'COMMENTED'), review(4, 'c', 'CHANGES_REQUESTED'), review(5, 'd', 'APPROVED')];
    await readPrContext(g, REPO, 5);
    expect(g.calls.filter((c) => c.startsWith('perm')).sort()).toEqual(['perm a', 'perm d']);
    const e = ghWith([]); e.reviews = new Error('500');
    await readPrContext(e, REPO, 5);
    expect(e.calls.filter((c) => c.startsWith('perm'))).toEqual([]);
  });
  it('the author is never an approver, whatever the review says (review 17)', async () => {
    const g = ghWith([]); g.reviews = [review(1, 'Author', 'APPROVED'), review(2, 'alice', 'APPROVED')];
    expect((await readPrContext(g, REPO, 5)).approvals).toEqual(['alice']);
  });
});

describe('fix round 1 (3, 4): INI parsing is configparser (Python 3.12 oracle, test/fixtures/gate-integrity/oracle.json)', () => {
  const oracle = JSON.parse(readFileSync('test/fixtures/gate-integrity/oracle.json', 'utf8')) as {
    ini: Record<string, { text: string; sections: Record<string, Record<string, string>> | null; failClosed?: boolean }>;
    toml: Record<string, { text: string; value: unknown }>; toml_bad: Record<string, string>;
  };
  for (const [name, c] of Object.entries(oracle.ini)) {
    it(`ini ${name}: ${c.sections === null ? 'configparser rejects it, so do we' : c.failClosed === true ? 'Python reads it, JavaScript would read it differently: fail closed' : 'the same sections and values as configparser'}`, () => {
      const got = parseConfigDoc('setup.cfg', c.text);
      if (c.sections === null || c.failClosed === true) expect(got).toBeUndefined();
      else expect(got).toEqual(c.sections);
    });
  }
  const put = (g: Gh, ref: string, path: string, text: string): void => { g.contents.set(`${ref}:${path}`, contentOf(text)); };
  const secs = async (base: string, head: string): Promise<{ section: string; problem?: string }[]> => {
    const g = new Gh(); put(g, BASE, 'setup.cfg', base); put(g, HEAD, 'setup.cfg', head);
    return readConfigSections(g, REPO, ctx({ files: [file('setup.cfg')] }), ['setup.cfg:mypy', 'setup.cfg:mypy-*'], []);
  };
  it('review 3: [mypy]x = 1 is the header of section mypy (the rest of the line is ignored): the change is seen', async () => {
    const r = await secs('[metadata]\nname = x\n', '[metadata]\nname = x\n[mypy]x = 1\nignore_errors = True\n');
    expect(r.map((c) => c.section)).toEqual(['mypy']);
  });
  it('review 3: [mypy] ; c is a header too, not a parse failure', async () => {
    const r = await secs('[metadata]\nname = x\n', '[metadata]\nname = x\n[mypy] ; c\nignore_errors = True\n');
    expect(r).toEqual([{ file: 'setup.cfg', section: 'mypy' }]);
  });
  it('review 4: a change to [DEFAULT] is a change to every watched section', async () => {
    const r = await secs('[mypy]\nstrict = True\n', '[DEFAULT]\nignore_errors = True\n[mypy]\nstrict = True\n');
    expect(r).toEqual([{ file: 'setup.cfg', section: 'mypy' }]);
    expect(await secs('[mypy]\nstrict = True\n[other]\nx = 1\n', '[DEFAULT]\nignore_errors = True\n[mypy]\nstrict = True\n[other]\nx = 1\n')).toHaveLength(1);
  });
  it('review 4: a DEFAULT change with no watched section in either file is nothing; an own key overrides the default value', async () => {
    expect(await secs('[flake8]\nx = 1\n', '[DEFAULT]\nignore_errors = True\n[flake8]\nx = 1\n')).toEqual([]);
    expect(await secs('[mypy]\nignore_errors = False\n', '[DEFAULT]\nignore_errors = True\n[mypy]\nignore_errors = False\n')).toEqual([]);
  });
});

describe('fix round 1 (5): TOML keys are canonical paths (tomllib oracle)', () => {
  const oracle = JSON.parse(readFileSync('test/fixtures/gate-integrity/oracle.json', 'utf8')) as {
    toml: Record<string, { text: string; value: unknown }>; toml_bad: Record<string, string>;
  };
  for (const [name, c] of Object.entries(oracle.toml)) {
    it(`toml ${name}: the same document as tomllib`, () => { expect(plain(parseConfigDoc('pyproject.toml', c.text))).toEqual(c.value); });
  }
  for (const [name, text] of Object.entries(oracle.toml_bad)) {
    it(`toml ${name}: tomllib rejects it, so do we`, () => { expect(parseConfigDoc('pyproject.toml', text)).toBeUndefined(); });
  }
  const put = (g: Gh, ref: string, path: string, text: string): void => { g.contents.set(`${ref}:${path}`, contentOf(text)); };
  const secs = async (base: string, head: string) => {
    const g = new Gh(); put(g, BASE, 'pyproject.toml', base); put(g, HEAD, 'pyproject.toml', head);
    return readConfigSections(g, REPO, ctx({ files: [file('pyproject.toml')] }), ['pyproject.toml:tool.mypy'], []);
  };
  it('a literal "tool.mypy" key beside the table [tool.mypy] is a different key (fix round 2): only the table counts', async () => {
    const r = await secs('[tool.mypy]\nstrict = true\n', 'tool.x = 1\n"tool.mypy" = { strict = true }\n[tool.mypy]\nignore_errors = true\n');
    expect(r).toEqual([{ file: 'pyproject.toml', section: 'tool.mypy' }]);
    expect(await secs('[tool.mypy]\nstrict = true\n', 'tool.x = 1\n"tool.mypy" = { strict = false }\n[tool.mypy]\nstrict = true\n')).toEqual([]);
  });
  it('a dotted literal key that collides with nothing is not a problem and not a change', async () => {
    expect(await secs('[tool.mypy]\nstrict = true\n', '"a.b" = 1\n[tool.mypy]\nstrict = true\n')).toEqual([]);
  });
  it('x = inf to x = nan is a change; so is -inf', async () => {
    expect((await secs('[tool.mypy]\nx = inf\n', '[tool.mypy]\nx = nan\n')).map((c) => c.section)).toEqual(['tool.mypy']);
    expect((await secs('[tool.mypy]\nx = inf\n', '[tool.mypy]\nx = -inf\n')).length).toBe(1);
    expect(await secs('[tool.mypy]\nx = inf\n', '[tool.mypy]\nx = inf\n')).toEqual([]);
  });
  it('dotted keys, inline tables, quoted keys, \\u escapes and arrays of tables all reach [tool.mypy]', async () => {
    const base = '[tool.mypy]\nstrict = true\n';
    for (const head of ['tool.mypy.strict = true\ntool.mypy.ignore_errors = true\n', '[tool]\nmypy = { strict = true, ignore_errors = true }\n', '["tool"."mypy"]\nstrict = true\nignore_errors = true\n',
      '[tool."my\\u0070y"]\nstrict = true\nignore_errors = true\n', '[tool.mypy]\nstrict = true\n[[tool.mypy.overrides]]\nmodule = "a"\n']) {
      expect((await secs(base, head)).map((c) => c.section), head).toEqual(['tool.mypy']);
    }
  });
});

describe('fix round 1 (8, 7): compare is not paged; a moved head is incomplete', () => {
  it('a file with a binary-looking name but changes and no patch makes the diff incomplete (the author picks the name)', async () => {
    const g = new Gh(); g.cmp = { status: 'ahead', files: [{ filename: 'x.png', status: 'modified', changes: 5 }] };
    expect((await buildPrDiff(g, REPO, BASE, HEAD)).complete).toBe(false);
  });
  it('the integrity side keeps the binary exemption, and a removed file with no patch needs none', () => {
    expect(integrityFindings(ctx({ files: [file('x.png', { changes: 5, patch: undefined }), file('big.ts', { status: 'removed', changes: 99999, patch: undefined })] }), PROTECTED, OWNER_RULES)).toEqual([]);
  });
});

describe('fix round 1 (10, 11, 12): messages, markers, next-line markers, CODEOWNERS size', () => {
  const add = (text: string, filename = 'src/a.py'): PrFile => file(filename, { patch: `@@ -1,2 +1,3 @@\n keep\n+${text}\n keep2` });
  const found = (text: string): string[] => ids(integrityFindings(ctx({ files: [add(text)] }), PROTECTED, OWNER_RULES));
  it('a path owned only by a team says so and tells the author to name a user; no CODEOWNERS and unreadable CODEOWNERS say different things', () => {
    const team = integrityFindings(ctx({ files: [file(WF)] }), PROTECTED, owners('* @org/team\n'));
    expect(team[0]?.message).toMatch(/team/i);
    expect(team[0]?.message).toMatch(/name a user/i);
    const none = integrityFindings(ctx({ files: [file(WF)] }), PROTECTED, [], { codeowners: { found: null } });
    expect(none[0]?.message).toMatch(/no CODEOWNERS/i);
    const bad = integrityFindings(ctx({ files: [file(WF)] }), PROTECTED, [], { codeowners: { found: null, problem: 'CODEOWNERS of the base commit could not be read (x)' } });
    expect(bad[0]?.message).toMatch(/could not be read/i);
    expect(bad[0]?.message).not.toMatch(/has no CODEOWNERS/i);
    const empty = integrityFindings(ctx({ files: [file(WF)] }), PROTECTED, [], { codeowners: { found: '.github/CODEOWNERS' } });
    expect(empty[0]?.message).toMatch(/no rule/i);
  });
  it('more suppression markers', () => {
    for (const t of ['// betterleaks:allow', '// biome-ignore lint/security/noGlobalEval: x', '// biome-ignore-all lint: x', '// oxlint-disable-next-line', '// oxlint-disable', '# ruff: disable[S101]', '# ruff: noqa',
      '# pragma: no cover', '/* istanbul ignore next */', '/* c8 ignore next */', '/* v8 ignore next */', '# zizmor: ignore[artipacked]', '# type: ignore', '// @ts-ignore', '// @ts-expect-error', '// @ts-nocheck',
      '// eslint-disable-next-line no-eval', '# noqa: E501 # noqa: S101', '# noqa:E501,S608', '# noqa:S101', '# noqa : S101', '# nosem : rule', '// #nosec G101']) {
      expect(found(t), t).toEqual(['integrity:suppression']);
    }
    expect(found('x = 1  # noqa: E501 # noqa: W291')).toEqual([]);
  });
  it('an existing next-line marker directly above a changed line counts as added; a marker far above, or on the line itself unchanged, does not', () => {
    const above = (marker: string): PrFile => file('src/a.ts', { patch: `@@ -1,4 +1,4 @@\n keep\n ${marker}\n-old()\n+evil()\n keep2` });
    for (const m of ['// nosemgrep', '// eslint-disable-next-line no-eval', '# hadolint ignore=DL3008', '#trivy:ignore:AVD-1', '// @ts-ignore', '// biome-ignore lint: x']) {
      const f = integrityFindings(ctx({ files: [above(m)] }), PROTECTED, OWNER_RULES);
      expect(ids(f), m).toEqual(['integrity:suppression']);
      expect(f[0]?.line, m).toBe(3);
    }
    // two lines above (a blank between): the marker no longer applies to the changed line
    const far = file('src/a.ts', { patch: '@@ -1,4 +1,4 @@\n // nosemgrep\n ok()\n-old()\n+evil()\n keep2' });
    expect(integrityFindings(ctx({ files: [far] }), PROTECTED, OWNER_RULES)).toEqual([]);
    // a marker that is itself a removed line is gone
    const gone = file('src/a.ts', { patch: '@@ -1,2 +1,2 @@\n keep\n-// nosemgrep\n+evil()' });
    expect(ids(integrityFindings(ctx({ files: [gone] }), PROTECTED, OWNER_RULES))).toEqual([]);
  });
  it('CODEOWNERS up to 3 MB is read (through the raw media type above 1 MiB); over 3 MB or an unreadable raw answer fails closed', async () => {
    const big = '* @alice\n' + '#'.repeat(2_000_000) + '\n';
    const g = new Gh();
    g.contents.set(`${BASE}:.github/CODEOWNERS`, { type: 'file', encoding: 'none', size: Buffer.byteLength(big), content: '' });
    g.raw.set(`${BASE}:.github/CODEOWNERS`, big);
    const r = await loadCodeowners(g, REPO, BASE);
    expect(r.problem).toBeUndefined();
    expect(ownersOf(r.rules, 'x')).toEqual(['alice']);
    expect(g.calls).toEqual(['file b:.github/CODEOWNERS', 'raw b:.github/CODEOWNERS']);
    for (const bad of [{ type: 'file', encoding: 'none', size: 3 * 1024 * 1024 + 1, content: '' }]) {
      const h = new Gh(); h.contents.set(`${BASE}:.github/CODEOWNERS`, bad);
      expect((await loadCodeowners(h, REPO, BASE)).problem).toBeTypeOf('string');
      expect(h.calls).toEqual(['file b:.github/CODEOWNERS']);
    }
    for (const rawBad of [new Error('500'), 5, { x: 1 }]) {
      const h = new Gh(); h.contents.set(`${BASE}:.github/CODEOWNERS`, { type: 'file', encoding: 'none', size: 2_000_000, content: '' }); h.raw.set(`${BASE}:.github/CODEOWNERS`, rawBad as never);
      expect((await loadCodeowners(h, REPO, BASE)).problem, String(rawBad)).toBeTypeOf('string');
    }
  });
});


// ======================= fix round 2 (review-C4-r1.md, rulings in task-C4-fix-round-2.md) =======================

describe('fix round 2 (1): INI lines are Python-exact or fail closed', () => {
  const put = (g: Gh, ref: string, path: string, text: string): void => { g.contents.set(`${ref}:${path}`, contentOf(text)); };
  const secs = async (base: string, head: string): Promise<{ section: string; problem?: string }[]> => {
    const g = new Gh(); put(g, BASE, 'setup.cfg', base); put(g, HEAD, 'setup.cfg', head);
    return readConfigSections(g, REPO, ctx({ files: [file('setup.cfg')] }), ['setup.cfg:mypy'], []);
  };
  it("the reviewer's three inputs are findings (a problem), not a pass", async () => {
    for (const head of ['[metadata]\n  name = x\n\r  [mypy]\n  ignore_errors = True', '[metadata]\nname = x\n\x1c[mypy] = 1\nignore_errors = True\n', '[metadata]\nname = x\n\x85[mypy] = 1\nignore_errors = True\n']) {
      const r = await secs('[metadata]\nname = x\n', head);
      expect(r.length, JSON.stringify(head)).toBe(1);
      expect(r[0]?.problem, JSON.stringify(head)).toBeTypeOf('string');
    }
  });
  it('every Python line boundary or control character other than \\n and \\r\\n fails closed; tab, CRLF and ordinary Unicode do not', () => {
    for (const c of ['\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x1f', '\x85', '\u2028', '\u2029', '\ufeff', '\x00', '\x01', '\x08', '\x0e', '\x7f', '\x80', '\x9f']) {
      expect(parseConfigDoc('setup.cfg', `[metadata]\nname = x${c}[mypy]\nignore_errors = True\n`), JSON.stringify(c)).toBeUndefined();
      expect(parseConfigDoc('setup.cfg', `${c}[mypy]\nignore_errors = True\n`), JSON.stringify(c)).toBeUndefined();
    }
    expect(parseConfigDoc('setup.cfg', '[mypy]\r\nk\t= v\r\nj = \u00e9\u4e2d\r\n')).toEqual({ mypy: { k: 'v', j: '\u00e9\u4e2d' } });
  });
  it('a duplicate section is rejected (N19), also after another section; a DEFAULT section twice is merged, as Python does', () => {
    expect(parseConfigDoc('setup.cfg', '[a]\nk = 1\n[b]\nk = 1\n[a]\nj = 2\n')).toBeUndefined();
    expect(parseConfigDoc('setup.cfg', '[DEFAULT]\na = 1\n[s]\nk = v\n[DEFAULT]\nb = 2\n')).toEqual({ s: { a: '1', b: '2', k: 'v' } });
  });
});

describe('fix round 2 (2): TOML sections are keyed by the key path', () => {
  const put = (g: Gh, ref: string, path: string, text: string): void => { g.contents.set(`${ref}:${path}`, contentOf(text)); };
  const secs = async (base: string, head: string, sections = ['pyproject.toml:tool.mypy']) => {
    const g = new Gh(); put(g, BASE, 'pyproject.toml', base); put(g, HEAD, 'pyproject.toml', head);
    return readConfigSections(g, REPO, ctx({ files: [file('pyproject.toml')] }), sections, []);
  };
  it('review 2(a): ["tool.mypy"] (one key) is not [tool.mypy] (two keys): the table is gone, so it is a change', async () => {
    const r = await secs('[tool.mypy]\nstrict = true\n', '["tool.mypy"]\nstrict = true\n');
    expect(r.map((c) => c.section)).toEqual(['tool.mypy']);
    expect(r[0]?.problem).toBeUndefined();
  });
  it('review 2(b): a key named $num or $int in a table does not stop the walk below it', async () => {
    const base = '[tool]\n"$num" = 1\n"$int" = 2\n[tool.mypy]\nstrict = true\n';
    expect((await secs(base, base.replace('strict = true', 'strict = false'))).map((c) => c.section)).toEqual(['tool.mypy']);
  });
  it('a real inf is not equal to a table that looks like it: {"$num": "inf"} differs from x = inf', async () => {
    expect((await secs('[tool.mypy]\nx = inf\n', '[tool.mypy.x]\n"$num" = "inf"\n')).length).toBe(1);
    expect((await secs('[tool.mypy]\nx = inf\n', '[tool.mypy]\nx = { "$num" = "inf" }\n')).length).toBe(1);
  });
  it('dotted keys stay allowed: Poetry-style "zope.interface" is no problem and no change', async () => {
    const t = '[tool.poetry.dependencies]\n"zope.interface" = "^6"\npython = "^3.12"\n[tool.mypy]\nstrict = true\n';
    expect(await secs(t, t)).toEqual([]);
    expect((await secs(t, t.replace('^6', '^7'), ['pyproject.toml:tool.poetry'])).map((c) => c.section)).toEqual(['tool.poetry']);
  });
  it('a wildcard spec matches inside one segment only', async () => {
    const base = '[tool.mypy-a]\nx = 1\n[tool.mypy.b]\nx = 1\n';
    const head = '[tool.mypy-a]\nx = 2\n[tool.mypy.b]\nx = 2\n';
    expect((await secs(base, head, ['pyproject.toml:tool.mypy*'])).map((c) => c.section).sort()).toEqual(['tool.mypy', 'tool.mypy-a']);
  });
  it('a document is not rejected for a literal dotted key that equals a table path in another document (no cross-document collision check)', async () => {
    expect(await secs('"a.b" = 1\n[tool.mypy]\nstrict = true\n', '"a.b" = 2\n[tool.mypy]\nstrict = true\n')).toEqual([]);
  });
});

describe('fix round 2 (4, 6): approver flood and the permission note', () => {
  const rules = codeOwners('* @zowner\n');
  it('30 throwaway approvers sorting before the owner do not push the owner out: only code owners get a permission check', async () => {
    const g = ghWith([]);
    g.reviews = [...Array.from({ length: 40 }, (_, i) => review(i + 1, `aaa${String(i).padStart(2, '0')}`, 'APPROVED')), review(100, 'zowner', 'APPROVED')];
    const pr = await readPrContext(g, REPO, 5, { codeowners: rules });
    expect(pr.approvals).toEqual(['zowner']);
    expect(g.calls.filter((c) => c.startsWith('perm'))).toEqual(['perm zowner']);
  });
  it('the cap applies after the filter, to code owners only', async () => {
    const many35 = codeOwners(`* ${Array.from({ length: 35 }, (_, i) => `@own${String(i).padStart(2, '0')}`).join(' ')}\n`);
    const g = ghWith([]); g.reviews = Array.from({ length: 35 }, (_, i) => review(i + 1, `own${String(i).padStart(2, '0')}`, 'APPROVED'));
    const pr = await readPrContext(g, REPO, 5, { codeowners: many35 });
    expect(pr.approvals.length).toBe(30);
    expect(pr.problems.join(' ')).toMatch(/approvers/);
  });
  it('a CODEOWNERS list naming the reviewer lets it through; an owner list with no owner names means no approver and no call', async () => {
    const g = ghWith([]); g.reviews = [review(1, 'a', 'APPROVED')];
    expect((await readPrContext(g, REPO, 5)).approvals).toEqual(['a']);
    const h = ghWith([]); h.reviews = [review(1, 'a', 'APPROVED')];
    expect((await readPrContext(h, REPO, 5, { codeowners: [] })).approvals).toEqual([]);
    expect(h.calls.filter((c) => c.startsWith('perm'))).toEqual([]);
  });
  it('a failed permission call adds a note naming the user; a plain read-only answer does not', async () => {
    const g = ghWith([]); g.reviews = [review(1, 'zowner', 'APPROVED')]; g.perms.set('zowner', new Error('403'));
    const pr = await readPrContext(g, REPO, 5, { codeowners: rules });
    expect(pr.approvals).toEqual([]);
    expect(pr.problems).toContain('approval by zowner not counted: could not read their permission');
    const h = ghWith([]); h.reviews = [review(1, 'zowner', 'APPROVED')]; h.perms.set('zowner', { permission: 'read' });
    expect((await readPrContext(h, REPO, 5, { codeowners: rules })).problems.join(' ')).not.toMatch(/permission/);
  });
});

describe('fix round 2 (m4): a copy leaves the original in place', () => {
  it('a copied file does not need its source path approved, and a copied shared config file is no (file moved)', async () => {
    const copy = file('src/new.yml', { status: 'copied', previous_filename: WF, changes: 0, patch: undefined });
    expect(integrityFindings(ctx({ files: [copy] }), PROTECTED, OWNER_RULES)).toEqual([]);
    const g = new Gh();
    g.contents.set(`${HEAD}:copy/pyproject.toml`, contentOf('[project]\nname = "x"\n'));
    const r = await readConfigSections(g, REPO, ctx({ files: [file('copy/pyproject.toml', { status: 'copied', previous_filename: 'pyproject.toml', changes: 0, patch: undefined })] }), ['pyproject.toml:tool.mypy'], []);
    expect(r).toEqual([]);
    expect(g.calls).toEqual(['file a:copy/pyproject.toml']);
  });
});

describe('fix round 2 (5): a leading slash scopes a protected path to the root', () => {
  it('"/ruff.toml" matches ruff.toml only at the root; "ruff.toml" matches at any depth; entries with a slash stay as written', () => {
    const hit = (pattern: string, path: string): boolean => integrityFindings(ctx({ files: [file(path)] }), [pattern], OWNER_RULES).length > 0;
    expect(hit('/ruff.toml', 'ruff.toml')).toBe(true);
    expect(hit('/ruff.toml', 'Ruff.TOML')).toBe(true);
    expect(hit('/ruff.toml', 'services/api/ruff.toml')).toBe(false);
    expect(hit('/services/api/ruff.toml', 'services/api/ruff.toml')).toBe(true);
    expect(hit('ruff.toml', 'services/api/ruff.toml')).toBe(true);
    expect(hit('.github/x.yml', 'a/.github/x.yml')).toBe(false);
  });
});
