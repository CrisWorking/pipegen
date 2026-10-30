// v0.2 Plan D, D0b: the judges for CODEOWNERS, dependabot.yml and PIPEGEN.md (preflight 4.2, S2, S14) and the pure builders Plan G
// calls to produce those files (codeownersBlock, dependabotEntry).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { stringify } from 'yaml';
import { codeOwners, ownersOf } from '../gate/src/integrity.js';
import { knownValueScrubber } from '../src/ai/redact.js';
import { CODEOWNERS_BEGIN, CODEOWNERS_END, CENTRAL_PROTECTED_PATHS, codeownersBlock, codeownersFile, codeownersPattern, codeownersProtectedPaths, dependabotEntry } from '../src/engine/created-builders.js';
import { createdFileProblems, type CreatedEnv } from '../src/engine/created-files.js';
import { codeownersJudge, codeownersProbes, codeownersSemanticProblems } from '../src/engine/created-judges/codeowners.js';
import { effectiveProtectedPaths } from '../src/engine/protected-paths.js';
import { referee, type Linters } from '../src/engine/referee.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { CreatedFile, PipelineDraft, RepoProfile, ReviewedTool } from '../src/types.js';
import { fake } from './helpers/secret-repo.js';
import { platform, profile, reviewedList, service } from './helpers/render.js';

const reviewed = reviewedList();
const OWNERS = ['@alice', '@bob'];
const baseProfile = (over: Partial<RepoProfile> = {}, files: Partial<RepoProfile['repoFiles']> = {}): RepoProfile => ({ ...profile([service({ name: 'root', path: '.' }), service({ name: 'api', path: 'api' }), service({ name: 'web', path: 'services/web' })]), ...over, repoFiles: { ...emptyRepoFiles(), ...files } });
const mkDraft = (over: Partial<PipelineDraft> = {}, prof: RepoProfile = baseProfile()): PipelineDraft => ({
  profile: prof, capabilities: { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true },
  needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
  codeOwners: { owners: OWNERS, writers: 2 }, ...over,
});
const draft = mkDraft();
/** drafts whose repo already has a CODEOWNERS / dependabot file (an edit with an original needs one) */
const existCo = mkDraft({}, baseProfile({}, { codeowners: '.github/CODEOWNERS' }));
const existDep = mkDraft({}, baseProfile({}, { dependabot: '.github/dependabot.yml' }));
const env = (inputs: CreatedEnv['inputs'] = {}, list: readonly ReviewedTool[] = reviewed): CreatedEnv => ({ reviewed: list, inputs });
const verdict = (f: CreatedFile, d: PipelineDraft = draft, e: CreatedEnv = env()) => createdFileProblems(f, d, undefined, e);
const problems = (f: CreatedFile, d: PipelineDraft = draft, e: CreatedEnv = env()) => verdict(f, d, e).problems;
const text = (f: CreatedFile, d: PipelineDraft = draft, e: CreatedEnv = env()) => problems(f, d, e).join(' | ');

// ---------- CODEOWNERS ----------

const paths = codeownersProtectedPaths(draft, reviewed);
const block = codeownersBlock(paths, OWNERS);
const coFile = (content: string, original = '', over: Partial<CreatedFile> = {}): CreatedFile => ({ path: '.github/CODEOWNERS', content, part: 'codeowners', reason: 't', repo: 'app', edited: { original }, ...over });
const good = (original = '') => coFile(codeownersFile(original, block), original);

describe('codeownersPattern: a protected path as a CODEOWNERS pattern', () => {
  const table: [string, string][] = [
    ['.github/workflows/**', '/.github/workflows/'], ['.husky/**', '/.husky/'], ['.zap/**', '/.zap/'], ['installs/**', '/installs/'],
    ['CODEOWNERS', 'CODEOWNERS'], ['lefthook.yml', 'lefthook.yml'], ['.gitleaksignore', '.gitleaksignore'],
    ['.github/CODEOWNERS', '/.github/CODEOWNERS'], ['docs/CODEOWNERS', '/docs/CODEOWNERS'], ['.github/dependabot.yml', '/.github/dependabot.yml'],
    ['/trivy.yaml', '/trivy.yaml'], ['/api/trivy.yaml', '/api/trivy.yaml'],
    ['**/biome.json', '**/biome.json'], ['**/.prettierrc.*', '**/.prettierrc.*'], ['vitest.config.*', 'vitest.config.*'], ['.prettierrc.*', '.prettierrc.*'],
  ];
  for (const [path, pattern] of table) it(`${path} -> ${pattern}`, () => expect(codeownersPattern(path)).toBe(pattern));
  it('a path the format can not carry is refused (never silently dropped)', () => {
    for (const bad of ['', '/', '//', 'a b', 'a\tb', '!x', 'a[b]', 'a]b', '\\#x', '#x', 'a#b', 'a\\b', 'a\nb', '.github//x', 'a/../b', '../x', '{a,b}', 'a@b', '/**', '**']) expect(() => codeownersPattern(bad), JSON.stringify(bad)).toThrow();
  });
});

describe('codeownersBlock: the exact text', () => {
  it('begin marker, one line per pattern with the owners, end marker', () => {
    expect(codeownersBlock(['.github/workflows/**', 'CODEOWNERS', '/trivy.yaml', '**/biome.json', 'vitest.config.*'], ['@alice', '@bob'])).toBe(
      '# pipegen:begin\n/.github/workflows/ @alice @bob\nCODEOWNERS @alice @bob\n/trivy.yaml @alice @bob\n**/biome.json @alice @bob\nvitest.config.* @alice @bob\n# pipegen:end\n');
  });
  it('the markers are the documented constants', () => {
    expect(CODEOWNERS_BEGIN).toBe('# pipegen:begin');
    expect(CODEOWNERS_END).toBe('# pipegen:end');
  });
  it('two paths with one pattern make one line', () => {
    expect(codeownersBlock(['lefthook.yml', 'lefthook.yml'], ['@a'])).toBe('# pipegen:begin\nlefthook.yml @a\n# pipegen:end\n');
  });
  it('an owner that is not a user login is refused: team, e-mail, bot, bare name, empty list', () => {
    for (const bad of [['@org/team'], ['a@b.co'], ['@dependabot[bot]'], ['alice'], [], ['@alice', '@alice'], ['@ALICE', '@alice'], ['@-x'], ['@x-'], ['@' + 'a'.repeat(40)], ['@a b']]) expect(() => codeownersBlock(['CODEOWNERS'], bad), JSON.stringify(bad)).toThrow();
  });
  it('the file is the original, a blank line when it has text, then the block', () => {
    expect(codeownersFile('', block)).toBe(block);
    expect(codeownersFile('* @c\n', block)).toBe(`* @c\n\n${block}`);
    expect(codeownersFile('* @c', block)).toBe(`* @c\n\n${block}`);
  });
  it('the central repo covers workflows and installs', () => {
    expect([...CENTRAL_PROTECTED_PATHS]).toEqual(['.github/workflows/**', 'installs/**']);
  });
});

describe('codeowners judge: edit form and block', () => {
  it('a new file (empty original) with the block passes', () => {
    expect(text(good())).toBe('');
  });
  it('the app block is the protected paths of the whole reviewed list plus the service-root copies', () => {
    expect(paths).toEqual(expect.arrayContaining(effectiveProtectedPaths(reviewed, ['.', 'api', 'services/web'])));
    expect(paths).toContain('/services/web/lefthook.yml');
  });
  it('gateSettings.protectedPaths are protected by the gate, so the block owns them too', () => {
    const d = mkDraft({ gateSettings: { protectedPaths: ['infra/**', 'deploy.sh'] } });
    const p = codeownersProtectedPaths(d, reviewed);
    expect(p).toEqual(expect.arrayContaining(['infra/**', 'deploy.sh']));
    expect(text(coFile(codeownersFile('', codeownersBlock(p, OWNERS))), d)).toBe('');
    expect(text(good(), d)).not.toBe('');   // the block without them is not the block for this draft
  });
  it('an edit keeps the original as a byte prefix', () => {
    for (const original of ['* @carol\n', '* @carol', '# my rules\n\n/src/ @carol @dave\n', 'x @a\r\ny @b\r\n']) expect(text(good(original), existCo), JSON.stringify(original)).toBe('');
  });
  it('an original that is not a prefix is refused', () => {
    expect(text(coFile(codeownersFile('* @carol\n', block), '* @mallory\n'), existCo)).toMatch(/prefix/);
    expect(text(coFile(block, '* @carol\n'), existCo)).toMatch(/prefix/);   // the user's line dropped
    expect(text(coFile(`# changed\n${block}`, '# x\n'), existCo)).toMatch(/prefix/);
  });
  it('a change inside the user text, with the original lying, is refused when the content does not start with it', () => {
    const f = coFile(codeownersFile('* @carol\n', block).replace('@carol', '@mallory'), '* @carol\n');
    expect(problems(f, existCo).length).toBeGreaterThan(0);
    expect(text(f, existCo)).toMatch(/prefix/);
  });
  it('anything after the block, or a second block, is refused', () => {
    expect(problems(coFile(`${codeownersFile('', block)}* @mallory\n`)).length).toBeGreaterThan(0);
    expect(problems(coFile(`${block}\n${block}`)).length).toBeGreaterThan(0);
  });
  it('an original that already holds a pipegen marker is refused (two blocks)', () => {
    for (const original of [`${CODEOWNERS_BEGIN}\nx @a\n${CODEOWNERS_END}\n`, `# pipegen:begin\n`, 'a # pipegen:end\n']) expect(text(coFile(codeownersFile(original, block), original), existCo), original).toMatch(/pipegen:begin|marker/);
  });
  it('a block that differs from the builder output is refused: line removed, owner order, extra owner, extra line, wrong pattern', () => {
    const lines = block.split('\n');
    const variants = [
      [...lines.slice(0, 2), ...lines.slice(3)].join('\n'),
      block.replaceAll('@alice @bob', '@bob @alice'),
      block.replaceAll('@alice @bob', '@alice @bob @mallory'),
      block.replace(CODEOWNERS_END, `/src/ @mallory\n${CODEOWNERS_END}`),
      block.replace('\nCODEOWNERS ', '\n/CODEOWNERS '),
      block.replace(CODEOWNERS_BEGIN, `${CODEOWNERS_BEGIN} extra`),
      block.replace(/\n$/, ''),
    ];
    for (const v of variants) expect(problems(coFile(v)).length, v.slice(0, 80)).toBeGreaterThan(0);
  });
  it('text before the block that is not the original is refused even when the block is right', () => {
    expect(problems(coFile(`* @mallory\n${block}`, '')).length).toBeGreaterThan(0);
  });
  it('a file without the edited marker, or with a bad one, is refused', () => {
    const f = good();
    delete (f as { edited?: unknown }).edited;
    expect(problems(f).length).toBeGreaterThan(0);
  });
});

describe('codeowners judge: the path (the order the gate reads)', () => {
  const at = (found: string | null) => mkDraft({}, baseProfile({}, { codeowners: found }));
  const cases: [string | null, string, boolean][] = [
    [null, '.github/CODEOWNERS', true], [null, 'CODEOWNERS', false], [null, 'docs/CODEOWNERS', false],
    ['.github/CODEOWNERS', '.github/CODEOWNERS', true], ['.github/CODEOWNERS', 'CODEOWNERS', false], ['.github/CODEOWNERS', 'docs/CODEOWNERS', false],
    ['CODEOWNERS', 'CODEOWNERS', true], ['CODEOWNERS', '.github/CODEOWNERS', false], ['CODEOWNERS', 'docs/CODEOWNERS', false],
    ['docs/CODEOWNERS', 'docs/CODEOWNERS', true], ['docs/CODEOWNERS', '.github/CODEOWNERS', false], ['docs/CODEOWNERS', 'CODEOWNERS', false],
  ];
  for (const [found, path, ok] of cases) {
    it(`existing ${String(found)}: a file at ${path} is ${ok ? 'accepted' : 'refused'}`, () => {
      const d = at(found);
      const f = coFile(codeownersFile('', codeownersBlock(codeownersProtectedPaths(d, reviewed), OWNERS)), '', { path });
      const t = text(f, d);
      if (ok) expect(t).toBe('');
      else expect(t).toMatch(/CODEOWNERS file|higher|lower|first/i);
    });
  }
  it('an existing file at a lower-priority path is the one to edit (a block in a shadowed file is ignored by GitHub)', () => {
    const d = at('docs/CODEOWNERS');
    expect(text(good(), d)).toMatch(/docs\/CODEOWNERS/);
  });
  it('an original text for a repo that has no CODEOWNERS is refused', () => {
    expect(text(good('* @carol\n'))).toMatch(/no CODEOWNERS file exists/);
  });
  it('a reader value outside the three places is refused', () => {
    const d = at('src/CODEOWNERS');
    // no rule claims src/CODEOWNERS, so the judge is called directly
    expect(codeownersJudge(coFile(codeownersFile('', codeownersBlock(paths, OWNERS)), '', { path: 'src/CODEOWNERS' }), { draft: d, ...env() }).join(' ')).toMatch(/not one GitHub reads/);
    expect(problems(coFile(codeownersFile('', codeownersBlock(paths, OWNERS)), '', { path: '.github/CODEOWNERS' }), d).length).toBeGreaterThan(0);
  });
});

describe('codeowners judge: owners (preflight 4.2 and S14)', () => {
  const withOwners = (owners: string[] | undefined, writers = 2): PipelineDraft => { const d = mkDraft(); if (owners === undefined) delete d.codeOwners; else d.codeOwners = { owners, writers }; return d; };
  const fileFor = (d: PipelineDraft, owners: string[]) => coFile(codeownersFile('', codeownersBlock(codeownersProtectedPaths(d, reviewed), owners)));
  it('a draft without codeOwners writes no CODEOWNERS', () => {
    expect(text(good(), withOwners(undefined))).toMatch(/owners/);
  });
  it('empty owners are refused', () => {
    expect(text(good(), withOwners([], 0))).toMatch(/owners/);
  });
  it('a team, an e-mail, a bot, a bare name, a duplicate is refused in the draft', () => {
    for (const bad of ['@org/team', 'a@b.co', '@dependabot[bot]', 'alice', '@pipegen-app[bot]', '@ALICE']) {
      const d = withOwners(['@carol', bad], 2);
      expect(text(good(), d), bad).toMatch(/owner/);
    }
    expect(text(good(), withOwners(['@carol', '@CAROL'], 2))).toMatch(/owner/);
  });
  it('an owner list that differs from the draft is refused: extra, missing, other', () => {
    expect(problems(fileFor(draft, ['@alice', '@bob', '@mallory'])).length).toBeGreaterThan(0);
    expect(problems(fileFor(draft, ['@alice'])).length).toBeGreaterThan(0);
    expect(problems(fileFor(draft, ['@alice', '@mallory'])).length).toBeGreaterThan(0);
  });
  it('S14: writers >= 2 with one owner is refused (lockout); one writer with one owner is fine', () => {
    const one = withOwners(['@alice'], 2);
    expect(text(fileFor(one, ['@alice']), one)).toMatch(/two|2|lock/i);
    expect(text(fileFor(withOwners(['@alice'], 5), ['@alice']), withOwners(['@alice'], 5))).toMatch(/two|2|lock/i);
    const solo = withOwners(['@alice'], 1);
    expect(text(fileFor(solo, ['@alice']), solo)).toBe('');
    const zero = withOwners(['@alice'], 0);
    expect(text(fileFor(zero, ['@alice']), zero)).toBe('');
  });
  it('writers that is not a count is refused', () => {
    for (const w of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '2' as unknown as number]) {
      const d = withOwners(['@alice', '@bob'], w);
      expect(problems(fileFor(withOwners(['@alice', '@bob']), ['@alice', '@bob']), d).length, String(w)).toBeGreaterThan(0);
    }
  });
  it('three owners and two writers is fine', () => {
    const d = withOwners(['@alice', '@bob', '@carol'], 2);
    expect(text(fileFor(d, ['@alice', '@bob', '@carol']), d)).toBe('');
  });
});

describe('codeowners judge: the gate parser owns every protected path by exactly the owners', () => {
  const rules = codeOwners(good().content);
  const own = (p: string) => ownersOf(rules, p)?.slice().sort();
  const want = ['alice', 'bob'];
  it('explicit probes: roots, nested, services, globs', () => {
    for (const p of ['.github/workflows/ci.yml', '.github/workflows/a/b.yml', '.github/actions/x/action.yml', '.husky/pre-commit', '.zap/rules.tsv', 'CODEOWNERS', 'docs/CODEOWNERS', '.github/CODEOWNERS', '.github/dependabot.yml',
      'lefthook.yml', 'deep/dir/lefthook.yml', 'api/lefthook.yml', '.pre-commit-config.yaml', 'docker-compose.pipegen.yml', 'renovate.json', '.gitleaksignore', 'api/.gitleaksignore', 'services/web/.gitleaksignore', 'sub/.semgrepignore', 'vitest.config.ts', 'api/vitest.config.mts', 'a/b/vite.config.js']) {
      expect(own(p), p).toEqual(want);
    }
  });
  it('unrelated files are not owned', () => {
    for (const p of ['src/index.ts', 'README.md', 'package.json', 'api/src/x.ts', 'workflows/ci.yml', 'docs/readme.md', '.github/pull_request_template.md', 'github/workflows/x.yml']) expect(ownersOf(rules, p), p).toBeUndefined();
  });
  it('round trip: every protected path the engine produces is owned by exactly the owners (probe list)', () => {
    const sets = [['.'], ['.', 'api'], ['.', 'api', 'services/web', 'a/b/c'], ['web']];
    for (const roots of sets) {
      const d = mkDraft({}, baseProfile({ services: roots.map((r, i) => service({ name: `s${i}`, path: r })) }));
      const eff = effectiveProtectedPaths(reviewed, roots);
      const b = codeownersBlock(eff, OWNERS);
      const rs = codeOwners(b);
      const probes = codeownersProbes(eff, roots);
      expect(probes.length).toBeGreaterThan(eff.length);
      const bad = probes.filter((p) => JSON.stringify(ownersOf(rs, p)?.slice().sort()) !== JSON.stringify(want));
      expect(bad, roots.join(',')).toEqual([]);
      expect(codeownersSemanticProblems(b, eff, roots, OWNERS)).toEqual([]);
      expect(text(coFile(codeownersFile('', codeownersBlock(codeownersProtectedPaths(d, reviewed), OWNERS))), d)).toBe('');
    }
  });
  it('the block parsed by the gate gives owners for each protected path itself, not only the probes', () => {
    const eff = effectiveProtectedPaths(reviewed, ['.', 'api']);
    const rs = codeOwners(codeownersBlock(eff, OWNERS));
    for (const p of eff.filter((x) => !/[*?]/.test(x))) expect(ownersOf(rs, p.replace(/^\//, ''))?.slice().sort(), p).toEqual(want);
  });
  it('probe list shapes: dir/** gets nested files, a bare name gets any depth and each service root, /name stays at the root', () => {
    const probes = codeownersProbes(['.github/workflows/**', 'lefthook.yml', '/trivy.yaml', '**/biome.json', 'vitest.config.*'], ['api']);
    expect(probes).toEqual(expect.arrayContaining(['.github/workflows/x', '.github/workflows/a/b/c.y', 'lefthook.yml', 'sub/dir/lefthook.yml', 'api/lefthook.yml', 'trivy.yaml', 'biome.json', 'sub/dir/biome.json', 'vitest.config.x', 'sub/dir/vitest.config.x']));
  });
  it('a glob translation error is an issue: anchored where any depth is needed, a dir without its subtree, a wrong owner', () => {
    const roots = ['.', 'api'];
    const eff = ['.github/workflows/**', 'vitest.config.*', 'lefthook.yml', '/trivy.yaml'];
    const ok = codeownersBlock(eff, OWNERS);
    expect(codeownersSemanticProblems(ok, eff, roots, OWNERS)).toEqual([]);
    const wrong = [
      ok.replace('\nvitest.config.* ', '\n/vitest.config.* '),       // anchored: nested config not owned
      ok.replace('/.github/workflows/ ', '/.github/workflows/* '),   // one level only
      ok.replace('\nlefthook.yml ', '\n/lefthook.yml '),
      ok.replace('/trivy.yaml ', 'trivy.yaml/ '),
      ok.replace('/.github/workflows/ @alice @bob', '/.github/workflows/ @alice'),
      ok.replace('/trivy.yaml @alice @bob', '/trivy.yaml @alice @bob\n/trivy.yaml @mallory'),   // a later rule takes it over
      `${ok}* @mallory\n`,                                                     // catch-all after
      ok.replace(CODEOWNERS_END, `src/ @mallory\n${CODEOWNERS_END}`),         // owns more than the protected set
    ];
    for (const w of wrong) expect(codeownersSemanticProblems(w, eff, roots, OWNERS).length, w).toBeGreaterThan(0);
  });
  it('the whole-file check sees the user text first: a user rule after nothing of ours is overridden, a later user rule is not allowed', () => {
    // the judge only accepts original + block, so a user rule can never come after the block
    expect(problems(coFile(`${block}\n* @mallory\n`)).length).toBeGreaterThan(0);
  });
});

describe('codeowners judge: limits and patterns GitHub drops', () => {
  const longName = 'a'.repeat(5000);
  const withConfig = (names: string[]): ReviewedTool[] => { const l = reviewedList(); (l[0] as ReviewedTool).configFiles = [...(l[0] as ReviewedTool).configFiles, ...names]; return l; };
  for (const [label, name] of [['a line over 4096 characters', longName], ['a ! pattern', '!x.json'], ['a [ pattern', 'a[1].json'], ['a ] pattern', 'a]b'], ['a \\# pattern', '\\#x'], ['a space', 'a b.json'], ['a # in the name', 'a#b']] as const) {
    it(`${label} in the tool list is refused, never written`, () => {
      const list = withConfig([name]);
      const d = draft;
      const t = text(good(), d, env({}, list));
      expect(t.length).toBeGreaterThan(0);
      if (name === longName) expect(t).toMatch(/4096/);
    });
  }
  it('the whole file over 3 MiB is refused', () => {
    const big = `# ${'x'.repeat(3 * 1024 * 1024)}\n`;
    expect(text(coFile(codeownersFile(big, block), big), existCo)).toMatch(/3 MiB|too large|size/i);
  });
  it('100,000 user rules before the block would make the gate stop reading before it: refused by the whole-file check', () => {
    const many = '/x @a\n'.repeat(100_001);
    expect(many.length).toBeLessThan(3 * 1024 * 1024);
    expect(text(coFile(codeownersFile(many, block), many), existCo)).toMatch(/gate would not read/);
  });
  it('just under 3 MiB is accepted', () => {
    const small = `# ${'x'.repeat(2 * 1024 * 1024)}\n`;
    expect(text(coFile(codeownersFile(small, block), small), existCo)).toBe('');
  });
});

describe('codeowners judge: the central repo', () => {
  const central = (content: string, original = '', path = '.github/CODEOWNERS'): CreatedFile => ({ path, content, part: 'codeowners', reason: 't', repo: 'central', edited: { original } });
  const cblock = codeownersBlock(CENTRAL_PROTECTED_PATHS, OWNERS);
  it('covers .github/workflows/** and installs/** with the draft owners', () => {
    expect(cblock).toBe('# pipegen:begin\n/.github/workflows/ @alice @bob\n/installs/ @alice @bob\n# pipegen:end\n');
    expect(text(central(cblock), draft, env({ centralCodeowners: null }))).toBe('');
  });
  it('the existing central file decides the path; absent knowledge is refused', () => {
    expect(text(central(cblock, '', 'CODEOWNERS'), draft, env({ centralCodeowners: null }))).toMatch(/CODEOWNERS file|first|higher/i);
    expect(text(central(cblock, '', 'CODEOWNERS'), draft, env({ centralCodeowners: 'CODEOWNERS' }))).toBe('');
    expect(text(central(cblock), draft, env({ centralCodeowners: 'docs/CODEOWNERS' }))).toMatch(/docs\/CODEOWNERS/);
    expect(text(central(cblock), draft, env({}))).toMatch(/central/i);
  });
  it('the app block in the central repo, or the central block in the app repo, is refused', () => {
    expect(problems(central(block), draft, env({ centralCodeowners: null })).length).toBeGreaterThan(0);
    expect(problems(coFile(codeownersFile('', cblock))).length).toBeGreaterThan(0);
  });
  it('a central file with an edit keeps the user text', () => {
    expect(text(central(codeownersFile('* @carol\n', cblock), '* @carol\n'), draft, env({ centralCodeowners: '.github/CODEOWNERS' }))).toBe('');
    expect(text(central(codeownersFile('* @carol\n', cblock), '* @dave\n'), draft, env({ centralCodeowners: '.github/CODEOWNERS' }))).toMatch(/prefix/);
  });
  it('the central file is owned by the same S14 rules', () => {
    const d = mkDraft({ codeOwners: { owners: ['@alice'], writers: 3 } });
    expect(problems(central(codeownersBlock(CENTRAL_PROTECTED_PATHS, ['@alice'])), d, env({ centralCodeowners: null })).length).toBeGreaterThan(0);
  });
  it('the semantic probes for central: workflows and installs owned, others not', () => {
    const rs = codeOwners(cblock);
    for (const p of ['.github/workflows/p--merge.yml', '.github/workflows/a/b.yml', 'installs/p.json', 'installs/x/y.json']) expect(ownersOf(rs, p)?.slice().sort(), p).toEqual(['alice', 'bob']);
    for (const p of ['README.md', 'enrolled-repos.yml', 'other/installs/x.json', 'workflows/x.yml']) expect(ownersOf(rs, p), p).toBeUndefined();
  });
});

describe('codeowners judge: the rules are registered', () => {
  it('the app and central CODEOWNERS rules no longer refuse everything', () => {
    expect(text(good())).not.toMatch(/not built yet/);
  });
  it('a wrong part is refused', () => {
    expect(problems(coFile(codeownersFile('', block), '', { part: 'docs' })).length).toBeGreaterThan(0);
  });
});

// ---------- dependabot.yml ----------

const DEP = '.github/dependabot.yml';
const depFile = (content: string, original = '', over: Partial<CreatedFile> = {}): CreatedFile => ({ path: DEP, content, part: 'pipeline', reason: 't', repo: 'app', edited: { original }, ...over });
const yml = (o: unknown): string => stringify(o, { lineWidth: 0 });
const entry = dependabotEntry(draft);
const NPM = { 'package-ecosystem': 'npm', directory: '/', schedule: { interval: 'daily' }, 'open-pull-requests-limit': 3 };
const withEntry = (userDoc: Record<string, unknown> | null, e: unknown = entry): string => {
  const base = userDoc ?? { version: 2 };
  const updates = Array.isArray(base.updates) ? base.updates : [];
  return yml({ ...base, updates: [...updates, e] });
};
const privateDraft = mkDraft({ centralPin: { repo: 'o/pipelines', sha: 'a'.repeat(40) } }, baseProfile({ private: true }));

describe('dependabotEntry', () => {
  it('a public repo: github-actions, /, weekly, 7-day cooldown, minor+patch grouped, majors separate, no ignore', () => {
    expect(entry).toEqual({
      'package-ecosystem': 'github-actions', directory: '/', schedule: { interval: 'weekly' }, cooldown: { 'default-days': 7 },
      groups: { 'github-actions-minor-patch': { 'update-types': ['minor', 'patch'], patterns: ['*'] } },
    });
  });
  it('a private repo ignores the central repo (#89)', () => {
    expect(dependabotEntry(privateDraft).ignore).toEqual([{ 'dependency-name': 'o/pipelines/*' }]);
  });
  it('a private repo without a central pin has no entry (it can not name the central repo)', () => {
    expect(() => dependabotEntry(mkDraft({}, baseProfile({ private: true })))).toThrow();
  });
  it('a pin that is not owner/name is refused', () => {
    for (const repo of ['pipelines', 'o/pipelines/x', 'o/p ipelines', 'o/*', '*/x', '../x', 'o/..']) expect(() => dependabotEntry(mkDraft({ centralPin: { repo, sha: 'a'.repeat(40) } }, baseProfile({ private: true }))), repo).toThrow();
  });
  it('the result is a fresh object each call', () => {
    const a = dependabotEntry(draft) as { schedule: { interval: string } };
    a.schedule.interval = 'daily';
    expect((dependabotEntry(draft) as { schedule: { interval: string } }).schedule.interval).toBe('weekly');
  });
});

describe('dependabot judge: the file', () => {
  it('a new file with one entry passes', () => {
    expect(text(depFile(withEntry(null)))).toBe('');
  });
  it('private repo: the entry with the ignore passes; the public entry does not', () => {
    expect(text(depFile(withEntry(null, dependabotEntry(privateDraft))), privateDraft)).toBe('');
    expect(problems(depFile(withEntry(null)), privateDraft).length).toBeGreaterThan(0);
    expect(problems(depFile(withEntry(null, dependabotEntry(privateDraft)))).length).toBeGreaterThan(0);
  });
  it('the user content is kept as is: other ecosystems, top-level keys, registries of the user', () => {
    const user = { version: 2, registries: { npm1: { type: 'npm-registry', url: 'https://registry.npmjs.org', note: 'a ${{ b }}' } }, updates: [{ ...NPM, registries: ['npm1'] }, { 'package-ecosystem': 'pip', directory: '/py', schedule: { interval: 'weekly' } }] };
    const original = yml(user);
    expect(text(depFile(withEntry(user), original), existDep)).toBe('');
  });
  it('the user text may keep its comments (parsed data is compared)', () => {
    const user = { version: 2, updates: [NPM] };
    const original = `# mine\n${yml(user)}`;
    expect(text(depFile(withEntry(user), original), existDep)).toBe('');
  });
  it('a changed user entry, a removed one, a changed top-level key, an added one, a reorder: refused', () => {
    const user = { version: 2, updates: [NPM, { 'package-ecosystem': 'pip', directory: '/py', schedule: { interval: 'weekly' } }] };
    const original = yml(user);
    const edit = (f: (u: typeof user) => unknown) => depFile(withEntry(f(structuredClone(user)) as Record<string, unknown>), original);
    const problems = (f: CreatedFile) => verdict(f, existDep).problems;
    expect(problems(edit((u) => { (u.updates[0] as { schedule: { interval: string } }).schedule.interval = 'weekly'; return u; })).length).toBeGreaterThan(0);
    expect(problems(edit((u) => { u.updates.pop(); return u; })).length).toBeGreaterThan(0);
    expect(problems(edit((u) => ({ ...u, 'enable-beta-ecosystems': true }))).length).toBeGreaterThan(0);
    expect(problems(edit((u) => ({ ...u, registries: { x: { type: 'git', url: 'https://evil.example' } } }))).length).toBeGreaterThan(0);
    expect(problems(edit((u) => { u.updates.reverse(); return u; })).length).toBeGreaterThan(0);
    expect(problems(depFile(yml({ version: 2, updates: [entry, ...user.updates] }), original)).length).toBeGreaterThan(0);   // pipegen's must be last
    expect(problems(edit((u) => { (u.updates[0] as { schedule: { interval: string } }).schedule.interval = 'weekly'; return u; })).join(' ')).toMatch(/changed/);
  });
  it('an existing file whose version is not 2 is refused even though it is kept as is', () => {
    const user = { version: 1, updates: [NPM] };
    expect(verdict(depFile(withEntry(user), yml(user)), existDep).problems.join(' ')).toMatch(/version/);
  });
  it('a changed value under a kept top-level key is named', () => {
    const user = { version: 2, registries: { a: { type: 'npm-registry', url: 'https://registry.npmjs.org' } }, updates: [NPM] };
    const swapped = { ...structuredClone(user), registries: { a: { type: 'npm-registry', url: 'https://evil.example' } } };
    expect(verdict(depFile(withEntry(swapped), yml(user)), existDep).problems.join(' ')).toMatch(/`registries` was changed/);
  });
  it('the user has no updates key or an empty one: still exactly one entry', () => {
    expect(text(depFile(yml({ version: 2, updates: [entry] }), yml({ version: 2 })), existDep)).toBe('');
    expect(text(depFile(yml({ version: 2, updates: [entry] }), yml({ version: 2, updates: [] })), existDep)).toBe('');
  });
  it('nothing appended, or two entries appended, is refused', () => {
    const user = { version: 2, updates: [NPM] };
    const ps = (f: CreatedFile) => problems(f, existDep);
    expect(ps(depFile(yml(user), yml(user))).join(' ')).toMatch(/exactly one/);
    expect(ps(depFile(yml({ ...user, updates: [NPM, entry, structuredClone(entry)] }), yml(user))).join(' ')).toMatch(/exactly one/);
    expect(ps(depFile(yml({ ...user, updates: [NPM, structuredClone(entry), { ...structuredClone(entry), directory: '/other' }] }), yml(user))).join(' ')).toMatch(/exactly one/);
  });
  it('version must be 2', () => {
    expect(problems(depFile(yml({ version: 1, updates: [entry] }))).length).toBeGreaterThan(0);
    expect(problems(depFile(yml({ updates: [entry] }))).length).toBeGreaterThan(0);
    expect(problems(depFile(yml({ version: '2', updates: [entry] }))).length).toBeGreaterThan(0);
  });
  it('the appended entry must equal dependabotEntry(draft): interval, cooldown, directory, groups, ecosystem', () => {
    const e = entry as unknown as Record<string, unknown>;
    const variants: unknown[] = [
      { ...e, schedule: { interval: 'daily' } }, { ...e, cooldown: { 'default-days': 3 } }, { ...e, cooldown: { 'default-days': '7' } }, { ...e, directory: '/sub' },
      { ...e, groups: {} }, { ...e, 'package-ecosystem': 'npm' }, { ...e, cooldown: undefined }, { ...e, groups: { 'github-actions-minor-patch': { 'update-types': ['major'], patterns: ['*'] } } },
      { ...e, schedule: { interval: 'weekly', day: 'monday' } },
    ];
    for (const v of variants) expect(problems(depFile(withEntry(null, v))).length, JSON.stringify(v)).toBeGreaterThan(0);
  });
  it('the refused keys in pipegen\'s entry are named: registries, insecure-external-code-execution, open-pull-requests-limit, target-branch, vendor, enable-beta-ecosystems, ignore', () => {
    const e = entry as unknown as Record<string, unknown>;
    const keys: Record<string, unknown> = {
      registries: ['evil'], 'insecure-external-code-execution': 'allow', 'open-pull-requests-limit': 0, 'target-branch': 'staging', vendor: true, 'enable-beta-ecosystems': true,
      ignore: [{ 'dependency-name': '*' }], allow: [{ 'dependency-type': 'direct' }], 'rebase-strategy': 'disabled', labels: ['x'], assignees: ['mallory'], reviewers: ['mallory'], 'commit-message': { prefix: 'x' },
    };
    for (const [k, v] of Object.entries(keys)) {
      const t = text(depFile(withEntry(null, { ...e, [k]: v })));
      expect(t, k).toMatch(new RegExp(k.replace(/[-]/g, '[- ]')));
    }
  });
  it('open-pull-requests-limit 5 is refused too (only the builder\'s entry is written)', () => {
    expect(problems(depFile(withEntry(null, { ...(entry as object), 'open-pull-requests-limit': 5 }))).length).toBeGreaterThan(0);
  });
  it('a second ignore on a private repo, or an ignore on a public one, is refused', () => {
    const pe = dependabotEntry(privateDraft) as { ignore: unknown[] };
    expect(problems(depFile(withEntry(null, { ...pe, ignore: [...pe.ignore, { 'dependency-name': 'actions/*' }] })), privateDraft).length).toBeGreaterThan(0);
    expect(problems(depFile(withEntry(null, { ...(entry as object), ignore: [{ 'dependency-name': 'o/pipelines/*' }] }))).length).toBeGreaterThan(0);
    expect(text(depFile(withEntry(null, { ...pe, ignore: [{ 'dependency-name': 'o/pipelines/*', versions: ['>0'] }] })), privateDraft)).not.toBe('');
  });
  it('${{ anywhere in the file text is refused', () => {
    expect(text(depFile(withEntry(null, { ...(entry as object), groups: { x: { patterns: ['${{ secrets.X }}'] } } })))).toMatch(/\$\{\{/);
    expect(text(depFile(`${withEntry(null)}# \${{ x }}\n`))).toMatch(/\$\{\{/);
  });
});

describe('dependabot judge: duplicates, Renovate, path', () => {
  const actions = (over: Record<string, unknown> = {}) => ({ 'package-ecosystem': 'github-actions', directory: '/', schedule: { interval: 'monthly' }, ...over });
  const dup = (e: Record<string, unknown>) => { const user = { version: 2, updates: [e] }; return depFile(withEntry(user), yml(user)); };
  const dProblems = (f: CreatedFile) => verdict(f, existDep).problems;
  const dText = (f: CreatedFile) => dProblems(f).join(' | ');
  it('a user github-actions entry for / means pipegen adds nothing', () => {
    expect(dText(dup(actions()))).toMatch(/already|duplicate/i);
  });
  it('the same through directories, a trailing slash, ./, a target branch', () => {
    for (const e of [actions({ directory: undefined, directories: ['/'] }), actions({ directory: undefined, directories: ['/a', '/'] }), actions({ directory: '' }), actions({ directory: './' }), actions({ directory: '.' }), actions({ 'target-branch': 'dev' }), actions({ directory: undefined, directories: ['/*'] }), actions({ directory: undefined, directories: ['**'] }), actions({ directory: undefined, directories: 'weird' })]) {
      expect(dText(dup(Object.fromEntries(Object.entries(e).filter(([, v]) => v !== undefined)))), JSON.stringify(e)).toMatch(/already/);
    }
  });
  it('a user github-actions entry for another folder, or another ecosystem at /, is no duplicate', () => {
    expect(dText(dup(actions({ directory: '/sub' })))).toBe('');
    expect(dText(dup({ ...NPM }))).toBe('');
  });
  it('a Renovate repo gets no file', () => {
    const d = mkDraft({}, baseProfile({}, { renovate: 'renovate.json' }));
    expect(text(depFile(withEntry(null)), d)).toMatch(/Renovate/);
    const p = mkDraft({}, baseProfile({}, { renovate: 'package.json' }));
    expect(text(depFile(withEntry(null)), p)).toMatch(/Renovate/);
  });
  it('an existing .yaml is the path to use; the .yml one is then refused', () => {
    const d = mkDraft({}, baseProfile({}, { dependabot: '.github/dependabot.yaml' }));
    const user = { version: 2, updates: [NPM] };
    expect(text(depFile(withEntry(user), yml(user), { path: '.github/dependabot.yaml' }), d)).toBe('');
    expect(text(depFile(withEntry(user), yml(user)), d)).toMatch(/dependabot\.yaml/);
  });
  it('an existing .yml is the path; a .yaml file is refused; with none, only .yml', () => {
    const d = mkDraft({}, baseProfile({}, { dependabot: '.github/dependabot.yml' }));
    expect(text(depFile(withEntry(null), '', { path: '.github/dependabot.yaml' }), d)).toMatch(/dependabot\.yml/);
    expect(text(depFile(withEntry(null), '', { path: '.github/dependabot.yaml' }))).toMatch(/dependabot\.yml/);
    expect(text(depFile(withEntry(null)))).toBe('');
  });
  it('a new file (original empty) when the repo has one is refused: the original must be the file', () => {
    // RepoFiles says a dependabot file exists, so an edit with an empty original would replace the user's file
    const d = mkDraft({}, baseProfile({}, { dependabot: '.github/dependabot.yml' }));
    expect(text(depFile(withEntry(null), ''), d)).toMatch(/exist|original|replace/i);
  });
  it('an original given for a repo that has no dependabot file is refused', () => {
    const user = { version: 2, updates: [NPM] };
    expect(text(depFile(withEntry(user), yml(user)))).toMatch(/exist|original|no .*file/i);
  });
});

describe('dependabot judge: strict parse', () => {
  const user = { version: 2, updates: [NPM] };
  it('anchors, aliases, tags, merge keys, duplicate keys, several documents, invalid YAML, non-maps: refused in the content', () => {
    const good = withEntry(user);
    const bads = [
      good.replace('npm', '&a npm').replace('daily', '*a'), '&x\n' + good, good + '---\nversion: 2\n', good.replace('version: 2', 'version: !!int 2'), `${good}version: 2\n`, '[1, 2]\n', 'a: [\n', '', '<<: {a: 1}\nversion: 2\nupdates: []\n',
    ];
    for (const b of bads) expect(verdict(depFile(b, yml(user)), existDep).problems.join(' '), b.slice(0, 40)).toMatch(/new Dependabot file|YAML|anchor|alias|tag|document|key|map|valid/i);
  });
  it('the original is parsed strictly too (an alias there can hide a key)', () => {
    const original = 'version: 2\nupdates:\n  - &n\n    package-ecosystem: npm\n    directory: /\n    schedule: { interval: daily }\n';
    expect(verdict(depFile(withEntry({ version: 2, updates: [NPM] }), original), existDep).problems.join(' ')).toMatch(/existing Dependabot file/);
  });
  it('an original that is not a map is refused', () => {
    expect(verdict(depFile(withEntry(null), '- a\n'), existDep).problems.join(' ')).toMatch(/existing Dependabot file/);
  });
  it('updates that is not a list is refused', () => {
    expect(verdict(depFile(yml({ version: 2, updates: entry }), yml({ version: 2, updates: {} })), existDep).problems.join(' ')).toMatch(/not a list/);
  });
  it('the registry rule exists and takes parts pipeline and docs', () => {
    expect(problems(depFile(withEntry(null), '', { part: 'tests' })).length).toBeGreaterThan(0);
    expect(text(depFile(withEntry(null), '', { part: 'docs' }))).toBe('');
  });
});

// ---------- PIPEGEN.md ----------

const vault = knownValueScrubber(['correct-horse-battery-staple-9']);
const containsKnownValue = (t: string): boolean => vault(t) !== t;
const docInputs = (over: Partial<NonNullable<CreatedEnv['inputs']['pipegenDoc']>> = {}): CreatedEnv['inputs'] => ({ pipegenDoc: { baseSha: null, recordSha: null, ...over }, containsKnownValue });
const docFile = (content: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path: 'PIPEGEN.md', content, part: 'docs', reason: 't', repo: 'app', ...over });
const docText = (content: string, inputs = docInputs(), d = draft): string => text(docFile(content), d, env(inputs));
const DOC_OK = '# Pipeline\n\nThis repo uses pipegen. See [the repo](https://github.com/o/r/blob/main/.github/workflows/pipegen.yml) and [GitHub docs](https://docs.github.com/en/actions).\n\n```yaml\n- run: echo "<div> @octocat ![x](y.png) https://evil.example"\n```\n\nCode owners: `alice` and `bob`.\n';

describe('pipegen-doc judge', () => {
  it('a document in the allowed forms passes; fenced code may hold HTML, mentions, images and any URL', () => {
    expect(docText(DOC_OK)).toBe('');
  });
  it('the path is exactly PIPEGEN.md at the root', () => {
    for (const path of ['pipegen.md', 'docs/PIPEGEN.md', 'PIPEGEN.MD', 'PIPEGEN.md/x', '.github/PIPEGEN.md']) expect(verdict(docFile(DOC_OK, { path }), draft, env(docInputs())).claimed && problems(docFile(DOC_OK, { path }), draft, env(docInputs())).length === 0, path).toBe(false);
  });
  it('size: 256 KiB passes, one byte more is refused, multi-byte characters count as bytes', () => {
    const pad = (n: number) => `# t\n\n${'a'.repeat(n - 6)}\n`;   // n bytes in all
    const limit = 256 * 1024;
    expect(docText(pad(limit))).toBe('');
    expect(docText(pad(limit + 1))).toMatch(/256 KiB|too large|size/i);
    expect(docText(`# t\n\n${'\u00e9'.repeat(limit / 2)}\n`)).toMatch(/256 KiB|too large|size/i);
  });
  it('the allowed line forms: empty, heading, list (two levels), table, separator row, fence with info, plain text with inline code and allowed links', () => {
    const doc = [
      '# Title', '## Section 2', '### Three', '#### Four', '', 'Plain text, with: punctuation. (Yes!) It\'s "fine"; 100% a/b - c_d + e = f & g * h ~ i?',
      '- item one', '  - nested item', '- item with `code` and [a link](https://github.com/o/r/blob/main/x.md?a=b&c=d)', '| name | value |', '|---|:--:|', '| a | `b` |', '| [docs](https://docs.github.com/en/x) |  |',
      '', '```yaml', 'anything: <here> @all [x]: y ${ no', '```', '```', 'no info', '```', '```c-2', 'x', '```', '1. numbered', '--- ', 'Text with https://github.com/o/r/issues and https://docs.github.com/en/x.', '',
    ].join('\n');
    expect(docText(doc)).toBe('');
  });
  const REFUSED: [string, RegExp][] = [
    ['<div>x</div>', /HTML/], ['<img src=x onerror=alert(1)>', /HTML/], ['a </p> b', /HTML/], ['<!-- c -->', /HTML/], ['<?php echo 1 ?>', /HTML/], ['<https://github.com/o/r>', /HTML/], ['a < b', /HTML/], ['1<2', /HTML/],
    ['a > b', /HTML|quote/], ['> quote', /HTML|quote/], ['>> x', /HTML|quote/], ['- > x', /HTML|quote/],
    ['@octocat', /mention/], ['cc @octocat please', /mention/], ['a@b.example', /mention/], ['`@octocat`', /mention/], ['@org/team', /mention/], ['an @ alone', /mention/], ['- @x', /mention/],
    ['[x][ref]', /link/], ['[x]', /link/], ['a ] b', /link/], ['a [ b', /link/], ['[ref]: https://docs.github.com/en/x', /link/], ['[ref]:', /link/], ['[ref]: <>', /./], ['> [ref]: https://github.com/o/r', /./], ['- [ref]: https://github.com/o/r', /link/],
    ['  - [ref]: https://github.com/o/r', /link/], ['\\[ref\\]: https://github.com/o/r', /backslash/], ['[a\\]: x', /backslash|link/], ['   [ref]: https://github.com/o/r', /./], ['[^note]: text', /link/],
    ['![a](https://github.com/o/r/raw/main/x.png)', /image/], ['![a][r]', /image/], ['![](x)', /image/], ['- ![a](https://github.com/o/r/x.png)', /image/],
    ['[a](https://evil.example)', /link/], ['[a]()', /link/], ['[a](<>)', /./], ['[a]( )', /link/], ['[a](#x)', /link/], ['[a](relative.md)', /link/], ['[a](javascript:alert(1))', /link/], ['[a](//evil.example)', /link/], ['[a](http://github.com/o/r)', /link/],
    ['[a](https://github.com@evil.example/o/r)', /link/], ['[a](https://github.com/o/r/../../evil/x)', /link/], ['[a](https://github.com/o/rx)', /link/], ['[a](https://github.com/other/repo)', /link/], ['[a](https://github.com:444/o/r)', /link/], ['[a](https://user@github.com/o/r)', /link/],
    ['[a](https://github.com/o/r "title")', /link/], ['[a [b]](https://github.com/o/r)', /link/], ['[`a`](https://github.com/o/r)', /link/], ['[https://evil.example](https://github.com/o/r)', /link/],
    ['x https://evil.example', /link/], ['www.evil.example', /link/], ['x https://evil.example/a.', /link/], ['HTTPS://EVIL.EXAMPLE', /link/],
    ['back\\slash', /backslash/], ['\\`x`', /backslash/], ['a \\* b', /backslash/], ['${{ secrets.X }}', /\$\{\{/], ['cost $5', /not allowed/], ['a # b', /not allowed/], ['#hash', /not allowed/], ['##### five', /not allowed/], ['#  x', /./], ['#', /not allowed/],
    ['| a | <b> |', /HTML/], ['| a | [x] |', /link/], ['| a |\t', /./], ['a{b}', /not allowed/], ['a b', /not allowed|control|character/],
    ['    indented', /./], [' leading space', /./], ['\ttab', /./], ['- ~~~', /fence/],
    ['`unclosed', /./], ['``double``', /./], ['```', /fence/], ['a ``` b', /./], ['`a``b`', /./], ['``a``', /./],
    ['~~~', /fence/], ['~~~~', /fence/], ['   ```', /fence/], ['   ``` x', /fence/], ['```Yaml', /fence/], ['``` yaml', /fence/], ['```yaml extra', /fence/], ['````', /fence/], ['```a`b', /fence/], ['- ```', /./], ['1. ```', /./], ['> ```', /./], ['+ ~~~', /fence/], ['* ~~~', /fence/], ['x ~~~', /fence/], ['  ~~~', /./], ['- - ~~~', /fence/],
  ];
  it('every scan bypass and every character outside the grammar is refused, as plain text, in a heading, a list item and a table cell', () => {
    for (const [line, why] of REFUSED) {
      if (line === '') continue;
      expect(docText(`# t\n\n${line}\n`), line).toMatch(why);
      expect(docText(`# t\n\n- ${line}\n`), `- ${line}`).not.toBe('');
      if (!line.startsWith(' ')) expect(docText(`# t\n\n| ${line} |\n`), `| ${line} |`).not.toBe('');   // a table cell is trimmed of spaces
      expect(docText(`# ${line}\n`), `# ${line}`).not.toBe('');
    }
  });
  it('a pipe outside a table row, and a table row that is not closed, are refused', () => {
    for (const l of ['a | b', '|a|b', '| a | b', 'x | y |']) expect(docText(`# t\n\n${l}\n`), l).not.toBe('');
    for (const l of ['| a |', '|a|b|', '| |', '||']) expect(docText(`# t\n\n${l}\n`), l).toBe('');
  });
  it('fence rules: inside a fence a line that starts 3+ backticks or tildes and is not exactly three backticks is refused; the fence closes only on an exact line; unclosed is refused', () => {
    const closers = ['   ````', ' ```', '```  ', '```x', '````', '~~~', '   ~~~~', '\t```', '```\t', '``` y', '  ```'];
    for (const c of closers) {
      expect(docText(`# t\n\n\`\`\`\nx\n${c}\n[a](https://evil.example)\n\`\`\`\n`), JSON.stringify(c)).toMatch(/fence/);
      expect(docText(`# t\n\n\`\`\`\nx\n${c}\n<img src=x>\n`), JSON.stringify(c)).toMatch(/fence/);
    }
    expect(docText('# t\n\n```\nx\n')).toMatch(/never closed|fence/);
    expect(docText('# t\n\n```\nx\n``` \n')).toMatch(/fence/);
    expect(docText('# t\n\n```\n<div>x</div>\n```\n<div>y</div>\n')).toMatch(/HTML/);
    expect(docText('# t\n\n```\n<div> `single` ``in`` text ~ tilde\n```\n')).toBe('');
    expect(docText('# t\n\n```\r\nx\r\n```\r\n')).toBe('');
    expect(docText('# t\n\n```\nx\n```\n```\ny\n```\n')).toBe('');
  });
  it('fuzz: a line built from allowed words with one forbidden character in it is always refused', () => {
    let seed = 12345;
    const rnd = (n: number) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const ALPHA = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;:!?\'"()/-_+=%&*~';
    const word = () => { let w = ''; for (let i = 0, n = 1 + rnd(8); i < n; i++) w += ALPHA[rnd(ALPHA.length)]; return w; };
    const clean = () => { let l = 'x' + Array.from({ length: 1 + rnd(5) }, word).join(' '); l = l.replace(/https?|www|~{3,}/gi, 'q').replace(/[()]/g, ''); return l; };
    const FORBIDDEN = ['<', '>', '[', ']', '\\', '@', '${{', '#', '$', '{', '}', '^', '`'];
    const wrap = [(l: string) => l, (l: string) => `# ${l}`, (l: string) => `- ${l}`, (l: string) => `  - ${l}`, (l: string) => `| ${l} |`, (l: string) => `| a | ${l} | b |`];
    for (let k = 0; k < 600; k++) {
      const base = clean();
      const bad = FORBIDDEN[rnd(FORBIDDEN.length)] as string;
      const at = 1 + rnd(base.length);
      const line = wrap[rnd(wrap.length)]?.(`${base.slice(0, at)}${bad}${base.slice(at)}`) as string;
      expect(docText(`# t\n\n${line}\n`), JSON.stringify(line)).not.toBe('');
    }
  });
  it('fuzz: lines of allowed characters only are accepted', () => {
    let seed = 777;
    const rnd = (n: number) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const ALPHA = 'abcdefghijklmnopqrstuvwxyz0123456789 .,;:!?\'"/-_+=%&*~';
    for (let k = 0; k < 300; k++) {
      let l = 'a'; for (let i = 0, n = rnd(40); i < n; i++) l += ALPHA[rnd(ALPHA.length)];
      l = l.replace(/https?|www|~{3,}/gi, 'q');
      expect(docText(`# t\n\n${l}\n\n- ${l}\n\n| ${l} | ${l} |\n`), l).toBe('');
    }
  });
  it('links: only this repository, docs.github.com and the pipegen repository, as inline links or bare URLs', () => {
    for (const ok of ['[a](https://github.com/o/r)', '[a](https://github.com/o/r/)', '[a](https://github.com/o/r/blob/main/x.md#y)', '[a](https://github.com/O/R/x)', '[a](https://docs.github.com/en/x)', '[a](https://github.com/CrisWorking/pipegen)', '[a](https://github.com/CrisWorking/pipegen/blob/main/docs/x.md)', 'see https://github.com/o/r/issues', 'see https://docs.github.com/en/x.', '- [a](https://github.com/o/r) and [b](https://docs.github.com/en/y)']) {
      expect(docText(`# t\n\n${ok}\n`), ok).toBe('');
    }
  });
  it('the pipegen repo link follows the package repository', () => {
    const pkg = JSON.parse(readPkg()) as { repository: { url: string } };
    expect(pkg.repository.url).toContain('github.com/CrisWorking/pipegen');
  });
  it('${{ is refused everywhere, fenced or not', () => {
    expect(docText('# t\n\n${{ secrets.X }}\n')).toMatch(/\$\{\{/);
    expect(docText('# t\n\n```\nrun: ${{ github.event.pull_request.title }}\n```\n')).toMatch(/\$\{\{/);
    expect(docText('# t\n\n`${{ x }}`\n')).toMatch(/\$\{\{/);
    expect(docText('# t\n\n- ${{ x }}\n')).toMatch(/\$\{\{/);
  });
  it('control and invisible characters are refused: NUL, ESC, bidi overrides, zero-width, BOM in the body', () => {
    for (const c of ['\u0000', '\u001b', '\u202e', '\u2066', '\u200b', '\ufeff', '\u007f', '\u0085']) expect(docText(`# t\n\nab${c}cd\n`), JSON.stringify(c)).toMatch(/control|invisible|character/i);
    expect(docText('# t\n\nCRLF line ends\r\nare fine\r\n')).toBe('');
    expect(docText('# t\n\n```\nTabs\tin a fence\n```\n')).toBe('');
  });
  it('a vault value (or its base64 / URL form) is refused, in prose and in a fence', () => {
    const v = 'correct-horse-battery-staple-9';
    for (const form of [v, Buffer.from(v).toString('base64'), encodeURIComponent(v)]) {
      expect(docText(`# t\n\nhello ${form}\n`), form).toMatch(/secret|value/i);
      expect(docText(`# t\n\n\`\`\`\n${form}\n\`\`\`\n`), form).toMatch(/secret|value/i);
    }
  });
  it('without the vault check the file is refused (fail closed)', () => {
    expect(docText(DOC_OK, { pipegenDoc: { baseSha: null, recordSha: null } })).toMatch(/was not given/);
  });
  it('a secret-like string is refused by the global scan, in prose and in a fence', () => {
    const t = fake.githubClassic();
    expect(docText(`# t\n\n${t}\n`)).toMatch(/secret/i);
    expect(docText(`# t\n\n\`\`\`\n${t}\n\`\`\`\n`)).toMatch(/secret/i);
    expect(docText(`# t\n\nkey ${fake.awsKey()}\n`)).toMatch(/secret/i);
  });
  it('ownership: new file; owned and unchanged; edited by the user; unknown; no input', () => {
    expect(docText(DOC_OK, docInputs({ baseSha: null, recordSha: null }))).toBe('');
    expect(docText(DOC_OK, docInputs({ baseSha: null, recordSha: 'a'.repeat(40) }))).toBe('');   // the record is stale, the file is gone: new
    expect(docText(DOC_OK, docInputs({ baseSha: 'a'.repeat(40), recordSha: 'a'.repeat(40) }))).toBe('');
    expect(docText(DOC_OK, docInputs({ baseSha: 'a'.repeat(40), recordSha: 'b'.repeat(40) }))).toMatch(/own|changed|exists/i);
    expect(docText(DOC_OK, docInputs({ baseSha: 'a'.repeat(40), recordSha: null }))).toMatch(/own|exists/i);
    expect(docText(DOC_OK, { containsKnownValue })).toMatch(/own|input|install record/i);
  });
  it('a blob sha that is not 40 hex characters is refused', () => {
    for (const sha of ['abc', 'A'.repeat(40), 'g'.repeat(40), '']) {
      expect(docText(DOC_OK, docInputs({ baseSha: sha, recordSha: sha })), sha).toMatch(/40-character/);
      expect(docText(DOC_OK, docInputs({ baseSha: null, recordSha: sha })), sha).toMatch(/40-character/);
    }
  });
  it('an edited marker on PIPEGEN.md is refused (it is written whole)', () => {
    expect(text(docFile(DOC_OK, { edited: { original: '' } }), draft, env(docInputs())).length).toBeGreaterThan(0);
  });
  it('a wrong part is refused', () => {
    expect(text(docFile(DOC_OK, { part: 'pipeline' }), draft, env(docInputs())).length).toBeGreaterThan(0);
  });
  it('the owner and repo come from the draft profile (a link to another repo is foreign)', () => {
    const other = mkDraft({}, baseProfile({ owner: 'acme', repo: 'shop' }));
    expect(docText('# t\n\n[a](https://github.com/acme/shop/x)\n', docInputs(), other)).toBe('');
    expect(docText('# t\n\n[a](https://github.com/o/r/x)\n', docInputs(), other)).toMatch(/link|URL/i);
  });
});

function readPkg(): string { return readFileSync(new URL('../package.json', import.meta.url), 'utf8'); }

// ---------- through the referee ----------

describe('referee: the three judges run on real files', () => {
  const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
  const run = (files: CreatedFile[], inputs: CreatedEnv['inputs'] = {}, d: PipelineDraft = draft) => referee(files, d, platform(), reviewed, LINTERS, 'tok', { runLinters: async () => [], createdInputs: inputs });
  it('good files pass', async () => {
    const r = await run([good(), depFile(withEntry(null)), docFile(DOC_OK)], docInputs());
    expect(r.issues).toEqual([]);
    expect(r.ok).toBe(true);
  });
  it('bad files are template issues', async () => {
    const r = await run([coFile(`${block}* @mallory\n`), depFile(withEntry(null, { ...(entry as object), 'open-pull-requests-limit': 0 })), docFile('<img src=x>\n')], docInputs());
    expect(r.ok).toBe(false);
    for (const p of ['.github/CODEOWNERS', DEP, 'PIPEGEN.md']) expect(r.issues.some((i) => i.file === p && i.check === 'template'), p).toBe(true);
  });
  it('without createdInputs the PIPEGEN.md and central CODEOWNERS are refused', async () => {
    expect((await run([docFile(DOC_OK)])).ok).toBe(false);
  });
});
