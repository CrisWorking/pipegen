// v0.2 Plan D, D0a: every created file is judged or refused (preflight B1, S1, S11). The registry of created-file kinds,
// the CF-1 path rule and the `edited` marker.
import { describe, expect, it } from 'vitest';
import { referee, type Linters } from '../src/engine/referee.js';
import { createdPathProblem } from '../src/engine/job-rules.js';
import { CREATED_RULES, duplicatePathProblems, type CreatedRule } from '../src/engine/created-files.js';
import type { Capabilities, CreatedFile, PipelineDraft } from '../src/types.js';
import { platform, profile, reviewedList, service } from './helpers/render.js';

const prof = profile([service({ name: 'api', path: '.' })]);
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const draft: PipelineDraft = { profile: prof, capabilities: caps, needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [] };
const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
const p = platform();
const run = (files: CreatedFile[], createdRules?: readonly CreatedRule[]) => referee(files, draft, p, reviewedList(), LINTERS, 'tok', { runLinters: async () => [], ...(createdRules === undefined ? {} : { createdRules }) });
const file = (path: string, content = 'x\n', extra: Partial<CreatedFile> = {}): CreatedFile => ({ path, content, part: 'docs', reason: 't', repo: 'app', ...extra });

describe('registry: a CreatedFile no rule claims is refused', () => {
  const UNCLAIMED = ['CODEOWNERS', 'docs/CODEOWNERS', 'lefthook.yml', '.gitleaksignore', '.semgrepignore', '.trivyignore', 'biome.json', 'eslint.config.js', '.hadolint.yaml', '.c8rc.json', 'vitest.config.ts', 'knip.json', 'x.txt'];
  for (const path of UNCLAIMED) {
    it(`refuses ${path} (template)`, async () => {
      const r = await run([file(path)]);
      expect(r.ok).toBe(false);
      expect(r.issues.some((i) => i.check === 'template' && i.file === path)).toBe(true);
    });
  }
  it('a path that is claimed by no rule says so', async () => {
    const r = await run([file('x.txt')]);
    expect(r.issues.map((i) => i.message).join(' ')).toMatch(/pipegen writes no file of this kind/);
  });
  it('the old behaviour (a normalized path outside .github/ passes unjudged) is gone', async () => {
    expect((await run([file('docs/notes.txt')])).ok).toBe(false);
  });
});

describe('registry: each registered rule runs its judge', () => {
  const rule = (over: Partial<CreatedRule> = {}): CreatedRule => ({ id: 't', repo: 'app', parts: ['docs'], match: (path) => path === 'NOTES.md', mode: 'new', judge: () => [], ...over });
  it('a judge with no problem lets the file pass', async () => {
    expect((await run([file('NOTES.md')], [rule()])).issues).toEqual([]);
  });
  it('a judge problem becomes a template issue on that file', async () => {
    const r = await run([file('NOTES.md')], [rule({ judge: () => ['the text is wrong'] })]);
    expect(r.issues).toEqual([expect.objectContaining({ file: 'NOTES.md', check: 'template', message: expect.stringContaining('the text is wrong') })]);
  });
  it('the judge gets the file and the draft', async () => {
    let seen: unknown;
    await run([file('NOTES.md', 'abc')], [rule({ judge: (f, ctx) => { seen = [f.content, ctx.draft === draft]; return []; } })]);
    expect(seen).toEqual(['abc', true]);
  });
  it('a judge that throws is an issue, never a crash', async () => {
    const r = await run([file('NOTES.md')], [rule({ judge: () => { throw new Error('boom'); } })]);
    expect(r.ok).toBe(false);
  });
  it('two rules that claim one path is an issue', async () => {
    expect((await run([file('NOTES.md')], [rule({ id: 'a' }), rule({ id: 'b' })])).ok).toBe(false);
  });
  it('the wrong repo or the wrong part is an issue', async () => {
    expect((await run([file('NOTES.md', 'x', { repo: 'central' })], [rule()])).ok).toBe(false);
    expect((await run([file('NOTES.md', 'x', { part: 'tests' })], [rule()])).ok).toBe(false);
  });
  it('mode new refuses an edit; mode edit needs the edited marker', async () => {
    expect((await run([file('NOTES.md', 'x', { edited: { original: '' } })], [rule()])).ok).toBe(false);
    expect((await run([file('NOTES.md')], [rule({ mode: 'edit' })])).ok).toBe(false);
    expect((await run([file('NOTES.md', 'x', { edited: { original: '' } })], [rule({ mode: 'edit' })])).ok).toBe(true);
  });
  it('a rule that needs confirmation refuses a file without needsConfirm', async () => {
    expect((await run([file('NOTES.md')], [rule({ needsConfirm: true })])).ok).toBe(false);
    expect((await run([file('NOTES.md', 'x', { needsConfirm: true })], [rule({ needsConfirm: true })])).ok).toBe(true);
  });
  it('a rule on a .github/ path is reached (D0b registers dependabot and CODEOWNERS there)', async () => {
    const r = rule({ match: (path) => path === '.github/CODEOWNERS' });
    expect((await run([file('.github/CODEOWNERS')], [r])).ok).toBe(true);
    expect((await run([file('.github/CODEOWNERS')], [])).ok).toBe(false);
  });
  it('the default registry has a refusing stub for each later sub-task file, none passes unjudged', async () => {
    const paths = ['CODEOWNERS', 'docs/CODEOWNERS', '.github/CODEOWNERS', '.github/dependabot.yml', '.github/dependabot.yaml', 'PIPEGEN.md', 'Dockerfile', 'api/Dockerfile', 'api/.dockerignore', 'docker-compose.pipegen.yml', 'api/tests/a.test.ts', 'api/test/a.test.ts', 'api/__tests__/a.test.ts', 'package.json', 'api/package.json', 'package-lock.json', 'api/package-lock.json'];
    for (const path of paths) {
      const matching = CREATED_RULES.filter((r) => r.repo === 'app' && r.match(path, draft));
      expect(matching.length, path).toBe(1);
      const r = await run([file(path, 'x', { part: matching[0]?.parts[0] ?? 'docs', needsConfirm: true, ...(matching[0]?.mode === 'edit' ? { edited: { original: '' } } : {}) })]);
      expect(r.ok, path).toBe(false);
    }
  });
  it('the central repo has its own CODEOWNERS stub and nothing else', async () => {
    expect(CREATED_RULES.filter((r) => r.repo === 'central').map((r) => r.id)).toEqual(['codeowners-central']);
    expect((await run([file('CODEOWNERS', 'x', { repo: 'central', part: 'codeowners', edited: { original: '' } })])).ok).toBe(false);
    expect((await run([file('PIPEGEN.md', 'x', { repo: 'central' })])).issues.some((i) => /no file of this kind/.test(i.message))).toBe(true);
  });
  it('the default registry has no rule for a tool config or an ignore file', () => {
    for (const path of ['biome.json', 'eslint.config.js', '.hadolint.yaml', '.c8rc.json', 'vitest.config.ts', 'knip.json', '.prettierrc', '.prettierignore', '.gitleaksignore', '.semgrepignore', '.trivyignore', 'lefthook.yml', '.pre-commit-config.yaml']) {
      expect(CREATED_RULES.filter((r) => r.match(path, draft)).map((r) => r.id), path).toEqual([]);
    }
  });
  it('rule ids are unique', () => {
    const ids = CREATED_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('package.json / package-lock.json rules need needsConfirm', () => {
  for (const path of ['package.json', 'package-lock.json', 'api/package.json', 'api/package-lock.json']) {
    it(`${path}: a rule that would pass the content still refuses without needsConfirm`, async () => {
      const real = CREATED_RULES.filter((r) => r.match(path, draft));
      expect(real).toHaveLength(1);
      expect(real[0]?.needsConfirm).toBe(true);
      const passing: CreatedRule[] = CREATED_RULES.map((r) => (r === real[0] ? { ...r, judge: () => [] } : r));
      const edited = { original: '{}' };
      const without = await run([file(path, '{}', { part: 'tests', edited })], passing);
      expect(without.issues.some((i) => i.check === 'template' && /confirm/i.test(i.message))).toBe(true);
      const withIt = await run([file(path, '{}', { part: 'tests', edited, needsConfirm: true })], passing);
      expect(withIt.ok).toBe(true);
    });
  }
});

describe('the edited marker (S11) and inserted', () => {
  it('edited on a path no rule claims → template', async () => {
    const r = await run([file('biome.json', '{}', { edited: { original: '{}' } })]);
    expect(r.issues.some((i) => i.check === 'template' && i.file === 'biome.json')).toBe(true);
  });
  it('inserted on a non-workflow file is still refused', async () => {
    const ins = { original: '', jobs: [], needs: [] };
    const r = await run([file('NOTES.md', 'x', { inserted: ins })], [{ id: 't', repo: 'app', parts: ['docs'], match: () => true, mode: 'new', judge: () => [] }]);
    expect(r.issues.some((i) => i.check === 'template' && /edited user workflow/.test(i.message))).toBe(true);
  });
  it('edited on a workflow file is refused (a workflow edit uses inserted)', async () => {
    const wf = ['name: x', 'on: pull_request', 'permissions: {}', 'jobs: {}', ''].join('\n');
    const r = await run([file('.github/workflows/x.yml', wf, { part: 'pipeline', edited: { original: wf } })]);
    expect(r.issues.some((i) => i.check === 'template' && /edited/.test(i.message))).toBe(true);
  });
  it('a malformed edited marker (original not a string) is refused', async () => {
    const r = await run([file('NOTES.md', 'x', { edited: { original: 5 as unknown as string } })], [{ id: 't', repo: 'app', parts: ['docs'], match: () => true, mode: 'edit', judge: () => [] }]);
    expect(r.ok).toBe(false);
  });
});

describe('path rule CF-1 (S1)', () => {
  const REFUSED: [string, string][] = [
    ['percent', 'a%2Fb/x.yml'], ['question mark', 'a?/x.yml'], ['hash', 'a#b/x.yml'], ['colon', 'C:/x'], ['space inside', 'a b/x'],
    ['leading space', ' x/y'], ['trailing space', 'x/y '], ['segment leading space', 'a/ b'],
    ['leading dash', 'a/-rf'], ['leading dash first segment', '-x/y'], ['at', 'a@b/x'], ['plus', 'a+b/x'], ['tilde', 'GIT~1/x'],
    ['.git', '.git/config'], ['.GIT', 'a/.GIT/config'], ['.Git file', 'a/.Git'], ['trailing dot', 'a./x'], ['trailing dot file', 'a/b.'],
    ['CON', 'CON'], ['con', 'a/con'], ['NUL.txt', 'NUL.txt'], ['aux.tar.gz', 'x/aux.tar.gz'], ['COM1', 'COM1'], ['Com9.yml', 'Com9.yml'], ['LPT1', 'x/LPT1'], ['lpt9.md', 'lpt9.md'], ['PRN', 'PRN'],
    ['segment 101', `${'a'.repeat(101)}/x`], ['total 201', `${'a'.repeat(100)}/${'b'.repeat(100)}`], ['total 201 b', `${'a'.repeat(70)}/${'b'.repeat(70)}/${'c'.repeat(59)}`],
  ];
  for (const [name, path] of REFUSED) it(`refuses ${name}`, () => { expect(createdPathProblem(path), JSON.stringify(path)).not.toBeNull(); });
  it('accepts the plain forms pipegen writes', () => {
    for (const ok of ['.github/workflows/pipegen.yml', '.github/actions/x/action.yml', 'docs/CODEOWNERS', 'Dockerfile', '.pre-commit-config.yaml', '.zap/rules.tsv', 'api/tests/a.test.ts', 'a_b/c-d/e.f.g', '.gitignore', '.github/CODEOWNERS', 'console/x', 'CON1', 'communicate.txt', 'a'.repeat(100), `${'a'.repeat(99)}/${'b'.repeat(100)}`]) expect(createdPathProblem(ok), ok).toBeNull();
  });
  it('the limits sit exactly: 100 per segment, 200 in total', () => {
    expect(createdPathProblem(`${'a'.repeat(100)}/${'b'.repeat(99)}`)).toBeNull();   // 200
    expect(createdPathProblem(`${'a'.repeat(100)}/${'b'.repeat(100)}`)).not.toBeNull();   // 201
    expect(createdPathProblem('a'.repeat(101))).not.toBeNull();
  });
  it('the referee refuses these as a path issue', async () => {
    for (const path of ['a%2Fb.txt', 'a b.txt', 'x/.GIT/y', 'x/NUL.txt', 'x/-y.txt', 'x./y.txt']) {
      const r = await run([file(path)], [{ id: 't', repo: 'app', parts: ['docs'], match: () => true, mode: 'new', judge: () => [] }]);
      expect(r.issues.some((i) => i.check === 'template' && /path is refused/.test(i.message)), path).toBe(true);
    }
  });
});

describe('path rule: no two created files equal ignoring case', () => {
  it('duplicatePathProblems finds case clashes and exact repeats in one repo', () => {
    expect(duplicatePathProblems([file('A/b.txt'), file('a/B.txt')])).toHaveLength(1);
    expect(duplicatePathProblems([file('a.txt'), file('a.txt')])).toHaveLength(1);
    expect(duplicatePathProblems([file('a.txt'), file('b.txt')])).toEqual([]);
  });
  it('the same path in the app repo and the central repo is two different files', () => {
    expect(duplicatePathProblems([file('CODEOWNERS'), file('CODEOWNERS', 'x', { repo: 'central' })])).toEqual([]);
  });
  it('the referee refuses the clash', async () => {
    const any: CreatedRule = { id: 't', repo: 'app', parts: ['docs'], match: () => true, mode: 'new', judge: () => [] };
    const r = await run([file('Notes.md'), file('notes.MD')], [any]);
    expect(r.ok).toBe(false);
    expect(r.issues.some((i) => /ignoring (letter )?case/i.test(i.message))).toBe(true);
    expect((await run([file('Notes.md'), file('other.md')], [any])).ok).toBe(true);
  });
});

describe('the five P14 paths and the CF-1 table (final-review-r1 l.140-147) are refused', () => {
  const hostile = ['name: x', 'on: pull_request', 'permissions: {}', 'jobs:', '  j:', '    runs-on: self-hosted', '    steps:', '      - run: echo ${{ github.head_ref }}', ''].join('\n');
  const PATHS = [
    './.github/workflows/x.yml', 'tests/../.github/workflows/x.yml', '.github//workflows/x.yml', '.github/actions/../workflows/action.yml', `.github/workflows/${'a'.repeat(101)}.yml`,
    '.GitHub/Workflows/x.yml', '.GITHUB/workflows/x.yml', '.github/Workflows/x.yml', '.github/workflows/', '.github/workflows/x.yml/', '.github/workflows/sub/x.yml',
    '.github/workflows/x.YML', '.github/workflows/x.yml ', 'C:\\x\\.github\\workflows\\x.yml', 'C:/.github/workflows/x.yml',
    '.github%2Fworkflows%2Fx.yml', '%2egithub/workflows/x.yml', 'tests/%2e%2e/.github/workflows/x.yml', 'a?/x.yml', 'a#b/x.yml', ' .github/workflows/x.yml',
  ];
  for (const path of PATHS) {
    it(`refuses ${JSON.stringify(path.length > 60 ? `${path.slice(0, 40)}...` : path)}`, async () => {
      const r = await run([file(path, hostile, { part: 'pipeline' })]);
      expect(r.ok).toBe(false);
      expect(r.issues.some((i) => i.check === 'template')).toBe(true);
    });
  }
  it('.github/workflows/x.yaml is still judged like .yml', async () => {
    const r = await run([file('.github/workflows/x.yaml', hostile, { part: 'pipeline' })]);
    expect(r.issues.length).toBeGreaterThan(1);
  });
});

describe('parity: what the engine produces today still passes', () => {
  const good = ['name: pipegen', 'on: pull_request', 'permissions: {}', 'jobs:', '  noop:', '    runs-on: ubuntu-latest', '    permissions:', '      contents: read', '    steps:', '      - run: echo hi', ''].join('\n');
  it('a workflow and a composite action keep their old paths and verdicts', async () => {
    const wf = await run([file('.github/workflows/pipegen.yml', good, { part: 'pipeline' })]);
    const wfOld = wf.issues.filter((i) => i.file === '.github/workflows/pipegen.yml' && /path|kind of|edited|case/i.test(i.message));
    expect(wfOld).toEqual([]);
  });
  it('the rule table did not grow a rule for a workflow or an action path', () => {
    for (const path of ['.github/workflows/pipegen.yml', '.github/workflows/pipegen-central.yml', '.github/actions/x/action.yml']) {
      expect(CREATED_RULES.filter((r) => r.match(path, draft)), path).toEqual([]);
    }
  });
  it('workflow paths pass the path rule', () => {
    for (const path of ['.github/workflows/pipegen.yml', '.github/workflows/pipegen-central.yml', `.github/workflows/${'a'.repeat(96)}.yml`, '.github/actions/pipegen-gate/action.yml', '.github/actions/a_b.c/action.yaml']) expect(createdPathProblem(path), path).toBeNull();
  });
});
