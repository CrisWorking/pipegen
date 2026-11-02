// v0.2 Plan D, D0a: every created file is judged or refused (preflight B1, S1, S11). The registry of created-file kinds,
// the CF-1 path rule and the `edited` marker.
import { describe, expect, it } from 'vitest';
import { referee, type Linters } from '../src/engine/referee.js';
import { createdPathProblem } from '../src/engine/job-rules.js';
import { CREATED_RULES, createdFileProblems, duplicatePathProblems, type CreatedRule } from '../src/engine/created-files.js';
import type { Capabilities, CreatedFile, PipelineDraft } from '../src/types.js';
import { PROTECTED_PATHS_BASE } from '../src/types.js';
import { effectiveProtectedPaths } from '../src/engine/protected-paths.js';
import { isProtectedPath } from '../src/engine/protected-match.js';
import { starterOwner } from '../src/create/test-rules.js';
import { renderJobPrelude, renderStep, stepsToYaml, type RenderContext } from '../src/engine/render-step.js';
import { Document } from 'yaml';
import { entry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';

const prof = profile([service({ name: 'root', path: '.' }), service({ name: 'api', path: 'api' })]);
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
  // a real rendered workflow (the Plan B/C renderer): prelude + the gitleaks steps, in the shape final-fix-c uses
  const gl = specFor(entry('gitleaks'), { needId: 'secrets' });
  const rctx: RenderContext = { profile: prof };
  const wfText = (): string => {
    const steps = [...renderJobPrelude({ fetchDepth: '1' }, p).steps, ...renderStep(gl, entry('gitleaks'), p, rctx).steps];
    const doc = new Document();
    doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, jobs: { j: { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none' } } });
    doc.setIn(['jobs', 'j', 'steps'], stepsToYaml(steps));
    return doc.toString({ lineWidth: 0 });
  };
  it('a rendered workflow keeps its verdict: nothing the new rules add', async () => {
    const d: PipelineDraft = { ...draft, steps: [gl], needs: [{ id: 'secrets', layer: 'merge', category: 'secrets', why: 't', blocking: true, floor: false }] };
    const before = await referee([file('.github/workflows/pipegen.yml', wfText(), { part: 'pipeline' })], d, p, reviewedList(), LINTERS, 'tok', { runLinters: async () => [] });
    expect(before.issues.filter((i) => /path|kind|edited|case|rule/i.test(i.message))).toEqual([]);
    expect(before.issues.filter((i) => i.check === 'template')).toEqual([]);
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

describe('fix round 1: matchers claim only their own files', () => {
  const claim = (path: string, repo: 'app' | 'central' = 'app') => CREATED_RULES.filter((r) => r.repo === repo && r.match(path, draft)).map((r) => r.id);
  const ALLOWED: Record<string, string[]> = { CODEOWNERS: ['codeowners', 'codeowners-central'], 'docs/CODEOWNERS': ['codeowners', 'codeowners-central'], '.github/CODEOWNERS': ['codeowners', 'codeowners-central'], '.github/dependabot.yml': ['dependabot'], 'docker-compose.pipegen.yml': ['compose'] };
  const configNames = [...new Set([...reviewedList().flatMap((t) => t.configFiles), 'biome.json', 'biome.jsonc', 'eslint.config.js', 'eslint.config.mjs', '.hadolint.yaml', '.c8rc.json', '.c8rc', 'vitest.config.ts', 'vite.config.ts', 'knip.json', '.prettierrc', '.prettierignore', '.gitleaksignore', '.semgrepignore', '.trivyignore', 'lefthook.yml', '.pre-commit-config.yaml', '.husky/pre-commit', '.zap/rules.tsv', 'renovate.json', '.renovaterc', 'CODEOWNERS', 'dependabot.yml', 'docker-compose.pipegen.yml'])];
  const protectedNames = PROTECTED_PATHS_BASE.map((x) => x.replace(/\/\*\*$/, '/x'));
  const FOLDERS = ['', 'test/', 'tests/', '__tests__/', 'api/', 'api/test/', 'api/tests/', 'api/__tests__/', '.github/', '.github/workflows/', '.github/actions/x/', '.github/actions/x/tests/', '.husky/', '.husky/test/', '.zap/', 'node_modules/x/', 'test/.github/'];
  it('no protected path, config, ignore or hook name is claimed by a rule not meant for it, at any depth', () => {
    const bad: string[] = [];
    for (const name of [...configNames, ...protectedNames]) for (const dir of FOLDERS) {
      const path = `${dir}${name}`;
      for (const repo of ['app', 'central'] as const) {
        const ids = claim(path, repo);
        if (ids.length > 0 && !(ALLOWED[path] !== undefined && ids.every((i) => ALLOWED[path]?.includes(i)))) bad.push(`${repo}:${path} -> ${ids.join(',')}`);
      }
    }
    expect(bad).toEqual([]);
  });
  it('the reviewer\'s attack paths are unclaimed', () => {
    for (const path of ['api/tests/biome.json', 'test/eslint.config.js', 'test/vitest.config.ts', '__tests__/.gitleaksignore', 'test/lefthook.yml', '.husky/test/x', '.github/test/x.yml', '.github/workflows/tests/x.yml', '.github/actions/x/tests/run.sh', '.github/Dockerfile', '.github/workflows/Dockerfile', '.github/actions/x/Dockerfile', '.github/.dockerignore', '.github/package.json', 'node_modules/x/package.json', 'a/b/c/Dockerfile', 'a/package.json', 'x/api/package.json', 'api/tests/helper.ts', 'api/tests/x.test.json', 'api/tests/a.json.ts', 'api/tests/a.test.d.ts', 'api/tests/.hidden.test.ts', 'api/tests/.x/a.test.ts', 'api/src/a.test.ts', 'api/tests/a.test.ts.bak', 'api/test/a.spec.ts', 'api/test/a.test.tsx', 'api/test/a.test.jsx', 'api/tests/a.spec.js', 'api/test/a.test.mts', 'api/tests/helpers/h.ts', 'api/__tests__/helpers/h.ts', 'api/test/helpers/h.json', 'api/test/a.ts', 'api/test/vitest.config.test.ts', 'api/tests/vite.config.spec.js', 'api/__tests__/vitest.workspace.test.mjs', 'api/tests/prettier.config.test.ts', 'api/test/knip.config.spec.cjs', 'dockerfile', 'api/Dockerfile.prod', 'API/Dockerfile', 'src/tests/a.test.ts', 'api/src/tests/a.test.ts', 'x/tests/a.test.ts']) expect(claim(path), path).toEqual([]);
  });
  it('D0a/D0b m1: no starter-test path is claimed when the gate\'s own matcher protects it (every protected glob made concrete, in every test folder)', () => {
    const roots = ['', 'api'];
    const globs = effectiveProtectedPaths(reviewedList(), roots);
    const concreteName = (g: string): string => g.replace(/^\//, '').replace(/^\*\*\//, '').replace(/\*\*/g, 'a/b').replace(/\*$/, 'test.ts').replace(/\*/g, 'x');
    const folders = ['test/', 'tests/', '__tests__/', 'test/helpers/', 'api/test/', 'api/tests/', 'api/__tests__/', 'api/test/helpers/', 'test/sub/', 'api/tests/sub/deep/'];
    let shapeOk = 0;
    const bad: string[] = [];
    for (const g of globs) for (const dir of folders) for (const suffix of ['', '.test.ts', '.test.mjs', '.test']) {
      const path = `${dir}${concreteName(g)}${suffix}`;
      const protectedByGate = isProtectedPath(path, roots);
      if (starterOwner(path, roots) !== null && protectedByGate) shapeOk++;
      if (protectedByGate && claim(path).includes('starter-tests')) bad.push(path);
    }
    expect(bad).toEqual([]);
    expect(shapeOk).toBeGreaterThan(50);   // the check is not vacuous: many names have the starter-test shape AND are protected (vitest.config.*, vite.config.*, prettier.config.*, knip.config.*, vitest.workspace.*)
    for (const path of ['test/vitest.config.test.ts', 'tests/vite.config.spec.js', '__tests__/vitest.workspace.test.mjs', 'tests/prettier.config.test.ts', 'api/test/knip.config.spec.cjs', 'api/test/vitest.config.test.mjs']) {
      expect(isProtectedPath(path, roots), path).toBe(true);
      expect(claim(path), path).toEqual([]);
    }
    // the matcher is the same one the CODEOWNERS judge uses
    expect(isProtectedPath('.github/workflows/x.yml', roots)).toBe(true);
    expect(isProtectedPath('api/test/a.test.ts', roots)).toBe(false);
  });
  it('the real forms are still claimed by exactly one rule', () => {
    const want: Record<string, string> = { Dockerfile: 'dockerfile', 'api/Dockerfile': 'dockerfile', '.dockerignore': 'dockerignore', 'api/.dockerignore': 'dockerignore', 'package.json': 'package-json', 'api/package.json': 'package-json', 'package-lock.json': 'package-lock', 'api/package-lock.json': 'package-lock', 'tests/a.test.ts': 'starter-tests', 'api/tests/a.test.ts': 'starter-tests', 'api/test/sub/b.test.mjs': 'starter-tests', 'api/__tests__/c.test.cjs': 'starter-tests', 'test/x.test.cjs': 'starter-tests', 'api/test/helpers/h.ts': 'starter-tests', 'test/helpers/deep/h.mjs': 'starter-tests', 'docker-compose.pipegen.yml': 'compose', 'PIPEGEN.md': 'pipegen-doc', '.github/dependabot.yml': 'dependabot', '.github/dependabot.yaml': 'dependabot' };
    for (const [path, id] of Object.entries(want)) expect(claim(path), path).toEqual([id]);
  });
  it('a service folder named test is claimed once (no double claim)', () => {
    const d: PipelineDraft = { ...draft, profile: profile([service({ name: 't', path: 'test' })]) };
    for (const path of ['test/package.json', 'test/Dockerfile', 'test/package-lock.json']) expect(CREATED_RULES.filter((r) => r.repo === 'app' && r.match(path, d)).length, path).toBe(1);
  });
  it('a service folder that is itself hidden or vendored gets no created file', () => {
    const d: PipelineDraft = { ...draft, profile: profile([service({ name: 'g', path: '.github' }), service({ name: 'n', path: 'node_modules/x' }), service({ name: 'h', path: '.hidden' })]) };
    for (const path of ['.github/Dockerfile', '.github/package.json', 'node_modules/x/package.json', 'node_modules/x/Dockerfile', '.hidden/package.json', '.hidden/Dockerfile', '.hidden/.dockerignore', '.hidden/tests/a.test.ts', '.github/tests/a.test.ts']) expect(CREATED_RULES.filter((r) => r.match(path, d)), path).toEqual([]);
  });
  it('a file at a service root needs that service; the root only counts when a service is there', () => {
    const d: PipelineDraft = { ...draft, profile: profile([service({ name: 'web', path: './web/' })]) };
    expect(CREATED_RULES.filter((r) => r.match('web/package.json', d)).map((r) => r.id)).toEqual(['package-json']);
    expect(CREATED_RULES.filter((r) => r.match('package.json', d))).toEqual([]);
    expect(CREATED_RULES.filter((r) => r.match('api/package.json', d))).toEqual([]);
  });
});

describe('fix round 1: inserted only on workflows, before parsing', () => {
  const ins = { original: '', jobs: [] as string[], needs: [] as { job: string; added: string[] }[] };
  const act = 'name: &a x\ndescription: *a\ninputs:\n  mode:\n    description: m\nruns:\n  using: composite\n  steps: []\n';
  it('inserted on a composite action is refused, with anchor content too', async () => {
    for (const content of [act, act.replace('&a ', '').replace('*a', 'd')]) {
      const r = await run([file('.github/actions/x/action.yml', content, { part: 'pipeline', inserted: ins })]);
      expect(r.ok).toBe(false);
      expect(r.issues.some((i) => i.check === 'template' && /edited user workflow/.test(i.message))).toBe(true);
      expect(r.issues.some((i) => /anchor|alias/i.test(i.message))).toBe(false);   // refused before the parse
    }
  });
  it('the anchor action without the marker is still refused for the anchor', async () => {
    expect((await run([file('.github/actions/x/action.yml', act, { part: 'pipeline' })])).issues.some((i) => /anchor|alias/i.test(i.message))).toBe(true);
  });
});

describe('fix round 1: minors', () => {
  const any: CreatedRule = { id: 't', repo: 'app', parts: ['docs'], match: () => true, mode: 'edit', judge: () => [] };
  it('edited: null and other malformed markers are an issue, never a throw', async () => {
    for (const bad of [null, 5, 'x', {}, { original: null }, []]) {
      const r = await run([file('N.md', 'x', { edited: bad as unknown as { original: string } })], [any]);
      expect(r.ok, JSON.stringify(bad)).toBe(false);
    }
  });
  it('a file and a folder of the same name (any case) are refused', () => {
    expect(duplicatePathProblems([file('a'), file('a/b')])).toHaveLength(1);
    expect(duplicatePathProblems([file('A'), file('a/b/c')])).toHaveLength(1);
    expect(duplicatePathProblems([file('a/b'), file('a')])).toHaveLength(1);
    expect(duplicatePathProblems([file('a'), file('a/b', 'x', { repo: 'central' })])).toEqual([]);
    expect(duplicatePathProblems([file('a'), file('A/b')])).toHaveLength(1);   // R16: the folder clash is compared ignoring case, the file in lower case, the folder in upper
    expect(duplicatePathProblems([file('ab'), file('a/b')])).toEqual([]);
    expect(duplicatePathProblems([file('a'), file('A/b')])).toHaveLength(1);
  });
  it('the referee refuses the file/folder clash', async () => {
    expect((await run([file('a'), file('a/b')], [{ ...any, mode: 'new' }])).ok).toBe(false);
  });
  it('unclaimed and path-refused issues carry the repo', async () => {
    const r = await run([file('x.txt', 'x', { repo: 'central' }), file('a b', 'x', { repo: 'central' })]);
    expect(r.issues.length).toBeGreaterThanOrEqual(2);
    for (const i of r.issues) expect(i.repo).toBe('central');
  });
  it('registry problems on a wrong-part file still carry the repo', async () => {
    const r = await run([file('NOTES.md', 'x', { part: 'tests' })], [{ ...any, mode: 'new', match: (x) => x === 'NOTES.md' }]);
    expect(r.issues.every((i) => i.repo === 'app')).toBe(true);
  });
});

describe('D0b part 0: createdFileProblems runs the path rule itself', () => {
  const hostile: PipelineDraft = { ...draft, profile: profile([service({ name: 'abs', path: '/abs' }), service({ name: 'dot', path: 'a.' })]) };
  it('a path the path rule refuses is a problem even when a matcher claims it', () => {
    for (const path of ['/abs/Dockerfile', 'a./package.json']) {
      expect(CREATED_RULES.some((r) => r.match(path, hostile)), path).toBe(true);
      const v = createdFileProblems(file(path, 'x', { part: path.endsWith('Dockerfile') ? 'docker' : 'tests' }), hostile);
      expect(v.claimed, path).toBe(true);
      expect(v.problems.join(' '), path).toMatch(/path is refused/);
    }
  });
  it('an unclaimed bad path is also refused (claimed, with the path problem)', () => {
    const v = createdFileProblems(file('a b/x.txt'), draft);
    expect(v.problems.length).toBeGreaterThan(0);
  });
});
