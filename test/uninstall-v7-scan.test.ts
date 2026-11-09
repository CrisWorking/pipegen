// v0.2 Plan V V7 (the V6-R3 security carry, review-V6-security-r3.md M3): the entry-point scan (test/helpers/import-scan.ts) must catch the forms
// G1-G5, G10-G14 that got round the first parsed scan, and src/cli/uninstall.ts has an allow-list of its own. Each form below was shown to compile
// and to load the real guarded function at run time; the scan reads the parsed code (esbuild strips the types, acorn parses the rest).
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { describe, expect, it } from 'vitest';
import { codeFilesUnder, entryImportProblems } from './helpers/import-scan.js';

const root = join(import.meta.dirname, '..');
const problems = (file: string, code: string): string[] => entryImportProblems(file, code);

describe('V7 scan: the G-forms the V6-R3 review found', () => {
  it('scan: G1-G5 (an allowed file hands a guarded binding on: alias export, export const, extends, export default, object) are caught', () => {
    const forms: [string, string, string][] = [
      ['G1', 'src/uninstall/apply.ts', "import { deleteCentralRepo } from './target.js';\nconst d = deleteCentralRepo;\nexport { d as dcr };"],
      ['G2', 'src/uninstall/apply.ts', "import { deleteCentralRepo } from './target.js';\nexport const dcr = deleteCentralRepo;"],
      ['G3', 'src/uninstall/plan.ts', "import { UninstallApi } from './target.js';\nexport class Api2 extends UninstallApi {}"],
      ['G4', 'src/uninstall/apply.ts', "import { deleteCentralRepo } from './target.js';\nexport default deleteCentralRepo;"],
      ['G5', 'src/uninstall/apply.ts', "import { deleteCentralRepo } from './target.js';\nexport const all = { deleteCentralRepo };"],
      ['G5b', 'src/uninstall/apply.ts', "import { takeApi } from './target.js';\nexport const all = [takeApi];"],
      ['arg', 'src/uninstall/apply.ts', "import { planUninstall } from './plan.js';\nrun(planUninstall);"],
      ['assign', 'src/uninstall/apply.ts', "import { planUninstall } from './plan.js';\nlet f; f = planUninstall;"],
      ['member', 'src/uninstall/apply.ts', "import { planUninstall } from './plan.js';\nplanUninstall.call(null, gh);"],
      ['alias', 'src/uninstall/apply.ts', "import { planUninstall as p } from './plan.js';\nexport const q = p;"],
      // V6-R3 G11/G12: an E writer handed on by an allowed file
      ['G11', 'src/proof/zz.ts', "import { cleanupWrite } from './target.js';\nexport const cw = cleanupWrite;"],
      ['G12', 'src/cli/cleanup.ts', "import { cleanupWrite } from '../proof/target.js';\nexport const cw = cleanupWrite;"],
      ['G12b', 'src/cli/cleanup.ts', "import { cleanupLeftovers } from '../proof/cleanup.js';\nexport default cleanupLeftovers;"],
    ];
    for (const [name, file, code] of forms) expect(problems(file, code).length, name).toBeGreaterThan(0);
  });

  it('scan: a guarded binding stays allowed as a call or new target in its allowed files', () => {
    expect(problems('src/uninstall/apply.ts', "import { deleteCentralRepo, takeApi } from './target.js';\nimport { planUninstall, type UninstallPlan } from './plan.js';\nexport async function f(gh: never, p: UninstallPlan) { const a = await planUninstall(gh, p); takeApi(p, 'A'); return deleteCentralRepo?.(gh); }")).toEqual([]);
    expect(problems('src/uninstall/plan.ts', "import { UninstallApi } from './target.js';\nexport const f = (gh: never, app: never): UninstallApi => new UninstallApi(gh, app);")).toEqual([]);
    expect(problems('src/cli/cleanup.ts', "import { cleanupLeftovers } from '../proof/cleanup.js';\nexport const f = async () => cleanupLeftovers(gh, store, {});")).toEqual([]);
    // a value the file calls with another value of the same name passed as argument is a reference of the argument, not the call
    expect(problems('src/uninstall/apply.ts', "import { takeApi } from './target.js';\nexport const f = () => takeApi(plan, phase);")).toEqual([]);
  });

  it('scan: G10 (`import { default as d }`) is a default import', () => {
    expect(problems('src/cli/uninstall.ts', "import { default as d } from '../uninstall/apply.js';\nexport const x = d;").length).toBeGreaterThan(0);
    expect(problems('src/uninstall/central.ts', "import { default as d } from './target.js';\nexport const x = d;").length).toBeGreaterThan(0);
    expect(problems('src/uninstall/central.ts', "import { default as d } from '../proof/cleanup.js';").length).toBeGreaterThan(0);
    expect(problems('src/uninstall/central.ts', "import d from './target.js';").length).toBeGreaterThan(0);   // r3: already caught
    expect(problems('src/uninstall/central.ts', "export { default as d } from './target.js';").length).toBeGreaterThan(0);
  });

  it('scan: G13 (a .mts, .cts or .js file under src) is read, and a file that is not code is a problem', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pg-scan-'));
    try {
      mkdirSync(join(dir, 'a'));
      for (const f of ['x.ts', 'a/y.mts', 'a/z.cts', 'a/w.js', 'a/v.mjs', 'a/u.cjs', 'a/t.tsx', 'a/s.jsx', 'a/data.json', 'a/notes.md']) writeFileSync(join(dir, f), '');
      const found = codeFilesUnder(dir);
      expect(found.code.map((f) => relative(dir, f).split(sep).join('/')).sort()).toEqual(['a/s.jsx', 'a/t.tsx', 'a/u.cjs', 'a/v.mjs', 'a/w.js', 'a/y.mts', 'a/z.cts', 'x.ts']);
      expect(found.other.map((f) => relative(dir, f).split(sep).join('/')).sort()).toEqual(['a/data.json', 'a/notes.md']);
    } finally { rmSync(dir, { recursive: true, force: true }); }
    // the scan of such a file: UninstallApi in a .mts file is an import outside plan.ts, whatever the extension and the specifier's spelling
    for (const spec of ['./target.js', './target.mjs', './target.ts', './target']) {
      expect(problems('src/uninstall/zz-ext.mts', `import { UninstallApi } from '${spec}';\nexport const U = UninstallApi;`).length, spec).toBeGreaterThan(0);
    }
    // the specifier's spelling decides which module it is: a namespace import of the guarded module, however it is written
    for (const spec of ['./target.js', './target.mjs', './target.cjs', './target.ts', './target', './target.mts']) {
      expect(problems('src/uninstall/central.ts', `import * as t from '${spec}';`).length, `ns ${spec}`).toBeGreaterThan(0);
    }
    expect(problems('src/uninstall/zz-ext.cts', "const t = require('./target.js');").length).toBeGreaterThan(0);
    expect(problems('src/cli/zz.js', "export * from '../uninstall/target.js';").length).toBeGreaterThan(0);
  });

  it('scan: G14 (a second src/cli file hands a proof or uninstall binding on to src/cli/uninstall.ts) is caught by uninstall.ts\'s own allow-list', () => {
    expect(problems('src/cli/uninstall.ts', "import { cleanupAfterProof } from './zz.js';\nexport const f7 = cleanupAfterProof;").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { x } from './cleanup.js';").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { run } from './run.js';").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { finish } from '../deliver/finish.js';").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { cleanupWrite } from '../proof/target.js';").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { StateStore } from '../proof/state.js';").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import * as c from './commands.js';").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { finishCommand } from './commands.js';").length).toBeGreaterThan(0);   // a name outside the list, from a listed module
    expect(problems('src/cli/uninstall.ts', "import { exec } from 'node:child_process';").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { x } from 'left-pad';").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "const m = await import('./commands.js');").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "export { uninstallStep } from '../uninstall/apply.js';").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { uninstallStep } from '../uninstall/apply.js';\nexport const step = uninstallStep;").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { uninstallStep } from '../uninstall/apply.js';\nexport default uninstallStep;").length).toBeGreaterThan(0);
    expect(problems('src/cli/uninstall.ts', "import { loadUninstallRecord as l } from '../uninstall/record.js';\nexport { l };").length).toBeGreaterThan(0);
    // the same name from another file of src/cli is not touched by this rule (other commands use cleanupAfterProof by design)
    expect(problems('src/cli/zz.ts', "import { cleanupAfterProof } from '../proof/cleanup.js';\nexport const f = () => cleanupAfterProof(a, b, c, d, e);")).toEqual([]);
    // what the file needs is allowed, types included
    expect(problems('src/cli/uninstall.ts', [
      "import type { Octokit } from '@octokit/rest';",
      "import { localRecordPath } from '../deliver/record.js';",
      "import { isRateStop } from '../engine/github-rate.js';",
      "import { GitHubAccessError, hideToken } from '../github/client.js';",
      "import { NotGitHubRepoError } from '../read/project.js';",
      "import type { StateDeps } from '../proof/state.js';",
      "import { uninstallStep, type StepResult } from '../uninstall/apply.js';",
      "import { UninstallError, UninstallFinished } from '../uninstall/errors.js';",
      "import { MAX_PROGRESS_BYTES, uninstallProgressPath } from '../uninstall/progress.js';",
      "import { loadUninstallRecord } from '../uninstall/record.js';",
      "import { safeText } from '../util/safe-text.js';",
      "import { interactiveRun, type CommandGitHub, type connect } from './commands.js';",
      "import type { CliIO } from './io.js';",
      "import { lstatSync, readFileSync } from 'node:fs';",
    ].join('\n'))).toEqual([]);
  });

  it('scan: the real tree passes (every code file under src, each extension)', () => {
    const found = codeFilesUnder(join(root, 'src'));
    expect(found.other.map((f) => relative(root, f))).toEqual([]);
    expect(found.code.some((f) => f.endsWith(join('cli', 'uninstall.ts')))).toBe(true);
    const bad: string[] = [];
    for (const f of found.code) bad.push(...entryImportProblems(relative(root, f).split(sep).join('/'), readFileSync(f, 'utf8')));
    expect(bad).toEqual([]);
  });
});
