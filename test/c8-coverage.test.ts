// D9 (v0.2 Plan D, ruling B5 c8 part, rulings D6-B2 and D9-2): c8 runs the service's own tests with a coverage minimum pipegen's code fills.
// Before D9 the reviewed c8 entry ran `c8 --check-coverage` with no command, which c8 12.0.0 refuses on every run ("Not enough non-option
// arguments", exit 1; the live check is in L/task-D9-report.md). Now:
// - choice `lines` (COVERAGE_MINIMUMS), rendered as `--lines={lines}`; pipegen's code fills it (coverageChoice), never the AI;
// - the command after `--` comes from a fixed table by the service's package manager (TEST_COMMANDS: npm → `"$nodebin/npm" test`), never
//   from repo text or from the entry's own words; anything not in the table is refused with a note.
// Written first.
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { parse, stringify } from 'yaml';
import { aiChoiceNames, CODE_FILLED_CHOICES } from '../src/create/coverage.js';
import { RenderError, renderStepWith, type RenderedStep, type RenderResult } from '../src/engine/render-step.js';
import { argvPolicyProblems, loadReviewed } from '../src/engine/reviewed.js';
import { ARGV_POLICIES, COVERAGE_MINIMUMS, TEST_COMMANDS, type ArgvPolicy } from '../src/engine/tool-flags.js';
import type { PackageManager, ReviewedTool, Service } from '../src/types.js';
import { ctxFor, entry, platform, service, specFor } from './helpers/render.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

const ROOT = resolve(import.meta.dirname, '..');
const DATA = join(ROOT, 'data/reviewed-tools.yml');
type Entry = Record<string, any>;
const rawFile = () => parse(readFileSync(DATA, 'utf8')) as { pinnedOn: string; tools: Entry[] };
const realEntry = (id: string): Entry => structuredClone(rawFile().tools.find((t) => t.id === id) as Entry);
const loadAt = (tools: Entry[]) => {
  const dir = makeTempDir();
  writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: rawFile().pinnedOn, tools }));
  return loadReviewed(`${dir}/reviewed-tools.yml`);
};
afterAll(() => cleanupRepos());

const npmApp = (over: Partial<Service> = {}): Service => service({ name: 'app', path: '.', packageManager: 'npm', scripts: ['test'], ...over });
/** `svc` null: a step that names no service. */
const renderC8 = (svc: Service | null = npmApp(), choices: Record<string, string> = { lines: '80' }, policies?: Record<string, ArgvPolicy>): RenderResult => {
  const t = entry('c8');
  const ctx = ctxFor(svc === null ? [npmApp()] : [svc]);
  return renderStepWith(specFor(t, { needId: 'coverage', ...(svc === null ? {} : { service: svc.name }), ...(svc !== null && svc.path !== '.' ? { workingDir: svc.path } : {}), choices }), t, platform(), ctx, policies === undefined ? {} : { policies });
};
const lastRun = (r: RenderResult): RenderedStep => r.steps.filter((s) => s.run !== undefined).at(-1) as RenderedStep;

describe('D9: the c8 policy and the fixed test-command table', () => {
  it('c8 takes --check-coverage, --all (E9, D9 review I1) and --lines from COVERAGE_MINIMUMS, all required, and runs the service\'s test command (testCommand)', () => {
    const p = ARGV_POLICIES.c8 as ArgvPolicy;
    expect(p.flags).toEqual({ 'check-coverage': 'bool', all: 'bool', lines: { values: COVERAGE_MINIMUMS } });
    expect(p.required).toEqual({ 'check-coverage': 'true', all: 'true', lines: null });
    expect(p.testCommand).toBe(true);
    expect(p.runsRepoCode).toBe(true);
    expect(p.positionals).toBeUndefined();
    expect(COVERAGE_MINIMUMS).toEqual(['60', '70', '80', '90']);
  });
  it('TEST_COMMANDS is a frozen table with one row: npm runs `npm test` (the project\'s script runner, from the Node setup folder)', () => {
    expect(TEST_COMMANDS).toEqual({ npm: { exe: 'npm', args: ['test'] } });
    expect(Object.isFrozen(TEST_COMMANDS)).toBe(true);
    expect(Object.isFrozen(TEST_COMMANDS.npm)).toBe(true);
    expect(Object.isFrozen(TEST_COMMANDS.npm?.args)).toBe(true);
  });
  it('only c8 runs a test command, and only as an npm tool that runs repo code (vitest-coverage runs its own `vitest run`, D9-2: no --isolate)', () => {
    const with_ = Object.entries(ARGV_POLICIES).filter(([, p]) => p.testCommand === true).map(([id]) => id);
    expect(with_).toEqual(['c8']);
    const v = ARGV_POLICIES['vitest-coverage'] as ArgvPolicy;
    expect(v.testCommand).toBeUndefined();
    expect(Object.keys(v.flags)).not.toContain('isolate');
  });
});

describe('D9: the reviewed c8 entry', () => {
  it('runs `c8 --check-coverage --all --lines={lines}` with the same fixed args, offers lines 60/70/80/90, and loads', () => {
    const t = loadReviewed().find((e) => e.id === 'c8') as ReviewedTool;
    expect(t.step.cli?.command).toEqual(['c8', '--check-coverage', '--all', '--lines={lines}']);
    expect(t.fixedInputs.args).toEqual(['--check-coverage', '--all', '--lines={lines}']);
    expect(t.choices).toEqual({ lines: ['60', '70', '80', '90'] });
    expect(argvPolicyProblems({ ...t, releasedAt: realEntry('c8').releasedAt } as Parameters<typeof argvPolicyProblems>[0])).toEqual([]);
    expect(t.reviewedBy).toBe('Claude delegated DECISIONS 105');
    expect(t.reviewedAt).toBe('2026-11-04');
  });
  it('the loader refuses c8 without --all (E9: an empty measurement would pass the minimum)', () => {
    const e = realEntry('c8');
    e.step.cli.command = ['c8', '--check-coverage', '--lines={lines}']; e.fixedInputs.args = ['--check-coverage', '--lines={lines}'];
    expect(() => loadAt([e])).toThrow(/c8/);
  });
  it('the AI is never offered `lines`: pipegen\'s code fills it (Plan F schema uses aiChoiceNames)', () => {
    const t = loadReviewed().find((e) => e.id === 'c8') as ReviewedTool;
    expect(CODE_FILLED_CHOICES.c8).toBe('lines');
    expect(aiChoiceNames('c8', t.choices)).toEqual([]);
  });
  it('the comment above the entry no longer says the minimum goes into .c8rc.json (B4: pipegen creates no c8 config)', () => {
    const text = readFileSync(DATA, 'utf8');
    const at = text.indexOf('  - id: c8\n');
    const above = text.slice(text.lastIndexOf('\n\n', at), at);
    expect(above).not.toMatch(/\.c8rc\.json \(Plan D\)/);
    expect(above).toMatch(/--lines/);
    expect(above).toMatch(/npm test/);
    expect(above).toMatch(/--all/);
  });
  it('the loader refuses a test command, a `--`, or any other word in the entry itself (the table is the only source)', () => {
    const both = (change: (xs: string[]) => string[]) => {
      const e = realEntry('c8');
      e.step.cli.command = [e.step.cli.command[0], ...change(e.step.cli.command.slice(1))];
      e.fixedInputs.args = change(e.fixedInputs.args);
      return e;
    };
    const cmdOnly = (words: string[]) => { const e = realEntry('c8'); e.step.cli.command = [...e.step.cli.command, ...words]; return e; };
    for (const e of [cmdOnly(['--', 'npm', 'test']), cmdOnly(['npm', 'test']), cmdOnly(['--', 'node', '-e', 'x']), cmdOnly(['--']), both((xs) => [...xs, '--', 'npm', 'test'])]) {
      expect(() => loadAt([e])).toThrow(/c8/);
    }
  });
  it('the loader refuses c8 without --lines, with a value off the list, with a choice value off the list, or with --lines turned into a constant', () => {
    const e1 = realEntry('c8'); e1.step.cli.command = ['c8', '--check-coverage', '--all']; e1.fixedInputs.args = ['--check-coverage', '--all']; e1.choices = {};
    const e2 = realEntry('c8'); e2.choices.lines = ['50', '60'];
    const e3 = realEntry('c8'); e3.step.cli.command = ['c8', '--check-coverage', '--all', '--lines=0']; e3.fixedInputs.args = ['--check-coverage', '--all', '--lines=0']; e3.choices = {};
    const e4 = realEntry('c8'); e4.step.cli.command = ['c8', '--check-coverage', '--all', '--lines={lines}', '--lines=0'];
    const e5 = realEntry('c8'); e5.fixedInputs.args = ['--check-coverage', '--all'];
    const e6 = realEntry('c8'); e6.step.cli.command = ['c8', '--check-coverage', '--all', '--lines={lines}', '--per-file'];
    for (const e of [e1, e2, e3, e4, e5, e6]) expect(() => loadAt([e])).toThrow(/c8/);
    expect(loadAt([realEntry('c8')])).toHaveLength(1);
  });
  it('only `--flag={flag}` (its own placeholder) is a choice slot: a fixed constant or another placeholder still makes the choice a fixed input', () => {
    // a constant --lines=80 in the fixed args with a `lines` choice offered: the AI may not choose a fixed flag
    const constant = realEntry('c8');
    constant.step.cli.command = ['c8', '--check-coverage', '--all', '--lines=80']; constant.fixedInputs.args = ['--check-coverage', '--all', '--lines=80'];
    expect(() => loadAt([constant])).toThrow(/the AI may not choose lines: it is a fixed input/);
    // --lines={other}: the placeholder is not the flag's own, so --lines is fixed and the `lines` choice is refused
    const other = realEntry('c8');
    other.step.cli.command = ['c8', '--check-coverage', '--all', '--lines={other}']; other.fixedInputs.args = ['--check-coverage', '--all', '--lines={other}'];
    other.choices = { lines: ['60'], other: ['60'] };
    expect(() => loadAt([other])).toThrow(/the AI may not choose lines: it is a fixed input/);
  });
});

describe('D9: rendering c8', () => {
  it('render: c8 argv = --check-coverage --all --lines=<n> -- npm test', () => {
    const run = lastRun(renderC8());
    expect(run.run).toContain('"$nodebin/node" "$PWD/node_modules/c8/bin/c8.js" --check-coverage --all --lines="$PIPEGEN_ARG_0" -- "$nodebin/npm" test || rc=$?');
    expect(run.env?.PIPEGEN_ARG_0).toBe('80');
    expect(run.run).toMatch(/^ {2}"CI=true"$/m);
    expect(run.id).toMatch(/^repocode-[0-9a-f]{16}$/);
    // the test command appears once, at the end, after the only `--`
    expect((run.run as string).match(/ -- /g)).toHaveLength(1);
    expect(run.run).not.toMatch(/\bnpx\b/);
  });
  it('every value of the minimum renders, and the default (no value given) is the lowest, 60', () => {
    for (const v of COVERAGE_MINIMUMS) expect(lastRun(renderC8(npmApp(), { lines: v })).env?.PIPEGEN_ARG_0).toBe(v);
    expect(lastRun(renderC8(npmApp(), {})).env?.PIPEGEN_ARG_0).toBe('60');
    expect(() => renderC8(npmApp(), { lines: '50' })).toThrow(RenderError);
    expect(() => renderC8(npmApp(), { lines: '0' })).toThrow(RenderError);
  });
  it('a service folder: the run cds into it first, and the test command is still the fixed one', () => {
    const r = lastRun(renderC8(npmApp({ name: 'api', path: 'services/api' })));
    expect(r.run).toContain("cd -- ./services/api");
    expect(r.run).toContain('-- "$nodebin/npm" test || rc=$?');
  });
  it('anything not in the table is refused with a note: pnpm, yarn, bun, pip, poetry, uv, other, no package manager', () => {
    for (const pm of ['pnpm', 'yarn', 'bun', 'pip', 'poetry', 'uv', 'other', undefined] as (PackageManager | undefined)[]) {
      const svc = npmApp(pm === undefined ? {} : { packageManager: pm });
      if (pm === undefined) delete (svc as { packageManager?: PackageManager }).packageManager;
      expect(() => renderC8(svc), String(pm)).toThrow(/runs the service's tests with a fixed command, which pipegen has for npm services only/);
    }
  });
  it('a service with no test script, or no service at all, is refused (npm test would only fail)', () => {
    expect(() => renderC8(npmApp({ scripts: ['lint'] }))).toThrow(/has no test script/);
    expect(() => renderC8(null)).toThrow(/runs the tests of one service/);
  });
  it('the table is read by own keys only: a package manager named like an Object.prototype member finds nothing', () => {
    for (const pm of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
      expect(() => renderC8(npmApp({ packageManager: pm as PackageManager }))).toThrow(RenderError);
    }
  });
  it('a policy that asks for a test command but is not an npm tool that runs repo code is refused (fail closed)', () => {
    const base = ARGV_POLICIES.c8 as ArgvPolicy;
    const { runsRepoCode: _drop, ...noRepo } = base;
    expect(() => renderC8(npmApp(), { lines: '80' }, { ...ARGV_POLICIES, c8: noRepo as ArgvPolicy })).toThrow(/test command/);
  });
  it('without testCommand the old form (no command) is what renders, so the flag is what adds the command', () => {
    const { testCommand: _drop, ...plain } = ARGV_POLICIES.c8 as ArgvPolicy;
    const run = lastRun(renderC8(npmApp(), { lines: '80' }, { ...ARGV_POLICIES, c8: plain as ArgvPolicy }));
    expect(run.run).not.toContain(' -- ');
    expect(run.run).not.toContain('"CI=true"');
  });
});
