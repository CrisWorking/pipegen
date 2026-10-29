// LIVE (PIPEGEN_LIVE_TESTS=1, uses the network): ruling S22. The real pinned actionlint and zizmor are downloaded and
// verified by ensureLinters(), then run (runLinters, pipegen's own configs; zizmor online with the token from the environment) over a
// workflow made by the real renderer whose job has `cache-mode: none`. Neither linter may reject that key. Without
// the token only actionlint is checked and zizmor is skipped (and says so). Skipped by default, so `npm test` stays offline.
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { ensureLinters, loadPinnedBinaries, runLinters } from '../src/engine/linters.js';
import { renderJobPrelude, renderStep, stepsToYaml, type RenderedStep } from '../src/engine/render-step.js';
import type { CreatedFile } from '../src/types.js';
import { liveToken } from './helpers/live-token.js';
import { ctxFor, entry, platform, specFor } from './helpers/render.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1' && process.platform !== 'win32';
const online = liveToken() ?? null;

/** A pull_request workflow with one gitleaks job as the renderer makes it, `cache-mode: none` on the job. */
function fixture(): CreatedFile {
  const t = entry('gitleaks');
  const spec = specFor(t, { needId: 'secrets', service: undefined });
  const r = renderStep(spec, t, platform(), ctxFor());
  const steps: RenderedStep[] = [
    ...renderJobPrelude({ fetchDepth: r.fullHistory === true ? '0' : '1' }, platform()).steps,
    ...r.steps,   // no scrub or upload: the point here is the job key, and the scrub step needs the gate action, which is Plan C's C6
  ];
  const doc = new Document();
  doc.contents = doc.createNode({
    name: 'pipegen', on: { pull_request: null }, permissions: {},
    jobs: { scan: { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none' } },
  });
  doc.setIn(['jobs', 'scan', 'steps'], stepsToYaml(steps));
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 'live test', repo: 'app' };
}

describe.skipIf(!live)('live: the real actionlint and zizmor accept cache-mode: none under pipegen\'s configs (S22)', () => {
  it('real actionlint and zizmor pass a rendered job with cache-mode none', async () => {
    const f = fixture();
    expect(f.content).toContain('cache-mode: none');
    const pins = loadPinnedBinaries();
    const linters = ensureLinters();
    const a = await linters.actionlint();
    const z = await linters.zizmor();
    console.log(`actionlint ${pins.actionlint.version} at ${a}`);
    console.log(`zizmor ${pins.zizmor.version} at ${z}`);
    const issues = await runLinters([f], linters, online);
    for (const i of issues) console.log(`${i.check} ${i.file}:${i.line ?? '-'} ${i.message}`);
    if (online === null) console.log(`no GitHub token is set (GITHUB_TOKEN or GH_TOKEN): zizmor was skipped (the no-credential issue above is expected)`);
    // S22: no linter refuses the job key
    expect(issues.filter((i) => /cache-mode/.test(i.message)), JSON.stringify(issues)).toEqual([]);
    // and the tools really ran: every issue is a finding with a line, except the expected no-token one
    expect(issues.filter((i) => i.line === undefined && !(online === null && i.check === 'zizmor')), JSON.stringify(issues)).toEqual([]);
    expect(issues.filter((i) => i.check === 'actionlint'), 'actionlint finds nothing in a rendered workflow').toEqual([]);
    // the linters really ran: a planted problem is found by each of them, with a line, under the same configs
    const bad: CreatedFile = {
      ...f,
      content: 'name: bad\non: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    cache-mode: none\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo ${{ github.head_ref }} ${{ nosuchcontext.x }}\n',
    };
    const found = await runLinters([bad], linters, online);
    for (const i of found) console.log(`planted: ${i.check} ${i.file}:${i.line ?? '-'} ${i.message.slice(0, 120)}`);
    expect(found.filter((i) => /cache-mode/.test(i.message))).toEqual([]);
    expect(found.some((i) => i.check === 'actionlint' && i.line !== undefined), JSON.stringify(found)).toBe(true);
    if (online !== null) expect(found.some((i) => i.check === 'zizmor' && i.line !== undefined), JSON.stringify(found)).toBe(true);

    // --no-ignores: an inline ignore comment does not silence an injection. The comment sits on the `run: |` line itself, so it
    // does not cut the scalar and BOTH planted expressions stay active (the comment on the expression line used to hide one).
    const ignored: CreatedFile = { ...f, content: bad.content.replace('      - run: echo ${{ github.head_ref }} ${{ nosuchcontext.x }}\n', '      - run: | # zizmor: ignore[template-injection]\n          echo ${{ github.head_ref }} ${{ nosuchcontext.x }}\n') };
    expect(ignored.content).toContain('# zizmor: ignore[template-injection]\n          echo ${{ github.head_ref }} ${{ nosuchcontext.x }}');
    const ig = await runLinters([ignored], linters, online);
    for (const i of ig) console.log(`inline-ignore: ${i.check} ${i.file}:${i.line ?? '-'} ${i.message.slice(0, 80)}`);
    // both expressions stay active: zizmor reports two template-injection findings (it reported one before the fix)
    if (online !== null) expect(ig.filter((i) => i.check === 'zizmor' && /template-injection/.test(i.message)), JSON.stringify(ig)).toHaveLength(2);
    // --strict-collection: a central repo with one valid workflow and one schema-invalid action file is an issue
    const central: CreatedFile[] = [
      { ...f, repo: 'central' },
      { path: '.github/actions/x/action.yml', content: 'name: x\nruns:\n  using: composite\n  steps: 5\n  bogus-key: ${{ github.head_ref }}\n', part: 'pipeline', reason: 'live test', repo: 'central' },
    ];
    const strict = await runLinters(central, linters, online);
    for (const i of strict) console.log(`strict: ${i.check} ${i.file}:${i.line ?? '-'} ${i.message.slice(0, 100)}`);
    if (online !== null) expect(strict.some((i) => i.check === 'zizmor' && i.repo === 'central'), JSON.stringify(strict)).toBe(true);
    // impostor-commit (online only): a commit that exists only in a fork of actions/checkout
    const impostor: CreatedFile = { ...f, content: 'name: imp\non: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@c7d749a2d57b4b375d1ebcd17cfbfb60c676f18e\n' };
    const imp = await runLinters([impostor], linters, online);
    for (const i of imp) console.log(`impostor: ${i.check} ${i.file}:${i.line ?? '-'} ${i.message.slice(0, 100)}`);
    if (online !== null) expect(imp.some((i) => i.check === 'zizmor' && /impostor-commit/.test(i.message)), JSON.stringify(imp)).toBe(true);
    // S22 again under --no-ignores and --strict-collection: the rendered fixture still passes
    expect((await runLinters([f], linters, online)).filter((i) => /cache-mode/.test(i.message))).toEqual([]);
  }, 600_000);
});
