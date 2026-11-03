// Plan E E3 fix round 1 (review-E3 I1, I2/E3-R2): the rules every proof workflow is held to before it can enter a pushed
// tree, whoever rendered it (the harness, Plan G's assemble, this project's central files) and, narrower, the compat copies.
// These jobs run next to the user's real test keys. No network.
import { describe, expect, it } from 'vitest';
import { EGRESS_DOMAIN_SETS, renderEgressStep } from '../src/engine/egress.js';
import { stepsToYaml } from '../src/engine/render-step.js';
import { checkProofWorkflows, FORBIDDEN_PROOF_TRIGGERS, proofWorkflowProblems, type ProofWorkflowKind } from '../src/proof/workflow-check.js';
import { ProofStopError } from '../src/proof/target.js';
import { Document } from 'yaml';
import { reviewedList } from './helpers/render.js';

const reviewed = reviewedList();
const BULLFROG = reviewed.find((t) => t.id === 'bullfrog')!;
const CHECKOUT = reviewed.find((t) => t.id === 'actions-checkout')!.step.action!.uses;
const SETUP_NODE = reviewed.find((t) => t.id === 'actions-setup-node')!.step.action!.uses;
const SHA = 'a'.repeat(40);

/** The egress step as YAML lines at a job's steps indent. */
const egress = (sets: Parameters<typeof renderEgressStep>[0] = ['npm'], dockerNetworks = false): string => {
  const d = new Document();
  d.contents = stepsToYaml([renderEgressStep(sets, { dockerNetworks })]);
  return d.toString().trimEnd().split('\n').map((l) => `      ${l}`).join('\n');
};
const wf = (opts: { on?: string; first?: string; steps?: string; job?: string } = {}): string => `on: ${opts.on ?? 'pull_request'}
permissions: {}
jobs:
  build:
    runs-on: ubuntu-24.04
${opts.job ?? ''}    steps:
${opts.first ?? egress()}
      - uses: ${CHECKOUT}
        with:
          persist-credentials: "false"
${opts.steps ?? '      - run: npm test\n'}`;
const problems = (content: string, kind: ProofWorkflowKind = 'proof') => proofWorkflowProblems({ path: '.github/workflows/pipegen-x.yml', content }, kind, reviewed);

describe('proof workflow check (I1)', () => {
  it('proof workflow: a well-formed job passes; every rule names the file', () => {
    expect(problems(wf())).toEqual([]);
    expect(problems(wf({ on: '{ push: { branches: [main] }, pull_request: {} }' }))).toEqual([]);
    expect(problems(wf({ first: egress(['dockerhub', 'npm'], true) }))).toEqual([]);
    expect(() => checkProofWorkflows([{ path: '.github/workflows/pipegen-x.yml', content: wf({ on: 'workflow_dispatch' }), kind: 'proof' }], reviewed)).toThrow(ProofStopError);
    expect(() => checkProofWorkflows([{ path: '.github/workflows/pipegen-x.yml', content: wf({ on: 'workflow_dispatch' }), kind: 'proof' }], reviewed)).toThrow(/pipegen-x\.yml/);
    // files outside .github/workflows are not workflows
    expect(() => checkProofWorkflows([{ path: 'docs/x.yml', content: 'on: workflow_dispatch\n', kind: 'proof' }], reviewed)).not.toThrow();
  });

  it('proof workflow: the egress step is the first step of every job, with the reviewed pin and fixed inputs', () => {
    // no egress step at all
    expect(problems(wf({ first: '      - run: echo hi' })).join(' ')).toMatch(/build.*first step.*egress/);
    // a step before it
    expect(problems(wf({ first: `      - run: echo before\n${egress()}` })).join(' ')).toMatch(/first step/);
    // enable-sudo true, or another input changed or added
    for (const [from, to] of [[/enable-sudo: "false"/, 'enable-sudo: "true"'], [/egress-policy: block/, 'egress-policy: audit'], [/dns-policy: allowed-domains-only/, 'dns-policy: any']] as const) {
      expect(egress()).toMatch(from);
      expect(problems(wf({ first: egress().replace(from, to) })).join(' '), to).toMatch(/egress step/);
    }
    expect(problems(wf({ first: `${egress()}\n          extra: "x"` })).join(' ')).toMatch(/egress step/);
    // another pin of bullfrog, or a raw domain in the list
    expect(problems(wf({ first: egress().replace(BULLFROG.candidate.pin.sha!, SHA) })).join(' ')).toMatch(/egress step/);
    expect(problems(wf({ first: egress().replace('registry.npmjs.org', 'registry.npmjs.org\n            example.com') })).join(' ')).toMatch(/example\.com/);
    expect(problems(wf({ first: egress([], true).replace('172.16.0.0/12', '0.0.0.0/0') })).join(' ')).toMatch(/allowed-ips/);
    // every listed host is in a reviewed set
    for (const h of Object.values(EGRESS_DOMAIN_SETS).flat()) expect(problems(wf({ first: egress().replace('registry.npmjs.org', h) })), h).toEqual([]);
  });

  it('proof workflow: no workflow_dispatch, schedule, workflow_run, repository_dispatch or issue_comment trigger', () => {
    for (const t of ['workflow_dispatch', 'schedule', 'workflow_run', 'repository_dispatch', 'issue_comment']) {
      expect(FORBIDDEN_PROOF_TRIGGERS).toContain(t);
      for (const on of [t, `[pull_request, ${t}]`, `{ pull_request: {}, ${t}: {} }`]) {
        for (const kind of ['proof', 'compat'] as const) expect(problems(wf({ on }), kind).join(' '), `${kind} ${on}`).toMatch(new RegExp(t));
      }
    }
    // central files keep E2-R3's own trigger rule (checkCentralTriggers): not judged here
    expect(problems(wf({ on: 'workflow_call' }), 'central')).toEqual([]);
  });

  it('proof workflow: every uses is pinned by sha, a job container or a reusable call elsewhere is refused', () => {
    expect(problems(wf({ steps: '      - uses: actions/setup-node@v4\n' })).join(' ')).toMatch(/not pinned/);
    expect(problems(wf({ steps: '      - uses: docker://alpine:3\n' })).join(' ')).toMatch(/not pinned/);
    expect(problems(wf({ steps: `      - uses: docker://alpine@sha256:${'b'.repeat(64)}\n` }))).toEqual([]);
    expect(problems(wf({ steps: '      - uses: ./.github/actions/pipegen-x\n' }))).toEqual([]);
    expect(problems(wf({ job: '    container: node:24\n' })).join(' ')).toMatch(/container/);
    expect(problems(wf({ job: '    services:\n      db:\n        image: postgres:17\n' })).join(' ')).toMatch(/digest/);
    expect(problems(wf({ job: `    services:\n      db:\n        image: postgres:17@sha256:${'c'.repeat(64)}\n        options: --privileged\n` })).join(' ')).toMatch(/services/);
    expect(problems(wf({ job: `    services:\n      db:\n        image: postgres:17@sha256:${'c'.repeat(64)}\n        volumes: ["/:/host"]\n` })).join(' ')).toMatch(/services/);
    // a reusable-workflow call job is checked in its callee: a local file or the central draft at a sha
    const call = (uses: string) => `on: pull_request\njobs:\n  merge:\n    uses: ${uses}\n`;
    expect(problems(call('./.github/workflows/pipegen-merge.yml'))).toEqual([]);
    expect(problems(call(`CrisWorking/pipelines/.github/workflows/shop--merge.yml@${SHA}`))).toEqual([]);
    expect(problems(call('CrisWorking/pipelines/.github/workflows/shop--merge.yml@main')).join(' ')).toMatch(/reusable/);
    expect(problems(call('evil/x/.github/workflows/y.yml@' + SHA)).join(' ')).toMatch(/reusable/);
    // compat copies may keep the user's tag-pinned actions (ruling E3-R2), and have no egress step (S17)
    expect(problems(wf({ first: '      - uses: actions/checkout@v4', steps: '      - run: make\n' }), 'compat')).toEqual([]);
  });

  it('proof workflow (E3-R2): no proof job uses actions/cache; no key-holding job enables a setup cache', () => {
    for (const a of ['actions/cache', 'actions/cache/restore', 'actions/cache/save']) {
      for (const kind of ['proof', 'compat', 'central'] as const) {
        expect(problems(wf({ first: kind === 'compat' ? '      - run: echo' : egress(), steps: `      - uses: ${a}@${SHA}\n` }), kind).join(' '), `${kind} ${a}`).toMatch(/cache/);
      }
    }
    // setup-* with a cache, in a job that may hold keys (proof, central)
    expect(problems(wf({ steps: `      - uses: ${SETUP_NODE}\n        with:\n          package-manager-cache: "false"\n          cache: npm\n` })).join(' ')).toMatch(/cache/);
    expect(problems(wf({ steps: `      - uses: ${SETUP_NODE}\n        with:\n          node-version: "24"\n` })).join(' ')).toMatch(/package-manager-cache/);
    expect(problems(wf({ steps: `      - uses: ${SETUP_NODE}\n        with:\n          package-manager-cache: "false"\n          node-version: "24"\n` }))).toEqual([]);
    expect(problems(wf({ steps: `      - uses: docker/build-push-action@${SHA}\n        with:\n          cache-from: type=gha\n` })).join(' ')).toMatch(/cache/);
    expect(problems(wf({ steps: `      - uses: docker/build-push-action@${SHA}\n        with:\n          no-cache: "true"\n` }))).toEqual([]);
    // a compat copy holds no key, so a setup cache there is the user's own and can poison nothing that holds keys
    expect(problems(wf({ first: '      - run: echo', steps: '      - uses: actions/setup-node@v4\n        with:\n          cache: npm\n' }), 'compat')).toEqual([]);
  });

  it('proof workflow: a file pipegen can not read strictly is a problem', () => {
    expect(problems('on: pull_request\njobs:\n  a: &x\n    runs-on: ubuntu-24.04\n').join(' ')).toMatch(/can't read/);
    expect(problems('"not yaml').join(' ')).toMatch(/can't read/);
    expect(problems('on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-24.04\n').join(' ')).toMatch(/steps/);
  });
});
