// Plan E E3 fix round 2 (review-E3-r1 I1-r1 a-d, m1-m3; rulings E3-R4 amended, E3-R5, E3-R6): the probes of
// tmp-E3-review/wfcheck.probe.test.ts lifted as tests (each came back clean and must now report a problem), plus the
// brief's own cases. No network.
import { describe, expect, it } from 'vitest';
import { Document } from 'yaml';
import { renderEgressStep } from '../src/engine/egress.js';
import { renderBaselineCheckStep, renderComposeUp, renderFindingsBlock, renderFindRunStep, renderGateUploads, renderJobPrelude, renderRuntimeEnv, renderStep, stepsToYaml, type RenderedStep } from '../src/engine/render-step.js';
import { proofWorkflowProblems, proofWorkflowsProblems, type ProofCheckFile } from '../src/proof/workflow-check.js';
import { ctxFor, platform, profile, reviewedList, service, specFor } from './helpers/render.js';
import { planCompose } from '../src/create/compose.js';
import { loadBaseImages } from '../src/engine/base-images.js';

const reviewed = reviewedList();
const eg = renderEgressStep(['npm'], { dockerNetworks: false });
const q = (s: string) => JSON.stringify(s);
const egYaml = (extra = '') => `      - name: egress\n        uses: ${q(eg.uses!)}\n        with:\n${Object.entries(eg.with!).map(([k, v]) => `          ${k}: ${q(v)}`).join('\n')}\n${extra}`;
const wf = (on: string, jobBody: string, top = 'permissions: {}\n') => `on: ${on}\n${top}jobs:\n  a:\n    runs-on: ubuntu-24.04\n${jobBody}`;
const steps = (extraEg: string, rest: string) => `    steps:\n${egYaml(extraEg)}${rest}`;
const P = (content: string, kind: 'proof' | 'compat' | 'central' = 'proof') => proofWorkflowProblems({ path: '.github/workflows/x.yml', content }, kind, reviewed);
const CHECKOUT = reviewed.find((t) => t.id === 'actions-checkout')!.step.action!.uses;
const SETUP_NODE = reviewed.find((t) => t.id === 'actions-setup-node')!.step.action!.uses;
const ATTEST = reviewed.find((t) => t.id === 'actions-attest')!.step.action!.uses;
const SHA = 'd'.repeat(40);
// the id-token key built at run time (a redact pattern reads that key with a value as a credential)
const IDT = ['id', 'tok' + 'en'].join('-');
const SEC = ['secr', 'ets'].join('');

describe('probes from review-E3-r1 (each was clean; now a problem)', () => {
  it('probe baseline: a well-formed key-holding job passes', () => {
    expect(P(wf('pull_request', steps('', '      - run: make\n')))).toEqual([]);
  });

  it('probe (b): the egress step can not be disabled, delayed, given env, or reconfigured by a second bullfrog step', () => {
    for (const extra of ['        if: false\n', '        continue-on-error: true\n', '        env: { NODE_OPTIONS: "--require /tmp/x.js" }\n', '        timeout-minutes: 1\n']) {
      expect(P(wf('pull_request', steps(extra, '      - run: make\n'))).join(' '), extra).toMatch(/egress step/);
    }
    expect(P(wf('pull_request', '    env: { NODE_OPTIONS: "--require ./x.js" }\n' + steps('', '      - run: make\n'))).join(' ')).toMatch(/NODE_OPTIONS/);
    expect(P(wf('pull_request', steps('', egYaml().replace('block', 'audit')))).join(' ')).toMatch(/one bullfrog step/);
  });

  it('probe (c): only push, pull_request (and workflow_call for a local callee) trigger a proof workflow; spelled exactly', () => {
    for (const t of ['deployment', 'deployment_status', 'check_run', 'status', 'release', 'create', 'issues', 'pull_request_review', 'workflow_call', 'Workflow_Dispatch', '[push, WORKFLOW_DISPATCH]', '{ schedule: [{ cron: "0 0 * * *" }] }', 'Push', '[Pull_Request]']) {
      expect(P(wf(t, steps('', '      - run: make\n'))).join(' '), t).toMatch(/trigger/);
    }
    for (const t of ['push', 'pull_request', '[push, pull_request]', '{ push: { branches: [main] }, pull_request: {} }']) expect(P(wf(t, steps('', '      - run: make\n'))), t).toEqual([]);
  });

  it('probe (d): every action of a key-holding job comes from the reviewed list; no local composite, no unreviewed image', () => {
    expect(P(wf('pull_request', steps('', '      - uses: ./.github/actions/x\n'))).join(' ')).toMatch(/reviewed/);
    expect(P(wf('pull_request', steps('', `      - uses: evil/act@${'a'.repeat(40)}\n`))).join(' ')).toMatch(/reviewed/);
    expect(P(wf('pull_request', steps('', `      - uses: docker://alpine@sha256:${'b'.repeat(64)}\n`))).join(' ')).toMatch(/reviewed/);
    // a reviewed action at another commit is not the reviewed pin
    expect(P(wf('pull_request', steps('', `      - uses: ${CHECKOUT.replace(/@.*/, `@${'e'.repeat(40)}`)}\n`))).join(' ')).toMatch(/reviewed/);
    expect(P(wf('pull_request', steps('', `      - uses: ${CHECKOUT}\n`)))).toEqual([]);
  });

  it('probe (e) / m1: run-script gha cache, self-hosted runner, id-token write', () => {
    expect(P(wf('pull_request', steps('', '      - run: docker buildx build --cache-from type=gha .\n'))).join(' ')).toMatch(/cache/);
    expect(P(wf('pull_request', steps('', '      - run: docker buildx build --cache-to "type=gha,mode=max" .\n'))).join(' ')).toMatch(/cache/);
    expect(P(wf('pull_request', steps('', '      - run: gh cache delete --all\n'))).join(' ')).toMatch(/cache/);
    expect(P('on: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: self-hosted\n' + steps('', '      - run: make\n')).join(' ')).toMatch(/runs-on/);
    expect(P(wf('pull_request', `    permissions: { ${IDT}: write, contents: write }\n` + steps('', '      - run: make\n'))).join(' ')).toMatch(/id-token/);
  });

  it('probe (a): a reusable callee that is not a checked file of this push is a problem', () => {
    expect(P(`on: pull_request\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/nope.yml\n    ${SEC}: inherit\n`).join(' ')).toMatch(/nope\.yml/);
    expect(P(`on: pull_request\npermissions: {}\njobs:\n  a:\n    uses: o/pipelines/.github/workflows/other--merge.yml@${SHA}\n    ${SEC}: inherit\n`).join(' ')).toMatch(/other--merge\.yml/);
  });

  it('probes that were already closed stay closed', () => {
    expect(P('on: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n').join(' ')).toMatch(/steps/);
    expect(P('on: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps: { a: 1 }\n').join(' ')).toMatch(/steps/);
    const base = wf('pull_request', steps('', '      - run: make\n'));
    expect(P(base.replace(/@[0-9a-f]{40}/, '@' + 'e'.repeat(40))).join(' ')).toMatch(/egress/);
    expect(P(base.replace('enable-sudo: "false"', 'enable-sudo: "true"')).join(' ')).toMatch(/egress/);
    expect(P(base.replace('egress-policy: "block"', 'egress-policy: "audit"')).join(' ')).toMatch(/egress/);
    expect(P(base.replace('registry.npmjs.org', 'evil.example')).join(' ')).toMatch(/evil\.example/);
    expect(P(base.replace('allowed-domains:', 'allowed-ips: "0.0.0.0/0"\n          allowed-domains:')).join(' ')).toMatch(/allowed-ips/);
    for (const u of ['actions/cache@v4', 'Actions/Cache@v4', 'actions/cache/restore@v4']) {
      expect(P(`on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ uses: ${u} }]\n`, 'compat').join(' '), u).toMatch(/cache/);
    }
    expect(P(wf('pull_request', steps('', `      - uses: ${SETUP_NODE}\n        with: { package-manager-cache: "false", cache: npm }\n`))).join(' ')).toMatch(/cache/);
    expect(P(wf('pull_request', steps('', `      - uses: ${SETUP_NODE}\n        with: { cache: "\${{ 'npm' }}", package-manager-cache: "false" }\n`))).join(' ')).toMatch(/cache/);
  });
});

describe('fix round 2: the brief', () => {
  const file = (path: string, content: string, kind: ProofCheckFile['kind'] = 'proof'): ProofCheckFile => ({ path, content, kind });
  const callee = (body = steps('', '      - run: make\n')) => `on: workflow_call\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n${body}`;
  const caller = (uses: string) => `on: [push, pull_request]\npermissions: {}\njobs:\n  p:\n    uses: ${uses}\n`;
  const flat = (r: { path: string; problems: string[] }[]) => r.flatMap((x) => x.problems.map((p) => `${x.path}: ${p}`)).join(' | ');

  it('I1-r1 (a): a local callee in the batch is checked (transitively), and workflow_call is allowed only there', () => {
    const ok = proofWorkflowsProblems([file('.github/workflows/pipegen.yml', caller('./.github/workflows/pipegen-merge.yml')), file('.github/workflows/pipegen-merge.yml', callee())], { reviewed });
    expect(flat(ok)).toBe('');
    // the callee breaks a job rule: the problem is the callee's
    const bad = proofWorkflowsProblems([file('.github/workflows/pipegen.yml', caller('./.github/workflows/pipegen-merge.yml')), file('.github/workflows/pipegen-merge.yml', callee('    steps:\n      - run: make\n'))], { reviewed });
    expect(flat(bad)).toMatch(/pipegen-merge\.yml: .*egress/);
    // a callee that calls a further callee, which breaks a rule
    const chain = proofWorkflowsProblems([
      file('.github/workflows/pipegen.yml', caller('./.github/workflows/a.yml')),
      file('.github/workflows/a.yml', 'on: workflow_call\npermissions: {}\njobs:\n  b:\n    uses: ./.github/workflows/b.yml\n'),
      file('.github/workflows/b.yml', callee('    steps:\n      - run: make\n')),
    ], { reviewed });
    expect(flat(chain)).toMatch(/b\.yml: .*egress/);
    // workflow_call on a file nobody calls
    expect(flat(proofWorkflowsProblems([file('.github/workflows/pipegen-merge.yml', callee())], { reviewed }))).toMatch(/workflow_call/);
    // a compat copy can not be a callee
    expect(flat(proofWorkflowsProblems([file('.github/workflows/pipegen.yml', caller('./.github/workflows/c.yml')), file('.github/workflows/c.yml', callee(), 'compat')], { reviewed }))).toMatch(/c\.yml/);
  });

  it('I1-r1 (a): central callees are resolved in the pushed central tree and checked, inherited files included; unreached ones are not', () => {
    const central = (workflows: { path: string; content: string }[]) => ({ sha: SHA, workflows });
    const app = [file('.github/workflows/pipegen.yml', caller(`CrisWorking/pipelines/.github/workflows/shop--merge.yml@${SHA}`))];
    expect(flat(proofWorkflowsProblems(app, { reviewed, central: central([{ path: '.github/workflows/shop--merge.yml', content: callee() }]) }))).toBe('');
    // the callee is not in the tree, or the pin is another commit
    expect(flat(proofWorkflowsProblems(app, { reviewed, central: central([]) }))).toMatch(/shop--merge\.yml/);
    expect(flat(proofWorkflowsProblems([file('.github/workflows/pipegen.yml', caller(`CrisWorking/pipelines/.github/workflows/shop--merge.yml@${'e'.repeat(40)}`))], { reviewed, central: central([{ path: '.github/workflows/shop--merge.yml', content: callee() }]) }))).toMatch(/shop--merge\.yml/);
    // an inherited file reached through the project's file breaks a job rule (pre-Bullfrog): a problem
    const inherited = proofWorkflowsProblems(app, { reviewed, central: central([
      { path: '.github/workflows/shop--merge.yml', content: 'on: workflow_call\npermissions: {}\njobs:\n  s:\n    uses: ./.github/workflows/shared-sign.yml\n' },
      { path: '.github/workflows/shared-sign.yml', content: callee('    steps:\n      - run: sign\n') },
    ]) });
    expect(flat(inherited)).toMatch(/shared-sign\.yml: .*egress/);
    // a central file no proof workflow reaches keeps only E2-R3's trigger rule
    expect(flat(proofWorkflowsProblems(app, { reviewed, central: central([
      { path: '.github/workflows/shop--merge.yml', content: callee() },
      { path: '.github/workflows/old--nightly.yml', content: 'on: schedule\njobs:\n  n:\n    runs-on: ubuntu-latest\n    steps:\n      - run: old\n' },
    ]) }))).toBe('');
    // 'later': the shape only (proofAppFiles; pushProofSetup checks again with the tree)
    expect(flat(proofWorkflowsProblems(app, { reviewed, central: 'later' }))).toBe('');
    expect(flat(proofWorkflowsProblems([file('.github/workflows/pipegen.yml', caller('CrisWorking/pipelines/.github/workflows/shop--merge.yml@main'))], { reviewed, central: 'later' }))).toMatch(/reusable/);
  });

  it('fix round 2 (mutants): a reached central file\'s missing local callee, a compat file\'s call, a lowercase empty bash_env, a call job without permissions', () => {
    const app = [file('.github/workflows/pipegen.yml', caller(`CrisWorking/pipelines/.github/workflows/shop--merge.yml@${SHA}`))];
    expect(flat(proofWorkflowsProblems(app, { reviewed, central: { sha: SHA, workflows: [{ path: '.github/workflows/shop--merge.yml', content: 'on: workflow_call\npermissions: {}\njobs:\n  s:\n    uses: ./.github/workflows/missing.yml\n' }] } }))).toMatch(/missing\.yml/);
    // a compat file never makes a callee: workflow_call on the file it names stays refused
    expect(flat(proofWorkflowsProblems([file('.github/workflows/c.yml', caller('./.github/workflows/x.yml'), 'compat'), file('.github/workflows/x.yml', callee())], { reviewed }))).toMatch(/x\.yml: .*workflow_call/);
    // only the exact upper-case BASH_ENV and ENV may be emptied
    expect(P(wf('pull_request', steps('', '      - run: make\n        env: { bash_env: "" }\n'))).join(' ')).toMatch(/bash_env/);
    // a reusable call job is held to the permissions rule too
    expect(flat(proofWorkflowsProblems([file('.github/workflows/pipegen.yml', 'on: [push, pull_request]\njobs:\n  p:\n    uses: ./.github/workflows/m.yml\n'), file('.github/workflows/m.yml', callee())], { reviewed }))).toMatch(/pipegen\.yml: .*permissions/);
  });

  it('I1-r1 (b): env names that change a runtime are refused at every level of a key-holding job; empty BASH_ENV/ENV is the renderer\'s own guard', () => {
    const names = ['NODE_OPTIONS', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'BASH_ENV', 'ENV', 'PYTHONSTARTUP', 'PYTHONPATH', 'PERL5OPT', 'RUBYOPT', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'GIT_SSH_COMMAND', 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY'];
    for (const n of [...names, ...names.map((x) => x.toLowerCase()), 'Node_Options']) {
      for (const at of ['top', 'job', 'step'] as const) {
        const env = `{ ${n}: "x" }`;
        const content = at === 'top' ? wf('pull_request', steps('', '      - run: make\n'), `permissions: {}\nenv: ${env}\n`)
          : at === 'job' ? wf('pull_request', `    env: ${env}\n` + steps('', '      - run: make\n'))
          : wf('pull_request', steps('', `      - run: make\n        env: ${env}\n`));
        expect(P(content).join(' '), `${at} ${n}`).toMatch(new RegExp(n, 'i'));
      }
    }
    // the renderer's own run steps clear BASH_ENV and ENV (empty): that guard stays allowed, any value is refused
    expect(P(wf('pull_request', steps('', '      - run: make\n        env: { BASH_ENV: "", ENV: "" }\n')))).toEqual([]);
    expect(P(wf('pull_request', steps('', '      - run: make\n        env: { BASH_ENV: "/tmp/x" }\n'))).join(' ')).toMatch(/BASH_ENV/);
    expect(P(wf('pull_request', steps('', '      - run: make\n        env: { NODE_OPTIONS: "" }\n'))).join(' ')).toMatch(/NODE_OPTIONS/);
    // an ordinary name is fine; compat jobs are not key-holding
    expect(P(wf('pull_request', '    env: { CI: "true", STRIPE_KEY_NAME: x }\n' + steps('', '      - run: make\n')))).toEqual([]);
    expect(P('on: pull_request\npermissions: { contents: read }\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    env: { NODE_OPTIONS: x }\n    steps: [{ run: make }]\n', 'compat')).toEqual([]);
  });

  it('I1-r1 (b): job or workflow defaults.run.shell other than bash or sh is refused', () => {
    for (const sh of ['pwsh', 'python', 'bash --rcfile /tmp/x {0}', 'node {0}']) {
      expect(P(wf('pull_request', `    defaults: { run: { shell: ${q(sh)} } }\n` + steps('', '      - run: make\n'))).join(' '), sh).toMatch(/shell/);
      expect(P(wf('pull_request', steps('', '      - run: make\n'), `permissions: {}\ndefaults: { run: { shell: ${q(sh)} } }\n`)).join(' '), sh).toMatch(/shell/);
    }
    for (const sh of ['bash', 'sh']) expect(P(wf('pull_request', `    defaults: { run: { shell: ${sh} } }\n` + steps('', '      - run: make\n'))), sh).toEqual([]);
  });

  it('I1-r1 (c): central files keep E2-R3\'s trigger allowlist; the on key is spelled exactly', () => {
    for (const t of ['workflow_call', 'schedule', '{ workflow_dispatch: {}, workflow_call: {} }']) expect(P(wf(t, steps('', '      - run: make\n')), 'central'), t).toEqual([]);
    for (const t of ['push', 'pull_request', 'Workflow_Call']) expect(P(wf(t, steps('', '      - run: make\n')), 'central').join(' '), t).toMatch(/trigger/);
    expect(P('On: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n' + steps('', '      - run: make\n')).join(' ')).toMatch(/on/);
    expect(P('jobs:\n  a:\n    runs-on: ubuntu-24.04\n' + steps('', '      - run: make\n')).join(' ')).toMatch(/trigger|on/);
  });

  it('I1-r1 (d): docker:// only as a reviewed image by digest; a local action only when pipegen renders it in this push', () => {
    const semgrep = reviewed.find((t) => t.id === 'semgrep')!;
    const img = `docker://${semgrep.step.cli!.install.package}@${semgrep.candidate.pin.digest}`;
    expect(P(wf('pull_request', steps('', `      - uses: ${img}\n`)))).toEqual([]);
    const withAction = (path: string) => proofWorkflowsProblems([
      { path: '.github/workflows/pipegen.yml', content: wf('pull_request', steps('', '      - uses: ./.github/actions/pipegen-x\n')), kind: 'proof' },
      { path, content: 'runs: { using: composite, steps: [] }\n', kind: 'proof' },
    ], { reviewed });
    expect(flat(withAction('.github/actions/pipegen-x/action.yml'))).toBe('');
    expect(flat(withAction('.github/actions/other/action.yml'))).toMatch(/reviewed/);
  });

  it('m1: runs-on from pipegen\'s hosted labels; permissions explicit and minimal; id-token only with the reviewed attest action', () => {
    for (const r of ['ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-24.04-arm', 'ubuntu-22.04-arm']) expect(P(wf('pull_request', steps('', '      - run: make\n')).replace('ubuntu-24.04', r)), r).toEqual([]);
    for (const r of ['windows-latest', 'macos-14', '"${{ matrix.os }}"', '[self-hosted, linux]', 'ubuntu-latest-16-cores']) expect(P(wf('pull_request', steps('', '      - run: make\n')).replace('ubuntu-24.04', r)).join(' '), r).toMatch(/runs-on/);
    // permissions: missing everywhere, write-all, or a workflow-level write with none on the job
    expect(P(wf('pull_request', steps('', '      - run: make\n'), '')).join(' ')).toMatch(/permissions/);
    expect(P(wf('pull_request', '    permissions: write-all\n' + steps('', '      - run: make\n'))).join(' ')).toMatch(/write-all/);
    expect(P(wf('pull_request', steps('', '      - run: make\n'), 'permissions: { contents: write }\n')).join(' ')).toMatch(/permissions/);
    expect(P(wf('pull_request', steps('', '      - run: make\n'), 'permissions: write-all\n')).join(' ')).toMatch(/permissions/);
    expect(P(wf('pull_request', '    permissions: { contents: read, packages: write }\n' + steps('', '      - run: make\n'), ''))).toEqual([]);
    expect(P(wf('pull_request', steps('', '      - run: make\n'), 'permissions: { contents: read }\n'))).toEqual([]);
    // id-token with the reviewed attest action is allowed (the plan's attestation job)
    expect(P(wf('pull_request', `    permissions: { ${IDT}: write, attestations: write, contents: read }\n` + steps('', `      - uses: ${ATTEST}\n`)))).toEqual([]);
  });

  it('m2: a key-holding job never restores a cache: setup-node with cache, or without package-manager-cache "false"', () => {
    expect(P(wf('pull_request', steps('', `      - uses: ${SETUP_NODE}\n        with: { node-version: "24", cache: npm, package-manager-cache: "false" }\n`))).join(' ')).toMatch(/cache/);
    expect(P(wf('pull_request', steps('', `      - uses: ${SETUP_NODE}\n        with: { node-version: "24" }\n`))).join(' ')).toMatch(/package-manager-cache/);
    expect(P(wf('pull_request', steps('', `      - uses: ${SETUP_NODE}\n        with: { node-version: "24", package-manager-cache: "false" }\n`)))).toEqual([]);
    // compat jobs may keep a setup cache (no key-holding job reads any cache)
    expect(P('on: pull_request\npermissions: { contents: read }\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps: [{ uses: actions/setup-node@v4, with: { cache: npm } }]\n', 'compat')).toEqual([]);
  });
});

describe('fix round 2: the renderers of Plans B, C and D pass the proof rules', () => {
  it('every step pipegen renders today, after the egress step, passes (no rule refuses pipegen\'s own output)', () => {
    const pf = platform(reviewed);
    const gate = reviewed.find((t) => t.id === 'pipegen-gate')!;
    const job = (st: RenderedStep[]) => {
      const d = new Document();
      d.contents = stepsToYaml([renderEgressStep(['npm', 'dockerhub', 'ghcr', 'github-releases', 'pypi', 'trivy-db', 'osv'], { dockerNetworks: true }), ...st]);
      return `on: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: { contents: read }\n    steps:\n${d.toString().split('\n').map((l) => `      ${l}`).join('\n')}\n`;
    };
    const ctx = ctxFor([service({ scripts: ['test', 'lint'], hasTests: true })], { image: 'pipegen/app:x', url: 'http://127.0.0.1:3000/', spec: 'openapi.yaml' });
    let rendered = 0;
    for (const t of reviewed) {
      if (t.id === 'bullfrog') continue;
      let st: RenderedStep[];
      try { st = renderFindingsBlock(specFor(t), t, pf, ctx, gate).steps; } catch {
        try { st = renderStep(specFor(t), t, pf, ctx).steps; } catch { continue; }   // not renderable from this context (a pip tool, an image target, Go, ...)
      }
      rendered++;
      expect(P(job([...renderJobPrelude({ node: {} }, pf).steps, ...st])), t.id).toEqual([]);
    }
    expect(rendered).toBeGreaterThan(25);
    expect(P(job([...renderGateUploads(pf), renderBaselineCheckStep(gate), renderFindRunStep(gate, {}), renderComposeUp(), renderComposeUp({ proofOverride: true }),
      renderRuntimeEnv(planCompose(profile([service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000, scripts: ['start'], dependsOn: [{ kind: 'postgres', name: 'pg', evidence: 'x', envVars: ['DATABASE_URL'] }] })]), loadBaseImages(), []).env)]))).toEqual([]);
  });
});
