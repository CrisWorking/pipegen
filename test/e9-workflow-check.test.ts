// E9: two more rules of the proof workflow check (src/proof/workflow-check.ts), for key-holding jobs only.
// - ruling E3-R7: no run script bind-mounts a host path into a container (docker -v / --volume / --mount type=bind /
//   --volumes-from). Bullfrog with sudo off refuses those at run time anyway; pipegen's own steps copy instead (render-cli.ts), so
//   a script that still mounts is not one pipegen rendered, and the proof stops before it is pushed.
// - carry E4-R4 R5: the only `vars.` a key-holding job may read is vars.PIPEGEN_BLOCK_FROM (organisation and repo variables are not
//   listed or emptied by the scratch-key checks, so any other one could hold a value nobody checked).
// Written first.
import { describe, expect, it } from 'vitest';
import { Document } from 'yaml';
import { renderEgressStep } from '../src/engine/egress.js';
import { renderStepWith, stepsToYaml } from '../src/engine/render-step.js';
import { proofWorkflowProblems, type ProofWorkflowKind } from '../src/proof/workflow-check.js';
import { ctxFor, entry, platform, reviewedList, service, specFor } from './helpers/render.js';

const reviewed = reviewedList();
const CHECKOUT = reviewed.find((t) => t.id === 'actions-checkout')!.step.action!.uses;
const egress = (): string => {
  const d = new Document();
  d.contents = stepsToYaml([renderEgressStep(['npm', 'dockerhub'], { dockerNetworks: true })]);
  return d.toString().trimEnd().split('\n').map((l) => `      ${l}`).join('\n');
};
const wf = (steps: string, top = ''): string => `on: pull_request
permissions: {}
${top}jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
${egress()}
      - uses: ${CHECKOUT}
        with:
          persist-credentials: "false"
${steps}`;
const run = (script: string): string => `      - run: |\n${script.split('\n').map((l) => `          ${l}`).join('\n')}\n`;
const problems = (content: string, kind: ProofWorkflowKind = 'proof') => proofWorkflowProblems({ path: '.github/workflows/pipegen-x.yml', content }, kind, reviewed);
const MOUNT = /bind/;

describe('E9 (E3-R7): no bind mount in a key-holding run script', () => {
  it('proof workflow: a run script that bind-mounts a host path into a container is refused (-v, --volume, --mount type=bind, --volumes-from, short-flag groups)', () => {
    const bad = [
      'docker run --rm -v "$GITHUB_WORKSPACE:/src" img:1 scan',
      'docker run --rm -v/home/runner:/h img:1',
      '/usr/bin/docker run --rm --volume "$GITHUB_WORKSPACE:/src" img:1',
      'docker run --volume=/etc:/e img:1',
      'docker run --mount type=bind,source="$PWD",target=/src img:1',
      'docker run --mount=type=bind,src=/,dst=/h img:1',
      'docker run --mount "dst=/h,type=bind,src=/" img:1',
      'docker create --name x -v /:/h img:1',
      'docker container run -itv /:/h img:1',
      'sudo docker run -v /:/h img:1',
      'docker run --volumes-from other img:1',
      'echo hi && docker run -v /:/h img:1 || true',
      'docker run \\\n  -v "$GITHUB_WORKSPACE:/src" \\\n  img:1',
      'podman run -v /:/h img:1',
      'docker compose run -v /:/h app',
      // strict on purpose: a -v word in the container's own command counts too (the check does not parse where the image stands)
      'docker run --rm -e A=1 -w /x img:1 -v',
      // security scan (E9): a --mount value is parsed as docker's key=value list, never matched as a whole
      'docker run --mount type=volume,type=bind,src=/,dst=/h img:1',
      'docker run --mount type=bind,type=volume,src=/,dst=/h img:1',
      'docker run --mount type=volume,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/,dst=/h img:1',
      'docker run --mount type=volume,volume-driver=local,dst=/h img:1',
      'docker run --mount src=/,dst=/h img:1',
      'docker run --mount TYPE=bind,src=/,dst=/h img:1',
      'docker run --mount type=VOLUME2,dst=/h img:1',
      `docker run --mount 'type=volume,"src=a,type=bind",dst=/h' img:1`,
      'docker run --mount type=volume,bind-propagation=shared,dst=/h img:1',
      'docker run --mount img:1',
      'docker run --mount',
      'docker volume create --opt type=none --opt o=bind --opt device=/ v1',
      'docker volume create -o device=/ v1',
      'docker volume create --opt=device=/ v1',
      'docker volume create -d local-persist v1',
      'docker run --volume=named:/h img:1',
      'docker run -v named:/h img:1',
    ];
    for (const b of bad) expect(problems(wf(run(b))).join(' '), b).toMatch(MOUNT);
  });

  it('proof workflow: docker without a bind mount passes, and so do -v words of other commands (command -v, grep -v) and a volume-type mount', () => {
    const ok = [
      'docker create --name x --network none img:1 scan > /dev/null\ndocker cp -a "$PWD/." x:/src\ndocker start -a x || rc=$?\ndocker cp x:/src/r.sarif "$out"',
      'node="$(command -v node || true)"',
      'docker ps | grep -v pipegen',
      'docker run --rm --mount type=tmpfs,destination=/tmp img:1',
      'docker run --rm --mount type=volume,source=cache,target=/c img:1',
      'docker pull --quiet img:1',
    ];
    for (const o of ok) expect(problems(wf(run(o))), o).toEqual([]);
  });

  it('proof workflow: every docker step pipegen renders passes the check (semgrep with extra rules, zap)', () => {
    const ctx = ctxFor([service({ name: 'app', path: '.', scripts: ['test'] })], { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080' });
    for (const [id, needId] of [['semgrep', 'sast'], ['zap-baseline', 'dast']] as const) {
      const t = entry(id);
      const steps = renderStepWith(specFor(t, { needId, service: 'app' }), t, platform(), ctx).steps;
      const d = new Document();
      d.contents = stepsToYaml(steps.filter((s) => s.run !== undefined));
      const body = d.toString().trimEnd().split('\n').map((l) => `      ${l}`).join('\n');
      expect(problems(wf(`${body}\n`)), id).toEqual([]);
    }
  });

  it('compat copies are not checked for it (they hold no key and run no egress step)', () => {
    const compat = `on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - run: docker run -v "$GITHUB_WORKSPACE:/src" img:1
`;
    expect(problems(compat, 'compat').join(' ')).not.toMatch(MOUNT);
  });
});

describe('E9 (E4-R4 R5): only vars.PIPEGEN_BLOCK_FROM in a key-holding workflow', () => {
  it('proof workflow: vars.PIPEGEN_BLOCK_FROM passes; any other vars reference (a name, an index, the whole context, any case) is refused', () => {
    expect(problems(wf(run('echo ok'), 'env:\n  BLOCK: ${{ vars.PIPEGEN_BLOCK_FROM }}\n'))).toEqual([]);
    expect(problems(wf(`      - run: echo "\${{ vars.PIPEGEN_BLOCK_FROM }}"\n`))).toEqual([]);
    const bad = [
      wf(run('echo ok'), 'env:\n  X: ${{ vars.OTHER }}\n'),
      wf(`      - run: echo "\${{ vars.OTHER }}"\n`),
      wf(`      - run: echo "\${{ VARS.other }}"\n`),
      wf(`      - run: echo "\${{ vars['PIPEGEN_BLOCK_FROM'] }}"\n`),
      wf(`      - run: echo "\${{ toJSON(vars) }}"\n`),
      wf(`      - run: echo "\${{ vars.PIPEGEN_BLOCK_FROM_X }}"\n`),
      wf(`      - if: vars.DEPLOY == 'yes'\n        run: echo hi\n`),
      wf(`      - run: echo hi\n        env:\n          K: \${{ format('{0}', vars.KEY) }}\n`),
    ];
    for (const b of bad) expect(problems(b).join(' '), b).toMatch(/vars/);
  });

  it('security scan (E9): a `}}` inside a quoted literal does not end the search, so vars after it is still seen', () => {
    for (const b of [
      wf(`      - run: echo "\${{ format('}}', vars.SECRET_HOST) }}"\n`),
      wf(`      - run: echo "\${{ format('{0}}}', vars.SECRET_HOST) }}"\n`),
      wf(`      - run: echo "\${{ format('x''}}', vars.SECRET_HOST) }}"\n`),
    ]) expect(problems(b).join(' '), b).toMatch(/vars/);
  });

  it('strict on purpose: the word vars anywhere in a key-holding workflow is refused, even outside an expression (whole string values, decoded)', () => {
    expect(problems(wf(run('echo "no vars here"'))).join(' ')).toMatch(/vars/);
    expect(problems(wf(run('echo ok')))).toEqual([]);
  });

  it('compat copies are not checked for it', () => {
    const compat = `on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - run: echo "\${{ vars.OTHER }}"
`;
    expect(problems(compat, 'compat').join(' ')).not.toMatch(/vars/);
  });
});
