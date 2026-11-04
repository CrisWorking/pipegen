// E9 (ruling E3-R7, MUST-DO before Plan G ships proof): Bullfrog with `enable-sudo: false` refuses every host path a container mounts
// ("Error response from daemon: bullfrog: mounting the host path ... is not allowed while sudo is disabled", spike S8). So a docker
// scanner step never bind-mounts: the image's container is CREATED with the tool's words, the folders it needs are copied in with
// `docker cp -a` (owner and mode kept, so the tool's user can write its result), it is STARTED attached, and the result is copied OUT
// to the path the result check reads. Written first.
import { chmodSync, existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { NEED_IDS } from '../src/engine/need-ids.js';
import { renderStepWith, type RenderedStep, type RenderResult } from '../src/engine/render-step.js';
import { ARGV_POLICIES } from '../src/engine/tool-flags.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import type { ReviewedTool, StepSpec } from '../src/types.js';
import { ctxFor, entry, platform, reviewedList, service, specFor } from './helpers/render.js';
import { exec, sandbox, stepEnv, type Sandbox } from './helpers/step-harness.js';

const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
const ctx = ctxFor([service({ name: 'app', path: '.', scripts: ['test'] })], { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080' });
const spec = (t: ReviewedTool, over: Partial<StepSpec> = {}): StepSpec => specFor(t, { needId: needFor(t), service: 'app', ...over });
const render = (id: string, over: Partial<StepSpec> = {}): RenderResult => { const t = entry(id); return renderStepWith(spec(t, over), t, platform(), ctx); };
const lastRun = (r: RenderResult): RenderedStep => r.steps.filter((s) => s.run !== undefined).at(-1) as RenderedStep;
const dockerIds = (): string[] => reviewedList().filter((t) => ARGV_POLICIES[t.id]?.method === 'docker' && ARGV_POLICIES[t.id]?.entrypoint !== true).map((t) => t.id);
/** Every word of a docker command line of a script (the lines that run /usr/bin/docker). */
const dockerLines = (run: string): string[] => run.split('\n').filter((l) => l.includes('/usr/bin/docker'));

describe('E9 (E3-R7): docker scanner steps without bind mounts', () => {
  it('docker: no step of a docker entry bind-mounts (no -v, --volume, --mount or --volumes-from): the container is created, filled by docker cp -a, started attached, its result copied out', () => {
    const ids = dockerIds();
    expect(ids).toEqual(expect.arrayContaining(['semgrep', 'zap-baseline']));
    for (const id of ids) {
      const r = render(id);
      for (const s of r.steps) {
        for (const l of dockerLines(s.run ?? '')) {
          const words = l.split(/\s+/);
          expect(words.filter((w) => /^-[A-Za-z]*v/.test(w) || /^--(?:volume|mount|volumes-from)\b/.test(w)), `${id}: ${l}`).toEqual([]);
          expect(l, id).not.toMatch(/ run /);
        }
      }
      const run = lastRun(r).run as string;
      const lines = dockerLines(run);
      const at = (re: RegExp) => lines.findIndex((l) => re.test(l));
      const create = at(/\/usr\/bin\/docker create --name pipegen-tool-[0-9a-f]{16} --pull=never /);
      const copyIn = at(/\/usr\/bin\/docker cp -a "/);
      const start = at(/\/usr\/bin\/docker start -a pipegen-tool-[0-9a-f]{16} \|\| rc=\$\?$/);
      const copyOut = at(/\/usr\/bin\/docker cp pipegen-tool-[0-9a-f]{16}:\/\S+ "\$out" /);
      expect([create, copyIn, start, copyOut].every((i) => i >= 0), `${id}:\n${lines.join('\n')}`).toBe(true);
      expect(create < copyIn && copyIn < start && start < copyOut, id).toBe(true);
      // the leftover of a re-run goes first; the container goes after its result is out
      expect(lines[0], id).toMatch(/docker rm -f pipegen-tool-[0-9a-f]{16} > \/dev\/null 2>&1 \|\| true$/);
      expect(lines.at(-1), id).toMatch(/docker rm -f pipegen-tool-[0-9a-f]{16} > \/dev\/null 2>&1 \|\| true$/);
      expect(lines[create], id).toContain('--security-opt no-new-privileges --cap-drop ALL');
      expect(lines[create], id).toContain('"$PIPEGEN_IMAGE"');
      expect(run, id).not.toContain('--rm');
    }
  });

  it('docker: semgrep copies the service folder to /src (its workdir), and the verified rules folder (and each tuning rule folder) to their reviewed paths', () => {
    const run = lastRun(render('semgrep')).run as string;
    expect(run).toMatch(/docker cp -a "\$PWD\/\." pipegen-tool-[0-9a-f]{16}:\/src$/m);
    expect(run).toMatch(/docker cp -a "\$rules\/\$PIPEGEN_ARG_0\/\." pipegen-tool-[0-9a-f]{16}:\/pipegen-rules$/m);
    expect(run).toMatch(/docker create .* --network none .*-w \/src /);
    expect(run).toMatch(/docker cp pipegen-tool-[0-9a-f]{16}:\/src\/semgrep\.sarif "\$out" /);
  });

  it('docker: zap copies its fresh work folder (pinned config inside) to /zap/wrk and copies zap.json back out of it', () => {
    const run = lastRun(render('zap-baseline', { needId: 'dast' })).run as string;
    expect(run).toMatch(/docker cp -a "\$work\/\." pipegen-tool-[0-9a-f]{16}:\/zap\/wrk$/m);
    expect(run).toMatch(/docker cp pipegen-tool-[0-9a-f]{16}:\/zap\/wrk\/zap\.json "\$out" /);
    expect(run).toContain('out="$work/zap.json"');
  });

  it('docker: the container name is per result artifact, so two docker steps of one job never share one', () => {
    const a = /pipegen-tool-([0-9a-f]{16})/.exec(lastRun(render('semgrep')).run as string)?.[1];
    const b = /pipegen-tool-([0-9a-f]{16})/.exec(lastRun(render('semgrep', { service: undefined })).run as string)?.[1];
    expect(a).toBeDefined();
    expect(a).not.toBe(b);
  });
});

/**
 * A stand-in for /usr/bin/docker that keeps a container's files in a folder: `create` makes it, `cp -a SRC/. CTR:DIR` copies in,
 * `start -a` runs `tool.sh` there (which writes the result where the real tool would) and exits with its code, `cp CTR:PATH DEST` copies
 * out as cp -P would (a link stays a link), `rm -f` removes it. Every call is logged.
 */
function fakeDocker(sb: Sandbox, toolScript: string): string {
  const path = join(sb.dir, 'docker-stub');
  const box = join(sb.dir, 'containers');
  mkdirSync(box, { recursive: true });
  writeFileSync(join(sb.dir, 'tool.sh'), `#!/bin/sh\n${toolScript}\n`);
  chmodSync(join(sb.dir, 'tool.sh'), 0o755);
  writeFileSync(path, [
    '#!/bin/bash', 'set -e', `box=${JSON.stringify(box)}`, `echo "$*" >> ${JSON.stringify(join(sb.dir, 'docker.log'))}`,
    'case "$1" in',
    '  pull) exit 0 ;;',
    '  rm) rm -rf "$box/$3"; exit 0 ;;',
    // the image has / and /zap (zap-stable's home); docker cp makes only the LAST folder of a destination, as the real one does
    '  create) n=""; prev=""; for a in "$@"; do [ "$prev" = "--name" ] && n="$a"; [ "$prev" = "-w" ] && echo "$a" > "$box/.w"; prev="$a"; done; mkdir -p "$box/$n/root/zap"; exit 0 ;;',
    '  cp)',
    '    if [ "$2" = "-a" ]; then src="$3"; ctr="${4%%:*}"; dir="${4#*:}"; [ -d "$box/$ctr/root$(dirname "$dir")" ] || exit 1; mkdir -p "$box/$ctr/root$dir"; cp -a "$src" "$box/$ctr/root$dir/"; exit 0; fi',
    '    ctr="${2%%:*}"; p="${2#*:}"; [ -e "$box/$ctr/root$p" ] || [ -L "$box/$ctr/root$p" ] || exit 1; cp -P -R "$box/$ctr/root$p" "$3"; exit 0 ;;',
    `  start) ctr="$3"; w="$(cat "$box/.w" 2>/dev/null || echo /zap/wrk)"; cd "$box/$ctr/root$w"; rc=0; ${JSON.stringify(join(sb.dir, 'tool.sh'))} || rc=$?; exit $rc ;;`,
    'esac', 'exit 99', '',
  ].join('\n'));
  chmodSync(path, 0o755);
  return path;
}

describe('E9 (E3-R7): the copy-in / copy-out run, real bash with a stand-in docker', () => {
  const runSemgrep = (toolScript: string): { status: number | null; sb: Sandbox; log: string; art: string } => {
    const sb = sandbox();
    const t = entry('semgrep');
    const s = spec(t, { needId: 'sast' });
    const art = resultArtifactName('sast', 'app');
    for (const rules of ['javascript', 'typescript', 'python']) mkdirSync(join(sb.rt, 'pipegen-rules', art, rules), { recursive: true });
    writeFileSync(join(sb.ws, 'app.js'), 'x\n');
    let step = lastRun(renderStepWith(s, t, platform(), ctx));
    step = { ...step, run: (step.run as string).replaceAll('/usr/bin/docker', fakeDocker(sb, toolScript)) };
    const r = exec(step, sb, stepEnv(step, sb));
    return { status: r.status, sb, log: readFileSync(join(sb.dir, 'docker.log'), 'utf8'), art };
  };

  it('a result the tool wrote in its folder is copied out and moved to pipegen-raw; the repo folder was copied in (the tool saw app.js)', () => {
    const { status, sb, log, art } = runSemgrep('[ -f app.js ] || exit 7\necho \'{"runs":[]}\' > semgrep.sarif');
    expect(status).toBe(0);
    expect(existsSync(join(sb.rt, 'pipegen-raw', art, 'semgrep.sarif'))).toBe(true);
    expect(log.split('\n').filter(Boolean).map((l) => l.split(' ')[0])).toEqual(['rm', 'create', 'cp', 'cp', 'start', 'cp', 'rm']);
    expect(log).not.toMatch(/(^| )-v( |$)|--mount|--volume/);
  });

  it('no result → the step fails (the copy-out finds nothing); a tool error exit → the step fails with it and nothing is kept', () => {
    const none = runSemgrep('exit 0');
    expect(none.status).not.toBe(0);
    expect(existsSync(join(none.sb.rt, 'pipegen-raw'))).toBe(false);
    const err = runSemgrep('echo \'{"runs":[]}\' > semgrep.sarif\nexit 3');
    expect(err.status).toBe(3);
    expect(existsSync(join(err.sb.rt, 'pipegen-raw'))).toBe(false);
  });

  it('a result that is a link in the container comes out as a link and is refused (never followed to a runner file)', () => {
    const { status, sb } = runSemgrep('ln -s /etc/passwd semgrep.sarif');
    expect(status).not.toBe(0);
    expect(existsSync(join(sb.rt, 'pipegen-raw'))).toBe(false);
    expect(existsSync(join(sb.ws, 'semgrep.sarif'))).toBe(false);
  });

  it('the tool can not write into the runner workspace: a file it drops next to its result stays in the container', () => {
    const { status, sb } = runSemgrep('echo x > dropped.txt\necho \'{"runs":[]}\' > semgrep.sarif');
    expect(status).toBe(0);
    expect(existsSync(join(sb.ws, 'dropped.txt'))).toBe(false);
  });

  it('tuning extra rule folders reach the container (gathered in one runner folder first: docker cp makes only the last folder of a path)', () => {
    const sb = sandbox();
    const t = entry('semgrep');
    const s = spec(t, { needId: 'sast', choices: { tuning: { 'extra-rules': ['typescript', 'dockerfile'] } } });
    const tsCtx = ctxFor([service({ name: 'app', path: '.', dockerfile: 'Dockerfile', scripts: ['test'], quality: { ...emptyServiceQuality(), tsconfig: true } })]);
    const art = resultArtifactName('sast', 'app');
    for (const rules of ['javascript', 'typescript', 'python', 'dockerfile']) {
      mkdirSync(join(sb.rt, 'pipegen-rules', art, rules), { recursive: true });
      writeFileSync(join(sb.rt, 'pipegen-rules', art, rules, `${rules}.yaml`), 'rules: []\n');
    }
    let step = lastRun(renderStepWith(s, t, platform(), tsCtx));
    const check = '[ -f /dev/null ] && for d in ../pipegen-rules/javascript.yaml ../pipegen-rules-extra/typescript/typescript.yaml ../pipegen-rules-extra/dockerfile/dockerfile.yaml; do [ -f "$d" ] || exit 8; done\necho \'{"runs":[]}\' > semgrep.sarif';
    step = { ...step, run: (step.run as string).replaceAll('/usr/bin/docker', fakeDocker(sb, check)) };
    expect(exec(step, sb, stepEnv(step, sb)).status).toBe(0);
    expect(existsSync(join(sb.rt, 'pipegen-raw', art, 'semgrep.sarif'))).toBe(true);
  });

  it('zap: the work folder (with the pinned config) goes to /zap/wrk and zap.json comes back to the work folder, then to pipegen-raw', () => {
    const sb = sandbox();
    const t = entry('zap-baseline');
    const art = resultArtifactName('dast', 'app');
    let step = lastRun(renderStepWith(spec(t, { needId: 'dast' }), t, platform(), ctx));
    step = { ...step, run: (step.run as string).replaceAll('/usr/bin/docker', fakeDocker(sb, '[ -f zap-baseline.conf ] || exit 8\necho \'{"site":[]}\' > zap.json\nexit 2')) };
    expect(exec(step, sb, stepEnv(step, sb)).status).toBe(0);
    expect(existsSync(join(sb.rt, 'pipegen-raw', art, 'zap.json'))).toBe(true);
  });

  it('a repo symlink named like the result is refused before the tool runs (the result path must be free)', () => {
    const sb0 = sandbox();
    symlinkSync('/etc/passwd', join(sb0.ws, 'semgrep.sarif'));
    const t = entry('semgrep');
    const step = lastRun(renderStepWith(spec(t, { needId: 'sast' }), t, platform(), ctx));
    const r = exec({ ...step, run: (step.run as string).replaceAll('/usr/bin/docker', fakeDocker(sb0, 'exit 0')) }, sb0, stepEnv(step, sb0));
    expect(r.status).not.toBe(0);
  });
});
