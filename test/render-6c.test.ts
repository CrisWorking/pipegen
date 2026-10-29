// Plan B 6c: run-time slots (B6), rule archives (S12), container actions (S13), project scripts (S10). Written first.
// Shell is run through real bash and real git (a local bare repo, no network).
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { slotProblem, SLOT_KINDS } from '../src/engine/slots.js';
import { checkJobOrder, dedupeJobSteps, RenderError, renderStepWith, type RenderContext, type RenderedStep, type RenderResult } from '../src/engine/render-step.js';
import { NEED_IDS } from '../src/engine/need-ids.js';
import { ARGV_POLICIES, type ArgvPolicy } from '../src/engine/tool-flags.js';
import type { ReviewedTool, StepSpec } from '../src/types.js';
import { ctxFor, entry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';
import { exec, sandbox, stepEnv } from './helpers/step-harness.js';

const IMG = `ghcr.io/o/app@sha256:${'a'.repeat(64)}`;
const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
const ctxWith = (targets: RenderContext['targets'], svc = service({ name: 'app', path: '.', dockerfile: 'Dockerfile' }), defaultBranch = 'main'): RenderContext => ({ profile: { ...profile([svc]), defaultBranch }, targets });
const full = ctxWith({ image: IMG, url: 'http://localhost:8080' });
const render = (id: string, c: RenderContext = full, over: Partial<StepSpec> = {}, opts?: Parameters<typeof renderStepWith>[4]): RenderResult => {
  const t = entry(id);
  return renderStepWith(specFor(t, { needId: needFor(t), ...over }), t, platform(), c, opts);
};
const runOf = (r: RenderResult): RenderedStep => r.steps.filter((s) => s.run !== undefined).at(-1) as RenderedStep;
const argEnv = (s: RenderedStep): string[] => Object.entries(s.env ?? {}).filter(([k]) => /^PIPEGEN_ARG_\d+$/.test(k)).map(([, v]) => v);
const it2 = it.skipIf(process.platform === 'win32');

describe('B6: slot validators reject hostile values', () => {
  const bad = (kind: (typeof SLOT_KINDS)[number], values: string[], ctx?: Parameters<typeof slotProblem>[2]): void => {
    for (const v of values) expect(slotProblem(kind, v, ctx), `${kind}: ${JSON.stringify(v)}`).not.toBeNull();
  };
  it('there are exactly four kinds', () => expect([...SLOT_KINDS].sort()).toEqual(['git-ref', 'image-digest', 'local-url', 'repo-path']));

  it('image-digest', () => {
    expect(slotProblem('image-digest', IMG)).toBeNull();
    expect(slotProblem('image-digest', `docker.io/library/alpine@sha256:${'b'.repeat(64)}`)).toBeNull();
    bad('image-digest', [
      'ghcr.io/o/app', 'ghcr.io/o/app:latest', `ghcr.io/o/app:1@sha256:${'a'.repeat(64)}`, `ghcr.io/o/app@sha256:${'a'.repeat(63)}`, `ghcr.io/o/app@sha256:${'a'.repeat(65)}`,
      `ghcr.io/o/app@sha256:${'A'.repeat(64)}`, `${IMG}@sha256:${'b'.repeat(64)}`, `-ghcr.io/o/app@sha256:${'a'.repeat(64)}`, `file://x@sha256:${'a'.repeat(64)}`,
      `evil.example/o/app@sha256:${'a'.repeat(64)}`, `ghcr.io/o/app@sha256:${'a'.repeat(64)} --privileged`, `ghcr.io/o/app@sha256:${'a'.repeat(64)}\n`, `ghcr.io/ö/app@sha256:${'a'.repeat(64)}`, '',
    ]);
  });

  it('local-url', () => {
    for (const ok of ['http://localhost:8080', 'http://127.0.0.1:3000', 'http://localhost:8080/', 'http://localhost:8080/health/x-y_z.1']) expect(slotProblem('local-url', ok), ok).toBeNull();
    bad('local-url', [
      'file:///etc/passwd', 'http://localhost.evil.com:80', 'http://127.0.0.1@evil.com', ['http://localhost:80', '@evil.com'].join(''), ['http://127.0.0.1:8080', '@evil'].join(''), 'http://lоcalhost:8080', 'http://localhost',
      'http://localhost:0', 'http://localhost:65536', 'http://localhost:080', 'https://localhost:8080', 'http://localhost:8080/../x', 'http://localhost:8080//x', 'http://localhost:8080/a b',
      'http://localhost:8080?x=1', 'http://localhost:8080/#f', 'http://[::1]:8080', 'http://0.0.0.0:80', 'http://127.0.0.2:80', 'http://localhost:8080\n', ' http://localhost:8080', '-t', '',
    ]);
  });

  it('repo-path', () => {
    for (const ok of ['Dockerfile', 'docker/Dockerfile.prod', 'k8s', 'deploy/k8s/base', '.']) expect(slotProblem('repo-path', ok), ok).toBeNull();
    bad('repo-path', ['../x', 'a/../b', '/etc/passwd', '-f', '--config=x', 'a/*', 'a b', 'a\nb', '$(id)', 'a;b', 'ö', '', 'a//b', '~/x', `${'a/'.repeat(120)}x`]);
  });

  it('git-ref is origin/<default branch> and nothing else', () => {
    const c = { defaultBranch: 'main' };
    expect(slotProblem('git-ref', 'origin/main', c)).toBeNull();
    expect(slotProblem('git-ref', 'origin/develop', { defaultBranch: 'develop' })).toBeNull();
    bad('git-ref', ['origin/dev', 'main', 'origin/main..x', 'origin/ma..in', 'origin/main~1', 'origin/main^', 'origin/main^{tree}', '-origin/main', 'origin/-main', 'origin/main:x', 'origin/ma in', 'origin/main.lock', 'origin/main.', 'refs/heads/main', 'origin/', 'origin/main\n', '--upload-pack=x', ''], c);
    // a default branch that is itself odd is refused when it is used
    for (const odd of ['a..b', 'x~1', 'x^', '-x', 'a b', 'feature/x', 'x.lock', '']) expect(slotProblem('git-ref', `origin/${odd}`, { defaultBranch: odd }), odd).not.toBeNull();
  });
});

describe('B6: slots in rendered steps (values only from the render context, passed through env)', () => {
  it('trivy-image and syft take the image digest target as the last word', () => {
    for (const id of ['trivy-image', 'syft']) {
      const run = runOf(render(id));
      expect(argEnv(run), id).toContain(IMG);
      expect(run.run, id).toMatch(/"\$PIPEGEN_ARG_\d+"( |\))*$|"\$PIPEGEN_ARG_\d+" \|\| rc=\$\?/m);
      expect(run.run, id).not.toContain(IMG);
    }
  });
  it('a missing, malformed or AI-looking target is a RenderError that names the target', () => {
    expect(() => render('trivy-image', ctxWith({}))).toThrow(/image/);
    expect(() => render('trivy-image', ctxWith({ image: 'ghcr.io/o/app:latest' }))).toThrow(RenderError);
    expect(() => render('syft', ctxWith({ image: `${IMG}; id` }))).toThrow(RenderError);
    expect(() => render('zap-baseline', ctxWith({}))).toThrow(/url/i);
    expect(() => render('zap-baseline', ctxWith({ url: 'http://localhost.evil.com:80' }))).toThrow(RenderError);
    expect(() => render('nuclei', ctxWith({ url: 'file:///etc/passwd' }))).toThrow(RenderError);
  });
  it('zap -t and nuclei -target take the local url', () => {
    const z = runOf(render('zap-baseline'));
    expect(argEnv(z)).toContain('http://localhost:8080');
    expect(z.run).toMatch(/ -t "\$PIPEGEN_ARG_\d+"/);
    expect(z.run).toContain('--network host');
    const n = runOf(render('nuclei'));
    expect(argEnv(n)).toContain('http://localhost:8080');
    expect(n.run).toMatch(/ -target "\$PIPEGEN_ARG_\d+"/);
  });
  it('jscpd --baseline-from-ref is origin/<default branch>, replacing the reviewed word, and asks for a full checkout', () => {
    const r = render('jscpd', ctxWith({}, service({ name: 'app', path: '.' }), 'develop'));
    const run = runOf(r);
    expect(argEnv(run)).toContain('origin/develop');
    expect(run.run).not.toContain('origin/main');
    expect(run.run?.match(/--baseline-from-ref/g)).toHaveLength(1);
    expect(r.fullHistory).toBe(true);
    expect(render('trivy-config').fullHistory).toBeUndefined();
    expect(() => render('jscpd', ctxWith({}, service({ name: 'app', path: '.' }), 'feat/x'))).toThrow(RenderError);
  });
  it('hadolint gets the service Dockerfile (a checked repo path); no Dockerfile or a hostile one is refused', () => {
    expect(argEnv(runOf(render('hadolint', full, { service: 'app' })))).toContain('Dockerfile');
    expect(() => render('hadolint', ctxWith({}, service({ name: 'app', path: '.' })), { service: 'app' })).toThrow(/Dockerfile/);
    for (const d of ['../Dockerfile', '-f', '/etc/passwd', 'a b']) expect(() => render('hadolint', ctxWith({}, service({ name: 'app', path: '.', dockerfile: d })), { service: 'app' })).toThrow(RenderError);
  });
  it('kube-linter gets a folder: the context target, else "." when the profile has Kubernetes files, else an error', () => {
    expect(() => render('kube-linter', ctxWith({}))).toThrow(/Kubernetes/);
    const withK8s: RenderContext = { profile: { ...profile([service({ name: 'app', path: '.' })]), repoFiles: { ...profile().repoFiles, kubernetes: true } } };
    expect(argEnv(runOf(render('kube-linter', withK8s)))).toContain('.');
    expect(argEnv(runOf(render('kube-linter', { ...withK8s, targets: { k8sDir: 'deploy/k8s' } })))).toContain('deploy/k8s');
    expect(() => render('kube-linter', { ...withK8s, targets: { k8sDir: '../x' } })).toThrow(RenderError);
  });
  it2('a repo-path slot that is a symlink fails the step at run time', () => {
    const run = runOf(render('hadolint', full, { service: 'app' }));
    expect(run.run).toMatch(/\[ -L /);
  });
  it('slot values never appear in the shell text', () => {
    for (const [id, v] of [['trivy-image', IMG], ['zap-baseline', 'http://localhost:8080'], ['nuclei', 'http://localhost:8080']] as const) expect(runOf(render(id)).run, id).not.toContain(v);
  });
});

describe('permanent refusals say why (no "6c" is left)', () => {
  it('schemathesis: pip not available yet; cosign: Plan G sign job; gosec: Go not supported', () => {
    expect(() => render('schemathesis')).toThrow(/pip.*not available yet|not available yet/);
    expect(() => render('cosign')).toThrow(/Plan G's sign job/);
    expect(() => render('gosec')).toThrow(/Go is not supported in v0\.2/);
  });
  it('the whole reviewed list: every entry renders or throws a documented permanent RenderError, none mentions 6c', () => {
    const outcome: Record<string, string> = {};
    for (const t of reviewedList()) {
      if (t.step.cli === undefined) continue;
      try {
        renderStepWith(specFor(t, { needId: needFor(t), service: 'app' }), t, platform(), ctxWith({ image: IMG, url: 'http://localhost:8080' }));
        outcome[t.id] = 'rendered';
      } catch (e) {
        expect(e, t.id).toBeInstanceOf(RenderError);
        const m = (e as Error).message;
        expect(m, t.id).not.toMatch(/6c|ruling B6|rendered in 6/);
        expect(m, t.id).toMatch(/Plan G|not available yet|job service|Go is not supported|render context does not have/);
        outcome[t.id] = m;
      }
    }
    expect(Object.entries(outcome).filter(([, v]) => v !== 'rendered').map(([k]) => k).sort()).toEqual(['bandit', 'cosign', 'coverage-py', 'creosote', 'gosec', 'kube-linter', 'mypy', 'registry', 'schemathesis', 'vulture']);
  });
});

// ---------- rule archives (S12) ----------
const git = (cwd: string, ...args: string[]): string => {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', env: { PATH: process.env.PATH ?? '', HOME: cwd, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
};

/** A bare repo that serves "<owner>/<name>" under a base folder, holding a javascript/ and a python/ rules folder. */
function ruleRepo(owner: string, name: string, marker = ''): { base: string; commit: string; tree: string; other: string; otherTree: string } {
  const base = mkdtempSync(join(tmpdir(), 'pipegen-rules-'));
  const work = join(base, 'work');
  mkdirSync(work, { recursive: true });
  git(work, 'init', '--quiet', '-b', 'main');
  mkdirSync(join(work, 'javascript'));
  mkdirSync(join(work, 'python'));
  writeFileSync(join(work, 'javascript', 'a.yaml'), 'rules: []\n');
  writeFileSync(join(work, 'python', 'b.yaml'), `rules: []\n${marker}`);
  git(work, 'add', '-A');
  git(work, 'commit', '--quiet', '-m', 'one');
  const commit = git(work, 'rev-parse', 'HEAD');
  const tree = git(work, 'rev-parse', 'HEAD^{tree}');
  writeFileSync(join(work, 'javascript', 'a.yaml'), 'rules: [evil]\n');
  git(work, 'commit', '--quiet', '-am', 'two');
  const other = git(work, 'rev-parse', 'HEAD');
  const otherTree = git(work, 'rev-parse', 'HEAD^{tree}');
  const bare = join(base, owner, `${name}`);
  mkdirSync(join(base, owner), { recursive: true });
  git(base, 'clone', '--quiet', '--bare', work, bare);
  git(bare, 'config', 'uploadpack.allowAnySHA1InWant', 'true');
  return { base: `file://${base}/`, commit, tree, other, otherTree };
}

/** nuclei with its pinned commit and tree replaced by the fixture's (the entry's own are real GitHub values). */
function nucleiAgainst(f: { commit: string; tree: string }): ReviewedTool {
  const t = entry('nuclei');
  for (const env of [t.step.cli?.env, t.fixedInputs.env] as Record<string, string>[]) {
    env.PIPEGEN_NUCLEI_TEMPLATES_COMMIT = f.commit;
    env.PIPEGEN_NUCLEI_TEMPLATES_TREE = f.tree;
  }
  return t;
}
const rulesStep = (r: RenderResult): RenderedStep => r.steps.find((s) => s.name.includes('templates') || s.name.includes('rules')) as RenderedStep;

describe('S12: rule archives are fetched by commit and checked by tree (real git, a local bare repo)', () => {
  const fx = ruleRepo('projectdiscovery', 'nuclei-templates');
  const renderNuclei = (t: ReviewedTool, base = fx.base): RenderResult => renderStepWith(specFor(t, { needId: 'dast' }), t, platform(), full, { gitBase: base });

  it('nuclei: a separate step before the tool; its text has the helper\'s git commands and no value from the data', () => {
    const r = renderNuclei(nucleiAgainst(fx));
    const s = rulesStep(r);
    expect(s).toBeDefined();
    expect(r.steps.indexOf(s)).toBeLessThan(r.steps.indexOf(runOf(r)));
    expect(s.id).toMatch(/^tool-install-[0-9a-f]{16}$/);
    for (const part of ['init', 'fetch', '--depth 1', 'checkout', 'FETCH_HEAD', 'HEAD^{tree}', 'env -i', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null']) expect(s.run, part).toContain(part);
    expect(s.run).not.toContain(fx.commit);
    expect(s.env?.PIPEGEN_RULES_COMMIT).toBe(fx.commit);
    // the tool is told the checked-out folder, not a path that does not exist on the runner
    expect(runOf(r).run).not.toContain('/pipegen-nuclei-templates');
    expect(checkJobOrder(dedupeJobSteps(r.steps))).toEqual([]);
  });

  it2('a correct commit and tree: the folder holds the files, has no .git, and is read-only', () => {
    const r = renderNuclei(nucleiAgainst(fx));
    const s = rulesStep(r);
    const sb = sandbox();
    const res = exec(s, sb, stepEnv(s, sb));
    expect(res.status, res.stderr).toBe(0);
    const dir = join(sb.rt, 'pipegen-rules', 'pipegen-out-dast');
    expect(readFileSync(join(dir, 'javascript', 'a.yaml'), 'utf8')).toBe('rules: []\n');
    expect(existsSync(join(dir, '.git'))).toBe(false);
  });

  it2('a wrong tree fails; a wrong commit fails; a commit that does not exist fails', () => {
    for (const [what, edit] of [['tree', { commit: fx.commit, tree: fx.otherTree }], ['commit', { commit: fx.other, tree: fx.tree }], ['missing', { commit: 'c'.repeat(40), tree: fx.tree }]] as const) {
      const s = rulesStep(renderNuclei(nucleiAgainst(edit)));
      const sb = sandbox();
      const res = exec(s, sb, stepEnv(s, sb));
      expect(res.status, what).not.toBe(0);
    }
  });

  it2('a wrong remote that serves other content (a different repo with the same commit name) is caught by the tree', () => {
    const evil = ruleRepo('projectdiscovery', 'nuclei-templates', '# evil\n');   // same names, other content
    const s = rulesStep(renderNuclei(nucleiAgainst({ commit: evil.commit, tree: fx.tree }), evil.base));
    const sb = sandbox();
    expect(exec(s, sb, stepEnv(s, sb)).status).not.toBe(0);
  });

  it2('git config and GIT_* variables in the environment, the repo and the home folder have no effect', () => {
    const decoy = ruleRepo('projectdiscovery', 'nuclei-templates');
    const s = rulesStep(renderNuclei(nucleiAgainst(fx)));
    const sb = sandbox();
    // a workspace repo whose config redirects the remote to a decoy and runs a command, a home .gitconfig that does the same, and hostile GIT_* variables
    git(sb.ws, 'init', '--quiet');
    writeFileSync(join(sb.ws, '.git', 'config'), `[url "${decoy.base}"]\n\tinsteadOf = ${fx.base}\n[core]\n\tfsmonitor = touch ${sb.dir}/pwned\n`);
    const home = join(sb.rt, 'pipegen-home', 'pipegen-out-dast');
    mkdirSync(home, { recursive: true });
    writeFileSync(join(home, '.gitconfig'), `[url "${decoy.base}"]\n\tinsteadOf = ${fx.base}\n`);
    const evilCfg = join(sb.dir, 'evil.cfg');
    writeFileSync(evilCfg, `[url "${decoy.base}"]\n\tinsteadOf = ${fx.base}\n`);
    const env = stepEnv(s, sb, {}, {
      GIT_DIR: join(sb.ws, '.git'), GIT_WORK_TREE: sb.ws, GIT_CONFIG_GLOBAL: evilCfg, GIT_CONFIG_SYSTEM: evilCfg, GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'core.fsmonitor', GIT_CONFIG_VALUE_0: `touch ${sb.dir}/pwned2`,
      GIT_EXEC_PATH: '/nonexistent', GIT_TEMPLATE_DIR: sb.dir, GIT_SSH_COMMAND: `touch ${sb.dir}/pwned3`, GIT_PROXY_COMMAND: 'false', HOME: home, XDG_CONFIG_HOME: sb.dir, GIT_ALLOW_PROTOCOL: 'ext',
    });
    const res = exec(s, sb, env);
    expect(res.status, res.stderr).toBe(0);
    for (const f of ['pwned', 'pwned2', 'pwned3']) expect(existsSync(join(sb.dir, f)), f).toBe(false);
    expect(readFileSync(join(sb.rt, 'pipegen-rules', 'pipegen-out-dast', 'javascript', 'a.yaml'), 'utf8')).toBe('rules: []\n');
  });

  it('a hostile commit or tree value in the data is refused at render time, never written into a shell', () => {
    const t = nucleiAgainst({ commit: fx.commit, tree: fx.tree });
    for (const env of [t.step.cli?.env, t.fixedInputs.env] as Record<string, string>[]) env.PIPEGEN_NUCLEI_TEMPLATES_TREE = `${fx.tree}; id`;
    expect(() => renderNuclei(t)).toThrow(RenderError);
  });

  describe('semgrep: <tree>/<rules choice> mounted read-only at /pipegen-rules, --network none', () => {
    const sg = ruleRepo('semgrep', 'semgrep-rules');
    const semgrepAgainst = (f: { commit: string; tree: string }): ReviewedTool => {
      const t = entry('semgrep');
      for (const env of [t.step.cli?.env, t.fixedInputs.env] as Record<string, string>[]) {
        env.PIPEGEN_RULES_URL = `https://github.com/semgrep/semgrep-rules/archive/${f.commit}.tar.gz`;
        env.PIPEGEN_RULES_TREE = f.tree;
      }
      return t;
    };
    const renderSemgrep = (t: ReviewedTool, choice = 'javascript'): RenderResult => renderStepWith(specFor(t, { needId: 'sast', choices: { rules: choice } }), t, platform(), full, { gitBase: sg.base });

    it('layout and mount', () => {
      const r = renderSemgrep(semgrepAgainst({ commit: sg.commit, tree: sg.tree }));
      const run = runOf(r).run as string;
      expect(run).toContain('--network none');
      expect(run).toMatch(/-v "\$rules\/\$PIPEGEN_ARG_\d+:\/pipegen-rules:ro"/);
      expect(run).toContain('--config /pipegen-rules');
      expect(argEnv(runOf(r))).toContain('javascript');
      expect(rulesStep(r).env?.PIPEGEN_RULES_COMMIT).toBe(sg.commit);
      expect(checkJobOrder(dedupeJobSteps(r.steps))).toEqual([]);
    });
    it2('the rules step with real git: right tree passes, wrong tree fails', () => {
      const ok = rulesStep(renderSemgrep(semgrepAgainst({ commit: sg.commit, tree: sg.tree })));
      const sb = sandbox();
      expect(exec(ok, sb, stepEnv(ok, sb)).status).toBe(0);
      expect(existsSync(join(sb.rt, 'pipegen-rules', 'pipegen-out-sast', 'python', 'b.yaml'))).toBe(true);
      const bad = rulesStep(renderSemgrep(semgrepAgainst({ commit: sg.commit, tree: sg.otherTree })));
      const sb2 = sandbox();
      expect(exec(bad, sb2, stepEnv(bad, sb2)).status).not.toBe(0);
    });
    it('a rules choice that is not in the entry\'s list is refused', () => {
      expect(() => renderSemgrep(semgrepAgainst({ commit: sg.commit, tree: sg.tree }), '../x')).toThrow(RenderError);
    });
    it('the real entry renders (no gitBase): https://github.com/ and only the https protocol', () => {
      const r = render('semgrep');
      const s = rulesStep(r);
      expect(s.env?.PIPEGEN_RULES_REMOTE).toBe('https://github.com/semgrep/semgrep-rules');
      expect(s.run).toContain('GIT_ALLOW_PROTOCOL=https');
      expect(s.env?.PIPEGEN_RULES_COMMIT).toBe('17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9');
      expect(s.env?.PIPEGEN_RULES_TREE_WANT).toBe('dd3179667faf14717e05c33b1916b0d2c349673d');
    });
  });
});

// ---------- ESLint (S11 as amended by DECISIONS #107) ----------
describe('S11: the ESLint config resolves @eslint/js and typescript-eslint from pipegen\'s closure folder, never from the repo', () => {
  it2('a planted repo copy that throws on import is never loaded', () => {
    const t = entry('eslint-typescript');
    const r = renderStepWith(specFor(t, { needId: 'lint' }), t, platform(), full);
    const run = runOf(r);
    expect(run.run).toContain('printf \'%s\' "$PIPEGEN_CONFIG" > "$npmdir/eslint.config.mjs"');
    const sb = sandbox();
    const closure = join(sb.rt, 'pipegen-npm', 'x');
    const fake = (root: string, name: string, body: string): void => {
      const d = join(root, 'node_modules', name);
      mkdirSync(d, { recursive: true });
      writeFileSync(join(d, 'package.json'), JSON.stringify({ name, version: '1.0.0', type: 'module', main: 'index.js', exports: './index.js' }));
      writeFileSync(join(d, 'index.js'), body);
    };
    fake(closure, '@eslint/js', 'export default { configs: { recommended: { rules: {} } } };\n');
    fake(closure, 'typescript-eslint', 'export default { configs: { recommended: [] } };\n');
    fake(sb.ws, '@eslint/js', 'throw new Error("repo copy loaded");\n');
    fake(sb.ws, 'typescript-eslint', 'throw new Error("repo copy loaded");\n');
    writeFileSync(join(closure, 'eslint.config.mjs'), run.env?.PIPEGEN_CONFIG as string);
    const res = spawnSync(process.execPath, ['--input-type=module', '-e', `const m = await import(${JSON.stringify(`file://${join(closure, 'eslint.config.mjs')}`)}); console.log(Array.isArray(m.default));`], { cwd: sb.ws, encoding: 'utf8' });
    expect(res.stderr).not.toContain('repo copy loaded');
    expect(res.stdout.trim()).toBe('true');
  });
});

