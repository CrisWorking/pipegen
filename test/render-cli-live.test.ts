// LIVE (PIPEGEN_LIVE_TESTS=1, uses the network and the real npm): the rendered eslint checker steps install eslint from
// pipegen's closure lock and run it, while the repo plants a .npmrc with `node-options=--require=./evil.js` and a
// lockfile whose eslint entry is a `link`. Neither may have any effect (6b fix round 1, R-A). Skipped by default.
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { renderStepWith } from '../src/engine/render-step.js';
import { REPO_CODE_STEP_ID_RE } from '../src/engine/tool-flags.js';
import { ctxFor, entry, platform, service, specFor } from './helpers/render.js';
import { exec, sandbox, stepEnv } from './helpers/step-harness.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1' && process.platform !== 'win32';

describe.skipIf(!live)('live: a checker is installed from pipegen\'s closure, not from the repo', () => {
  it.each(['eslint', 'eslint-typescript', 'prettier', 'biome', 'oxlint-typeaware', 'knip'])('%s installs from the closure lock and runs; a planted .npmrc and link lockfile in the service folder do nothing', (id) => {
    const t = entry(id);
    const major = process.versions.node.split('.')[0] as string;
    const c = ctxFor([service({ name: 'app', path: 'svc', runtimeVersion: major })]);
    const r = renderStepWith(specFor(t, { needId: t.categories[0] as string, service: 'app', workingDir: 'svc' }), t, platform(), c);
    const sb = sandbox();
    const svc = join(sb.ws, 'svc');
    mkdirSync(svc, { recursive: true });
    writeFileSync(join(svc, 'evil.js'), `require('fs').writeFileSync(${JSON.stringify(join(sb.dir, 'EVIL-RAN'))}, 'x');\n`);
    writeFileSync(join(svc, '.npmrc'), 'node-options=--require=./evil.js\nscript-shell=./evil.js\n');
    writeFileSync(join(svc, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, [`node_modules/${t.step.cli?.install.package}`]: { version: t.step.cli?.install.version, resolved: 'vendor/x', link: true } } }));
    writeFileSync(join(svc, 'package.json'), '{"name":"svc","version":"1.0.0"}');
    writeFileSync(join(svc, 'a.js'), 'export const a = 1;\n');
    writeFileSync(join(svc, 'b.ts'), 'export const b: number = 1;\n');
    // each tool's own repo hooks (root and nested), all of which write the EVIL-RAN marker if they run
    const evil = `require('fs').writeFileSync(${JSON.stringify(join(sb.dir, 'EVIL-RAN'))}, 'x');\n`;
    mkdirSync(join(svc, 'sub'), { recursive: true });
    for (const f of ['eslint.config.js', 'sub/eslint.config.js', '.prettierrc.cjs', 'knip.ts', 'vite.config.js']) writeFileSync(join(svc, f), evil);
    for (const f of ['.oxlintrc.json', 'sub/.oxlintrc.json']) writeFileSync(join(svc, f), JSON.stringify({ jsPlugins: ['./evil.js'] }));
    writeFileSync(join(svc, 'sub', 'biome.json'), JSON.stringify({ root: false, linter: { enabled: false } }));
    mkdirSync(join(svc, 'node_modules', '.bin'), { recursive: true });
    writeFileSync(join(svc, 'node_modules', '.bin', 'tsgolint'), `#!/bin/sh\ntouch ${join(sb.dir, 'EVIL-RAN')}\n`);
    chmodSync(join(svc, 'node_modules', '.bin', 'tsgolint'), 0o755);
    // a module above runner temp that a closure package also needs: the closure's own copy must be the one that loads
    mkdirSync(join(sb.dir, 'node_modules', 'debug'), { recursive: true });
    writeFileSync(join(sb.dir, 'node_modules', 'debug', 'index.js'), evil);
    writeFileSync(join(sb.dir, 'node_modules', 'debug', 'package.json'), '{"name":"debug","version":"0.0.1","main":"index.js"}');
    // a checkout is a git repository: oxlint lints `git ls-files` (d1407a3), so the sandbox needs one with the files added (final review minor 4)
    execFileSync('git', ['init', '-q'], { cwd: sb.ws });
    execFileSync('git', ['add', '-A'], { cwd: sb.ws });
    const steps = r.steps.filter((s) => s.run !== undefined);
    for (const step of steps) {
      const res = exec(step, sb, stepEnv(step, sb));
      // the install must succeed; the tool itself may report findings (evil.js is a lint finding for some of them): exit 0 or 1
      const ok = step === steps.at(-1) ? res.status === 0 || res.status === 1 : res.status === 0;
      expect(ok, `${step.name}\n${res.stderr}\n${res.stdout}`).toBe(true);
      if (step === steps.at(-1)) expect(res.stderr, 'the tool really ran').not.toMatch(/pipegen:/);
    }
    // prettier and knip load repo files by design: their run step is marked as a repo-code step instead
    if (id === 'prettier' || id === 'knip') expect(steps.at(-1)?.id).toMatch(REPO_CODE_STEP_ID_RE);
    else expect(existsSync(join(sb.dir, 'EVIL-RAN')), 'a repo hook ran in a checker').toBe(false);
    // eslint really ran from the isolated folder
    const lock = JSON.parse(readFileSync(join(sb.rt, 'pipegen-npm', `pipegen-out-${t.categories[0]}--app`, 'node_modules', t.step.cli?.install.package as string, 'package.json'), 'utf8')) as { version: string };
    expect(lock.version).toBe(t.step.cli?.install.version);
    expect(existsSync(join(svc, 'node_modules', t.step.cli?.install.package as string))).toBe(false);   // only the planted .bin/tsgolint is there
  }, 280_000);
});
