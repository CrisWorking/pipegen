// D3 fix round 2: an ENV/ARG name allowlist (B1), paths limited to the app folder (B2), a single command in exec-form RUN (B3), script names
// that start with a letter or digit (C2), and five more .dockerignore lines. The reviewer's round-1 repros are in test/fixtures/dockerfile-attacks-r1/.
import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { DOCKERIGNORE_LINES, dockerfileProblems, dockerignoreText, type DockerfileCtx } from '../src/create/dockerfile-rules.js';
import { baseImageRef, loadBaseImages } from '../src/engine/base-images.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import type { Service } from '../src/types.js';

const REF = baseImageRef('node-24-bookworm-slim');
const svc = (over: Partial<Service> = {}): Service => ({
  name: 'api', path: 'api', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: ['start', 'build'], frameworks: [], quality: emptyServiceQuality(), ...over,
});
const ctx = (over: Partial<DockerfileCtx> = {}): DockerfileCtx => ({ port: 3000, baseImages: loadBaseImages(), buildsInside: false, scripts: ['start', 'build'], ...over });
const problems = (t: string, over: Partial<DockerfileCtx> = {}): string[] => dockerfileProblems(t, svc(), ctx(over));
const SINGLE = [`FROM ${REF}`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --omit=dev --ignore-scripts', 'COPY . .', 'EXPOSE 3000', 'USER node', 'CMD ["node", "index.js"]', ''].join('\n');
const swap = (t: string, a: string, b: string): string => { expect(t).toContain(a); return t.replace(a, b); };
const withLine = (line: string): string => swap(SINGLE, 'COPY . .', `COPY . .\n${line}`);
const refused = (t: string, re: RegExp = /.+/, over: Partial<DockerfileCtx> = {}): void => {
  const p = problems(t, over);
  expect(p.length, t).toBeGreaterThan(0);
  expect(p.join('\n'), t).toMatch(re);
};

describe('round-1 repro fixtures', () => {
  const dir = new URL('./fixtures/dockerfile-attacks-r1/', import.meta.url);
  // the plain ones among the reviewer's probes: valid Dockerfiles that must keep passing
  const GOOD = new Set([
    'ci_omit_eq_both', 'cmd_hidden_dir', 'cmd_nm', 'cmd_none', 'cont_amp', 'cont_glue_hash', 'cont_glue_word', 'copy_chmod_0755', 'copy_chmod_777', 'copy_link_from', 'copy_quoted_flag',
    'exec_ci', 'label_subst', 'mount_exact', 'network_none_ci', 'tab_sep', 'user_1000', 'user_cont', 'user_inherited', 'user_tab', 'user_variants',
  ]);
  it('every other fixture is refused (including the ENV, path and exec-&& repros); the plain ones pass', () => {
    const names = readdirSync(dir).filter((n) => n.endsWith('.Dockerfile')).map((n) => n.replace('.Dockerfile', ''));
    expect(names.length).toBeGreaterThanOrEqual(80);
    for (const n of names) {
      const p = problems(readFileSync(new URL(`${n}.Dockerfile`, dir), 'utf8'), { buildsInside: /^(?:copy_|final_|user_root_then)/.test(n) });
      if (GOOD.has(n)) expect(p, n).toEqual([]);
      else expect(p.length, n).toBeGreaterThan(0);
    }
    for (const n of ['chown_etc', 'chown_root', 'chown_usr_local', 'env_home', 'env_path', 'env_prefix', 'exec_amp', 'exec_amp_escaped', 'mkdir_etc', 'workdir_root']) expect(names, n).toContain(n);
  });
});

describe('B1: ENV and ARG names are an allowlist', () => {
  it('the allowed names with their only values pass, in ENV and ARG, in any stage', () => {
    for (const line of [
      'ENV NODE_ENV=production', 'ENV NODE_ENV=development', 'ENV NODE_ENV=test', 'ARG NODE_ENV=production', 'ENV PORT=3000', 'ARG PORT=3000', 'ENV NODE_ENV production',
      'ENV NPM_CONFIG_UPDATE_NOTIFIER=false', 'ENV NPM_CONFIG_FUND=false', 'ENV NPM_CONFIG_AUDIT=false', 'ARG NPM_CONFIG_AUDIT=false',
      'ENV NODE_ENV=production PORT=3000 NPM_CONFIG_FUND=false', 'env NODE_ENV=production', 'ENV NODE_ENV="production"', 'ENV PORT=3000',
    ]) expect(problems(withLine(line)), line).toEqual([]);
    expect(problems(withLine('ENV PORT=8080').replace('EXPOSE 3000', 'EXPOSE 8080'), { port: 8080 })).toEqual([]);
  });

  it('every other name is refused, with or without a value; so is any other value; the match is case-sensitive', () => {
    for (const line of [
      'ENV PATH=/app/node_modules/.bin:/usr/local/bin:/usr/bin:/bin', 'ENV PATH=/evil:$PATH', 'ENV HOME=/app', 'ENV PREFIX=/app', 'ENV NODE_OPTIONS=--require=/x.js', 'ENV NODE_EXTRA_CA_CERTS=/x', 'ENV NODE_TLS_REJECT_UNAUTHORIZED=0',
      'ENV LD_PRELOAD=/x.so', 'ENV LD_LIBRARY_PATH=/x', 'ENV BASH_ENV=/x', 'ENV HTTPS_PROXY=http://evil:3128', 'ENV https_proxy=http://evil:3128', 'ENV NPM_CONFIG_REGISTRY=https://evil.example', 'ENV NPM_CONFIG_IGNORE_SCRIPTS=false',
      'ENV NPM_CONFIG_PREFIX=/x', 'ENV NPM_CONFIG_CACHE=/x', 'ENV NPM_CONFIG_FUND=true', 'ENV NPM_CONFIG_PREFIX=false', 'ENV NPM_CONFIG_REGISTRY=false', 'ENV NPM_CONFIG_USERCONFIG=false', 'ENV NPM_CONFIG_AUDIT=0', 'ENV NPM_CONFIG_AUDIT=False', 'ENV NPM_CONFIG_AUDIT=', 'ENV NPM_CONFIG_AUDIT', 'ENV npm_config_fund=false', 'ENV Npm_Config_Fund=false',
      'ENV node_env=production', 'ENV Node_Env=production', 'ENV NODE_ENV=prod', 'ENV NODE_ENV=Production', 'ENV NODE_ENV=', 'ENV NODE_ENV', 'ENV NODE_ENV=$X', 'ENV NODE_ENV=production2', 'ENV NODE_ENV="production x"',
      'ENV PORT=3001', 'ENV PORT=1', 'ENV PORT=false', 'ENV PORT=03000', 'ENV PORT=', 'ENV PORT=$PORT', 'ENV PORT=3000x', 'ENV PORT=3000.0', 'ENV PORT=+3000',
      'ARG PATH', 'ARG HOME=/x', 'ARG BUILD_ID', 'ARG BUILD_ID=1', 'ARG PORT', 'ARG NODE_ENV', 'ARG NPM_CONFIG_REGISTRY', 'ARG FOO=bar', 'ENV FOO=bar', 'ENV A=1 B=2', 'ENV NODE_ENV=production FOO=bar', 'ENV FOO bar',
      'ENV CI=true', 'ENV TZ=UTC', 'ENV DEBUG=*', 'ENV API_' + 'KEY=', 'ENV DATABASE_' + 'URL=', 'ARG NPM_' + 'TOKEN',
    ]) refused(withLine(line), /ENV|ARG/);
  });
});

describe('B2: paths stay in the app folder', () => {
  it('WORKDIR is /app or a plain path under /app/', () => {
    for (const wd of ['WORKDIR /app', 'WORKDIR /app/sub', 'WORKDIR /app/sub-dir_1.0/x', 'WORKDIR /app/.cache']) expect(problems(swap(SINGLE, 'WORKDIR /app', wd)), wd).toEqual([]);
    for (const wd of ['WORKDIR /', 'WORKDIR /etc', 'WORKDIR /app/..', 'WORKDIR /app/../etc', 'WORKDIR /apple', 'WORKDIR /app2', 'WORKDIR app', 'WORKDIR ./app', 'WORKDIR /usr/local/lib/node_modules', 'WORKDIR /app//x', 'WORKDIR /appx/y', 'WORKDIR /root', 'WORKDIR /tmp', 'WORKDIR $HOME', 'WORKDIR /app/-x/..']) {
      refused(swap(SINGLE, 'WORKDIR /app', wd), /WORKDIR/);
    }
  });

  it('mkdir -p and chown [-R] node:node take a plain relative path or a plain path under /app/', () => {
    for (const cmd of [
      'mkdir -p data', 'mkdir -p data/cache', 'mkdir -p ./data', 'mkdir -p /app/data', 'mkdir -p /app/a/b', 'chown node:node data', 'chown -R node:node /app', 'chown -R node:node /app/data', 'chown node:node ./x', 'chown -R node:node .',
      'mkdir -p data && chown -R node:node data',
    ]) expect(problems(withLine(`RUN ${cmd}`)), cmd).toEqual([]);
    for (const cmd of [
      'mkdir -p /', 'mkdir -p /etc', 'mkdir -p /etc/profile.d/x', 'mkdir -p /app/..', 'mkdir -p /app/../etc', 'mkdir -p /apple', 'mkdir -p /app//x', 'mkdir -p /app/./x', 'chown -R node:node /app/.', 'mkdir -p ..', 'mkdir -p ../x', 'mkdir -p a/../../x', 'mkdir -p -x', 'mkdir -p /usr/local/lib',
      'mkdir -p /root/.npm', 'mkdir -p /tmp/x', 'mkdir -p /app', 'chown -R node:node /', 'chown -R node:node /etc', 'chown node:node /usr/local/lib/node_modules', 'chown -R node:node /app/..', 'chown -R node:node /apple', 'chown -R node:node ..',
      'chown -R node:node ../x', 'chown node:node -x', 'chown node:node /root', 'chown -R node:node //app',
    ].filter((c) => c !== 'mkdir -p /app')) refused(withLine(`RUN ${cmd}`), /RUN/);
    // /app itself is fine for mkdir too (it is the app folder)
    expect(problems(withLine('RUN mkdir -p /app'))).toEqual([]);
  });
});

describe('B3: exec-form RUN is exactly one command', () => {
  it('an && element is refused, as is its escaped spelling; one command passes', () => {
    for (const run of [
      'RUN ["mkdir", "-p", "x", "&&", "chown", "node:node", "x"]', 'RUN ["chown", "node:node", "x", "\\u0026\\u0026", "npm", "run", "start"]', 'RUN ["npm", "ci", "--ignore-scripts", "&&", "npm", "run", "build"]',
      'RUN ["&&"]', 'RUN ["&&", "npm", "ci", "--ignore-scripts"]', 'RUN ["npm", "ci", "--ignore-scripts", "&&"]', 'RUN ["npm", "ci", "--ignore-scripts", "\\u0026&"]',
    ]) refused(swap(SINGLE, 'COPY . .', `${run}`), /RUN/);
    expect(problems(withLine('RUN ["mkdir", "-p", "x"]'))).toEqual([]);
    expect(problems(withLine('RUN ["npm", "run", "build"]'))).toEqual([]);
    // the shell form still joins with &&
    expect(problems(withLine('RUN mkdir -p x && chown node:node x'))).toEqual([]);
  });
});

describe('C2: script names start with a letter or digit', () => {
  it('npm run and CMD ["npm","run",...] refuse a name that starts with : . _ or -', () => {
    for (const name of [':x', '.x', '_x', '-x', '--x', '..', '.']) {
      refused(withLine(`RUN npm run ${name}`), /RUN/, { scripts: [name] });
      refused(swap(SINGLE, 'CMD ["node", "index.js"]', `CMD ["npm", "run", "${name}"]`), /CMD/, { scripts: [name] });
    }
    for (const name of ['build', 'build:prod', '0x', 'a.b', 'a_b-c', 'Z']) {
      expect(problems(withLine(`RUN npm run ${name}`), { scripts: [name] }).filter((p) => /RUN/.test(p)), name).toEqual([]);
      expect(problems(swap(SINGLE, 'CMD ["node", "index.js"]', `CMD ["npm", "run", "${name}"]`), { scripts: [name] }), name).toEqual([]);
    }
  });
});

describe('.dockerignore: five more lines', () => {
  it('adds **/.kube, **/_netrc, **/.pypirc, **/.terraform and **/.venv, and keeps .venv', () => {
    const lines = [
      '.git', '.env*', '**/.env*', '**/*.pem', '**/*.key', '**/.npmrc', '**/.netrc', '**/*.tfstate', '**/*.tfvars', '**/id_rsa*', '**/node_modules', '.venv',
      '**/.git', '**/.ssh', '**/.aws', '**/.docker', '**/.git-credentials', '**/id_ed25519*', '**/id_ecdsa*', '**/id_dsa*', '**/*.p12', '**/*.pfx', '**/*.jks', '**/*.tfstate.backup', '**/*.tfvars.json',
      '**/.kube', '**/_netrc', '**/.pypirc', '**/.terraform', '**/.venv',
    ];
    expect([...DOCKERIGNORE_LINES]).toEqual(lines);
    expect(dockerignoreText(svc(), false)).toBe(`${lines.join('\n')}\n`);
    expect(dockerignoreText(svc(), true)).toBe(`${[...lines, 'dist'].join('\n')}\n`);
  });
});
