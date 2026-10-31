// D3 fix round 3 (blocker X1): the first instruction after every FROM is a WORKDIR (/app or a plain path under /app/), because the pinned Node
// images set no working directory, so a relative mkdir/chown/COPY target would resolve under `/`. Also c1: PORT takes only the service port.
import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { dockerfileProblems, type DockerfileCtx } from '../src/create/dockerfile-rules.js';
import { baseImageRef, loadBaseImages } from '../src/engine/base-images.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import type { Service } from '../src/types.js';

const REF = baseImageRef('node-24-bookworm-slim');
const svc = (): Service => ({ name: 'api', path: 'api', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: ['start', 'build'], frameworks: [], quality: emptyServiceQuality() });
const ctx = (over: Partial<DockerfileCtx> = {}): DockerfileCtx => ({ port: 3000, baseImages: loadBaseImages(), buildsInside: false, scripts: ['start', 'build'], ...over });
const problems = (t: string, over: Partial<DockerfileCtx> = {}): string[] => dockerfileProblems(t, svc(), ctx(over));
const SINGLE = [`FROM ${REF}`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --omit=dev --ignore-scripts', 'COPY . .', 'EXPOSE 3000', 'USER node', 'CMD ["node", "index.js"]', ''].join('\n');
const MULTI = [
  `FROM ${REF} AS build`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --ignore-scripts', 'COPY . .', 'RUN npm run build',
  `FROM ${REF}`, 'WORKDIR /app', 'COPY --from=build --chown=node:node /app/dist ./dist', 'EXPOSE 3000', 'USER node', 'CMD ["node", "dist/index.js"]', '',
].join('\n');
const swap = (t: string, a: string, b: string): string => { expect(t).toContain(a); return t.replace(a, b); };
const refused = (t: string, re: RegExp, over: Partial<DockerfileCtx> = {}): void => {
  const p = problems(t, over);
  expect(p.length, t).toBeGreaterThan(0);
  expect(p.join('\n'), t).toMatch(re);
};

describe('X1: the fixtures of the round-2 review', () => {
  const dir = new URL('./fixtures/dockerfile-attacks-r2/', import.meta.url);
  const GOOD = new Set(['arg_default', 'chown_app', 'chown_trailing', 'env_legacy', 'env_multi', 'env_quoted', 'env_single_quoted', 'exec_ok', 'exec_slash_esc', 'port_ok', 'wd_app_chown_dot', 'wd_quoted', 'wd_sub']);
  const WD_ATTACKS = ['wd_none_chown_dot', 'wd_none_chown_etc', 'wd_none_chown_usr', 'wd_none_mkdir', 'multi_stage_no_wd'];
  it('the plain ones pass, every attack is refused (the five WORKDIR repros for the WORKDIR rule)', () => {
    const names = readdirSync(dir).filter((n) => n.endsWith('.Dockerfile')).map((n) => n.replace('.Dockerfile', ''));
    expect(names.length).toBeGreaterThanOrEqual(45);
    for (const n of names) {
      const p = problems(readFileSync(new URL(`${n}.Dockerfile`, dir), 'utf8'), { buildsInside: n === 'multi_stage_no_wd' });
      if (GOOD.has(n)) expect(p, n).toEqual([]);
      else expect(p.length, n).toBeGreaterThan(0);
      if (WD_ATTACKS.includes(n)) expect(p.join('\n'), n).toMatch(/WORKDIR/);
    }
  });
});

describe('X1: WORKDIR right after every FROM', () => {
  it('relative chown and mkdir targets are refused when no WORKDIR comes right after FROM', () => {
    for (const cmd of ['chown -R node:node .', 'chown -R node:node etc', 'chown -R node:node usr/local/lib/node_modules', 'mkdir -p etc/profile.d', 'chown node:node x', 'mkdir -p data']) {
      refused(swap(SINGLE, 'WORKDIR /app\n', '').replace('COPY . .', `RUN ${cmd}\nCOPY . .`), /WORKDIR/);
    }
    // the same files pass with WORKDIR /app first
    for (const cmd of ['chown -R node:node .', 'mkdir -p data']) expect(problems(swap(SINGLE, 'COPY . .', `RUN ${cmd}`))).toEqual([]);
  });

  it('every stage needs it: a multi-stage file whose final (or first) stage has none is refused', () => {
    expect(problems(MULTI, { buildsInside: true })).toEqual([]);
    refused(swap(MULTI, `FROM ${REF}\nWORKDIR /app\n`, `FROM ${REF}\n`), /WORKDIR/, { buildsInside: true });
    refused(swap(MULTI, 'AS build\nWORKDIR /app\n', 'AS build\n'), /WORKDIR/, { buildsInside: true });
  });

  it('it must be the FIRST instruction, a valid WORKDIR, and an alias stage needs its own', () => {
    refused(swap(SINGLE, 'WORKDIR /app\nCOPY package.json package-lock.json ./', 'COPY package.json package-lock.json ./\nWORKDIR /app'), /WORKDIR/);
    refused(swap(SINGLE, 'WORKDIR /app\n', 'ENV NODE_ENV=production\nWORKDIR /app\n'), /WORKDIR/);
    refused(swap(SINGLE, 'WORKDIR /app\n', 'USER node\nWORKDIR /app\n'), /WORKDIR/);
    for (const wd of ['WORKDIR /', 'WORKDIR /etc', 'WORKDIR app', 'WORKDIR /app/..', 'WORKDIR $HOME']) refused(swap(SINGLE, 'WORKDIR /app', wd), /WORKDIR/);
    expect(problems(swap(SINGLE, 'WORKDIR /app', 'WORKDIR /app/srv'))).toEqual([]);
    // comments and blank lines between FROM and WORKDIR are not instructions
    expect(problems(swap(SINGLE, `FROM ${REF}\n`, `FROM ${REF}\n\n# note\n`))).toEqual([]);
    // a stage that starts from an earlier stage also pins its own directory
    const alias = (wd: boolean): string => [`FROM ${REF} AS base`, 'WORKDIR /app', 'RUN npm ci --ignore-scripts', 'USER node', 'FROM base', ...(wd ? ['WORKDIR /app'] : []), 'EXPOSE 3000', ''].join('\n');
    expect(problems(alias(true))).toEqual([]);
    refused(alias(false), /WORKDIR/);
    // a stage that ends right after its FROM
    refused([`FROM ${REF} AS a`, ...SINGLE.split('\n')].join('\n'), /WORKDIR/);
    refused(`${SINGLE}FROM ${REF}\n`, /WORKDIR/);
    refused(`FROM ${REF}\n`, /WORKDIR/);
  });
});

describe('c1: PORT takes only the service port', () => {
  it('ENV PORT=<another port> is refused, even a valid one', () => {
    const env = (v: string): string => swap(SINGLE, 'COPY . .', `COPY . .\nENV PORT=${v}`);
    expect(problems(env('3000'))).toEqual([]);
    for (const v of ['8080', '3001', '1', '65535', '80']) refused(env(v), /PORT/);
    expect(problems(env('8080').replace('EXPOSE 3000', 'EXPOSE 8080'), { port: 8080 })).toEqual([]);
    refused(env('3000'), /PORT/, { port: 8080 });
  });
});
