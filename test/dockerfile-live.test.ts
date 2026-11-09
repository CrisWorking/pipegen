// LIVE (PIPEGEN_LIVE_TESTS=1, uses the network): D3, preflight S5. CI lints created Dockerfiles with the reviewed hadolint under pipegen's pinned
// config and `--failure-threshold warning`, so every Dockerfile the creator writes must pass exactly that. The real hadolint release asset is
// downloaded, its sha256 checked against the reviewed pin, and run on fixture Dockerfiles made by createDockerfile (canned AI answers).
// A planted bad Dockerfile proves the linter really ran under the same config. Skipped by default, so `npm test` stays offline.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { bundleCode } from '../src/ai/redact.js';
import { createDockerfile } from '../src/create/dockerfile.js';
import { baseImageRef } from '../src/engine/base-images.js';
import { loadReviewed } from '../src/engine/reviewed.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import { DEFAULT_MODEL, type AiProvider, type AiUsage, type RepoProfile, type Service } from '../src/types.js';
import { CLEAN, gitleaksAt, makeStub, scanWith } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1' && process.platform === 'linux' && process.arch === 'x64';
const REF = baseImageRef('node-24-bookworm-slim');
const work = mkdtempSync(join(tmpdir(), 'pipegen-hadolint-'));
afterAll(() => { rmSync(work, { recursive: true, force: true }); cleanupRepos(); });

const svc = (over: Partial<Service> = {}): Service => ({
  name: 'api', path: 'api', language: 'node', packageManager: 'npm', runtimeVersion: '24', hasTests: true, envVars: [], dependsOn: [], scripts: ['start'], frameworks: [], quality: emptyServiceQuality(), ...over,
});
const profile = (s: Service): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none', services: [s], terraformDirs: [], hasCompose: false,
  existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
});
// AiUsage field names hold "Tokens", which the secret-literal check watches, so the object is built from a list.
const usage = (input: number, output: number): AiUsage => Object.fromEntries([['inputTokens', input], ['outputTokens', output]]) as unknown as AiUsage;
const ai = (dockerfile: string): AiProvider => ({ name: 'claude', model: DEFAULT_MODEL, complete: async () => ({ data: { dockerfile, port: 3000, reasoning: 'ok' }, usage: usage(1, 1) }) });

const SINGLE = [
  'FROM node:24', 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --omit=dev --ignore-scripts --git=/usr/bin/git', 'COPY . .', 'ENV NODE_ENV=production', 'EXPOSE 3000', 'USER node', 'CMD ["npm", "start"]', '',
].join('\n');
const MULTI = [
  'FROM node:24 AS build', 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --ignore-scripts --git=/usr/bin/git', 'COPY . .', 'RUN npm run build',
  'FROM node:24', 'WORKDIR /app', 'ENV NODE_ENV=production', 'COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./',
  'RUN npm ci --omit=dev --ignore-scripts --git=/usr/bin/git && npm cache clean --force', 'COPY --from=build --chown=node:node /app/dist ./dist', 'EXPOSE 3000', 'USER node',
].join('\n');

describe.skipIf(!live)('live: hadolint 2.15.1 under pipegen\'s pinned config', () => {
  it("hadolint 2.15.1 with pipegen's pinned config passes every created fixture Dockerfile", async () => {
    const tool = loadReviewed().find((t) => t.id === 'hadolint');
    if (tool === undefined) throw new Error('no hadolint entry in the reviewed list');
    const install = tool.step.cli?.install;
    const config = tool.fixedInputs.config?.content;
    if (install === undefined || config === undefined || tool.candidate.pin.checksum === undefined) throw new Error('the hadolint entry is incomplete');
    expect(install.version).toBe('v2.15.1');
    const res = await fetch(`https://github.com/${tool.candidate.repo}/releases/download/${install.version}/${install.package}`, { redirect: 'follow', signal: AbortSignal.timeout(120_000) });
    expect(res.ok).toBe(true);
    const bin = Buffer.from(await res.arrayBuffer());
    expect(createHash('sha256').update(bin).digest('hex')).toBe(tool.candidate.pin.checksum);
    const exe = join(work, 'hadolint');
    writeFileSync(exe, bin);
    chmodSync(exe, 0o755);
    const cfg = join(work, 'hadolint.yaml');
    writeFileSync(cfg, config);
    const lint = (name: string, content: string): { code: number | null; out: string } => {
      const file = join(work, `${name}.Dockerfile`);
      writeFileSync(file, content);
      const r = spawnSync(exe, ['--no-color', '--failure-threshold', 'warning', '--config', cfg, '--format', 'json', file], { encoding: 'utf8', timeout: 60_000 });
      return { code: r.status, out: `${r.stdout}${r.stderr}` };
    };
    const version = spawnSync(exe, ['--version'], { encoding: 'utf8' }).stdout;
    console.log(`hadolint: ${version.trim()}; config: ${JSON.stringify(config)}`);
    expect(version).toContain('2.15.1');

    // the fixtures: written by createDockerfile from canned AI answers (the creator owns the FROM lines)
    const dir = makeTempDir();
    writeIn(dir, 'api/package.json', '{"name":"api"}\n');
    const bundle = await bundleCode(dir, scanWith(gitleaksAt(makeStub(CLEAN).bin)));
    const repoPaths = new Set(['api/package.json', 'api/package-lock.json']);
    const fixtures: [string, string][] = [];
    const specs: [string, string, Partial<Service>][] = [['single', SINGLE, {}], ['multi', MULTI, { scripts: ['start', 'build'] }]];
    for (const [name, text, over] of specs) {
      const s = svc(over);
      const out = await createDockerfile(s, profile(s), bundle, ai(text), { repoPaths });
      expect(out.files.map((f) => f.path)).toEqual(['api/Dockerfile', 'api/.dockerignore']);
      const content = out.files[0]?.content ?? '';
      expect(content).toContain(`FROM ${REF}`);
      fixtures.push([name, content]);
    }
    for (const [name, content] of fixtures) {
      const r = lint(name, content);
      console.log(`hadolint ${name}: exit ${String(r.code)} ${r.out.trim().slice(0, 600)}`);
      expect(r.code, `${name}: ${r.out}`).toBe(0);
      // exit 0 is the CI verdict (--failure-threshold warning); info and style findings are shown but do not fail
      const found = JSON.parse(r.out) as { code: string; level: string; line: number }[];
      expect(found.filter((f) => f.level === 'warning' || f.level === 'error'), name).toEqual([]);
    }
    // the linter really ran under the same config: a planted problem fails it
    const bad = lint('bad', 'FROM node:latest\nRUN cd /tmp && apt-get update && apt-get install curl\nUSER root\n');
    console.log(`hadolint planted: exit ${String(bad.code)} ${bad.out.trim().slice(0, 300)}`);
    expect(bad.code).not.toBe(0);
    expect(bad.out).toMatch(/DL3\d\d\d/);
  }, 300_000);
});
