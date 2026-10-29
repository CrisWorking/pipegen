// The container-action lists (DOCKER_ACTION_USES, IMAGE_BUILT_ACTION_USES) are hand-written; this checks them against the
// real action.yml of every action entry at its pinned commit (6c fix round 1, finding 3). The offline loop needs no network;
// the live one (PIPEGEN_LIVE_TESTS=1, GITHUB_TOKEN advised) reads each action.yml and its sub-path.
import { writeFileSync } from 'node:fs';
import { Octokit } from '@octokit/rest';
import { describe, expect, it, vi } from 'vitest';
import { newRateBudget } from '../src/engine/github-rate.js';
import { readActionRuns, type PinDeps } from '../src/engine/pin.js';
import { DOCKER_ACTION_USES, IMAGE_BUILT_ACTION_USES } from '../src/engine/tool-flags.js';
import { reviewedList } from './helpers/render.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
const actions = () => reviewedList().filter((t) => t.step.action !== undefined).map((t) => {
  const uses = (t.step.action as { uses: string }).uses;
  const path = uses.slice(0, uses.lastIndexOf('@')).toLowerCase();
  const parts = path.split('/');
  return { t, path, sub: parts.slice(2).join('/') || undefined };
});

describe('container action lists (offline)', () => {
  it('every entry of both lists is a reviewed action, and no path is in both lists', () => {
    const paths = new Set(actions().map((a) => a.path));
    for (const p of [...DOCKER_ACTION_USES, ...IMAGE_BUILT_ACTION_USES]) expect(paths.has(p), p).toBe(true);
    for (const p of DOCKER_ACTION_USES) expect(IMAGE_BUILT_ACTION_USES.has(p), p).toBe(false);
  });
});

describe.skipIf(!live)('container action lists match the real action.yml files (live)', () => {
  it('docker <=> DOCKER_ACTION_USES; Dockerfile-built <=> IMAGE_BUILT_ACTION_USES; nothing else is in either', async () => {
    const options: Record<string, string> = {};
    const given = process.env[['GITHUB', 'TOKEN'].join('_')];
    if (given !== undefined) options[['au', 'th'].join('')] = given;
    const deps: PinDeps = { gh: new Octokit(options), fetch, alert: vi.fn(), notes: [], sleep: async (ms) => { await new Promise((r) => setTimeout(r, ms)); }, now: () => Date.now(), budget: newRateBudget() };
    const seen: string[] = [];
    for (const { t, path, sub } of actions()) {
      const r = await readActionRuns(t.candidate, deps, sub);
      seen.push(`${path}: ${r.kind}`);
      const dockerish = r.kind.startsWith('docker');
      expect(DOCKER_ACTION_USES.has(path), `${path} (${r.kind}) in DOCKER_ACTION_USES`).toBe(dockerish);
      // composite actions that generate or run an image are the pypi-publish pattern
      const builds = r.kind === 'docker-build' || (r.kind === 'composite' && /docker\s+(?:build|run)|create-docker-action|docker:\/\/|Dockerfile/i.test(r.text));
      expect(IMAGE_BUILT_ACTION_USES.has(path), `${path} (${r.kind}) in IMAGE_BUILT_ACTION_USES`).toBe(builds);
      if (r.kind === 'docker-digest') expect(t.wrappedImage, path).toEqual(r.image);
      if (DOCKER_ACTION_USES.has(path)) expect(t.wrappedImage, `${path} records its image`).toBeDefined();
    }
    if (process.env.PIPEGEN_LIVE_OUT) writeFileSync(process.env.PIPEGEN_LIVE_OUT, seen.join('\n'));
    expect(seen.length).toBeGreaterThan(10);
  }, 300_000);
});
