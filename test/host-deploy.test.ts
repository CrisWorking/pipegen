// Plan P PL-B2: a host that deploys a site from Git (Cloudflare Pages, Netlify, Vercel) is reported, once, when no
// workflow in the repo deploys: one warning and one Consider line. Invented repos; two shapes per host.
import { symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { buildAudit } from '../src/audit/model.js';
import { renderMarkdown, renderTerminal } from '../src/audit/render.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { hostDeployOf } from '../src/read/host-deploy.js';
import type { Capabilities } from '../src/types.js';
import { cleanupRepos, makeRepo, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

const root = { path: '.' };

describe('hostDeployOf', () => {
  it('Cloudflare Pages, two shapes: wrangler.toml and wrangler.jsonc with pages_build_output_dir', async () => {
    const a = makeTempDir();
    writeIn(a, 'wrangler.toml', 'name = "site"\npages_build_output_dir = "./dist"\n');
    expect(await hostDeployOf(a, root)).toEqual({ host: 'Cloudflare Pages', file: 'wrangler.toml' });
    const b = makeTempDir();
    writeIn(b, 'web/wrangler.jsonc', '{\n  // pages\n  "name": "site", "pages_build_output_dir": "dist"\n}\n');
    expect(await hostDeployOf(b, { path: 'web' })).toEqual({ host: 'Cloudflare Pages', file: 'web/wrangler.jsonc' });
  });
  it('a Worker wrangler config (main, no pages_build_output_dir) → null', async () => {
    const a = makeTempDir();
    writeIn(a, 'wrangler.toml', 'name = "api"\nmain = "src/index.ts"\n');
    writeIn(a, 'wrangler.json', '{ "name": "api", "main": "src/index.ts" }');
    expect(await hostDeployOf(a, root)).toBeNull();
  });
  it('Netlify, two shapes: a [build] netlify.toml at the root; a redirects-only one in a service folder', async () => {
    const a = makeTempDir();
    writeIn(a, 'netlify.toml', '[build]\n  publish = "dist"\n');
    expect(await hostDeployOf(a, root)).toEqual({ host: 'Netlify', file: 'netlify.toml' });
    const b = makeTempDir();
    writeIn(b, 'apps/site/netlify.toml', '[[redirects]]\n  from = "/*"\n  to = "/index.html"\n  status = 200\n');
    expect(await hostDeployOf(b, { path: 'apps/site' })).toEqual({ host: 'Netlify', file: 'apps/site/netlify.toml' });
  });
  it('Vercel, two shapes: an empty vercel.json; one with rewrites and headers', async () => {
    const a = makeTempDir();
    writeIn(a, 'vercel.json', '{}\n');
    expect(await hostDeployOf(a, root)).toEqual({ host: 'Vercel', file: 'vercel.json' });
    const b = makeTempDir();
    writeIn(b, 'vercel.json', '{ "rewrites": [{ "source": "/(.*)", "destination": "/" }], "headers": [] }\n');
    expect(await hostDeployOf(b, root)).toEqual({ host: 'Vercel', file: 'vercel.json' });
  });
  it('symlinked wrangler.toml → ignored', async () => {
    const a = makeTempDir();
    writeIn(a, 'elsewhere/w.toml', 'pages_build_output_dir = "dist"\n');
    symlinkSync(join(a, 'elsewhere/w.toml'), join(a, 'wrangler.toml'));
    expect(await hostDeployOf(a, root)).toBeNull();
  });
  it('no host config → null', async () => {
    expect(await hostDeployOf(makeTempDir(), root)).toBeNull();
  });
});

const NOW = Date.parse('2026-10-27T12:00:00Z');
const bare: Capabilities = {
  branchProtection: false, environments: true, envRequiredReviewers: false, deploymentBranchPolicies: false,
  attestations: false, codeScanning: false, keylessSigningAllowed: false,
};
const denied = () => Object.assign(new Error('not allowed'), { status: 403, response: { status: 403, data: {}, headers: {} } });
const gh = {
  rest: {
    activity: { listRepoEvents: async () => ({ data: [], headers: {} }) }, pulls: { list: async () => ({ data: [] }) },
    codeScanning: { getDefaultSetup: async () => { throw denied(); } },
    actions: {
      listRepoWorkflows: async () => ({ data: { total_count: 0, workflows: [] } }),
      listWorkflowRuns: async () => ({ data: { total_count: 0, workflow_runs: [] } }),
      listJobsForWorkflowRun: async () => ({ data: { total_count: 0, jobs: [] } }),
    },
  },
} as unknown as Parameters<typeof buildAudit>[1]['gh'];
const auditOf = (dir: string) => buildAudit(dir, {
  gh, anonymous: false, context: { private: false, ownerType: 'User', plan: 'free', defaultBranch: 'main' }, capabilities: bare,
  permissions: [], reviewed: [], now: () => NOW, budget: newRateBudget(),
});
// the short report lists the line as a Note under part 5 (Deploy)
const consider = (t: string) => t.slice(t.indexOf('5 Deploy'));

describe('PL-B2 in the audit', () => {
  it('netlify.toml, no deploy workflow → part 5 line', async () => {
    const dir = makeRepo('static-vite-spa', 'https://github.com/o/r.git');
    writeIn(dir, 'netlify.toml', '[build]\n  publish = "dist"\n');
    const r = await auditOf(dir);
    expect(r.warnings.map((w) => w.text)).toContain("Netlify deploys this site from Git (netlify.toml); no workflow in the repo deploys it, so pipegen can't check a deploy before it happens.");
    const t = renderTerminal(r, { knownValues: [], now: () => NOW });
    expect(t).toContain('⚠ Netlify deploys this site from Git (netlify.toml)');
    expect(consider(t)).toContain('Netlify deploy (netlify.toml): deploy from a workflow');
  });
  it('the Consider line also shows in the verbose terminal report and in markdown (Fold R1)', async () => {
    const dir = makeRepo('static-vite-spa', 'https://github.com/o/r.git');
    writeIn(dir, 'netlify.toml', '[build]\n  publish = "dist"\n');
    const r = await auditOf(dir);
    const line = 'Netlify deploy (netlify.toml): deploy from a workflow';
    expect(r.notes.some((n) => n.startsWith(line))).toBe(true);
    expect(renderTerminal(r, { knownValues: [], now: () => NOW, verbose: true })).toContain(line);
    expect(renderMarkdown(r, { knownValues: [], now: () => NOW })).toContain(line);
    // short view: shown once, not twice
    const t = renderTerminal(r, { knownValues: [], now: () => NOW });
    expect(t.split(line).length - 1).toBe(1);
  });
  it('vercel.json with a deploy workflow → no line', async () => {
    const dir = makeRepo('static-astro', 'https://github.com/o/r.git');
    writeIn(dir, 'vercel.json', '{}\n');
    const r = await auditOf(dir);
    expect(r.profile.existingWorkflows.some((w) => w.deploys)).toBe(true);
    expect(r.warnings.some((w) => w.text.includes('Vercel'))).toBe(false);
    expect(renderTerminal(r, { knownValues: [], now: () => NOW })).not.toContain('Vercel');
  });
  it('symlinked wrangler.toml in a repo → no line', async () => {
    const dir = makeRepo('static-vite-spa', 'https://github.com/o/r.git');
    writeIn(dir, 'cfg/w.toml', 'pages_build_output_dir = "dist"\n');
    symlinkSync(join(dir, 'cfg/w.toml'), join(dir, 'wrangler.toml'));
    const r = await auditOf(dir);
    expect(renderTerminal(r, { knownValues: [], now: () => NOW })).not.toContain('Cloudflare');
  });
});
