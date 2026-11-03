import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EGRESS_DOMAIN_SETS, renderEgressCheckStep, renderEgressStep, type EgressSet } from '../src/engine/egress.js';
import { RenderError } from '../src/engine/render-error.js';
import { loadReviewed } from '../src/engine/reviewed.js';

const bullfrog = () => loadReviewed().find((t) => t.id === 'bullfrog')!;
const lines = (s: ReturnType<typeof renderEgressStep>) => (s.with?.['allowed-domains'] ?? '').split('\n');
const HOST_RE = /^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$/;

describe('egress', () => {
  it('sets github-core, npm, pypi, dockerhub (with production.cloudfront.docker.com and the R2 host), ghcr', () => {
    expect(Object.keys(EGRESS_DOMAIN_SETS).sort()).toEqual(['dockerhub', 'ghcr', 'github-core', 'npm', 'pypi']);
    // the set names equal the reviewed choices
    expect(Object.keys(EGRESS_DOMAIN_SETS).sort()).toEqual([...bullfrog().choices['allowed-domains']!].sort());
    const s = EGRESS_DOMAIN_SETS;
    expect(s['github-core']).toEqual(expect.arrayContaining(['github.com', 'api.github.com', 'codeload.github.com', 'objects.githubusercontent.com']));
    expect(s.npm).toEqual(['registry.npmjs.org']);
    expect([...s.pypi].sort()).toEqual(['files.pythonhosted.org', 'pypi.org']);
    expect(s.dockerhub).toEqual(expect.arrayContaining(['registry-1.docker.io', 'auth.docker.io', 'production.cloudfront.docker.com',
      'docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com']));
    expect([...s.ghcr].sort()).toEqual(['ghcr.io', 'pkg-containers.githubusercontent.com']);
    for (const hosts of Object.values(s)) for (const h of hosts) expect(h, h).toMatch(HOST_RE);
    for (const h of Object.values(s).flat()) expect(h).toBe(h.toLowerCase());
    expect(Object.isFrozen(s)).toBe(true);
    for (const hosts of Object.values(s)) expect(Object.isFrozen(hosts)).toBe(true);
  });

  it('renderEgressStep renders the union one per line, sorted, deduped, bullfrog pin and fixed inputs', () => {
    const t = bullfrog();
    const step = renderEgressStep(['pypi', 'npm', 'npm', 'github-core'], { dockerNetworks: false });
    expect(step.uses).toBe(t.step.action!.uses);
    expect(step.usesComment).toBe(t.candidate.version);
    expect(step.with).toMatchObject(t.fixedInputs.with!);
    const hosts = lines(step);
    expect(hosts).toEqual([...new Set(hosts)].sort());
    expect(hosts).toEqual([...new Set([...EGRESS_DOMAIN_SETS['github-core'], ...EGRESS_DOMAIN_SETS.npm, ...EGRESS_DOMAIN_SETS.pypi])].sort());
    expect(step.with!['allowed-domains']).not.toMatch(/\n$/);
    expect(hosts).not.toContain('npm');
  });

  it('github-core is always included, and an empty list renders github-core only', () => {
    expect(lines(renderEgressStep([], { dockerNetworks: false }))).toEqual([...EGRESS_DOMAIN_SETS['github-core']].sort());
    expect(lines(renderEgressStep(['ghcr'], { dockerNetworks: false }))).toEqual(expect.arrayContaining(['github.com', 'ghcr.io']));
  });

  it('egress: allowed-ips 172.16.0.0/12 only with services or docker networks', () => {
    expect(renderEgressStep(['npm'], { dockerNetworks: true }).with!['allowed-ips']).toBe('172.16.0.0/12');
    const off = renderEgressStep(['npm'], { dockerNetworks: false });
    expect(Object.hasOwn(off.with!, 'allowed-ips')).toBe(false);
  });

  it('egress: an unknown set or a raw domain → RenderError', () => {
    for (const bad of ['docker', 'example.com', 'github.com', '*.npmjs.org', '', 'toString', '__proto__', 'constructor']) {
      expect(() => renderEgressStep([bad as EgressSet], { dockerNetworks: false }), bad).toThrow(RenderError);
    }
    expect(() => renderEgressStep([{} as unknown as EgressSet], { dockerNetworks: false })).toThrow(RenderError);
    expect(() => renderEgressStep('npm' as unknown as EgressSet[], { dockerNetworks: false })).toThrow(RenderError);
    for (const bad of ['true', 1, undefined, null, 0]) {
      expect(() => renderEgressStep(['npm'], { dockerNetworks: bad as unknown as boolean }), String(bad)).toThrow(RenderError);
    }
    expect(() => renderEgressStep(['npm'], undefined as never)).toThrow(RenderError);
  });

  it('renderEgressStep does not mutate the table and has no expression opener', () => {
    const before = JSON.stringify(EGRESS_DOMAIN_SETS);
    const step = renderEgressStep(['dockerhub', 'ghcr'], { dockerNetworks: true });
    expect(JSON.stringify(EGRESS_DOMAIN_SETS)).toBe(before);
    expect(JSON.stringify(step)).not.toContain('${{');
  });
});

describe('egress-check step', () => {
  const step = renderEgressCheckStep();
  const run = (curl: string | null) => {
    const dir = mkdtempSync(join(tmpdir(), 'egress-'));
    if (curl !== null) { writeFileSync(join(dir, 'curl'), curl); chmodSync(join(dir, 'curl'), 0o755); }
    // only bash builtins + the fake curl on PATH: no real curl, no network
    symlinkSync(spawnSync('which', ['bash']).stdout.toString().trim(), join(dir, 'bash'));
    return spawnSync(join(dir, 'bash'), ['-e', '-c', step.run!], { env: { PATH: dir }, encoding: 'utf8' });
  };

  it('is a fixed run step: curl --max-time 10 to https://example.com', () => {
    expect(step.run).toContain('curl');
    expect(step.run).toContain('--max-time 10');
    expect(step.run).toContain('https://example.com');
    expect(step.run).toContain('::error::');
    expect(step.uses).toBeUndefined();
    expect(step.shell).toBe('bash');
    expect(renderEgressCheckStep()).toEqual(step);
  });
  it('passes when curl fails (egress blocked)', () => {
    expect(run('#!/bin/bash\nexit 28\n').status).toBe(0);
  });
  it('fails the job when curl succeeds, with an ::error:: line', () => {
    const r = run('#!/bin/bash\nexit 0\n');
    expect(r.status).not.toBe(0);
    expect(r.stdout + r.stderr).toMatch(/::error::/);
  });
  it('fails when curl is missing (no silent pass)', () => {
    const r = run(null);
    expect(r.status).not.toBe(0);
    expect(r.stdout + r.stderr).toMatch(/::error::/);
  });
});
