// LIVE (PIPEGEN_LIVE_TESTS=1, needs a running Docker with the compose plugin; no network, no containers started): D4. `docker compose config` must accept the
// file the creator writes and show only what pipegen put in it: the ports on 127.0.0.1, no privileged, no volumes. Skipped by default, and skipped with a
// note when Docker is not available or not running.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { createCompose } from '../src/create/compose.js';
import { loadBaseImages } from '../src/engine/base-images.js';
import { DBPW } from './helpers/dbpw.js';
import { profile, service } from './helpers/render.js';

const wanted = process.env.PIPEGEN_LIVE_TESTS === '1';
const dockerUp = (): boolean => {
  const r = spawnSync('docker', ['compose', 'version'], { encoding: 'utf8', timeout: 20_000 });
  return r.error === undefined && r.status === 0;
};
const work = mkdtempSync(join(tmpdir(), 'pipegen-compose-'));
afterAll(() => rmSync(work, { recursive: true, force: true }));

describe('compose (live)', () => {
  it.skipIf(!wanted)('docker compose config accepts every kind and shows no privilege, volume or foreign port', () => {
    if (!dockerUp()) { console.warn('compose live check skipped: docker compose is not available here'); return; }
    const dep = (kind: 'postgres' | 'mysql' | 'redis' | 'mongodb' | 'rabbitmq') => ({ kind, name: kind, evidence: 'x', envVars: [] });
    const p = profile([
      service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000, scripts: ['start'], dependsOn: (['postgres', 'mysql', 'redis', 'mongodb', 'rabbitmq'] as const).map(dep) }),
      service({ name: 'gh', path: 'github.com/acme/api', dockerfile: 'github.com/acme/api/Dockerfile', port: 3001, scripts: ['start'], dependsOn: [dep('postgres')] }),
    ]);
    const { file } = createCompose(p, { repoPaths: new Set(['api/Dockerfile', 'github.com/acme/api/Dockerfile']), baseImages: loadBaseImages() });
    expect(file).not.toBeNull();
    writeFileSync(join(work, 'docker-compose.pipegen.yml'), file?.content ?? '');
    const r = spawnSync('docker', ['compose', '--env-file', '/dev/null', '-f', join(work, 'docker-compose.pipegen.yml'), 'config', '--format', 'json'], { encoding: 'utf8', timeout: 60_000, env: { ...process.env, [DBPW]: 'x'.repeat(32) } });
    expect(r.status, r.stderr).toBe(0);
    // both ./api and ./github.com/acme/api must resolve to local folders, never a remote Git context
    for (const ctxDir of ['api', 'github.com/acme/api']) expect(r.stdout).toContain(JSON.stringify(join(work, ctxDir)).slice(1, -1));
    const cfg = JSON.parse(r.stdout) as { services: Record<string, { ports?: { host_ip?: string }[]; privileged?: boolean; volumes?: unknown[]; cap_drop?: string[]; security_opt?: string[] }> };
    for (const [key, s] of Object.entries(cfg.services)) {
      expect(s.privileged).toBeUndefined();
      expect(s.volumes ?? []).toEqual([]);
      for (const port of s.ports ?? []) expect(port.host_ip).toBe('127.0.0.1');
      // G17 row 13: docker reads the app containers' hardening as written (every capability dropped, no privilege gain)
      if (key.startsWith('app-')) { expect(s.cap_drop, key).toEqual(['ALL']); expect(s.security_opt, key).toEqual(['no-new-privileges:true']); }
    }
    expect(Object.keys(cfg.services).filter((k) => k.startsWith('app-')).length).toBe(2);
  });

  // G17B-R1 sec M2: the dependency containers gain no privilege and still start (their entrypoints switch users with gosu/setpriv, no setuid);
  // pulls the pinned postgres and redis images, starts them healthy, reads NoNewPrivs of their first process, then removes them
  it.skipIf(!wanted)('the dependency containers start healthy with no-new-privileges (NoNewPrivs 1)', () => {
    if (!dockerUp()) { console.warn('compose live start skipped: docker compose is not available here'); return; }
    const dep = (kind: 'postgres' | 'redis') => ({ kind, name: kind, evidence: 'x', envVars: [] });
    const p = profile([service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000, scripts: ['start'], dependsOn: [dep('postgres'), dep('redis')] })]);
    const { file } = createCompose(p, { repoPaths: new Set(['api/Dockerfile']), baseImages: loadBaseImages() });
    const dir = join(work, 'start');
    mkdirSync(dir, { recursive: true });
    const f = join(dir, 'docker-compose.pipegen.yml');
    writeFileSync(f, file?.content ?? '');
    // the test's own override drops the published ports only (a developer machine may already use 5432 or 6379); the hardening keys stay
    const o = join(dir, 'ports-off.yml');
    writeFileSync(o, 'services:\n  postgres:\n    ports: !reset []\n  redis:\n    ports: !reset []\n');
    const env = { ...process.env, [DBPW]: 'x'.repeat(32) };
    const dc = (args: string[], timeout = 300_000) => spawnSync('docker', ['compose', '--env-file', '/dev/null', '-p', 'pipegen-g17b-live', '-f', f, '-f', o, ...args], { encoding: 'utf8', timeout, env });
    try {
      const up = dc(['up', '-d', '--wait', 'postgres', 'redis']);
      expect(up.status, up.stderr).toBe(0);
      for (const svc of ['postgres', 'redis']) {
        const r = dc(['exec', '-T', svc, 'grep', 'NoNewPrivs', '/proc/1/status'], 60_000);
        expect(r.stdout, `${svc}: ${r.stderr}`).toMatch(/NoNewPrivs:\s+1/);
      }
    } finally { dc(['down', '-v'], 120_000); }
  }, 600_000);
});
