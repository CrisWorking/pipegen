// LIVE (PIPEGEN_LIVE_TESTS=1, needs a running Docker with the compose plugin; no network, no containers started): D4. `docker compose config` must accept the
// file the creator writes and show only what pipegen put in it: the ports on 127.0.0.1, no privileged, no volumes. Skipped by default, and skipped with a
// note when Docker is not available or not running.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
    const p = profile([service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000, scripts: ['start'], dependsOn: (['postgres', 'mysql', 'redis', 'mongodb', 'rabbitmq'] as const).map(dep) })]);
    const { file } = createCompose(p, { repoPaths: new Set(['api/Dockerfile']), baseImages: loadBaseImages() });
    expect(file).not.toBeNull();
    writeFileSync(join(work, 'docker-compose.pipegen.yml'), file?.content ?? '');
    const r = spawnSync('docker', ['compose', '--env-file', '/dev/null', '-f', join(work, 'docker-compose.pipegen.yml'), 'config', '--format', 'json'], { encoding: 'utf8', timeout: 60_000, env: { ...process.env, [DBPW]: 'x'.repeat(32) } });
    expect(r.status, r.stderr).toBe(0);
    const cfg = JSON.parse(r.stdout) as { services: Record<string, { ports?: { host_ip?: string }[]; privileged?: boolean; volumes?: unknown[] }> };
    for (const s of Object.values(cfg.services)) {
      expect(s.privileged).toBeUndefined();
      expect(s.volumes ?? []).toEqual([]);
      for (const port of s.ports ?? []) expect(port.host_ip).toBe('127.0.0.1');
    }
  });
});
