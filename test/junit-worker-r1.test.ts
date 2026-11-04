// E5 fix round 1: the worker's limits can only be lowered by a caller, and a file over the cap is refused from its size before any read.
import { mkdtempSync, rmSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';

const reads: number[] = [];
vi.mock('node:fs/promises', async (orig) => {
  const real = await orig<typeof import('node:fs/promises')>();
  return {
    ...real,
    open: async (...a: Parameters<typeof real.open>) => {
      const h = await real.open(...a);
      const read = h.read.bind(h);
      (h as unknown as { read: (...x: unknown[]) => unknown }).read = (...x: unknown[]) => { reads.push(1); return (read as (...y: unknown[]) => unknown)(...x); };
      return h;
    },
  };
});
const { JUNIT_RESOURCE_LIMITS, readJunitBytes, readJunitFile } = await import('../src/create/junit-worker.js');
const { MAX_JUNIT_BYTES } = await import('../src/create/junit.js');
const dir = mkdtempSync(join(tmpdir(), 'junit-r1-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('junit worker: fix round 1', () => {
  it('m8: a file over the cap is refused from its size: the file is never read', async () => {
    const p = join(dir, 'big.xml');
    writeFileSync(p, '');
    truncateSync(p, MAX_JUNIT_BYTES + 1);
    reads.length = 0;
    const r = await readJunitFile(p);
    expect(r.ok).toBe(false);
    expect(reads).toHaveLength(0);
  });
  it('m6: a caller can only lower the resource limits', async () => {
    const probe = join(dir, 'limits.mjs');
    writeFileSync(probe, `import { parentPort, resourceLimits } from 'node:worker_threads'; parentPort.postMessage({ ok: true, cases: [{ id: JSON.stringify(resourceLimits), status: 'pass' }] });`);
    const seen = async (rl: object) => { const r = await readJunitBytes(new Uint8Array(1), { workerUrl: pathToFileURL(probe), resourceLimits: rl }); if (!r.ok) throw new Error(r.reason); return JSON.parse(r.cases[0]?.id ?? '{}') as Record<string, number>; };
    const raised = await seen({ maxOldGenerationSizeMb: 99_999, maxYoungGenerationSizeMb: 99_999, codeRangeSizeMb: 99_999, stackSizeMb: 99_999 });
    for (const [k, v] of Object.entries(JUNIT_RESOURCE_LIMITS)) expect(raised[k], k).toBe(v);
    const lowered = await seen({ maxOldGenerationSizeMb: 64 });
    expect(lowered.maxOldGenerationSizeMb).toBe(64);
    expect(lowered.stackSizeMb).toBe(JUNIT_RESOURCE_LIMITS.stackSizeMb);
  });
});
