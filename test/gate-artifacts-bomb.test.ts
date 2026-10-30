// C5a fix round 1 (review I3a): the zip-bomb defence is the cap on what inflate may produce (maxOutputLength), not only the size check
// after it. A spy on node:zlib proves the cap really limits: inflate is never allowed more than the declared size + 1 or the file cap,
// so a lying header can not make the gate inflate gigabytes before it refuses.
import { deflateRawSync } from 'node:zlib';
import { describe, expect, it, vi } from 'vitest';

const seen: { maxOutputLength?: number }[] = [];
vi.mock('node:zlib', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:zlib')>();
  return { ...real, inflateRawSync: (buf: Uint8Array, opts?: { maxOutputLength?: number }) => { seen.push({ ...(opts ?? {}) }); return real.inflateRawSync(buf, opts); } };
});
const { MAX_RESULT_FILE_BYTES, readZipEntry } = await import('../gate/src/artifacts.js');
const { makeZip } = await import('./helpers/zip.js');

describe('zip bomb: inflate is capped at the declared size (+1) and the file cap', () => {
  it('a header that declares 100 bytes over 64 MiB of zeros: inflate may produce at most 101 bytes, and the refusal is the inflate error', () => {
    const raw = deflateRawSync(Buffer.alloc(64 * 1024 * 1024));
    seen.length = 0;
    const t0 = Date.now();
    const r = readZipEntry(makeZip({ entries: [{ name: 'a.sarif', data: '', rawData: raw, uncompressedSize: 100, crc: 0 }] }), {});
    expect(r.ok).toBe(false);
    expect(r.ok === false ? r.problem : '').toMatch(/does not inflate within its declared size/);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.maxOutputLength).toBe(101);
    expect(Date.now() - t0).toBeLessThan(2000);
  });
  it('an honest header is capped too: never more than the declared size + 1, never more than the file cap', () => {
    seen.length = 0;
    readZipEntry(makeZip({ entries: [{ name: 'a.sarif', data: 'x'.repeat(5000) }] }), {});
    readZipEntry(makeZip({ entries: [{ name: 'a.sarif', data: 'y'.repeat(5000) }] }), { maxBytes: 5000 });
    expect(seen.map((s) => s.maxOutputLength)).toEqual([5001, 5000]);
    for (const s of seen) expect(s.maxOutputLength).toBeLessThanOrEqual(MAX_RESULT_FILE_BYTES);
  });
});
