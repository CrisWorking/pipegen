// Plan C Task C5a: the result artifacts the gate reads (gate/src/artifacts.ts). Everything about an artifact is hostile: its listing
// (name, run, size), its zip (entries, names, modes, flags, sizes) and the bytes inside. One verifier, pure, over the listing and the
// downloaded bytes: any doubt is `tampered` (the gate blocks), never a guess. Written first (strict test-first).
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import {
  downloadResult, MAX_RESULT_FILE_BYTES, MAX_RESULT_ZIP_BYTES, pickArtifact, readZipEntry, type ResultIo,
} from '../gate/src/artifacts.js';
import { makeZip, zipOf } from './helpers/zip.js';

const RUN = 4242;
const NAME = 'pipegen-out-sast--app';
const art = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: 9, name: NAME, size_in_bytes: 300, expired: false, workflow_run: { id: RUN, head_sha: 'a'.repeat(40) }, ...over,
});
const listing = (...artifacts: unknown[]): unknown => ({ total_count: artifacts.length, artifacts });
const SARIF = '{"version":"2.1.0","runs":[]}';

describe('pickArtifact: the listing, before any download', () => {
  it('the one artifact of exactly the expected name and of this run is picked, with its id and size', () => {
    expect(pickArtifact(listing(art()), { name: NAME, runId: RUN })).toEqual({ ok: true, id: 9, size: 300 });
  });
  it('no artifact of that name: missing (not tampered); other names in the answer are never picked', () => {
    const r = pickArtifact(listing(art({ name: 'pipegen-out-sast' }), art({ name: `${NAME}-x` }), art({ name: NAME.toUpperCase() })), { name: NAME, runId: RUN });
    expect(r).toMatchObject({ ok: false, missing: true });
    expect(pickArtifact(listing(), { name: NAME, runId: RUN })).toMatchObject({ ok: false, missing: true });
  });
  it('artifact: two artifacts of one name, another run, expired, or no usable id or size: tampered', () => {
    const cases: [string, unknown][] = [
      ['two of one name', listing(art(), art({ id: 10 }))],
      ['another run', listing(art({ workflow_run: { id: RUN + 1 } }))],
      ['no run', listing(art({ workflow_run: null }))],
      ['run id as text', listing(art({ workflow_run: { id: String(RUN) } }))],
      ['expired', listing(art({ expired: true }))],
      ['expired not a boolean', listing(art({ expired: 'false' }))],
      ['no id', listing(art({ id: 0 }))],
      ['no size', listing(art({ size_in_bytes: undefined }))],
      ['negative size', listing(art({ size_in_bytes: -1 }))],
    ];
    for (const [why, l] of cases) {
      const r = pickArtifact(l, { name: NAME, runId: RUN });
      expect(r.ok, why).toBe(false);
      expect(r.ok === false && r.missing, why).toBe(false);
    }
  });
  it('artifact: size over cap from metadata → not downloaded (tampered before any download)', () => {
    const r = pickArtifact(listing(art({ size_in_bytes: MAX_RESULT_ZIP_BYTES + 1 })), { name: NAME, runId: RUN });
    expect(r).toMatchObject({ ok: false, missing: false });
    expect(r.ok === false ? r.problem : '').toMatch(/size cap/);
  });
  it('a listing that is not the API shape is tampered, never "missing" (a broken answer must not read as "the scanner did not run")', () => {
    for (const l of [null, 'x', [], { artifacts: 'x' }, { artifacts: [5] }, { total_count: 3, artifacts: [art()] }]) {
      const r = pickArtifact(l, { name: NAME, runId: RUN });
      expect(r.ok, JSON.stringify(l)).toBe(false);
    }
    // a listing entry that is not an object, beside the right one, is tampered too (the answer is not what the API gives)
    expect(pickArtifact(listing(art(), 'junk'), { name: NAME, runId: RUN }).ok).toBe(false);
  });
});

describe('readZipEntry: exactly one regular file of the expected name', () => {
  it('reads the zip upload-artifact v4 writes (deflate, data descriptor, Unix mode 100644), and a stored one', () => {
    const r = readZipEntry(zipOf('semgrep.sarif', SARIF), { expectedFile: 'semgrep.sarif' });
    expect(r).toEqual({ ok: true, name: 'semgrep.sarif', bytes: new Uint8Array(Buffer.from(SARIF)) });
    expect(readZipEntry(makeZip({ entries: [{ name: 'a.sarif', data: SARIF, method: 0 }] }), {}).ok).toBe(true);
    expect(readZipEntry(makeZip({ entries: [{ name: 'a.sarif', data: SARIF, madeByHost: 0, mode: 0 }] }), {}).ok).toBe(true);   // MS-DOS: no mode
    expect(readZipEntry(makeZip({ entries: [{ name: 'a.sarif', data: SARIF }], comment: 'made by a tool' }), {}).ok).toBe(true);
    expect(readZipEntry(makeZip({ entries: [{ name: 'a.sarif', data: '' }] }), {}).ok).toBe(true);
  });
  it('a real zip written by Python\'s zipfile (deflate, no data descriptor) reads', () => {
    // Python 3.12: import zipfile,io; b=io.BytesIO(); z=zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED)
    //   z.writestr(zipfile.ZipInfo('r.sarif',(2026,10,30,0,0,0)),'{"runs":[]}',compress_type=zipfile.ZIP_DEFLATED); z.close(); print(b.getvalue().hex())
    const hex = '504b030414000000080000005e5dae0029f40d0000000b00000007000000722e7361726966ab562a2acd2b56b28a8ead0500504b0102140314000000080000005e5dae0029f40d0000000b000000070000000000000000000000800100000000722e7361726966504b0506000000000100010035000000320000000000';
    const r = readZipEntry(new Uint8Array(Buffer.from(hex, 'hex')), { expectedFile: 'r.sarif' });
    expect(r.ok && Buffer.from(r.bytes).toString()).toBe('{"runs":[]}');
  });
  it('artifact: zip with two entries, a path entry or a symlink → tampered', () => {
    const bad: [string, Uint8Array][] = [
      ['two entries', makeZip({ entries: [{ name: 'a.sarif', data: SARIF }, { name: 'b.sarif', data: SARIF }] })],
      ['two entries, one name', makeZip({ entries: [{ name: 'a.sarif', data: SARIF }, { name: 'a.sarif', data: '{}' }] })],
      ['path entry', zipOf('dir/a.sarif', SARIF)],
      ['parent path', zipOf('../a.sarif', SARIF)],
      ['absolute path', zipOf('/tmp/a.sarif', SARIF)],
      ['backslash path', zipOf('dir\\a.sarif', SARIF)],
      ['dot name', zipOf('..', SARIF)],
      ['hidden name', zipOf('.a.sarif', SARIF)],
      ['NUL in the name', zipOf('a\0.sarif', SARIF)],
      ['symlink', makeZip({ entries: [{ name: 'a.sarif', data: '/etc/passwd', mode: 0o120777, method: 0 }] })],
      ['folder entry', makeZip({ entries: [{ name: 'a.sarif/', data: '', mode: 0o040755, method: 0 }] })],
      ['folder mode', makeZip({ entries: [{ name: 'a.sarif', data: '', mode: 0o040755, method: 0 }] })],
      ['fifo mode', makeZip({ entries: [{ name: 'a.sarif', data: '', mode: 0o010644, method: 0 }] })],
    ];
    for (const [why, z] of bad) expect(readZipEntry(z, {}).ok, why).toBe(false);
  });
  it('encryption, an unknown method, a wrong CRC, a size that lies, zip64 markers: tampered', () => {
    const bad: [string, Uint8Array][] = [
      ['encrypted', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, flags: 1 }] })],
      ['bzip2', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, method: 12 }] })],
      ['wrong crc', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, crc: 1 }] })],
      ['uncompressed size lies (small)', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, uncompressedSize: 3 }] })],
      ['uncompressed size lies (large)', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, uncompressedSize: SARIF.length + 9 }] })],
      ['compressed size past the end', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, compressedSize: 100_000 }] })],
      ['zip64 sizes', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, uncompressedSize: 0xffffffff, compressedSize: 0xffffffff }] })],
      ['stored with other sizes', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, method: 0, compressedSize: 3 }] })],
      ['local name differs', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, localName: 'b.sarif' }] })],
      ['bytes in front', makeZip({ entries: [{ name: 'a.sarif', data: SARIF }], prefix: new Uint8Array(64) })],
      ['bytes between data and directory', makeZip({ entries: [{ name: 'a.sarif', data: SARIF }], gap: new Uint8Array(40) })],
      ['end record counts lie', makeZip({ entries: [{ name: 'a.sarif', data: SARIF }], countOverride: 2 })],
      ['no entry at all', makeZip({ entries: [] })],
      ['not a zip', new Uint8Array(Buffer.from('PK nothing here'))],
      ['empty', new Uint8Array()],
      ['truncated', zipOf('a.sarif', SARIF).slice(0, 40)],
      ['broken deflate', makeZip({ entries: [{ name: 'a.sarif', data: SARIF, rawData: new Uint8Array([0xff, 0xff, 0xff, 0xff]) }] })],
    ];
    for (const [why, z] of bad) expect(readZipEntry(z, {}).ok, why).toBe(false);
  });
  it('a zip bomb is stopped: an entry whose real size is over the cap fails without inflating it all, whatever its header says', () => {
    const big = Buffer.alloc(MAX_RESULT_FILE_BYTES + 1024, 0x20);
    const raw = deflateRawSync(big);
    expect(raw.length).toBeLessThan(64 * 1024);   // a few KiB that inflate to over 16 MiB
    const honest = makeZip({ entries: [{ name: 'a.sarif', data: '', rawData: raw, uncompressedSize: big.length, crc: 0 }] });
    const lying = makeZip({ entries: [{ name: 'a.sarif', data: '', rawData: raw, uncompressedSize: 100, crc: 0 }] });
    for (const z of [honest, lying]) {
      const r = readZipEntry(z, {});
      expect(r.ok).toBe(false);
      expect(r.ok === false ? r.problem : '').toMatch(/size cap|size|bomb/i);
    }
    // the caller's own cap is lower still
    expect(readZipEntry(zipOf('a.sarif', 'x'.repeat(2000)), { maxBytes: 1000 }).ok).toBe(false);
  });
  it('the file name must be the expected one when the caller knows it', () => {
    expect(readZipEntry(zipOf('other.sarif', SARIF), { expectedFile: 'semgrep.sarif' }).ok).toBe(false);
    expect(readZipEntry(zipOf('SEMGREP.SARIF', SARIF), { expectedFile: 'semgrep.sarif' }).ok).toBe(false);
  });
  it('fuzz: no truncation or byte flip of a valid zip throws; every answer is ok or a problem', () => {
    const z = zipOf('a.sarif', SARIF);
    for (let n = 0; n < z.length; n++) expect(() => readZipEntry(z.slice(0, n), {})).not.toThrow();
    let seed = 7;
    for (let k = 0; k < 2000; k++) {
      seed = (seed * 1103515245 + 12345) >>> 0;
      const c = new Uint8Array(z);
      c[seed % c.length] = (seed >>> 8) & 0xff;
      const r = readZipEntry(c, {});
      if (r.ok) expect(r.name).toMatch(/^[A-Za-z0-9_][A-Za-z0-9._-]*$/);
    }
  });
});

describe('downloadResult: the listing, then the zip, then the file', () => {
  const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
  const io = (l: unknown, zip: Uint8Array | Error): ResultIo & { calls: string[] } => {
    const calls: string[] = [];
    return {
      calls,
      listRunArtifacts: async (_o, _n, runId, name) => { calls.push(`list ${runId} ${name}`); return l; },
      artifactZip: async (_o, _n, id, max) => { calls.push(`zip ${id} ${max}`); if (zip instanceof Error) throw zip; return zip; },
    };
  };
  const want = { owner: 'acme', repo: 'app', runId: RUN, name: NAME, format: 'sarif' as const };
  it('reads only the expected name of this run, and gives the sha256 of the file bytes and the file read back', async () => {
    const x = io(listing(art()), zipOf('semgrep.sarif', SARIF));
    const r = await downloadResult(x, want);
    expect(x.calls).toEqual([`list ${RUN} ${NAME}`, `zip 9 ${MAX_RESULT_ZIP_BYTES}`]);
    expect(r.kind).toBe('file');
    if (r.kind === 'file') {
      expect(r.file.sha256).toBe(sha(SARIF));
      expect(r.file.problem).toBeUndefined();
    }
  });
  it('missing: no artifact of that name (no download); over cap: tampered with no download; a zip problem: tampered', async () => {
    const none = io(listing(), zipOf('a', SARIF));
    expect(await downloadResult(none, want)).toEqual({ kind: 'missing' });
    expect(none.calls).toHaveLength(1);
    const big = io(listing(art({ size_in_bytes: MAX_RESULT_ZIP_BYTES + 1 })), zipOf('a', SARIF));
    const rb = await downloadResult(big, want);
    expect(rb.kind === 'file' && rb.file.problem).toMatch(/size cap/);
    expect(big.calls).toHaveLength(1);
    const two = io(listing(art()), makeZip({ entries: [{ name: 'a', data: SARIF }, { name: 'b', data: SARIF }] }));
    const rt = await downloadResult(two, want);
    expect(rt.kind === 'file' && rt.file.problem).toMatch(/entr/);
  });
  it('an API error on the listing or the download is tampered (it blocks), never missing', async () => {
    const e1: ResultIo = { listRunArtifacts: async () => { throw new Error('500'); }, artifactZip: async () => new Uint8Array() };
    const r1 = await downloadResult(e1, want);
    expect(r1.kind === 'file' && r1.file.problem).toBeTypeOf('string');
    const r2 = await downloadResult(io(listing(art()), new Error('403')), want);
    expect(r2.kind === 'file' && r2.file.problem).toBeTypeOf('string');
  });
  it('a file the scrub did not write reads back as a tool error inside a hash-checked file (decide calls it a tool error, or tampered on a hash mismatch)', async () => {
    const r = await downloadResult(io(listing(art()), zipOf('x.sarif', 'not json')), want);
    expect(r.kind === 'file' && r.file.read.toolError).toBeTypeOf('string');
  });
});
