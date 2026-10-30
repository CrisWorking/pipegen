// A small ZIP writer for the gate's artifact tests (C5a). It writes the layout actions/upload-artifact v4 produces (archiver / zip-stream:
// deflate, a data descriptor with its signature, "made by" Unix with the file mode in the external attributes), and every hostile variant
// the verifier must refuse: two entries, a path entry, a link, a folder, encryption, a wrong CRC, a size that lies, a zip64 marker,
// bytes in front, a name that differs between the local and the central header. Test-only: the gate never writes a zip.
import { crc32, deflateRawSync } from 'node:zlib';

export interface ZipEntrySpec {
  name: string;
  data: Uint8Array | string;
  method?: 0 | 8 | 12;
  /** Unix mode (S_IFREG 0o100644 by default); written in the high 16 bits of the external attributes when madeBy is Unix. */
  mode?: number;
  /** 3 = Unix (default), 0 = MS-DOS (no mode). */
  madeByHost?: number;
  /** General purpose flags; bit 3 (data descriptor) is set by default for deflate, bit 0 = encrypted. */
  flags?: number;
  descriptor?: boolean;
  /** Overrides, to lie in the headers. */
  crc?: number;
  uncompressedSize?: number;
  compressedSize?: number;
  localName?: string;
  /** Raw compressed bytes to write instead of the real ones. */
  rawData?: Uint8Array;
  extra?: Uint8Array;
}
export interface ZipSpec {
  entries: ZipEntrySpec[];
  prefix?: Uint8Array;
  comment?: string;
  /** Lie in the end record's entry counts. */
  countOverride?: number;
  /** Bytes between the last entry's data and the central directory. */
  gap?: Uint8Array;
}

const u16 = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16LE(n & 0xffff); return b; };
const u32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };

export function makeZip(spec: ZipSpec): Uint8Array {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  const push = (b: Buffer): void => { parts.push(b); offset += b.length; };
  if (spec.prefix !== undefined) push(Buffer.from(spec.prefix));
  for (const e of spec.entries) {
    const data = typeof e.data === 'string' ? Buffer.from(e.data, 'utf8') : Buffer.from(e.data);
    const method = e.method ?? 8;
    const body = e.rawData !== undefined ? Buffer.from(e.rawData) : method === 8 ? deflateRawSync(data) : data;
    const descriptor = e.descriptor ?? method === 8;
    const flags = (e.flags ?? 0) | (descriptor ? 0x08 : 0) | 0x800;   // bit 11: UTF-8 names (zip-stream sets it)
    const crc = e.crc ?? crc32(data);
    const csize = e.compressedSize ?? body.length;
    const usize = e.uncompressedSize ?? data.length;
    const name = Buffer.from(e.name, 'utf8');
    const lname = Buffer.from(e.localName ?? e.name, 'utf8');
    const extra = Buffer.from(e.extra ?? new Uint8Array());
    const localAt = offset;
    push(Buffer.concat([
      u32(0x04034b50), u16(20), u16(flags), u16(method), u16(0), u16(0x21),
      u32(descriptor ? 0 : crc), u32(descriptor ? 0 : csize), u32(descriptor ? 0 : usize), u16(lname.length), u16(extra.length), lname, extra,
    ]));
    push(body);
    if (descriptor) push(Buffer.concat([u32(0x08074b50), u32(crc), u32(csize), u32(usize)]));
    const host = e.madeByHost ?? 3;
    const mode = e.mode ?? 0o100644;
    const external = host === 3 ? ((mode & 0xffff) << 16) >>> 0 : 0;
    central.push(Buffer.concat([
      u32(0x02014b50), u16((host << 8) | 20), u16(20), u16(flags), u16(method), u16(0), u16(0x21),
      u32(crc), u32(csize), u32(usize), u16(name.length), u16(extra.length), u16(0), u16(0), u16(0), u32(external), u32(localAt), name, extra,
    ]));
  }
  if (spec.gap !== undefined) push(Buffer.from(spec.gap));
  const cdAt = offset;
  const cd = Buffer.concat(central);
  push(cd);
  const comment = Buffer.from(spec.comment ?? '', 'utf8');
  const n = spec.countOverride ?? spec.entries.length;
  push(Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(n), u16(n), u32(cd.length), u32(cdAt), u16(comment.length), comment]));
  return new Uint8Array(Buffer.concat(parts));
}

/** One regular file, the way upload-artifact v4 writes it. */
export const zipOf = (name: string, data: Uint8Array | string): Uint8Array => makeZip({ entries: [{ name, data }] });
