// A hand-written ustar writer for tests: builds release archives at test runtime (gzip via node:zlib), including
// the hostile ones (links, devices, `..`, absolute paths, pax headers, bad header checksums) a real tar won't make.
import { gzipSync } from 'node:zlib';

export interface TarEntry {
  name: string;
  /** ustar typeflag: '0' file (default), '1' hardlink, '2' symlink, '3' char device, '4' block device, '5' dir, 'x' pax header. */
  type?: string;
  content?: string | Uint8Array;
  linkname?: string;
  /** ustar prefix field (joined to name with '/'). */
  prefix?: string;
  /** Overrides the size written in the header (the data written stays `content`). */
  size?: number;
  /** Corrupts the header checksum. */
  badChecksum?: boolean;
  /** Overrides the magic field (6 bytes) and version (2 bytes). */
  magic?: string;
}

function field(block: Buffer, offset: number, length: number, value: string): void {
  block.write(value.slice(0, length), offset, length, 'latin1');
}

const octal = (n: number, width: number) => n.toString(8).padStart(width - 1, '0') + '\0';

export function makeTar(entries: TarEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    const data = typeof e.content === 'string' ? Buffer.from(e.content) : Buffer.from(e.content ?? new Uint8Array());
    const h = Buffer.alloc(512);
    field(h, 0, 100, e.name);
    field(h, 100, 8, octal(0o755, 8));
    field(h, 108, 8, octal(1000, 8));
    field(h, 116, 8, octal(1000, 8));
    field(h, 124, 12, octal(e.size ?? data.length, 12));
    field(h, 136, 12, octal(0, 12));
    field(h, 148, 8, '        ');
    field(h, 156, 1, e.type ?? '0');
    field(h, 157, 100, e.linkname ?? '');
    field(h, 257, 8, e.magic ?? 'ustar\u000000');
    field(h, 345, 155, e.prefix ?? '');
    let sum = 0;
    for (const b of h) sum += b;
    if (e.badChecksum) sum += 1;
    field(h, 148, 8, sum.toString(8).padStart(6, '0') + '\0 ');
    parts.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

export const makeTarGz = (entries: TarEntry[]): Buffer => gzipSync(makeTar(entries));
