// A minimal ustar reader (ruling B3): pulls ONE regular file out of a tar held in memory, so pipegen never starts
// `tar` (or any other child process) to unpack a pinned tool. It is strict on purpose: the whole archive is
// refused when any entry is a link (hard or symbolic), a device or FIFO, a pax/GNU extension header (they can
// rename entries), or has an unsafe path (absolute, `..`, backslash, drive letter). Header checksums are checked,
// and the wanted file must appear exactly once and be no larger than `maxBytes`. Nothing is written to disk here.

export class TarError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TarError';
  }
}

const BLOCK = 512;
const MAX_ENTRIES = 10_000;
const utf8 = new TextDecoder('utf-8', { fatal: true });

/** A NUL-terminated header field as bytes. */
function raw(h: Uint8Array, offset: number, length: number): Uint8Array {
  const f = h.subarray(offset, offset + length);
  const end = f.indexOf(0);
  return end === -1 ? f : f.subarray(0, end);
}

function text(h: Uint8Array, offset: number, length: number): string {
  try {
    return utf8.decode(raw(h, offset, length));
  } catch {
    throw new TarError('The archive has an entry whose name is not valid text (unsafe path).');
  }
}

/** An octal number field (NUL/space padded). Base-256 or anything else is refused. */
function octal(h: Uint8Array, offset: number, length: number, what: string): number {
  const s = Buffer.from(h.subarray(offset, offset + length)).toString('latin1').replace(/[\0 ]+$/, '').replace(/^ +/, '');
  if (!/^[0-7]{1,12}$/.test(s)) throw new TarError(`The archive has a corrupt header (${what} is not an octal number).`);
  return Number.parseInt(s, 8);
}

/** True for an entry path pipegen could never write safely: empty, absolute, `..`, backslash, drive letter. */
function unsafePath(path: string): boolean {
  if (path === '' || path.startsWith('/') || path.includes('\\') || /^[A-Za-z]:/.test(path) || path.includes('\0')) return true;
  return path.replace(/\/+$/, '').split('/').some((seg) => seg === '..');
}

const isZero = (b: Uint8Array) => b.every((x) => x === 0);

/**
 * Returns the bytes of the one regular file named exactly `member` (no `./`, no directory) in the ustar archive
 * `tar`. Throws TarError (with a plain-English message) for anything else.
 */
export function readTarMember(tar: Uint8Array, member: string, maxBytes: number): Buffer {
  let found: Buffer | null = null;
  let entries = 0;
  for (let off = 0; ; ) {
    if (off + BLOCK > tar.length) throw new TarError('The archive is truncated (it ends without an end-of-archive marker).');
    const h = tar.subarray(off, off + BLOCK);
    if (isZero(h)) break; // end of archive
    if (++entries > MAX_ENTRIES) throw new TarError(`The archive has more than ${MAX_ENTRIES} entries.`);

    // header checksum: the sum of all header bytes, with the checksum field itself counted as spaces
    const stored = octal(h, 148, 8, 'the header checksum');
    let sum = 0;
    for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : (h[i] as number);
    if (sum !== stored) throw new TarError('The archive has a corrupt header (its checksum does not match).');
    const magic = Buffer.from(h.subarray(257, 265)).toString('latin1');
    if (magic !== 'ustar\u000000' && magic !== 'ustar  \u0000') throw new TarError('The archive is not in the ustar format pipegen reads.');

    const name = text(h, 0, 100);
    // POSIX ustar keeps a path prefix at 345; GNU tar keeps times and other fields there instead, so it is ignored
    const prefix = magic === 'ustar  \u0000' ? '' : text(h, 345, 155);
    const path = prefix === '' ? name : `${prefix}/${name}`;
    const type = String.fromCharCode(h[156] as number);
    const size = octal(h, 124, 12, 'the entry size');
    const dataStart = off + BLOCK;
    if (dataStart + size > tar.length) throw new TarError('The archive is truncated (an entry is larger than the data that follows it).');

    if (type === '1' || type === '2') throw new TarError('The archive holds a link (hard or symbolic); pipegen refuses archives with links.');
    if (type === '3' || type === '4' || type === '6') throw new TarError('The archive holds a device or FIFO entry; pipegen refuses archives with special files.');
    if (type !== '0' && type !== '\0' && type !== '5') throw new TarError(`The archive has an entry type pipegen doesn't accept ("${type === '\0' ? '\\0' : type.replace(/[^\x21-\x7e]/g, '?')}").`);
    if (unsafePath(path)) throw new TarError('The archive has an entry with an unsafe path (absolute, "..", or a backslash).');

    if (type !== '5' && path === member) {
      if (found !== null) throw new TarError(`The archive holds ${member} more than once.`);
      if (size > maxBytes) throw new TarError(`${member} in the archive is larger than its pinned size (${size} > ${maxBytes} bytes).`);
      found = Buffer.from(tar.subarray(dataStart, dataStart + size));
    }
    off = dataStart + Math.ceil(size / BLOCK) * BLOCK;
  }
  if (found === null) throw new TarError(`The archive has no ${member} file in it.`);
  return found;
}
