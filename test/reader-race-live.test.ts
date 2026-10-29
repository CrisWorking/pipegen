// P49: the reviewer's swapper against the limited reader. A second process swaps `root/sub` (a real folder holding INSIDE)
// with a symlink to a folder outside the repo (holding OUTSIDE), as fast as it can, with renameat2(RENAME_EXCHANGE),
// while the reader reads `root/sub/f.txt` with the repo root given. Every check by path leaves a window, so the reader
// must verify the opened descriptor itself (Linux: /proc/self/fd). No read may ever return OUTSIDE.
// Linux only (renameat2 and /proc), python3 needed. Long (PIPEGEN_RACE_SECONDS, default 25), so it is gated like the live
// tests: skipped unless PIPEGEN_LIVE_TESTS=1.
import { spawn } from 'node:child_process';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { readTextLimitedWithReason } from '../src/read/limits.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1' && process.platform === 'linux';
const SECONDS = Number(process.env.PIPEGEN_RACE_SECONDS ?? '25');

const SWAPPER = `
import ctypes, sys, time
libc = ctypes.CDLL(None, use_errno=True)
a, b, end = sys.argv[1].encode(), sys.argv[2].encode(), time.time() + float(sys.argv[3])
n = 0
while time.time() < end:
    if libc.renameat2(-100, a, -100, b, 2) == 0:
        n += 1
print(n)
`;

describe.skipIf(!live)('limited reader under a racing folder swap (P49, live, Linux)', () => {
  afterAll(cleanupRepos);

  it(`live: ${SECONDS} s of renameat2 swaps of a folder with a link to outside: no read ever returns the outside file`, async () => {
    const root = makeTempDir();
    const outside = makeTempDir();
    writeFileSync(join(outside, 'f.txt'), 'OUTSIDE\n');
    mkdirSync(join(root, 'sub'));
    writeFileSync(join(root, 'sub', 'f.txt'), 'INSIDE\n');
    symlinkSync(outside, join(root, 'other'));
    const script = join(makeTempDir(), 'swap.py');
    writeFileSync(script, SWAPPER);
    const child = spawn('python3', ['-I', script, join(root, 'sub'), join(root, 'other'), String(SECONDS)], { stdio: ['ignore', 'pipe', 'inherit'] });
    let swaps = '';
    child.stdout.on('data', (d: Buffer) => { swaps += d.toString(); });
    const done = new Promise<void>((resolve) => child.on('exit', () => resolve()));
    const counts: Record<string, number> = {};
    const end = Date.now() + SECONDS * 1000;
    while (Date.now() < end) {
      const r = await readTextLimitedWithReason(join(root, 'sub', 'f.txt'), root);
      const k = 'text' in r ? `text:${r.text.trim()}` : r.skipped;
      counts[k] = (counts[k] ?? 0) + 1;
    }
    await done;
    console.log(`P49 race: ${swaps.trim()} swaps; reads ${JSON.stringify(counts)}`);
    expect(Number(swaps.trim())).toBeGreaterThan(1000); // the swapper really ran
    expect(counts['text:INSIDE'] ?? 0).toBeGreaterThan(0); // and reads still work in between
    expect(counts['text:OUTSIDE'] ?? 0).toBe(0);
  }, (SECONDS + 60) * 1000);
});
