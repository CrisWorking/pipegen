// C1b fix round 1: tests that need node:fs wrapped (a module mock, as gate-fingerprint-open.test.ts does):
// m2 (the /proc real-path check M2 and the dev/ino check M17), m3 (one open per file) and m5 (a failed write leaves no file).
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ParsedFinding } from '../gate/src/parse-common.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

const SF = ('sec' + 'ret') as 'secret';
const KEY = ['fp', 'test', 'a'.repeat(40)].join('-');
const hooks: {
  opened: string[];
  readlink?: (p: string) => string | undefined;
  openAs?: (p: string) => string | undefined;
  writeFail?: boolean;
  linkFail?: boolean;
} = { opened: [] };
vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>();
  const wrapped = {
    ...real,
    openSync: (...a: Parameters<typeof real.openSync>) => {
      hooks.opened.push(String(a[0]));
      const as = hooks.openAs?.(String(a[0]));
      return real.openSync(as ?? a[0], ...(a.slice(1) as [never]));
    },
    readlinkSync: (...a: Parameters<typeof real.readlinkSync>) => {
      const over = hooks.readlink?.(String(a[0]));
      return over ?? real.readlinkSync(...a);
    },
    writeSync: (...a: Parameters<typeof real.writeSync>) => {
      if (hooks.writeFail) {
        const args = a as unknown[];
        (real.writeSync as (...x: unknown[]) => number)(args[0], args[1], args[2], Math.min(3, Number(args[3])), args[4]);   // a partial write, then the failure
        throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
      }
      return real.writeSync(...a);
    },
    linkSync: (...a: Parameters<typeof real.linkSync>) => {
      if (hooks.linkFail) throw Object.assign(new Error('no links'), { code: 'EPERM' });
      return real.linkSync(...a);
    },
  };
  return { ...wrapped, default: wrapped };
});
beforeEach(() => { hooks.opened.length = 0; hooks.readlink = undefined; hooks.openAs = undefined; hooks.writeFail = false; hooks.linkFail = false; });
afterEach(cleanupRepos);

const leak = (file: string, over: Partial<ParsedFinding> = {}): ParsedFinding => ({
  tool: 'betterleaks', ruleId: `${'sec' + 'ret:'}x`, severity: 'critical', file, line: 1, startColumn: 1, endLine: 1, endColumn: 3, message: '', uriUnmapped: false, [SF]: true, ...over,
});

describe('m2: the two checks of the region reader that only a race reaches', () => {
  it('M2: an opened descriptor whose real path is outside the workspace is refused (/proc/self/fd/<n> says so)', async () => {
    const { readRegion } = await import('../gate/src/fingerprint.js');
    const ws = makeTempDir();
    writeFileSync(join(ws, 'a.txt'), 'abcdef\n');
    expect(readRegion(ws, leak('a.txt')).ok, 'control: the real /proc path is inside').toBe(true);
    hooks.readlink = (p) => (p.startsWith('/proc/self/fd/') ? '/etc/hosts' : undefined);
    const r = readRegion(ws, leak('a.txt'));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toBe('the opened file is outside the workspace');
    hooks.readlink = (p) => (p.startsWith('/proc/self/fd/') ? `${ws}-sibling/a.txt` : undefined);   // a sibling folder with the same prefix
    expect(readRegion(ws, leak('a.txt')).ok).toBe(false);
    hooks.readlink = (p) => (p.startsWith('/proc/self/fd/') ? `${join(ws, 'a.txt')} (deleted)` : undefined);
    expect(readRegion(ws, leak('a.txt')).ok, 'a deleted file that was inside is still inside').toBe(true);
  });

  it('M17: a file swapped between the lstat and the open (another device or inode) is refused', async () => {
    const { readRegion } = await import('../gate/src/fingerprint.js');
    const ws = makeTempDir();
    writeFileSync(join(ws, 'a.txt'), 'abcdef\n');
    writeFileSync(join(ws, 'other.txt'), 'uvwxyz\n');
    hooks.openAs = (p) => (p === join(ws, 'a.txt') ? join(ws, 'other.txt') : undefined);
    const r = readRegion(ws, leak('a.txt'));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toBe('the file changed while it was opened');
  });
});

describe('m3: one open per file', () => {
  it('many findings in one file open it once; a second file once more; a missing file is not opened', async () => {
    const { fingerprintAll } = await import('../gate/src/fingerprint.js');
    const ws = makeTempDir();
    writeFileSync(join(ws, 'a.txt'), 'abcdef\n'.repeat(50));
    writeFileSync(join(ws, 'b.txt'), 'uvwxyz\n'.repeat(5));
    const findings = [...Array.from({ length: 40 }, (_, i) => leak('a.txt', { line: i + 1, endLine: i + 1 })), leak('b.txt'), leak('b.txt', { line: 2, endLine: 2 }), leak('missing.txt'), leak('missing.txt', { line: 2, endLine: 2 })];
    const out = fingerprintAll(findings, { fpKey: KEY, workspace: ws });
    expect(out.map((f) => f.fpBy).filter((b) => b === 'region')).toHaveLength(42);
    expect(hooks.opened.filter((p) => p.endsWith('a.txt'))).toHaveLength(1);
    expect(hooks.opened.filter((p) => p.endsWith('b.txt'))).toHaveLength(1);
    expect(hooks.opened.filter((p) => p.endsWith('missing.txt'))).toHaveLength(0);
  });
});

describe('m5: a failed write leaves no output file', () => {
  const raw = () => readFileSync(join(import.meta.dirname, 'fixtures', 'sarif', 'trivy-config.sarif'));
  function setup() {
    const base = makeTempDir();
    mkdirSync(join(base, 'pipegen-raw', 'pipegen-out-iac'), { recursive: true });
    const rawPath = join(base, 'pipegen-raw', 'pipegen-out-iac', 'trivy.sarif');
    writeFileSync(rawPath, raw());
    return { base, raw: rawPath, out: join(base, 'pipegen-out', 'pipegen-out-iac', 'trivy.sarif'), dir: join(base, 'pipegen-out', 'pipegen-out-iac') };
  }
  const go = async (s: ReturnType<typeof setup>) => {
    const { scrubFile } = await import('../gate/src/scrub.js');
    return scrubFile({ tool: 'trivy-config', format: 'sarif', artifact: 'pipegen-out-iac', raw: s.raw, out: s.out, fpKey: KEY, workspace: '/home/runner/work/fixture/fixture', eventText: '{}' });
  };

  it('a write that fails half way: tool-error, and neither the result file nor a temporary one is left', async () => {
    const s = setup();
    hooks.writeFail = true;
    const r = await go(s);
    expect(r).toMatchObject({ status: 'tool-error' });
    expect(readdirSync(s.dir)).toEqual([]);
  });

  it('a failure to publish the file: tool-error, nothing left behind', async () => {
    const s = setup();
    hooks.linkFail = true;
    expect(await go(s)).toMatchObject({ status: 'tool-error' });
    expect(readdirSync(s.dir)).toEqual([]);
  });

  it('a good write leaves exactly the result file (no temporary), whole and readable; an existing file is never replaced', async () => {
    const s = setup();
    const r = await go(s);
    expect(r.status).toBe('ok');
    expect(readdirSync(s.dir)).toEqual(['trivy.sarif']);
    const { readScrubbed } = await import('../gate/src/scrub.js');
    expect(readScrubbed(readFileSync(s.out), 'sarif').toolError).toBeUndefined();
    writeFileSync(s.out, 'keep me');
    expect(await go(s)).toMatchObject({ status: 'tool-error', error: expect.stringMatching(/exists/) });
    expect(readFileSync(s.out, 'utf8')).toBe('keep me');
    expect(readdirSync(s.dir)).toEqual(['trivy.sarif']);
  });
});
