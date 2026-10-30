// C6 Part 0 (review-C5b-r2 c1-c3): stale gate files never ship. Written first.
// Design for c1 (one design): when result.json, baseline.json or marker.json can not be removed or replaced, the gate moves the whole
// gate folder aside (a rename needs only the parent folder, not the files); if that fails it locks the folder (chmod 0); either way the
// result upload finds nothing it can read and fails (`if-no-files-found: error`). If even that fails, the step says so and exits 2.
import { execFileSync } from 'node:child_process';
import { chmodSync, lstatSync, symlinkSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main, type MainDeps } from '../gate/src/main.js';
import { FakeGh, pushWorld, runner, VIEW, type Runner } from './helpers/gate-world.js';

const NOW = new Date('2026-10-30T12:00:00Z');
const CLEAN = (): Parameters<typeof pushWorld>[0] => ({ 'sast--app': readFileSync('test/fixtures/sarif/clean/semgrep.sarif', 'utf8') });
const eacces = (): never => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); };

async function go(opts: { fs?: MainDeps['fs']; env?: (e: Record<string, string>) => void; pre?: (r: Runner) => void } = {}): Promise<{ code: number; out: string; r: Runner }> {
  const w = pushWorld(CLEAN());
  const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
  opts.pre?.(r);
  opts.env?.(r.env);
  const chunks: string[] = [];
  const gh = new FakeGh(w);
  const code = await main({ env: r.env, now: () => NOW, reviewed: () => VIEW, write: (t) => { chunks.push(t); }, github: () => gh, ...(opts.fs === undefined ? {} : { fs: opts.fs }) });
  return { code, out: chunks.join(''), r };
}
const dirOf = (r: Runner): string => join(r.temp, 'pipegen-gate');
const noGateOutput = (e: Record<string, string>): void => { delete e.GITHUB_OUTPUT; };
const unlinkFails = (names: string[]) => (p: string): void => { if (names.some((n) => p.endsWith(`/${n}`))) eacces(); unlinkSync(p); };
const renameAsideFails = (a: string, b: string): void => { if (b.includes('.stale-')) eacces(); renameSync(a, b); };

describe('C6 part 0, c2: a planted result.json never survives a failed write', () => {
  it('a pass result.json planted before the gate step is replaced by the real result', async () => {
    const x = await go({ pre: (r) => { mkdirSync(dirOf(r), { recursive: true }); writeFileSync(join(dirOf(r), 'result.json'), '{"result":"pass","planted":true}\n'); } });
    const doc = JSON.parse(readFileSync(join(dirOf(x.r), 'result.json'), 'utf8')) as Record<string, unknown>;
    expect(doc.planted).toBeUndefined();
    expect(doc.pipegenGateResult).toBe(1);
  });
  it('a planted result.json that can not be removed: the gate blocks, never leaves it for the upload (folder moved aside), status 2', async () => {
    const x = await go({
      pre: (r) => { mkdirSync(dirOf(r), { recursive: true }); writeFileSync(join(dirOf(r), 'result.json'), '{"result":"pass","planted":true}\n'); },
      fs: { unlink: unlinkFails(['result.json']) },
    });
    expect(x.code).toBe(2);
    expect(x.out).toMatch(/::error::.*result file may be stale/);
    expect(existsSync(dirOf(x.r))).toBe(false);
  });
});

describe('C6 part 0 (scan finding): any entry left at result.json is stale, whatever its type', () => {
  const kinds: [string, (p: string) => void][] = [
    ['a symlink', (p) => { symlinkSync('/etc/hostname', p); }],
    ['a folder', (p) => { mkdirSync(p); }],
    ['a FIFO', (p) => { execFileSync('mkfifo', [p]); }],
  ];
  for (const [name, plant] of kinds) {
    it(`${name} left at result.json (it can not be removed): status 2 and the folder is moved aside`, async () => {
      const x = await go({
        pre: (r) => { mkdirSync(dirOf(r), { recursive: true }); plant(join(dirOf(r), 'result.json')); },
        fs: { unlink: unlinkFails(['result.json']) },
      });
      expect(x.code).toBe(2);
      expect(x.out).toMatch(/::error::.*result file may be stale/);
      expect(existsSync(dirOf(x.r))).toBe(false);
    });
  }
  it('a symlink at result.json that CAN be removed is replaced by the real result, never followed', async () => {
    const x = await go({ pre: (r) => { mkdirSync(dirOf(r), { recursive: true }); symlinkSync('/etc/hostname', join(dirOf(r), 'result.json')); } });
    expect(lstatSync(join(dirOf(x.r), 'result.json')).isFile()).toBe(true);
    expect(JSON.parse(readFileSync(join(dirOf(x.r), 'result.json'), 'utf8')).pipegenGateResult).toBe(1);
  });
  it('a folder at result.json (the write fails, the unlink fails): status 2, not a plain block', async () => {
    const x = await go({ pre: (r) => { mkdirSync(join(dirOf(r), 'result.json'), { recursive: true }); } });
    expect(x.code).toBe(2);
    expect(existsSync(dirOf(x.r))).toBe(false);
  });
});

describe('C6 part 0, c1: the upload ships nothing stale', () => {
  it('c3 (left): the late replacement works but the baseline can not be removed: status 2, the folder is moved aside', async () => {
    const x = await go({ env: noGateOutput, fs: { unlink: unlinkFails(['baseline.json']) } });
    expect(x.code).toBe(2);
    expect(x.out).toMatch(/::error::.*result file may be stale/);
    expect(existsSync(join(dirOf(x.r), 'result.json'))).toBe(false);
    const aside = readdirSync(x.r.temp).filter((n) => n.startsWith('pipegen-gate.stale-'));
    expect(aside).toHaveLength(1);
    // nothing but the moved folder: the upload path pipegen-gate/ does not exist, so `if-no-files-found: error` fails the result upload
    expect(existsSync(dirOf(x.r))).toBe(false);
  });
  it('c3 (not written): result.json can not be written (a folder is there) and the marker can not be removed: status 2, folder moved aside', async () => {
    const x = await go({ pre: (r) => { mkdirSync(join(dirOf(r), 'result.json'), { recursive: true }); }, fs: { unlink: unlinkFails(['marker.json']) } });
    expect(x.code).toBe(2);
    expect(x.out).toMatch(/::error::.*result file may be stale/);
    expect(existsSync(dirOf(x.r))).toBe(false);
  });
  it('the old read-only-folder case: the rename still works (only the parent matters), so the stale files are gone from the upload path', async () => {
    const w = pushWorld(CLEAN());
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    const dir = dirOf(r);
    const env = new Proxy(r.env, { get(t, k) { if (k === 'GITHUB_OUTPUT' && existsSync(join(dir, 'result.json'))) { chmodSync(dir, 0o555); return undefined; } return Reflect.get(t, k); } });
    const chunks: string[] = [];
    const gh = new FakeGh(w);
    const code = await main({ env, now: () => NOW, reviewed: () => VIEW, write: (t) => { chunks.push(t); }, github: () => gh });
    expect(code).toBe(2);
    expect(existsSync(dir)).toBe(false);
    const aside = readdirSync(r.temp).filter((n) => n.startsWith('pipegen-gate.stale-'));
    for (const a of aside) chmodSync(join(r.temp, a), 0o755);
  });
  it('the rename fails: the folder is locked (mode 0), so nothing in it can be read for the upload', async () => {
    const x = await go({ env: noGateOutput, fs: { unlink: unlinkFails(['baseline.json']), rename: renameAsideFails } });
    expect(x.code).toBe(2);
    expect(statSync(dirOf(x.r)).mode & 0o777).toBe(0);
    chmodSync(dirOf(x.r), 0o755);
  });
  it('neither the rename nor the lock works: exit 2 and the error says the uploads may ship stale files', async () => {
    const x = await go({ env: noGateOutput, fs: { unlink: unlinkFails(['baseline.json']), rename: renameAsideFails, chmod: () => eacces() } });
    expect(x.code).toBe(2);
    expect(x.out).toMatch(/::error::.*could not be moved aside or locked.*stale/);
  });
  it('nothing goes wrong: no folder is moved aside', async () => {
    const x = await go();
    expect(x.code).toBe(0);
    expect(readdirSync(x.r.temp).filter((n) => n.includes('.stale-'))).toEqual([]);
    expect(existsSync(join(dirOf(x.r), 'result.json'))).toBe(true);
  });
});

describe('C6 part 0 (scan notes): quarantine happens at once, and a lock that does not hold is not claimed', () => {
  it('stale is handled before the outputs: with the outputs failing too there is one moved-aside folder and status 2', async () => {
    const x = await go({
      env: noGateOutput,
      pre: (r) => { mkdirSync(dirOf(r), { recursive: true }); writeFileSync(join(dirOf(r), 'result.json'), '{"result":"pass"}\n'); },
      fs: { unlink: unlinkFails(['result.json']) },
    });
    expect(x.code).toBe(2);
    expect(readdirSync(x.r.temp).filter((n) => n.startsWith('pipegen-gate.stale-'))).toHaveLength(1);
    expect(existsSync(dirOf(x.r))).toBe(false);
  });
  it('before locking, result.json is overwritten with a block document (best effort)', async () => {
    const written: string[] = [];
    const x = await go({
      env: noGateOutput,
      fs: { unlink: unlinkFails(['baseline.json']), rename: renameAsideFails, overwrite: (p, d) => { written.push(`${p}\n${d}`); } },
    });
    expect(x.code).toBe(2);
    expect(written).toHaveLength(1);
    expect(written[0]).toMatch(/result\.json\n.*"result":"block"/);
    chmodSync(dirOf(x.r), 0o755);
  });
  it('a lock that leaves the folder readable (root) is not claimed: the error says it could not be moved aside or locked', async () => {
    const x = await go({ env: noGateOutput, fs: { unlink: unlinkFails(['baseline.json']), rename: renameAsideFails, chmod: () => undefined, access: () => undefined } });
    expect(x.code).toBe(2);
    expect(x.out).toMatch(/::error::.*could not be moved aside or locked.*stale/);
    expect(x.out).not.toMatch(/was locked/);
  });
});
