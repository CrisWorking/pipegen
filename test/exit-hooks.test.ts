// D5: the one exit-hook registry (src/util/exit-hooks.ts). Real signal handling is tested in a child node process.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { onExit, runExitHooks } from '../src/util/exit-hooks.js';

const MODULE = resolve(__dirname, '../src/util/exit-hooks.ts');
const dirs: string[] = [];
afterEach(() => { runExitHooks(); for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

interface Out { code: number | null; signal: NodeJS.Signals | null; stdout: string }
/** Runs `body` (module source after the import of onExit) in a child node, sends `signal` once it prints READY, and collects the result. */
function child(body: string, signal: NodeJS.Signals): Promise<Out> {
  const dir = mkdtempSync(join(tmpdir(), 'pg-exit-'));
  dirs.push(dir);
  const file = join(dir, 'c.mjs');
  writeFileSync(file, `import { onExit } from ${JSON.stringify(MODULE)};\n${body}\nconsole.log('READY');\nsetInterval(() => {}, 1000);\n`);
  return new Promise((done, fail) => {
    const p = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let sent = false;
    const guard = setTimeout(() => { p.kill('SIGKILL'); fail(new Error(`child timed out; output so far: ${stdout}`)); }, 15_000);
    p.stdout.on('data', (b: Buffer) => {
      stdout += b.toString();
      if (!sent && stdout.includes('READY')) { sent = true; p.kill(signal); }
    });
    p.on('exit', (code, sig) => { clearTimeout(guard); done({ code, signal: sig, stdout }); });
  });
}
const lines = (s: string): string[] => s.split('\n').filter((l) => l !== '' && l !== 'READY');

describe('exit-hooks: one registry', () => {
  it('runExitHooks runs each hook once and in order; a hook that throws does not stop the others', () => {
    const seen: string[] = [];
    onExit(() => seen.push('a'));
    onExit(() => { throw new Error('boom'); });
    onExit(() => seen.push('b'));
    runExitHooks();
    runExitHooks();
    expect(seen).toEqual(['a', 'b']);
  });

  it('onExit returns an unregister function', () => {
    const seen: string[] = [];
    const off = onExit(() => seen.push('x'));
    off();
    runExitHooks();
    expect(seen).toEqual([]);
  });

  it('the process handlers are registered once for any number of hooks, and removed when none is left', () => {
    const before = { exit: process.listenerCount('exit'), int: process.listenerCount('SIGINT'), term: process.listenerCount('SIGTERM') };
    const offs = [onExit(() => {}), onExit(() => {}), onExit(() => {})];
    expect(process.listenerCount('exit')).toBe(before.exit + 1);
    expect(process.listenerCount('SIGINT')).toBe(before.int + 1);
    expect(process.listenerCount('SIGTERM')).toBe(before.term + 1);
    for (const off of offs) off();
    expect(process.listenerCount('exit')).toBe(before.exit);
    expect(process.listenerCount('SIGINT')).toBe(before.int);
    expect(process.listenerCount('SIGTERM')).toBe(before.term);
  });

  it('SIGINT runs every hook exactly once, then the process still dies by SIGINT', async () => {
    const r = await child("onExit(() => console.log('h1'));\nonExit(() => console.log('h2'));", 'SIGINT');
    expect(lines(r.stdout)).toEqual(['h1', 'h2']);
    expect(r.signal).toBe('SIGINT');
  });

  it('SIGTERM likewise', async () => {
    const r = await child("onExit(() => console.log('h1'));", 'SIGTERM');
    expect(lines(r.stdout)).toEqual(['h1']);
    expect(r.signal).toBe('SIGTERM');
  });

  it('with another SIGINT handler present the hooks run once and the process is not re-killed', async () => {
    const r = await child("onExit(() => console.log('h1'));\nprocess.on('SIGINT', () => { console.log('other'); setTimeout(() => process.exit(0), 50); });", 'SIGINT');
    expect(lines(r.stdout).sort()).toEqual(['h1', 'other']);
    expect(r.code).toBe(0);
    expect(r.signal).toBeNull();
  });

  it('a normal exit runs the hooks once', async () => {
    const r = await child("onExit(() => console.log('h1'));\nsetTimeout(() => process.exit(0), 100);", 'SIGCONT');
    expect(lines(r.stdout)).toEqual(['h1']);
    expect(r.code).toBe(0);
  });
});
