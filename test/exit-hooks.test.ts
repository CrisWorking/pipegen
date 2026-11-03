// D5: the one exit-hook registry (src/util/exit-hooks.ts). Real signal handling is tested in a child node process.
// E0b (ruling B2): interrupt hooks (async, each with a deadline) run on the first signal before the sync hooks; a second
// signal skips to the sync hooks; a PromptCancelledError mid-proof takes the same path (src/proof/interrupt.ts).
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PromptCancelledError } from '../src/cli/io.js';
import { installInterruptHandler, interruptOnCancel } from '../src/proof/interrupt.js';
import { DEFAULT_INTERRUPT_DEADLINE_MS, interrupt, interrupting, onExit, onInterrupt, runExitHooks } from '../src/util/exit-hooks.js';

const MODULE = resolve(__dirname, '../src/util/exit-hooks.ts');
const dirs: string[] = [];
afterEach(() => { runExitHooks(); vi.useRealTimers(); vi.restoreAllMocks(); for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

interface Out { code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string; ms: number }
/**
 * Runs `body` (module source after the import of the registry) in a child node, sends `signal` once it prints READY, and collects the
 * result. With `again`, the signal is sent a second time once the child prints that marker.
 */
function child(body: string, signal: NodeJS.Signals, again?: string): Promise<Out> {
  const dir = mkdtempSync(join(tmpdir(), 'pg-exit-'));
  dirs.push(dir);
  const file = join(dir, 'c.mjs');
  writeFileSync(file, `import { onExit, onInterrupt, interrupt } from ${JSON.stringify(MODULE)};\nconst sleep = (ms) => new Promise((r) => setTimeout(r, ms));\n${body}\nconsole.log('READY');\nsetInterval(() => {}, 1000);\n`);
  return new Promise((done, fail) => {
    const p = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let sent = false;
    let sentAgain = false;
    let t0 = 0;
    const guard = setTimeout(() => { p.kill('SIGKILL'); fail(new Error(`child timed out; output so far: ${stdout}`)); }, 15_000);
    p.stderr.on('data', (b: Buffer) => { stderr += b.toString(); });
    p.stdout.on('data', (b: Buffer) => {
      stdout += b.toString();
      if (!sent && stdout.includes('READY')) { sent = true; t0 = Date.now(); p.kill(signal); }
      if (again !== undefined && !sentAgain && stdout.includes(again)) { sentAgain = true; p.kill(signal); }
    });
    p.on('exit', (code, sig) => { clearTimeout(guard); done({ code, signal: sig, stdout, stderr, ms: Date.now() - t0 }); });
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

describe('exit-hooks: interrupt path (E0b, ruling B2)', () => {
  it('exit-hooks: onInterrupt hooks run before the sync hooks on SIGINT, then the signal is re-raised', async () => {
    const r = await child([
      "onExit(() => console.log('sync'));",
      "onInterrupt(async () => { console.log('a1'); await sleep(100); console.log('a1 done'); }, { label: 'first' });",
      "onInterrupt(async () => { await sleep(10); console.log('a2'); });",
    ].join('\n'), 'SIGINT');
    expect(lines(r.stdout)).toEqual(['a1', 'a1 done', 'a2', 'sync']);
    expect(r.signal).toBe('SIGINT');
    expect(r.stderr).toContain('first');
    expect(r.stderr).toContain('up to 90 s');   // the default deadline is printed
  });

  it('exit-hooks: interrupt hook past its deadline → sync hooks still run, leftovers recorded', async () => {
    const r = await child([
      "const record = (item) => console.log('LEFT ' + item);",   // the fake recorder (E8 wires the state file)
      "onExit(() => console.log('sync'));",
      "onInterrupt(async (ctx) => { ctx.signal.addEventListener('abort', () => console.log('aborted')); ctx.leftover('secret API_KEY in scratch'); await new Promise(() => {}); }, { label: 'scratch cleanup', deadlineMs: 300, record });",
      "onInterrupt(async () => { console.log('next hook ran'); }, { record });",
    ].join('\n'), 'SIGINT');
    expect(lines(r.stdout)).toEqual(['LEFT secret API_KEY in scratch', 'aborted', 'LEFT scratch cleanup: did not finish within 0.3 s', 'next hook ran', 'sync']);
    expect(r.signal).toBe('SIGINT');
    expect(r.ms).toBeLessThan(10_000);
  });

  it('exit-hooks: second SIGINT during an interrupt hook → straight to the sync hooks', async () => {
    const r = await child([
      "const record = (item) => console.log('LEFT ' + item);",
      "onExit(() => console.log('sync'));",
      "onInterrupt(async (ctx) => { ctx.signal.addEventListener('abort', () => console.log('aborted')); console.log('STARTED'); await new Promise(() => {}); }, { label: 'slow', record });",
      "onInterrupt(async () => { console.log('second hook ran'); }, { label: 'later', record });",
    ].join('\n'), 'SIGINT', 'STARTED');
    expect(lines(r.stdout)).toEqual(['STARTED', 'aborted', 'LEFT slow: stopped by a second signal', 'LEFT later: not run (stopped by a second signal)', 'sync']);
    expect(r.signal).toBe('SIGINT');
    expect(r.ms).toBeLessThan(10_000);   // the hook's deadline is 90 s: only the second signal ends it this fast
  });

  it('exit-hooks: PromptCancelledError mid-proof takes the same path', async () => {
    const seen: string[] = [];
    const kill = vi.spyOn(process, 'kill').mockImplementation(((_pid: number, sig?: string | number) => { seen.push(`raise ${String(sig)}`); return true; }) as typeof process.kill);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    onExit(() => seen.push('sync'));
    installInterruptHandler(async () => { await Promise.resolve(); seen.push('cleanup'); });
    const cancelled = new PromptCancelledError();
    await expect(interruptOnCancel(async () => { seen.push('proof'); throw cancelled; })).rejects.toBe(cancelled);
    expect(seen).toEqual(['proof', 'cleanup', 'sync', 'raise SIGINT']);
    expect(kill).toHaveBeenCalledWith(process.pid, 'SIGINT');
  });

  it('exit-hooks: still one SIGINT listener whatever the number of hooks', async () => {
    const r = await child([
      "for (let i = 0; i < 5; i++) onExit(() => {});",
      "for (let i = 0; i < 5; i++) onInterrupt(async () => {});",
      "const off = onInterrupt(async () => {}); off();",
      "console.log('SIGINT ' + process.listenerCount('SIGINT') + ' SIGTERM ' + process.listenerCount('SIGTERM') + ' exit ' + process.listenerCount('exit'));",
      "onInterrupt(async () => { console.log('during SIGINT ' + process.listenerCount('SIGINT')); });",
      "onExit(() => console.log('sync'));",
    ].join('\n'), 'SIGINT');
    expect(lines(r.stdout)).toEqual(['SIGINT 1 SIGTERM 1 exit 1', 'during SIGINT 1', 'sync']);
    expect(r.signal).toBe('SIGINT');
  });

  it('a second signal still reaches the registry when every other hook was unregistered during the cleanup', async () => {
    const r = await child([
      "const record = (item) => console.log('LEFT ' + item);",
      "const off = onExit(() => {});",
      "onInterrupt(async () => { off(); console.log('STARTED'); await new Promise(() => {}); }, { label: 'slow', record });",
    ].join('\n'), 'SIGINT', 'STARTED');
    expect(lines(r.stdout)).toEqual(['STARTED', 'LEFT slow: stopped by a second signal']);
    expect(r.signal).toBe('SIGINT');
  });

  it('SIGTERM takes the same path', async () => {
    const r = await child("onExit(() => console.log('sync'));\nonInterrupt(async () => { await sleep(20); console.log('a1'); });", 'SIGTERM');
    expect(lines(r.stdout)).toEqual(['a1', 'sync']);
    expect(r.signal).toBe('SIGTERM');
  });

  it('a hook that throws or rejects is recorded, and the next hook still runs', async () => {
    const r = await child([
      "const record = (item) => console.log('LEFT ' + item);",
      "onInterrupt(() => { throw new Error('sync throw ERRTEXT-must-not-show'); }, { label: 'one', record });",
      "onInterrupt(async () => { throw new Error('async throw'); }, { label: 'two', record });",
      "onInterrupt(async () => { console.log('three'); }, { label: 'three', record });",
      "onExit(() => console.log('sync'));",
    ].join('\n'), 'SIGINT');
    expect(lines(r.stdout)).toEqual(['LEFT one: stopped with an error', 'LEFT two: stopped with an error', 'three', 'sync']);
    expect(r.stdout).not.toContain('ERRTEXT');   // the error text is never recorded or printed
    expect(r.stderr).not.toContain('ERRTEXT');
    expect(r.signal).toBe('SIGINT');
  });
});

describe('exit-hooks: interrupt path, in process (raising the signal is stubbed)', () => {
  function stubbed(): { seen: string[]; err: string[] } {
    const seen: string[] = [];
    const err: string[] = [];
    vi.spyOn(process, 'kill').mockImplementation(((pid: number, sig?: string | number) => { seen.push(`raise ${String(sig)} ${pid === process.pid ? 'self' : pid}`); return true; }) as typeof process.kill);
    vi.spyOn(process.stderr, 'write').mockImplementation(((s: string | Uint8Array) => { err.push(String(s)); return true; }) as typeof process.stderr.write);
    return { seen, err };
  }

  it('interrupt(): hooks in registration order, each awaited before the next, then the sync hooks, then the signal', async () => {
    const { seen } = stubbed();
    onExit(() => seen.push('sync1'));
    onInterrupt(async () => { await new Promise((r) => setTimeout(r, 20)); seen.push('a1'); });
    onExit(() => seen.push('sync2'));
    onInterrupt(async () => { seen.push('a2'); });
    await interrupt('SIGTERM');
    expect(seen).toEqual(['a1', 'a2', 'sync1', 'sync2', 'raise SIGTERM self']);
  });

  it('interrupt() defaults to SIGINT, and with no interrupt hook still runs the sync hooks and raises', async () => {
    const { seen } = stubbed();
    onExit(() => seen.push('sync'));
    await interrupt();
    expect(seen).toEqual(['sync', 'raise SIGINT self']);
  });

  it('the default deadline is 90 s and is printed; a hook is cut at its deadline, not before', async () => {
    expect(DEFAULT_INTERRUPT_DEADLINE_MS).toBe(90_000);
    const { seen, err } = stubbed();
    vi.useFakeTimers();
    const left: string[] = [];
    onInterrupt(() => new Promise(() => {}), { label: 'stuck', record: (i) => left.push(i) });
    const done = interrupt();
    let finished = false;
    void done.then(() => { finished = true; });
    await vi.advanceTimersByTimeAsync(DEFAULT_INTERRUPT_DEADLINE_MS - 1);
    expect(finished).toBe(false);
    expect(left).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await done;
    expect(left).toEqual(['stuck: did not finish within 90 s']);
    expect(seen).toEqual(['raise SIGINT self']);
    expect(err.join('')).toBe('Cleaning up before stopping: stuck (up to 90 s; press Ctrl-C again to stop now).\n');
  });

  it('a custom deadline is used and printed; the hook\'s signal is aborted when it passes', async () => {
    const { err } = stubbed();
    vi.useFakeTimers();
    const left: string[] = [];
    let aborted = false;
    onInterrupt((ctx) => { ctx.signal.addEventListener('abort', () => { aborted = true; }); return new Promise(() => {}); }, { deadlineMs: 2_500, record: (i) => left.push(i) });
    const done = interrupt();
    await vi.advanceTimersByTimeAsync(2_499);
    expect(aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await done;
    expect(aborted).toBe(true);
    expect(left).toEqual(['cleanup: did not finish within 2.5 s']);
    expect(err.join('')).toContain('cleanup (up to 2.5 s;');
  });

  it('a hook that finishes in time is not aborted and records nothing; its timer does not hold the process', async () => {
    stubbed();
    const left: string[] = [];
    let signal: AbortSignal | undefined;
    onInterrupt(async (ctx) => { signal = ctx.signal; ctx.leftover('branch proof/1'); }, { record: (i) => left.push(i) });
    const t0 = Date.now();
    await interrupt();
    expect(Date.now() - t0).toBeLessThan(1_000);
    expect(signal?.aborted).toBe(false);
    expect(left).toEqual(['branch proof/1']);
  });

  it('without a recorder, leftovers are printed to stderr with control characters removed', async () => {
    const { err } = stubbed();
    onInterrupt(async (ctx) => { ctx.leftover('pr #4\u001b[31m\r\nfake line'); }, { label: 'prs' });
    await interrupt();
    expect(err.join('')).toContain('Left behind: pr #4?[31m??fake line\n');
  });

  it('interrupt() raises the signal even when another handler of it exists (no handler has seen it yet)', async () => {
    const { seen } = stubbed();
    const other = (): void => {};
    process.on('SIGINT', other);
    try {
      onInterrupt(async () => { seen.push('a1'); });
      await interrupt();
    } finally {
      process.removeListener('SIGINT', other);
    }
    expect(seen).toEqual(['a1', 'raise SIGINT self']);
  });

  it('no deadline timer is left behind once a hook ends', async () => {
    stubbed();
    vi.useFakeTimers();
    onInterrupt(async () => {});
    onInterrupt(() => new Promise(() => {}), { deadlineMs: 10, record: () => {} });
    const done = interrupt();
    await vi.advanceTimersByTimeAsync(10);
    await done;
    expect(vi.getTimerCount()).toBe(0);
  });

  it('a recorder that throws does not stop the cleanup', async () => {
    const { seen } = stubbed();
    onInterrupt(async (ctx) => { ctx.leftover('x'); seen.push('after leftover'); }, { record: () => { throw new Error('disk full'); } });
    onExit(() => seen.push('sync'));
    await interrupt();
    expect(seen).toEqual(['after leftover', 'sync', 'raise SIGINT self']);
  });

  it('interrupting() is true from the first signal until the sync hooks run', async () => {
    const { seen } = stubbed();
    expect(interrupting()).toBe(false);
    onInterrupt(async () => { seen.push(`during ${interrupting()}`); });
    onExit(() => seen.push(`sync ${interrupting()}`));
    const done = interrupt();
    expect(interrupting()).toBe(true);
    await done;
    expect(interrupting()).toBe(false);
    expect(seen).toEqual(['during true', 'sync false', 'raise SIGINT self']);
  });

  it('a second interrupt() while one runs joins it: the hooks run once', async () => {
    const { seen } = stubbed();
    onInterrupt(async () => { await Promise.resolve(); seen.push('a1'); });
    const one = interrupt();
    const two = interrupt();
    expect(two).toBe(one);
    await one;
    expect(seen).toEqual(['a1', 'raise SIGINT self']);
    await interrupt();   // a later stop starts afresh (nothing left to run)
    expect(seen).toEqual(['a1', 'raise SIGINT self', 'raise SIGINT self']);
  });

  it('onInterrupt returns an unregister function; runExitHooks (the exit event) forgets the interrupt hooks', async () => {
    const { seen } = stubbed();
    const off = onInterrupt(async () => { seen.push('off'); });
    off();
    off();
    onInterrupt(async () => { seen.push('forgotten'); });
    runExitHooks();
    await interrupt();
    expect(seen).toEqual(['raise SIGINT self']);
  });

  it('onInterrupt alone installs the one set of process handlers; they go when the last hook goes', () => {
    const before = { exit: process.listenerCount('exit'), int: process.listenerCount('SIGINT'), term: process.listenerCount('SIGTERM') };
    const a = onInterrupt(async () => {});
    const b = onExit(() => {});
    const c = onInterrupt(async () => {});
    expect(process.listenerCount('exit')).toBe(before.exit + 1);
    expect(process.listenerCount('SIGINT')).toBe(before.int + 1);
    expect(process.listenerCount('SIGTERM')).toBe(before.term + 1);
    a();
    b();
    expect(process.listenerCount('SIGINT')).toBe(before.int + 1);   // c is still there
    c();
    expect(process.listenerCount('exit')).toBe(before.exit);
    expect(process.listenerCount('SIGINT')).toBe(before.int);
    expect(process.listenerCount('SIGTERM')).toBe(before.term);
  });

  it('installInterruptHandler is onInterrupt (options passed through)', async () => {
    const { seen } = stubbed();
    const left: string[] = [];
    const before = process.listenerCount('SIGINT');
    const off = installInterruptHandler(async (ctx) => { ctx.leftover('l1'); seen.push('h'); }, { label: 'state', record: (i) => left.push(i) });
    expect(process.listenerCount('SIGINT')).toBe(before + 1);
    off();
    expect(process.listenerCount('SIGINT')).toBe(before);
    installInterruptHandler(async (ctx) => { ctx.leftover('l2'); seen.push('h2'); }, { record: (i) => left.push(i) });
    await interrupt();
    expect(seen).toEqual(['h2', 'raise SIGINT self']);
    expect(left).toEqual(['l2']);
  });

  it('interruptOnCancel: a result passes through; any other error is rethrown without stopping', async () => {
    const { seen } = stubbed();
    onInterrupt(async () => { seen.push('cleanup'); });
    await expect(interruptOnCancel(async () => 42)).resolves.toBe(42);
    const other = new Error('network');
    await expect(interruptOnCancel(async () => { throw other; })).rejects.toBe(other);
    expect(seen).toEqual([]);
    expect(interrupting()).toBe(false);
  });
});
