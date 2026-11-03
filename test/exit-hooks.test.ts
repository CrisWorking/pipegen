// D5: the one exit-hook registry (src/util/exit-hooks.ts). Real signal handling is tested in a child node process.
// E0b (ruling B2): interrupt hooks (async, each with a deadline) run on the first signal before the sync hooks; a second
// signal skips to the sync hooks; a PromptCancelledError mid-proof takes the same path (src/proof/interrupt.ts).
// Fix round 1: a repeat signal within SECOND_SIGNAL_GRACE_MS of the first is ignored (npx forwards the terminal's Ctrl-C); hooks
// registered during the hook phase run; the gate is sticky; an interrupt that ran hooks ends with 128 + signo whatever exits.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { onExit, runExitHooks } from '../src/util/exit-hooks.js';

const MODULE = resolve(__dirname, '../src/util/exit-hooks.ts');
const dirs: string[] = [];

type EH = typeof import('../src/util/exit-hooks.js');
type PI = typeof import('../src/proof/interrupt.js');
type IO = typeof import('../src/cli/io.js');
/** In-process interrupt tests each get a fresh registry: once an interrupt starts, the module stays interrupted (sticky gate). */
let live: EH | null = null;
async function fresh(): Promise<{ eh: EH; pi: PI; io: IO }> {
  vi.resetModules();
  const eh = await import('../src/util/exit-hooks.js');
  const pi = await import('../src/proof/interrupt.js');
  const io = await import('../src/cli/io.js');
  live = eh;
  return { eh, pi, io };
}
let exitListeners: Function[] = [];
let exitCode: typeof process.exitCode;
beforeEach(() => { exitListeners = process.listeners('exit'); exitCode = process.exitCode; });
afterEach(() => {
  runExitHooks();
  live?.runExitHooks();
  live = null;
  for (const l of process.listeners('exit')) if (!exitListeners.includes(l)) process.removeListener('exit', l as () => void);   // a held exit code
  process.exitCode = exitCode;
  vi.useRealTimers();
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

interface Out { code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string; ms: number }
interface ChildOpts {
  /** Send the signal again this many ms after the first, once per entry. */
  extra?: number[];
  /** Send the signal again `delayMs` after the child prints `marker`. */
  again?: { marker: string; delayMs: number };
  /** Keep the child's event loop alive (default true); false lets it end on its own. */
  keep?: boolean;
}
/** Runs `body` (module source after the import of the registry) in a child node, sends `signal` once it prints READY, and collects the result. */
function child(body: string, signal: NodeJS.Signals, opts: ChildOpts = {}): Promise<Out> {
  const dir = mkdtempSync(join(tmpdir(), 'pg-exit-'));
  dirs.push(dir);
  const file = join(dir, 'c.mjs');
  const keep = opts.keep === false ? '' : 'setInterval(() => {}, 1000);\n';
  writeFileSync(file, `import { onExit, onInterrupt, interrupt, interrupting } from ${JSON.stringify(MODULE)};\nconst sleep = (ms) => new Promise((r) => setTimeout(r, ms));\n${body}\nconsole.log('READY');\n${keep}`);
  return new Promise((done, fail) => {
    const p = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let sent = false;
    let sentAgain = false;
    let t0 = 0;
    const timers: ReturnType<typeof setTimeout>[] = [];
    const send = (): void => { try { p.kill(signal); } catch { /* gone */ } };
    const guard = setTimeout(() => { p.kill('SIGKILL'); fail(new Error(`child timed out; output so far: ${stdout}`)); }, 15_000);
    p.stderr.on('data', (b: Buffer) => { stderr += b.toString(); });
    p.stdout.on('data', (b: Buffer) => {
      stdout += b.toString();
      if (!sent && stdout.includes('READY')) {
        sent = true;
        t0 = Date.now();
        send();
        for (const ms of opts.extra ?? []) timers.push(setTimeout(send, ms));
      }
      if (opts.again !== undefined && !sentAgain && stdout.includes(opts.again.marker)) { sentAgain = true; timers.push(setTimeout(send, opts.again.delayMs)); }
    });
    p.on('exit', (code, sig) => { clearTimeout(guard); for (const t of timers) clearTimeout(t); done({ code, signal: sig, stdout, stderr, ms: Date.now() - t0 }); });
  });
}
const lines = (s: string): string[] => s.split('\n').filter((l) => l !== '' && l !== 'READY');
/** Past the grace window: a deliberate second Ctrl-C. */
const DELIBERATE = 1_500;

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
      "onInterrupt(async (ctx) => {",
      "  ctx.signal.addEventListener('abort', () => console.log('aborted'));",
      "  onInterrupt(async () => { console.log('late hook ran'); }, { label: 'late', record });",   // registered during the hook phase
      "  console.log('STARTED');",
      "  await new Promise(() => {});",
      "}, { label: 'slow', record });",
      "onInterrupt(async () => { console.log('second hook ran'); }, { label: 'later', record });",
    ].join('\n'), 'SIGINT', { again: { marker: 'STARTED', delayMs: DELIBERATE } });
    expect(lines(r.stdout)).toEqual(['STARTED', 'aborted', 'LEFT slow: stopped by a second signal', 'LEFT later: not run (stopped by a second signal)', 'LEFT late: not run (stopped by a second signal)', 'sync']);
    expect(r.signal).toBe('SIGINT');
    expect(r.ms).toBeLessThan(10_000);   // the hook's deadline is 90 s: only the second signal ends it this fast
  });

  it('exit-hooks: two SIGINTs a few ms apart (npx forwards the terminal\'s Ctrl-C) → the cleanup still runs fully', async () => {
    const r = await child([
      "await sleep(1200);",   // the window counts from the first signal, not from the start of the process
      "const record = (item) => console.log('LEFT ' + item);",
      "onExit(() => console.log('sync'));",
      "onInterrupt(async () => { await sleep(900); console.log('secrets deleted'); }, { label: 'scratch cleanup', record });",
      "onInterrupt(async () => { console.log('prs closed'); }, { label: 'prs', record });",
    ].join('\n'), 'SIGINT', { extra: [2, 600] });   // npm's forwarded copy, then a repeat still inside the 1 s window
    expect(lines(r.stdout)).toEqual(['secrets deleted', 'prs closed', 'sync']);
    expect(r.signal).toBe('SIGINT');
  });

  it('exit-hooks: PromptCancelledError mid-proof takes the same path', async () => {
    const { eh, pi, io } = await fresh();
    const seen: string[] = [];
    const kill = vi.spyOn(process, 'kill').mockImplementation(((_pid: number, sig?: string | number) => { seen.push(`raise ${String(sig)}`); return true; }) as typeof process.kill);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    eh.onExit(() => seen.push('sync'));
    pi.installInterruptHandler(async () => { await Promise.resolve(); seen.push('cleanup'); });
    const cancelled = new io.PromptCancelledError();
    await expect(pi.interruptOnCancel(async () => { seen.push('proof'); throw cancelled; })).rejects.toBe(cancelled);
    expect(seen).toEqual(['proof', 'cleanup', 'sync', 'raise SIGINT']);
    expect(kill).toHaveBeenCalledWith(process.pid, 'SIGINT');
  });

  it('exit-hooks: still one SIGINT listener whatever the number of hooks', async () => {
    const r = await child([
      "for (let i = 0; i < 5; i++) onExit(() => {});",
      "for (let i = 0; i < 5; i++) onInterrupt(async () => {});",
      "const off = onInterrupt(async () => {}); off();",
      "console.log('SIGINT ' + process.listenerCount('SIGINT') + ' SIGTERM ' + process.listenerCount('SIGTERM') + ' exit ' + process.listenerCount('exit'));",
      "onInterrupt(async () => { console.log('during SIGINT ' + process.listenerCount('SIGINT') + ' exit ' + process.listenerCount('exit')); });",
      "onExit(() => console.log('sync'));",
    ].join('\n'), 'SIGINT');
    expect(lines(r.stdout)).toEqual(['SIGINT 1 SIGTERM 1 exit 1', 'during SIGINT 1 exit 1', 'sync']);
    expect(r.signal).toBe('SIGINT');
  });

  it('a second signal still reaches the registry when every other hook was unregistered during the cleanup', async () => {
    const r = await child([
      "const record = (item) => console.log('LEFT ' + item);",
      "const off = onExit(() => {});",
      "onInterrupt(async () => { off(); console.log('STARTED'); await new Promise(() => {}); }, { label: 'slow', record });",
    ].join('\n'), 'SIGINT', { again: { marker: 'STARTED', delayMs: DELIBERATE } });
    expect(lines(r.stdout)).toEqual(['STARTED', 'LEFT slow: stopped by a second signal']);
    expect(r.signal).toBe('SIGINT');
  });

  it('a plain exit (no signal) runs the sync hooks and records nothing for the interrupt hooks, with exit code 0', async () => {
    const r = await child([
      "const record = (item) => console.log('LEFT ' + item);",
      "onExit(() => console.log('sync'));",
      "onInterrupt(async () => { console.log('ran'); }, { label: 'cleanup', record });",
    ].join('\n'), 'SIGCONT', { keep: false });
    expect(lines(r.stdout)).toEqual(['sync']);
    expect(r.code).toBe(0);
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

  it('a foreign non-exiting SIGINT handler: the process lives on, interrupting() stays true, and it ends with 130', async () => {
    const r = await child([
      "process.on('SIGINT', () => console.log('other'));",
      "onExit(() => console.log('sync'));",
      "onInterrupt(async () => { await sleep(50); console.log('cleaned'); });",
      "(async () => { while (!interrupting()) await sleep(5); await sleep(300); console.log('after: interrupting()=' + interrupting()); })();",
    ].join('\n'), 'SIGINT', { keep: false });
    expect(lines(r.stdout)).toEqual(['other', 'cleaned', 'sync', 'after: interrupting()=true']);
    expect(r.signal).toBeNull();
    expect(r.code).toBe(130);
  });

  it('process.exit(0) during the cleanup: the cut and pending hooks are recorded, the sync hooks run, the exit code is 130', async () => {
    const r = await child([
      "const record = (item) => console.log('LEFT ' + item);",
      "onExit(() => console.log('sync'));",
      "onInterrupt(async () => { await sleep(20); process.exit(0); }, { label: 'one', record });",
      "onInterrupt(async () => { console.log('two ran'); }, { label: 'two', record });",
    ].join('\n'), 'SIGINT');
    expect(lines(r.stdout)).toEqual(['LEFT one: cut by the process exiting', 'LEFT two: not run (cut by the process exiting)', 'sync']);
    expect(r.signal).toBeNull();
    expect(r.code).toBe(130);
  });

  it('an uncaught exception in the proof flow during a SIGTERM cleanup: the hook is recorded as cut, the exit code is 143', async () => {
    const r = await child([
      "const record = (item) => console.log('LEFT ' + item);",
      "onExit(() => console.log('sync'));",
      "onInterrupt(async () => { await sleep(2000); console.log('cleaned'); }, { label: 'slow', record });",
      "(async () => { while (!interrupting()) await sleep(5); setTimeout(() => { throw new Error('boom'); }, 50); })();",
    ].join('\n'), 'SIGTERM');
    expect(lines(r.stdout)).toEqual(['LEFT slow: cut by the process exiting', 'sync']);
    expect(r.signal).toBeNull();
    expect(r.code).toBe(143);
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
    const { eh } = await fresh();
    const { seen } = stubbed();
    eh.onExit(() => seen.push('sync1'));
    eh.onInterrupt(async () => { await new Promise((r) => setTimeout(r, 20)); seen.push('a1'); });
    eh.onExit(() => seen.push('sync2'));
    eh.onInterrupt(async () => { seen.push('a2'); });
    await eh.interrupt('SIGTERM');
    expect(seen).toEqual(['a1', 'a2', 'sync1', 'sync2', 'raise SIGTERM self']);
  });

  it('interrupt() defaults to SIGINT, and with no interrupt hook still runs the sync hooks and raises', async () => {
    const { eh } = await fresh();
    const { seen } = stubbed();
    eh.onExit(() => seen.push('sync'));
    await eh.interrupt();
    expect(seen).toEqual(['sync', 'raise SIGINT self']);
  });

  it('the grace window for a repeat signal is 1 s', async () => {
    const { eh } = await fresh();
    expect(eh.SECOND_SIGNAL_GRACE_MS).toBe(1_000);
  });

  it('the default deadline is 90 s and is printed; a hook is cut at its deadline, not before', async () => {
    const { eh } = await fresh();
    expect(eh.DEFAULT_INTERRUPT_DEADLINE_MS).toBe(90_000);
    const { seen, err } = stubbed();
    vi.useFakeTimers();
    const left: string[] = [];
    eh.onInterrupt(() => new Promise(() => {}), { label: 'stuck', record: (i) => left.push(i) });
    const done = eh.interrupt();
    let finished = false;
    void done.then(() => { finished = true; });
    await vi.advanceTimersByTimeAsync(eh.DEFAULT_INTERRUPT_DEADLINE_MS - 1);
    expect(finished).toBe(false);
    expect(left).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await done;
    expect(left).toEqual(['stuck: did not finish within 90 s']);
    expect(seen).toEqual(['raise SIGINT self']);
    expect(err.join('')).toBe('Cleaning up before stopping: stuck (up to 90 s; press Ctrl-C again to stop now).\n');
  });

  it('a custom deadline is used and printed; the hook\'s signal is aborted when it passes', async () => {
    const { eh } = await fresh();
    const { err } = stubbed();
    vi.useFakeTimers();
    const left: string[] = [];
    let aborted = false;
    eh.onInterrupt((ctx) => { ctx.signal.addEventListener('abort', () => { aborted = true; }); return new Promise(() => {}); }, { deadlineMs: 2_500, record: (i) => left.push(i) });
    const done = eh.interrupt();
    await vi.advanceTimersByTimeAsync(2_499);
    expect(aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await done;
    expect(aborted).toBe(true);
    expect(left).toEqual(['cleanup: did not finish within 2.5 s']);
    expect(err.join('')).toContain('cleanup (up to 2.5 s;');
  });

  it('deadlineMs must be a finite number from 1 to 2147483647 ms, checked when the hook is registered', async () => {
    const { eh } = await fresh();
    for (const bad of [Infinity, -Infinity, NaN, 0, 0.5, -1, 2_147_483_648, '100' as unknown as number]) {
      expect(() => eh.onInterrupt(async () => {}, { deadlineMs: bad }), String(bad)).toThrow(/deadlineMs/);
    }
    expect(() => eh.onInterrupt(async () => {}, { deadlineMs: 1 })).not.toThrow();
    expect(() => eh.onInterrupt(async () => {}, { deadlineMs: 2_147_483_647 })).not.toThrow();
    expect(() => eh.onInterrupt(async () => {}, { deadlineMs: 1.5 })).not.toThrow();
  });

  it('a hook that finishes in time is not aborted and records nothing; its timer does not hold the process', async () => {
    const { eh } = await fresh();
    stubbed();
    const left: string[] = [];
    let signal: AbortSignal | undefined;
    eh.onInterrupt(async (ctx) => { signal = ctx.signal; ctx.leftover('branch proof/1'); }, { record: (i) => left.push(i) });
    const t0 = Date.now();
    await eh.interrupt();
    expect(Date.now() - t0).toBeLessThan(1_000);
    expect(signal?.aborted).toBe(false);
    expect(left).toEqual(['branch proof/1']);
  });

  it('without a recorder, leftovers are printed to stderr with control characters removed', async () => {
    const { eh } = await fresh();
    const { err } = stubbed();
    eh.onInterrupt(async (ctx) => { ctx.leftover('pr #4\u001b[31m\r\nfake line'); }, { label: 'prs' });
    await eh.interrupt();
    expect(err.join('')).toContain('Left behind: pr #4?[31m??fake line\n');
  });

  it('interrupt() raises the signal even when another handler of it exists (no handler has seen it yet)', async () => {
    const { eh } = await fresh();
    const { seen } = stubbed();
    const other = (): void => {};
    process.on('SIGINT', other);
    try {
      eh.onInterrupt(async () => { seen.push('a1'); });
      await eh.interrupt();
    } finally {
      process.removeListener('SIGINT', other);
    }
    expect(seen).toEqual(['a1', 'raise SIGINT self']);
  });

  it('no deadline timer is left behind once a hook ends', async () => {
    const { eh } = await fresh();
    stubbed();
    vi.useFakeTimers();
    eh.onInterrupt(async () => {});
    eh.onInterrupt(() => new Promise(() => {}), { deadlineMs: 10, record: () => {} });
    const done = eh.interrupt();
    await vi.advanceTimersByTimeAsync(10);
    await done;
    expect(vi.getTimerCount()).toBe(0);
  });

  it('a recorder that throws does not stop the cleanup', async () => {
    const { eh } = await fresh();
    const { seen } = stubbed();
    eh.onInterrupt(async (ctx) => { ctx.leftover('x'); seen.push('after leftover'); }, { record: () => { throw new Error('disk full'); } });
    eh.onExit(() => seen.push('sync'));
    await eh.interrupt();
    expect(seen).toEqual(['after leftover', 'sync', 'raise SIGINT self']);
  });

  it('interrupting() turns true when an interrupt starts and stays true for the rest of the process (sticky gate)', async () => {
    const { eh } = await fresh();
    const { seen } = stubbed();
    expect(eh.interrupting()).toBe(false);
    eh.onInterrupt(async () => { seen.push(`during ${eh.interrupting()}`); });
    eh.onExit(() => seen.push(`sync ${eh.interrupting()}`));
    const done = eh.interrupt();
    expect(eh.interrupting()).toBe(true);
    await done;
    expect(eh.interrupting()).toBe(true);
    expect(seen).toEqual(['during true', 'sync true', 'raise SIGINT self']);
  });

  it('a plain stop without interrupt hooks also closes the gate', async () => {
    const { eh } = await fresh();
    stubbed();
    await eh.interrupt();
    expect(eh.interrupting()).toBe(true);
  });

  it('a second interrupt() while one runs joins it: the hooks run once', async () => {
    const { eh } = await fresh();
    const { seen } = stubbed();
    eh.onInterrupt(async () => { await Promise.resolve(); seen.push('a1'); });
    const one = eh.interrupt();
    const two = eh.interrupt();
    expect(two).toBe(one);
    await one;
    expect(seen).toEqual(['a1', 'raise SIGINT self']);
    await eh.interrupt();   // a later stop runs only the sync part (nothing left to run)
    expect(seen).toEqual(['a1', 'raise SIGINT self', 'raise SIGINT self']);
  });

  it('a hook registered during the hook phase runs after the running one, in registration order; one unregistered first does not', async () => {
    const { eh } = await fresh();
    const { seen } = stubbed();
    eh.onInterrupt(async () => {
      eh.onInterrupt(async () => { seen.push('late1'); }, { label: 'late1' });
      const off = eh.onInterrupt(async () => { seen.push('dropped'); });
      eh.onInterrupt(async () => { seen.push('late2'); }, { label: 'late2' });
      off();
      await Promise.resolve();
      seen.push('a1');
    });
    eh.onInterrupt(async () => { seen.push('a2'); });
    eh.onExit(() => seen.push('sync'));
    await eh.interrupt();
    expect(seen).toEqual(['a1', 'a2', 'late1', 'late2', 'sync', 'raise SIGINT self']);
  });

  it('a hook registered after the hook phase is recorded as a leftover at once and never runs', async () => {
    const { eh } = await fresh();
    const { seen, err } = stubbed();
    const left: string[] = [];
    eh.onInterrupt(async () => { seen.push('a1'); });
    eh.onExit(() => { eh.onInterrupt(async () => { seen.push('from sync ran'); }, { label: 'from sync', record: (i) => left.push(i) }); });
    await eh.interrupt();
    const before = process.listenerCount('SIGINT');
    const off = eh.onInterrupt(async () => { seen.push('after ran'); }, { label: 'after', record: (i) => left.push(i) });
    eh.onInterrupt(async () => {}, { label: 'printed' });
    expect(process.listenerCount('SIGINT')).toBe(before);   // nothing installed for it
    off();
    for (const bad of [0, NaN]) expect(() => eh.onInterrupt(async () => {}, { deadlineMs: bad })).toThrow(/deadlineMs/);   // checked in every phase
    await eh.interrupt();
    expect(seen).toEqual(['a1', 'raise SIGINT self', 'raise SIGINT self']);
    expect(left).toEqual(['from sync: not run (registered after the cleanup)', 'after: not run (registered after the cleanup)']);
    expect(err.join('')).toContain('Left behind: printed: not run (registered after the cleanup)\n');
  });

  it('after an interrupt with hooks the one exit listener stays (it holds the exit code); new hooks do not add a second', async () => {
    const { eh } = await fresh();
    stubbed();
    const before = process.listenerCount('exit');
    eh.onInterrupt(async () => {});
    expect(process.listenerCount('exit')).toBe(before + 1);
    await eh.interrupt();
    expect(process.listenerCount('exit')).toBe(before + 1);
    const off = eh.onExit(() => {});
    expect(process.listenerCount('exit')).toBe(before + 1);
    off();
    expect(process.listenerCount('exit')).toBe(before + 1);
  });

  it('onInterrupt returns an unregister function; runExitHooks (the exit event) forgets the interrupt hooks', async () => {
    const { eh } = await fresh();
    const { seen } = stubbed();
    const off = eh.onInterrupt(async () => { seen.push('off'); });
    off();
    off();
    eh.onInterrupt(async () => { seen.push('forgotten'); });
    eh.runExitHooks();
    await eh.interrupt();
    expect(seen).toEqual(['raise SIGINT self']);
  });

  it('onInterrupt alone installs the one set of process handlers; they go when the last hook goes', async () => {
    const { eh } = await fresh();
    const before = { exit: process.listenerCount('exit'), int: process.listenerCount('SIGINT'), term: process.listenerCount('SIGTERM') };
    const a = eh.onInterrupt(async () => {});
    const b = eh.onExit(() => {});
    const c = eh.onInterrupt(async () => {});
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
    const { eh, pi } = await fresh();
    const { seen } = stubbed();
    const left: string[] = [];
    const before = process.listenerCount('SIGINT');
    const off = pi.installInterruptHandler(async (ctx) => { ctx.leftover('l1'); seen.push('h'); }, { label: 'state', record: (i) => left.push(i) });
    expect(process.listenerCount('SIGINT')).toBe(before + 1);
    off();
    expect(process.listenerCount('SIGINT')).toBe(before);
    pi.installInterruptHandler(async (ctx) => { ctx.leftover('l2'); seen.push('h2'); }, { record: (i) => left.push(i) });
    expect(() => pi.installInterruptHandler(async () => {}, { deadlineMs: 0 })).toThrow(/deadlineMs/);
    await eh.interrupt();
    expect(seen).toEqual(['h2', 'raise SIGINT self']);
    expect(left).toEqual(['l2']);
  });

  it('interruptOnCancel: a result passes through; any other error is rethrown without stopping', async () => {
    const { eh, pi } = await fresh();
    const { seen } = stubbed();
    eh.onInterrupt(async () => { seen.push('cleanup'); });
    await expect(pi.interruptOnCancel(async () => 42)).resolves.toBe(42);
    const other = new Error('network');
    await expect(pi.interruptOnCancel(async () => { throw other; })).rejects.toBe(other);
    expect(seen).toEqual([]);
    expect(eh.interrupting()).toBe(false);
  });

  it('interruptOnCancel prints why it stops (no terminal), control characters removed, before the cleanup starts', async () => {
    const { eh, pi, io } = await fresh();
    const { seen, err } = stubbed();
    eh.onInterrupt(async () => { seen.push('cleanup'); });
    const noTty = new io.PromptCancelledError('pipegen needs an interactive terminal to ask this question.');
    await expect(pi.interruptOnCancel(async () => { throw noTty; })).rejects.toBe(noTty);
    expect(err[0]).toBe('pipegen needs an interactive terminal to ask this question.\n');
    expect(err[1]).toMatch(/^Cleaning up before stopping/);
    const odd = new io.PromptCancelledError('a\u001b[2Jb\nc');
    await expect(pi.interruptOnCancel(async () => { throw odd; })).rejects.toBe(odd);
    expect(err.join('')).not.toContain('\u001b');
    expect(err.join('')).not.toContain('b\nc');
    expect(seen).toEqual(['cleanup', 'raise SIGINT self', 'raise SIGINT self']);
  });
});
