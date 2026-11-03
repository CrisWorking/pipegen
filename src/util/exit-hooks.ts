// The one exit-hook registry (v0.2 Plan D, D5; ruling S8). Everything that must be cleaned when the process stops (the secret vault's wipe, the
// secret scan's temp folder) registers here with onExit(). The registry owns the process handlers: ONE 'exit', ONE 'SIGINT' and ONE 'SIGTERM'
// listener, however many hooks there are. They are installed with the first hook and removed with the last, so a process with nothing to clean
// keeps Node's default signal behaviour.
//
// On a signal the hooks run (each once; one that throws does not stop the others), then the signal is raised again when no other handler of
// the process wants it, so the process still stops by it. When another handler exists, it decides (it was there before; we only clean up).
// A hook runs at most once: running drains the registry. Sync hooks must be quick, synchronous and must never print a secret.
//
// Interrupt hooks (v0.2 Plan E, E0b; ruling B2). A proof leaves things in GitHub (scratch secrets that may hold the user's real test keys,
// PRs, branches) whose cleanup is asynchronous, so it can't be a sync hook. onInterrupt() registers such a hook, with a deadline (default
// DEFAULT_INTERRUPT_DEADLINE_MS, printed when it starts). On the FIRST signal (or interrupt(), which a PromptCancelledError mid-proof calls
// through src/proof/interrupt.ts) the interrupt hooks run one after the other, in the order they were registered (E8 registers the
// "state saved as interrupted" hook first), each awaited until it ends or its deadline passes. Then the sync hooks run (the vault wipe is
// one, so it still runs on every exit path), then the signal is raised again.
//
// A SECOND signal stops waiting at once and goes straight to the sync hooks, but only once SECOND_SIGNAL_GRACE_MS (1 s) has passed since
// the first. A repeat inside that window is ignored (E0b review C1): under `npx`, with bash as npm's script shell, pipegen is npm's direct
// child, so one terminal Ctrl-C reaches it twice, from the tty and forwarded by npm's signal manager, a few ms apart. 1 s is far above
// that forwarding delay (18 ms measured) and above a nervous double-tap, while a deliberate second Ctrl-C (after reading the printed
// "press Ctrl-C again" line) costs at most 1 s more.
//
// The queue is live (review I1): a hook registered while the hooks run is run after them, in order (or recorded "not run" after a second
// signal). A hook registered once the hook phase is over (from a sync hook, or later in a process that lives on) is recorded as a
// leftover at once, never run and never installed.
//
// A hook that fails, passes its deadline or is cut by the second signal does not stop the sync hooks; its AbortSignal is aborted, and what
// it left behind is recorded: the hook reports each leftover it finds through ctx.leftover(), and the registry adds one for a hook that did
// not finish (or never ran). Leftovers go to the hook's `record` callback (E8: the state file, for `pipegen cleanup`; it must write
// synchronously, since the process may stop right after; a returned promise is not awaited), or to stderr when there is none. Error texts
// are never recorded or printed (they may hold anything).
//
// The 'exit' event can't wait (review I3): when the process exits during the hook phase (process.exit, an uncaught exception), the hook
// that was running is recorded as cut and the pending ones as not run, then the sync hooks run. Once an interrupt with hooks has begun,
// the process ends with 128 + signo (130 for SIGINT, 143 for SIGTERM) whatever else asks for: our 'exit' listener stays and sets
// process.exitCode, which overrides process.exit(0) and an uncaught exception's 1. That also covers a foreign handler of the signal that
// does not exit (review I2): there is no re-raise then (the D5 rule), but the process can't end as a success. The plain D5 stop (no
// interrupt hook registered) keeps D5's rule: another handler decides, exit code included.
//
// interrupting() is the gate for work that must not go on (pushes, secret writes): it turns true when a stop begins and stays true for
// the rest of the process (review I2), even when the process lives on.
//
// Limits: never call interrupt() from an interrupt hook (it joins the interrupt in progress, so the hook waits for itself until its
// deadline). A hook that blocks the event loop (long synchronous work) defeats both its deadline and the second signal, which need the
// loop to run.
//
// While another handler of the signal exists, it still gets the first signal too; if it exits the process, the cleanup is cut there (and
// recorded as above).
//
// Windows (npx users): Ctrl-C in a console raises SIGINT in Node, so this path works there. SIGTERM can be listened for but is never sent
// by Windows; its listener is harmless. Raising the signal again (process.kill on our own pid) ends the process there too: Node emulates
// SIGINT/SIGTERM on Windows as an unconditional termination. Ctrl-Break (SIGBREAK) and closing the console window (SIGHUP) are not
// handled: the process ends by Node's default, without the async cleanup, as before E0b; leftovers recorded so far stay for
// `pipegen cleanup`. Whether npm on Windows forwards Ctrl-C to pipegen itself or to a cmd.exe in between is for the live session.
//
// Keep this file free of imports and of syntax Node's type stripping cannot run (no enums, no parameter properties): the signal test runs it
// in a child process, straight from source.

/** What an interrupt hook gets: `signal` is aborted when the hook is cut (deadline or second signal); `leftover` records one thing it left. */
export interface InterruptContext {
  readonly signal: AbortSignal;
  leftover(item: string): void;
}
export interface InterruptOptions {
  /** Shown when the hook starts and in its recorded leftovers. A constant; never a secret. Default 'cleanup'. */
  label?: string;
  /** How long the hook may run once an interrupt starts, 1 to MAX_INTERRUPT_DEADLINE_MS. Default DEFAULT_INTERRUPT_DEADLINE_MS. */
  deadlineMs?: number;
  /** Where leftovers go. Must write synchronously (a returned promise is not awaited). Default: printed to stderr. */
  record?: (item: string) => void;
}
/** Never call interrupt() from one: it would wait for itself until its deadline. */
export type InterruptHook = (ctx: InterruptContext) => Promise<void>;
export type StopSignal = 'SIGINT' | 'SIGTERM';

/** Ruling B2: an interrupt hook gets 90 s unless it asks for another deadline. */
export const DEFAULT_INTERRUPT_DEADLINE_MS = 90_000;
/** setTimeout's largest delay; a larger one (or Infinity, NaN, 0) would fire after 1 ms and cut the cleanup at once. */
export const MAX_INTERRUPT_DEADLINE_MS = 2_147_483_647;
/** A repeat signal this soon after the first is the same Ctrl-C (npm forwards it), not a second one. See the header. */
export const SECOND_SIGNAL_GRACE_MS = 1_000;

interface Entry { fn: InterruptHook; label: string; deadlineMs: number; record: (item: string) => void }

const hooks = new Set<() => void>();
/** The live queue of interrupt hooks: the hook phase takes the first until it is empty. */
const interruptHooks = new Set<Entry>();
let installed = false;
let exitListening = false;
/** 'none' before any stop; 'hooks' while interrupt hooks run; 'after' from the end of the first stop's hook phase, for good. */
let phase: 'none' | 'hooks' | 'after' = 'none';
/** The sticky gate: a stop has begun. Never reset. */
let gate = false;
/** 128 + signo once an interrupt with hooks has begun; our 'exit' listener then stays and sets it. Never reset. */
let heldExitCode: number | null = null;
/** The interrupt in progress (from its start until the sync hooks run), when it began, the hook running, and the second signal's cut. */
let stopping: Promise<void> | null = null;
let startedAt = 0;
let current: Entry | null = null;
let skipToSync: () => void = () => {};

/** Control characters out, so a leftover or label can't move the cursor or fake a line. */
const shown = (s: string): string => String(s).replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
function printErr(s: string): void {
  try { process.stderr.write(s); } catch { /* stderr gone while stopping */ }
}
const printLeftover = (item: string): void => printErr(`Left behind: ${shown(item)}\n`);
function record(h: Entry, item: string): void {
  try { h.record(item); } catch { /* a recorder that fails must not stop the cleanup */ }
}
const exitCodeOf = (sig: StopSignal): number => 128 + (sig === 'SIGTERM' ? 15 : 2);

/** Runs every sync hook once, in the order they were registered, and forgets every hook. A hook that throws does not stop the rest. */
export function runExitHooks(): void {
  const batch = [...hooks];
  hooks.clear();
  interruptHooks.clear();   // they can't be awaited here (the 'exit' event, or the end of an interrupt)
  uninstall();
  for (const fn of batch) {
    try { fn(); } catch { /* best effort while stopping */ }
  }
}

/** The 'exit' event: a hook phase still running is cut (recorded), the sync hooks run, and a held exit code wins. */
function onProcessExit(): void {
  if (phase === 'hooks') {
    if (current !== null) record(current, `${current.label}: cut by the process exiting`);
    for (const h of interruptHooks) record(h, `${h.label}: not run (cut by the process exiting)`);
  }
  runExitHooks();
  if (heldExitCode !== null) process.exitCode = heldExitCode;
}

/** True once a stop has begun, for the rest of the process: long-running work must stop and push nothing more. */
export function interrupting(): boolean {
  return gate;
}

/** The end of every stop: the sync hooks, then the signal again (after a real signal, only when no other handler of it is left). */
function finish(sig: StopSignal, fromSignal: boolean): void {
  stopping = null;
  current = null;
  phase = 'after';
  skipToSync = () => {};
  runExitHooks();   // also removes our signal listeners, so listenerCount below counts only other handlers
  if (!fromSignal || process.listenerCount(sig) === 0) process.kill(process.pid, sig);
}

/** Runs one interrupt hook until it ends, its deadline passes or a second signal comes; records why it did not finish. */
async function runOne(h: Entry, skip: Promise<'skipped'>): Promise<void> {
  const ctl = new AbortController();
  const secs = `${h.deadlineMs / 1000} s`;
  printErr(`Cleaning up before stopping: ${shown(h.label)} (up to ${secs}; press Ctrl-C again to stop now).\n`);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<'deadline'>((done) => { timer = setTimeout(() => done('deadline'), h.deadlineMs); });
  let work: Promise<'done' | 'error'>;
  try {
    work = Promise.resolve(h.fn({ signal: ctl.signal, leftover: (item) => record(h, item) })).then(() => 'done' as const, () => 'error' as const);
  } catch {
    work = Promise.resolve('error' as const);
  }
  const end = await Promise.race([work, deadline, skip]);
  clearTimeout(timer);
  if (end === 'done') return;
  ctl.abort();
  if (end === 'deadline') record(h, `${h.label}: did not finish within ${secs}`);
  else if (end === 'skipped') record(h, `${h.label}: stopped by a second signal`);
  else record(h, `${h.label}: stopped with an error`);
}

/** The first signal (or interrupt()): the interrupt hooks in order (the queue is live), then finish. A second call while one runs joins it. */
function begin(sig: StopSignal, fromSignal: boolean): Promise<void> {
  if (stopping !== null) return stopping;
  gate = true;
  if (interruptHooks.size === 0) {
    finish(sig, fromSignal);   // nothing async to wait for: the D5 behaviour, synchronously
    return Promise.resolve();
  }
  phase = 'hooks';
  heldExitCode = exitCodeOf(sig);
  startedAt = performance.now();
  let skipped = false;
  const skip = new Promise<'skipped'>((done) => { skipToSync = () => { skipped = true; done('skipped'); }; });
  const run = async (): Promise<void> => {
    for (let h = nextHook(); h !== undefined; h = nextHook()) {
      interruptHooks.delete(h);
      if (skipped) {
        record(h, `${h.label}: not run (stopped by a second signal)`);
        continue;
      }
      current = h;
      await runOne(h, skip);
      current = null;
    }
    finish(sig, fromSignal);
  };
  // `stopping` is set before the first hook starts, so a hook already sees interrupting() and can't start a second run.
  stopping = Promise.resolve().then(run);
  return stopping;
}
const nextHook = (): Entry | undefined => interruptHooks.values().next().value;

function onSignal(sig: StopSignal): void {
  if (stopping !== null) {
    if (performance.now() - startedAt < SECOND_SIGNAL_GRACE_MS) return;   // the same Ctrl-C, forwarded (see the header)
    skipToSync();   // a second signal: straight to the sync hooks
    return;
  }
  void begin(sig, true);
}
const onSigint = (): void => onSignal('SIGINT');
const onSigterm = (): void => onSignal('SIGTERM');

/**
 * Stops the process the way a signal does (interrupt hooks, sync hooks, then `sig` is raised), for a stop that is not a signal: a
 * PromptCancelledError mid-proof (the user pressed Ctrl-C inside a prompt, which reads the key instead of raising SIGINT). The signal is
 * always raised at the end, since no handler has seen it yet. Resolves after raising it; a caller must not carry on as if nothing happened.
 * Never call it from an interrupt hook.
 */
export function interrupt(sig: StopSignal = 'SIGINT'): Promise<void> {
  return begin(sig, false);
}

function install(): void {
  if (installed) return;
  installed = true;
  if (!exitListening) {
    exitListening = true;
    process.on('exit', onProcessExit);
  }
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);
}
function uninstall(): void {
  if (!installed) return;
  installed = false;
  if (heldExitCode === null) {   // a held exit code keeps the 'exit' listener for the rest of the process
    exitListening = false;
    process.removeListener('exit', onProcessExit);
  }
  process.removeListener('SIGINT', onSigint);
  process.removeListener('SIGTERM', onSigterm);
}
/** The listeners stay while an interrupt runs, so a second signal still reaches us. */
function uninstallIfEmpty(): void {
  if (hooks.size === 0 && interruptHooks.size === 0 && stopping === null) uninstall();
}

/** Registers a hook to run on exit, SIGINT or SIGTERM. Returns a function that unregisters it (safe to call twice). */
export function onExit(fn: () => void): () => void {
  const entry = (): void => fn();   // a fresh function per call, so the same fn can be registered twice and removed separately
  hooks.add(entry);
  install();
  return () => {
    hooks.delete(entry);
    uninstallIfEmpty();
  };
}

/**
 * Registers an async hook to run on the first SIGINT or SIGTERM (or interrupt()), before the sync hooks, with a deadline. Hooks run in
 * the order they were registered. Not run on a plain exit. Throws a RangeError for a deadline outside 1..MAX_INTERRUPT_DEADLINE_MS.
 * Once the hook phase of a stop is over, the hook is recorded as a leftover at once and not registered. Returns a function that
 * unregisters it (safe to call twice).
 */
export function onInterrupt(fn: InterruptHook, opts: InterruptOptions = {}): () => void {
  const deadlineMs = opts.deadlineMs ?? DEFAULT_INTERRUPT_DEADLINE_MS;
  if (!Number.isFinite(deadlineMs) || deadlineMs < 1 || deadlineMs > MAX_INTERRUPT_DEADLINE_MS) {
    throw new RangeError(`deadlineMs must be a number of milliseconds from 1 to ${MAX_INTERRUPT_DEADLINE_MS}`);
  }
  const entry: Entry = { fn, label: opts.label ?? 'cleanup', deadlineMs, record: opts.record ?? printLeftover };
  if (phase === 'after') {
    record(entry, `${entry.label}: not run (registered after the cleanup)`);
    return () => {};
  }
  interruptHooks.add(entry);
  install();
  return () => {
    interruptHooks.delete(entry);
    uninstallIfEmpty();
  };
}
