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
// one, so it still runs on every exit path), then the signal is raised again. A SECOND signal during that cleanup stops waiting at once and
// goes straight to the sync hooks. A hook that fails, passes its deadline or is cut by the second signal does not stop the sync hooks; its
// AbortSignal is aborted, and what it left behind is recorded: the hook reports each leftover it finds through ctx.leftover(), and the
// registry adds one for a hook that did not finish (or never ran). Leftovers go to the hook's `record` callback (E8: the state file, for
// `pipegen cleanup`; it must write synchronously, since the process may stop right after), or to stderr when there is none. Error texts
// are never recorded or printed (they may hold anything). The 'exit' event can't wait, so at exit only the sync hooks run.
// While another handler of the signal exists, it still gets the first signal too; if it exits the process, the cleanup is cut there.
//
// Windows (npx users): Ctrl-C in a console raises SIGINT in Node, so this path works there. SIGTERM can be listened for but is never sent
// by Windows; its listener is harmless. Raising the signal again (process.kill on our own pid) ends the process there too: Node emulates
// SIGINT/SIGTERM on Windows as an unconditional termination. Ctrl-Break (SIGBREAK) and closing the console window (SIGHUP) are not
// handled: the process ends by Node's default, without the async cleanup, as before E0b; leftovers recorded so far stay for
// `pipegen cleanup`.
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
  /** How long the hook may run once an interrupt starts. Default DEFAULT_INTERRUPT_DEADLINE_MS. */
  deadlineMs?: number;
  /** Where leftovers go (synchronously). Default: printed to stderr. */
  record?: (item: string) => void;
}
export type InterruptHook = (ctx: InterruptContext) => Promise<void>;

/** Ruling B2: an interrupt hook gets 90 s unless it asks for another deadline. */
export const DEFAULT_INTERRUPT_DEADLINE_MS = 90_000;

interface Entry { fn: InterruptHook; label: string; deadlineMs: number; record: (item: string) => void }

const hooks = new Set<() => void>();
const interruptHooks = new Set<Entry>();
let installed = false;
/** The interrupt in progress (from its start until the sync hooks run), and the function a second signal calls to cut it. */
let stopping: Promise<void> | null = null;
let skipToSync: () => void = () => {};

/** Control characters out, so a leftover or label can't move the cursor or fake a line. */
const shown = (s: string): string => String(s).replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
function printErr(s: string): void {
  try { process.stderr.write(s); } catch { /* stderr gone while stopping */ }
}
const printLeftover = (item: string): void => printErr(`Left behind: ${shown(item)}\n`);

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

/** True from the start of an interrupt until its sync hooks run: long-running work should stop and push nothing more. */
export function interrupting(): boolean {
  return stopping !== null;
}

/** The end of every stop: the sync hooks, then the signal again (after a real signal, only when no other handler of it is left). */
function finish(sig: NodeJS.Signals, fromSignal: boolean): void {
  stopping = null;
  skipToSync = () => {};
  runExitHooks();   // also removes our listeners, so listenerCount below counts only other handlers
  if (!fromSignal || process.listenerCount(sig) === 0) process.kill(process.pid, sig);
}

/** Runs one interrupt hook until it ends, its deadline passes or a second signal comes; records why it did not finish. */
async function runOne(h: Entry, skip: Promise<'skipped'>): Promise<void> {
  const ctl = new AbortController();
  const record = (item: string): void => {
    try { h.record(item); } catch { /* a recorder that fails must not stop the cleanup */ }
  };
  const secs = `${h.deadlineMs / 1000} s`;
  printErr(`Cleaning up before stopping: ${shown(h.label)} (up to ${secs}; press Ctrl-C again to stop now).\n`);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<'deadline'>((done) => { timer = setTimeout(() => done('deadline'), h.deadlineMs); });
  let work: Promise<'done' | 'error'>;
  try {
    work = Promise.resolve(h.fn({ signal: ctl.signal, leftover: record })).then(() => 'done' as const, () => 'error' as const);
  } catch {
    work = Promise.resolve('error' as const);
  }
  const end = await Promise.race([work, deadline, skip]);
  clearTimeout(timer);
  if (end === 'done') return;
  ctl.abort();
  if (end === 'deadline') record(`${h.label}: did not finish within ${secs}`);
  else if (end === 'skipped') record(`${h.label}: stopped by a second signal`);
  else record(`${h.label}: stopped with an error`);
}

/** The first signal (or interrupt()): the interrupt hooks in order, then finish. A second call while one runs joins it. */
function begin(sig: NodeJS.Signals, fromSignal: boolean): Promise<void> {
  if (stopping !== null) return stopping;
  const batch = [...interruptHooks];
  interruptHooks.clear();
  if (batch.length === 0) {
    finish(sig, fromSignal);   // nothing async to wait for: the D5 behaviour, synchronously
    return Promise.resolve();
  }
  let skipped = false;
  const skip = new Promise<'skipped'>((done) => { skipToSync = () => { skipped = true; done('skipped'); }; });
  const run = async (): Promise<void> => {
    for (const h of batch) {
      if (skipped) {
        try { h.record(`${h.label}: not run (stopped by a second signal)`); } catch { /* as in runOne */ }
        continue;
      }
      await runOne(h, skip);
    }
    finish(sig, fromSignal);
  };
  // `stopping` is set before the first hook starts, so a hook already sees interrupting() and can't start a second run.
  stopping = Promise.resolve().then(run);
  return stopping;
}

function onSignal(sig: NodeJS.Signals): void {
  if (stopping !== null) { skipToSync(); return; }   // a second signal: straight to the sync hooks
  void begin(sig, true);
}
const onSigint = (): void => onSignal('SIGINT');
const onSigterm = (): void => onSignal('SIGTERM');

/**
 * Stops the process the way a signal does (interrupt hooks, sync hooks, then `sig` is raised), for a stop that is not a signal: a
 * PromptCancelledError mid-proof (the user pressed Ctrl-C inside a prompt, which reads the key instead of raising SIGINT). The signal is
 * always raised at the end, since no handler has seen it yet. Resolves after raising it; a caller must not carry on as if nothing happened.
 */
export function interrupt(sig: NodeJS.Signals = 'SIGINT'): Promise<void> {
  return begin(sig, false);
}

function install(): void {
  if (installed) return;
  installed = true;
  process.on('exit', runExitHooks);
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);
}
function uninstall(): void {
  if (!installed) return;
  installed = false;
  process.removeListener('exit', runExitHooks);
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
 * the order they were registered. Not run on a plain exit. Returns a function that unregisters it (safe to call twice).
 */
export function onInterrupt(fn: InterruptHook, opts: InterruptOptions = {}): () => void {
  const entry: Entry = { fn, label: opts.label ?? 'cleanup', deadlineMs: opts.deadlineMs ?? DEFAULT_INTERRUPT_DEADLINE_MS, record: opts.record ?? printLeftover };
  interruptHooks.add(entry);
  install();
  return () => {
    interruptHooks.delete(entry);
    uninstallIfEmpty();
  };
}
