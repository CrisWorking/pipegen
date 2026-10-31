// The one exit-hook registry (v0.2 Plan D, D5; ruling S8). Everything that must be cleaned when the process stops (the secret vault's wipe, the
// secret scan's temp folder) registers here with onExit(). The registry owns the process handlers: ONE 'exit', ONE 'SIGINT' and ONE 'SIGTERM'
// listener, however many hooks there are. They are installed with the first hook and removed with the last, so a process with nothing to clean
// keeps Node's default signal behaviour.
//
// On a signal the hooks run (each once; one that throws does not stop the others), then the signal is raised again when no other handler of
// the process wants it, so the process still stops by it. When another handler exists, it decides (it was there before; we only clean up).
// A hook runs at most once: running drains the registry. Hooks must be quick, synchronous and must never print a secret.
//
// Keep this file free of imports and of syntax Node's type stripping cannot run (no enums, no parameter properties): the signal test runs it
// in a child process, straight from source.

const hooks = new Set<() => void>();
let installed = false;

/** Runs every hook once, in the order they were registered, and forgets them. A hook that throws does not stop the rest. */
export function runExitHooks(): void {
  const batch = [...hooks];
  hooks.clear();
  uninstall();
  for (const fn of batch) {
    try { fn(); } catch { /* best effort while stopping */ }
  }
}

function onSignal(sig: NodeJS.Signals): void {
  runExitHooks();   // also removes our listeners, so listenerCount below counts only other handlers
  if (process.listenerCount(sig) === 0) process.kill(process.pid, sig);
}
const onSigint = (): void => onSignal('SIGINT');
const onSigterm = (): void => onSignal('SIGTERM');

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

/** Registers a hook to run on exit, SIGINT or SIGTERM. Returns a function that unregisters it (safe to call twice). */
export function onExit(fn: () => void): () => void {
  const entry = (): void => fn();   // a fresh function per call, so the same fn can be registered twice and removed separately
  hooks.add(entry);
  install();
  return () => {
    hooks.delete(entry);
    if (hooks.size === 0) uninstall();
  };
}
