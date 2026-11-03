// Plan E E0b (ruling B2): the proof's way into the one exit-hook registry (src/util/exit-hooks.ts). The cleanup after a Ctrl-C (scratch
// secrets first, then PRs and branches, leftovers recorded) is an interrupt hook there; E8 registers the "state saved as interrupted" hook
// first, because interrupt hooks run in registration order.
import { PromptCancelledError } from '../cli/io.js';
import { interrupt, onInterrupt, type InterruptHook, type InterruptOptions } from '../util/exit-hooks.js';

/** Plan E Task 7's interface, now a thin wrapper over onInterrupt (ruling B2). Returns the unregister function. */
export function installInterruptHandler(cleanup: InterruptHook, opts?: InterruptOptions): () => void {
  return onInterrupt(cleanup, opts);
}

/**
 * Runs a stage of the proof. A Ctrl-C inside a prompt does not raise SIGINT (the prompt reads the key) but throws PromptCancelledError;
 * that takes the same path as the signal: the interrupt hooks, the sync hooks (vault wipe), then SIGINT is raised. The error is thrown
 * again afterwards, so nothing carries on as if the stage had finished. Any other error or result passes through untouched.
 */
export async function interruptOnCancel<T>(stage: () => Promise<T>): Promise<T> {
  try {
    return await stage();
  } catch (e) {
    if (e instanceof PromptCancelledError) await interrupt('SIGINT');
    throw e;
  }
}
