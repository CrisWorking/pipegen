// The gate action's entry (C6 bundles this file to gate/dist/index.js). It runs main unconditionally: no guard on the module's own path,
// which a symlinked action folder would make false so that nothing ran and the step passed (review-C5b Important 1). Tests import
// main.ts, never this file.
import { main } from './main.js';

void main({ env: process.env, write: (t) => { process.stdout.write(t); } }).then(
  (code) => { process.exitCode = code; },
  () => { process.stdout.write('::error::the gate action failed unexpectedly, so it fails closed\n'); process.exitCode = 1; },
);
