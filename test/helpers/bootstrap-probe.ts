// Plan G G0 (B8): bundled with the release tsup options (the PIPEGEN_RELEASE define) by test/plan-g0.test.ts, then run under
// plain node with PIPEGEN_BOOTSTRAP_PROOFS=1: the release bundle must refuse the switch. Prints one JSON line.
import { bootstrapProofs } from '../../src/engine/reviewed.js';

try {
  process.stdout.write(`${JSON.stringify({ on: bootstrapProofs(process.env) })}\n`);
} catch (e) {
  process.stdout.write(`${JSON.stringify({ refused: e instanceof Error ? e.message : String(e) })}\n`);
}
