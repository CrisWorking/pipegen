// Built by the redact test with tsup into a temp package (like config-probe.ts) and run as its own node process:
// bundleCode with a betterleaks stub that never finishes on its own, so the test can stop this process with a signal
// while the scan runs and check that the temp folder holding the raw report is gone (Task 7 review M1).
import { bundleCode } from '../../src/ai/redact.js';
import { betterleaksAt, scanWith } from './gitleaks-stub.js';

const [repo, stub] = process.argv.slice(2) as [string, string];
await bundleCode(repo, scanWith(betterleaksAt(stub), {}, 120_000));
console.log('finished');
