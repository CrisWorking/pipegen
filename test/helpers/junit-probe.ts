// Plan G G0 (carry E-b12, ruling S20): bundled with the release tsup options by test/package.test.ts and run under plain node
// next to the built dist/cli/junit-thread.js. readJunitBytes runs with its default worker entry (./junit-thread.js next to the
// bundle), the way dist/cli/main.js reads a report. argv[2]: the JUnit report's path. Prints one JSON line.
import { readFileSync } from 'node:fs';
import { readJunitBytes } from '../../src/create/junit-worker.js';

const r = await readJunitBytes(new Uint8Array(readFileSync(process.argv[2] as string)));
process.stdout.write(`${JSON.stringify(r.ok ? { ok: true, statuses: r.cases.map((c) => c.status) } : r)}\n`);
