// pipegen's command line (Plan A Task 8). `run` is the whole CLI behind the CliIO seam (tests call it directly);
// the bottom of this file runs it only when this module is the program node started (dist/cli/main.js, the `pipegen`
// bin), never when it is imported.
import { readFileSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { hideToken } from '../github/client.js';
import { safeText } from '../util/safe-text.js';
import { inspect } from './inspect.js';
import { processIO, type CliIO } from './io.js';

/** The running version from pipegen's own package.json (next to dist/ once installed, the repo root in dev). */
function version(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' ? safeText(pkg.version, 40) : 'unknown';
  } catch {
    return 'unknown';
  }
}

const USAGE = [
  'Usage: pipegen <command> [options]',
  '',
  'Commands:',
  '  pipegen inspect    Read this repo and its GitHub settings and print a summary. Read-only; no AI.',
  '',
  'Options:',
  '  --dir <folder>        The repo folder (default: the current folder).',
  '  --allow-broad-token   Accept a classic token (it reaches every repo you have).',
  '  -h, --help            Show this help.',
  '  -v, --version         Show the version.',
  '',
  'GitHub access: set GITHUB_TOKEN to a fine-grained, read-only token for the repo. A public repo also works without one.',
];

/** Runs one pipegen command. Returns the exit code; output goes through io.out, errors and usage-on-error through io.err. */
export async function run(argv: string[], io: CliIO): Promise<number> {
  const say = (s: string) => { io.out(s); };
  const fail = (s: string) => { io.err(s); };
  let values: { dir?: string; 'allow-broad-token'?: boolean; help?: boolean; version?: boolean };
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        dir: { type: 'string' },
        'allow-broad-token': { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    }));
  } catch (e) {
    fail(safeText(e instanceof Error ? e.message : String(e), 300));
    fail('Run pipegen --help to see the options.');
    return 1;
  }
  if (values.version) {
    say(`pipegen ${version()}`);
    return 0;
  }
  const [command, ...rest] = positionals;
  if (values.help || command === undefined) {
    for (const line of USAGE) say(line);
    return 0;
  }
  if (command !== 'inspect') {
    fail(`Unknown command "${safeText(command, 60)}".`);
    for (const line of USAGE) fail(line);
    return 1;
  }
  if (rest.length > 0) {
    fail(`pipegen inspect takes no arguments (got "${safeText(rest.join(' '), 60)}"). Use --dir <folder> for another folder.`);
    return 1;
  }
  const dir = resolve(io.cwd ?? process.cwd(), values.dir ?? '.');
  try {
    return await inspect(dir, io, { allowBroad: values['allow-broad-token'] === true });
  } catch (e) {
    // Anything unexpected: one cleaned line, never a token, never a stack trace.
    fail(`pipegen inspect failed: ${safeText(hideToken(e instanceof Error ? e.message : String(e)), 500)}`);
    return 1;
  }
}

/** True when node was started on this file (directly or through the npm bin link), not when it is imported. */
function startedDirectly(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (startedDirectly()) {
  process.exitCode = await run(process.argv.slice(2), processIO());
}
