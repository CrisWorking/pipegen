// pipegen's command line (Plan A Task 8, Plan U Task 4b). `run` is the whole CLI behind the CliIO seam (tests call it
// directly); the bottom of this file runs it only when this module is the program node started (dist/cli/main.js, the
// `pipegen` bin), never when it is imported.
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { safeRunCommand } from '../audit/model.js';
import { hideToken, permissionsTable } from '../github/client.js';
import { packageVersion } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { AI_CHOICES, audit, normalizeAiFlag, unsafeFolderStop, type AiChoice } from './audit.js';
import { hookSecrets } from './hook.js';
import { inspect } from './inspect.js';
import { processIO, type CliIO } from './io.js';
import { parseTypeFlags } from './type-confirm.js';

/**
 * The help text. `npx pipegen` inside the project folder comes first (DECISIONS #124, ruling S10); the safe mode for a
 * repo you don't trust carries the running version, exactly (ruling S30), or no command at all (U18).
 */
function usage(): string[] {
  const command = safeRunCommand(packageVersion());
  return [
    'Usage: pipegen [command] [options]',
    '',
    'In your project folder:',
    '  npx pipegen        Audit this folder (the same as pipegen audit). pipegen shows the type it found for each',
    '                     service and asks "Is this right? (Y/n)" before it reads GitHub.',
    '',
    'Commands:',
    '  pipegen audit      Report which checks your CI already runs, what is missing at each layer, and what the full',
    '                     setup would add, cost and need. Read-only: it changes nothing; no AI unless --ai.',
    '  pipegen inspect    Read this repo and its GitHub settings and print a summary. Read-only; no AI.',
    '  pipegen hook secrets  What pipegen\'s pre-commit hook runs: its pinned gitleaks on the staged changes.',
    '',
    'Safe mode, for a repo you don\'t trust: run pipegen from OUTSIDE it, with an exact version and npm\'s own registry,',
    'so the repo\'s .npmrc or node_modules can\'t change which pipegen runs:',
    ...(command === null ? ['  (use npm\'s registry and an exact pipegen version)'] : [`  ${command}`]),
    'Inside a folder whose .npmrc, node_modules/.bin/pipegen or committed node_modules could change which pipegen runs,',
    `pipegen stops before reading anything and prints that command (exit code 4).`,
    '',
    'Options:',
    '  --dir <folder>        The repo folder (default: the current folder).',
    '  --type <type>         audit: set the type of the repo\'s only service, or --type <service>=<type> (give it once',
    '                        per service): static-site, library, cli, server or container. No question is asked then.',
    '  --verbose             audit: the full report in the terminal.',
    '  --out <file>          audit: also write the report as Markdown. A relative path is read from the current folder,',
    '                        never from --dir. pipegen never follows a symbolic link; it replaces a file or writes',
    '                        inside the repo only with --force.',
    '  --force               audit, with --out: replace an existing regular file, or write inside the repo (never',
    '                        through a symbolic link). Not available on Windows.',
    '  --json                audit: print the report as JSON (no question is asked).',
    '  --ai [claude|openai|ollama]',
    '                        audit: also ask an AI which checks and tools to mention. pipegen first shows what it would',
    '                        send and what it may cost, and asks you (default No). Needs Linux or macOS (WSL works).',
    '  --model <name>        With --ai: the model.',
    '  --effort <level>      With --ai claude: the effort level.',
    '  --allow-broad-token   Accept a classic token (it reaches every repo you have).',
    '  -h, --help            Show this help.',
    '  -v, --version         Show the version.',
    '',
    'GitHub access: set GITHUB_TOKEN to a fine-grained, read-only token for the repo, with',
    `  ${permissionsTable('read').map((p) => p.permission).join(', ')}.`,
    'A public repo also works without one.',
  ];
}

/** Options only `pipegen audit` takes. */
const AUDIT_ONLY = ['out', 'force', 'json', 'ai', 'model', 'effort', 'type', 'verbose'] as const;
/** Ruling S10: options that may be given more than once (each --type names one service). */
const REPEATABLE: ReadonlySet<string> = new Set(['type']);

/** Runs one pipegen command. Returns the exit code; output goes through io.out, errors and usage-on-error through io.err. */
export async function run(argv: string[], io: CliIO): Promise<number> {
  const say = (s: string) => { io.out(s); };
  const fail = (s: string) => { io.err(s); };
  let values: {
    dir?: string; out?: string; force?: boolean; json?: boolean; ai?: string; model?: string; effort?: string;
    type?: string[]; verbose?: boolean; 'allow-broad-token'?: boolean; help?: boolean; version?: boolean;
  };
  let positionals: string[];
  let tokens: { kind: string; name?: string }[];
  try {
    ({ values, positionals, tokens } = parseArgs({
      args: normalizeAiFlag(argv),
      allowPositionals: true,
      strict: true,
      tokens: true,
      options: {
        dir: { type: 'string' },
        out: { type: 'string' },
        force: { type: 'boolean' },
        json: { type: 'boolean' },
        ai: { type: 'string' },
        model: { type: 'string' },
        effort: { type: 'string' },
        type: { type: 'string', multiple: true },
        verbose: { type: 'boolean' },
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
  // a repeated option would silently use the last value (`--ai claude --ai ollama` runs Ollama): refused (review M8)
  const seen = new Set<string>();
  for (const t of tokens) {
    if (t.kind !== 'option' || t.name === undefined || REPEATABLE.has(t.name)) continue;
    if (seen.has(t.name)) {
      fail(`--${t.name} was given more than once. Give each option once.`);
      return 1;
    }
    seen.add(t.name);
  }
  if (values.version) {
    say(`pipegen ${packageVersion() ?? 'unknown'}`);
    return 0;
  }
  // DECISIONS #124: no command is `pipegen audit` (on --dir or the current folder); --help alone prints the usage
  const [given, ...rest] = positionals;
  if (values.help) {
    for (const line of usage()) say(line);
    return 0;
  }
  const command = given ?? 'audit';
  // G6: the pre-commit secrets hook's command (exactly `pipegen hook secrets`, optionally --dir); it runs only the pinned gitleaks
  if (command === 'hook') {
    const extra = Object.keys(values).find((k) => k !== 'dir' && (values as Record<string, unknown>)[k] !== undefined);
    if (rest.length !== 1 || rest[0] !== 'secrets' || extra !== undefined) {
      fail('Use: pipegen hook secrets (what pipegen\'s pre-commit hook runs). It takes no other argument or option but --dir.');
      return 1;
    }
    return hookSecrets(io, resolve(io.cwd ?? process.cwd(), values.dir ?? '.'));
  }
  if (command !== 'inspect' && command !== 'audit') {
    fail(`Unknown command "${safeText(command, 60)}".`);
    for (const line of usage()) fail(line);
    return 1;
  }
  if (rest.length > 0) {
    fail(`pipegen ${command} takes no arguments (got "${safeText(rest.join(' '), 60)}"). Use --dir <folder> for another folder.`);
    return 1;
  }
  const cwd = io.cwd ?? process.cwd();
  const dir = resolve(cwd, values.dir ?? '.');

  if (command === 'inspect') {
    const extra = AUDIT_ONLY.find((o) => values[o] !== undefined);
    if (extra !== undefined) {
      fail(`--${extra} works with pipegen audit only.`);
      return 1;
    }
    const stopped = await stopIfUnsafe(io, dir);
    if (stopped !== null) return stopped;
    try {
      return await inspect(dir, io, { allowBroad: values['allow-broad-token'] === true });
    } catch (e) {
      // Anything unexpected: one cleaned line, never a token, never a stack trace.
      fail(`pipegen inspect failed: ${safeText(hideToken(e instanceof Error ? e.message : String(e)), 500)}`);
      return 1;
    }
  }

  if (values.ai !== undefined && values.ai !== '' && !(AI_CHOICES as readonly string[]).includes(values.ai)) {
    fail(`Unknown --ai value "${safeText(values.ai, 40)}". Use ${AI_CHOICES.slice(0, -1).join(', ')} or ${AI_CHOICES.at(-1)}.`);
    return 1;
  }
  if (values.ai === undefined && (values.model !== undefined || values.effort !== undefined)) {
    fail('--model and --effort only work with --ai.');
    return 1;
  }
  if (values.force === true && values.out === undefined) {
    fail('--force only works with --out.');
    return 1;
  }
  const types = parseTypeFlags(values.type ?? []);
  if (typeof types === 'string') {
    fail(types);
    return 1;
  }
  // the stop comes before anything audit does: the --ai checks (an Ollama call), the repo read, any GitHub call
  const stopped = await stopIfUnsafe(io, dir);
  if (stopped !== null) return stopped;
  return audit(io, {
    dir: values.dir,
    out: values.out,
    force: values.force === true,
    json: values.json === true,
    ai: values.ai === undefined ? null : { provider: values.ai === '' ? undefined : values.ai as AiChoice },
    model: values.model,
    effort: values.effort,
    allowBroad: values['allow-broad-token'] === true,
    types,
    verbose: values.verbose === true,
  });
}

/** unsafeFolderStop, with an unexpected error as one cleaned line and exit 1 (never a stack trace). */
async function stopIfUnsafe(io: CliIO, dir: string): Promise<number | null> {
  try {
    return await unsafeFolderStop(io, dir);
  } catch (e) {
    io.err(`pipegen stopped: it couldn't check this folder: ${safeText(e instanceof Error ? e.message : String(e), 300)}`);
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
