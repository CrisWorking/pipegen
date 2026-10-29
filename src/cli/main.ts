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
import { AI_CHOICES, audit, normalizeAiFlag, type AiChoice } from './audit.js';
import { inspect } from './inspect.js';
import { processIO, type CliIO } from './io.js';

/** The help text. The run command carries the running version, exactly (ruling S30), or no command at all (U18). */
function usage(): string[] {
  const command = safeRunCommand(packageVersion());
  return [
    'Usage: pipegen <command> [options]',
    '',
    'Commands:',
    '  pipegen audit      Report which checks your CI already runs, what is missing at each layer, and what the full',
    '                     setup would add, cost and need. Read-only: it changes nothing; no AI unless --ai.',
    '  pipegen inspect    Read this repo and its GitHub settings and print a summary. Read-only; no AI.',
    '',
    'Run pipegen from OUTSIDE the repo you audit, with an exact version and npm\'s own registry, so the repo\'s',
    '.npmrc or node_modules can\'t change which pipegen runs:',
    ...(command === null ? ['  (use npm\'s registry and an exact pipegen version)'] : [`  ${command}`]),
    '',
    'Options:',
    '  --dir <folder>        The repo folder (default: the current folder).',
    '  --out <file>          audit: also write the report as Markdown. A relative path is read from the current folder,',
    '                        never from --dir. pipegen never follows a symbolic link; it replaces a file or writes',
    '                        inside the repo only with --force.',
    '  --force               audit, with --out: replace an existing regular file, or write inside the repo (never',
    '                        through a symbolic link). Not available on Windows.',
    '  --json                audit: print the report as JSON.',
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
const AUDIT_ONLY = ['out', 'force', 'json', 'ai', 'model', 'effort'] as const;

/** Runs one pipegen command. Returns the exit code; output goes through io.out, errors and usage-on-error through io.err. */
export async function run(argv: string[], io: CliIO): Promise<number> {
  const say = (s: string) => { io.out(s); };
  const fail = (s: string) => { io.err(s); };
  let values: {
    dir?: string; out?: string; force?: boolean; json?: boolean; ai?: string; model?: string; effort?: string;
    'allow-broad-token'?: boolean; help?: boolean; version?: boolean;
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
    if (t.kind !== 'option' || t.name === undefined) continue;
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
  const [command, ...rest] = positionals;
  if (values.help || command === undefined) {
    for (const line of usage()) say(line);
    return 0;
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

  if (command === 'inspect') {
    const extra = AUDIT_ONLY.find((o) => values[o] !== undefined);
    if (extra !== undefined) {
      fail(`--${extra} works with pipegen audit only.`);
      return 1;
    }
    try {
      return await inspect(resolve(cwd, values.dir ?? '.'), io, { allowBroad: values['allow-broad-token'] === true });
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
  return audit(io, {
    dir: values.dir,
    out: values.out,
    force: values.force === true,
    json: values.json === true,
    ai: values.ai === undefined ? null : { provider: values.ai === '' ? undefined : values.ai as AiChoice },
    model: values.model,
    effort: values.effort,
    allowBroad: values['allow-broad-token'] === true,
  });
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
