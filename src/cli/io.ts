// The CLI's input and output seams (Plan A Task 8). Every question goes through a Prompter and every line through
// CliIO.out, so tests inject answers and read the output; the real ones wrap @clack/prompts and stdout.
import { confirm, isCancel, password, select, text } from '@clack/prompts';

/** How the CLI asks the user something. A cancelled or impossible question throws PromptCancelledError. */
export interface Prompter {
  confirm(msg: string, def: boolean): Promise<boolean>;
  select<T extends string>(msg: string, opts: { value: T; label: string; hint?: string }[], def: T): Promise<T>;
  text(msg: string, opts?: { secret?: boolean; validate?: (v: string) => string | undefined }): Promise<string>;
}

/**
 * Everything a command touches outside pipegen. `prompt`, `out` and `env` are the brief's seams; `err` takes errors,
 * warnings and usage-on-error (stderr), so a script reading `out` gets only the command's output; `cwd` (the folder
 * commands run in, default process.cwd()) and `fetch` (the transport for GitHub calls, default the global fetch) let
 * tests run a command on a temp repo against a fake GitHub. Nothing else in the CLI reads process.env or the network.
 */
export interface CliIO {
  prompt: Prompter; out: (s: string) => void; err: (s: string) => void; env: NodeJS.ProcessEnv; cwd?: string; fetch?: typeof fetch;
  /**
   * Plan J J5 (ruling S9): true only when someone can answer at a terminal (stdin and the stream questions are drawn on
   * are both TTYs). The type question is asked only then; unset or false, nothing waits for an answer.
   */
  interactive?: boolean;
}

/** The user cancelled a question (Ctrl+C / Esc), or there is no terminal to ask in. */
export class PromptCancelledError extends Error {
  constructor(message = 'Cancelled.') {
    super(message);
    this.name = 'PromptCancelledError';
  }
}

const NO_TERMINAL = 'pipegen needs an interactive terminal to ask this question.';

function answered<T>(value: T): Exclude<T, symbol> {
  if (isCancel(value)) throw new PromptCancelledError();
  return value as Exclude<T, symbol>;
}

/**
 * The real Prompter (@clack/prompts). Without an interactive terminal (stdin or stdout not a TTY, as in CI or a
 * pipe) it never guesses an answer: it throws PromptCancelledError, and askConsent turns that into No.
 */
export function clackPrompter(stdin: NodeJS.ReadStream = process.stdin, stdout: NodeJS.WriteStream = process.stdout): Prompter {
  const interactive = () => {
    if (!stdin.isTTY || !stdout.isTTY) throw new PromptCancelledError(NO_TERMINAL);
  };
  return {
    async confirm(msg, def) {
      interactive();
      return answered(await confirm({ message: msg, initialValue: def, input: stdin, output: stdout }));
    },
    async select(msg, opts, def) {
      interactive();
      return answered(await select({ message: msg, options: opts as never, initialValue: def, input: stdin, output: stdout })) as typeof def;
    },
    async text(msg, opts = {}) {
      interactive();
      const validate = opts.validate ? (v: string | undefined) => opts.validate?.(v ?? '') : undefined;
      const value = opts.secret
        ? await password({ message: msg, validate, input: stdin, output: stdout })
        : await text({ message: msg, validate, input: stdin, output: stdout });
      return answered(value);
    },
  };
}

/**
 * The CliIO a real run uses: clack prompts, stdout and stderr, the process environment and folder, the global fetch.
 * Questions are drawn on stderr (like errors), so stdout holds only the command's output (`audit --json > report.json`
 * can still ask for consent).
 */
export function processIO(): CliIO {
  return {
    prompt: clackPrompter(process.stdin, process.stderr),
    out: (s) => { process.stdout.write(`${s}\n`); },
    err: (s) => { process.stderr.write(`${s}\n`); },
    env: process.env,
    interactive: process.stdin.isTTY === true && process.stderr.isTTY === true,
  };
}
