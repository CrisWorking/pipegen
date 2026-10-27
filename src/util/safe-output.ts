// The one output helper (Plan U ruling U10, with the T2b known-value carry-forward): every repo-, GitHub- or
// AI-derived string that `pipegen audit` (terminal, Markdown, JSON) or `pipegen inspect` prints goes through
// safeOutput(), and nothing else cleans those strings. In order:
// 1. the cleaning safeText does (ANSI/OSC, control and bidi characters, every invisible (default-ignorable) character
//    and line separator), so a value split by one of them is seen whole by the next two steps;
// 2. scrubKnownValues(knownValues): the GitHub token and the AI key in use, which redact() may not recognise;
// 3. redact(): secret-like text (a token or key used as a file, folder or service name);
// 4. safeText() for the terminal and JSON, or safeMarkdown() for Markdown, with the length cap;
// 5. a value that is empty after all that becomes EMPTY_PLACEHOLDER in human output, so it never reads as missing data
//    (and `****` can't become a Markdown thematic break); JSON keeps the empty string.
// A value redact() hides whole because it is over 4 KB (its "line too long" marker) is shown as TOO_LONG, which doesn't
// read as if a secret had been found. makeSafeOutput() works out the known values' forms once, for many strings.
// Callers apply it exactly once per value (a second safeMarkdown pass escapes the first pass's escapes), build their
// own structure around it, and never put its result inside backticks.
import { knownValueScrubber, LONG_LINE, redact } from '../ai/redact.js';
import { safeMarkdown, safeText } from './safe-text.js';

export type OutputTarget = 'terminal' | 'markdown';

/** Length caps (code points): names and ids, paths, and prose (why texts, notes, basis lines). */
export const OUTPUT_CAP = Object.freeze({ name: 200, path: 500, text: 2000 });

/** Shown in place of a value that is empty after cleaning. */
export const EMPTY_PLACEHOLDER = '(empty)';
/** Shown in place of a value over 4 KB, which redact() hides whole (masking comes before the cap, so no half token shows). */
export const TOO_LONG = '(value too long to show)';

/**
 * Known values shorter than this are not scrubbed: no real token or API key is that short, and scrubbing a short
 * value (a test placeholder such as "probe") would cut ordinary words out of the report.
 */
export const MIN_KNOWN_VALUE = 8;

const NO_CUT = Number.MAX_SAFE_INTEGER;

/** Options for one value; `knownValues` is given to makeSafeOutput instead. */
export interface CleanOptions {
  target: OutputTarget;
  /** Code points kept; default OUTPUT_CAP.name. */
  max?: number;
  /**
   * false only for pipegen's own fixed tables whose wording redact() would cut (the permission row "Secrets: read and
   * write"): those skip step 3 and keep every other step. Never false for a repo, GitHub or AI string.
   */
  redact?: boolean;
  /** Default true: an empty result becomes EMPTY_PLACEHOLDER. false for JSON, which keeps the empty string. */
  placeholder?: boolean;
}
export interface SafeOutputOptions extends CleanOptions {
  /** The GitHub token (when set) and the AI key in use. Never printed. */
  knownValues?: readonly string[];
}

/** The environment variables whose values pipegen never prints nor sends to an AI (ruling S19): the GitHub token and the AI keys. */
export const KNOWN_VALUE_VARS = Object.freeze(['GITHUB_TOKEN', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY'] as const);

/** The values of KNOWN_VALUE_VARS set in `env`, each as given and trimmed (one list for audit and inspect). */
export function knownValuesFrom(env: Readonly<Record<string, string | undefined>>): string[] {
  const out: string[] = [];
  for (const name of KNOWN_VALUE_VARS) {
    const value = env[name];
    if (typeof value === 'string' && value.trim() !== '') out.push(value, value.trim());
  }
  return out;
}

/** The known values worth scrubbing: strings of at least MIN_KNOWN_VALUE characters once trimmed. */
export function usableKnownValues(values: readonly unknown[] | undefined): string[] {
  return (values ?? []).filter((v): v is string => typeof v === 'string' && v.trim().length >= MIN_KNOWN_VALUE);
}

/** The helper for one render or one command: the known values' forms are worked out once. See the file header. */
export function makeSafeOutput(knownValues: readonly unknown[] | undefined): (s: string, opts: CleanOptions) => string {
  const known = usableKnownValues(knownValues);
  const scrub = known.length > 0 ? knownValueScrubber(known) : null;
  return (s, opts) => {
    let v = safeText(String(s), NO_CUT); // safeText strips the invisible characters and line separators too (T6)
    if (scrub !== null) v = scrub(v);
    if (opts.redact !== false) v = redact(v);
    if (v === LONG_LINE) v = TOO_LONG;
    const max = opts.max ?? OUTPUT_CAP.name;
    const out = opts.target === 'markdown' ? safeMarkdown(v, max) : safeText(v, max);
    return out.trim() === '' && opts.placeholder !== false ? EMPTY_PLACEHOLDER : out;
  };
}

/** One value through the helper (see the file header); for many values, use makeSafeOutput once. */
export function safeOutput(s: string, opts: SafeOutputOptions): string {
  return makeSafeOutput(opts.knownValues)(s, opts);
}
