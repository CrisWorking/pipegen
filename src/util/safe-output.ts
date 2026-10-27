// The one output helper (Plan U ruling U10, with the T2b known-value carry-forward): every repo-, GitHub- or
// AI-derived string that `pipegen audit` (terminal, Markdown, JSON) or `pipegen inspect` prints goes through
// safeOutput(), and nothing else cleans those strings. In order:
// 1. the cleaning safeText does (ANSI/OSC, control and bidi characters), plus every invisible (default-ignorable)
//    character and line separator, so a value split by one of them is seen whole by the next two steps;
// 2. scrubKnownValues(knownValues): the GitHub token and the AI key in use, which redact() may not recognise;
// 3. redact(): secret-like text (a token or key used as a file, folder or service name);
// 4. safeText() for the terminal and JSON, or safeMarkdown() for Markdown, with the length cap;
// 5. a value that is empty after all that becomes EMPTY_PLACEHOLDER, so it never reads as missing data (and `****`
//    can't become a Markdown thematic break).
// Callers apply it exactly once per value (a second safeMarkdown pass escapes the first pass's escapes), build their
// own structure around it, and never put its result inside backticks.
import { redact, scrubKnownValues } from '../ai/redact.js';
import { safeMarkdown, safeText } from './safe-text.js';

export type OutputTarget = 'terminal' | 'markdown';

/** Length caps (code points): names and ids, paths, and prose (why texts, notes, basis lines). */
export const OUTPUT_CAP = Object.freeze({ name: 200, path: 500, text: 2000 });

/** Shown in place of a value that is empty after cleaning. */
export const EMPTY_PLACEHOLDER = '(empty)';

/**
 * Known values shorter than this are not scrubbed: no real token or API key is that short, and scrubbing a short
 * value (a test placeholder such as "probe") would cut ordinary words out of the report.
 */
export const MIN_KNOWN_VALUE = 8;

const INVISIBLE = /[\p{Default_Ignorable_Code_Point}\ufff9-\ufffb]/gu;
const LINE_SEP = /[\u2028\u2029]/g;
const NO_CUT = Number.MAX_SAFE_INTEGER;

export interface SafeOutputOptions {
  target: OutputTarget;
  /** The GitHub token (when set) and the AI key in use. Never printed. */
  knownValues?: readonly string[];
  /** Code points kept; default OUTPUT_CAP.name. */
  max?: number;
  /**
   * false only for pipegen's own fixed tables whose wording redact() would cut (the permission row "Secrets: read and
   * write"): those skip step 3 and keep every other step. Never false for a repo, GitHub or AI string.
   */
  redact?: boolean;
}

/** The known values worth scrubbing: strings of at least MIN_KNOWN_VALUE characters once trimmed. */
export function usableKnownValues(values: readonly unknown[] | undefined): string[] {
  return (values ?? []).filter((v): v is string => typeof v === 'string' && v.trim().length >= MIN_KNOWN_VALUE);
}

/** See the file header. */
export function safeOutput(s: string, opts: SafeOutputOptions): string {
  let v = safeText(String(s), NO_CUT).replace(INVISIBLE, '').replace(LINE_SEP, ' ');
  const known = usableKnownValues(opts.knownValues);
  if (known.length > 0) v = scrubKnownValues(v, known);
  if (opts.redact !== false) v = redact(v);
  const max = opts.max ?? OUTPUT_CAP.name;
  const out = opts.target === 'markdown' ? safeMarkdown(v, max) : safeText(v, max);
  return out.trim() === '' ? EMPTY_PLACEHOLDER : out;
}
