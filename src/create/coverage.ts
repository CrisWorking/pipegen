// The coverage minimum, computed by code (v0.2 Plan D, D6; ruling B5). The AI never chooses it: Plan F's schema omits the choice
// (`coverage-thresholds-lines` for vitest, `lines` for c8), and pipegen fills it from this module. D9 (c8 policy) and Plan G consume
// coverageChoice, readExistingMinimum, measuredLines and coverageNotes.
//
//   choice = max { v in COVERAGE_MINIMUMS : v <= floor(measured) - 1 and (existing == null or v <= existing) }
//
// No value fits (measured below 61%) -> the `coverage` need is rendered NON-BLOCKING with a note; it never becomes a blocking check that can
// not pass. The repo's own higher minimum is never edited (the CLI flag overrides the config only in pipegen's job): a note says so.
// Every input is hostile repo text: reads are bounded (size caps, bounded regexes, a strict JSON parse), and anything unreadable is null plus a note.
import { COVERAGE_MINIMUMS } from '../engine/tool-flags.js';
import { activeSafeText } from '../util/known-values.js';
import { parseJsonStrict } from './package-rules.js';

/** The choices pipegen fills by code; the AI schema (Plan F) must not offer them. Keyed by reviewed entry id. */
// G2 (F2-R11 b): coverage.py's `fail-under` too, by name (not only because its values are the minimums: a later list must not hand it to the AI)
export const CODE_FILLED_CHOICES: Readonly<Record<string, string>> = Object.freeze({ 'vitest-coverage': 'coverage-thresholds-lines', c8: 'lines', 'coverage-py': 'fail-under' });
/** The AI-choosable choice names of a reviewed entry: its choices minus the one pipegen fills. */
export const aiChoiceNames = (entryId: string, choices: Readonly<Record<string, unknown>>): string[] => Object.keys(choices).filter((k) => k !== CODE_FILLED_CHOICES[entryId]);

const LOWEST = Number(COVERAGE_MINIMUMS[0]);
/** A text longer than this is not read (a config file is small; a huge one is a trap or a minified bundle). */
const MAX_TEXT = 256 * 1024;

/**
 * The highest minimum of the enum that is at most floor(measured) - 1 and at most `existing` (when there is one); null when none fits.
 * `measured` and `existing` are percentages. A value that is not a finite number in 0..100 fits nothing.
 */
export function coverageChoice(measured: number, existing: number | null): (typeof COVERAGE_MINIMUMS)[number] | null {
  if (typeof measured !== 'number' || !Number.isFinite(measured) || measured < 0 || measured > 100) return null;
  if (existing !== null && (typeof existing !== 'number' || !Number.isFinite(existing))) return null;
  const limit = Math.min(Math.floor(measured) - 1, existing ?? Number.POSITIVE_INFINITY);
  let best: (typeof COVERAGE_MINIMUMS)[number] | null = null;
  for (const v of COVERAGE_MINIMUMS) if (Number(v) <= limit) best = v;
  return best;
}

/** What the `coverage` need does: the minimum to render, or non-blocking, with the notes to show the user. */
export interface CoverageDecision { choice: (typeof COVERAGE_MINIMUMS)[number] | null; blocking: boolean; notes: string[] }

export function coverageNotes(measured: number, existing: number | null): CoverageDecision {
  if (typeof measured !== 'number' || !Number.isFinite(measured) || measured < 0 || measured > 100) {
    return { choice: null, blocking: false, notes: ['the measured coverage could not be read, so the coverage check is not blocking'] };
  }
  const choice = coverageChoice(measured, existing);
  const notes: string[] = [];
  if (choice === null) {
    // the measurement is the cause only when it is below the lowest minimum; otherwise the repo's own (lower) minimum is
    if (Math.floor(measured) - 1 >= LOWEST && existing !== null && existing < LOWEST) notes.push(`your own config asks for only ${existing}%, below pipegen's lowest minimum (${LOWEST}%), so the coverage check is not blocking`);
    else notes.push(`coverage is ${Math.floor(measured * 100) / 100}%, below pipegen's lowest minimum (${LOWEST}%), so the coverage check is not blocking`);
    return { choice: null, blocking: false, notes };
  }
  if (existing !== null && existing > Number(choice)) notes.push(`your own config still requires ${existing}% in your test job; pipegen's check uses ${choice}% and never edits your config`);
  return { choice, blocking: true, notes };
}

// ---------- the repo's own minimum ----------

export interface ExistingMinimumInput {
  /** vitest.config.* / vite.config.* files: path and text */
  vitestConfigs?: readonly { path: string; text: string }[];
  /** .c8rc* files: path and text */
  c8rcs?: readonly { path: string; text: string }[];
  /** the service's package.json text (its `c8` section) */
  packageJson?: string;
}

const pct = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 100 ? v : null);
/** `thresholds: { ... lines: N ... }` inside one flat block (no nested brace, at most 400 characters), N a plain number. */
const THRESHOLDS_RE = /\bthresholds\s*:\s*\{([^{}]{0,400})\}/g;
const LINES_RE = /(?:^|[\s,])(?:lines|'lines'|"lines")\s*:\s*([^,}]{1,40})/;
const NUMBER_RE = /^(\d{1,3})(?:\.\d{1,4})?$/;

/** From one vitest/vite config text: the `lines` minima found, and whether something was there that could not be read. */
/** `text` without `// …` line comments and `/* … *\/` block comments (bounded by the caller's size cap; no regex backtracking). */
function stripComments(text: string): string {
  let out = '';
  let i = 0;
  let quote = '';
  while (i < text.length) {
    const c = text[i] as string;
    if (quote !== '') { out += c; if (c === '\\') { out += text[i + 1] ?? ''; i += 2; continue; } if (c === quote) quote = ''; i++; continue; }
    if (c === '"' || c === "'" || c === '`') { quote = c; out += c; i++; continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (c === '/' && text[i + 1] === '*') { const end = text.indexOf('*/', i + 2); i = end < 0 ? text.length : end + 2; out += ' '; continue; }
    out += c; i++;
  }
  return out;
}

function fromVitestConfig(raw: string): { values: number[]; unreadable: boolean } {
  const text = stripComments(raw);
  const values: number[] = [];
  let unreadable = false;
  for (const m of text.matchAll(THRESHOLDS_RE)) {
    if ((m[1] as string).includes('...')) unreadable = true;   // a spread may bring a lines minimum from elsewhere
    const l = LINES_RE.exec(m[1] as string);
    if (l === null) continue;   // a thresholds block with no lines minimum
    const raw = (l[1] as string).trim();
    const v = NUMBER_RE.test(raw) ? pct(Number(raw)) : null;
    if (v === null) unreadable = true; else values.push(v);
  }
  // `thresholds` written some other way (a variable, a spread, a nested object): present but not read
  if (values.length === 0 && !unreadable && /\bthresholds\b/.test(text) && !/\bthresholds\s*:\s*\{[^{}]{0,400}\}/.test(text)) unreadable = true;
  return { values, unreadable };
}

/**
 * The repo's own `lines` minimum, or null when none is configured, one could not be read, or several disagree; `notes` say what could not be read. Bounded: a text over 256 KiB is not read.
 */
export function readExistingMinimum(input: ExistingMinimumInput): { minimum: number | null; notes: string[] } {
  const values: number[] = [];
  const notes: string[] = [];
  // the notes are written at the end (D6 N2): with a minimum read elsewhere, that one is used, and the note must not say "assumes none"
  const unread: string[] = [];
  const bad = (where: string, why: string): void => { unread.push(`pipegen could not read the coverage minimum in ${activeSafeText(where, 80)} (${why})`); };
  for (const f of input.vitestConfigs ?? []) {
    if (f.text.length > MAX_TEXT) { bad(f.path, 'the file is too large'); continue; }
    const r = fromVitestConfig(f.text);
    if (r.unreadable) bad(f.path, 'the thresholds are not a plain number'); else values.push(...r.values);
  }
  const json = (where: string, text: string, pick: (v: Record<string, unknown>) => unknown): void => {
    if (text.length > MAX_TEXT) { bad(where, 'the file is too large'); return; }
    let parsed: unknown;
    try { parsed = parseJsonStrict(text); } catch { bad(where, 'it is not plain JSON'); return; }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) { bad(where, 'it is not a JSON object'); return; }
    const section = pick(parsed as Record<string, unknown>);
    if (section === undefined) return;
    if (typeof section !== 'object' || section === null || Array.isArray(section)) { bad(where, 'the c8 section is not an object'); return; }
    const lines = (section as Record<string, unknown>).lines;
    if (lines === undefined) return;
    const v = pct(lines);
    if (v === null) bad(where, 'lines is not a number from 0 to 100'); else values.push(v);
  };
  for (const f of input.c8rcs ?? []) json(f.path, f.text, (o) => o);
  if (input.packageJson !== undefined) json('package.json', input.packageJson, (o) => o.c8);
  // several different minima (several configs, or a config and a c8 section): none is chosen, and the note says so
  const minimum = new Set(values).size > 1 ? null : values[0] ?? null;
  for (const u of unread) notes.push(minimum === null ? `${u}, so it assumes none` : `${u}, so pipegen uses the minimum it could read elsewhere`);
  if (new Set(values).size > 1) { notes.push(`pipegen found different coverage minimums in your configuration (${[...new Set(values)].sort((a, b) => a - b).join('%, ')}%) that disagree, so it assumes none`); return { minimum: null, notes }; }
  return { minimum, notes };
}

// ---------- the measured value ----------

/**
 * The `% Lines` of the `All files` row of a vitest (v8) or c8 text summary (columns: % Stmts | % Branch | % Funcs | % Lines | ...), or null.
 * Reads at most the first 1 MiB and lines of at most 400 characters.
 */
export function measuredLines(output: string): number | null {
  for (const line of output.slice(0, 1024 * 1024).split('\n')) {
    if (line.length > 400) continue;
    const m = /^\s*All files\s*\|([^\r]*)\r?$/.exec(line);
    if (m === null) continue;
    const cells = (m[1] as string).split('|').map((c) => c.trim());
    const raw = cells[3];
    if (raw === undefined || !/^\d{1,3}(?:\.\d{1,4})?$/.test(raw)) return null;
    return pct(Number(raw));
  }
  return null;
}
