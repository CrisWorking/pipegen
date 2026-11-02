// Showing text that may hold a secret value the user gave pipegen (v0.2 Plan D, D5, fix rounds 2 and 3). One rule for every place that prints
// or reports repo- or file-derived text: check and scrub the text AS IT WILL BE DISPLAYED and in the forms it can be decoded or altered into,
// and clean it BEFORE anything that cuts or escapes it (a cut leaves a prefix no scrubber can match).
//
// Two layers (fix round 3):
//   1. the judges check every decoded key and scalar of what they read (anyString over a parsed workflow, package.json or draft), and
//      containsKnownValue looks at the raw text, its display form, its characters-removed form and the NFC form of each;
//   2. every helper that CUTS text for display scrubs its input first, with the vault that is active for the duration of a referee or guard call
//      (withActiveVault). With no active vault the helpers behave exactly as without this file.
// Fail closed (fix round 4): with a vault, a text that holds ESC or a C1 control counts as holding a value (layer 1) and is shown as one
// [REDACTED] (layer 2). An escape sequence can eat a character next to it and split the rest, so no decoding form is safe; pipegen never
// writes ESC or C1 into a file or a draft. This applies to text that is checked or shown, never to the content of a file. Caps that stop
// a walk (anyString) also count as holding.
// Plain cutters left elsewhere in src/engine (tool-flags.ts, npm-closure.ts, gate-job-list.ts) show only text the judges check decoded
// first; tool-flags.ts and gate-job-list.ts are in the gate bundle, so they stay as they are (review D5 r3).
import { AsyncLocalStorage } from 'node:async_hooks';
import { parseAllDocuments, visit } from 'yaml';
import type { KnownValueCheck } from '../types.js';
import { displayForm, safeText } from './safe-text.js';

/** The marker the vault scrubber puts in place of a value (redact-core's R; not imported, so the renderers' module graph stays free of src/ai). */
const R = '[REDACTED]';
/** ESC or a C1 control (U+0080 to U+009F): with a vault, a text that holds one counts as holding a value, and is never shown. */
const FAIL_CLOSED = /[\u001b\u0080-\u009f]/;
export const holdsEscape = (s: string): boolean => FAIL_CLOSED.test(s);

/** The vault check the judges use: `check.containsKnownValue`, failing closed on ESC and C1 whatever the check does. */
export const vaultHolds = (check: Pick<KnownValueCheck, 'containsKnownValue'>, t: string): boolean => holdsEscape(t) || check.containsKnownValue(t);

/** Every control (C0, DEL, C1), bidi and default-ignorable code point, removed one character at a time: no escape-sequence parsing, so ESC alone goes. */
const STRIP = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069\ufff9-\ufffb\p{Default_Ignorable_Code_Point}]/gu;
export const stripChars = (s: string): string => s.replace(STRIP, '');

/** The forms of a text a value can hide in: as written, as displayed, with controls and invisibles removed, and the NFC form of each. */
export function textForms(text: string): string[] {
  const base = [text, displayForm(text), stripChars(text)];
  return [...new Set([...base, ...base.map((t) => t.normalize('NFC'))])];
}

type Scrub = (raw: string) => string;

/** Scrub rounds before fullScrub gives up and shows the whole text as one [REDACTED]. */
const MAX_SCRUB_ROUNDS = 8;

/**
 * One scrub that covers every form in textForms (the same set layer 1 checks): while any form holds a value, the text becomes that form,
 * scrubbed (the raw text is tried first). ESC or a C1 control, or a value still held after MAX_SCRUB_ROUNDS, gives one [REDACTED].
 */
function fullScrub(check: Pick<KnownValueCheck, 'scrubber'>): Scrub {
  const sc = check.scrubber();
  return (raw) => {
    let x = String(raw);
    if (holdsEscape(x)) return R;
    for (let round = 0; round < MAX_SCRUB_ROUNDS; round++) {
      const hit = textForms(x).find((t) => sc(t) !== t);
      if (hit === undefined) return x;
      x = sc(hit);
    }
    return R;
  };
}

/**
 * `raw` with every vault value removed, as it would be displayed: scrub the raw text, then each altered form, and only then `finish` it
 * (default safeText: cut to 200 code points, one line). Pass your own `finish` where the output is cut or escaped differently.
 */
export function scrubForDisplay(check: Pick<KnownValueCheck, 'scrubber'>, raw: string, finish: (s: string) => string = (s) => safeText(s)): string {
  return finish(fullScrub(check)(raw));
}

// ---------- the active vault ----------

const active = new AsyncLocalStorage<Scrub | undefined>();

/** Runs `fn` with `check` as the active vault: the cutters below scrub with it. The previous one is restored afterwards (also on a throw); `undefined` switches it off. */
export function withActiveVault<T>(check: Pick<KnownValueCheck, 'scrubber'> | undefined, fn: () => T): T {
  return active.run(check === undefined ? undefined : fullScrub(check), fn);
}

/** `s` scrubbed with the active vault; unchanged when none is active. Call it before any cut. */
export function scrubActive(s: string): string {
  const scrub = active.getStore();
  return scrub === undefined ? s : scrub(s);
}

/** safeText that scrubs with the active vault first. The renderers, the referee and the guard import this under the name `safeText`. */
export function activeSafeText(s: string, max?: number): string {
  return safeText(scrubActive(String(s)), max);
}

// ---------- walking parsed data ----------

const MAX_DEPTH = 64;
const MAX_NODES = 1_000_000;

/** Digits from which a fractional number fails closed: the vault's shortest value (secrets.ts MIN_VALUE_LENGTH; a test keeps them equal). */
export const LONG_NUMBER_DIGITS = 8;

/**
 * Whether a decoded scalar holds a value, or null when `v` is no scalar (fix round 5, O1). A string is checked as it is; a number, bigint or
 * boolean as its text (`0xBC614E` decodes to 12345678). An integer beyond the safe range, NaN or an infinity holds: its text may be a rounded
 * piece of a value (`0xab54a98ceb1f0ad2` decodes to 12345678901234567000), and pipegen writes no such number. A fractional number (amendment)
 * is checked as its text, and holds when that text has LONG_NUMBER_DIGITS digits or more (it may be rounded), so `3.11` or `22.5` pass.
 */
function scalarHolds(v: unknown, pred: (text: string) => boolean): boolean | null {
  if (typeof v === 'string') return pred(v);
  if (typeof v === 'number') {
    if (!Number.isFinite(v) || (Number.isInteger(v) && !Number.isSafeInteger(v))) return true;
    const text = String(v);
    if (!Number.isInteger(v)) return text.replace(/\D/g, '').length >= LONG_NUMBER_DIGITS || pred(text);
    // an all-digit value with leading zeros decodes from another integer form without them (0o57060516 is 12345678): also check it zero-padded
    return pred(text) || pred(`${'0'.repeat(64)}${text.replace('-', '')}`);
  }
  if (typeof v === 'bigint' || typeof v === 'boolean') return pred(String(v));
  return null;
}

/**
 * Whether `pred` holds for any KEY or scalar leaf of `root` (strings as they are, other scalars through scalarHolds). Iterative (no stack
 * overflow), cycle-safe. Fails closed: an object deeper than 64 levels, or more than a million nodes, counts as holding (fix round 4, m1),
 * since what it would not look at could hold a value.
 */
export function anyString(root: unknown, pred: (text: string) => boolean): boolean {
  const seen = new Set<object>();
  const stack: [unknown, number][] = [[root, 0]];
  let nodes = 0;
  while (stack.length > 0) {
    const [v, depth] = stack.pop() as [unknown, number];
    if (++nodes > MAX_NODES) return true;
    const leaf = scalarHolds(v, pred);
    if (leaf !== null) { if (leaf) return true; continue; }
    if (typeof v !== 'object' || v === null || seen.has(v)) continue;
    if (depth >= MAX_DEPTH) return true;
    seen.add(v);
    if (Array.isArray(v)) { for (const x of v) stack.push([x, depth + 1]); continue; }
    for (const [k, x] of Object.entries(v)) {
      if (pred(k)) return true;
      stack.push([x, depth + 1]);
    }
  }
  return false;
}

/**
 * Whether `pred` holds for any decoded scalar (key or value; numbers through scalarHolds) of a YAML text, read leniently: every document, tags and anchors allowed,
 * aliases NOT expanded (each scalar is visited once, where it is written), parse errors tolerated. For a file the strict parse refuses
 * (fix round 4, B7) and for other .yml files. No alias is expanded, so no alias cap is needed. A text the lenient parse can not read at all is false here: the caller checks it as written.
 */
export function anyYamlScalar(text: string, pred: (text: string) => boolean): boolean {
  let found = false;
  try {
    // uniqueKeys off: duplicate keys are no error here (lenient), and the duplicate-key check is quadratic in the number of keys
    for (const doc of parseAllDocuments(text, { uniqueKeys: false })) {
      visit(doc, { Scalar(_, node) { if (scalarHolds(node.value, pred) === true) { found = true; return visit.BREAK; } return undefined; } });
      if (found) return true;
    }
  } catch { /* unreadable: the caller checks the text as written */ }
  return found;
}
