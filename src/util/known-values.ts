// Showing text that may hold a secret value the user gave pipegen (v0.2 Plan D, D5, fix rounds 2 and 3). One rule for every place that prints
// or reports repo- or file-derived text: check and scrub the text AS IT WILL BE DISPLAYED and in the forms it can be decoded or altered into,
// and clean it BEFORE anything that cuts or escapes it (a cut leaves a prefix no scrubber can match).
//
// Two layers (fix round 3):
//   1. the judges check every decoded key and string of what they read (anyString over a parsed workflow, package.json or draft), and
//      containsKnownValue looks at the raw text, its display form, its characters-removed form and the NFC form of each;
//   2. every helper that CUTS text for display scrubs its input first, with the vault that is active for the duration of a referee or guard call
//      (withActiveVault). With no active vault the helpers behave exactly as without this file.
import { AsyncLocalStorage } from 'node:async_hooks';
import type { KnownValueCheck } from '../types.js';
import { displayForm, safeText } from './safe-text.js';

/** Every control (C0, DEL, C1), bidi and default-ignorable code point, removed one character at a time: no escape-sequence parsing, so ESC alone goes. */
const STRIP = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069\ufff9-\ufffb\p{Default_Ignorable_Code_Point}]/gu;
export const stripChars = (s: string): string => s.replace(STRIP, '');

/** The forms of a text a value can hide in: as written, as displayed, with controls and invisibles removed, and the NFC form of each. */
export function textForms(text: string): string[] {
  const base = [text, displayForm(text), stripChars(text)];
  return [...new Set([...base, ...base.map((t) => t.normalize('NFC'))])];
}

type Scrub = (raw: string) => string;

/** One scrub that covers every form in textForms: a form that holds a value replaces the text with that form, scrubbed. */
function fullScrub(check: Pick<KnownValueCheck, 'scrubber'>): Scrub {
  const sc = check.scrubber();
  return (raw) => {
    let x = sc(String(raw));
    for (const form of [displayForm, stripChars, (t: string) => t.normalize('NFC')]) {
      const y = form(x);
      const z = sc(y);
      if (z !== y) x = z;
    }
    return x;
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

/** Whether `pred` holds for any KEY or string leaf of `root`. Iterative (no stack overflow), cycle-safe; looks no deeper than 64 levels or at more than a million nodes. */
export function anyString(root: unknown, pred: (text: string) => boolean): boolean {
  const seen = new Set<object>();
  const stack: [unknown, number][] = [[root, 0]];
  let nodes = 0;
  while (stack.length > 0) {
    const [v, depth] = stack.pop() as [unknown, number];
    if (++nodes > MAX_NODES) return false;
    if (typeof v === 'string') { if (pred(v)) return true; continue; }
    if (typeof v !== 'object' || v === null || depth >= MAX_DEPTH || seen.has(v)) continue;
    seen.add(v);
    if (Array.isArray(v)) { for (const x of v) stack.push([x, depth + 1]); continue; }
    for (const [k, x] of Object.entries(v)) {
      if (pred(k)) return true;
      stack.push([x, depth + 1]);
    }
  }
  return false;
}
