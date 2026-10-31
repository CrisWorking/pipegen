// Showing text that may hold a secret value the user gave pipegen (v0.2 Plan D, D5, fix round 2). One rule for every place that prints
// or reports repo- or file-derived text: check and scrub the text AS IT WILL BE DISPLAYED (safeText joins a value split by an invisible
// character back together), and clean it BEFORE anything that cuts or escapes it (a cut leaves a prefix no scrubber can match).
import type { KnownValueCheck } from '../types.js';
import { displayForm, safeText } from './safe-text.js';

/**
 * `raw` with every vault value removed, as it would be displayed: scrub the raw text, take its display form, scrub again, and only then
 * `finish` it (default safeText: cut to 200 code points, one line). Pass your own `finish` where the output is cut or escaped differently.
 */
export function scrubForDisplay(check: Pick<KnownValueCheck, 'scrubber'>, raw: string, finish: (s: string) => string = (s) => safeText(s)): string {
  const scrub = check.scrubber();
  return finish(scrub(displayForm(scrub(String(raw)))));
}
