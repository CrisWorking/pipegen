// G17-F1 round 3 (sec r2 M1): NEL (U+0085), LS (U+2028) and PS (U+2029) are content to a YAML 1.2 reader but line breaks to a YAML 1.1
// one (keys.ts workflowSecretNames refuses a text that holds them raw). The `yaml` library writes them raw even inside a double-quoted
// scalar, so the renderers pass their text through here.
import { isDeepStrictEqual } from 'node:util';
import { parse } from 'yaml';

const BREAK = /[\u0085\u2028\u2029]/;
const ESCAPE: Readonly<Record<string, string>> = { '\u0085': '\\N', '\u2028': '\\L', '\u2029': '\\P' };

/**
 * The text with every NEL, LS and PS written as the YAML escape `\N`, `\L`, `\P`, or null when that is not the same document: a character
 * in a plain or single-quoted value or a block can't be escaped (its value would change), so the caller refuses or leaves the content out.
 * In a comment the escape is harmless (no reader reads a comment). Checked, not assumed: both texts are parsed and must give the same
 * value, and no raw character may be left.
 */
export function escapeLineBreaks(text: string): string | null {
  if (!BREAK.test(text)) return text;
  const out = text.replace(/[\u0085\u2028\u2029]/g, (c) => ESCAPE[c] as string);
  if (BREAK.test(out)) return null;
  try {
    if (!isDeepStrictEqual(parse(text, { version: '1.2' }), parse(out, { version: '1.2' }))) return null;
  } catch {
    return null;
  }
  return out;
}
