// Every repo- or AI-derived string pipegen prints goes through safeText();
// every one it writes to a Markdown file goes through safeMarkdown() (see its contract below).

const DEFAULT_MAX = 200;

// OSC: ESC ] ... terminated by BEL or ESC \ (or end of input, so an unterminated one can't hide text).
// OSC 8 hyperlinks are two OSC sequences around the visible text, so removing both keeps only that text.
const OSC = /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)/g;
// CSI: ESC [ params intermediates final byte
const CSI = /\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]/g;
// Other two-character escapes (ESC followed by one byte), and any lone ESC left over.
const ESC_OTHER = /\x1b[\x20-\x2f]*[\x30-\x7e]?/g;
// C0 (incl. NUL, CR, LF, TAB), DEL and C1 control characters.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;
// Bidi controls: U+202A-202E, U+2066-2069, U+200E, U+200F, U+061C.
const BIDI = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/g;

function clean(s: string): string {
  return String(s).replace(OSC, '').replace(CSI, '').replace(ESC_OTHER, '').replace(CONTROL, '').replace(BIDI, '');
}

function cut(s: string, max: number): string {
  const chars = Array.from(s); // code points, so a surrogate pair is never split
  if (chars.length <= max) return s;
  if (max <= 0) return '';
  return chars.slice(0, max - 1).join('') + '…';
}

export function safeText(s: string, max: number = DEFAULT_MAX): string {
  return cut(clean(s), max);
}

// Invisible characters that can hide text or make two different names look the same: zero-width space,
// non-joiner and joiner, word joiner and invisible operators, BOM, soft hyphen, Mongolian vowel separator,
// and the Unicode tag block (invisible "ASCII smuggling").
const INVISIBLE = /[\u00ad\u180e\u200b-\u200d\u2060-\u2064\ufeff\u{e0000}-\u{e007f}]/gu;
// Unicode line and paragraph separators: some editors break the line there.
const LINE_SEP = /[\u2028\u2029]/g;
const ZWSP = '\u200b';

/**
 * Makes a repo-, search- or AI-derived string safe to put inside a Markdown document.
 *
 * Guarantee: the result is ONE inline run of inert text. Wherever the caller puts it inside its own Markdown
 * structure (a table cell, a list item, a heading's text, after other text on a line), it renders as the
 * literal characters of the cleaned input and nothing else:
 * - one line: control characters (incl. CR, LF, TAB), ANSI/OSC sequences, bidi controls and invisible
 *   characters (zero-width, BOM, soft hyphen, tag characters) are removed; U+2028/U+2029 become a space;
 *   leading and trailing spaces are trimmed;
 * - no inline syntax: `\` `` ` `` `*` `_` `|` `~` `[` `]` are backslash-escaped; `&` `<` `>` become `&amp;`
 *   `&lt;` `&gt;` (so no HTML, no `<url>` autolink, and no entity such as `&#8238;` that renders as a bidi
 *   override); `!` is escaped before `[` and at the end;
 * - no block syntax: a leading `#` `-` `+` `=` or ordered-list marker (`1.` `1)`) is backslash-escaped, and a
 *   leading `>` is already `&gt;`;
 * - no links or notifications: a zero-width space goes between every two slashes (`https:/\u200b/`), between
 *   `www` and its dot (`www\u200b.`) and after every `@`, so bare URLs, `//host` links, emails and @mentions are
 *   not linked. (A zero-width space AFTER `://` or `www.` is not enough: GFM renderers such as micromark take it
 *   as part of the domain and browsers drop it from the host, so the link would still go to the real site.)
 * - at most `max` code points; when cut, it ends with `…` and never with half an escape or half an entity,
 *   and the result never ends with an unescaped backslash, so it can't escape the caller's next character.
 *
 * Callers build the structure around the value and escape nothing themselves. Apply it once (it is not
 * idempotent: a second pass escapes the first pass's backslashes). Not for code spans or fenced code, where
 * backslash escapes don't work.
 */
export function safeMarkdown(s: string, max: number = DEFAULT_MAX): string {
  const escaped = clean(s)
    .replace(INVISIBLE, '')
    .replace(LINE_SEP, ' ')
    .replace(/^ +| +$/g, '')
    .replace(/\\/g, '\\\\') // first, so later escapes aren't doubled
    .replace(/&/g, '&amp;') // before &lt; / &gt; are added; no entities
    .replace(/</g, '&lt;') // no HTML tags or <url> autolinks
    .replace(/>/g, '&gt;') // so a leading > can't start a block quote either
    .replace(/[`*_|~[\]]/g, '\\$&') // no code spans, emphasis, strikethrough, table cells, links or images
    .replace(/!(?=\\\[|$)/g, '\\!') // no image, even with the caller's next [
    .replace(/^(?:[#+=-]|(\d+)([.)]))/, (m, digits?: string, mark?: string) => (digits === undefined ? `\\${m}` : `${digits}\\${mark}`))
    .replace(/\/(?=\/)/g, `/${ZWSP}`) // no `scheme://` or `//host` autolinks
    .replace(/(www)\./gi, `$1${ZWSP}.`) // no `www.` autolinks
    .replace(/@/g, `@${ZWSP}`); // nobody is notified, no email autolinks
  const cutText = cut(escaped, max);
  if (cutText === escaped) return cutText;
  return cutText
    .replace(/(?<!\\)((?:\\\\)*)\\…$/, '$1…') // no dangling escape backslash before the ellipsis
    .replace(/&[a-z]{0,3}…$/, '…'); // no half &amp; / &lt; / &gt;
}
