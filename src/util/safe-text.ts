// Every repo- or AI-derived string pipegen prints goes through safeText();
// every one it writes to a Markdown file goes through safeMarkdown() (see its contract below).

const DEFAULT_MAX = 200;

/**
 * P45: the cut for a repo path written into a note or a report line before the report is rendered. Longer than any path
 * a file system allows (PATH_MAX is 4096 on Linux), so in practice nothing is cut there: the renderer cuts, after it has
 * masked what the secret scan found (a cut first could leave half of a secret that then no longer matches).
 */
export const PATH_SHOWN_MAX = 4096;

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

// Invisible characters that can hide text or make two different names look the same: every Unicode
// default-ignorable code point (zero-width space, joiners, word joiner, BOM, soft hyphen, variation selectors
// incl. U+E0100-E01EF, Hangul fillers, the tag block used for "ASCII smuggling", ...) and the interlinear
// annotation characters U+FFF9-FFFB.
const INVISIBLE = /[\p{Default_Ignorable_Code_Point}\ufff9-\ufffb]/gu;
// Unicode line and paragraph separators: some editors break the line there.
const LINE_SEP = /[\u2028\u2029]/g;

/** Makes a repo-, GitHub- or AI-derived string safe to print to a terminal: one line of visible text, cut to `max` code points. */
export function safeText(s: string, max: number = DEFAULT_MAX): string {
  return cut(clean(s).replace(INVISIBLE, '').replace(LINE_SEP, ' '), max);
}

const ZWSP = '\u200b';

/**
 * Makes a repo-, search- or AI-derived string safe to put inside a Markdown document.
 *
 * Guarantee: the result is ONE inline run of inert text. Wherever the caller puts it inside its own Markdown
 * structure (a table cell, a list item, a heading's text, after other text on a line), GFM and GitHub render it
 * as the literal characters of the cleaned input and nothing else:
 * - one line: control characters (incl. CR, LF, TAB), ANSI/OSC sequences, bidi controls and every
 *   default-ignorable (invisible) code point are removed; U+2028/U+2029 become a space; leading and trailing
 *   whitespace (incl. NBSP and U+3000) is trimmed;
 * - no inline syntax: `\` `` ` `` `*` `_` `|` `~` `[` `]` are backslash-escaped; `&` `<` `>` become `&amp;`
 *   `&lt;` `&gt;` (no HTML, no `<url>` autolink, no entity such as `&#8238;` that renders as a bidi override);
 *   `$` becomes U+200B + `\$` (no GitHub math, which a backslash alone does not stop); `!` and `^` are escaped
 *   before `[` and at the end (no image or inline footnote with the caller's next `[`);
 * - no block syntax: a leading `#` `-` `+` `=` `:` or ordered-list marker (`1.` `1)`) is backslash-escaped
 *   (`:` so `:---:` can't turn the caller's previous line into a table); a leading `>` is already `&gt;`; a
 *   leading `[` gets U+200B before its escape (no task-list box); a trailing `#` is escaped (no heading closer);
 * - nothing linked or notified by GFM or GitHub: U+200B goes between every two slashes (`https:/\u200b/`),
 *   between `www` and its dot, on both sides of every `@` (mentions, emails), after `#` before a digit
 *   (`#123`, `owner/repo#1`) and between `GH` and `-` before a digit. A U+200B after `://` or `www.` would not
 *   be enough: renderers take it as part of the domain and browsers drop it from the host. Fuzzy linkifiers
 *   (some editors) may still link a bare domain such as `evil.com`;
 * - at most `max` code points; when cut, it ends with `…` and never with half an escape or half an entity,
 *   and it never ends with an unescaped backslash, so it can't escape the caller's next character.
 *
 * Caller rules:
 * - build the structure around the value and escape nothing yourself; apply safeMarkdown exactly once (a
 *   second pass escapes the first pass's backslashes and entities);
 * - never put the value inside a code span, backticks or a fenced block (escapes don't work there);
 * - the value can be empty after cleaning: put a placeholder in its place (`****` is a thematic break, an
 *   empty table cell shifts nothing but reads as missing data);
 * - don't put letters or digits right after your own closing `**`/`_` (a value ending in punctuation then
 *   can't close the emphasis).
 */
export function safeMarkdown(s: string, max: number = DEFAULT_MAX): string {
  const escaped = clean(s)
    .replace(INVISIBLE, '')
    .replace(LINE_SEP, ' ')
    .trim() // linear, and covers NBSP / U+3000 that would break the caller's emphasis
    // Inline syntax.
    .replace(/\\/g, '\\\\') // first, so later escapes aren't doubled
    .replace(/&/g, '&amp;') // before &lt; / &gt; are added; no entities
    .replace(/</g, '&lt;') // no HTML tags or <url> autolinks
    .replace(/>/g, '&gt;') // so a leading > can't start a block quote either
    .replace(/[`*_|~[\]]/g, '\\$&') // no code spans, emphasis, strikethrough, table cells, links or images
    .replace(/\$/g, `${ZWSP}\\$$`) // no GitHub math
    .replace(/[!^](?=\\\[|$)/g, '\\$&') // no image or inline footnote, even with the caller's next [
    // Block syntax at either end.
    .replace(/#$/, '\\#') // no closing heading sequence
    .replace(/^(?:[#+=:-]|(\d+)([.)]))/, (m, digits?: string, mark?: string) => (digits === undefined ? `\\${m}` : `${digits}\\${mark}`))
    .replace(/^\\\[/, `${ZWSP}\\[`) // no task-list box
    // Links and notifications.
    .replace(/\/(?=\/)/g, `/${ZWSP}`) // no `scheme://` or `//host` autolinks
    .replace(/(www)\./gi, `$1${ZWSP}.`) // no `www.` autolinks
    .replace(/@/g, `${ZWSP}@${ZWSP}`) // nobody is notified, no email autolinks
    .replace(/#(?=\d)/g, `#${ZWSP}`) // no `#123` / `owner/repo#1` references
    .replace(/\b(GH)-(?=\d)/gi, `$1${ZWSP}-`); // no `GH-123` references
  // Accepted: GitHub still links a bare commit SHA, but only to a commit in the repo the text is pasted into
  // (no notification, no cross-repo reference); breaking hex runs would spoil the pins the audit prints.
  const cutText = cut(escaped, max);
  if (cutText === escaped) return cutText;
  if (cutText === '') return ''; // max <= 0: nothing fits, not even the ellipsis
  return `${dropHalfEscape(cutText.slice(0, -1))}…`;
}

// The cut text without its ellipsis: drop an odd trailing backslash (half of `\x`) and a partial
// `&amp;` / `&lt;` / `&gt;`. A loop, not a regex, so a long run of backslashes stays linear.
function dropHalfEscape(body: string): string {
  let n = 0;
  while (n < body.length && body[body.length - 1 - n] === '\\') n++;
  if (n % 2 === 1) return body.slice(0, -1);
  return body.replace(/&[a-z]{0,3}$/, '');
}
