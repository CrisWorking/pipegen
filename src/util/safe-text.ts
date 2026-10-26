// Every repo- or AI-derived string pipegen prints goes through safeText();
// every one it writes to a Markdown file goes through safeMarkdown().

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

export function safeMarkdown(s: string, max: number = DEFAULT_MAX): string {
  const escaped = clean(s)
    .replace(/\\/g, '\\\\')
    .replace(/\[/g, '\\[') // no links, images or reference definitions
    .replace(/\]/g, '\\]')
    .replace(/!(?=\\\[)/g, '\\!')
    .replace(/</g, '&lt;') // no HTML tags or autolinks
    .replace(/>/g, '&gt;')
    .replace(/@/g, '@\u200b'); // zero-width space after @ so nobody is notified
  const cutText = cut(escaped, max);
  // Don't leave a dangling escape backslash right before the ellipsis.
  return cutText.replace(/(?<!\\)((?:\\\\)*)\\…$/, '$1…');
}
