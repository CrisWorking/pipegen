// The cleaner for AI-written text that goes into PIPEGEN.md (v0.2 Plan F, F1; ruling S5): builder reasons, suggestion `why`, judge
// claims and debate transcript lines. PIPEGEN.md is committed into the user's repository and rendered by GitHub, so text that a
// prompt injection made the AI write (a link, an image beacon, HTML, an @mention) must never survive (spec §19, threat T22).
//
// cleanForDoc builds on safeMarkdown (Plan A; the plan's global constraint) and is held to the PIPEGEN.md judge (Plan D,
// src/engine/created-judges/pipegen-doc.ts; ruling F1-R1: the judge is never loosened). Three steps:
//   1. strip: what a renderer would turn into a link, an image, HTML or a notification goes, so the text stays readable (a link
//      keeps its words, a URL goes instead of showing as escaped noise). Every line goes through displayForm (safe-text.ts) first,
//      so a link or a mention split by a zero-width or bidi character is whole again before the strip looks at it; there is no
//      second set of invisible characters here.
//   2. doc alphabet: only characters that the judge allows AND that safeMarkdown leaves as they are stay (letters, digits, blank,
//      . , ; : ! ? ' " ( ) / + = % -); `_` becomes a blank, `&` becomes `and`, typographic quotes, dashes and the ellipsis their
//      ASCII forms, every other character a blank. Then each place where safeMarkdown would put a backslash or U+200B, or the judge
//      would see a bare URL or an emoji shortcode, is broken with a blank (`//`, `www.`, `GH-1`, `:name:`, a leading list or
//      heading marker, a trailing `!`).
//   3. the cut (to `maxChars`, with ` ...`: the judge refuses U+2026), then safeMarkdown exactly once (S5). On this text it has
//      nothing left to do; if it ever changed something, the placeholder is written instead (fail closed).
//
// Every pattern below is linear: each one is either anchored, or scans a run of characters that can't hold its own start (so a
// failed try ends at the next start), or has a bounded repeat. The round loop is bounded too (CLEAN_ROUNDS).
import { displayForm, safeMarkdown } from '../util/safe-text.js';

/** The default cap, in code points of the output. */
export const CLEAN_DOC_MAX = 400;

/** What cleanForDoc returns when nothing is left: a fixed text, so the caller never writes an empty table cell or list item. */
export const CLEAN_DOC_PLACEHOLDER = '(no reason given)';

/**
 * The most strip rounds. One round removes every piece it can see; removing a piece can expose another one (`java<b></b>script:`,
 * `[a](<https://x>)`), so the rounds repeat until nothing changes. Ordinary text settles in two; text that still changes after
 * this many is nested on purpose, and none of it is kept.
 */
const CLEAN_ROUNDS = 8;

// Line breaks of every kind (a tab is a blank, not a break). displayForm would delete them, gluing two words into one.
const LINE_BREAKS = /\r\n?|[\n\v\f\u0085\u2028\u2029]/;
// Leading block syntax: headings (`#`, setext `=`/`-`), table pipes and alignment colons, quotes and `-` list markers, with
// blanks between them.
const LEADING = /^[\s#|>=:-]+/;
// A reference definition (`[x]: url`, also `[^1]: note`), after the leading syntax is gone: the whole line goes.
const REF_DEFINITION = /^\[[^[\]]+\]:/;

// HTML comments; an unterminated one hides the rest of the text, so it goes to the end.
const COMMENT = /<!--[\s\S]*?(?:-->|$)/g;
// HTML tags (open, close, `<!…>`, `<?…>`) and `<scheme:…>` / `<name@host>` autolinks: `<`, then a letter, `/`, `!` or `?`, up to
// the next `>`. An unterminated one at the end goes too.
const TAG = /<[a-z/!?][^<>]*(?:>|$)/gi;
// Character references: numeric (with or without `;`, as HTML decodes them) and named (with `;`). Removed, never decoded.
const ENTITY = /&#(?:x[0-9a-f]+|[0-9]+);?|&[a-z][a-z0-9]*;/gi;
// A link destination: `(…)` with one level of balanced parentheses inside (`(https://x/a_(b))`), or a reference `[…]`.
const DEST = String.raw`(?:\((?:[^()]|\([^()]*\))*\)|\[[^[\]]*\])`;
// Images, whole (alt text too): inline, reference and shortcut.
const IMAGE = new RegExp(String.raw`!\[[^[\]]*\]${DEST}?`, 'g');
// Links: inline and reference; the visible text stays. A shortcut `[x]` stays as text (safeMarkdown escapes its brackets).
const LINK = new RegExp(String.raw`\[([^[\]]*)\]${DEST}`, 'g');
// A URL: any scheme (2 to 33 characters, as long as one in an autolink can be) followed by `//`, or by anything but a blank or a
// digit, up to the next blank. A colon before a digit (`node:20`, `localhost:8080`) or a blank (`because: …`) is not a URL.
// Unanchored, so a scheme glued to a longer word (`aaaa…javascript:`) is still found.
const URL = /[a-z][a-z0-9+.-]{1,32}:(?:\/\/|(?=[^\s\d]))\S*|\/\/\S+/gi;
// `www.` hosts, up to the next blank (GFM links them without a scheme).
const WWW = /www\d{0,3}\.\S*/gi;
// Every `@` (mentions, team mentions, emails), and its fullwidth and small forms.
const AT = /[@\uff20\ufe6b]/g;
const BLANKS = /\s+/g;

// Step 2, the doc alphabet. Typographic punctuation an AI writes often, in its ASCII form.
const TYPOGRAPHIC: readonly (readonly [RegExp, string])[] = [
  [/[\u2018\u2019\u201a\u201b\u2032\u02bc]/g, "'"],
  [/[\u201c\u201d\u201e\u201f\u2033]/g, '"'],
  [/[\u2010-\u2015\u2212]/g, '-'],
  [/\u2026/g, '...'],
];
// Everything outside the doc alphabet: the judge's TEXT_CH (pipegen-doc.ts) without `_ * ~` (safeMarkdown escapes them) and
// without the backtick (a code span). It becomes a blank (so `_` does too), never nothing: dropping it could glue `www` to a
// `.` or `/` to `/`. One character at a time, so the pattern is linear.
const NOT_DOC = /[^\p{L}\p{N} .,;:!?'"()/+=%-]/gu;
// Where safeMarkdown would insert U+200B (`//`, `www.`, `GH-1`) and where the judge sees an emoji shortcode (`:name:`; its own
// pattern): a blank goes in. A blank can't complete any of these, so one pass is enough.
const SLASH_SLASH = /\/(?=\/)/g;
const WWW_DOT = /(www)\./gi;
const GH_REF = /\b(GH)-(?=\d)/gi;
const SHORTCODE = /:(?=[A-Za-z0-9_+-]+:)/g;
// Leading block syntax safeMarkdown would escape (`+ = : -`, an ordered-list marker before a blank), with the blanks around it.
const DOC_LEADING = /^(?:[ +=:-]|\d+[.)](?= ))+/;
// Digits then `.` or `)` at the start, not before a blank (`3.12`): safeMarkdown would escape the mark, so a blank goes before it.
const DOC_LEADING_NUMBER = /^(\d+)([.)])/;

/** One strip round over the joined line. */
function stripRound(s: string): string {
  return s
    .replace(COMMENT, ' ')
    .replace(TAG, ' ')
    .replace(ENTITY, '')
    .replace(IMAGE, ' ')
    .replace(LINK, '$1')
    .replace(URL, ' ')
    .replace(WWW, ' ')
    .replace(AT, '')
    .replace(BLANKS, ' ')
    .trim()
    .replace(LEADING, '');
}

/**
 * Steps 1 and 2 of cleanForDoc, with no escaping: the text as one line with URLs (any scheme, `www.` hosts, autolinks), images
 * (whole), link destinations (the visible text stays), reference definitions, HTML tags, comments and entities, every `@`, leading
 * heading, table, quote and list characters, controls, bidi and invisible characters removed, then in the doc alphabet. For the
 * terminal, which shows it through safeText. Can be '' (nothing left, or text nested past the round limit). A non-string is ''.
 */
export function stripForDoc(text: string): string {
  if (typeof text !== 'string') return '';
  const lines: string[] = [];
  for (const raw of text.split(LINE_BREAKS)) {
    const line = displayForm(raw).replace(LEADING, '');
    if (!REF_DEFINITION.test(line)) lines.push(line);
  }
  let s = lines.join(' ');
  for (let round = 0; round < CLEAN_ROUNDS; round++) {
    const next = stripRound(s);
    if (next === s) return docAlphabet(s);
    s = next;
  }
  return '';
}

/** Step 2: the stripped line in the doc alphabet, with every place safeMarkdown or the judge would act on broken by a blank. */
function docAlphabet(s: string): string {
  let t = s.normalize('NFC'); // a combining mark joins its letter first, so `e` + U+0301 stays `\u00e9`
  for (const [re, ascii] of TYPOGRAPHIC) t = t.replace(re, ascii);
  t = t
    .replace(/&/g, ' and ')
    .replace(NOT_DOC, ' ')
    .replace(SLASH_SLASH, '/ ')
    .replace(WWW_DOT, '$1 .')
    .replace(GH_REF, '$1 ')
    .replace(SHORTCODE, ': ')
    .replace(BLANKS, ' ')
    .replace(DOC_LEADING, '') // blanks at the start go here, at the end in the loop below
    .replace(DOC_LEADING_NUMBER, '$1 $2');
  // A trailing `!` (safeMarkdown escapes it) and blanks, by a loop from the end: a `[ !]+$` pattern would retry at every `!`.
  let end = t.length;
  while (end > 0 && (t[end - 1] === ' ' || t[end - 1] === '!')) end--;
  return t.slice(0, end);
}

/** Step 3's cut: at most `max` code points, ending with ` ...` when cut (the blank keeps `www`, `12` or `:x` off the dots). */
function docCut(s: string, max: number): string {
  const chars = Array.from(s);
  if (chars.length <= max) return s;
  if (max < 5) return '...'.slice(0, max);
  const kept = chars.slice(0, max - 4).join('').trimEnd();
  return kept === '' ? '...' : `${kept} ...`;
}

/**
 * AI-written text made safe for PIPEGEN.md: stripForDoc, the cut to `maxChars` (default 400; ` ...` marks a cut), then
 * safeMarkdown exactly once, which leaves this text as it is; so the cap counts the output, and the output passes the PIPEGEN.md
 * judge in a list item, a table cell or a heading. Empty → CLEAN_DOC_PLACEHOLDER (cut to the cap too), never ''.
 *
 * Caller rules (S5, F1-R1; for Plan G): the result goes into PIPEGEN.md as it is, never through safeMarkdown again, and never in a
 * code span or a fence. Code-built lines (scoreboard, tool names) go through safeMarkdown once and must pass the judge too.
 */
export function cleanForDoc(text: string, maxChars: number = CLEAN_DOC_MAX): string {
  if (!Number.isInteger(maxChars) || maxChars < 1) throw new RangeError('cleanForDoc: maxChars must be a whole number of at least 1.');
  const stripped = stripForDoc(text);
  const cut = docCut(stripped === '' ? CLEAN_DOC_PLACEHOLDER : stripped, maxChars);
  const out = safeMarkdown(cut, maxChars);
  return out === cut ? out : docCut(CLEAN_DOC_PLACEHOLDER, maxChars);
}
