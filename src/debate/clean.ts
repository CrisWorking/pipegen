// The cleaner for AI-written text that goes into PIPEGEN.md (v0.2 Plan F, F1; ruling S5): builder reasons, suggestion `why`, judge
// claims and debate transcript lines. PIPEGEN.md is committed into the user's repository and rendered by GitHub, so text that a
// prompt injection made the AI write (a link, an image beacon, HTML, an @mention) must never survive (spec §19, threat T22).
//
// cleanForDoc builds on safeMarkdown (Plan A; the plan's global constraint): it strips what safeMarkdown would only escape, joins
// the text into one line, then applies safeMarkdown exactly once with the cap. safeMarkdown is the guarantee (inert inline text,
// no link, no HTML, no notification); the strip is the second line and keeps the text readable (a link keeps its words, a URL goes
// instead of showing as escaped noise). There is no second set of escaping rules here, and no second set of invisible characters:
// every line goes through displayForm (safe-text.ts), so a link or a mention split by a zero-width or bidi character is whole again
// before the strip looks at it.
//
// Every pattern below is linear: each one is either anchored, or scans a run of characters that can't hold its own start (so a
// failed try ends at the next start), or has a bounded repeat. The round loop is bounded too (CLEAN_ROUNDS).
import { displayForm, safeMarkdown } from '../util/safe-text.js';

/** The default cap, in code points of the output (escapes and entities count). */
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
 * Step 1 of cleanForDoc, plus the join, with no escaping: the text as one line with URLs (any scheme, `www.` hosts, autolinks),
 * images (whole), link destinations (the visible text stays), reference definitions, HTML tags, comments and entities, every `@`,
 * leading heading, table, quote and list characters, controls, bidi and invisible characters removed. For the terminal, which shows
 * it through safeText. Can be '' (nothing left, or text nested past the round limit). A non-string is ''.
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
    if (next === s) return s;
    s = next;
  }
  return '';
}

/**
 * AI-written text made safe for PIPEGEN.md: stripForDoc, then safeMarkdown exactly once with `maxChars` (default 400), so the cap
 * counts the escaped output. Empty after that → CLEAN_DOC_PLACEHOLDER (cut to the cap too), never ''.
 *
 * Caller rule (S5, for Plan G): the result goes into PIPEGEN.md as it is, never through safeMarkdown again (a second pass doubles
 * every escape). Code-built lines (scoreboard, names) go through safeMarkdown once.
 */
export function cleanForDoc(text: string, maxChars: number = CLEAN_DOC_MAX): string {
  if (!Number.isInteger(maxChars) || maxChars < 1) throw new RangeError('cleanForDoc: maxChars must be a whole number of at least 1.');
  const out = safeMarkdown(stripForDoc(text), maxChars);
  return out === '' ? safeMarkdown(CLEAN_DOC_PLACEHOLDER, maxChars) : out;
}
