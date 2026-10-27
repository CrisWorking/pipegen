import { describe, expect, it } from 'vitest';
import { safeMarkdown, safeText } from '../src/util/safe-text.js';
import { hostileNames } from './fixtures/hostile-names.js';

const ESC = '\x1b';

describe('safeText', () => {
  it('ANSI and OSC sequences removed; OSC 8 link keeps only its visible text', () => {
    expect(safeText(`${ESC}[31mred${ESC}[0m`)).toBe('red');
    expect(safeText(`${ESC}[2Japp`)).toBe('app');
    expect(safeText(`${ESC}]8;;https://evil.example${ESC}\\click me${ESC}]8;;${ESC}\\`)).toBe('click me');
    expect(safeText(`${ESC}]8;;https://evil.example\x07click me${ESC}]8;;\x07`)).toBe('click me');
    expect(safeText(`${ESC}]0;window title\x07hello`)).toBe('hello');
  });

  it('bidi characters and other control characters removed', () => {
    expect(safeText('a\u202eb\u2066c\u2069d\u200ee\u200ff\u061cg')).toBe('abcdefg');
    expect(safeText('a\x00b\rc\nd\te\x7Ff\x9bg')).toBe('abcdefg');
  });

  it('long string cut to max with …', () => {
    const r = safeText('a'.repeat(500));
    expect(r.length).toBe(200);
    expect(r.endsWith('…')).toBe(true);
    expect(safeText('abcdef', 4)).toBe('abc…');
    expect(safeText('abcd', 4)).toBe('abcd');
  });

  it('hostile-names fixture cleaned', () => {
    for (const [name, value] of Object.entries(hostileNames)) {
      for (const out of [safeText(value), safeMarkdown(value)]) {
        expect(out, name).not.toMatch(/[\u0000-\u001F\u007F-\u009F\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/);
        expect(out.length, name).toBeLessThanOrEqual(200);
      }
    }
  });
});

describe('safeMarkdown', () => {
  it('links, images, HTML and @mentions escaped', () => {
    const link = safeMarkdown('[click](https://evil.example)');
    expect(link).not.toMatch(/(^|[^\\])\]\(/);
    expect(link).not.toMatch(/(^|[^\\])\[/);
    const img = safeMarkdown('![x](https://e.example/a.png)');
    expect(img).not.toMatch(/(^|[^\\])\]\(/);
    expect(img).not.toMatch(/(^|[^\\])!/);
    const html = safeMarkdown('<script>alert(1)</script>');
    expect(html).not.toContain('<');
    expect(html).not.toContain('>');
    const m = safeMarkdown('hi @octocat and @org/team');
    expect(m).not.toMatch(/(^|[^`\u200b])@octocat/);
    expect(m).toContain('octocat');
    expect(m).toContain('org/team');
  });
});

// Plan U T0 (ruling B5): exact output for every rule. Z is the zero-width space safeMarkdown inserts. It goes
// INSIDE the autolink trigger (`:/Z/`, `wwwZ.`): after `://` or `www.` a GFM renderer still links the URL.
const Z = '\u200b';

describe('safeMarkdown exact output', () => {
  it('escapes every inline-syntax character, anywhere in the string', () => {
    const cases: [string, string][] = [
      ['a\\b', 'a\\\\b'],
      ['a`b', 'a\\`b'],
      ['a*b', 'a\\*b'],
      ['a_b', 'a\\_b'],
      ['a|b', 'a\\|b'], // table cell: the pipe can't end the cell
      ['a~b', 'a\\~b'],
      ['a&b', 'a&amp;b'],
      ['a[b]c', 'a\\[b\\]c'],
      ['a<b>c', 'a&lt;b&gt;c'],
      ['a!b', 'a!b'],
      ['![x]', '\\!\\[x\\]'],
      ['done!', 'done\\!'], // a trailing ! can't start an image with the caller's next [
      ['plain text 123', 'plain text 123'],
    ];
    for (const [input, out] of cases) expect(safeMarkdown(input), input).toBe(out);
  });

  it('neutralises a leading block marker, and only a leading one', () => {
    const cases: [string, string][] = [
      ['# heading', '\\# heading'],
      ['### h3', '\\### h3'],
      ['#tag', '\\#tag'],
      ['- item', '\\- item'],
      ['---', '\\---'],
      ['+ item', '\\+ item'],
      ['> quote', '&gt; quote'],
      ['=====', '\\====='],
      ['1. list', '1\\. list'],
      ['12) list', '12\\) list'],
      ['1.', '1\\.'],
      ['1.2.3', '1\\.2.3'],
      ['   # indented', '\\# indented'], // leading spaces trimmed, marker still escaped
      ['a # b - c + d = e 1. f > g', 'a # b - c + d = e 1. f &gt; g'],
      ['v1. x', 'v1. x'],
    ];
    for (const [input, out] of cases) expect(safeMarkdown(input), input).toBe(out);
  });

  it('defangs bare autolinks and @mentions with a zero-width space', () => {
    const cases: [string, string][] = [
      ['https://evil.com', `https:/${Z}/evil.com`],
      ['http://evil.com/a?b=c', `http:/${Z}/evil.com/a?b=c`],
      ['ftp://evil.com', `ftp:/${Z}/evil.com`],
      ['www.evil.com', `www${Z}.evil.com`],
      ['WWW.evil.com', `WWW${Z}.evil.com`],
      ['see www.a.com and https://b.com', `see www${Z}.a.com and https:/${Z}/b.com`],
      ['//evil.com/x', `/${Z}/evil.com/x`],
      ['a///b', `a/${Z}/${Z}/b`],
      ['@someone', `${Z}@${Z}someone`],
      ['me@example.com', `me${Z}@${Z}example.com`], // ZWSP on both sides: linkify-it needs it before the @
    ];
    for (const [input, out] of cases) expect(safeMarkdown(input), input).toBe(out);
  });

  it('removes zero-width and other invisible characters from the input; line separators become spaces', () => {
    expect(safeMarkdown('ma\u200bin')).toBe('main');
    expect(safeMarkdown('a\u200cb\u200dc\u2060d\ufeffe\u00adf\u180eg')).toBe('abcdefg');
    expect(safeMarkdown('a\u{e0041}\u{e007f}b')).toBe('ab');
    expect(safeMarkdown('a\u2028b\u2029c')).toBe('a b c');
    expect(safeMarkdown('a\u200b@b')).toBe(`a${Z}@${Z}b`); // only the space safeMarkdown itself inserts remains
  });

  it('a dangling backslash stays data and never escapes what the caller adds next', () => {
    expect(safeMarkdown('a\\')).toBe('a\\\\');
    expect(safeMarkdown('\\')).toBe('\\\\');
    expect(safeMarkdown('a\\') + '|').toBe('a\\\\|'); // the caller's pipe still ends the cell
    // Cut right after an escape backslash: the half escape is dropped, not left before the ellipsis.
    expect(safeMarkdown('ab\\cd', 4)).toBe('ab…');
    expect(safeMarkdown('a[b', 3)).toBe('a…');
    expect(safeMarkdown('xx' + '['.repeat(300))).toBe('xx' + '\\['.repeat(98) + '…');
    expect(safeMarkdown('ab\\\\', 5)).toBe('ab\\\\…');
  });

  it('a cut never leaves half an entity', () => {
    expect(safeMarkdown('a&b', 4)).toBe('a…');
    expect(safeMarkdown('a<b', 5)).toBe('a…');
    expect(safeMarkdown('a&b', 7)).toBe('a&amp;b');
  });

  it('keeps cleaning ANSI, OSC, control and bidi characters and capping the length', () => {
    expect(safeMarkdown(`${ESC}[31m# red${ESC}[0m`)).toBe('\\# red');
    expect(safeMarkdown('\n# x')).toBe('\\# x'); // a newline can't start a new block
    expect(safeMarkdown('a\u202eb')).toBe('ab');
    expect(safeMarkdown('abcdef', 4)).toBe('abc…');
    expect(safeMarkdown('abcd', 4)).toBe('abcd');
    expect(safeMarkdown('', 4)).toBe('');
  });

  it('hostile-names fixture: exact output for every entry', () => {
    const expected: Record<string, string> = {
      ansiColour: 'red-app',
      screenClear: 'app',
      osc8Link: 'click me',
      osc8LinkBel: 'click me',
      bidiOverride: 'appfdp.exe',
      bidiIsolates: 'app',
      nulAndCr: 'appnameOVERWRITTEN',
      newlines: 'line1line2line3tab',
      mention: `thanks ${Z}@${Z}octocat and ${Z}@${Z}org/team`,
      htmlTag: '&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;',
      markdownLink: `${Z}\\[click\\](https:/${Z}/evil.example) \\!\\[img\\](https:/${Z}/evil.example/a.png)`,
      veryLong: 'a'.repeat(199) + '…',
      entityBidi: `app&amp;#${Z}8238;fdp.exe`, // and no #8238 issue link
      codeSpan: '\\`code\\`',
      bold: '\\*\\*bold\\*\\*',
      link: `${Z}\\[x\\](http:/${Z}/evil)`,
      image: '\\!\\[img\\](x)',
      scriptTag: '&lt;script&gt;',
      someone: `${Z}@${Z}someone`,
      wwwLink: `www${Z}.evil.com`,
      httpsLink: `https:/${Z}/evil.com`,
      heading: '\\# heading',
      orderedList: '1\\. list',
      quote: '&gt; quote',
      setext: '\\=====',
      zeroWidth: 'main',
      veryLongEscapes: Z + '\\['.repeat(99) + '…', // the ZWSP makes the 199-char cut land after a whole \[
      math: `${Z}\\$x^2${Z}\\$`,
      issueRef: `\\#${Z}123`,
      ghRef: `GH${Z}-1`,
      crossRepoRef: `cli/cli#${Z}1`,
      tableDelimiter: '\\:---:',
      trailingHash: 'foo \\#',
      taskBox: `${Z}\\[ \\] x`,
      nbspWrapped: 'a',
      variationSelectors: 'ab',
      email: `me${Z}@${Z}example.com`,
    };
    expect(Object.keys(expected).sort()).toEqual(Object.keys(hostileNames).sort());
    for (const [name, value] of Object.entries(hostileNames)) expect(safeMarkdown(value), name).toBe(expected[name]);
  });
});

// Fix round 1: what the real GitHub renderer still did after T0 (rendered with `gh api /markdown`).
describe('safeMarkdown exact output: GitHub-specific syntax (fix round 1)', () => {
  it('$ math can not render: a zero-width space and a backslash go before every $', () => {
    expect(safeMarkdown('$x^2$')).toBe(`${Z}\\$x^2${Z}\\$`);
    expect(safeMarkdown('a $$b$$')).toBe(`a ${Z}\\$${Z}\\$b${Z}\\$${Z}\\$`);
  });

  it('issue and pull request references are not linked', () => {
    const cases: [string, string][] = [
      ['see #123', `see #${Z}123`],
      ['#123', `\\#${Z}123`],
      ['cli/cli#1', `cli/cli#${Z}1`],
      ['GH-1', `GH${Z}-1`],
      ['fix gh-12', `fix gh${Z}-12`],
      ['GH-x and #x', 'GH-x and #x'],
      ['&#8238;', `&amp;#${Z}8238;`],
      ['&#x202E;', '&amp;#x202E;'],
    ];
    for (const [input, out] of cases) expect(safeMarkdown(input), input).toBe(out);
  });

  it('a leading : (table delimiter row), a trailing # (heading closer) and a leading [ (task box) are neutralised', () => {
    const cases: [string, string][] = [
      [':---:', '\\:---:'],
      [':--', '\\:--'],
      ['a:b', 'a:b'],
      ['foo #', 'foo \\#'],
      ['#', '\\#'],
      ['# a #', '\\# a \\#'],
      ['a#b', 'a#b'],
      ['[ ] x', `${Z}\\[ \\] x`],
      ['[x] done', `${Z}\\[x\\] done`],
      ['a [ ] b', 'a \\[ \\] b'],
    ];
    for (const [input, out] of cases) expect(safeMarkdown(input), input).toBe(out);
  });

  it('^ before a [ or at the end is escaped (inline footnotes)', () => {
    expect(safeMarkdown('^[note]')).toBe('\\^\\[note\\]');
    expect(safeMarkdown('a^')).toBe('a\\^');
    expect(safeMarkdown('a^b')).toBe('a^b');
  });

  it('trims every kind of whitespace, so the caller\'s emphasis still closes', () => {
    expect(safeMarkdown('\u00a0a\u00a0')).toBe('a');
    expect(safeMarkdown('\u3000a b\u3000')).toBe('a b');
    expect(safeMarkdown(' \u00a0 # x')).toBe('\\# x');
  });

  it('removes every default-ignorable code point (variation selectors, Hangul fillers, ...)', () => {
    expect(safeMarkdown('a\ufe0fb')).toBe('ab');
    expect(safeMarkdown('a\u{e0100}b\u{e01ef}c')).toBe('abc');
    expect(safeMarkdown('a\u3164b\u115fc\uffa0d')).toBe('abcd');
    expect(safeMarkdown('a\u034fb\u17b4c\ufff9d\ufffbe')).toBe('abcde');
  });

  it('runs in linear time on long runs of spaces and backslashes', () => {
    const t0 = performance.now();
    expect(safeMarkdown('a' + ' '.repeat(80000) + 'x')).toBe('a' + ' '.repeat(198) + '…');
    expect(safeMarkdown('\\'.repeat(80000), 80000)).toBe('\\'.repeat(79998) + '…');
    expect(performance.now() - t0).toBeLessThan(1000); // linear takes ~1–14 ms; the old quadratic trim took ~4.3 s
  });

  it('safeMarkdown: max <= 0 gives an empty string, never a lone ellipsis', () => {
    expect(safeMarkdown('abc', 0)).toBe('');
    expect(safeMarkdown('abc', -1)).toBe('');
  });
});
