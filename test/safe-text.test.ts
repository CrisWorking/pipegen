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
      ['@someone', `@${Z}someone`],
      ['me@example.com', `me@${Z}example.com`],
    ];
    for (const [input, out] of cases) expect(safeMarkdown(input), input).toBe(out);
  });

  it('removes zero-width and other invisible characters from the input; line separators become spaces', () => {
    expect(safeMarkdown('ma\u200bin')).toBe('main');
    expect(safeMarkdown('a\u200cb\u200dc\u2060d\ufeffe\u00adf\u180eg')).toBe('abcdefg');
    expect(safeMarkdown('a\u{e0041}\u{e007f}b')).toBe('ab');
    expect(safeMarkdown('a\u2028b\u2029c')).toBe('a b c');
    expect(safeMarkdown('a\u200b@b')).toBe(`a@${Z}b`); // only the space safeMarkdown itself inserts remains
  });

  it('a dangling backslash stays data and never escapes what the caller adds next', () => {
    expect(safeMarkdown('a\\')).toBe('a\\\\');
    expect(safeMarkdown('\\')).toBe('\\\\');
    expect(safeMarkdown('a\\') + '|').toBe('a\\\\|'); // the caller's pipe still ends the cell
    // Cut right after an escape backslash: the half escape is dropped, not left before the ellipsis.
    expect(safeMarkdown('ab\\cd', 4)).toBe('ab…');
    expect(safeMarkdown('a[b', 3)).toBe('a…');
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
      mention: `thanks @${Z}octocat and @${Z}org/team`,
      htmlTag: '&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;',
      markdownLink: `\\[click\\](https:/${Z}/evil.example) \\!\\[img\\](https:/${Z}/evil.example/a.png)`,
      veryLong: 'a'.repeat(199) + '…',
      entityBidi: 'app&amp;#8238;fdp.exe',
      codeSpan: '\\`code\\`',
      bold: '\\*\\*bold\\*\\*',
      link: `\\[x\\](http:/${Z}/evil)`,
      image: '\\!\\[img\\](x)',
      scriptTag: '&lt;script&gt;',
      someone: `@${Z}someone`,
      wwwLink: `www${Z}.evil.com`,
      httpsLink: `https:/${Z}/evil.com`,
      heading: '\\# heading',
      orderedList: '1\\. list',
      quote: '&gt; quote',
      setext: '\\=====',
      zeroWidth: 'main',
      veryLongEscapes: '\\['.repeat(99) + '…',
    };
    expect(Object.keys(expected).sort()).toEqual(Object.keys(hostileNames).sort());
    for (const [name, value] of Object.entries(hostileNames)) expect(safeMarkdown(value), name).toBe(expected[name]);
  });
});
