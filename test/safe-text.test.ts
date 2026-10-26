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
