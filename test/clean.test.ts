// v0.2 Plan F, F1 (ruling S5): cleanForDoc, the cleaner for every AI-written string that goes into PIPEGEN.md (builder reasons,
// suggestion `why`, judge claims, transcript lines). PIPEGEN.md is committed into the user's repository and rendered by GitHub, so
// injected repo text that makes the AI write a link, an image, HTML or an @mention must never survive (spec §19, T22, Review Focus 7).
import { describe, expect, it } from 'vitest';
import { CLEAN_DOC_MAX, CLEAN_DOC_PLACEHOLDER, cleanForDoc, stripForDoc } from '../src/debate/clean.js';
import { safeMarkdown } from '../src/util/safe-text.js';

const cps = (s: string): number => Array.from(s).length;
// Nothing a renderer turns into a link, an image, HTML or a notification.
const ACTIVE = /https?|:\/\/|www\.|javascript|vbscript|data:|mailto|evil|<|&lt;|&#|@|\uff20|\ufe6b|\]\(|!\\?\[/i;
const INVISIBLE_OR_CONTROL = /[\p{Cc}\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c\p{Default_Ignorable_Code_Point}\ufff9-\ufffb\u2028\u2029]/u;

describe('clean', () => {
  it('clean: links, HTML and @mentions removed', () => {
    const out = cleanForDoc(
      'Use [semgrep](https://evil.example/x) <b>now</b> <img src=x onerror=alert(1)> cc @octocat and @acme/security <script>run()</script> https://evil.example/y',
    );
    expect(out).toBe('Use semgrep now cc octocat and acme/security run()');
    expect(out).not.toMatch(ACTIVE);
    // an unterminated tag at the end goes too (a line starting `<div` opens an HTML block without a `>`)
    expect(cleanForDoc('ok <img src=x onerror=alert(1)')).toBe('ok');
    expect(cleanForDoc('ok <div')).toBe('ok');
    // the same through the terminal form
    expect(stripForDoc('see <a href="https://evil.example">here</a> @octocat')).toBe('see here octocat');
    expect(stripForDoc('trailing <b>')).toBe('trailing'); // no blank left where the last piece was
  });

  it('clean: one line, length capped with …', () => {
    expect(cleanForDoc('line one\nline two\r\n\tline three\u2028four\u2029five\u0085six\vseven\fend')).toBe('line one line two line three four five six seven end');
    const long = cleanForDoc('word '.repeat(200));
    expect(cps(long)).toBe(CLEAN_DOC_MAX);
    expect(CLEAN_DOC_MAX).toBe(400);
    expect(long.endsWith('…')).toBe(true);
    expect(long).not.toContain('\n');
    const short = cleanForDoc('word '.repeat(200), 50);
    expect(cps(short)).toBe(50);
    expect(short.endsWith('…')).toBe(true);
    expect(cleanForDoc('fits', 4)).toBe('fits');
    // a cap that is not a whole number of at least 1 is a caller bug
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) expect(() => cleanForDoc('x', bad), String(bad)).toThrow(RangeError);
  });

  it('clean: any scheme (javascript:, data:, mailto:), www hosts and <autolinks> removed; a Markdown link keeps its text; an image is removed whole', () => {
    const urls = [
      'javascript:alert(1)', 'JavaScript:void(0)', 'data:text/html;base64,PHNjcmlwdD4=', 'data:,x', 'mailto:someone@evil.example', 'vbscript:msgbox',
      'ftp://evil.example/x', 'HTTPS://Evil.Example', 'http://127.0.0.1:8080/', '//evil.example/x', 'www.evil.example/path', 'WWW.Evil.Example',
      '<https://evil.example>', '<mailto:x@evil.example>', '<x@evil.example>', '<irc://evil.example>',
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaajavascript:alert(1)', // a scheme longer than an autolink's 32 characters
    ];
    for (const u of urls) {
      const out = cleanForDoc(`see ${u} ok`);
      expect(out, u).toMatch(/^see (?:a+ )?ok$/);
      expect(out, u).not.toMatch(ACTIVE);
    }
    // Markdown links keep their visible text, in every form; the destination goes
    expect(cleanForDoc('read [the docs](https://evil.example/a_(b)) here')).toBe('read the docs here');
    expect(cleanForDoc('[click](javascript:alert(1)) now')).toBe('click now');
    expect(cleanForDoc('[click](<https://evil.example>) now')).toBe('click now');
    expect(cleanForDoc('a [ref link][r1] and [collapsed][] b')).toBe('a ref link and collapsed b');
    // reference definitions go, wherever the line starts
    expect(cleanForDoc('a [x] b\n[x]: https://evil.example "t"\n  [y]: <https://evil.example>\n> [z]: evil.example')).toBe('a \\[x\\] b');
    // images go whole, alt text included, in every form; a link around an image goes too
    expect(cleanForDoc('before ![alt text](https://evil.example/p.png "t") after')).toBe('before after');
    expect(cleanForDoc('before ![alt][r] ![short] after')).toBe('before after');
    expect(cleanForDoc('before [![badge](https://evil.example/b.svg)](https://evil.example) after')).toBe('before after');
    // removing one piece can't assemble another
    expect(cleanForDoc('java<b></b>script:alert(1) ok')).toBe('java ok'); // a removed tag leaves a blank, so nothing is glued
    expect(cleanForDoc('java&#x09;script:alert(1) ok')).toBe('ok'); // a removed entity leaves nothing; the URL step comes after
    expect(cleanForDoc('w@ww.evil.example ok')).toBe('ok'); // the @ goes last in a round; the next round sees www.
    expect(cleanForDoc('see x_www.evil.example ok')).toBe('see x\\_ ok'); // GFM links www. after `_` too
    expect(cleanForDoc('x <@b>bold</@b> ok')).toBe('x bold ok');
    expect(cleanForDoc('[cl<!-- -->ick](ht<i>tp://evil.example) ok')).toBe('cl ick ok');
    // not a URL: a colon before a digit (image tags, ports, versions) and a colon before a space stay
    expect(cleanForDoc('node:20 and python:3.12, because: speed')).toBe('node:20 and python:3.12, because: speed');
  });

  it('clean: HTML comments and entities removed; every @ removed (mentions, team mentions, emails)', () => {
    expect(cleanForDoc('a <!-- hidden --> b <!-- a > b --> c')).toBe('a b c');
    expect(cleanForDoc('kept <!-- unterminated, hides the rest')).toBe('kept');
    expect(cleanForDoc('x &lt;script&gt; &#x3C;b&#62; &#60 &amp; &nbsp; &#8238; &AMP; y')).toBe('x script b y');
    expect(cleanForDoc('&lt;img src=x onerror=alert(1)&gt;')).toBe('img src=x onerror=alert(1)'); // plain words now
    // a bare & is not an entity: safeMarkdown writes it as &amp; (once)
    expect(cleanForDoc('AT&T and R & D')).toBe('AT&amp;T and R &amp; D');
    const at = cleanForDoc('@octocat @acme/security-team user@example.com \uff20wide \ufe6bsmall @@double');
    expect(at).toBe('octocat acme/security-team userexample.com wide small double');
    expect(at).not.toMatch(/[@\uff20\ufe6b]/);
    expect(at).not.toContain('\u200b'); // no @ left for safeMarkdown to break up
  });

  it('clean: leading heading, table and quote characters removed', () => {
    expect(cleanForDoc('# Title\n## Sub\n| a | b |\n|---|:-:|\n> quote\n> > nested\n- item\n=== \n---\n  #  indented')).toBe('Title Sub a \\| b \\| quote nested item indented');
    // also when the start appears only after something before it was removed
    expect(cleanForDoc('<b></b>## x')).toBe('x');
    expect(cleanForDoc('<!-- c -->> quoted')).toBe('quoted');
    expect(cleanForDoc('\u200b# zero-width first')).toBe('zero-width first');
    for (const s of ['# a', '| a', '> a', '- a', '= a', ': a', '#|>-=: a']) expect(cleanForDoc(s), s).toBe('a');
  });

  it('clean: result is safeMarkdown applied exactly once (no double escape); the cap counts the output', () => {
    const x = 'use npm_audit & a*b `code` [x] ~y~ $5 back\\slash 1. step | pipe #12 a // b';
    const out = cleanForDoc(x);
    expect(out).toBe(safeMarkdown(stripForDoc(x), CLEAN_DOC_MAX));
    expect(stripForDoc(x)).toBe(x); // stripForDoc escapes nothing
    expect(out).toContain('npm\\_audit');
    expect(out).toContain('&amp;');
    expect(out).toContain('back\\\\slash');
    expect(out).not.toContain('\\\\_'); // not escaped twice
    expect(out).not.toContain('&amp;amp;');
    expect(out).not.toContain('\\\\\\\\');
    // the cap counts the escaped output, not the input
    const underscores = cleanForDoc('_'.repeat(1_000));
    expect(cps(underscores)).toBeLessThanOrEqual(CLEAN_DOC_MAX);
    expect(cps(underscores)).toBeGreaterThanOrEqual(CLEAN_DOC_MAX - 2);
    expect(underscores).toBe(safeMarkdown('_'.repeat(1_000), CLEAN_DOC_MAX));
    expect(underscores.endsWith('\\_…')).toBe(true); // never half an escape
    expect(cps(cleanForDoc('&'.repeat(300), 100))).toBeLessThanOrEqual(100);
    expect(cleanForDoc('&'.repeat(300), 100).endsWith('&amp;…')).toBe(true);
  });

  it('clean: bidi, zero-width and control characters gone; a link split by them is still removed', () => {
    const cases: [string, string][] = [
      ['see ht\u200btps://evil.example ok', 'see ok'],
      ['[cl\u200dick](ja\u202evascript:alert(1)) ok', 'click ok'],
      ['\u2066[click]\u2069(https://evil.example) ok', 'click ok'],
      ['!\u200b[pixel](https://evil.example/p.png) ok', 'ok'],
      ['@\u2060octo and \u200b@\u200bcat', 'octo and cat'],
      ['w\u00adww.evil.example ok', 'ok'],
      ['<\u200bb>bold<\u200c/b> ok', 'bold ok'],
      ['&\u200blt;b&\u200bgt; ok', 'b ok'],
      ['<!\u200b-- hidden --> ok', 'ok'],
      ['\u001b[31mred\u001b[0m \u0000nul x\u202ey tag\u{E0041}\u{E0042}s \ufeffbom \u180emongolian \u3164hangul', 'red nul xy tags bom mongolian hangul'],
      ['\u001b]8;;https://evil.example\u0007osc link\u001b]8;;\u0007', 'osc link'],
    ];
    for (const [input, want] of cases) {
      const out = cleanForDoc(input);
      expect(out, JSON.stringify(input)).toBe(want);
      expect(out, JSON.stringify(input)).not.toMatch(INVISIBLE_OR_CONTROL);
      expect(stripForDoc(input), JSON.stringify(input)).not.toMatch(INVISIBLE_OR_CONTROL);
    }
  });

  it('clean: text that is empty after cleaning gives a fixed placeholder, never \'\'', () => {
    expect(CLEAN_DOC_PLACEHOLDER).toBe('(no reason given)');
    const empties = [
      '', '   ', '\n\n', '\u200b\u202e\u2060', '<b></b>', '[](https://evil.example)', '![x](https://evil.example/p.png)', '@', '@@ \uff20',
      '<!-- all hidden -->', '# ', '| --- |', 'https://evil.example', 'www.evil.example', '&lt;&gt;&amp;', '[x]: https://evil.example',
    ];
    for (const e of empties) {
      expect(stripForDoc(e), JSON.stringify(e)).toBe('');
      expect(cleanForDoc(e), JSON.stringify(e)).toBe(CLEAN_DOC_PLACEHOLDER);
    }
    // a value that is not a string (a malformed answer) is empty, not the text "undefined"
    for (const v of [undefined, null, 42, {}]) expect(cleanForDoc(v as unknown as string)).toBe(CLEAN_DOC_PLACEHOLDER);
    // the placeholder obeys the cap too, and still is not empty
    expect(cleanForDoc('', 5)).toBe('(no …');
    expect(cleanForDoc('', 1)).toBe('…');
  });

  it('clean: linear on long hostile input (200 KiB of nested [ ( <), and text nested past the round limit gives the placeholder', () => {
    const N = 200 * 1024;
    const fill = (unit: string): string => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
    const hostile = [
      '['.repeat(N / 4) + '('.repeat(N / 4) + '<'.repeat(N / 4) + '!'.repeat(N / 4),
      fill('[a]('), fill('[a]((x'), fill('![a]('), fill('[a]['), fill('[a]('.concat('(x)')), fill('<a'), fill('<!--'), fill('<a <b '),
      fill('&#'), fill('&#x1'), fill('&a'), fill('javascript:'), fill('a.'), fill('a+b-c.d'), fill('www.'), fill('w'), fill('@'),
      fill('# | > - = '), fill('\u200b<'), fill('[\u200b('), `${'['.repeat(N / 2)}${']('.repeat(N / 4)}`, `<!--${'a'.repeat(N)}`,
      `${'<a'.repeat(N / 4)}${'>'.repeat(N / 4)}`, fill('a\n'), fill('[x]: y\n'),
    ];
    for (const h of hostile) {
      const t0 = performance.now();
      const out = cleanForDoc(h);
      const ms = performance.now() - t0;
      expect(ms, `${JSON.stringify(h.slice(0, 12))}: ${ms.toFixed(0)} ms`).toBeLessThan(1_500);
      expect(cps(out)).toBeLessThanOrEqual(CLEAN_DOC_MAX);
      expect(out).not.toBe('');
    }
    // each removal round can only expose the next layer; past the round limit the text is hostile and none of it is kept
    expect(cleanForDoc(`keep ${'<a'.repeat(3)}${'>'.repeat(3)}`)).toBe('keep');
    expect(cleanForDoc(`keep ${'<a'.repeat(50)}${'>'.repeat(50)}`)).toBe(CLEAN_DOC_PLACEHOLDER);
    expect(stripForDoc(`keep ${'<a'.repeat(50)}${'>'.repeat(50)}`)).toBe('');
  });
});
