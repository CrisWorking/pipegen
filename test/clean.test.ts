// v0.2 Plan F, F1 (ruling S5): cleanForDoc, the cleaner for every AI-written string that goes into PIPEGEN.md (builder reasons,
// suggestion `why`, judge claims, transcript lines). PIPEGEN.md is committed into the user's repository and rendered by GitHub, so
// injected repo text that makes the AI write a link, an image, HTML or an @mention must never survive (spec §19, T22, Review Focus 7).
import { describe, expect, it } from 'vitest';
import { CLEAN_DOC_MAX, CLEAN_DOC_PLACEHOLDER, cleanForDoc, stripForDoc } from '../src/debate/clean.js';
import { findSecretLike } from '../src/ai/redact-core.js';
import { pipegenDocProblems } from '../src/engine/created-judges/pipegen-doc.js';
import { safeMarkdown } from '../src/util/safe-text.js';
import { fake } from './helpers/secret-repo.js';

const cps = (s: string): number => Array.from(s).length;
// Nothing a renderer turns into a link, an image, HTML or a notification.
const ACTIVE = /https?|:\/\/|www\.|javascript|vbscript|data:|mailto|evil|<|&lt;|&#|@|\uff20|\ufe6b|\]\(|!\\?\[/i;
// The PIPEGEN.md judge (Plan D) on a cleaned text placed where Plan G puts AI text: a list item, a table cell and a heading.
const DOC_OPTS = { owner: 'acme', repo: 'app', containsKnownValue: () => false };
const docProblems = (t: string): string[] => pipegenDocProblems(`# PIPEGEN\n\n- ${t}\n\n| Tool | Why |\n| --- | --- |\n| x | ${t} |\n\n## ${t}\n`, DOC_OPTS);
// safeMarkdown's own marks: a backslash escape, an entity, the zero-width space it puts in links and mentions, its ellipsis.
const ESCAPED = /[\\&\u200b\u2026]/;
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
    // the cut ends with ' ...': the PIPEGEN.md judge refuses U+2026 (ruling F1-R1)
    const long = cleanForDoc('word '.repeat(200));
    expect(cps(long)).toBe(CLEAN_DOC_MAX);
    expect(CLEAN_DOC_MAX).toBe(400);
    expect(long.endsWith('word w ...')).toBe(true);
    expect(long).not.toContain('\n');
    const short = cleanForDoc('word '.repeat(200), 50);
    expect(cps(short)).toBe(50);
    expect(short.endsWith(' ...')).toBe(true);
    expect(cleanForDoc('see www.x and 12345', 4)).toBe('...');
    expect(cleanForDoc('1234567890', 6)).toBe('12 ...'); // never `12...` (an ordered-list marker safeMarkdown would escape)
    expect(cleanForDoc('abc www and more', 11)).toBe('abc www ...'); // never `www...`
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
    expect(cleanForDoc('a [x] b\n[x]: https://evil.example "t"\n  [y]: <https://evil.example>\n> [z]: evil.example')).toBe('a x b');
    // images go whole, alt text included, in every form; a link around an image goes too
    expect(cleanForDoc('before ![alt text](https://evil.example/p.png "t") after')).toBe('before after');
    expect(cleanForDoc('before ![alt][r] ![short] after')).toBe('before after');
    expect(cleanForDoc('before [![badge](https://evil.example/b.svg)](https://evil.example) after')).toBe('before after');
    // removing one piece can't assemble another
    expect(cleanForDoc('java<b></b>script:alert(1) ok')).toBe('java ok'); // a removed tag leaves a blank, so nothing is glued
    expect(cleanForDoc('java&#x09;script:alert(1) ok')).toBe('ok'); // a removed entity leaves nothing; the URL step comes after
    expect(cleanForDoc('w@ww.evil.example ok')).toBe('ok'); // the @ goes last in a round; the next round sees www.
    expect(cleanForDoc('see x_www.evil.example ok')).toBe('see x ok'); // GFM links www. after `_` too
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
    // a bare & is not an entity: it is written as `and` (the judge refuses &, and safeMarkdown would write &amp;)
    expect(cleanForDoc('AT&T and R & D')).toBe('AT and T and R and D');
    const at = cleanForDoc('@octocat @acme/security-team user@example.com \uff20wide \ufe6bsmall @@double');
    expect(at).toBe('octocat acme/security-team userexample.com wide small double');
    expect(at).not.toMatch(/[@\uff20\ufe6b]/);
    expect(at).not.toContain('\u200b'); // no @ left for safeMarkdown to break up
  });

  it('clean: leading heading, table and quote characters removed', () => {
    expect(cleanForDoc('# Title\n## Sub\n| a | b |\n|---|:-:|\n> quote\n> > nested\n- item\n=== \n---\n  #  indented')).toBe('Title Sub a b quote nested item indented');
    // also when the start appears only after something before it was removed
    expect(cleanForDoc('<b></b>## x')).toBe('x');
    expect(cleanForDoc('<!-- c -->> quoted')).toBe('quoted');
    expect(cleanForDoc('\u200b# zero-width first')).toBe('zero-width first');
    for (const s of ['# a', '| a', '> a', '- a', '= a', ': a', '#|>-=: a']) expect(cleanForDoc(s), s).toBe('a');
  });

  it('clean: result is safeMarkdown applied exactly once (no double escape); the cap counts the output', () => {
    const x = 'use npm_audit & a*b `code` [x] ~y~ $5 back\\slash 1. step | pipe #12 a // b www.x GH-1 :rocket: ok!';
    const stripped = stripForDoc(x);
    expect(stripped).toBe('use npm audit and a b code x y 5 back slash 1. step pipe 12 a / / b GH 1 : rocket: ok');
    const out = cleanForDoc(x);
    expect(out).toBe(safeMarkdown(stripped, CLEAN_DOC_MAX)); // the one pass, and it has nothing left to do
    expect(out).toBe(stripped);
    expect(out).not.toMatch(ESCAPED);
    // the cap counts the output: `&` grows into ` and `, and the cut is made on that
    const amps = cleanForDoc('&'.repeat(300), 100);
    expect(cps(amps)).toBeLessThanOrEqual(100);
    expect(amps).toBe(`${'and '.repeat(24)}...`);
    expect(cleanForDoc('a'.repeat(1_000))).toBe(`${'a'.repeat(CLEAN_DOC_MAX - 4)} ...`);
  });

  it('clean: safeMarkdown is applied once and changes nothing (no backslash, no &amp;, no zero-width in the output)', () => {
    const inputs = [
      'npm_audit', 'a*b*c', '~~strike~~', '`code`', 'x|y', 'back\\slash', '$5 and $$x$$', 'AT&T', '&amp;', 'R &amp;amp; D', '#12 and GH-34 and gh-5',
      'a // b ///c', 'www.example', 'see WWW . ok www', '1. step', '12) step', '3.12 is the version', '- item', '+ item', '= x', ': x', '! end!', 'wow!!',
      'x :rocket: y :+1: z :a:b:c:', 'a~~~b', '\u201cquoted\u201d it\u2019s \u2013 dash \u2014 and\u2026', 'cafe\u0301 na\u00efve \u4e2d\u6587 \u0645\u0631\u062d\u0628\u0627',
      '\u{1F600} emoji \u2764\ufe0f', '[^1] footnote ^ caret', '{braces} <angle> and >', 'tab\there', '\u00a0nbsp\u3000ideographic',
    ];
    for (const x of inputs) {
      const out = cleanForDoc(x);
      expect(safeMarkdown(out, CLEAN_DOC_MAX), JSON.stringify(x)).toBe(out);
      expect(out, JSON.stringify(x)).not.toMatch(ESCAPED);
      expect(out, JSON.stringify(x)).not.toContain('&');
      expect(docProblems(out), JSON.stringify(x)).toEqual([]);
    }
    expect(cleanForDoc('\u201cquoted\u201d it\u2019s \u2013 dash and\u2026')).toBe('"quoted" it\'s - dash and...');
    expect(cleanForDoc('cafe\u0301 x')).toBe('caf\u00e9 x'); // NFC first, so a combining mark joins its letter
    expect(cleanForDoc('3.12 is the version')).toBe('3 .12 is the version');
    expect(cleanForDoc('1. step')).toBe('step');
    expect(cleanForDoc('+ item')).toBe('item');
    expect(cleanForDoc('= - : + x')).toBe('x');
    expect(cleanForDoc('see www\u2026 later')).toBe('see www ... later'); // the ellipsis' ASCII form can't make `www.`
    expect(cleanForDoc('a_b')).toBe('a b');
    // the fallback (safeMarkdown changed something, so the placeholder is written) never fires: stripForDoc's text is already inert
    for (const x of inputs) expect(safeMarkdown(stripForDoc(x), Number.MAX_SAFE_INTEGER), JSON.stringify(x)).toBe(stripForDoc(x));
    expect(cleanForDoc('x :rocket: y')).toBe('x : rocket: y');
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
    expect(cleanForDoc('', 5)).toBe('( ...');
    expect(cleanForDoc('', 1)).toBe('.');
    expect(docProblems(CLEAN_DOC_PLACEHOLDER)).toEqual([]);
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

  it('clean: output passes the PIPEGEN.md judge inside a list item', () => {
    const reasons = [
      // the six reasons of the F1 report's probe (R5)
      'Semgrep instead of CodeQL, because it is faster', 'uses npm_audit and eslint-plugin-security', 'Trivy (fewer false positives) & faster',
      'costs $0 and covers #12', 'see a // b', 'runs on node:20',
      // hostile ones
      'Use [semgrep](https://evil.example/x) <b>now</b> <img src=x onerror=alert(1)> cc @octocat', '![p](https://evil.example/p.png) **bold** _it_',
      '<!-- c --> &lt;script&gt; javascript:alert(1) data:,x mailto:a@b.c www.evil.example //evil.example', '# Heading\n| a | b |\n> quote\n- item\n1. one',
      'ht\u200btps://evil.example \u202eevil\u202c w\u00adww.x', '`${{ secrets.TOKEN }}` and ${{ github.token }}', ':rocket: :+1: :a_b: x:y:z',
      '~~~ fence ~~~', '```yaml', 'a\\b\\', 'end with #', 'end with !', 'GH-12 gh-3', '[x]: https://evil.example', 'C# and F# and C++',
      '\u0000\u001b[31mred \u0085next', 'see https://docs.github.com/en and https://github.com/acme/app', '1) first 2) second',
    ];
    for (const r of reasons) {
      const out = cleanForDoc(r);
      expect(docProblems(out), JSON.stringify(r)).toEqual([]);
      expect(docProblems(cleanForDoc(r, 30)), JSON.stringify(r)).toEqual([]);
    }
    expect(cleanForDoc('uses npm_audit and eslint-plugin-security')).toBe('uses npm audit and eslint-plugin-security');
    expect(cleanForDoc('Trivy (fewer false positives) & faster')).toBe('Trivy (fewer false positives) and faster');
    expect(cleanForDoc('costs $0 and covers #12')).toBe('costs 0 and covers 12');
    expect(cleanForDoc('see a // b')).toBe('see a / / b');
    // the judge reads UTF-16 units, so a letter or digit outside the BMP (math alphanumerics, CJK Extension B) is refused there:
    // the cleaner blanks it (review I1)
    expect(cleanForDoc('Use \u{1D412} now')).toBe('Use now');
    expect(cleanForDoc('Use \u{1D412}\u{1D41E}\u{1D426}\u{1D420}\u{1D42B}\u{1D41E}\u{1D429} now, \u{1D7CF} rule \u{20000}')).toBe('Use now, rule');
    expect(stripForDoc('\u{1D7CF}\u{10330}')).toBe('');
    expect(cleanForDoc('BMP letters stay: \u00e9 \u4e2d \u0645 \u2160')).toBe('BMP letters stay: \u00e9 \u4e2d \u0645 \u2160');
  });

  it('clean: seeded fuzz (5,000 hostile mixes): the output passes the PIPEGEN.md judge and safeMarkdown changes nothing', () => {
    let seed = 0x5eed_f1;
    const rnd = (): number => { // mulberry32
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
    const PIECES = [
      'word', 'Semgrep', 'because', ' ', ' ', '  ', '\n', '\r\n', '\t', '.', ',', ':', ';', '!', '?', '(', ')', '/', '//', '-', '--', '+', '=', '%', '*', '**',
      '_', '__', '~', '~~~', '`', '```', '\\', '|', '#', '##', '>', '<', '[', ']', '](', '![', '{', '}', '^', '$', '$$', '&', '&amp;', '&lt;', '&#60;',
      '&#x3c;', '&nbsp;', '@', 'a@b.c', '@octocat', '@org/team', 'www.', 'WWW.', 'http', 'https://evil.example/x', 'javascript:', 'data:', 'mailto:',
      '<b>', '</b>', '<!--', '-->', '<img src=x>', '<https://e.x>', '[t](https://e.x)', '![i](https://e.x/p.png)', '[r]: https://e.x', '1.', '12)',
      '3.12', 'node:20', ':rocket:', ':', 'GH-', 'gh-1', '#1', '${{', '}}', '\u200b', '\u200d', '\u202e', '\u2066', '\u00ad', '\u2028', '\u0085',
      '\u0000', '\u001b', '\u001b[31m', '\u0301', '\ufe0f', '\u{E0041}', '\u3164', '\u00a0', '\u3000', '\uff20', '\uff1c', '\uff0f', '\u2026',
      '\u201c', '\u2019', '\u2014', '\u4e2d', '\u00e9', '\u0645', '\u{1F600}', '\u2764', '\ud800', '\u{10FFFF}', '0', '9', 'A', 'z',
      '\u{1D400}', '\u{1D41E}\u{1D426}', '\u{1D7CF}', '\u{20000}', '\u{10330}', '\u{1D552}\u{1D553}', // astral letters and digits (review I1)
    ];
    const CAPS = [1, 4, 5, 9, 30, 200, 400];
    for (let n = 0; n < 5_000; n++) {
      let x = '';
      const len = 1 + Math.floor(rnd() * 40);
      for (let k = 0; k < len; k++) x += pick(PIECES);
      const cap = pick(CAPS);
      const out = cleanForDoc(x, cap);
      const why = `case ${n}: ${JSON.stringify(x)} cap ${cap} -> ${JSON.stringify(out)}`;
      expect(out, why).not.toBe('');
      expect(cps(out), why).toBeLessThanOrEqual(cap);
      expect(safeMarkdown(out, cap), why).toBe(out);
      const stripped = stripForDoc(x);
      expect(safeMarkdown(stripped, Number.MAX_SAFE_INTEGER), why).toBe(stripped); // so the fail-closed fallback never fires
      if (stripped !== '' && cps(stripped) <= cap) expect(out, why).toBe(stripped);
      expect(out, why).not.toMatch(ESCAPED);
      expect(docProblems(out), why).toEqual([]);
    }
  });

  it('clean: secret-shaped text gives the placeholder (the judge\'s secret check would refuse the whole doc)', () => {
    // built at runtime from pieces, like every secret-like test value (test/no-secret-literals.test.ts)
    const shapes = [
      fake.awsKey(), 'AS' + 'IA' + 'Q'.repeat(16), fake.slackBot(), 'xo' + 'xp-1-2-3', fake.jwt(), fake.openaiKey(), 'sk' + '-proj-' + 'Z'.repeat(22),
      fake.googleKey(),
    ];
    for (const shape of shapes) {
      const x = `use this key ${shape} in the job`;
      expect(findSecretLike(stripForDoc(x)), shape).not.toEqual([]); // the strip alone leaves it, so the check is what removes it
      expect(cleanForDoc(x), shape).toBe(CLEAN_DOC_PLACEHOLDER);
      expect(docProblems(cleanForDoc(x)), shape).toEqual([]);
      expect(cleanForDoc(x, 30), shape).toBe(cleanForDoc('', 30)); // a cut can't leave half of it either
    }
    // ordinary text that only looks a little like one stays
    expect(cleanForDoc('AKIA is a prefix, sk- too')).toBe('AKIA is a prefix, sk- too');
  });
});

