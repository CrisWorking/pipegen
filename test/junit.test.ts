// v0.2 Plan D, D8 (plan Task 6; rulings S10, S12): JUnit parsing. The XML comes from repo code, so it is hostile input.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MAX_JUNIT_ATTRIBUTES, MAX_JUNIT_TAGS, normaliseTestId, parseJunit, sameResults, type TestCaseResult } from '../src/create/junit.js';

const fixture = (name: string): string => readFileSync(new URL(`./fixtures/junit/${name}`, import.meta.url), 'utf8');
const VITEST = 'vitest-5.0.5.xml';
const JEST = 'jest-junit-17.0.0-configured.xml';
const JEST_DEFAULT = 'jest-junit-17.0.0-default.xml';
const r = (id: string, status: TestCaseResult['status'] = 'pass'): TestCaseResult => ({ id, status });
const suite = (cases: string): string => `<testsuites><testsuite name="s">${cases}</testsuite></testsuites>`;
const messageOf = (fn: () => unknown): string => { try { fn(); } catch (e) { return (e as Error).message; } throw new Error('did not throw'); };

describe('junit', () => {
  it('junit: jest-junit and vitest junit parsed', () => {
    const expected = [
      r('math.test > math > adds'),
      r('math.test > math > fails on purpose', 'fail'),
      r('math.test > math > is skipped', 'skip'),
      r('math.test > math > nested > deeper > multiplies'),
      r('math.test > math > nested > __proto__'),
    ];
    expect(parseJunit(fixture(VITEST))).toEqual(expected);
    expect(parseJunit(fixture(JEST))).toEqual(expected);
  });

  it('junit: real vitest 5.0.5 junit fixture (captured locally) and a jest-junit fixture', () => {
    // jest-junit with its DEFAULT options writes no file and one joined name: the id has no file part, and still parses.
    expect(parseJunit(fixture(JEST_DEFAULT))).toEqual([
      r('math adds'),
      r('math fails on purpose', 'fail'),
      r('math is skipped', 'skip'),
      r('math nested deeper multiplies'),
      r('math nested __proto__'),
    ]);
    const vitest = parseJunit(fixture(VITEST));
    expect(fixture(VITEST)).toContain('vitest tests');
    expect(vitest).toHaveLength(5);
    expect(vitest.map((c) => c.status)).toEqual(['pass', 'fail', 'skip', 'pass', 'pass']);
    expect(vitest.at(-1)?.id).toBe('math.test > math > nested > __proto__');
    expect(fixture(JEST_DEFAULT)).toContain('jest tests');
  });

  it('junit: skipped and failed statuses', () => {
    const xml = suite([
      '<testcase classname="a.test.ts" name="ok"/>',
      '<testcase classname="a.test.ts" name="f"><failure message="x"/></testcase>',
      '<testcase classname="a.test.ts" name="e"><error message="x"/></testcase>',
      '<testcase classname="a.test.ts" name="s"><skipped/></testcase>',
      '<testcase classname="a.test.ts" name="s2"><skipped message="why"></skipped></testcase>',
      '<testcase classname="a.test.ts" name="both"><skipped/><failure/></testcase>',
      '<testcase classname="a.test.ts" name="out"><system-out>failure error skipped</system-out></testcase>',
    ].join(''));
    expect(parseJunit(xml).map((c) => `${c.id}=${c.status}`)).toEqual([
      'a.test > ok=pass', 'a.test > f=fail', 'a.test > e=fail', 'a.test > s=skip', 'a.test > s2=skip', 'a.test > both=fail', 'a.test > out=pass',
    ]);
  });

  it('junit: a single testcase, a bare testsuite root and nested suites are read', () => {
    expect(parseJunit('<testsuite name="x"><testcase classname="a.test.ts" name="one"/></testsuite>')).toEqual([r('a.test > one')]);
    expect(parseJunit(suite('<testcase classname="a.test.ts" name="one"/>'))).toEqual([r('a.test > one')]);
    const nested = '<testsuites><testsuite name="o"><testsuite name="i"><testcase classname="a.test.ts" name="deep"/></testsuite><testcase classname="a.test.ts" name="top"/></testsuite></testsuites>';
    expect(parseJunit(nested).map((c) => c.id).sort()).toEqual(['a.test > deep', 'a.test > top']);
    expect(parseJunit('<testsuites/>')).toEqual([]);
    expect(parseJunit('<testsuites><testsuite name="empty"/></testsuites>')).toEqual([]);
  });

  it('junit: entities in names are the five XML ones and number references, decoded once', () => {
    const xml = suite('<testcase classname="a.test.ts" name="x &gt; y &amp;lt; &quot;q&quot; &apos;a&apos; &#65;&#x42; &lt;t&gt; &bogus; &#xD800; &#99999999; &#0; &#1114112; &#1114111;"/>');
    expect(parseJunit(xml)[0]?.id).toBe('a.test > x > y &lt; "q" \'a\' ab <t> &bogus; &#xd800; &#99999999; &#0; &#1114112; \u{10ffff}');
  });

  it('junit: DOCTYPE or ENTITY → error; over 16 MiB or 50,000 cases → error', () => {
    const lol = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><testsuites><testsuite name="s"><testcase name="&lol2;" classname="a.test.ts"/></testsuite></testsuites>';
    expect(() => parseJunit(lol)).toThrow(/DOCTYPE|ENTITY|entity|entities/);
    expect(() => parseJunit('<!doctype x><testsuites/>')).toThrow();
    expect(() => parseJunit('<testsuites><!entity x "y"></testsuites>')).toThrow();
    expect(() => parseJunit('<testsuites><testsuite name="s"><testcase name="a" classname="b"><system-out><![CDATA[<!DOCTYPE x>]]></system-out></testcase></testsuite></testsuites>')).toThrow();
    // size: the cap counts UTF-8 bytes (a 3-byte character), not characters
    const MiB16 = 16 * 1024 * 1024;
    const pad = (n: number): string => `<testsuites><!--${'a'.repeat(n)}--></testsuites>`;
    expect(Buffer.byteLength(pad(MiB16 - 32))).toBe(MiB16);
    expect(parseJunit(pad(MiB16 - 32))).toEqual([]);
    expect(() => parseJunit(pad(MiB16 - 31))).toThrow(/16 MiB/);
    const wide = `<testsuites><!--${'€'.repeat(Math.floor(MiB16 / 3))}--></testsuites>`;
    expect(wide.length).toBeLessThan(MiB16);
    expect(() => parseJunit(wide)).toThrow(/16 MiB/);
    // case count
    const many = (n: number): string => suite(Array.from({ length: n }, (_, i) => `<testcase classname="a" name="t${i}"/>`).join(''));
    expect(parseJunit(many(50_000))).toHaveLength(50_000);
    expect(() => parseJunit(many(50_001))).toThrow(/50,000/);
    // the cases are counted in the text too, before any tree is built (a tag the parser would count differently)
    expect(() => parseJunit(`<testsuites>${'<testcase name="a"/>'.repeat(50_001)}</testsuites>`)).toThrow(/50,000/);
  });

  it('junit: the case cap counts the text, so cases hidden from the tree are counted too', () => {
    const inComment = (n: number): string => `<testsuites><!--${'<testcase name="a"/>'.repeat(n)}--></testsuites>`;
    expect(parseJunit(inComment(50_000))).toEqual([]);
    expect(() => parseJunit(inComment(50_001))).toThrow(/50,000/);
  });

  it('junit: test suites nested too deep are refused', () => {
    const nest = (n: number): string => `<testsuites>${'<testsuite name="s">'.repeat(n)}<testcase name="t" classname="a.test.ts"/>${'</testsuite>'.repeat(n)}</testsuites>`;
    expect(parseJunit(nest(60))).toEqual([r('a.test > t')]);
    expect(() => parseJunit(nest(70))).toThrow(/deeper/);
  });

  it('junit: every markup declaration is refused, not only DOCTYPE and ENTITY (review I1)', () => {
    for (const bad of ['<! x>', '<!\tENTITY x "y">', '<!ELEMENT a ANY>', '<!ATTLIST a b CDATA #IMPLIED>', '<!NOTATION n SYSTEM "x">', '<!>', '<! DOCTYPE x>', '<!-x>', '<![IGNORE[x]]>']) {
      expect(() => parseJunit(`<testsuites><testsuite name="s"><testcase classname="a.test.ts" name="x">${bad}</testcase></testsuite></testsuites>`), bad).toThrow(/declaration/);
    }
    // a comment and a CDATA section are fine
    expect(parseJunit('<testsuites><testsuite name="s"><!-- c --><testcase classname="a.test.ts" name="x"><system-out><![CDATA[ok]]></system-out></testcase></testsuite></testsuites>')).toEqual([r('a.test > x')]);
    // the flood that used to cost 1.8 GB is refused before any parsing, fast
    const flood = `<testsuites><testsuite name="s"><testcase classname="a.test.ts" name="x">${'<! '.repeat(5_000_000)}</testcase></testsuite></testsuites>`;
    const t = performance.now();
    expect(() => parseJunit(flood)).toThrow(/declaration/);
    expect(performance.now() - t).toBeLessThan(1000);
  });

  it('junit: a report that is not well-formed XML is refused (review M1)', () => {
    const tc = '<testcase classname="a.test.ts" name="y"/>';
    for (const bad of [
      `<testsuites><testsuite>${tc}`, // truncated
      `<testsuites><testsuite><testcase classname="a.test.ts" name="y"><failure></testcase></testsuite></testsuites>`, // mismatched close
      `<testsuites><testsuite><testcase classname="a.test.ts" name="y" name="z"/></testsuite></testsuites>`, // repeated attribute
      `<testsuites><testsuite><testcase classname="a.test.ts"><@_name>spoofed</@_name></testcase></testsuite></testsuites>`, // element posing as an attribute
      `<testsuites><testsuite><testcase classname="a.test.ts"><@_file>x.test.ts</@_file></testcase></testsuite></testsuites>`,
    ]) expect(() => parseJunit(bad), bad).toThrow(/not well-formed XML/);
    const m = messageOf(() => parseJunit(`<testsuites><testsuite><\u001b[31mEVIL\u202e`));
    expect(m).toMatch(/not well-formed XML/);
    expect(m).not.toMatch(/EVIL|[\u001b\u202e]/);
    expect(parseJunit(fixture(VITEST))).toHaveLength(5);
  });

  it('junit: counts on a testsuite that contradict what was parsed are refused (review I2)', () => {
    const t = '<testcase classname="a.test.ts" name="n"/>';
    const f = '<testcase classname="a.test.ts" name="f"><failure/></testcase>';
    const sk = '<testcase classname="a.test.ts" name="s"><skipped/></testcase>';
    const bad = [
      `<testsuites failures="3"><testsuite failures="3">${t}</testsuite></testsuites>`, // the reviewer's repro
      `<testsuites tests="3"/>`,
      `<testsuites tests="3"><testsuite name="x">text only</testsuite></testsuites>`,
      `<testsuites tests="2"><testsuite>${t}</testsuite></testsuites>`,
      `<testsuite tests="1" failures="1">${t}</testsuite>`,
      `<testsuite tests="2" skipped="0">${t}${sk}</testsuite>`,
      `<testsuite tests="2" errors="1">${t}${t.replace('"n"', '"m"')}</testsuite>`,
      `<testsuite tests="1" failures="0" errors="0">${f}</testsuite>`,
      `<testsuite tests="two">${t}</testsuite>`,
      `<testsuite tests="-1">${t}</testsuite>`,
      `<testsuites tests="1"><testsuite tests="1"><j:testcase classname="a.test.ts" name="n"/></testsuite></testsuites>`, // namespaced tag
      `<testsuites tests="1"><testsuite><TESTCASE classname="a.test.ts" name="n"/></testsuite></testsuites>`, // upper case
      `<testsuites tests="1"><testsuite><testsuites><testcase classname="a.test.ts" name="n"/></testsuites></testsuite></testsuites>`, // nested testsuites
      `<testsuites tests="2"><testsuite tests="1">${t}</testsuite></testsuites>`, // a child suite is outside the count of the other
    ];
    for (const xml of bad) expect(() => parseJunit(xml), xml).toThrow(/count|number/);
    expect(() => parseJunit(`<testsuite tests="two">${t}</testsuite>`)).toThrow(/not a number/);
    expect(() => parseJunit(`<testsuite tests="-1">${t}</testsuite>`)).toThrow(/not a number/);
    expect(() => parseJunit(`<testsuite failures="1.5">${f}</testsuite>`)).toThrow(/not a number/);
    const ok = [
      `<testsuites tests="3" failures="1" errors="0" skipped="1"><testsuite tests="3" failures="1" skipped="1">${t}${f}${sk}</testsuite></testsuites>`,
      `<testsuite tests="2" failures="0" errors="1">${t}<testcase classname="a.test.ts" name="e"><error/></testcase></testsuite>`,
      `<testsuites tests="2"><testsuite tests="1">${t}</testsuite><testsuite tests="1">${t.replace('"n"', '"m"')}</testsuite></testsuites>`,
      `<testsuites tests="2"><testsuite><testsuite tests="1">${t}</testsuite>${t.replace('"n"', '"m"')}</testsuite></testsuites>`, // counts include nested suites
      `<testsuite name="no counts">${t}</testsuite>`,
    ];
    for (const xml of ok) expect(parseJunit(xml).length, xml).toBeGreaterThan(0);
    expect(parseJunit(fixture(VITEST))).toHaveLength(5);
    expect(parseJunit(fixture(JEST))).toHaveLength(5);
    expect(parseJunit(fixture(JEST_DEFAULT))).toHaveLength(5);
  });

  it('junit: reports that parse to nothing never give a pass (review I2)', () => {
    const empties = [
      '<testsuites/>',
      '<testsuites>hello</testsuites>',
      '<testsuites><testsuite>txt</testsuite></testsuites>',
      '<testsuites><testsuite><j:testcase classname="a.test.ts" name="n"/></testsuite></testsuites>',
      '<testsuites><testsuite><TESTCASE classname="a.test.ts" name="n"/></testsuite></testsuites>',
      '<testsuites><testsuite><testsuites><testcase classname="a.test.ts" name="n"/></testsuites></testsuite></testsuites>',
    ];
    for (const xml of empties) {
      const run = parseJunit(xml);
      expect(run, xml).toEqual([]);
      expect(sameResults(run, run).ok, xml).toBe(false);
    }
  });

  it('junit: many attributes are capped, so the slowest input stays fast (review M2)', () => {
    const attrs = (n: number): string => Array.from({ length: n }, (_, i) => `a${i}=""`).join(' ');
    const doc = (n: number): string => `<testsuites><testsuite name="s"><testcase classname="a.test.ts" name="x" ${attrs(n)}/></testsuite></testsuites>`;
    expect(parseJunit(doc(1000))).toHaveLength(1);
    // the cap counts attribute-shaped text (name="..."), with spaces around the = too
    expect(parseJunit(doc(MAX_JUNIT_ATTRIBUTES - 3))).toHaveLength(1); // 3 more in the frame
    expect(() => parseJunit(doc(MAX_JUNIT_ATTRIBUTES - 2))).toThrow(/attributes/);
    expect(() => parseJunit(`<testsuites><!--${"a = '' ".repeat(MAX_JUNIT_ATTRIBUTES + 1)}--></testsuites>`)).toThrow(/attributes/);
    expect(() => parseJunit(`<testsuites><!--${'a = "" '.repeat(MAX_JUNIT_ATTRIBUTES + 1)}--></testsuites>`)).toThrow(/attributes/);
    const t = performance.now();
    expect(() => parseJunit(doc(MAX_JUNIT_ATTRIBUTES - 10))).not.toThrow();
    expect(performance.now() - t).toBeLessThan(10_000); // measured about 1.5 s here; the margin is for slow CI machines
  });

  it('junit: too many tags are capped too (review M2)', () => {
    const doc = (n: number): string => `<testsuites><testsuite name="s"><testcase classname="a.test.ts" name="x">${'<a/>'.repeat(n)}</testcase></testsuite></testsuites>`;
    expect(parseJunit(doc(1000))).toHaveLength(1);
    // exactly at the cap: the frame has 6 '<', each <a/> one
    expect(parseJunit(doc(MAX_JUNIT_TAGS - 6))).toHaveLength(1);
    expect(() => parseJunit(doc(MAX_JUNIT_TAGS - 5))).toThrow(/tags/);
    expect(() => parseJunit(`<testsuites>${'<'.repeat(MAX_JUNIT_TAGS + 1)}</testsuites>`)).toThrow(/tags/);
    // the largest legal shape (50,000 cases, each with a failure and output) is well under the cap
    const big = suite(Array.from({ length: 50_000 }, (_, i) => `<testcase classname="a.test.ts" name="t${i}"><failure message="m"/><system-out>o</system-out></testcase>`).join(''));
    expect(parseJunit(big)).toHaveLength(50_000);
  });

  it('junit: __proto__/constructor names parse as data', () => {
    const xml = suite(['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty'].map((n) => `<testcase classname="${n}.test.ts" name="${n}"/>`).join(''));
    const cases = parseJunit(xml);
    expect(cases.map((c) => c.id)).toEqual(['__proto__.test > __proto__', 'constructor.test > constructor', 'prototype.test > prototype', 'tostring.test > tostring', 'hasownproperty.test > hasownproperty']);
    expect(cases.every((c) => c.status === 'pass')).toBe(true);
    expect(({} as Record<string, unknown>)['pwned']).toBeUndefined();
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
    // as a suite and file name too, and compared as Map keys
    const withSuite = parseJunit(suite('<testcase classname="__proto__.test.ts" name="__proto__ &gt; constructor &gt; prototype"/>'));
    expect(withSuite).toEqual([r('__proto__.test > __proto__ > constructor > prototype')]);
    expect(sameResults(cases, cases)).toEqual({ ok: true, flaky: [] });
    expect(sameResults(cases, cases.map((c) => (c.id === '__proto__.test > __proto__' ? r(c.id, 'fail') : c))).flaky).toEqual(['__proto__.test > __proto__']);
  });

  it('junit: attribute names and element names that could reach prototypes are not followed', () => {
    const attr = suite('<testcase classname="a.test.ts" name="x" __proto__="y" constructor="z" file="b.test.ts"/>');
    expect(parseJunit(attr)).toEqual([r('b.test > a.test.ts > x')]);
    expect(({} as Record<string, unknown>)['y']).toBeUndefined();
    const el = suite('<testcase classname="a.test.ts" name="x"><__proto__><failure/></__proto__></testcase>');
    expect(() => parseJunit(el)).toThrow(/name pipegen won't read/);
    expect(() => parseJunit(suite('<constructor><testcase name="x"/></constructor>'))).toThrow();
    expect(() => parseJunit(suite('<prototype/>'))).toThrow();
  });

  it('junit: bad input is an error that carries no raw XML text', () => {
    const hostile = '\u001b[31mEVIL\u202e';
    const m1 = messageOf(() => parseJunit(`<testsuites><testsuite name="s"><testcase classname="a" /><${hostile}`));
    expect(m1).not.toMatch(/[\u001b\u202e]/);
    expect(() => parseJunit('')).toThrow();
    expect(() => parseJunit('not xml at all')).toThrow();
    expect(() => parseJunit('<html><body/></html>')).toThrow(/testsuite/);
    expect(() => parseJunit(suite('<testcase classname="a"/>'))).toThrow(/no name/);
    expect(() => parseJunit(suite('<testcase/>'))).toThrow(/no name/);
    expect(() => parseJunit(suite('<testcase classname="a" name=""/>'))).toThrow(/no name/);
    const long = 'x'.repeat(5000);
    const m2 = messageOf(() => parseJunit(`<testsuites><__proto__ ${long}="1"/></testsuites>`));
    expect(m2.length).toBeLessThan(600);
    const m3 = messageOf(() => parseJunit(`<testsuites><testsuite><testcase classname="\u001b[31m${long}\u202e" name="${long}"><x:${long.slice(0, 10)}`));
    expect(m3).not.toMatch(/[\u001b\u202e]/);
    expect(m3.length).toBeLessThan(600);
    // a very deep tree: an error or an empty list, never a crash that kills the process
    const deep = '<a>'.repeat(200_000) + '</a>'.repeat(200_000);
    expect(() => parseJunit(deep)).toThrow();
  });

  it('junit: a file attribute wins; the suite path comes from classname or the joined name', () => {
    // jest-junit with addFileAttribute: file from `file`, suite path from classname split on " > "
    expect(parseJunit(suite('<testcase classname="a &gt; b" name="t" file="src/__tests__/x.test.ts"/>'))).toEqual([r('src/__tests__/x.test > a > b > t')]);
    // vitest: classname is the file, the suite path is in front of the name
    expect(parseJunit(suite('<testcase classname="src/x.spec.ts" name="a &gt; b &gt; t"/>'))).toEqual([r('src/x.spec > a > b > t')]);
    expect(parseJunit(suite('<testcase classname="tests/x.test.mjs" name="t"/>'))).toEqual([r('x.test > t')]);
    // a classname that is not a file and no file attribute: it is the suite path
    expect(parseJunit(suite('<testcase classname="Suite A" name="t"/>'))).toEqual([r('suite a > t')]);
    expect(parseJunit(suite('<testcase name="only"/>'))).toEqual([r('only')]);
    // jest-junit with a file attribute but the default templates: classname equals name, so it is not also a suite
    expect(parseJunit(suite('<testcase classname="a b" name="a b" file="x.test.ts"/>'))).toEqual([r('x.test > a b')]);
  });
});

describe('normalise', () => {
  it('normalise: same test from jest and vitest gives same id', () => {
    // Review Focus 4
    const v = parseJunit(fixture(VITEST));
    const j = parseJunit(fixture(JEST));
    expect(j.map((c) => c.id)).toEqual(v.map((c) => c.id));
    expect(normaliseTestId('test/math.test.js', ['math', 'nested', 'deeper'], 'multiplies')).toBe(v[3]?.id);
    expect(normaliseTestId('src/__tests__/Foo.test.ts', ['Foo'], 'Does  A   Thing')).toBe(normaliseTestId('src/__tests__/foo.test.ts', ['foo'], 'does a thing'));
  });

  it('normalise: file prefix, extension, separators, case and whitespace', () => {
    expect(normaliseTestId('test/a.test.ts', [], 'x')).toBe('a.test > x');
    expect(normaliseTestId('tests/a.test.ts', [], 'x')).toBe('a.test > x');
    expect(normaliseTestId('__tests__/a.test.ts', [], 'x')).toBe('a.test > x');
    expect(normaliseTestId('Test/A.test.ts', [], 'x')).toBe('a.test > x');
    expect(normaliseTestId('./test/a.test.ts', [], 'x')).toBe('a.test > x');
    expect(normaliseTestId('test\\sub\\a.test.ts', [], 'x')).toBe('sub/a.test > x');
    expect(normaliseTestId('src/test/a.test.ts', [], 'x')).toBe('src/test/a.test > x'); // only a leading prefix goes
    expect(normaliseTestId('testing/a.ts', [], 'x')).toBe('testing/a > x');
    expect(normaliseTestId('a.test.tsx', ['S'], 'X')).toBe('a.test > s > x');
    expect(normaliseTestId('noext', [], 'x')).toBe('noext > x');
    expect(normaliseTestId('dir.d/noext', [], 'x')).toBe('dir.d/noext > x');
    expect(normaliseTestId('', ['S'], 'x')).toBe('s > x');
    expect(normaliseTestId('a.ts', ['  S \t one ', ''], ' a\n b ')).toBe('a > s one > a b');
  });

  it('normalise: ids carry no control characters and are cut at a bound', () => {
    expect(normaliseTestId('a.ts', [], 'x\u001b[31m\u202ey')).toBe('a > xy');
    const id = normaliseTestId('a.ts', [], 'n'.repeat(5000));
    expect(Array.from(id).length).toBeLessThanOrEqual(1000);
    expect(id.endsWith('…')).toBe(true);
  });
});

describe('sameResults', () => {
  it('sameResults: pass then fail → flaky, not ok', () => {
    const first = [r('a'), r('b')];
    const second = [r('a'), r('b', 'fail')];
    expect(sameResults(first, second)).toEqual({ ok: false, flaky: ['b'] });
    expect(sameResults(second, first)).toEqual({ ok: false, flaky: ['b'] });
  });

  it('sameResults: different test ids between runs → not ok', () => {
    expect(sameResults([r('a'), r('b')], [r('a')])).toEqual({ ok: false, flaky: [] });
    expect(sameResults([r('a')], [r('a'), r('b')])).toEqual({ ok: false, flaky: [] });
    expect(sameResults([r('a')], [r('b')])).toEqual({ ok: false, flaky: [] });
  });

  it('sameResults: both pass with the same ids → ok; fail in both or skip is not ok and not flaky', () => {
    expect(sameResults([r('a'), r('b')], [r('b'), r('a')])).toEqual({ ok: true, flaky: [] });
    expect(Object.hasOwn(sameResults([r('a')], [r('a')]), 'reason')).toBe(false);
    expect(sameResults([], [])).toMatchObject({ ok: false, flaky: [], reason: expect.stringMatching(/no test case/) }); // nothing run is not a proven pass
    expect(sameResults([r('a', 'fail')], [r('a', 'fail')])).toEqual({ ok: false, flaky: [] });
    expect(sameResults([r('a', 'skip')], [r('a', 'skip')])).toEqual({ ok: false, flaky: [] });
    expect(sameResults([r('a')], [r('a', 'skip')])).toEqual({ ok: false, flaky: [] });
    expect(sameResults([r('a', 'skip')], [r('a', 'fail')])).toEqual({ ok: false, flaky: [] });
  });

  it('junit: duplicate normalised id in one run → sameResults not ok', () => {
    expect(sameResults([r('a'), r('a')], [r('a')])).toMatchObject({ ok: false, flaky: [] });
    expect(sameResults([r('a')], [r('a'), r('a')])).toMatchObject({ ok: false, flaky: [] });
    // the refusal says why, including that case and spacing differences do not make two tests
    const why = sameResults([r('a'), r('a')], [r('a')]).reason ?? '';
    expect(why).toMatch(/more than once/);
    expect(why).toMatch(/differ only in case or spacing count as the same test/);
    expect(sameResults([r('a'), r('a')], [r('a'), r('a')]).ok).toBe(false);
    // two XML names that normalise to the same id are a duplicate
    const xml = suite('<testcase classname="a.test.ts" name="Same  Name"/><testcase classname="a.test.ts" name="same name"/>');
    const run = parseJunit(xml);
    expect(run).toHaveLength(2);
    expect(sameResults(run, run).ok).toBe(false);
    expect(sameResults([r('a'), r('a', 'fail')], [r('a', 'fail')])).toMatchObject({ ok: false, flaky: [] });
    // a duplicate that differs in status still reports flaky ids from the other run
    expect(sameResults([r('a'), r('a', 'fail'), r('b')], [r('a'), r('b', 'fail')])).toMatchObject({ ok: false, flaky: ['a', 'b'] });
  });

  it('sameResults: flaky is sorted, listed once and safe text', () => {
    const first = [r('z'), r('m'), r('a')];
    const second = [r('z', 'fail'), r('m', 'fail'), r('a', 'fail')];
    expect(sameResults(first, second).flaky).toEqual(['a', 'm', 'z']);
    const evil = r('x\u001b[31m\u202ey');
    expect(sameResults([evil], [r(evil.id, 'fail')]).flaky).toEqual(['xy']);
    const long = r('n'.repeat(5000));
    const shown = sameResults([long], [{ ...long, status: 'fail' }]).flaky[0] ?? '';
    expect(Array.from(shown).length).toBeLessThanOrEqual(1000);
  });
});
