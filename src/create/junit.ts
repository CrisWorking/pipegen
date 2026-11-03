// JUnit parsing (v0.2 Plan D, D8; plan Task 6; rulings S10 and S12).
// Plans E and T read the JUnit XML that test runs write, to decide pass/fail/skip per test and to compare two runs (flaky
// detection, parity). That XML comes from REPO CODE, so it is hostile input: entity expansion, a huge file, names like
// `__proto__`, duplicate ids. This module is pure (no file, no network, no process) and nothing in the gate imports it.
//
// Hardening, all of it tested:
//   - every `<!` that does not start a comment or a CDATA section is refused (`<!DOCTYPE`, `<!ENTITY` and the rest, any case,
//     with or without a space; the parser reads a bare `<! ` as an element and 5.6M of them cost 1.8 GB), and `<!DOCTYPE` and
//     `<!ENTITY` are refused even inside a comment or CDATA; the parser also runs with processEntities: false, so no
//     entity is ever expanded. The five XML entities and number references in names are decoded here, in one pass.
//   - XMLValidator.validate runs first: a truncated, mismatched or spoofed report (an element named like `@_name`) is refused.
//   - counts a testsuite carries (tests, failures + errors, skipped) must not be higher than what was parsed under it, so a report whose cases
//     were not recognised (another tag name, a namespace) is refused instead of reading as an empty pass.
//   - at most 600,000 `<` characters and 250,000 attribute-shaped texts outside comments and CDATA (the parser's time is linear in them: about 1.6 s at the cap; the slowest accepted shapes, one huge attribute
//     value or name, cost the validator about 2 s and 700 MB, and 3 s in all at 16 MiB).
//   - at most 16 MiB (UTF-8 bytes) and 50,000 test cases. The cases are counted in the text before a tree is built, and again
//     while walking.
//   - names are data: anything keyed by a test id is a Map; an element named __proto__, constructor or prototype is refused
//     by the parser (and reported without its name); attribute names carry a prefix, so none can be __proto__.
//   - an error message never carries raw XML text: what it names goes through safeText with a bound.
//
// Which attribute holds what (captured from real reports, see test/fixtures/junit/):
//   vitest 5.0.5     testcase@classname = the file (repo-relative); testcase@name = "describe > describe > test", so the suite
//                    path and the test name are both in `name`, split on " > ". No `file` attribute.
//   jest-junit 17    with addFileAttribute: testcase@file = the file; testcase@classname = the describe names joined with the
//                    ancestorSeparator (" > " if set so; the default is a space); testcase@name = the test title.
//   jest-junit 17    default options: no file, and classname = name = "describe describe test" joined with spaces. The id has no
//                    file part and no suite path; it is the whole name. (It can't equal a vitest id: nothing says which file.)
// So: file = @file, else @classname when it looks like a test file; suite path = @classname split on " > " (not when it
// equals @name, which is the jest-junit default), or the front of @name split on " > " when @classname was the file.
import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { safeText } from '../util/safe-text.js';

export interface TestCaseResult { id: string; status: 'pass' | 'fail' | 'skip' }

export const MAX_JUNIT_BYTES = 16 * 1024 * 1024;
export const MAX_JUNIT_CASES = 50_000;
/** The longest a normalised id is (code points); a longer one is cut. Two long names that differ only after the cut then count as duplicates, and sameResults fails closed. */
export const ID_MAX = 1000;
const SEP = ' > ';
const MAX_SUITE_DEPTH = 64;

const FORBIDDEN = /<!\s*(?:doctype|entity)/i;
/** `<!` that starts anything but a comment or a CDATA section. */
const DECLARATION = /<!(?!--|\[CDATA\[)/;
/** Attribute-shaped texts outside comments and CDATA. Real vitest writes 3 per case and 2 more per failure (50,000 cases at 10% failing: 160,000). */
export const MAX_JUNIT_ATTRIBUTES = 250_000;
/**
 * `<` characters outside comments and CDATA (each of those counts one). Real vitest 5.0.5 needs about 3 per passing case and 6 per
 * failing case with output (50,000 cases: 125,000 to 215,000 here), and the 16 MiB size cap binds first.
 */
export const MAX_JUNIT_TAGS = 600_000;
const ATTRIBUTE_LIKE = /=\s*["']/g;
const FILE_LIKE = /\.[cm]?[jt]sx?$/i;

function safeParser(): XMLParser {
  return new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_', // attribute names never look like prototype keys
    ignoreDeclaration: true,
    ignorePiTags: true,
    processEntities: false,
    htmlEntities: false,
    parseTagValue: false,
    parseAttributeValue: false,
    trimValues: true,
    isArray: (tag) => tag === 'testsuite' || tag === 'testcase',
  });
}

/** Counts "<testcase" in the text (stopping above the cap), so a case flood is refused before any tree exists. */
function countCaseTags(xml: string): number {
  let n = 0;
  for (let at = xml.indexOf('<testcase'); at !== -1; at = xml.indexOf('<testcase', at + 9)) {
    if (++n > MAX_JUNIT_CASES) return n;
  }
  return n;
}

const PROTECTED_START = /<!--|<!\[CDATA\[/g;

/**
 * Which cap the text is over, if any. Comments and CDATA sections are skipped: the parser reads their body in time linear in its
 * bytes (the 16 MiB cap bounds that), whatever `<` or quotes it holds, and a jest report with console output can hold much HTML. Each
 * section still counts as one tag, so a flood of tiny ones can't pass. An unclosed one runs to the end (the validator refuses it).
 */
function capsExceeded(xml: string): 'tags' | 'attributes' | null {
  let tags = 0;
  let attributes = 0;
  const count = (text: string): 'tags' | 'attributes' | null => {
    for (let at = text.indexOf('<'); at !== -1; at = text.indexOf('<', at + 1)) if (++tags > MAX_JUNIT_TAGS) return 'tags';
    for (const _ of text.matchAll(ATTRIBUTE_LIKE)) if (++attributes > MAX_JUNIT_ATTRIBUTES) return 'attributes';
    return null;
  };
  let from = 0;
  PROTECTED_START.lastIndex = 0;
  for (let m = PROTECTED_START.exec(xml); m !== null; m = PROTECTED_START.exec(xml)) {
    const over = count(xml.slice(from, m.index));
    if (over) return over;
    if (++tags > MAX_JUNIT_TAGS) return 'tags';
    const close = xml.indexOf(m[0] === '<!--' ? '-->' : ']]>', m.index + m[0].length);
    if (close === -1) return null;
    from = close + 3;
    PROTECTED_START.lastIndex = from;
  }
  return count(xml.slice(from));
}

const ENTITY = /&(?:#x([0-9a-fA-F]+)|#([0-9]+)|(amp|lt|gt|quot|apos));/g;
const NAMED: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
function decode(s: string): string {
  return s.replace(ENTITY, (whole, hex: string | undefined, dec: string | undefined, named: string | undefined) => {
    if (named !== undefined) return Object.hasOwn(NAMED, named) ? NAMED[named]! : whole;
    const cp = hex !== undefined ? parseInt(hex, 16) : parseInt(dec ?? '', 10);
    if (!Number.isInteger(cp) || cp < 1 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return whole;
    return String.fromCodePoint(cp);
  });
}

type Node = Record<string, unknown>;
const isNode = (v: unknown): v is Node => typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (n: Node, key: string): unknown => (Object.hasOwn(n, key) ? n[key] : undefined);
const attr = (n: Node, name: string): string => {
  const v = own(n, `@_${name}`);
  return typeof v === 'string' ? decode(v) : '';
};
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

function statusOf(tc: Node): TestCaseResult['status'] {
  if (Object.hasOwn(tc, 'failure') || Object.hasOwn(tc, 'error')) return 'fail';
  if (Object.hasOwn(tc, 'skipped')) return 'skip';
  return 'pass';
}

function parts(s: string): string[] {
  return s === '' ? [] : s.split(SEP);
}

/** file, suite path and test name of a test case, from the attributes of each reporter (see the top of this file). */
function locate(tc: Node): { file: string; suite: string[]; name: string } {
  const name = attr(tc, 'name');
  const classname = attr(tc, 'classname');
  const file = attr(tc, 'file');
  if (file !== '') return { file, suite: classname === name ? [] : parts(classname), name };
  if (FILE_LIKE.test(classname)) { // vitest: the file is the classname, the suite path is in front of the name
    const path = parts(name);
    return { file: classname, suite: path.slice(0, -1), name: path.at(-1) ?? '' };
  }
  return { file: '', suite: classname === name ? [] : parts(classname), name };
}

export function normaliseTestId(file: string, suitePath: string[], name: string): string {
  let f = file.replace(/\\/g, '/').replace(/^(?:\.\/)+/, '');
  f = f.replace(/^(?:test|tests|__tests__)\//i, '').replace(/\.[^./]*$/, '');
  const id = [f, ...suitePath, name]
    .map((p) => p.replace(/\s+/g, ' ').trim())
    .filter((p) => p !== '')
    .join(SEP)
    .toLowerCase();
  return safeText(id, ID_MAX);
}

/** Reads a JUnit report (vitest's junit reporter or jest-junit) into one result per test case. Throws on hostile or unreadable input. */
export function parseJunit(xml: string): TestCaseResult[] {
  if (Buffer.byteLength(xml, 'utf8') > MAX_JUNIT_BYTES) throw new Error('The JUnit report is over 16 MiB; pipegen won\'t read it.');
  if (FORBIDDEN.test(xml) || DECLARATION.test(xml)) throw new Error('The JUnit report has a DOCTYPE, ENTITY or other markup declaration; pipegen refuses it (entity expansion).');
  if (countCaseTags(xml) > MAX_JUNIT_CASES) throw new Error('The JUnit report has more than 50,000 test cases; pipegen won\'t read it.');
  const over = capsExceeded(xml);
  if (over === 'tags') throw new Error(`The JUnit report has more than ${MAX_JUNIT_TAGS.toLocaleString('en-US')} tags; pipegen won't read it.`);
  if (over === 'attributes') throw new Error(`The JUnit report has more than ${MAX_JUNIT_ATTRIBUTES.toLocaleString('en-US')} attributes; pipegen won't read it.`);
  const valid = XMLValidator.validate(xml);
  if (valid !== true) { // the validator's message carries XML text, so only the line number (a number) is kept
    const line = typeof valid.err?.line === 'number' ? ` (near line ${valid.err.line})` : '';
    throw new Error(`The JUnit report is not well-formed XML${line}; it may be cut short.`);
  }

  let tree: unknown;
  try {
    tree = safeParser().parse(xml);
  } catch (e) {
    // the parser's own message can carry the XML's names, so none of it is repeated
    if (e instanceof Error && e.message.startsWith('[SECURITY]')) throw new Error('The JUnit report has an element or attribute name pipegen won\'t read (it could reach an object prototype).');
    throw new Error('The JUnit report is not XML pipegen can read.');
  }
  const root = isNode(tree) ? tree : {};
  const start = [...list(own(root, 'testsuites')), ...list(own(root, 'testsuite'))];
  if (start.length === 0) throw new Error('The JUnit report has no testsuite element.');

  const results: TestCaseResult[] = [];
  const counted: Array<{ node: Node; tally: Tally }> = [];
  const stack: Frame[] = start.reverse().map((node) => ({ node, depth: 0, parent: null }));
  while (stack.length > 0) {
    const { node, depth, parent } = stack.pop()!;
    if (!isNode(node)) continue;
    if (depth > MAX_SUITE_DEPTH) throw new Error('The JUnit report nests test suites deeper than pipegen reads.');
    const tally: Tally = { tests: 0, fails: 0, skips: 0, parent };
    counted.push({ node, tally });
    for (const child of list(own(node, 'testsuite')).reverse()) stack.push({ node: child, depth: depth + 1, parent: tally });
    for (const raw of list(own(node, 'testcase'))) {
      if (results.length >= MAX_JUNIT_CASES) throw new Error('The JUnit report has more than 50,000 test cases; pipegen won\'t read it.');
      const tc = isNode(raw) ? raw : {};
      const { file, suite, name } = locate(tc);
      if (name.trim() === '') throw new Error(`A test case in "${safeText(file || attr(tc, 'classname'), 80)}" has no name.`);
      const status = statusOf(tc);
      results.push({ id: normaliseTestId(file, suite, name), status });
      for (let t: Tally | null = tally; t; t = t.parent) {
        t.tests++;
        if (status === 'fail') t.fails++;
        if (Object.hasOwn(tc, 'skipped')) t.skips++;
      }
    }
  }
  for (const { node, tally } of counted) checkCounts(node, tally);
  return results;
}

interface Tally { tests: number; fails: number; skips: number; parent: Tally | null }
interface Frame { node: unknown; depth: number; parent: Tally | null }

/**
 * A suite must not claim more tests, skips or failures than were parsed under it (nested suites included): that is a report whose cases
 * were not recognised, or one that was cut or edited. Claiming FEWER is accepted: jest-junit writes test.todo cases and afterAll hook
 * failures as cases and leaves them out of its counts. More cases parsed than claimed can't make a run ok (an extra fail or skip only
 * makes it less ok).
 */
function checkCounts(node: Node, tally: Tally): void {
  const declared = (name: string): number | undefined => {
    const raw = own(node, `@_${name}`);
    if (raw === undefined) return undefined;
    if (typeof raw !== 'string' || !/^\d{1,9}$/.test(raw.trim())) throw new Error(`The JUnit report's "${name}" count is not a number.`);
    return Number(raw.trim());
  };
  const tests = declared('tests');
  const skipped = declared('skipped');
  const failures = declared('failures');
  const errors = declared('errors');
  const bad = (what: string, said: number, found: number): never => {
    throw new Error(`The JUnit report's ${what} count (${said}) does not match the test cases pipegen read (${found}).`);
  };
  if (tests !== undefined && tests > tally.tests) bad('tests', tests, tally.tests);
  if (skipped !== undefined && skipped > tally.skips) bad('skipped', skipped, tally.skips);
  if (failures !== undefined || errors !== undefined) {
    const said = (failures ?? 0) + (errors ?? 0);
    if (said > tally.fails) bad('failures and errors', said, tally.fails);
  }
}

const DUPLICATE_REASON = 'A test id appears more than once in a run; test names that differ only in case or spacing count as the same test.';

function byId(run: TestCaseResult[]): Map<string, TestCaseResult['status'][]> {
  const map = new Map<string, TestCaseResult['status'][]>();
  for (const { id, status } of run) {
    const seen = map.get(id);
    if (seen) seen.push(status); else map.set(id, [status]);
  }
  return map;
}

/**
 * ok: both runs have the same ids, every id passes in both, and no id is repeated inside a run (a repeat can hide a failure behind a pass).
 * A run with no test case is never ok: nothing ran, or nothing was recognised, which proves nothing.
 * reason: set when ok is false because of that or because of a repeated id, so the caller can say why.
 * flaky: the ids that pass in one run and fail in the other, sorted, as safe text.
 */
export function sameResults(first: TestCaseResult[], second: TestCaseResult[]): { ok: boolean; flaky: string[]; reason?: string } {
  const a = byId(first);
  const b = byId(second);
  let ok = a.size > 0 && a.size === b.size;
  let reason: string | undefined = a.size === 0 || b.size === 0 ? 'A run has no test case, so it proves nothing.' : undefined;
  const flaky: string[] = [];
  for (const [id, one] of a) {
    const two = b.get(id);
    if (two === undefined) { ok = false; continue; }
    if (one.length !== 1 || two.length !== 1) {
      ok = false;
      reason ??= DUPLICATE_REASON;
    }
    if (one.some((s) => s !== 'pass') || two.some((s) => s !== 'pass')) ok = false;
    const passFail = one.every((s) => s === 'pass') && two.includes('fail');
    const failPass = one.includes('fail') && two.every((s) => s === 'pass');
    if (passFail || failPass) flaky.push(safeText(id, ID_MAX));
  }
  return reason === undefined ? { ok, flaky: flaky.sort() } : { ok, flaky: flaky.sort(), reason };
}
