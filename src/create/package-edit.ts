// The exact package.json text pipegen writes (v0.2 Plan D, D6; D1 carry): the ORIGINAL bytes with only the B2 devDependencies and `scripts.test`
// inserted. The producer (npm-deps.ts) writes this text and the package.json judge rebuilds it from the original and compares bytes, so
// nothing else (a reformatted file, a changed key, a trailing change) can ride along. Pure; a text it can not edit in place gives null.
//
// Style is copied from the file: the whitespace before the first key of the object, the text between a key and its value. A new `scripts` or
// `devDependencies` object goes at the end of the top-level object. Only the three places B2 allows are touched:
//   - devDependencies: entries appended (in name order) to the object, or the object added;
//   - scripts: `test` appended, or `scripts` added;
//   - scripts.test: an existing npm-default value replaced by the string `vitest run`.
import { B2_DEVDEPS, NPM_DEFAULT_TEST, parseJsonStrict, VITEST_TEST_SCRIPT } from './package-rules.js';

export interface PackageEdit {
  /** devDependencies to add: name -> version (the B2 table's). */
  add: Readonly<Record<string, string>>;
  /** Set scripts.test to `vitest run` (adds it, or replaces npm's default). */
  setTest: boolean;
}

interface Member { key: string; keyStart: number; keyEnd: number; valueStart: number; valueEnd: number }
interface Obj { open: number; close: number; members: Member[] }

/** Scans the JSON object that starts at `at` (text already parsed strictly, so the syntax is valid). */
function scanObject(text: string, at: number): Obj {
  let i = at;
  const ws = (): void => { while (i < text.length && ' \t\r\n'.includes(text[i] as string)) i++; };
  const str = (): void => { i++; while (text[i] !== '"') i += text[i] === '\\' ? 2 : 1; i++; };
  const skip = (): void => {
    ws();
    const c = text[i];
    if (c === '"') { str(); return; }
    if (c === '{' || c === '[') {
      let depth = 0;
      do {
        const d = text[i];
        if (d === '"') { str(); continue; }
        if (d === '{' || d === '[') depth++;
        else if (d === '}' || d === ']') depth--;
        i++;
      } while (depth > 0);
      return;
    }
    while (i < text.length && !',}] \t\r\n'.includes(text[i] as string)) i++;
  };
  const members: Member[] = [];
  i++;   // {
  ws();
  while (text[i] !== '}') {
    const keyStart = i;
    str();
    const keyEnd = i;
    const key = JSON.parse(text.slice(keyStart, keyEnd)) as string;
    ws(); i++;   // :
    ws();
    const valueStart = i;
    skip();
    members.push({ key, keyStart, keyEnd, valueStart, valueEnd: i });
    ws();
    if (text[i] === ',') { i++; ws(); }
  }
  return { open: at, close: i, members };
}

const isPlainWs = (s: string): boolean => /^[ \t\r\n]*$/.test(s);

/** The text of `original` with `edit` applied, or null when the file is not shaped for an in-place edit (the caller then reports not-proven). */
export function buildPackageJson(original: string, edit: PackageEdit): string | null {
  let parsed: unknown;
  try { parsed = parseJsonStrict(original); } catch { return null; }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const rootStart = original.search(/\S/);
  if (rootStart < 0 || original[rootStart] !== '{') return null;
  const root = scanObject(original, rootStart);
  const first = root.members[0];
  if (first === undefined) return null;   // an empty package.json is not an npm package pipegen edits
  const rootWs = original.slice(root.open + 1, first.keyStart);
  const colon = original.slice(first.keyEnd, first.valueStart);
  if (!isPlainWs(rootWs) || !isPlainWs(colon.replace(':', ''))) return null;
  const nl = rootWs.lastIndexOf('\n');
  const unit = nl < 0 ? '' : rootWs.slice(nl + 1);   // one level of indent (the top-level object sits at column 0)
  const innerWs = nl < 0 ? '' : `${rootWs}${unit}`;
  const q = (s: string): string => JSON.stringify(s);
  const entry = (k: string, v: string): string => `${q(k)}${colon}${q(v)}`;
  const byName = Object.entries(edit.add).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const member = (k: string): Member | undefined => root.members.find((m) => m.key === k);

  const edits: { at: number; end: number; text: string }[] = [];
  const rootAdds: string[] = [];
  /** Append `entries` to the depth-1 object `m` (or build a whole object when it is empty). */
  const append = (m: Member, entries: string[]): boolean => {
    if (original[m.valueStart] !== '{') return false;
    const o = scanObject(original, m.valueStart);
    const f = o.members[0];
    if (f === undefined) {
      const body = entries.map((e) => `${innerWs}${e}`).join(',');
      edits.push({ at: o.open, end: o.close + 1, text: `{${body}${rootWs}}` });
      return true;
    }
    const ws = original.slice(o.open + 1, f.keyStart);
    if (!isPlainWs(ws)) return false;
    const last = o.members[o.members.length - 1] as Member;
    edits.push({ at: last.valueEnd, end: last.valueEnd, text: entries.map((e) => `,${ws}${e}`).join('') });
    return true;
  };
  const objText = (entries: string[]): string => `{${entries.map((e) => `${innerWs}${e}`).join(',')}${rootWs}}`;

  if (edit.setTest) {
    const scripts = member('scripts');
    if (scripts === undefined) rootAdds.push(`${q('scripts')}${colon}${objText([entry('test', VITEST_TEST_SCRIPT)])}`);
    else {
      if (original[scripts.valueStart] !== '{') return null;
      const so = scanObject(original, scripts.valueStart);
      const t = so.members.find((m) => m.key === 'test');
      if (t === undefined) { if (!append(scripts, [entry('test', VITEST_TEST_SCRIPT)])) return null; }
      else {
        if (JSON.parse(original.slice(t.valueStart, t.valueEnd)) !== NPM_DEFAULT_TEST) return null;
        edits.push({ at: t.valueStart, end: t.valueEnd, text: q(VITEST_TEST_SCRIPT) });
      }
    }
  }
  if (byName.length > 0) {
    const dev = member('devDependencies');
    const entries = byName.map(([k, v]) => entry(k, v));
    if (dev === undefined) rootAdds.push(`${q('devDependencies')}${colon}${objText(entries)}`);
    else if (!append(dev, entries)) return null;
  }
  if (rootAdds.length > 0) {
    const last = root.members[root.members.length - 1] as Member;
    edits.push({ at: last.valueEnd, end: last.valueEnd, text: rootAdds.map((a) => `,${rootWs}${a}`).join('') });
  }
  let out = original;
  for (const e of edits.sort((a, b) => b.at - a.at)) out = out.slice(0, e.at) + e.text + out.slice(e.end);
  // the result must be strict JSON again, with the same content plus the edit (a final guard against a mis-scan)
  try { parseJsonStrict(out); } catch { return null; }
  for (const k of Object.keys(edit.add)) if (!Object.hasOwn(B2_DEVDEPS, k)) return null;
  return out;
}

/** What a changed package.json adds, read from the parsed objects: the devDependencies not in the original, and whether scripts.test changed. */
export function editOf(original: Record<string, unknown>, content: Record<string, unknown>): PackageEdit {
  const dev = (o: Record<string, unknown>): Record<string, unknown> => (typeof o.devDependencies === 'object' && o.devDependencies !== null && !Array.isArray(o.devDependencies) ? o.devDependencies as Record<string, unknown> : {});
  const test = (o: Record<string, unknown>): unknown => (typeof o.scripts === 'object' && o.scripts !== null && !Array.isArray(o.scripts) ? (o.scripts as Record<string, unknown>).test : undefined);
  const add: Record<string, string> = {};
  for (const [k, v] of Object.entries(dev(content))) if (!Object.hasOwn(dev(original), k)) add[k] = String(v);
  return { add, setTest: test(original) !== test(content) };
}
