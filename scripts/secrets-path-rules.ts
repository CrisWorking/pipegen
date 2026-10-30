// C1c: the path facts of the pinned secrets scanners' default configs, for the gate's staged secrets scan (gate/src/stage.ts).
//
// The stage step copies every file of the checkout under a neutral name (f00000001.txt, …), so no path allowlist of a scanner
// can match a name a pull request chose. Five rules of the default configs fire only on files whose PATH matches (pkcs12 files,
// HashiCorp, Kubernetes, NuGet and freemius files): such a file keeps one rule-target suffix (f00000007.yaml) so the rule still
// sees it. This script reads both pinned default configs (betterleaks 1.9.0 and gitleaks 8.30.1, fetched from their release tags
// and checked against the sha256 recorded below) and writes gate/src/generated/secrets-path-rules.ts:
//   - PATH_RULES: every rule with a `path`, its pattern and the suffixes a staged name may keep for it;
//   - PATH_FILTERS: every path pattern that can drop a file or a finding (gitleaks' global and per-rule allowlists; betterleaks'
//     prefilter and the `attributes["path"]` lists of its rule filters), with what it does;
//   - the longest bounded match of any rule regex (the overlap of the pieces of a large file must be at least that).
// It refuses (exit 1) a config whose sha256 differs, a path rule this file does not know (a new path rule needs a reviewed
// suffix here), and a path test in a form it does not read. test/gate-stage-suffix.test.ts proves the suffixes against the
// written table, and its live part runs this extraction on the downloaded configs and compares.
//
// Run: `node scripts/secrets-path-rules.ts` (network: the two config files). Keep to syntax Node's type stripping runs.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseToml } from 'smol-toml';

export interface PinnedConfig { tool: 'betterleaks' | 'gitleaks'; version: string; url: string; sha256: string }
export const PINNED_CONFIGS: readonly PinnedConfig[] = [
  { tool: 'betterleaks', version: '1.9.0', url: 'https://raw.githubusercontent.com/betterleaks/betterleaks/v1.9.0/config/betterleaks.toml', sha256: 'a8f553eb634ac3c5c1ca3f0dc95e2b8abdea7d14b622604c5af07f30ce7926ef' },
  { tool: 'gitleaks', version: '8.30.1', url: 'https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml', sha256: 'e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf' },
];

/**
 * The reviewed suffixes per path pattern (the exact pattern text of the config). Each is a suffix or basename test, so the rule
 * fires on a staged name that ends with one of these. A staged file keeps the listed suffix its own name ends with (any case),
 * else the first one: `.tf` stays `.tf` and `.hcl` stays `.hcl`, because betterleaks' code-file filter treats them differently.
 */
export const KNOWN_PATH_RULES: Readonly<Record<string, readonly string[]>> = {
  '(?i)\\.php$': ['.php'],
  '(?i)\\.(?:tf|hcl)$': ['.tf', '.hcl'],
  '(?i)\\.ya?ml$': ['.yaml', '.yml'],
  // unanchored on the left: `mynuget.config` matches too, so the suffix is `.nuget.config` (f00000001.nuget.config)
  '(?i)nuget\\.config$': ['.nuget.config'],
  '(?i)(?:^|\\/)[^\\/]+\\.p(?:12|fx)$': ['.p12', '.pfx'],
};

/** What a path pattern does when it matches. */
export type FilterKind =
  | 'skip-file'      // the file is never scanned (gitleaks [allowlist].paths, betterleaks prefilter)
  | 'drop-finding'   // a finding of the rule in that file is dropped (a per-rule allowlist or filter)
  | 'drop-finding-and' // the same, only together with a line test (condition AND)
  | 'code-file'      // betterleaks isCodeFile: an unquoted value of a generic password or username rule is dropped in a code file
  | 'confidence';    // betterleaks isTestOrDocumentationSource: only lowers the confidence label of generic-credential-uri
export interface PathFilter { tool: 'betterleaks' | 'gitleaks'; where: string; kind: FilterKind; pattern: string }
export interface PathRule { tool: 'betterleaks' | 'gitleaks'; rule: string; pattern: string; suffixes: readonly string[] }
export interface Extracted { pathRules: PathRule[]; pathFilters: PathFilter[]; longestBounded: { bytes: number; tool: string; rule: string }; unboundedRules: number; rules: Record<string, number> }

class ExtractError extends Error {}
const refuse = (m: string): never => { throw new ExtractError(m); };

// ---------- the longest match of a regex (RE2 syntax), in bytes ----------

/**
 * The most bytes a match of an RE2 regex can span, or Infinity. An upper bound: a character class or `.` counts as 4 bytes
 * (any code point), a case-folded letter as 3 (RE2 folds k to the Kelvin sign), every other literal as its UTF-8 length.
 */
export function maxMatchBytes(re: string): number {
  let i = 0;
  const fold: boolean[] = [false];
  const peek = (): string => re[i] as string;
  function atomClass(): number {
    // [ ... ]: skip to the closing bracket (escapes and [:name:] inside)
    i++;
    if (peek() === '^') i++;
    if (peek() === ']') i++;
    while (i < re.length && peek() !== ']') {
      if (peek() === '\\') i += 2;
      else if (re.startsWith('[:', i)) { const e = re.indexOf(':]', i + 2); i = e < 0 ? refuse('an open [: in a class') : e + 2; }
      else i++;
    }
    if (peek() !== ']') refuse('an open character class');
    i++;
    return 4;
  }
  function escape(): number {
    i++;
    const c = peek();
    i++;
    if (c === undefined) return refuse('a trailing backslash');
    if ('bBAz'.includes(c)) return 0;
    if ('dswDSW'.includes(c)) return 4;
    if (c === 'x') {
      if (peek() === '{') { const e = re.indexOf('}', i); const cp = parseInt(re.slice(i + 1, e), 16); i = e + 1; return Buffer.byteLength(String.fromCodePoint(cp)); }
      const cp = parseInt(re.slice(i, i + 2), 16); i += 2; return Buffer.byteLength(String.fromCodePoint(cp));
    }
    if (c === 'p' || c === 'P') { if (peek() === '{') i = re.indexOf('}', i) + 1; else i++; return 4; }
    if (c === 'Q') { const e = re.indexOf('\\E', i); const lit = re.slice(i, e < 0 ? re.length : e); i = e < 0 ? re.length : e + 2; return Buffer.byteLength(lit) * (fold.at(-1) ? 3 : 1); }
    if ('nrtfv0'.includes(c)) return 1;
    return fold.at(-1) && /[a-z]/i.test(c) ? 3 : Buffer.byteLength(c);
  }
  function quantified(atom: number): number {
    let n = atom;
    for (;;) {
      const c = peek();
      if (c === '*' || c === '+') { i++; n = atom === 0 ? 0 : Infinity; }
      else if (c === '?') { i++; }
      else if (c === '{' && /^\{\d+(?:,\d*)?\}/.test(re.slice(i))) {
        const m = /^\{(\d+)(?:(,)(\d*))?\}/.exec(re.slice(i)) as RegExpExecArray;
        i += m[0].length;
        const max = m[2] === undefined ? Number(m[1]) : m[3] === '' ? Infinity : Number(m[3]);
        n = atom === 0 ? 0 : atom * max;
      } else return n;
      if (peek() === '?') i++;   // lazy
    }
  }
  function alternation(): number {
    let best = sequence();
    while (peek() === '|') { i++; best = Math.max(best, sequence()); }
    return best;
  }
  function sequence(): number {
    let total = 0;
    while (i < re.length && peek() !== '|' && peek() !== ')') {
      const c = peek();
      let atom: number;
      if (c === '(') {
        i++;
        let flags: string | null = null;
        if (peek() === '?') {
          const m = /^\?(?:P<\w+>|<\w+>|([a-zA-Z-]*)(:|\)))/.exec(re.slice(i));
          if (m === null) return refuse(`a group form this reader does not know at ${i}`);
          i += m[0].length;
          if (m[2] === ')') { if ((m[1] ?? '').includes('i') && !(m[1] ?? '').startsWith('-')) fold[fold.length - 1] = true; continue; }
          flags = m[1] ?? '';
        }
        fold.push(flags !== null && flags.includes('i') ? true : fold.at(-1) as boolean);
        atom = alternation();
        fold.pop();
        if (peek() !== ')') refuse('an open group');
        i++;
      } else if (c === '[') atom = atomClass();
      else if (c === '\\') atom = escape();
      else if (c === '.') { i++; atom = 4; }
      else if (c === '^' || c === '$') { i++; atom = 0; }
      else { const cp = re.codePointAt(i) as number; const ch = String.fromCodePoint(cp); i += ch.length; atom = fold.at(-1) && /[a-z]/i.test(ch) ? 3 : Buffer.byteLength(ch); }
      total += quantified(atom);
    }
    return total;
  }
  const n = alternation();
  if (i !== re.length) refuse(`an unbalanced ) at ${i}`);
  return n;
}

// ---------- extraction ----------

/** The backtick-quoted patterns of every `matchesAny(attributes["path"], [ … ])` list in a CEL text, with the name the list is assigned to (`let x = …`), if any. */
function celPathLists(cel: string, where: string): { name: string | null; patterns: string[]; and: boolean }[] {
  const out: { name: string | null; patterns: string[]; and: boolean }[] = [];
  const any = cel.split('attributes[').length - 1;
  const head = /(?:let\s+(\w+)\s*=\s*)?(?:filter\.)?matchesAny\(attributes\["path"\],\s*\[/g;
  for (const m of cel.matchAll(head)) {
    // the list: backtick-quoted patterns (a pattern may hold ] and ,) separated by commas, up to the ] outside any pattern
    let i = (m.index as number) + m[0].length;
    const patterns: string[] = [];
    for (;;) {
      while (i < cel.length && /[\s,]/.test(cel[i] as string)) i++;
      if (cel[i] === ']') { i++; break; }
      if (cel[i] !== '`') return refuse(`${where}: a path list item that is not a backtick-quoted pattern`);
      const e = cel.indexOf('`', i + 1);
      if (e < 0) return refuse(`${where}: an open pattern`);
      patterns.push(cel.slice(i + 1, e));
      i = e + 1;
    }
    if (cel[i] !== ')') refuse(`${where}: a path list that is not closed by )`);
    if (patterns.length === 0) refuse(`${where}: a path list with no pattern`);
    out.push({ name: m[1] ?? null, patterns, and: /^\s*&&/.test(cel.slice(i + 1)) });
  }
  if (out.length !== any) refuse(`${where}: attributes[…] is used ${any} time(s), but only ${out.length} are path lists this script reads`);
  return out;
}

const KIND_OF_LET: Readonly<Record<string, FilterKind>> = { isCodeFile: 'code-file', isTestOrDocumentationSource: 'confidence' };

function jsRegex(pattern: string, where: string): RegExp {
  let p = pattern;
  let flags = 'u';
  if (p.startsWith('(?i)')) { p = p.slice(4); flags += 'i'; }
  if (/\(\?[a-z-]*\)/.test(p)) refuse(`${where}: an inline flag inside ${JSON.stringify(pattern)}`);
  try { return new RegExp(p, flags); } catch { return refuse(`${where}: ${JSON.stringify(pattern)} is not a regex JavaScript reads the same way`); }
}

type Toml = Record<string, unknown>;
const isObj = (v: unknown): v is Toml => typeof v === 'object' && v !== null && !Array.isArray(v);
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : refuse('a list field is not a list'));
const strs = (v: unknown, where: string): string[] => list(v).map((x) => (typeof x === 'string' ? x : refuse(`${where}: not a string`)));

/** Reads the path facts of the two configs (their texts). Throws on anything it does not know. */
export function extract(texts: Record<'betterleaks' | 'gitleaks', string>): Extracted {
  const pathRules: PathRule[] = [];
  const pathFilters: PathFilter[] = [];
  let longest = { bytes: 0, tool: '', rule: '' };
  let unbounded = 0;
  const rules: Record<string, number> = {};
  for (const tool of ['betterleaks', 'gitleaks'] as const) {
    const doc = parseToml(texts[tool]) as Toml;
    const addFilter = (where: string, kind: FilterKind, pattern: string): void => { jsRegex(pattern, where); pathFilters.push({ tool, where, kind, pattern }); };
    // global
    for (const al of [...(isObj(doc.allowlist) ? [doc.allowlist] : []), ...list(doc.allowlists)]) {
      if (!isObj(al)) return refuse(`${tool}: an allowlist is not a table`);
      for (const p of strs(al.paths, `${tool} global allowlist`)) addFilter('global allowlist', al.condition === 'AND' ? 'drop-finding-and' : 'skip-file', p);
    }
    if (doc.prefilter !== undefined) {
      if (typeof doc.prefilter !== 'string') refuse(`${tool}: prefilter is not text`);
      for (const l of celPathLists(doc.prefilter as string, `${tool} prefilter`)) for (const p of l.patterns) addFilter('prefilter', 'skip-file', p);
    }
    if (typeof doc.filter === 'string') for (const l of celPathLists(doc.filter, `${tool} filter`)) for (const p of l.patterns) addFilter('filter', l.name === null ? 'drop-finding' : KIND_OF_LET[l.name] ?? refuse(`${tool} filter: a path list named ${l.name}`), p);
    const rs = list(doc.rules);
    rules[tool] = rs.length;
    for (const r of rs) {
      if (!isObj(r) || typeof r.id !== 'string') return refuse(`${tool}: a rule without an id`);
      const id = r.id;
      if (r.path !== undefined) {
        if (typeof r.path !== 'string') refuse(`${tool} ${id}: path is not text`);
        const suffixes = Object.hasOwn(KNOWN_PATH_RULES, r.path as string) ? KNOWN_PATH_RULES[r.path as string] : refuse(`${tool} ${id}: the path rule ${JSON.stringify(r.path)} has no reviewed suffix in scripts/secrets-path-rules.ts`);
        jsRegex(r.path as string, `${tool} ${id}`);
        pathRules.push({ tool, rule: id, pattern: r.path as string, suffixes: suffixes as readonly string[] });
      }
      for (const al of list(r.allowlists)) {
        if (!isObj(al)) return refuse(`${tool} ${id}: an allowlist is not a table`);
        for (const p of strs(al.paths, `${tool} ${id}`)) addFilter(`rule ${id}`, al.condition === 'AND' ? 'drop-finding-and' : 'drop-finding', p);
      }
      if (isObj(r.allowlist)) for (const p of strs(r.allowlist.paths, `${tool} ${id}`)) addFilter(`rule ${id}`, 'drop-finding', p);
      if (r.filter !== undefined) {
        if (typeof r.filter !== 'string') refuse(`${tool} ${id}: filter is not text`);
        for (const l of celPathLists(r.filter as string, `${tool} ${id}`)) {
          // a list assigned to a known name, or used directly: `||` with a path list drops the finding; `&&` (the .bb/.inc case) needs a line test too
          const kind = l.name !== null ? KIND_OF_LET[l.name] ?? refuse(`${tool} ${id}: a path list named ${l.name}`) : l.and ? 'drop-finding-and' : 'drop-finding';
          for (const p of l.patterns) addFilter(`rule ${id}`, kind, p);
        }
      }
      if (typeof r.regex === 'string') {
        const n = maxMatchBytes(r.regex);
        if (n === Infinity) unbounded++;
        else if (n > longest.bytes) longest = { bytes: n, tool, rule: id };
      }
    }
  }
  return { pathRules, pathFilters, longestBounded: longest, unboundedRules: unbounded, rules };
}

/** The TypeScript module the stage step reads. */
export function render(x: Extracted): string {
  const j = (v: unknown): string => JSON.stringify(v, null, 2);
  return `// GENERATED by scripts/secrets-path-rules.ts from the pinned default configs below. Do not edit: run the script.
// C1c: the gate's stage step gives a file that a path rule targets one of that rule's suffixes; test/gate-stage-suffix.test.ts
// proves that no staged name matches any of PATH_FILTERS that skips a file or drops a finding.

export interface PathRule { readonly tool: 'betterleaks' | 'gitleaks'; readonly rule: string; readonly pattern: string; readonly suffixes: readonly string[] }
export type FilterKind = 'skip-file' | 'drop-finding' | 'drop-finding-and' | 'code-file' | 'confidence';
export interface PathFilter { readonly tool: 'betterleaks' | 'gitleaks'; readonly where: string; readonly kind: FilterKind; readonly pattern: string }

export const PINNED_CONFIGS = ${j(PINNED_CONFIGS)} as const;

/** The rules of each config. */
export const RULE_COUNTS = ${j(x.rules)} as const;

export const PATH_RULES: readonly PathRule[] = ${j(x.pathRules)};

export const PATH_FILTERS: readonly PathFilter[] = ${j(x.pathFilters)};

/** The longest match, in bytes, of any rule whose regex has a bound (an upper bound: a class counts 4 bytes). */
export const LONGEST_BOUNDED_MATCH = ${j(x.longestBounded)} as const;
/** Rules whose regex has no bound (a * or + or {n,}). */
export const UNBOUNDED_RULES = ${x.unboundedRules};
`;
}

/** Fetches a pinned config and checks its sha256. */
export async function fetchPinned(c: PinnedConfig): Promise<string> {
  const res = await fetch(c.url, { redirect: 'error' });
  if (!res.ok) throw new ExtractError(`${c.tool}: ${c.url} answered ${res.status}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  const got = createHash('sha256').update(bytes).digest('hex');
  if (got !== c.sha256) throw new ExtractError(`${c.tool}: the config at ${c.url} has sha256 ${got}, not the pinned ${c.sha256}`);
  return bytes.toString('utf8');
}

export const GENERATED_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'gate', 'src', 'generated', 'secrets-path-rules.ts');

async function main(): Promise<void> {
  const texts = { betterleaks: '', gitleaks: '' };
  for (const c of PINNED_CONFIGS) texts[c.tool] = await fetchPinned(c);
  writeFileSync(GENERATED_PATH, render(extract(texts)));
  console.log(`wrote ${join('gate', 'src', 'generated', 'secrets-path-rules.ts')}`);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e: unknown) => { console.error(e instanceof Error ? e.message : String(e)); process.exit(1); });
}
