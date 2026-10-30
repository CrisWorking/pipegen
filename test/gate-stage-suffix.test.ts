// C1c: the proof that a staged name hides nothing. The stage step names every file `fNNNNNNNN` + one suffix of STAGE_SUFFIXES; the
// suffixes come from the path rules of the pinned default configs (betterleaks 1.9.0, gitleaks 8.30.1), read by
// scripts/secrets-path-rules.ts into gate/src/generated/secrets-path-rules.ts. Offline here; the live part re-reads the configs
// from their release tags (sha256-checked) and compares the table. Written first (strict test-first).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PIECE_OVERLAP_BYTES } from '../src/ai/scan-staging.js';
import { LONGEST_BOUNDED_MATCH, PATH_FILTERS, PATH_RULES, PINNED_CONFIGS, UNBOUNDED_RULES } from '../gate/src/generated/secrets-path-rules.js';
import { STAGE_SUFFIXES, STAGED_NAME_RE, suffixFor } from '../gate/src/stage.js';
import { extract, fetchPinned, GENERATED_PATH, KNOWN_PATH_RULES, maxMatchBytes, render } from '../scripts/secrets-path-rules.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
/** A Go pattern as JavaScript reads it (the leading (?i) as the i flag; u for RE2's Unicode case folding). */
const rx = (p: string): RegExp => new RegExp(p.replace(/^\(\?i\)/, ''), p.startsWith('(?i)') ? 'iu' : 'u');
const NAMES = ['f00000001', 'f00000010', 'f12345678', 'f99999999'];
const staged = (s: string): string[] => NAMES.map((n) => `${n}${s}`);
const HIDING = new Set(['skip-file', 'drop-finding', 'drop-finding-and']);

describe('the staged names against both pinned default configs', () => {
  it('the table is from the pinned configs (their release tags and sha256) and holds every path rule of both: the five that target files by path', () => {
    expect(PINNED_CONFIGS.map((c) => [c.tool, c.version])).toEqual([['betterleaks', '1.9.0'], ['gitleaks', '8.30.1']]);
    for (const c of PINNED_CONFIGS) expect(c.url).toMatch(new RegExp(`^https://raw\\.githubusercontent\\.com/${c.tool}/${c.tool}/v${c.version.replace(/\./g, '\\.')}/config/${c.tool}\\.toml$`));
    const byTool = (t: string): string[] => PATH_RULES.filter((r) => r.tool === t).map((r) => r.rule).sort();
    const five = ['freemius-secret-key', 'hashicorp-tf-password', 'kubernetes-secret-yaml', 'nuget-config-password', 'pkcs12-file'];
    expect(byTool('betterleaks')).toEqual(five);
    expect(byTool('gitleaks')).toEqual(five);
    // the pkcs12 rule fires on .p12 AND .pfx; nuget\.config$ is unanchored on the left
    expect(PATH_RULES.find((r) => r.rule === 'pkcs12-file')?.suffixes).toEqual(['.p12', '.pfx']);
    expect(PATH_RULES.find((r) => r.rule === 'nuget-config-password')?.pattern).toBe('(?i)nuget\\.config$');
    expect(STAGE_SUFFIXES).toEqual(['.txt', '.php', '.tf', '.hcl', '.yaml', '.yml', '.nuget.config', '.p12', '.pfx']);
    // the filters the table holds: the global allowlist of each, the per-rule ones, and betterleaks' CEL path lists
    expect(PATH_FILTERS.filter((f) => f.tool === 'gitleaks' && f.kind === 'skip-file').length).toBeGreaterThanOrEqual(20);
    expect(PATH_FILTERS.filter((f) => f.tool === 'betterleaks' && f.kind === 'skip-file').length).toBeGreaterThanOrEqual(20);
    for (const p of ['gitleaks\\.toml', '(?:^|/)node_modules(?:/.*)?$', '(?i)\\.(?:bmp|gif|jpe?g|png|svg|tiff?)$', 'go\\.(?:mod|sum|work(?:\\.sum)?)$']) {
      for (const tool of ['betterleaks', 'gitleaks']) expect(PATH_FILTERS.some((f) => f.tool === tool && f.kind === 'skip-file' && f.pattern === p), `${tool} ${p}`).toBe(true);
    }
    expect(PATH_FILTERS.some((f) => f.kind === 'drop-finding' && f.pattern.includes('@octokit'))).toBe(true);
    expect(PATH_FILTERS.some((f) => f.kind === 'drop-finding-and' && f.pattern === '\\.bb$')).toBe(true);
  });

  it('no staged name matches any path pattern that skips a file or drops a finding, in either config (global and per rule)', () => {
    const hits: string[] = [];
    for (const s of STAGE_SUFFIXES) for (const name of staged(s)) for (const f of PATH_FILTERS) if (HIDING.has(f.kind) && rx(f.pattern).test(name)) hits.push(`${name} ~ ${f.tool} ${f.where} ${f.pattern}`);
    expect(hits).toEqual([]);
  });

  it('each path rule fires on exactly the staged names of its own suffixes, never on .txt or another rule\'s', () => {
    for (const r of PATH_RULES) {
      for (const s of STAGE_SUFFIXES) {
        for (const name of staged(s)) expect(rx(r.pattern).test(name), `${r.tool} ${r.rule} on ${name}`).toBe(r.suffixes.includes(s));
      }
    }
    // mind the unanchored nuget pattern: f…nuget.config matches as a whole name, and so does any name ending in nuget.config
    expect(rx('(?i)nuget\\.config$').test('mynuget.config')).toBe(true);
    expect(suffixFor('mynuget.config')).toBe('.nuget.config');
    expect(rx('(?i)nuget\\.config$').test('f00000001.nuget.config')).toBe(true);
  });

  it('betterleaks\' code-file list (isCodeFile, a discard of unquoted values in code) matches a staged name only for .php and .tf, and exactly when the original did', () => {
    const code = PATH_FILTERS.filter((f) => f.kind === 'code-file');
    expect(code.length).toBeGreaterThan(0);
    const isCode = (p: string): boolean => code.some((f) => rx(f.pattern).test(p));
    for (const s of STAGE_SUFFIXES) expect(isCode(`f00000001${s}`), s).toBe(['.php', '.tf'].includes(s));
    for (const orig of ['a.php', 'x/Y.PHP', 'infra/main.tf', 'M.TF', 'x.hcl', 'k.yaml', 'k.YML', 'nuget.config', 'c.p12', 'c.PFX']) {
      const s = suffixFor(orig);
      expect(isCode(`f00000001${s}`), `${orig} -> ${s}`).toBe(isCode(orig));
    }
  });

  it('betterleaks\' test-or-documentation list only labels confidence, and matches no staged name', () => {
    const conf = PATH_FILTERS.filter((f) => f.kind === 'confidence');
    expect(conf.length).toBeGreaterThan(0);
    for (const s of STAGE_SUFFIXES) for (const name of staged(s)) expect(conf.some((f) => rx(f.pattern).test(name)), name).toBe(false);
  });

  it('suffixFor runs each path rule\'s own pattern on the original path; STAGED_NAME_RE allows exactly the staged forms', () => {
    const cases: [string, string][] = [
      ['a.php', '.php'], ['x/Y.PHP', '.php'], ['infra/main.tf', '.tf'], ['M.TF', '.tf'], ['x.hcl', '.hcl'], ['k8s/a.yaml', '.yaml'], ['k8s/a.YML', '.yml'],
      ['NuGet.Config', '.nuget.config'], ['src/mynuget.config', '.nuget.config'], ['c.p12', '.p12'], ['c.PFX', '.pfx'], ['dir/.pfx', '.txt'],
      ['a.tfvars', '.txt'], ['a.yaml.bak', '.txt'], ['nuget.config.old', '.txt'], ['package-lock.json', '.txt'], ['node_modules/x.js', '.txt'], ['gitleaks.toml/app.js', '.txt'],
    ];
    for (const [p, s] of cases) expect(suffixFor(p), p).toBe(s);
    for (const s of STAGE_SUFFIXES) expect(STAGED_NAME_RE.test(`f00000001${s}`), s).toBe(true);
    for (const bad of ['f0000001.txt', 'f000000001.txt', 'F00000001.txt', 'f00000001.TXT', 'f00000001.js', './f00000001.txt', 'f00000001.txt!x', 'a/f00000001.txt', 'f00000001.txt\n']) expect(STAGED_NAME_RE.test(bad), bad).toBe(false);
  });

  it('the overlap of the pieces of a large file is at least the longest bounded match of any pinned rule, and at least 8 KiB', () => {
    expect(LONGEST_BOUNDED_MATCH.bytes).toBeGreaterThan(100);
    expect(PIECE_OVERLAP_BYTES).toBeGreaterThanOrEqual(Math.max(8 * 1024, LONGEST_BOUNDED_MATCH.bytes));
    expect(UNBOUNDED_RULES).toBeGreaterThan(0);
  });
});

describe('scripts/secrets-path-rules.ts', () => {
  it('maxMatchBytes: an upper bound on the bytes of a match (RE2 syntax); Infinity without a bound', () => {
    expect(maxMatchBytes('abc')).toBe(3);
    expect(maxMatchBytes('a{2,5}')).toBe(5);
    expect(maxMatchBytes('a{3}b?')).toBe(4);
    expect(maxMatchBytes('a+')).toBe(Infinity);
    expect(maxMatchBytes('a{2,}')).toBe(Infinity);
    expect(maxMatchBytes('(?i)k')).toBe(3);
    expect(maxMatchBytes('[a-z]{3}')).toBe(12);
    expect(maxMatchBytes('(?:ab|cde)')).toBe(3);
    expect(maxMatchBytes('\\x60\\b')).toBe(1);
    expect(maxMatchBytes('(?P<x>[\\]a]{2})')).toBe(8);
    expect(maxMatchBytes('^\\d{4}$')).toBe(16);
    expect(maxMatchBytes('a*?b')).toBe(Infinity);
  });

  const cfg = (over: string): string => `title = "t"\n${over}\n`;
  const base = { betterleaks: cfg('[[rules]]\nid = "x"\nregex = \'\'\'abc\'\'\'\n'), gitleaks: cfg('[[rules]]\nid = "y"\nregex = \'\'\'a{2}\'\'\'\n') };
  it('extract reads the global and per-rule allowlists, the CEL path lists and the path rules', () => {
    const x = extract({
      betterleaks: cfg(`prefilter = '''\nmatchesAny(attributes["path"], [\n  \`(?:^|/)node_modules(?:/.*)?$\`,\n  \`[a-z]+\\.min\\.js$\`\n])\n'''\n[[rules]]\nid = "p"\npath = '''(?i)\\.php$'''\nregex = '''x'''\nfilter = '''\nlet isCodeFile = filter.matchesAny(attributes["path"], [\`(?i)\\.js$\`]);\nisCodeFile || matchesAny(attributes["path"], [\`README\\.md$\`])\n'''\n`),
      gitleaks: cfg(`[allowlist]\npaths = ['''go\\.sum$''']\n[[rules]]\nid = "g"\nregex = '''x'''\n[[rules.allowlists]]\ncondition = "AND"\npaths = ['''\\.bb$''']\nregexes = ['''y''']\n`),
    });
    expect(x.pathRules).toEqual([{ tool: 'betterleaks', rule: 'p', pattern: '(?i)\\.php$', suffixes: ['.php'] }]);
    expect(x.pathFilters.map((f) => [f.tool, f.kind, f.pattern])).toEqual([
      ['betterleaks', 'skip-file', '(?:^|/)node_modules(?:/.*)?$'], ['betterleaks', 'skip-file', '[a-z]+\\.min\\.js$'], ['betterleaks', 'code-file', '(?i)\\.js$'], ['betterleaks', 'drop-finding', 'README\\.md$'],
      ['gitleaks', 'skip-file', 'go\\.sum$'], ['gitleaks', 'drop-finding-and', '\\.bb$'],
    ]);
    expect(extract(base).longestBounded).toMatchObject({ bytes: 3 });
  });

  it('extract refuses a path rule with no reviewed suffix, a path test it does not read, and a pattern JavaScript reads otherwise', () => {
    expect(() => extract({ ...base, gitleaks: cfg('[[rules]]\nid = "n"\npath = \'\'\'(?i)\\.env$\'\'\'\n') })).toThrow(/no reviewed suffix/);
    expect(() => extract({ ...base, betterleaks: cfg(`[[rules]]\nid = "c"\nregex = '''x'''\nfilter = '''\nattributes["path"].endsWith(".js")\n'''\n`) })).toThrow(/path lists this script reads/);
    expect(() => extract({ ...base, betterleaks: cfg(`[[rules]]\nid = "c"\nregex = '''x'''\nfilter = '''\nlet other = matchesAny(attributes["path"], [\`x\`]);\n'''\n`) })).toThrow(/named other/);
    expect(() => extract({ ...base, gitleaks: cfg(`[allowlist]\npaths = ['''a(?i)b''']\n`) })).toThrow(/inline flag/);
    expect(Object.keys(KNOWN_PATH_RULES).sort()).toEqual(PATH_RULES.filter((r) => r.tool === 'gitleaks').map((r) => r.pattern).sort());
  });

  it.skipIf(!live)('live: the table equals what the script reads from the pinned configs today (fetched from the release tags, sha256-checked)', async () => {
    const texts = { betterleaks: '', gitleaks: '' };
    for (const c of PINNED_CONFIGS) texts[c.tool] = await fetchPinned(c);
    expect(render(extract(texts))).toBe(readFileSync(GENERATED_PATH, 'utf8'));
  }, 120_000);
});
