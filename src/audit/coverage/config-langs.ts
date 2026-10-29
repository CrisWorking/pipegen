// Coverage mapper (see ../coverage.ts for the rules): the languages a multi-language tool really checks, from its
// config (P60 R2). A leaf module: pure functions, no I/O.
//   - semgrep: `--config`/`-c` values (and the action's `config:` input). Registry packs map to their languages
//     (https://semgrep.dev/explore: p/python, p/django → Python; p/javascript, p/typescript, p/react → JavaScript and
//     TypeScript; …); multi-language packs (auto, p/default, p/ci, p/security-audit, p/owasp-top-ten, p/secrets, …) are
//     any language; a rule id `r/<language>.…` is that language; a local rules file is read for its rules' `languages:`;
//     anything else (an unknown pack, a URL, a folder, a variable) is a language pipegen can't tell ('?').
//   - CodeQL: the init step's `languages:` (https://github.com/github/codeql-action/blob/main/init/action.yml).
// Language tags are src/types.ts Language values, plus 'none' (the tool checks no service language: Terraform,
// Dockerfiles, C) and '?' (pipegen can't tell). 'any' means every language.

const PACKS: Readonly<Record<string, readonly string[]>> = {};
const pack = (langs: readonly string[], names: string) => { for (const n of names.split(' ')) (PACKS as Record<string, readonly string[]>)[n] = langs; };
pack(['any'], 'default ci security-audit owasp-top-ten r2c-ci r2c-security-audit r2c-best-practices cwe-top-25 secrets insecure-transport jwt sql-injection xss command-injection gitleaks supply-chain comment');
pack(['python'], 'python django flask fastapi bandit');
pack(['node'], 'javascript typescript nodejs react nextjs express eslint-plugin-security nodejsscan angular vue');
pack(['go'], 'golang go gosec');
pack(['java'], 'java spring findsecbugs kotlin');
pack(['ruby'], 'ruby rails brakeman');
pack(['php'], 'php laravel phpcs-security-audit symfony');
pack(['dotnet'], 'csharp');
pack(['none'], 'terraform dockerfile kubernetes docker-compose github-actions c');

/** semgrep's language names (a rule's `languages:`, the first part of an `r/` id) as service languages. */
const SEMGREP_LANG: Readonly<Record<string, string>> = {
  python: 'python', py: 'python', python3: 'python', javascript: 'node', js: 'node', typescript: 'node', ts: 'node', go: 'go', golang: 'go',
  java: 'java', kotlin: 'java', kt: 'java', ruby: 'ruby', rb: 'ruby', php: 'php', csharp: 'dotnet', 'c#': 'dotnet', cs: 'dotnet',
  generic: 'any', regex: 'any', none: 'any',
};
const semgrepLang = (name: string): string => SEMGREP_LANG[name.toLowerCase()] ?? 'none';

/**
 * One semgrep config value: its languages, or `{ file }` for a local rules file to read (a plain relative path), or '?'.
 * null = a value pipegen can't read (a variable, an expression).
 */
export function semgrepConfig(value: string | null): readonly string[] | { file: string } {
  if (value === null || value === '' || /[$`*?{}\s'"]/.test(value)) return ['?'];
  if (value === 'auto') return ['any'];
  const p = /^p\/([a-z0-9-]{1,64})$/.exec(value);
  if (p !== null) return PACKS[p[1] as string] ?? ['?'];
  const r = /^r\/([A-Za-z0-9#]+)\./.exec(value);
  if (r !== null) return [semgrepLang(r[1] as string)];
  if (/^[a-z][a-z0-9+.-]*:/i.test(value) || value.endsWith('/')) return ['?']; // a URL, a folder
  if (/\.ya?ml$/.test(value) && /^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,200}$/.test(value) && !value.split('/').includes('..')) return { file: value };
  return ['?'];
}

/** The languages a semgrep rules file's rules list, or ['?'] when it can't be read that way. */
export function ruleFileLangs(doc: unknown): readonly string[] {
  const rules = (doc as { rules?: unknown } | null)?.rules;
  if (!Array.isArray(rules)) return ['?'];
  const out = new Set<string>();
  for (const rule of rules) {
    const langs = (rule as { languages?: unknown } | null)?.languages;
    if (!Array.isArray(langs) || !langs.every((l) => typeof l === 'string')) return ['?'];
    for (const l of langs as string[]) out.add(semgrepLang(l));
  }
  return out.size === 0 ? ['none'] : [...out];
}

/** CodeQL's language names (init `languages:`) as service languages. */
export function codeqlLang(name: string): string {
  const n = name.trim().toLowerCase();
  if (['javascript', 'javascript-typescript', 'typescript', 'js'].includes(n)) return 'node';
  if (['java', 'java-kotlin', 'kotlin'].includes(n)) return 'java';
  if (n === 'csharp') return 'dotnet';
  if (['python', 'go', 'ruby'].includes(n)) return n;
  return 'none';
}

/** Several language tags as Found.langs: undefined when one is 'any'; 'none' alone when nothing else is left. */
export function toLangs(tags: Iterable<string>): readonly string[] | undefined {
  const set = new Set(tags);
  if (set.has('any')) return undefined;
  if (set.size > 1) set.delete('none');
  return [...set];
}
