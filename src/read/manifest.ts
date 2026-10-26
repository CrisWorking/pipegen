import { regexLines, regexSafe } from './limits.js';

export type Obj = Record<string, unknown>;

/** Env var and secret names: what env.ts and workflows.ts keep. */
export const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/** Source files scanned for env var references and port defaults. */
export const CODE_FILE_RE = /\.(js|mjs|cjs|jsx|ts|tsx|mts|cts|py)$/;
/** pip requirements files, matched on the file name (requirements.txt, requirements-dev.txt, ...). */
export const REQUIREMENTS_FILE_RE = /^requirements.*\.txt$/;

/** Repo-relative path helpers (forward slashes, '.' is the repo root). */
export const inDir = (dir: string, name: string): string => (dir === '.' ? name : `${dir}/${name}`);
export const dirOf = (file: string): string => (file.includes('/') ? file.slice(0, file.lastIndexOf('/')) : '.');
export const baseOf = (file: string): string => file.slice(file.lastIndexOf('/') + 1);

/** The package lines of a requirements file: comments and option lines (-r, -e, --hash ...) are left out. */
export const requirementLines = (text: string): string[] => regexLines(text).filter((l) => !/^\s*(#|-)/.test(l));
export const asObj = (v: unknown): Obj => (v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});
export const asStrings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
export const asString = (v: unknown): string | undefined => (typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined);

/** Package names from PEP 508 strings or requirements lines, lowercased with _ as -. */
export function pythonNames(lines: string[]): string[] {
  return lines.filter(regexSafe).flatMap((l) => {
    const name = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(l)?.[1];
    return name ? [name.toLowerCase().replace(/[._]/g, '-')] : [];
  });
}

export interface PyInfo { main: string[]; all: string[]; scripts: string[]; requires?: string; name?: string }

/** A service's manifests, read and parsed once by readProject (with notes for anything skipped) and shared with readEnv. */
export interface Manifests { pkg: Obj | null; py: PyInfo; requirements: { file: string; names: string[] }[] }

export function readPyproject(toml: Obj | null): PyInfo {
  const project = asObj(toml?.project);
  const poetry = asObj(asObj(toml?.tool).poetry);
  const poetryDeps = asObj(poetry.dependencies);
  const groups = Object.values(asObj(poetry.group)).flatMap((g) => Object.keys(asObj(asObj(g).dependencies)));
  const main = [...pythonNames(asStrings(project.dependencies)), ...Object.keys(poetryDeps).filter((k) => k !== 'python').map((k) => k.toLowerCase())];
  const extras = [
    ...Object.values(asObj(project['optional-dependencies'])).flatMap(asStrings),
    ...Object.values(asObj(toml?.['dependency-groups'])).flatMap(asStrings),
    ...asStrings(asObj(asObj(asObj(toml?.tool).uv))['dev-dependencies']),
  ];
  return {
    main,
    all: [...main, ...pythonNames(extras), ...groups.map((g) => g.toLowerCase()), ...Object.keys(asObj(poetry['dev-dependencies'])).map((k) => k.toLowerCase())],
    scripts: [...Object.keys(asObj(project.scripts)), ...Object.keys(asObj(poetry.scripts))],
    requires: asString(project['requires-python']) ?? asString(poetryDeps.python),
    name: asString(project.name) ?? asString(poetry.name),
  };
}

/** Test files and test folders: test/, tests/, __tests__/, *.test.*, *.spec.*, test_*.py, *_test.py. `rel` is relative to the service. */
export const isTestFile = (rel: string): boolean => {
  if (!regexSafe(rel)) return false;
  const segments = rel.split('/');
  const name = segments[segments.length - 1] ?? '';
  return segments.slice(0, -1).some((s) => ['test', 'tests', '__tests__'].includes(s)) || /^.+\.(test|spec)\..+$/.test(name) || /^test_.+\.py$/.test(name) || /_test\.py$/.test(name);
};

