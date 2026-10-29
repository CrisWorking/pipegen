// pipegen's npm closure locks (Plan B 6b fix round 1, DECISIONS #107): data/npm-closures/<entry-id>.json is a complete
// npm lockfile v3 for a minimal package.json that depends on exactly one checker tool (biome, eslint, oxlint, prettier,
// knip), its pinned plugins and, where a plugin peers on it, one pinned typescript. The renderer installs a checker from
// that file into a fresh folder under runner temp, never from the repo's lockfile, which any PR author can change.
// This module only reads and judges the file; scripts/npm-closure.ts makes it and scripts/cooldown.ts dates it.
// It imports only names.ts and package-data.ts, so the reviewed-list loader can use it.
import { readFileSync } from 'node:fs';
import type { ReviewedTool } from '../types.js';
import { isNpmName, SRI_SHA512_RE } from './names.js';
import { packageDataPath } from '../util/package-data.js';

export class NpmClosureError extends Error {}

export interface NpmPin { name: string; version: string; integrity: string }

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_PACKAGES = 3000;
const EXACT_RE = /^\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,40})?$/;
const ID_RE = /^[a-z0-9][a-z0-9-]{0,60}$/;
/** A dependency spec in a lock entry that is not a plain registry range: an alias, a path, a git or tarball source. */
const FOREIGN_SPEC_RE = /^(?:npm:|file:|link:|git|github:|gitlab:|bitbucket:|gist:|https?:|workspace:|portal:|patch:)|\/|\.tgz$/i;
/** Entry fields that mean something other than a plain registry package. */
const FORBIDDEN_FIELDS = ['link', 'inBundle', 'bundled', 'bundleDependencies', 'bundledDependencies', 'hasShrinkwrap'] as const;
const DEP_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'] as const;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The tool and every plugin of a checker entry, with the exact version and integrity the closure must hold. */
export function expectedPins(tool: ReviewedTool): NpmPin[] {
  const cli = tool.step.cli;
  if (cli === undefined) return [];
  return [
    { name: cli.install.package, version: cli.install.version, integrity: tool.candidate.pin.checksum ?? '' },
    ...(cli.plugins ?? []).map((p) => ({ name: p.package, version: p.version, integrity: p.checksum ?? '' })),
  ];
}

const NAME = '(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*';
/** `node_modules/<name>` or `node_modules/<name>/node_modules/<name>…`: nothing else (no `.` or `..` segment, no absolute path, no other folder). */
const KEY_RE = new RegExp(`^node_modules/(?:${NAME}/node_modules/)*(${NAME})$`);

/** The package name a `node_modules/…` key stands for (its last segment), or null for a key that isn't exactly that shape. */
function nameOfKey(key: string): string | null {
  const m = KEY_RE.exec(key);
  return m === null ? null : (m[1] as string);
}

/** Plain-English problems with a closure's text; empty = fine. */
export function closureProblems(text: string, pins: readonly NpmPin[]): string[] {
  const out: string[] = [];
  if (typeof text !== 'string' || text.length > MAX_BYTES) return ['the closure is not text of a sane size'];
  let lock: unknown;
  try {
    lock = JSON.parse(text);
  } catch {
    return ['the closure is not valid JSON'];
  }
  if (!isObj(lock) || lock.lockfileVersion !== 3 || !isObj(lock.packages)) return ['the closure is not an npm lockfile v3 with a `packages` section'];
  const packages = lock.packages;
  const keys = Object.keys(packages);
  if (keys.length > MAX_PACKAGES) return ['the closure has too many packages'];
  const root = packages[''];
  if (isObj(root)) for (const f of Object.keys(root)) if (f !== 'name' && f !== 'version' && f !== 'dependencies') out.push(`the root package has ${f}; only name, version and dependencies are allowed`);
  if (!isObj(root) || !isObj(root.dependencies)) out.push('the closure has no root package with dependencies');
  else for (const [name, spec] of Object.entries(root.dependencies)) if (typeof spec !== 'string' || !EXACT_RE.test(spec) || !isNpmName(name)) out.push(`the root depends on ${name} at ${String(spec)}, not an exact version`);
  for (const key of keys) {
    if (key === '') continue;
    const e = packages[key];
    const name = nameOfKey(key);
    if (name === null || !isObj(e)) { out.push(`"${key.slice(0, 80)}" is not a package under node_modules/`); continue; }
    for (const f of FORBIDDEN_FIELDS) if (f in e) out.push(`${key} has ${f}, which is not a plain registry package`);
    const version = e.version;
    if (typeof version !== 'string' || !EXACT_RE.test(version)) { out.push(`${key} has no exact version`); continue; }
    const base = name.slice(name.indexOf('/') + 1);
    if (e.resolved !== `https://registry.npmjs.org/${name}/-/${base}-${version}.tgz`) out.push(`${key} is not resolved from https://registry.npmjs.org/${name}/-/${base}-${version}.tgz (an alias, path, git or other source)`);
    if (typeof e.integrity !== 'string' || !SRI_SHA512_RE.test(e.integrity)) out.push(`${key} has no sha512 integrity`);
    for (const f of DEP_FIELDS) {
      const deps = e[f];
      if (deps === undefined) continue;
      if (!isObj(deps)) { out.push(`${key} has a malformed ${f}`); continue; }
      for (const [d, spec] of Object.entries(deps)) if (typeof spec !== 'string' || FOREIGN_SPEC_RE.test(spec)) out.push(`${key} depends on ${d} through ${String(spec).slice(0, 40)}, not a registry range`);
    }
  }
  for (const p of pins) {
    const e = packages[`node_modules/${p.name}`];
    if (!isObj(e)) out.push(`the closure does not hold ${p.name}`);
    else {
      if (e.version !== p.version) out.push(`the closure holds ${p.name} ${String(e.version)}, not the reviewed ${p.version}`);
      if (e.integrity !== p.integrity) out.push(`the closure holds ${p.name} ${p.version} with another integrity than the reviewed entry`);
    }
    if (isObj(root) && isObj(root.dependencies) && root.dependencies[p.name] !== p.version) out.push(`the root does not depend on ${p.name} at exactly ${p.version}`);
  }
  return out;
}

/** The root `dependencies` of a closure (name → exact version); the renderer writes them into a fixed package.json. Call only on text that passed closureProblems. */
export function closureRootDependencies(text: string): Record<string, string> {
  const lock = JSON.parse(text) as { packages: { '': { dependencies: Record<string, string> } } };
  return { ...lock.packages[''].dependencies };
}

/**
 * The closure text of a checker entry, read and judged. `read` is how the file is read (default: pipegen's own
 * data/npm-closures/<id>.json). Throws NpmClosureError for a missing, unreadable or malformed file.
 */
export function loadNpmClosure(id: string, pins: readonly NpmPin[], read: (id: string) => string = readClosureFile): string {
  if (!ID_RE.test(id)) throw new NpmClosureError('an npm closure is named after a plain reviewed entry id');
  let text: string;
  try {
    text = read(id);
  } catch (e) {
    throw new NpmClosureError(`the npm closure lock of ${id} could not be read`, { cause: e });
  }
  const problems = closureProblems(text, pins);
  if (problems.length > 0) throw new NpmClosureError(`the npm closure lock of ${id} is refused: ${problems[0]}`);
  return text;
}

function readClosureFile(id: string): string {
  return readFileSync(packageDataPath(`npm-closures/${id}.json`), 'utf8');
}
