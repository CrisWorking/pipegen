// The planted problems every proof carries (v0.2 Plan F Task 4; rulings B4, B5, S15-S18; spec §10, §19).
//
// Plan E puts these files on the `planted` variant branch only (next to `main`, never on it), and every dispute variant carries
// them too. Each blocking scanner must catch its planted item, or the proof fails that need (evaluate.ts plantedChecks):
//   secret       a generic high-entropy API key (never a provider format)        repo root   pipegen-planted/config.txt
//   iac          a security group open to 0.0.0.0/0 on port 22 (Terraform only)  repo root   pipegen-planted/main.tf
//   sast-<lang>  a SQL query built from request input (node: .js, python: .py)   per service <service>/pipegen-planted/sast-<lang>-<slug>.<ext>
//   deps-<lang>  a manifest with a known-vulnerable dependency (lodash 4.17.11,  per service <service>/pipegen-planted/deps-<lang>-<slug>/<manifest>
//                PyYAML 5.3), copied from data/planted/*.planted
// Per-service scanners `cd` into the service folder (render-cli.ts cdLines), so sast and deps items sit under each scanned
// service's own pipegen-planted/ (B5). The deps manifest is two levels below the service root, so neither the service's own
// install nor a one-level workspace glob (`*`) takes it in (Review Focus 3).
// Every item carries its need key (jobIdFor(category, service), the gate job's id; ruling F5-R3), and the matcher credits it only
// to a finding of that job: a root service's recursive scan that also reports a sub-service's planted file never proves the
// sub-service's own scanner. So each node or python service gets its own items, named by its slug (`<slug>` above), even two
// services in one folder; the names also keep a path relative to a service root unique (the matcher accepts that form, S17).
//
// Nothing planted is ever delivered: the folder name is PLANTED_DIR, and isPlantedPath (a pipegen-planted segment at any depth)
// is the rule Plan G's delivery test uses. The C1b placements (snapshot.ts plantedSecretPlacements) are Plan E's and sit
// outside pipegen-planted/; this module never moves or copies them.
//
// The fixtures are stored as `*.planted` (S16): pipegen's own repo and package hold no real manifest a dependency bot or
// GitHub's dependency graph would read; the real names exist only on the proof branch.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { slug } from '../engine/artifact-names.js';
import { jobIdFor } from '../engine/gate-job-list.js';
import { PLAIN_REL_RE } from '../engine/tool-flags.js';
import type { PlantedItem as EvalPlantedItem } from '../proof/evaluate.js';
import type { SourcedFinding } from '../proof/gate-result.js';
import { PlantedError, plantedKeyValue } from '../proof/planted-value.js';
import { isWorkflowPath, type ProofFile } from '../proof/snapshot.js';
import type { Finding, Language, RepoProfile, Severity } from '../types.js';
import { packageDataPath } from '../util/package-data.js';

/** The folder every planted file sits in (at the repo root or at a service root). Plan G never delivers a path with this segment. */
export const PLANTED_DIR = 'pipegen-planted';
/** The blocking categories that have a planted item (S18): secrets, deps and sast always; iac only with Terraform. */
export const PLANTED_CATEGORIES = Object.freeze(['secrets', 'deps', 'sast', 'iac'] as const);
export type PlantedCategory = typeof PLANTED_CATEGORIES[number];
/** The planted secret's length: 40 base62 characters. */
export const PLANTED_SECRET_LENGTH = 40;

/**
 * One planted item (ruling B4): Plan E's type (`id`, `category`, `item`, `file?`) with a required file, the scoring weight and
 * the severity floor. Plan G passes these as EvalContext.plantedItems.
 */
export type PlantedItem = EvalPlantedItem & {
  /** The repo-relative path of the file the scanner must report. */
  file: string;
  /** Scoring weight only (spec §10): a missed critical loses the comparison. */
  critical: boolean;
  /** The lowest finding severity that counts: high for every item (the gate's block floor). */
  minSeverity: Severity;
  /**
   * The need key of the item's own need (jobIdFor(category, service): `secrets`, `iac`, `sast--<slug>`, `deps--<slug>`), the gate
   * job that must catch it (F5-R3). Only a finding whose `needKey` (asFindings) equals it counts.
   */
  needKey: string;
};

export { PlantedError };

/** The fixed English evaluate prints after "didn't catch the planted" (no article, no repo text). */
export const PLANTED_ITEM_TEXT = Object.freeze({
  secret: 'hard-coded API key in a config file',
  'deps-node': 'npm dependency with known critical vulnerabilities (lodash 4.17.11)',
  'deps-python': 'Python dependency with known critical vulnerabilities (PyYAML 5.3)',
  'sast-node': 'SQL query built from request input (JavaScript)',
  'sast-python': 'SQL query built from request input (Python)',
  iac: 'security group open to the internet on port 22 (Terraform)',
} as const);

type PlantedLanguage = Extract<Language, 'node' | 'python'>;
/** The manifests of each language: the name written on the proof branch and the fixture under data/ (S16). The last one is the file the deps scanner reports. */
export const PLANTED_FIXTURES: Readonly<Record<PlantedLanguage, readonly { name: string; data: string }[]>> = Object.freeze({
  node: Object.freeze([
    { name: 'package.json', data: 'planted/node/package.json.planted' },
    { name: 'package-lock.json', data: 'planted/node/package-lock.json.planted' },
  ]),
  python: Object.freeze([{ name: 'requirements.txt', data: 'planted/python/requirements.txt.planted' }]),
});

const HEADER = 'pipegen planted problem, on a proof branch only';
const SQL: Readonly<Record<PlantedLanguage, { ext: string; body: string }>> = {
  // the error-level tainted-SQL rules (S17): req.query → a string-concatenated db.query
  node: {
    ext: 'js',
    body: [
      `// ${HEADER}: a SQL query built from request input. Never delivered.`,
      "const express = require('express');",
      "const mysql = require('mysql');",
      '',
      'const app = express();',
      "const db = mysql.createConnection({ host: 'localhost', database: 'app' });",
      '',
      "app.get('/user', (req, res) => {",
      `  db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => {`,
      '    if (err) return res.status(500).end();',
      '    res.json(rows);',
      '  });',
      '});',
      '',
      'module.exports = app;',
      '',
    ].join('\n'),
  },
  // request.args → a string-concatenated cursor.execute
  python: {
    ext: 'py',
    body: [
      `# ${HEADER}: a SQL query built from request input. Never delivered.`,
      'import sqlite3',
      '',
      'from flask import Flask, request',
      '',
      'app = Flask(__name__)',
      '',
      '',
      '@app.route("/user")',
      'def user():',
      '    conn = sqlite3.connect("app.db")',
      '    cursor = conn.cursor()',
      `    cursor.execute("SELECT * FROM users WHERE name = '" + request.args.get("name") + "'")`,
      '    return str(cursor.fetchall())',
      '',
    ].join('\n'),
  },
};
const TERRAFORM = [
  `# ${HEADER}: a security group open to the internet on port 22. Never delivered.`,
  'resource "aws_security_group" "pipegen_planted" {',
  '  name        = "pipegen-planted"',
  '  description = "pipegen planted problem"',
  '',
  '  ingress {',
  '    description = "ssh from anywhere"',
  '    from_port   = 22',
  '    to_port     = 22',
  '    protocol    = "tcp"',
  '    cidr_blocks = ["0.0.0.0/0"]',
  '  }',
  '}',
  '',
].join('\n');

// ---------- the secret ----------

/**
 * The planted secret (S15): 40 base62 characters from `random` (node:crypto randomBytes by default) under the one planted-value
 * rule (src/proof/planted-value.ts, shared with Plan E's C1b placements): rejection sampling, a digit, an upper and a lower
 * letter, no run of 3 letters, no reachable stopword (md5, six zeros), entropy at least 4, all by drawing again. Throws
 * PlantedError when the source gives no usable bytes.
 */
export function plantedSecret(random: (n: number) => Uint8Array = (n) => randomBytes(n)): string {
  return plantedKeyValue(PLANTED_SECRET_LENGTH, random);
}

// ---------- paths ----------

const segmentsOf = (p: string): string[] => p.split(/[\\/]/);
/** A segment as a case-insensitive file system sees it (Windows also drops trailing dots and spaces). */
const isPlantedSegment = (s: string): boolean => s.replace(/[. ]+$/, '').toLowerCase() === PLANTED_DIR;
const lossy = new TextDecoder('utf-8', { ignoreBOM: true });

/**
 * True when the path has a pipegen-planted segment at any depth (either slash, any case, trailing dots or spaces ignored).
 * Plan G's delivery never includes such a path (spec §19).
 */
export function isPlantedPath(path: string | Uint8Array): boolean {
  const p = typeof path === 'string' ? path : lossy.decode(path);
  return segmentsOf(p).some(isPlantedSegment);
}

const NO_SLUG = 'A service name has no letters or digits, so pipegen has no id for its checks. Rename it.';
const SAME_SLUG = "Two services have names that give the same id once cleaned, so pipegen can't tell their checks apart. Rename one of them.";
const BAD_SERVICE_PATH = "A service folder is not a plain folder inside the repository, so pipegen can't plant its scanners' items there.";
const IN_PLANTED = 'A service folder is inside a pipegen-planted folder, which is never delivered, so pipegen refuses to plan around it.';

/** A service's folder as a repo-relative path without `.` segments ('' for the root). Refuses anything not plain. */
function serviceFolder(path: string): string {
  if (path.startsWith('/') || path.includes('\\')) throw new PlantedError(BAD_SERVICE_PATH);
  const parts = path.split('/').filter((s) => s !== '' && s !== '.');
  if (parts.some((s) => s === '..')) throw new PlantedError(BAD_SERVICE_PATH);
  const folder = parts.join('/');
  if (folder === '') return '';
  if (!PLAIN_REL_RE.test(folder)) throw new PlantedError(BAD_SERVICE_PATH);
  if (parts.some(isPlantedSegment)) throw new PlantedError(IN_PLANTED);
  return folder;
}

const BOT_CONFIG = /^(?:\.github\/dependabot\.ya?ml|renovate\.json5?|\.github\/renovate\.json5?|\.gitlab\/renovate\.json5?|\.renovaterc(?:\.json5?)?)$/i;

// ---------- the files ----------

export interface PlantedOptions {
  /** The random source for the secret (default node:crypto randomBytes). Tests inject one; never Math.random. */
  random?: (n: number) => Uint8Array;
  /**
   * The base tree's paths (the app repo's files). When given, a planted path that is taken (the same path, a file at one of
   * its folders) or any base path inside a pipegen-planted folder is refused: the proof would not show what it claims.
   */
  basePaths?: ReadonlySet<string>;
}

let fixtureCache: Map<string, string> | undefined;
function fixture(rel: string): string {
  fixtureCache ??= new Map();
  let text = fixtureCache.get(rel);
  if (text === undefined) {
    text = readFileSync(packageDataPath(rel), 'utf8');
    fixtureCache.set(rel, text);
  }
  return text;
}

/**
 * The planted files and the items each blocking scanner must catch (S15). Repo-wide items (secrets, and iac when the repo has
 * Terraform) sit under the root's pipegen-planted/; sast and deps items under every scanned service's own pipegen-planted/, one
 * per (folder, language) for node and python services (B5). Files are ProofFiles: they go on the planted and dispute branches
 * only, never into a CreatedFile (delivery) list. Throws PlantedError for a service folder that is not plain, a planted path in
 * a workflow or bot config place, or a collision with `basePaths`; the message holds no repo text.
 */
export function plantedFiles(p: RepoProfile, opts: PlantedOptions = {}): { files: ProofFile[]; expected: PlantedItem[] } {
  const files: ProofFile[] = [];
  const expected: PlantedItem[] = [];
  const item = (id: string, category: PlantedCategory, text: string, file: string, critical: boolean, needKey: string) => {
    expected.push({ id, category, item: text, file, critical, minSeverity: 'high', needKey });
  };

  const secret = `${PLANTED_DIR}/config.txt`;
  files.push({ path: secret, content: `api_key = "${plantedSecret(opts.random)}"\n` });
  item('secret', 'secrets', PLANTED_ITEM_TEXT.secret, secret, true, jobIdFor('secrets'));

  if (p.terraformDirs.length > 0) {
    const tf = `${PLANTED_DIR}/main.tf`;
    files.push({ path: tf, content: TERRAFORM });
    item('iac', 'iac', PLANTED_ITEM_TEXT.iac, tf, false, jobIdFor('iac'));
  }

  // every service's slug names its jobs (jobIdFor): two services with one slug, or a name with none, can't be told apart
  const slugs = new Set<string>();
  for (const s of p.services) {
    let tag: string;
    try { tag = slug(s.name); } catch { throw new PlantedError(NO_SLUG); }
    if (slugs.has(tag)) throw new PlantedError(SAME_SLUG);
    slugs.add(tag);
  }
  // one set of items per node or python service, in profile order: its own folder, its own names, its own need keys
  for (const s of p.services) {
    const folder = serviceFolder(s.path);
    if (s.language !== 'node' && s.language !== 'python') continue;
    const lang: PlantedLanguage = s.language;
    const tag = slug(s.name);
    const dir = folder === '' ? PLANTED_DIR : `${folder}/${PLANTED_DIR}`;
    const sast = `${dir}/sast-${lang}-${tag}.${SQL[lang].ext}`;
    files.push({ path: sast, content: SQL[lang].body });
    item(`sast-${lang}--${tag}`, 'sast', PLANTED_ITEM_TEXT[`sast-${lang}`], sast, false, jobIdFor('sast', s.name));
    const depsDir = `${dir}/deps-${lang}-${tag}`;
    for (const fx of PLANTED_FIXTURES[lang]) files.push({ path: `${depsDir}/${fx.name}`, content: fixture(fx.data) });
    item(`deps-${lang}--${tag}`, 'deps', PLANTED_ITEM_TEXT[`deps-${lang}`], `${depsDir}/${(PLANTED_FIXTURES[lang].at(-1) as { name: string }).name}`, true, jobIdFor('deps', s.name));
  }

  for (const f of files) {
    const path = f.path as string;
    if (isWorkflowPath(path) || BOT_CONFIG.test(path) || segmentsOf(path)[0]?.toLowerCase() === '.github') {
      throw new PlantedError('A planted file would sit in a workflow or bot config place; planted files never do.');
    }
  }
  if (opts.basePaths !== undefined) checkBase(files.map((f) => f.path as string), opts.basePaths);
  return { files, expected };
}

const TAKEN = 'A planted path is taken in the repository (the same path, a file where it needs a folder, or a pipegen-planted folder of its own), so pipegen refuses to plant there.';
function checkBase(planted: readonly string[], base: ReadonlySet<string>): void {
  const baseDirs = new Set<string>();
  for (const b of base) {
    if (isPlantedPath(b)) throw new PlantedError(TAKEN);
    const parts = b.split('/');
    for (let i = 1; i < parts.length; i++) baseDirs.add(parts.slice(0, i).join('/'));
  }
  for (const path of planted) {
    if (base.has(path) || baseDirs.has(path)) throw new PlantedError(TAKEN);
    const parts = path.split('/');
    for (let i = 1; i < parts.length; i++) if (base.has(parts.slice(0, i).join('/'))) throw new PlantedError(TAKEN);
  }
}

// ---------- the matcher ----------

const RANK: Readonly<Record<Severity, number>> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const rankOf = (s: unknown): number => (typeof s === 'string' && Object.hasOwn(RANK, s) ? RANK[s as Severity] : -1);
/** The gate's block floor: no item counts a finding below high, whatever it asks for. */
const FLOOR_RANK = RANK.high;

/** The path relative to the service root that holds the item's planted folder ('x/pipegen-planted/f' → 'pipegen-planted/f'). */
function serviceRelative(file: string): string | undefined {
  const parts = file.split('/');
  const at = parts.findIndex((s) => s === PLANTED_DIR);
  return at > 0 ? parts.slice(at).join('/') : undefined;
}

/**
 * Plan E's injected matcher (EvalContext.matchPlanted; ruling S17). An item is caught by a finding when the finding's tool is
 * the category's tool, its file equals the item's repo-relative path (or the path relative to the item's service root, unless
 * that form also names another item), and its severity is at least the item's minSeverity and never below high. A finding counts
 * for one item only. An item with no file, a category with no tool, or a malformed entry is missed; an entry without an id is
 * skipped (it can't be reported). An id is caught only when every entry with that id is; each id is listed once.
 * Origin (F5-R3, F5-R4): an item is caught only by a finding whose own `needKey` (asFindings: the gate job that produced it)
 * equals the item's own `needKey` property (every item plantedFiles makes has one). An item without one, or with an empty or
 * non-string one, is never caught; nor is a finding with no readable origin (fail-closed). The fingerprint is never parsed.
 */
export function matchPlanted(findings: Finding[], expected: readonly EvalPlantedItem[], toolsByCategory: Map<string, string>): { caught: string[]; missed: string[] } {
  const items = expected.filter((e): e is EvalPlantedItem => typeof e === 'object' && e !== null && typeof e.id === 'string' && e.id !== '');
  const fileOf = (e: EvalPlantedItem): string | undefined => (typeof e.file === 'string' && e.file !== '' ? e.file : undefined);
  // every path each item would accept, to drop a service-relative form another item also names
  const named = new Map<string, number>();
  const accepted = items.map((e) => {
    const file = fileOf(e);
    if (file === undefined) return [] as string[];
    const rel = serviceRelative(file);
    return rel === undefined || rel === file ? [file] : [file, rel];
  });
  for (const paths of accepted) for (const p of paths) named.set(p, (named.get(p) ?? 0) + 1);
  const used = new Set<number>();
  const result = new Map<string, boolean>();
  items.forEach((e, i) => {
    const file = fileOf(e);
    const tool = typeof e.category === 'string' ? toolsByCategory.get(e.category) : undefined;
    let caught = false;
    if (file !== undefined && tool !== undefined) {
      const ok = new Set((accepted[i] as string[]).filter((p) => p === file || named.get(p) === 1));
      const asked = rankOf((e as Partial<PlantedItem>).minSeverity);
      const min = Math.max(FLOOR_RANK, asked);
      // fail-closed (F5-R4): the item's own needKey property, a non-empty string, or nothing can catch it
      const key = Object.hasOwn(e, 'needKey') ? (e as { needKey?: unknown }).needKey : undefined;
      const origin = (f: Finding): boolean => {
        const from = (f as SourcedFinding).needKey;
        return typeof key === 'string' && key !== '' && typeof from === 'string' && from === key;
      };
      const at = findings.findIndex((f, j) => !used.has(j) && typeof f === 'object' && f !== null && f.tool === tool && typeof f.file === 'string' && ok.has(f.file) && rankOf(f.severity) >= min && origin(f));
      if (at >= 0) { used.add(at); caught = true; }
    }
    result.set(e.id, (result.get(e.id) ?? true) && caught);
  });
  const caught: string[] = [];
  const missed: string[] = [];
  for (const [id, ok] of result) (ok ? caught : missed).push(id);
  return { caught, missed };
}
