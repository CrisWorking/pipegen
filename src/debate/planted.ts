// The planted problems every proof carries (v0.2 Plan F Task 4; rulings B4, B5, S15-S18; spec §10, §19).
//
// Plan E puts these files on the `planted` variant branch only (next to `main`, never on it), and every dispute variant carries
// them too. Each blocking scanner must catch its planted item, or the proof fails that need (evaluate.ts plantedChecks):
//   secret       a generic high-entropy API key (never a provider format)        repo root   pipegen-planted/config.txt
//   iac          a security group open to 0.0.0.0/0 on port 22 (Terraform only)  repo root   pipegen-planted/main.tf
//   sast-<lang>  a SQL query built from request input (node: .js, python: .py)   per service <service>/pipegen-planted/sast-<lang>[-<tag>].<ext>
//   deps-<lang>  a manifest with a known-vulnerable dependency (lodash 4.17.11,  per service <service>/pipegen-planted/deps-<lang>[-<tag>]/<manifest>
//                PyYAML 5.3), copied from data/planted/*.planted
// Per-service scanners `cd` into the service folder (render-cli.ts cdLines), so sast and deps items sit under each scanned
// service's own pipegen-planted/ (B5). The deps manifest is two levels below the service root, so neither the service's own
// install nor a one-level workspace glob (`*`) takes it in (Review Focus 3). A folder other than the repo root adds a tag (its
// slug) to every name, so a path relative to a service root names one item only (the matcher accepts that form, S17).
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
import { PLAIN_REL_RE } from '../engine/tool-flags.js';
import type { PlantedItem as EvalPlantedItem } from '../proof/evaluate.js';
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
};

export class PlantedError extends Error {}

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

const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const DIGITS = '0123456789';
/** Largest multiple of 62 (and of 10) under 256: a byte at or above it is dropped, so every character is equally likely. */
const B62_LIMIT = 248;
const DIGIT_LIMIT = 250;
/** A source that keeps failing the rules is broken (or not random): stop rather than loop. */
const MAX_SECRET_BYTES = 1 << 16;
const MIN_ENTROPY = 4;
/**
 * The scanners' stopwords that a value with no 3-letter run can still hold: a value holding one is dropped by the generic rule.
 * Measured (F5) on the pinned gitleaks 8.30.1 and betterleaks 1.9.0 against every stopword with no 3-letter run: md5 (any case)
 * and six zeros. Re-measure when a pinned secrets scanner changes.
 */
const REACHABLE_STOPWORDS = /md5|000000/i;

const isLetter = (c: string): boolean => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

/**
 * The planted secret (S15): 40 base62 characters from `random` (node:crypto randomBytes by default) by rejection sampling,
 * with a digit, an upper and a lower letter, and no run of 3 or more letters (after two letters the next character is a digit),
 * so a scanner's stopword filter (a dictionary word inside the value) can't drop it, and none of the stopwords that rule leaves
 * reachable (REACHABLE_STOPWORDS: md5, six zeros). Shannon entropy at least 4. Every rule is
 * met by drawing again, never by editing the value. A generic key: no provider prefix can appear (no `_` or `-`, no four letters
 * in a row). Throws PlantedError when the source gives no usable bytes.
 */
export function plantedSecret(random: (n: number) => Uint8Array = (n) => randomBytes(n)): string {
  let used = 0;
  for (;;) {
    let v = '';
    let letters = 0;
    while (v.length < PLANTED_SECRET_LENGTH) {
      const bytes = random(64);
      if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new PlantedError('The random source for the planted secret gave no bytes.');
      used += bytes.length;
      if (used > MAX_SECRET_BYTES) throw new PlantedError('The random source for the planted secret never met its rules; it is not random.');
      for (const b of bytes) {
        if (v.length >= PLANTED_SECRET_LENGTH) break;
        if (letters >= 2) {
          if (b >= DIGIT_LIMIT) continue;
          v += DIGITS[b % 10];
          letters = 0;
        } else {
          if (b >= B62_LIMIT) continue;
          const c = B62[b % 62] as string;
          v += c;
          letters = isLetter(c) ? letters + 1 : 0;
        }
      }
    }
    if (/[0-9]/.test(v) && /[A-Z]/.test(v) && /[a-z]/.test(v) && !REACHABLE_STOPWORDS.test(v) && entropy(v) >= MIN_ENTROPY) return v;
  }
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
  const item = (id: string, category: PlantedCategory, text: string, file: string, critical: boolean) => {
    expected.push({ id, category, item: text, file, critical, minSeverity: 'high' });
  };

  const secret = `${PLANTED_DIR}/config.txt`;
  files.push({ path: secret, content: `api_key = "${plantedSecret(opts.random)}"\n` });
  item('secret', 'secrets', PLANTED_ITEM_TEXT.secret, secret, true);

  if (p.terraformDirs.length > 0) {
    const tf = `${PLANTED_DIR}/main.tf`;
    files.push({ path: tf, content: TERRAFORM });
    item('iac', 'iac', PLANTED_ITEM_TEXT.iac, tf, false);
  }

  // one entry per folder (first appearance order), with its planted languages (first appearance order)
  const folders = new Map<string, PlantedLanguage[]>();
  for (const s of p.services) {
    const folder = serviceFolder(s.path);
    if (s.language !== 'node' && s.language !== 'python') continue;
    const langs = folders.get(folder) ?? [];
    if (!langs.includes(s.language)) langs.push(s.language);
    folders.set(folder, langs);
  }
  const tags = new Set<string>();
  for (const [folder, langs] of folders) {
    let tag = '';
    if (folder !== '') {
      let base: string;
      try { base = slug(folder); } catch { base = 'folder'; }
      tag = base;
      for (let n = 2; tags.has(tag); n++) tag = `${base}-${n}`;
      tags.add(tag);
    }
    const dir = folder === '' ? PLANTED_DIR : `${folder}/${PLANTED_DIR}`;
    const suffix = tag === '' ? '' : `-${tag}`;
    const idSuffix = tag === '' ? '' : `--${tag}`;
    for (const lang of langs) {
      const sast = `${dir}/sast-${lang}${suffix}.${SQL[lang].ext}`;
      files.push({ path: sast, content: SQL[lang].body });
      item(`sast-${lang}${idSuffix}`, 'sast', PLANTED_ITEM_TEXT[`sast-${lang}`], sast, false);
      const depsDir = `${dir}/deps-${lang}${suffix}`;
      for (const fx of PLANTED_FIXTURES[lang]) files.push({ path: `${depsDir}/${fx.name}`, content: fixture(fx.data) });
      item(`deps-${lang}${idSuffix}`, 'deps', PLANTED_ITEM_TEXT[`deps-${lang}`], `${depsDir}/${(PLANTED_FIXTURES[lang].at(-1) as { name: string }).name}`, true);
    }
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
      const at = findings.findIndex((f, j) => !used.has(j) && typeof f === 'object' && f !== null && f.tool === tool && typeof f.file === 'string' && ok.has(f.file) && rankOf(f.severity) >= min);
      if (at >= 0) { used.add(at); caught = true; }
    }
    result.set(e.id, (result.get(e.id) ?? true) && caught);
  });
  const caught: string[] = [];
  const missed: string[] = [];
  for (const [id, ok] of result) (ok ? caught : missed).push(id);
  return { caught, missed };
}
