// Builds THIRD_PARTY_NOTICES from what tsup actually bundles (ruling B4). pipegen has zero runtime `dependencies`
// (everything is a devDependency that the bundler inlines), so the list cannot come from `dependencies`: it comes from the
// esbuild metafile that the release build writes to .build/meta.json (outside dist/, never packed).
//
//   node scripts/notices.ts            write THIRD_PARTY_NOTICES (run `npm run build` first; `npm pack` does both)
//   node scripts/notices.ts --sbom-only <file>   write only a CycloneDX 1.5 JSON SBOM of the same bundled packages
//                                      (the release workflow's SBOM; never lists devDependencies that are not bundled)
//
// For every package that has an input file under node_modules/ (scoped and nested copies included) it reads package.json
// `name`, `version` and `license`, plus the LICENSE / COPYING / NOTICE files in the package folder, and writes them in a
// fixed order (name@version, licence id, licence text). It fails when a package has no licence field, a licence outside
// ALLOWED_LICENSES, or no licence text (unless scripts/notices-overrides.json has a reviewed entry for that exact
// name@version). Files are read bounded, as regular files, never through a symlink.
// Keep to syntax Node's type stripping can run (no enums, no parameter properties, no namespaces).
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readFileSync, readSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** SPDX ids pipegen accepts in its bundle. Unlicense was added after checking the bundle (fast-sha256, a public-domain dedication). */
export const ALLOWED_LICENSES: readonly string[] = ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', '0BSD', 'BlueOak-1.0.0', 'CC0-1.0', 'Python-2.0', 'Unlicense'];

export const MAX_FILE_BYTES = 256 * 1024;
export const MAX_NOTICE_FILES = 8;
export const MAX_PACKAGES = 2000;

export interface Metafile {
  inputs: Record<string, unknown>;
}
export interface Override {
  reason: string;
  text: string;
}
export type Overrides = Record<string, Override>;
export interface NoticeEntry {
  name: string;
  version: string;
  license: string;
  files: { name: string; text: string }[];
}

const PKG_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const LICENSE_FILE = /^(?:licen[cs]e|licen[cs]ing|copying|copyright|notice)(?:[-._][^/\\]*)?$/i;
const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** The package folders (relative, `/`-separated, like `node_modules/micromatch/node_modules/picomatch`) with an input in the bundle. */
export function bundledPackageDirs(meta: Metafile): string[] {
  if (typeof meta !== 'object' || meta === null || typeof meta.inputs !== 'object' || meta.inputs === null) throw new Error('metafile has no `inputs`');
  const dirs = new Set<string>();
  for (const input of Object.keys(meta.inputs)) {
    const parts = input.split('/');
    let last = -1;
    for (let i = 0; i < parts.length; i++) if (parts[i] === 'node_modules') last = i; // the innermost node_modules decides
    if (last < 0) continue;
    const first = parts[last + 1];
    if (first === undefined) continue;
    const take = first.startsWith('@') ? 2 : 1;
    const name = parts.slice(last + 1, last + 1 + take).join('/');
    if (take === 2 && parts[last + 2] === undefined) continue;
    if (!PKG_NAME.test(name)) throw new Error(`unexpected package folder name in the metafile: ${JSON.stringify(name)}`);
    dirs.add(parts.slice(0, last + 1 + take).join('/'));
    if (dirs.size > MAX_PACKAGES) throw new Error(`more than ${MAX_PACKAGES} bundled packages; refusing`);
  }
  return [...dirs].sort(byCodeUnit);
}

/** Reads a regular file of at most MAX_FILE_BYTES; refuses a symlink (lstat, and O_NOFOLLOW where the OS has it). */
export function readBounded(path: string): string {
  const st = lstatSync(path);
  if (st.isSymbolicLink()) throw new Error(`${path} is a symlink; refusing to follow it`);
  if (!st.isFile()) throw new Error(`${path} is not a regular file`);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const fst = fstatSync(fd);
    if (!fst.isFile()) throw new Error(`${path} is not a regular file`);
    if (fst.size > MAX_FILE_BYTES) throw new Error(`${path} is larger than ${MAX_FILE_BYTES} bytes`);
    const buf = Buffer.alloc(MAX_FILE_BYTES + 1);
    let n = 0;
    for (;;) {
      const r = readSync(fd, buf, n, buf.length - n, null);
      if (r === 0) break;
      n += r;
      if (n > MAX_FILE_BYTES) throw new Error(`${path} is larger than ${MAX_FILE_BYTES} bytes`);
    }
    const slice = buf.subarray(0, n);
    if (slice.includes(0)) throw new Error(`${path} looks binary (NUL byte)`);
    return slice.toString('utf8');
  } finally {
    closeSync(fd);
  }
}

/** Every licence id in an SPDX expression like `(MIT OR Apache-2.0)`. */
export function licenseIds(expr: string): string[] {
  return expr.replace(/[()]/g, ' ').split(/\s+(?:OR|AND)\s+/i).map((s) => s.trim()).filter((s) => s !== '');
}

const normalize = (text: string): string => text.replace(/\r\n?/g, '\n').replace(/\s+$/, '');

export function readPackage(root: string, dir: string, overrides: Overrides = {}, allowed: readonly string[] = ALLOWED_LICENSES): NoticeEntry {
  const abs = join(root, dir);
  if (lstatSync(abs).isSymbolicLink()) throw new Error(`${dir} is a symlink; refusing to follow it`);
  let pkg: { name?: unknown; version?: unknown; license?: unknown };
  try {
    pkg = JSON.parse(readBounded(join(abs, 'package.json'))) as typeof pkg;
  } catch (e) {
    throw new Error(`${dir}: cannot read package.json (${(e as Error).message})`);
  }
  const { name, version, license } = pkg;
  if (typeof name !== 'string' || typeof version !== 'string') throw new Error(`${dir}: package.json has no name or version`);
  if (!dir.endsWith(`node_modules/${name}`)) throw new Error(`${dir}: package.json name ${JSON.stringify(name)} does not match its folder`);
  if (typeof license !== 'string' || license.trim() === '') throw new Error(`${name}@${version}: no \`license\` in package.json`);
  const ids = licenseIds(license);
  if (ids.length === 0) throw new Error(`${name}@${version}: no \`license\` in package.json`);
  for (const id of ids) if (!allowed.includes(id)) throw new Error(`${name}@${version}: licence ${JSON.stringify(id)} is not in the allowlist (${allowed.join(', ')})`);

  const names = readdirSync(abs, { withFileTypes: true })
    .filter((d) => LICENSE_FILE.test(d.name) && d.isFile()) // a Dirent for a symlink is not isFile(), so links are skipped
    .map((d) => d.name)
    .sort(byCodeUnit);
  if (names.length > MAX_NOTICE_FILES) throw new Error(`${name}@${version}: ${names.length} licence files, more than ${MAX_NOTICE_FILES}`);
  const files = names.map((n) => ({ name: n, text: normalize(readBounded(join(abs, n))) })).filter((f) => f.text !== '');
  if (files.length === 0) {
    const o = overrides[`${name}@${version}`];
    if (o === undefined || typeof o.text !== 'string' || o.text.trim() === '' || typeof o.reason !== 'string' || o.reason.trim() === '') {
      throw new Error(`${name}@${version}: no licence text found in ${dir} (add a reviewed entry to scripts/notices-overrides.json if the package ships none)`);
    }
    files.push({ name: '(no licence file in the package)', text: normalize(o.text) });
  }
  return { name, version, license, files };
}

const RULE = '='.repeat(80);
const THIN = '-'.repeat(80);

export function renderNotices(entries: NoticeEntry[], bundle: 'cli' | 'gate' = 'cli'): string {
  const sorted = [...entries].sort((a, b) => byCodeUnit(`${a.name}@${a.version}`, `${b.name}@${b.version}`));
  const out: string[] = [
    'THIRD-PARTY NOTICES',
    '',
    bundle === 'gate'
      ? "pipegen's gate action is run as one bundled file, gate/dist/index.js, which contains the packages listed below. Each is"
      : 'pipegen is published as one bundled file, dist/cli/main.js, which contains the packages listed below. Each is',
    'listed with its version, its licence, and the licence (and NOTICE) text it ships. This file is generated by',
    'scripts/notices.ts from the build metafile; do not edit it by hand.',
    '',
  ];
  let last = '';
  for (const e of sorted) {
    const body = e.files.map((f) => `File: ${f.name}\n\n${f.text}`).join('\n\n');
    const block = `${RULE}\n${e.name}@${e.version}\nLicense: ${e.license}\n${THIN}\n${body}\n`;
    if (block === last) continue; // the same version bundled from two folders, identical text: listed once
    last = block;
    out.push(block);
  }
  return `${out.join('\n')}`;
}

export function buildNotices(root: string, meta: Metafile, overrides: Overrides = {}, allowed: readonly string[] = ALLOWED_LICENSES, bundle: 'cli' | 'gate' = 'cli'): { text: string; count: number } {
  const dirs = bundledPackageDirs(meta);
  if (dirs.length === 0) throw new Error('the metafile lists no node_modules packages; wrong or empty build?');
  const entries = dirs.map((d) => readPackage(root, d, overrides, allowed));
  return { text: renderNotices(entries, bundle), count: dirs.length };
}

/** purl for an npm package: the scope's `@` is percent-encoded. */
const purl = (name: string, version: string): string => `pkg:npm/${name.replace(/^@/, '%40')}@${version}`;

/** CycloneDX 1.5 JSON of exactly the bundled packages (the NoticeEntry list). No timestamp or serial number, so it is reproducible. */
export function renderSbom(entries: NoticeEntry[], app: { name: string; version: string }): string {
  const seen = new Set<string>();
  const components: unknown[] = [];
  for (const e of [...entries].sort((a, b) => byCodeUnit(`${a.name}@${a.version}`, `${b.name}@${b.version}`))) {
    const ref = purl(e.name, e.version);
    if (seen.has(ref)) continue;
    seen.add(ref);
    const ids = licenseIds(e.license);
    components.push({
      type: 'library', 'bom-ref': ref, name: e.name, version: e.version, purl: ref,
      licenses: ids.map((id) => ({ license: { id } })),
    });
  }
  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: { component: { type: 'application', 'bom-ref': 'pipegen', name: app.name, version: app.version } },
    components,
  };
  return `${JSON.stringify(bom, null, 2)}\n`;
}

export function buildSbom(root: string, meta: Metafile, app: { name: string; version: string }, overrides: Overrides = {}, allowed: readonly string[] = ALLOWED_LICENSES): { text: string; count: number } {
  const dirs = bundledPackageDirs(meta);
  if (dirs.length === 0) throw new Error('the metafile lists no node_modules packages; wrong or empty build?');
  const entries = dirs.map((d) => readPackage(root, d, overrides, allowed));
  return { text: renderSbom(entries, app), count: dirs.length };
}

function main(argv: string[]): number {
  const root = process.cwd();
  const pos: string[] = [];
  let sbomOnly: string | null = null;
  let gate = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === '--sbom-only') {
      const v = argv[++i];
      if (v === undefined) throw new Error('--sbom-only needs a file');
      sbomOnly = v;
    } else if (a === '--gate') gate = true;
    else pos.push(a);
  }
  const metaPath = pos[0] ?? '.build/meta.json';
  const outPath = pos[1] ?? 'THIRD_PARTY_NOTICES';
  let meta: Metafile;
  try {
    meta = JSON.parse(readFileSync(join(root, metaPath), 'utf8')) as Metafile; // our own build output, larger than a licence file may be
  } catch (e) {
    console.error(`notices: cannot read ${metaPath} (run \`npm run build\` first): ${(e as Error).message}`);
    return 1;
  }
  const overrides = JSON.parse(readFileSync(join(import.meta.dirname, 'notices-overrides.json'), 'utf8')) as Overrides;
  if (sbomOnly !== null) {
    const app = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { name: string; version: string };
    const { text, count } = buildSbom(root, meta, app, overrides);
    writeFileSync(join(root, sbomOnly), text);
    console.log(`sbom: ${count} bundled packages written to ${sbomOnly}`);
    return 0;
  }
  const { text, count } = buildNotices(root, meta, overrides, ALLOWED_LICENSES, gate ? 'gate' : 'cli');
  writeFileSync(join(root, outPath), text);
  console.log(`notices: ${count} bundled packages written to ${outPath}`);
  return 0;
}

if (import.meta.main) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(`notices: ${(e as Error).message}`);
    process.exit(1);
  }
}
