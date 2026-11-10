// v0.2 Plan V V6-R2 (sec M2): the uninstall entry-point scan reads a file's module references from its parsed code, not from its text:
// esbuild strips the TypeScript (type-only imports and specifiers go, value imports stay: verbatimModuleSyntax), acorn parses the result,
// and every import, export-from, export of a local binding, dynamic import() and require() is read from the tree, with its specifier and
// names decoded (`'./target.js'`, `{ "UninstallApi" as U }`). A comment or a string that looks like code can't hide one.
import { readdirSync } from 'node:fs';
import { join, posix } from 'node:path';
import { parse } from 'acorn';
import { transformSync } from 'esbuild';

/** One module reference of a file. `spec` null: a dynamic import or require whose argument is not a plain string. */
export interface ModuleRef {
  kind: 'import' | 'export' | 'export-all' | 'dynamic' | 'require';
  spec: string | null;
  names: { imported: string; local: string }[];
  namespace: boolean;
  default: boolean;
}

type Node = { type: string; [k: string]: unknown };
const isNode = (v: unknown): v is Node => typeof v === 'object' && v !== null && typeof (v as { type?: unknown }).type === 'string';
const nameOf = (n: unknown): string => (isNode(n) ? (n.type === 'Identifier' ? String(n.name) : String(n.value)) : '');
const literal = (n: unknown): string | null => (isNode(n) && n.type === 'Literal' && typeof n.value === 'string' ? n.value : null);

/** The module references of a TypeScript file, and the names it exports from its own bindings (`export { x as y }` → x). */
export function moduleRefs(src: string): { refs: ModuleRef[]; localExports: string[]; exported: string[]; tree: unknown } {
  const js = transformSync(src, { loader: 'ts', format: 'esm', tsconfigRaw: { compilerOptions: { verbatimModuleSyntax: true } } }).code;
  const tree = parse(js, { ecmaVersion: 'latest', sourceType: 'module' }) as unknown as Node;
  const refs: ModuleRef[] = [];
  const localExports: string[] = [];
  /** Every name the file exports, in any form (declaration, specifier, default); V7: src/cli/uninstall.ts exports one. */
  const exported: string[] = [];
  const walk = (n: unknown): void => {
    if (Array.isArray(n)) { for (const x of n) walk(x); return; }
    if (!isNode(n)) return;
    switch (n.type) {
      case 'ImportDeclaration': {
        const specs = (n.specifiers as Node[]) ?? [];
        refs.push({
          kind: 'import', spec: literal(n.source),
          names: specs.filter((s) => s.type === 'ImportSpecifier').map((s) => ({ imported: nameOf(s.imported), local: nameOf(s.local) })),
          namespace: specs.some((s) => s.type === 'ImportNamespaceSpecifier'),
          // V7 (G10): `import { default as d }` is a default import
          default: specs.some((s) => s.type === 'ImportDefaultSpecifier' || (s.type === 'ImportSpecifier' && nameOf(s.imported) === 'default')),
        });
        break;
      }
      case 'ExportNamedDeclaration': {
        const specs = (n.specifiers as Node[]) ?? [];
        for (const s of specs) exported.push(nameOf(s.exported));
        if (isNode(n.declaration)) {
          if (n.declaration.type === 'VariableDeclaration') for (const d of (n.declaration.declarations as Node[])) exported.push(isNode(d.id) && d.id.type === 'Identifier' ? nameOf(d.id) : '(pattern)');
          else exported.push(isNode(n.declaration.id) ? nameOf(n.declaration.id) : '(unnamed)');
        }
        if (n.source !== null && n.source !== undefined) refs.push({ kind: 'export', spec: literal(n.source), names: specs.map((s) => ({ imported: nameOf(s.local), local: nameOf(s.exported) })), namespace: false, default: specs.some((s) => nameOf(s.local) === 'default') });
        else for (const s of specs) localExports.push(nameOf(s.local));
        break;
      }
      case 'ExportDefaultDeclaration':
        exported.push('default');
        break;
      case 'ExportAllDeclaration':
        refs.push({ kind: 'export-all', spec: literal(n.source), names: [], namespace: true, default: false });
        break;
      case 'ImportExpression':
        refs.push({ kind: 'dynamic', spec: literal(n.source), names: [], namespace: true, default: false });
        break;
      case 'CallExpression':
        if (isNode(n.callee) && n.callee.type === 'Identifier' && n.callee.name === 'require') {
          refs.push({ kind: 'require', spec: literal((n.arguments as unknown[])[0]), names: [], namespace: true, default: false });
        }
        break;
      default: break;
    }
    for (const [k, v] of Object.entries(n)) if (k !== 'type' && typeof v === 'object') walk(v);
  };
  walk(tree);
  return { refs, localExports, exported, tree };
}

/** `spec` as imported from `file`, as a path from the repo root (.ts), or null for a package. */
export function resolveSpec(file: string, spec: string): string | null {
  if (!spec.startsWith('.')) return null;
  // V7: every spelling of a source file's name (.js, .mjs, .cjs, .ts, .mts, .cts, or none) resolves to the module's .ts file
  return posix.normalize(posix.join(posix.dirname(file), spec)).replace(/\.(?:[cm]?[jt]s)$/, '') + '.ts';
}

/** The extensions of source files under src/ (V7, G13): all of them are read by the scans, so a .mts or .js file can't hide a module reference. */
const CODE_EXT = /\.(?:[cm]?[jt]s|[jt]sx)$/;
/** Every file under `dir`: `code` (read by the scans, whatever its extension) and `other` (a file that isn't code: a problem under src/). */
export function codeFilesUnder(dir: string): { code: string[]; other: string[] } {
  const code: string[] = [];
  const other: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) { const sub = codeFilesUnder(p); code.push(...sub.code); other.push(...sub.other); }
    else if (CODE_EXT.test(e.name)) code.push(p);
    else other.push(p);
  }
  return { code, other };
}

/**
 * V7 (V6-R3 M3): a guarded or writer binding may appear in a file only as the target of a call or `new`. Any other reference (assigned,
 * exported under any form, `extends`, in an object or array, passed as an argument, `.call`) is a way of handing it on. Returns the names.
 * Scope is not tracked: a parameter of the same name counts too (the safe side).
 */
function handedOn(tree: unknown, locals: ReadonlySet<string>): string[] {
  const out = new Set<string>();
  const walk = (n: unknown, parent: Node | null, key: string): void => {
    if (Array.isArray(n)) { for (const x of n) walk(x, parent, key); return; }
    if (!isNode(n)) return;
    if (n.type === 'Identifier' && locals.has(String(n.name)) && parent !== null) {
      const p = parent;
      const declared = p.type === 'ImportSpecifier' || p.type === 'ImportDefaultSpecifier' || p.type === 'ImportNamespaceSpecifier';
      const member = p.type === 'MemberExpression' && key === 'property' && p.computed !== true;
      const named = (p.type === 'Property' || p.type === 'PropertyDefinition' || p.type === 'MethodDefinition') && key === 'key' && p.computed !== true && p.shorthand !== true;
      const exportedAs = p.type === 'ExportSpecifier' && key === 'exported';
      const called = (p.type === 'CallExpression' || p.type === 'NewExpression') && key === 'callee';
      if (!declared && !member && !named && !exportedAs && !called) out.add(String(n.name));
    }
    for (const [k, v] of Object.entries(n)) if (k !== 'type' && typeof v === 'object' && v !== null) walk(v, n, k);
  };
  walk(tree, null, '');
  return [...out];
}

/**
 * V7 (V6-R3 M3): what src/cli/uninstall.ts may import, module by module and name by name (apply.ts's one entry, the loader, and read-only
 * helpers). Everything else, any default, namespace, dynamic, require or re-export form, and any package but the two listed, is a problem.
 * A second src/cli file (G14) can't hand the file a proof or uninstall binding: only commands.ts and io.ts of src/cli are listed.
 */
const CLI_UNINSTALL_ALLOWED: Readonly<Record<string, readonly string[]>> = {
  'src/uninstall/apply.ts': ['uninstallStep', 'holdUninstallLease'], 'src/uninstall/errors.ts': ['UninstallError', 'UninstallFinished'],
  'src/uninstall/progress.ts': ['MAX_PROGRESS_BYTES', 'uninstallProgressPath'], 'src/uninstall/record.ts': ['loadUninstallRecord'],
  'src/cli/commands.ts': ['interactiveRun'], 'src/cli/io.ts': [], 'src/deliver/record.ts': ['localRecordPath'],
  'src/engine/github-rate.ts': ['isRateStop'], 'src/github/client.ts': ['GitHubAccessError', 'hideToken'],
  'src/read/project.ts': ['NotGitHubRepoError'], 'src/util/safe-text.ts': ['safeText'], 'src/proof/state.ts': [],
};
const CLI_UNINSTALL_PACKAGES: Readonly<Record<string, readonly string[]>> = { 'node:fs': ['lstatSync', 'readFileSync'], '@octokit/rest': [] };
export const CLI_UNINSTALL_FILE = 'src/cli/uninstall.ts';
function cliUninstallProblems(refs: ModuleRef[], exported: string[]): string[] {
  const out: string[] = [];
  // it hands nothing on: one export, the command (a re-export, an `export const x = <import>` or a default would all show here)
  for (const x of exported) if (x !== 'uninstallCommand') out.push(`${CLI_UNINSTALL_FILE} exports ${x} (it exports only uninstallCommand)`);
  for (const r of refs) {
    if (r.spec === null) continue;   // reported above
    if (r.kind !== 'import') { out.push(`a ${r.kind} of ${r.spec} in ${CLI_UNINSTALL_FILE} (it only imports)`); continue; }
    if (r.namespace || r.default) { out.push(`a namespace or default import of ${r.spec} in ${CLI_UNINSTALL_FILE}`); continue; }
    const target = resolveSpec(CLI_UNINSTALL_FILE, r.spec);
    const allowed = target === null ? CLI_UNINSTALL_PACKAGES[r.spec] : CLI_UNINSTALL_ALLOWED[target];
    if (allowed === undefined) { out.push(`${r.spec} is not a module ${CLI_UNINSTALL_FILE} may import`); continue; }
    for (const n of r.names) if (!allowed.includes(n.imported)) out.push(`${n.imported} from ${r.spec} in ${CLI_UNINSTALL_FILE} (not on its allow-list)`);
  }
  return out;
}

/** The uninstall modules whose entry points are guarded (paths from the repo root). */
const GUARDED = ['src/uninstall/target.ts', 'src/uninstall/plan.ts', 'src/uninstall/apply.ts'];
/** E's scratch secret delete, its name spelled at run time (test/no-secret-literals.test.ts). */
const SCRATCH_SD = ['deleteScratch', 'Secret'].join('');
const E_WRITERS = ['cleanupWrite', SCRATCH_SD, 'deleteScratchRepo', 'cleanupLeftovers'];
const eAllowed = (f: string): boolean => f.startsWith('src/proof/') || f === 'src/cli/cleanup.ts' || f === 'src/uninstall/apply.ts';
/** Value names, and the only files that may import them. */
const ENTRY_ALLOWED: Readonly<Record<string, (file: string) => boolean>> = {
  UninstallApi: (f) => f === 'src/uninstall/plan.ts',
  planUninstall: (f) => f === 'src/uninstall/apply.ts', confirmPlan: (f) => f === 'src/uninstall/apply.ts',
  takeApi: (f) => f === 'src/uninstall/apply.ts', deleteCentralRepo: (f) => f === 'src/uninstall/apply.ts',
  // V9a (V8 sec i2): the whole flow, the loader and the lease are the CLI command's only
  uninstallStep: (f) => f === CLI_UNINSTALL_FILE, loadUninstallRecord: (f) => f === CLI_UNINSTALL_FILE, holdUninstallLease: (f) => f === CLI_UNINSTALL_FILE,
  ...Object.fromEntries(E_WRITERS.map((n) => [n, eAllowed])),
};
/**
 * V6-R2 sec M2: what uninstall's files (and V7's src/cli/uninstall.ts) may take from src/proof: read-only values only. apply.ts, the
 * phase-bound api, also takes E's scratch writers and the app's lease store.
 */
const PROOF_READ = ['proofTarget', 'assertScratch', 'isProofTarget', 'validBranchName', 'SCRATCH_MARKER', 'SCRATCH_PREFIX', 'CENTRAL_REPO', 'helperDescription', 'githubRead', 'ProofStopError', 'ScratchGuardError', 'StateError'];
const PROOF_APPLY = [...PROOF_READ, ...E_WRITERS, 'StateStore'];
const proofRestricted = (f: string): boolean => (f.startsWith('src/uninstall/') || f === 'src/cli/uninstall.ts');

/** What the allow-list finds wrong in one file of src/ (`file` from the repo root). */
export function entryImportProblems(file: string, src: string): string[] {
  const out: string[] = [];
  let parsed: ReturnType<typeof moduleRefs>;
  try { parsed = moduleRefs(src); } catch (e) { return [`${file} could not be parsed (${e instanceof Error ? e.message.slice(0, 120) : 'error'})`]; }
  const where = (spec: string): string | null => resolveSpec(file, spec);
  const guarded = (spec: string): boolean => { const r = where(spec); return r !== null && GUARDED.includes(r) && r !== file; };
  const proof = (spec: string): boolean => { const r = where(spec); return r !== null && r.startsWith('src/proof/'); };
  const entryLocals = new Set<string>();
  for (const r of parsed.refs) {
    if (r.spec === null) { out.push(`a ${r.kind} of something that is not a plain string in ${file}`); continue; }
    if (r.kind === 'dynamic' || r.kind === 'require') {
      if (guarded(r.spec) || (proofRestricted(file) && proof(r.spec))) out.push(`a ${r.kind} of ${r.spec} in ${file}`);
      continue;
    }
    if (r.kind === 'export-all') { if (guarded(r.spec) || proof(r.spec)) out.push(`export * from ${r.spec} in ${file}`); continue; }
    if ((r.namespace || r.default) && (guarded(r.spec) || (proofRestricted(file) && proof(r.spec)))) { out.push(`a namespace or default import of ${r.spec} in ${file}`); continue; }
    for (const n of r.names) {
      const ok = ENTRY_ALLOWED[n.imported];
      if (r.kind === 'export' && (ok !== undefined || guarded(r.spec))) out.push(`a re-export of ${n.imported} from ${r.spec} in ${file}`);
      else if (ok !== undefined && !ok(file)) out.push(`${n.imported} imported in ${file}`);
      if (r.kind === 'import' && proofRestricted(file) && proof(r.spec) && !(file === 'src/uninstall/apply.ts' ? PROOF_APPLY : PROOF_READ).includes(n.imported)) out.push(`${n.imported} from ${r.spec} in ${file} (not a read-only value of src/proof)`);
      if (r.kind === 'import' && ok !== undefined) entryLocals.add(n.local);
    }
  }
  // F8: an allowed file handing a guarded binding on under another name
  for (const l of parsed.localExports) if (entryLocals.has(l)) out.push(`an export of the imported ${l} in ${file}`);
  // V7 (G1-G5, G11, G12): ... under any form: the binding is only a call or `new` target in the file that imports it
  for (const l of handedOn(parsed.tree, entryLocals)) if (!parsed.localExports.includes(l)) out.push(`the imported ${l} is used in ${file} other than as a call or new target`);
  if (file === CLI_UNINSTALL_FILE) out.push(...cliUninstallProblems(parsed.refs, parsed.exported));
  return out;
}
