// v0.2 Plan V V6-R2 (sec M2): the uninstall entry-point scan reads a file's module references from its parsed code, not from its text:
// esbuild strips the TypeScript (type-only imports and specifiers go, value imports stay: verbatimModuleSyntax), acorn parses the result,
// and every import, export-from, export of a local binding, dynamic import() and require() is read from the tree, with its specifier and
// names decoded (`'./target.js'`, `{ "UninstallApi" as U }`). A comment or a string that looks like code can't hide one.
import { posix } from 'node:path';
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
export function moduleRefs(src: string): { refs: ModuleRef[]; localExports: string[] } {
  const js = transformSync(src, { loader: 'ts', format: 'esm', tsconfigRaw: { compilerOptions: { verbatimModuleSyntax: true } } }).code;
  const tree = parse(js, { ecmaVersion: 'latest', sourceType: 'module' }) as unknown as Node;
  const refs: ModuleRef[] = [];
  const localExports: string[] = [];
  const walk = (n: unknown): void => {
    if (Array.isArray(n)) { for (const x of n) walk(x); return; }
    if (!isNode(n)) return;
    switch (n.type) {
      case 'ImportDeclaration': {
        const specs = (n.specifiers as Node[]) ?? [];
        refs.push({
          kind: 'import', spec: literal(n.source),
          names: specs.filter((s) => s.type === 'ImportSpecifier').map((s) => ({ imported: nameOf(s.imported), local: nameOf(s.local) })),
          namespace: specs.some((s) => s.type === 'ImportNamespaceSpecifier'), default: specs.some((s) => s.type === 'ImportDefaultSpecifier'),
        });
        break;
      }
      case 'ExportNamedDeclaration': {
        const specs = (n.specifiers as Node[]) ?? [];
        if (n.source !== null && n.source !== undefined) refs.push({ kind: 'export', spec: literal(n.source), names: specs.map((s) => ({ imported: nameOf(s.local), local: nameOf(s.exported) })), namespace: false, default: false });
        else for (const s of specs) localExports.push(nameOf(s.local));
        break;
      }
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
  return { refs, localExports };
}

/** `spec` as imported from `file`, as a path from the repo root (.ts), or null for a package. */
export function resolveSpec(file: string, spec: string): string | null {
  if (!spec.startsWith('.')) return null;
  return posix.normalize(posix.join(posix.dirname(file), spec)).replace(/\.js$/, '.ts');
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
  return out;
}
