// One YAML document as plain data, or the reasons pipegen refuses it (S29). A leaf shared by the referee and the created-file judges
// (dependabot.yml), so no second parser can drift from the first.
import { isScalar, LineCounter, parseAllDocuments, visit, type Document } from 'yaml';
import { safeText } from '../util/safe-text.js';

export type Obj = Record<string, unknown>;
export const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
export const uniq = <T>(xs: Iterable<T>): T[] => [...new Set(xs)];

/** `scalars`: every string key and value as parsed (escapes decoded), for the secret-value check (S18). */
export interface Parsed { doc: Document; js: Obj; lines: LineCounter; scalars: string[] }

/**
 * One YAML document as a map, or the problems that make pipegen refuse it. `strict` (a file pipegen wrote whole): no
 * anchor or alias at all. `user` (a user's own workflow pipegen edited): the user's anchors are theirs, so they resolve
 * (bounded); the parts pipegen inserted are checked for them separately. Both refuse `<<` merge keys, tags, directives,
 * duplicate keys, a key that is not text, more than one document and anything that is not a map.
 */
export function parseYaml(text: string, mode: 'strict' | 'user'): { parsed: Parsed } | { problems: string[] } {
  const lines = new LineCounter();
  const problems: string[] = [];
  let docs: Document[];
  try {
    docs = parseAllDocuments(text, { uniqueKeys: true, lineCounter: lines, prettyErrors: false }) as unknown as Document[];
  } catch {
    return { problems: ['it is not YAML pipegen can read'] };
  }
  if (docs.length !== 1) return { problems: [`it holds ${docs.length} YAML documents; a workflow is exactly one`] };
  const doc = docs[0] as Document;
  for (const e of doc.errors) problems.push(e.code === 'DUPLICATE_KEY' ? 'a key is set twice (a later one could hide the first from a reader)' : `it is not valid YAML (${safeText(e.code, 40)})`);
  if (doc.warnings.length > 0) problems.push(`the YAML parser warns about it (${safeText(doc.warnings[0]?.code ?? '', 40)})`);
  const directives = doc.directives;
  if (directives?.yaml.explicit === true || Object.keys(directives?.tags ?? {}).some((h) => h !== '!!' && h !== '!')) problems.push('it has a YAML directive (%YAML or %TAG), which changes how values are read');
  const scalars: string[] = [];
  visit(doc, {
    Alias() { if (mode === 'strict') problems.push('it uses a YAML alias (*name), which can copy a key past a reader'); },
    // the S18 values are collected here, not in a Scalar visitor: one would replace this one for scalars, and their tags and
    // anchors would go unchecked (review-7a-r1 finding 2)
    Node(_, n) {
      if (isScalar(n) && typeof n.value === 'string') scalars.push(n.value);
      if (n.tag !== undefined) problems.push('it has a YAML tag (!!type), which changes what a value is');
      if (mode === 'strict' && n.anchor !== undefined) problems.push('it defines a YAML anchor (&name)');
    },
    Pair(_, p) {
      if (!isScalar(p.key) || typeof p.key.value !== 'string') problems.push('a key is not plain text');
      else if (p.key.value === '<<') problems.push('it has a << merge key, which can bring in keys a reader does not see');
    },
  });
  if (problems.length > 0) return { problems: uniq(problems) };
  let js: unknown;
  try {
    js = doc.toJS({ maxAliasCount: mode === 'strict' ? 0 : 100 });
  } catch {
    return { problems: ['its aliases can not be resolved within the limit'] };
  }
  if (!isObj(js)) return { problems: ['it is not a map of keys'] };
  return { parsed: { doc, js, lines, scalars } };
}
