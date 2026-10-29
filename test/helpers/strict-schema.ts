// Checks a JSON schema against OpenAI's structured-output `strict: true` rules (shared by the schema tests).
type Json = Record<string, unknown>;

/** OpenAI `strict: true` rules: every object closed, every property required (nullable instead of optional). */
export function strictProblems(s: unknown, at = '$'): string[] {
  if (s === null || typeof s !== 'object') return [];
  const node = s as Json;
  const out: string[] = [];
  if (node.type === 'object') {
    if (node.additionalProperties !== false) out.push(`${at}: object not closed`);
    const keys = Object.keys((node.properties ?? {}) as Json).sort();
    const req = [...((node.required ?? []) as string[])].sort();
    if (JSON.stringify(keys) !== JSON.stringify(req)) out.push(`${at}: not every property is required`);
  }
  for (const [k, v] of Object.entries(node)) {
    if (Array.isArray(v)) v.forEach((x, i) => out.push(...strictProblems(x, `${at}.${k}[${i}]`)));
    else if (v !== null && typeof v === 'object') out.push(...strictProblems(v, `${at}.${k}`));
  }
  return out;
}
