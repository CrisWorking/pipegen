// One zod schema → the pair every AI call needs: the zod schema completeValidated checks answers with, and the
// JSON schema sent to the provider (Plan B ruling S5). The JSON schema must suit OpenAI's `strict: true` mode
// (every object closed, every property required: use .nullable(), never .optional()) and the Claude SDK's
// structured-output helper, so a schema that breaks those rules is refused here, before any request.
import { z } from 'zod';

export interface AiSchema<T> { zod: z.ZodType<T>; jsonSchema: Record<string, unknown> }

function check(node: unknown, at: string): void {
  if (node === null || typeof node !== 'object') return;
  const n = node as Record<string, unknown>;
  if (n.type === 'object') {
    if (n.additionalProperties !== false) throw new Error(`AI schema: the object at ${at} must be closed (use z.strictObject).`);
    const props = Object.keys((n.properties ?? {}) as object);
    const required = new Set((n.required ?? []) as string[]);
    const loose = props.filter((k) => !required.has(k));
    if (loose.length > 0) throw new Error(`AI schema: ${at}.${loose[0]} must be required (use .nullable(), not .optional()).`);
  }
  for (const [k, v] of Object.entries(n)) {
    if (Array.isArray(v)) v.forEach((x, i) => check(x, `${at}.${k}[${i}]`));
    else check(v, `${at}.${k}`);
  }
}

export function aiSchema<T>(schema: z.ZodType<T>): AiSchema<T> {
  const { $schema: _dialect, ...jsonSchema } = z.toJSONSchema(schema) as Record<string, unknown>;
  check(jsonSchema, '$');
  return { zod: schema, jsonSchema };
}
