import { betaJSONSchemaOutputFormat } from '@anthropic-ai/sdk/helpers/beta/json-schema';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { aiSchema } from '../src/ai/schema.js';
import { strictProblems } from './helpers/strict-schema.js';

describe('aiSchema', () => {
  it('aiSchema: closed objects, every property required, nullable enum; accepted by the Claude SDK helper', () => {
    const s = aiSchema(z.strictObject({
      add: z.array(z.strictObject({ id: z.enum(['a', 'b']), service: z.enum(['web']).nullable() })),
      flag: z.boolean(),
    }));
    expect(strictProblems(s.jsonSchema)).toEqual([]);
    expect('$schema' in s.jsonSchema).toBe(false);
    expect(() => betaJSONSchemaOutputFormat(s.jsonSchema as Parameters<typeof betaJSONSchemaOutputFormat>[0])).not.toThrow();
    expect(s.zod.safeParse({ add: [{ id: 'a', service: null }], flag: true }).success).toBe(true);
    expect(s.zod.safeParse({ add: [{ id: 'c', service: null }], flag: true }).success).toBe(false);
    expect(s.zod.safeParse({ add: [], flag: true, extra: 1 }).success).toBe(false);
  });

  it('aiSchema: an optional property or an open object is refused', () => {
    expect(() => aiSchema(z.strictObject({ a: z.string().optional() }))).toThrow(/optional|required/);
    expect(() => aiSchema(z.looseObject({ a: z.string() }))).toThrow(/closed/);
    expect(() => aiSchema(z.strictObject({ inner: z.looseObject({ a: z.string() }) }))).toThrow(/closed/);
  });
});
