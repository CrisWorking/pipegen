// PL-D1 Fold R2 (security I1): the record schema and the header check use one version regex.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { PLAIN_VERSION_RE } from '../src/util/package-data.js';

describe('PL-D1 R2: one version regex', () => {
  it('record.ts imports PLAIN_VERSION_RE and keeps no literal copy', () => {
    const src = readFileSync(new URL('../src/deliver/record.ts', import.meta.url), 'utf8');
    expect(src).toMatch(/import \{[^}]*PLAIN_VERSION_RE[^}]*\} from '\.\.\/util\/package-data\.js'/);
    expect(src).toContain('.regex(PLAIN_VERSION_RE)');
    expect(src).not.toContain(PLAIN_VERSION_RE.source);
  });
});
