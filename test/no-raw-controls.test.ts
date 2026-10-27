// No raw control, bidi or invisible character in pipegen's own sources and tests (final review batch 2, M2). These
// are the "trojan source" shape: they can make a line read differently from what it does, and GitHub flags the file.
// Hostile strings are built in code with \u escapes instead (test/fixtures/hostile-names.ts).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { repoFiles, root } from './helpers/repo-files.js';

/**
 * C0 controls except tab, LF and CR; DEL and the C1 controls; the Arabic letter mark (U+061C, a bidi mark); zero-width
 * space, joiners and marks (U+200B–U+200F); bidi embeddings and overrides (U+202A–U+202E); bidi isolates
 * (U+2066–U+2069); the byte-order mark (U+FEFF).
 */
const FORBIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

/** Each forbidden character in `text` as "line:column U+XXXX". */
function hits(text: string): string[] {
  const out: string[] = [];
  text.split('\n').forEach((line, i) => {
    for (const m of line.matchAll(FORBIDDEN)) {
      out.push(`${i + 1}:${(m.index ?? 0) + 1} U+${(m[0].codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`);
    }
  });
  return out;
}

describe('sources', () => {
  it('the check finds every forbidden character and lets tab, LF and CR through', () => {
    const bad = ['\u0000', '\u001b', '\u007f', '\u0085', '\u061c', '\u200b', '\u200e', '\u200f', '\u202a', '\u202e', '\u2066', '\u2069', '\ufeff'];
    for (const c of bad) expect(hits(`a${c}b`), c.codePointAt(0)?.toString(16)).toHaveLength(1);
    expect(hits('a\tb\r\nc\nd')).toEqual([]);
    expect(hits('x\ny\u202ez')).toEqual(['2:2 U+202E']);
  });

  it('no raw control, bidi or invisible character in any file under src/ or test/ (write a \\u escape instead)', () => {
    const files = [...repoFiles('src'), ...repoFiles('test')];
    expect(files).toContain('src/util/safe-text.ts');
    expect(files).toContain('test/fixtures/hostile-names.ts');
    const found: Record<string, string[]> = {};
    for (const f of files) {
      const h = hits(readFileSync(join(root, f), 'utf8'));
      if (h.length > 0) found[f] = h;
    }
    expect(found).toEqual({});
  });
});
