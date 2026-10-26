import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '..');
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

describe('package', () => {
  it('license Apache-2.0, bin dist/cli/main.js, repository url set, no dependencies field', () => {
    expect(pkg.license).toBe('Apache-2.0');
    expect(pkg.bin.pipegen).toBe('dist/cli/main.js');
    expect(pkg.repository.url).toBe('git+https://github.com/CrisWorking/pipegen.git');
    expect(pkg.engines.node).toBe('>=24');
    expect(pkg.type).toBe('module');
    expect('dependencies' in pkg).toBe(false);
  });
});

describe('build', () => {
  it('dist/cli/main.js starts with the node shebang and imports only node: built-ins', () => {
    execFileSync('npx', ['tsup'], { cwd: root, stdio: 'pipe' });
    const out = readFileSync(resolve(root, 'dist/cli/main.js'), 'utf8');
    expect(out.startsWith('#!/usr/bin/env node\n')).toBe(true);
    const specs = [
      ...out.matchAll(/\bfrom\s*["']([^"']+)["']/g),
      ...out.matchAll(/\bimport\s*["']([^"']+)["']/g),
      ...out.matchAll(/\bimport\(\s*["']([^"']+)["']\s*\)/g),
      ...out.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g),
    ].map((m) => m[1]);
    for (const s of specs) expect(s.startsWith('node:'), `non-builtin import: ${s}`).toBe(true);
  });
});
