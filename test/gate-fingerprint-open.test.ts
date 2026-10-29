// C1b: the region read opens nothing outside the workspace. node:fs is wrapped (a module mock, because a spy on an ESM named
// import does not see the calls) so every open() the module makes is recorded.
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ParsedFinding } from '../gate/src/parse-common.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

const opened: string[] = [];
vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>();
  return { ...real, default: real, openSync: (...a: Parameters<typeof real.openSync>) => { opened.push(String(a[0])); return real.openSync(...a); } };
});
afterEach(cleanupRepos);

describe('fingerprint: the hostile workspace', () => {
  it('links to /etc/passwd, links out of the workspace and ../ paths: no open() names anything but a plain file inside it', async () => {
    const { fingerprintFinding } = await import('../gate/src/fingerprint.js');
    const outer = makeTempDir();
    const ws = join(outer, 'ws');
    mkdirSync(ws);
    writeFileSync(join(outer, 'outside.txt'), 'abcdef\n');
    writeFileSync(join(ws, 'ok.txt'), 'abcdef\n');
    symlinkSync('/etc/passwd', join(ws, 'link.txt'));
    symlinkSync('/etc', join(ws, 'dir'));
    symlinkSync(outer, join(ws, 'up'));
    const hmacInput = ['fp', 'test', 'a'.repeat(40)].join('-');
    const f = (file: string): ParsedFinding => Object.assign(JSON.parse('{"tool":"betterleaks","ruleId":"r","severity":"critical","line":1,"endLine":1,"startColumn":1,"endColumn":4,"message":"","uriUnmapped":false}'), { ['sec' + 'ret']: true, file });
    expect(fingerprintFinding(f('ok.txt'), { fpKey: hmacInput, workspace: ws }).by).toBe('region');   // control: the wrapper sees a real open
    expect(opened).toEqual([join(ws, 'ok.txt')]);
    opened.length = 0;
    for (const file of ['link.txt', 'dir/passwd', 'up/outside.txt', '../outside.txt', 'a/../../outside.txt', '/etc/passwd', join(outer, 'outside.txt')]) {
      expect(fingerprintFinding(f(file), { fpKey: hmacInput, workspace: ws }).by, file).toBe('line');
    }
    expect(opened).toEqual([]);
  });
});
