import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadBundledMemory, MAX_MEMORY_BYTES, MemoryError, openMemory, type MemoryEntry } from '../src/engine/memory.js';
import type { StepSpec } from '../src/types.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';

afterEach(cleanupRepos);

const T1 = new Date('2026-10-01T10:00:00Z');
const T2 = new Date('2026-10-02T10:00:00Z');
const T3 = new Date('2026-10-03T10:00:00Z');
// names that hold "secret" / "token" are built at runtime (repo rule: no secret-like literals in test/)
const NAMES_FIELD = 'sec' + 'rets';
const CI_VAR = 'GH_' + 'TOK' + 'EN';
const ARG_NAME = 'to' + 'ken';

function spec(over: { needId?: string; repo?: string; env?: Record<string, string>; withs?: Record<string, string>; names?: string[] } = {}): StepSpec {
  const repo = over.repo ?? 'o/scanner';
  return {
    needId: over.needId ?? 'sast',
    tool: {
      id: 'scanner', name: 'Scanner', kind: 'action', repo, version: '1.2.3', pin: { sha: 'a1'.repeat(20) },
      source: 'reviewed', reviewed: true, categories: ['sast'],
    },
    action: { uses: `${repo}@${'a1'.repeat(20)}`, with: over.withs ?? { config: 'auto' } },
    ...(over.env ? { cli: { install: { method: 'npm' as const, package: 'scanner', version: '1.2.3' }, command: ['scanner', '--sarif'], env: over.env } } : {}),
    output: { path: 'scanner.sarif', format: 'sarif' },
    ...(over.names ? { [NAMES_FIELD]: over.names } : {}),
  };
}

const tmp = () => makeTempDir();
const userFile = (root: string) => join(root, 'pipegen', 'memory.json');
const deps = (root: string) => ({ env: {}, home: root, uid: process.getuid?.() });

describe('memory', () => {
  it('memory: record proven then lookup returns it', async () => {
    const root = tmp();
    const m = await openMemory({ user: userFile(root), bundled: join(root, 'none.json') }, deps(root));
    m.record(spec(), 'node', 'proven', T1);
    const hits = m.lookup('sast', 'node');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ category: 'sast', language: 'node', provenAt: T1.toISOString(), proofs: 1 });
    expect(hits[0]?.spec.tool.repo).toBe('o/scanner');
    expect(m.lookup('sast', 'python')).toEqual([]);
    expect(m.lookup('lint', 'node')).toEqual([]);
  });

  it('memory: failure newer than proof hides entry', async () => {
    const root = tmp();
    const m = await openMemory({ user: userFile(root), bundled: join(root, 'none.json') }, deps(root));
    m.record(spec(), 'node', 'proven', T1);
    m.record(spec(), 'node', 'failed', T2);
    expect(m.lookup('sast', 'node')).toEqual([]);
    m.record(spec(), 'node', 'proven', T3); // proven again after the failure
    expect(m.lookup('sast', 'node').map((e) => e.proofs)).toEqual([2]);
    m.record(spec({ repo: 'o/never-proven' }), 'node', 'failed', T3); // nothing to hide, nothing stored
    expect(m.lookup('sast', 'node')).toHaveLength(1);
  });

  it('memory: user file overrides bundled entry with same repo+category', async () => {
    const root = tmp();
    const bundled = join(root, 'bundled.json');
    const old: MemoryEntry = { category: 'sast', language: 'node', spec: spec(), provenAt: T1.toISOString(), proofs: 9 };
    writeFileSync(bundled, JSON.stringify([old]));
    const first = await openMemory({ user: userFile(root), bundled }, deps(root));
    expect(first.lookup('sast', 'node')[0]?.proofs).toBe(9);
    first.record(spec(), 'node', 'failed', T2); // user's own view of the same entry
    await first.save();
    const again = await openMemory({ user: userFile(root), bundled }, deps(root));
    expect(again.lookup('sast', 'node')).toEqual([]); // the user's entry (failure newer) wins over the bundled one
    expect(JSON.parse(readFileSync(userFile(root), 'utf8'))).toHaveLength(1);
  });

  it('memory: refuses spec with secret-looking value', async () => {
    const root = tmp();
    const m = await openMemory({ user: userFile(root), bundled: join(root, 'none.json') }, deps(root));
    m.record(spec({ withs: { [ARG_NAME]: fake.githubClassic() } }), 'node', 'proven', T1);
    m.record(spec({ repo: 'o/two', env: { [CI_VAR]: fake.openaiKey() } }), 'node', 'proven', T1);
    m.record(spec({ repo: 'o/three', env: { DB: fake.assign('pass' + 'word', 'hunter22hunter22') } }), 'node', 'proven', T1);
    m.record(spec({ repo: 'o/four', names: [fake.githubClassic()] }), 'node', 'proven', T1); // a value where a name belongs
    expect(m.lookup('sast', 'node')).toEqual([]);
    expect(m.notes.length).toBeGreaterThanOrEqual(4);
    m.record(spec({ repo: 'o/fine', names: [CI_VAR], env: { MODE: 'ci' } }), 'node', 'proven', T1); // names only: allowed
    expect(m.lookup('sast', 'node')).toHaveLength(1);
    await m.save();
    expect(readFileSync(userFile(root), 'utf8')).not.toContain(fake.githubClassic());
  });

  it('memory: lookup orders by proofs', async () => {
    const root = tmp();
    const m = await openMemory({ user: userFile(root), bundled: join(root, 'none.json') }, deps(root));
    m.record(spec({ repo: 'o/few' }), 'node', 'proven', T1);
    for (const t of [T1, T2, T3]) m.record(spec({ repo: 'o/many' }), 'node', 'proven', t);
    m.record(spec({ repo: 'o/mid' }), 'node', 'proven', T1);
    m.record(spec({ repo: 'o/mid' }), 'node', 'proven', T2);
    expect(m.lookup('sast', 'node').map((e) => e.spec.tool.repo)).toEqual(['o/many', 'o/mid', 'o/few']);
  });

  it("memory: lookup returns the language plus 'any'", async () => {
    const root = tmp();
    const bundled = join(root, 'bundled.json');
    writeFileSync(bundled, JSON.stringify([{ category: 'sast', language: 'any', spec: spec({ repo: 'o/anylang' }), provenAt: T1.toISOString(), proofs: 5 }]));
    const m = await openMemory({ user: userFile(root), bundled }, deps(root));
    m.record(spec(), 'node', 'proven', T1);
    m.record(spec({ repo: 'o/py' }), 'python', 'proven', T1);
    expect(m.lookup('sast', 'node').map((e) => e.spec.tool.repo)).toEqual(['o/anylang', 'o/scanner']);
    expect(m.lookup('sast', 'go').map((e) => e.spec.tool.repo)).toEqual(['o/anylang']);
  });

  it('memory: category comes from the need id, unknown ids are refused', async () => {
    const root = tmp();
    const m = await openMemory({ user: userFile(root), bundled: join(root, 'none.json') }, deps(root));
    m.record(spec({ needId: 'type-check' }), 'node', 'proven', T1);
    m.record(spec({ needId: 'made-up', repo: 'o/other' }), 'node', 'proven', T1);
    expect(m.lookup('lint', 'node')).toHaveLength(1);
    expect(m.lookup('made-up', 'node')).toEqual([]);
    expect(m.notes.join()).toContain('o/other');
  });

  it('memory: save writes a private folder and file, and a new open reads it back', async () => {
    const root = tmp();
    const m = await openMemory({}, deps(root)); // default place under the temp home: <home>/.config/pipegen/memory.json
    m.record(spec(), 'node', 'proven', T1);
    await m.save();
    const dir = join(root, '.config', 'pipegen');
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(statSync(join(dir, 'memory.json')).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir)).toEqual(['memory.json']); // no temp file left
    const again = await openMemory({}, deps(root));
    expect(again.lookup('sast', 'node')).toHaveLength(1);
    expect(again.notes).toEqual([]);
  });

  it('memory: XDG_CONFIG_HOME is honoured', async () => {
    const root = tmp();
    const xdg = join(root, 'xdg');
    const m = await openMemory({}, { ...deps(root), env: { XDG_CONFIG_HOME: xdg } });
    m.record(spec(), 'node', 'proven', T1);
    await m.save();
    expect(existsSync(join(xdg, 'pipegen', 'memory.json'))).toBe(true);
    expect(existsSync(join(root, '.config'))).toBe(false);
  });

  it('memory: save refuses to write through a symlink', async () => {
    const root = tmp();
    const dir = join(root, 'pipegen');
    mkdirSync(dir, { mode: 0o700 });
    const victim = join(root, 'victim.txt');
    writeFileSync(victim, 'keep');
    symlinkSync(victim, join(dir, 'memory.json'));
    const m = await openMemory({ user: join(dir, 'memory.json'), bundled: join(root, 'none.json') }, deps(root));
    expect(m.notes.join()).toContain('symbolic link'); // read side
    m.record(spec(), 'node', 'proven', T1);
    await expect(m.save()).rejects.toThrow(MemoryError);
    expect(readFileSync(victim, 'utf8')).toBe('keep');
  });

  it('memory: a folder that others can write to is not trusted', async () => {
    const root = tmp();
    const dir = join(root, 'pipegen');
    mkdirSync(dir, { mode: 0o700 });
    const good = await openMemory({ user: join(dir, 'memory.json'), bundled: join(root, 'none.json') }, deps(root));
    good.record(spec(), 'node', 'proven', T1);
    await good.save();
    chmodSync(dir, 0o777);
    const m = await openMemory({ user: join(dir, 'memory.json'), bundled: join(root, 'none.json') }, deps(root));
    expect(m.lookup('sast', 'node')).toEqual([]); // not read
    expect(m.notes.join()).toContain('other users can write');
    m.record(spec(), 'node', 'proven', T1);
    await expect(m.save()).rejects.toThrow(MemoryError); // and not written
    chmodSync(dir, 0o700);
  });

  it('memory: a corrupt, oversized or unexpected store gives an empty memory and a note', async () => {
    const root = tmp();
    const dir = join(root, 'pipegen');
    mkdirSync(dir, { mode: 0o700 });
    const file = join(dir, 'memory.json');
    const good: MemoryEntry = { category: 'sast', language: 'node', spec: spec(), provenAt: T1.toISOString(), proofs: 1 };
    const leaky = spec({ withs: { k: fake.githubClassic() } });
    const cases: [string, string][] = [
      ['not json', '{nope'],
      ['wrong shape', JSON.stringify({ entries: [good] })],
      ['extra key', JSON.stringify([{ ...good, extra: 1 }])],
      ['negative proofs', JSON.stringify([{ ...good, proofs: -1 }])],
      ['one bad entry spoils the file', JSON.stringify([good, { ...good, proofs: 'x' }])],
      ['secret-looking value on disk', JSON.stringify([{ ...good, spec: leaky }])],
      ['category does not match the need', JSON.stringify([{ ...good, category: 'lint' }])],
      ['too large', ' '.repeat(MAX_MEMORY_BYTES + 1)],
    ];
    for (const [label, text] of cases) {
      writeFileSync(file, text);
      const m = await openMemory({ user: file, bundled: join(root, 'none.json') }, deps(root));
      expect(m.lookup('sast', 'node'), label).toEqual([]);
      expect(m.notes.length, label).toBe(1);
    }
    writeFileSync(file, JSON.stringify([good])); // sanity: the good one loads
    expect((await openMemory({ user: file, bundled: join(root, 'none.json') }, deps(root))).lookup('sast', 'node')).toHaveLength(1);
  });

  it('memory: the bundled file ships empty and loads', async () => {
    expect(await loadBundledMemory()).toEqual([]);
    const root = tmp();
    const m = await openMemory({ user: userFile(root) }, deps(root)); // default bundled path
    expect(m.notes).toEqual([]);
  });
});
