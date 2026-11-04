// v0.2 Plan E, E5 (ruling S8): the JUnit report is read in a worker with resourceLimits, and its size is checked before it is
// read. A refusal, a timeout, a crash or a limit hit is "report unreadable": never a pass, never "no results".
import { mkdtempSync, readFileSync, rmSync, writeFileSync, truncateSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MAX_JUNIT_BYTES } from '../src/create/junit.js';
import { JUNIT_RESOURCE_LIMITS, readJunitBytes, readJunitFile } from '../src/create/junit-worker.js';

const fixture = (name: string): Buffer => readFileSync(new URL(`./fixtures/junit/${name}`, import.meta.url));
let dir: string;
let thread: URL;
const script = (name: string, body: string): URL => { const p = join(dir, name); writeFileSync(p, body); return pathToFileURL(p); };

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'junit-worker-'));
  const out = join(dir, 'junit-thread.mjs');
  await build({ entryPoints: [new URL('../src/create/junit-thread.ts', import.meta.url).pathname], bundle: true, platform: 'node', format: 'esm', target: 'node24', outfile: out, logLevel: 'silent' });
  thread = pathToFileURL(out);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const reason = (r: { ok: boolean; reason?: string }): string => (r.ok ? '' : (r.reason ?? ''));

describe('junit-worker', () => {
  it('junit: size checked before reading; parse in a worker with resourceLimits', async () => {
    // over the cap: refused before any worker starts or any byte is decoded
    const probe = script('named-never.mjs', `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(join(dir, 'named-started'))}, '1');`);
    expect(reason(await readJunitBytes(new Uint8Array(MAX_JUNIT_BYTES + 1), { workerUrl: probe }))).toMatch(/limit/);
    expect(() => readFileSync(join(dir, 'named-started'))).toThrow();
    // within the cap: parsed in a worker that has the resourceLimits
    const limits = script('named-limits.mjs', `import { parentPort, resourceLimits, isMainThread } from 'node:worker_threads'; parentPort.postMessage({ ok: true, cases: [{ id: JSON.stringify({ isMainThread, ...resourceLimits }), status: 'pass' }] });`);
    const r = await readJunitBytes(new Uint8Array(1), { workerUrl: limits });
    expect(r.ok).toBe(true);
    if (r.ok) expect(JSON.parse(r.cases[0]?.id ?? '{}')).toMatchObject({ isMainThread: false, ...JUNIT_RESOURCE_LIMITS });
  });

  it('parses a real vitest report in the worker', async () => {
    const r = await readJunitBytes(fixture('vitest-5.0.5.xml'), { workerUrl: thread });
    expect(r.ok).toBe(true);
    if (r.ok) { expect(r.cases).toHaveLength(5); expect(r.cases.map((c) => c.status)).toEqual(['pass', 'fail', 'skip', 'pass', 'pass']); }
  });

  it('a file over the cap is refused from its size alone: the file is never read and no worker starts', async () => {
    const p = join(dir, 'big.xml');
    writeFileSync(p, '');
    truncateSync(p, MAX_JUNIT_BYTES + 1);   // a sparse file: reading it would allocate 16 MiB of zeroes
    const probe = script('never.mjs', `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(join(dir, 'started'))}, '1');`);
    const r = await readJunitFile(p, { workerUrl: probe });
    expect(r.ok).toBe(false);
    expect(reason(r)).toMatch(/^report unreadable: .*limit/);
    expect(() => readFileSync(join(dir, 'started'))).toThrow();
    const b = await readJunitBytes(new Uint8Array(MAX_JUNIT_BYTES + 1), { workerUrl: probe });
    expect(reason(b)).toMatch(/limit/);
    expect(() => readFileSync(join(dir, 'started'))).toThrow();
  });

  it('exactly at the cap is read (the cap is inclusive), one byte over is not', async () => {
    const ok = await readJunitBytes(fixture('vitest-5.0.5.xml'), { workerUrl: thread, maxBytes: fixture('vitest-5.0.5.xml').length });
    expect(ok.ok).toBe(true);
    const over = await readJunitBytes(fixture('vitest-5.0.5.xml'), { workerUrl: thread, maxBytes: fixture('vitest-5.0.5.xml').length - 1 });
    expect(over.ok).toBe(false);
  });

  it('a caller cannot raise the cap above MAX_JUNIT_BYTES', async () => {
    const r = await readJunitBytes(new Uint8Array(MAX_JUNIT_BYTES + 1), { workerUrl: thread, maxBytes: Number.MAX_SAFE_INTEGER });
    expect(r.ok).toBe(false);
  });

  it('readJunitFile reads a real file, refuses a missing one and a directory', async () => {
    const p = join(dir, 'ok.xml');
    writeFileSync(p, fixture('vitest-5.0.5.xml'));
    expect((await readJunitFile(p, { workerUrl: thread })).ok).toBe(true);
    expect(reason(await readJunitFile(join(dir, 'nope.xml'), { workerUrl: thread }))).toMatch(/^report unreadable/);
    expect(reason(await readJunitFile(dir, { workerUrl: thread }))).toMatch(/^report unreadable/);
  });

  it('the worker runs with resourceLimits (the defaults, or the caller\'s smaller ones)', async () => {
    const probe = script('limits.mjs', `import { parentPort, resourceLimits } from 'node:worker_threads'; parentPort.postMessage({ ok: true, cases: [{ id: JSON.stringify(resourceLimits), status: 'pass' }] });`);
    const r = await readJunitBytes(new Uint8Array(1), { workerUrl: probe });
    expect(r.ok).toBe(true);
    if (r.ok) {
      const seen = JSON.parse(r.cases[0]?.id ?? '{}') as Record<string, number>;
      for (const [k, v] of Object.entries(JUNIT_RESOURCE_LIMITS)) expect(seen[k], k).toBe(v);
    }
    const small = await readJunitBytes(new Uint8Array(1), { workerUrl: probe, resourceLimits: { maxOldGenerationSizeMb: 64 } });
    if (small.ok) expect((JSON.parse(small.cases[0]?.id ?? '{}') as Record<string, number>).maxOldGenerationSizeMb).toBe(64);
    else throw new Error('expected ok');
  });

  it('running out of memory in the worker is a caught "report unreadable"', async () => {
    const hog = script('hog.mjs', `const keep = []; for (;;) keep.push(new Array(1e6).fill(Math.random()));`);
    const r = await readJunitBytes(new Uint8Array(1), { workerUrl: hog, resourceLimits: { maxOldGenerationSizeMb: 32 }, timeoutMs: 20_000 });
    expect(r.ok).toBe(false);
    expect(reason(r)).toMatch(/^report unreadable: .*memory/);
  });

  it('a hang is stopped at the time limit; a crash and a silent exit are unreadable', async () => {
    const hang = script('hang.mjs', `for (;;) {}`);
    const t0 = Date.now();
    const r = await readJunitBytes(new Uint8Array(1), { workerUrl: hang, timeoutMs: 300 });
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(reason(r)).toMatch(/^report unreadable: .*longer than/);
    const crash = script('crash.mjs', `throw new Error('boom');`);
    expect(reason(await readJunitBytes(new Uint8Array(1), { workerUrl: crash }))).toMatch(/^report unreadable: .*crashed/);
    const quiet = script('quiet.mjs', `// exits without a message`);
    expect(reason(await readJunitBytes(new Uint8Array(1), { workerUrl: quiet }))).toMatch(/^report unreadable: .*without an answer/);
  });

  it('an answer that is not { ok, cases } with known statuses is unreadable (a worker is not trusted blindly)', async () => {
    for (const [i, msg] of ['null', '"x"', '{ ok: true }', '{ ok: true, cases: [{ id: 1, status: "pass" }] }', '{ ok: true, cases: [{ id: "a", status: "passed" }] }', '{ ok: 1, cases: [] }', '{ ok: true, cases: [null] }'].entries()) {
      const s = script(`bad${i}.mjs`, `import { parentPort } from 'node:worker_threads'; parentPort.postMessage(${msg});`);
      expect(reason(await readJunitBytes(new Uint8Array(1), { workerUrl: s })), msg).toMatch(/^report unreadable/);
    }
    const good = script('good.mjs', `import { parentPort } from 'node:worker_threads'; parentPort.postMessage({ ok: true, cases: [{ id: 'a', status: 'pass' }] });`);
    expect((await readJunitBytes(new Uint8Array(1), { workerUrl: good })).ok).toBe(true);
  });

  it('a refusal by parseJunit and invalid UTF-8 come back as unreadable with the parser\'s reason', async () => {
    const xxe = Buffer.from('<!DOCTYPE x [<!ENTITY a "b">]><testsuites/>');
    expect(reason(await readJunitBytes(xxe, { workerUrl: thread }))).toMatch(/^report unreadable: /);
    const bad = Buffer.from([0x3c, 0x74, 0xff, 0xfe, 0x3e]);
    expect(reason(await readJunitBytes(bad, { workerUrl: thread }))).toMatch(/^report unreadable: /);
    expect(reason(await readJunitBytes(Buffer.from('<testsuites><testsuite tests="3"><testcase name="a"/></testsuite></testsuites>'), { workerUrl: thread }))).toMatch(/^report unreadable: /);
  });

  it('no worker file (from the TypeScript sources, or a missing build) fails closed', async () => {
    expect(reason(await readJunitBytes(fixture('vitest-5.0.5.xml')))).toMatch(/^report unreadable: .*not available/);
    expect(reason(await readJunitBytes(fixture('vitest-5.0.5.xml'), { workerUrl: pathToFileURL(join(dir, 'missing.mjs')) }))).toMatch(/not available/);
    expect(reason(await readJunitBytes(fixture('vitest-5.0.5.xml'), { workerUrl: new URL('https://example.com/x.js') }))).toMatch(/not available/);
  });

  it('a report that is not bytes is unreadable', async () => {
    expect((await readJunitBytes('<testsuites/>' as unknown as Uint8Array, { workerUrl: thread })).ok).toBe(false);
  });
});
