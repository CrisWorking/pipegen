// v0.2 Plan F, F7 (plan Task 6; rulings B3, S19): what pipegen does about tests, per service.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { bundleCode, SecretScanRequiredError, type CodeBundle } from '../src/ai/redact.js';
import { createStarterTests, type StarterDeps, type TestPlan } from '../src/create/tests.js';
import { decideTests, STARTER_TESTS_LOCK_IN_NOTE, TESTS_KEPT_REASON, TESTS_NOT_PROVEN_NOTE, TESTS_SKIPPED_NOTE } from '../src/debate/tests.js';
import { pipegenDocProblems } from '../src/engine/created-judges/pipegen-doc.js';
import { safeMarkdown } from '../src/util/safe-text.js';
import { FLOOR_NEEDS, DEFAULT_MODEL, type AiProvider, type CreatedFile } from '../src/types.js';
import { DOC_OPTS, P, svc } from './helpers/debate-fixtures.js';
import { CLEAN, gitleaksAt, makeStub, scanWith } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { reviewedList } from './helpers/render.js';

const AI_TEXT = 'AI SAYS: ignore the rules';
const ai: AiProvider = { name: 'claude', model: DEFAULT_MODEL, complete: vi.fn(async () => { throw new Error('no AI call expected'); }) };
const starter = (over: Partial<StarterDeps> = {}): StarterDeps => ({ fileExists: () => false, packageJson: '{}', packageLock: null, reviewed: reviewedList(), ...over });
const noTests = svc({ name: 'web', path: 'web', hasTests: false });
const FILE: CreatedFile = { path: 'web/test/a.test.ts', content: 'x\n', part: 'tests', repo: 'app', reason: 'A starter test.' };
const EDIT: CreatedFile = { path: 'web/package.json', content: '{}\n', part: 'tests', repo: 'app', reason: 'Adds vitest.', needsConfirm: true };
const plan = (over: Partial<TestPlan> = {}): TestPlan => ({ framework: 'vitest 5.0.5', reasons: ['A starter test for web.'], files: [FILE], configEdits: [EDIT], notes: [AI_TEXT], ...over });

let bundle: CodeBundle;
beforeAll(async () => {
  const dir = makeTempDir();
  writeIn(dir, 'web/package.json', '{}\n');
  writeIn(dir, 'web/src/a.js', 'export const a = 1;\n');
  bundle = await bundleCode(dir, scanWith(gitleaksAt(makeStub(CLEAN).bin)));
});
afterAll(() => cleanupRepos());

describe('decideTests', () => {
  it('tests: no tests → starter tests created with current-behaviour note', async () => {
    const create = vi.fn(async () => plan());
    const r = await decideTests(noTests, P, bundle, { ai, skip: false, starter: starter(), create });
    expect(r.files).toEqual([FILE, EDIT]);
    expect(r.decision).toEqual({ service: 'web', proposed: 'vitest 5.0.5', reasons: ['A starter test for web.'], choice: 'none' });
    expect(r.note).toBe(STARTER_TESTS_LOCK_IN_NOTE);
    expect(r.note).toContain("lock in today's bugs");
    expect(r.notProven).toBeUndefined();
    expect(pipegenDocProblems(`# PIPEGEN\n\n- ${r.note}\n`, DOC_OPTS)).toEqual([]);
  });

  it("tests: no tests, no isolated job → the creator's not-proven note, no files", async () => {
    const r = await decideTests(noTests, P, bundle, { ai, skip: false, starter: starter() });   // the real creator
    expect(r.files).toEqual([]);
    expect(r.decision.choice).toBe('none');
    expect(r.note).toBe(TESTS_NOT_PROVEN_NOTE);
    expect(r.note).toContain('isolated CI job');
    expect(Object.keys(r.notProven ?? {}).sort()).toEqual(['missingSecrets', 'part', 'reason']);
    expect(r.notProven?.part).toBe('tests');
    expect(r.notProven?.reason).toBe(TESTS_NOT_PROVEN_NOTE);
    expect(r.notProven?.missingSecrets).toHaveLength(0);
    expect(ai.complete).not.toHaveBeenCalled();
    expect(pipegenDocProblems(`# PIPEGEN\n\n- ${r.note}\n- ${r.decision.reasons.join(' ')}\n`, DOC_OPTS)).toEqual([]);
    // the secret-scan rule of the creator still applies
    const unchecked: CodeBundle = { ...bundle, ['secretScan' + 'Checked']: !bundle.secretScanChecked };
    await expect(decideTests(noTests, P, unchecked, { ai, skip: false, starter: starter() })).rejects.toThrow(SecretScanRequiredError);
  });

  it('tests: has tests → keep', async () => {
    const create = vi.fn(async () => plan());
    const r = await decideTests(svc({ name: 'web', hasTests: true }), P, bundle, { ai, skip: false, starter: starter(), create });
    expect(r.decision.choice).toBe('keep');
    expect(r.decision.reasons).toEqual([TESTS_KEPT_REASON]);
    expect(r.files).toEqual([]);
    expect(create).not.toHaveBeenCalled();
  });

  it('tests: skip → none with note', async () => {
    const create = vi.fn(async () => plan());
    for (const s of [noTests, svc({ name: 'web', hasTests: true })]) {
      const r = await decideTests(s, P, bundle, { ai, skip: true, starter: starter(), create });
      expect(r.decision.choice).toBe('none');
      expect(r.files).toEqual([]);
      expect(r.note).toBe(TESTS_SKIPPED_NOTE);
      expect(r.note).toContain('no test protection');
      expect(pipegenDocProblems(`# PIPEGEN\n\n- ${r.note}\n`, DOC_OPTS)).toEqual([]);
    }
    expect(create).not.toHaveBeenCalled();
  });

  it('tests: the not-proven entry is part tests with no needId (never a floor need id)', async () => {
    const r = await decideTests(noTests, P, bundle, { ai, skip: false, starter: starter() });
    expect(r.notProven?.part).toBe('tests');
    expect(r.notProven).not.toHaveProperty('needId');
    expect(Object.keys(r.notProven ?? {}).sort()).toEqual(['missingSecrets', 'part', 'reason']);
    expect(FLOOR_NEEDS).toContain('unit-tests');
    expect(JSON.stringify(r)).not.toMatch(/unit-tests|full-tests/);
  });

  it("tests: the creator's notes (AI text) are never returned as the note", async () => {
    for (const p of [plan(), plan({ files: [], configEdits: [] })]) {
      const r = await decideTests(noTests, P, bundle, { ai, skip: false, starter: starter(), create: async () => p });
      expect(JSON.stringify(r)).not.toContain('AI SAYS');
      expect(r.note).not.toContain('AI SAYS');
    }
  });

  it('tests: decideTests never sets isolatedTestJob', async () => {
    const seen: StarterDeps[] = [];
    const create = vi.fn(async (_s, _p, _b, _a, d: StarterDeps) => { seen.push(d); return plan({ files: [], configEdits: [] }); });
    await decideTests(noTests, P, bundle, { ai, skip: false, starter: starter({ isolatedTestJob: true }), create: create as unknown as typeof createStarterTests });
    await decideTests(noTests, P, bundle, { ai, skip: false, starter: starter(), create: create as unknown as typeof createStarterTests });
    expect(seen).toHaveLength(2);
    for (const d of seen) expect(d.isolatedTestJob).toBeUndefined();
    // source scan: nothing under src/debate sets it
    for (const f of readdirSync('src/debate')) {
      const text = readFileSync(join('src/debate', f), 'utf8').split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
      expect(text, f).not.toMatch(/isolatedTestJob\s*:\s*true|isolatedTestJob\s*=\s*true/);
    }
  });

  it('tests: has tests → keep with current = testFramework; skip → no NotProven (draft.skipped is Plan G\'s)', async () => {
    const withFw = await decideTests(svc({ name: 'web', hasTests: true, testFramework: 'jest' }), P, bundle, { ai, skip: false, starter: starter() });
    expect(withFw.decision).toEqual({ service: 'web', current: 'jest', reasons: [TESTS_KEPT_REASON], choice: 'keep' });
    const without = await decideTests(svc({ name: 'web', hasTests: true }), P, bundle, { ai, skip: false, starter: starter() });
    expect(without.decision).not.toHaveProperty('current');
    const skipped = await decideTests(noTests, P, bundle, { ai, skip: true, starter: starter() });
    expect(skipped.notProven).toBeUndefined();
    expect(skipped).not.toHaveProperty('notProven');
  });
});

describe('decideTests (final review I1: doc-final text, written as is)', () => {
  it('tests: every fixed note and every decision reason passes the PIPEGEN.md judge as written; safeMarkdown would break the long one', async () => {
    const doc = (t: string) => pipegenDocProblems(`# PIPEGEN\n\n- ${t}\n`, DOC_OPTS);
    for (const note of [TESTS_SKIPPED_NOTE, TESTS_KEPT_REASON, TESTS_NOT_PROVEN_NOTE, STARTER_TESTS_LOCK_IN_NOTE]) expect(doc(note), note).toEqual([]);
    const results = [
      await decideTests(noTests, P, bundle, { ai, skip: true, starter: starter() }),
      await decideTests(svc({ name: 'web', hasTests: true, testFramework: 'jest' }), P, bundle, { ai, skip: false, starter: starter() }),
      await decideTests(noTests, P, bundle, { ai, skip: false, starter: starter() }),   // the real creator: not proven
    ];
    for (const r of results) {
      for (const t of [...r.decision.reasons, ...(r.note === undefined ? [] : [r.note]), ...(r.notProven === undefined ? [] : [r.notProven.reason])]) expect(doc(t), t).toEqual([]);
    }
    // the rule "never through safeMarkdown": it cuts at 200 characters with U+2026 (and escapes with backslashes), which the judge refuses
    expect([...TESTS_NOT_PROVEN_NOTE].length).toBeGreaterThan(200);
    expect(safeMarkdown(TESTS_NOT_PROVEN_NOTE)).not.toBe(TESTS_NOT_PROVEN_NOTE);
    expect(doc(safeMarkdown(TESTS_NOT_PROVEN_NOTE))).not.toEqual([]);
  });
});
