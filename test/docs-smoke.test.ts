// v0.2 Plan G G16: docs/smoke-test.md is the template of the one live session. These tests keep it honest: every Task 8 Step 5 check is
// there with a Result column, every result starts as "not run" (a pass is written only by the live session, never by a coding task), the
// live checklist sections the ledger names are present, and the design and threat-model fixes G16 owns are in.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { GATE_CHECK_NAME } from '../src/types.js';

const root = resolve(import.meta.dirname, '..');
const read = (rel: string): string => readFileSync(resolve(root, rel), 'utf8');
const smoke = read('docs/smoke-test.md');

interface Table { section: string; header: string[]; rows: string[][] }
const cells = (line: string): string[] => line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
/** Every markdown table of the file, with the heading it sits under. */
function tables(text: string): Table[] {
  const out: Table[] = [];
  let section = '';
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (/^#{1,6} /.test(line)) { section = line.replace(/^#+\s*/, ''); continue; }
    if (line.startsWith('|') && /^\|\s*:?-{3,}/.test(lines[i + 1] ?? '')) {
      const t: Table = { section, header: cells(line), rows: [] };
      for (i += 2; i < lines.length && (lines[i] as string).startsWith('|'); i++) t.rows.push(cells(lines[i] as string));
      i--;
      out.push(t);
    }
  }
  return out;
}
const all = tables(smoke);
const section = (title: RegExp): Table => {
  const t = all.find((x) => title.test(x.section));
  if (t === undefined) throw new Error(`docs/smoke-test.md has no table under a heading matching ${String(title)}`);
  return t;
};

/** Task 8 Step 5, plan lines 537-554: the 17 checks, in order (the pattern each row's check text must match). */
const STEP5: RegExp[] = [
  /consent shows the estimates/i,
  /helper repos are private.*records-only `?pipelines`?/is,
  /public project.*pipegen-merge\.yml.*`?gate`?/is,
  /created files are proven/i,
  /mid-run confirmation appears before real keys/i,
  /scratch secrets are gone before the preview/i,
  /setup PR passes its own gate/i,
  /hook blocks a fake key locally/i,
  /PR with a fake key is blocked by the gate/i,
  /editing `?pipegen\.yml`? without code-owner approval is blocked/i,
  /green commit status.*GATE_CHECK_NAME.*doesn't unblock/is,
  /approving, then pushing a new commit, dismisses the approval/i,
  /branch with an open PR runs only the merge layer/i,
  /`finish --print` prints commands and changes nothing/i,
  /`verify` reports a hand-made drift/i,
  /nightly issue with a patch is applied by `pipegen update` as a PR/i,
  /closing an unmerged setup PR leaves the repo with no new rules/i,
];

describe('docs', () => {
  it('docs: smoke-test.md lists every Task 8 Step 5 check with a result column', () => {
    const t = section(/Task 8 Step 5/);
    expect(t.header.at(-1)).toBe('Result');
    expect(t.rows).toHaveLength(STEP5.length);
    STEP5.forEach((re, i) => {
      const row = t.rows[i] as string[];
      expect(row[1], `Step 5 line ${i + 1}`).toMatch(re);
      expect(row.at(-1), `Step 5 line ${i + 1} result`).toBe('not run');
    });
    // the stale plan line is replaced as built, and says so
    expect(smoke).toMatch(/replaces the plan line "the public project is inline, and its check is named `GATE_CHECK_NAME`"/);
    expect(smoke).toContain(`\`${GATE_CHECK_NAME}\``);
    // the public project is in scope (the pipegen repo is public, S28 branch a)
    expect(smoke).toMatch(/public throwaway project/i);
    expect(smoke).toMatch(/S28/);
  });

  it('docs: smoke-test.md lists the live checklist sections with a result column, every result "not run"', () => {
    // every table has a Result column, last, and every row of it says "not run" (no pass, no fail, no date)
    expect(all.length).toBeGreaterThan(8);
    for (const t of all) {
      expect(t.header.at(-1), t.section).toBe('Result');
      for (const row of t.rows) expect(row.at(-1), `${t.section}: ${row[0] ?? ''}`).toBe('not run');
    }
    // the sections of pre-flight §6, and the sources the ledger names
    for (const title of [
      /Accounts and money/, /Bootstrap/, /Task 8 Step 5/, /G-specific API facts/, /D7-R7 acceptance/, /Plan F list/, /Plan E list/,
      /Live items by task/, /G15a live items/, /Release/,
    ]) expect(all.some((t) => title.test(t.section)), String(title)).toBe(true);
    const text = all.flatMap((t) => t.rows.map((r) => r.join(' | '))).join('\n');
    // the gate pin and the bootstrap switch
    expect(smoke).toContain('gate-v0.2.3');
    expect(smoke).toContain('468dd79af999342fbd525d4dd6fbe57f7e47e375');
    expect(text).toContain('PIPEGEN_BOOTSTRAP_PROOFS=1');
    // the D7-R7 probes
    for (const probe of ['f1b', 'f2', 'f3', 'o2', 'e1', 'e3']) expect(section(/D7-R7 acceptance/).rows.map((r) => r.join(' ')).join('\n')).toContain(probe);
    expect(text).toMatch(/isolatedTestJob/);
    // the Plan F list (seven lines) and the release check
    expect(section(/Plan F list/).rows).toHaveLength(7);
    expect(text).toContain('npx --yes --prefix=/ --registry=');
    expect(text).toContain('pipegen@0.2.0');
    // G15a: items 20 to 26 and the carries the task named
    for (const n of [20, 21, 22, 23, 24, 25, 26]) expect(section(/G15a live items/).rows.some((r) => r[0] === `G15a-${n}`), `G15a-${n}`).toBe(true);
    expect(text).toContain('zap-active.json');
    expect(text).toContain('pipegen-zap-active-nightly--<svc>');
    expect(text).toMatch(/classic.*containerd|containerd.*classic/i);
    expect(text).toMatch(/escaped `\\\*`.*CODEOWNERS|CODEOWNERS.*escaped `\\\*`/is);
    // a source for every row of the per-task table, and the tasks the brief names
    for (const row of section(/Live items by task/).rows) expect(row[2], `source of ${row[0] ?? ''}`).toMatch(/\S/);
    const bySource = section(/Live items by task/).rows.map((r) => r[2]).join(' ');
    for (const task of ['G0', 'G2', 'G3', 'G4', 'G4b', 'G5', 'G6', 'G7', 'G8', 'G10', 'G11', 'G13', 'G14', 'G15']) expect(bySource, task).toMatch(new RegExp(`\\b${task}[ab]?\\b`));
  });

  it('docs: smoke-test.md carries the G16-R1 live items and notes (cache-mode, closed items, cross-repo Closes, release order, signing)', () => {
    const text = all.flatMap((t) => t.rows.map((r) => r.join(' | '))).join('\n');
    // F4: the job-level `cache-mode: none` key must be a real GitHub key; a cross-repo `Closes <owner>/pipelines#N` from an app PR
    const byTask = section(/Live items by task/).rows;
    expect(byTask.some((r) => /cache-mode: none/.test(r[1] ?? '') && /progress/.test(r[2] ?? ''))).toBe(true);
    expect(byTask.some((r) => /Closes <owner>\/pipelines#N/.test(r[1] ?? '') && /write to the central repo/.test(r[1] ?? ''))).toBe(true);
    // F4: G15a-5, -13 and -19 are closed in the ledger: listed as closed, with where, and the result still "not run"
    const g15a = section(/G15a live items/).rows;
    for (const n of [5, 13, 19]) {
      const row = g15a.find((r) => r[0] === `G15a-${n}`) as string[];
      expect(row[1], `G15a-${n}`).toMatch(/^CLOSED /);
      expect(row.at(-1)).toBe('not run');
    }
    expect(g15a.find((r) => r[0] === 'G15a-5')?.[1]).toMatch(/2026-11-06/);
    // F5: the hook rows depend on the bumped and published version; row 14 signs only a project that builds an image
    expect(smoke).toMatch(/version bump.*publish.*come before.*row 8.*R1.*R2|publish.*before.*row 8/is);
    expect(section(/Task 8 Step 5/).rows[13]?.[1]).toMatch(/builds an image|has a Dockerfile/);
    expect(section(/Task 8 Step 5/).rows[13]?.[1]).toMatch(/signs nothing|no signing/);
    // F6, ruling G-SIGN1 (landed): a first run on a private repo with no signing environment makes it, reads it back, and signs; a re-run
    // after the environment exists signs; an environment already there that can't be proven is left as it is, and the run is unsigned
    const signing = section(/Signing on a private project/).rows;
    expect(signing.length).toBeGreaterThanOrEqual(3);
    expect(signing.map((r) => r.join(' ')).join('\n')).toMatch(/first run.*no `pipegen-signing` environment signs.*G-SIGN1/is);
    expect(signing.map((r) => r.join(' ')).join('\n')).not.toMatch(/until ruling G-SIGN1 lands|first run is unsigned/i);
    expect(signing.map((r) => r.join(' ')).join('\n')).toMatch(/already there.*unchanged.*Signing is off \(mode none\)/is);
    expect(signing.map((r) => r.join(' ')).join('\n')).toMatch(/re-run.*environment exists.*signs/is);
    for (const r of signing) expect(r.at(-1)).toBe('not run');
    expect(text).toMatch(/G-SIGN1/);
  });

  it('docs: design §4.1 and §19 and the threat model say what was built', () => {
    const design = read('docs/design.md');
    // §4.1: the public layout is the two-level local chain with a records-only pipelines
    expect(design).not.toMatch(/Public app repos get their workflows inline/);
    expect(design).toMatch(/Public app repos keep their workflows in their own repo.*pipegen-merge\.yml.*`gate`.*records only/s);
    // §19: the push triggers (the default branch, never tags) and the nightly ZAP active scan
    expect(design).toMatch(/`pipegen\.yml` triggers on `push` to the \*\*default branch only\*\*.*never tags/s);
    expect(design).toMatch(/`pipegen-push\.yml`.*`branches-ignore: \[<default>\]`/s);
    expect(design).toMatch(/ZAP Automation Framework active scan/);
    expect(design).toMatch(/CrisWorking.*only.*SCOPE_LINE|SCOPE_LINE.*CrisWorking/s);
    // the threat model: starter tests are a coverage floor and run the app's code; the nightly ZAP run job holds no key
    const threats = read('docs/threat-model.md');
    expect(threats).toMatch(/\| T53 \|.*coverage floor/s);
    expect(threats).toMatch(/\| T53 \|.*full power of that code/s);
    expect(threats).toMatch(/\| T53 \|.*not the boundary/s);
    expect(threats).toMatch(/\| T53 \|.*`isolatedTestJob` is false/s);
    // F9: no sentence the code does not show (proof runs have no isolated job)
    expect(threats).not.toMatch(/Proof runs use the same isolation/);
    expect(threats).toMatch(/\| T54 \|.*run job of each pair has \*\*no key and no secret\*\*/s);
  });
});
