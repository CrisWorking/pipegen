// Plan U Task 3: the audit report as terminal text, Markdown (`--out`) and JSON (`--json`). Controller rulings S8,
// S12, S13, S14, S27, S29, U10 (one output helper, known values scrubbed), the T0 carry-forwards (placeholder,
// no backticks around repo values, escaped exactly once) and Review Focus 3 (never suggest making the repo public).
import { describe, expect, it } from 'vitest';
import { EXCLUDED_KEPT, EXCLUDED_PATTERN_GROUPS, EXCLUDED_PATTERNS, excludedSummaryLines, redact } from '../src/ai/redact.js';
import { isBuiltInNeed, isOwnCommand, needLabel, safeRunCommand, type AuditReport } from '../src/audit/model.js';
import { CANT_SEE, renderJson, renderMarkdown, renderTerminal, type RenderOptions } from '../src/audit/render.js';
import { safeMarkdown } from '../src/util/safe-text.js';
import { EMPTY_PLACEHOLDER, safeOutput, TOO_LONG } from '../src/util/safe-output.js';
import { aiPart, FREE_PRIVATE_LIMITS, freePrivateReport, need, reviewedTool, service, SUGGESTION_NOTE, TREE, usageOf } from './fixtures/audit-report.js';
import { hostileNames } from './fixtures/hostile-names.js';
import { fake } from './helpers/secret-repo.js';

const NOW = Date.UTC(2026, 9, 27, 9, 30);
const ANON = { text: 'Without a GitHub token, pipegen reads public data only and is rate-limited.' };
const SWAP = { text: 'This repo could change which pipegen runs. Run pipegen from outside the repo, from the npm registry, with:', command: safeRunCommand('0.1.0')! };
const OPTS: RenderOptions = { knownValues: [], now: () => NOW };
const report = (): AuditReport => freePrivateReport(EXCLUDED_PATTERNS);
const term = (r: AuditReport, o: RenderOptions = OPTS) => renderTerminal(r, o);
/** Terminal text with the 100-column wrapping undone, for content checks. */
const flat = (t: string) => t.replace(/\n {2,}(?![-⚠] )/g, ' ');
const tflat = (r: AuditReport, o: RenderOptions = OPTS) => flat(term(r, o));
const md = (r: AuditReport, o: RenderOptions = OPTS) => renderMarkdown(r, o);
const json = (r: AuditReport, o: RenderOptions = OPTS) => renderJson(r, o);

/** Section titles, in the order the brief sets (1-9), with notes and the fixed limits just before the next step. */
const TITLES = [
  'What your GitHub plan allows', 'Checks by layer', 'What pipegen would add', 'Costs of the full setup',
  'What the full setup would send to the AI', 'Permissions the full setup needs', 'Notes', "What this audit can't see", 'Next step',
];

const ESC = '\u001b';
const C1 = /[\u0080-\u009f]/;
const BIDI = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/;
/** Every control character except the newline between lines. */
const CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/;
/** Characters the no-raw-controls check forbids in committed files: shown as visible markers in snapshots. */
const INVISIBLE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
const visible = (s: string) => s.replace(INVISIBLE, (c) => `<U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}>`);

/** Every string anywhere in a parsed JSON value. */
function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out);
  else if (v !== null && typeof v === 'object') for (const [k, x] of Object.entries(v)) { out.push(k); strings(x, out); }
  return out;
}

/** The line number of each section title (a terminal title line, or a Markdown `## ` heading). */
function positions(text: string, titles: string[]): number[] {
  const lines = text.split('\n').map((l) => l.replace(/^## /, ''));
  return titles.map((t) => lines.findIndex((l) => l === t || l.startsWith(`${t} (`)));
}
const lineOf = (text: string, needle: string) => text.split('\n').findIndex((l) => l.includes(needle));

describe('renderTerminal / renderMarkdown (brief)', () => {
  it('report: section order as specified', () => {
    const r = { ...report(), warnings: [ANON], ai: aiPart() };
    for (const text of [term(r), md(r)]) {
      const verdict = lineOf(text, '4 of 4 layers have gaps');
      const warn = lineOf(text, 'Warnings');
      const at = positions(text, TITLES);
      expect(verdict).toBeGreaterThan(-1);
      expect(warn).toBeGreaterThan(verdict);
      for (const p of at) expect(p).toBeGreaterThan(warn);
      expect(at).toEqual([...at].sort((a, b) => a - b));
      // the AI part sits inside "What pipegen would add", before the costs
      const ai = lineOf(text, 'the AI also suggests checking');
      expect(ai).toBeGreaterThan(at[2] as number);
      expect(ai).toBeLessThan(at[3] as number);
    }
  });

  it('report: free private shows limits, no public wording (Review Focus 3)', () => {
    const r = report();
    for (const text of [term(r), md(r), json(r)]) {
      expect(text).not.toMatch(/public/i);
      for (const l of FREE_PRIVATE_LIMITS) expect(text).toContain(l.slice(0, 40));
    }
    // the limits come first in their section: before what is available and before the repo line
    const t = term(r);
    const section = t.slice(t.indexOf('What your GitHub plan allows'), t.indexOf('Checks by layer'));
    const firstLimit = section.indexOf('No merge lock');
    expect(firstLimit).toBeGreaterThan(-1);
    expect(firstLimit).toBeLessThan(section.indexOf('Available here'));
    expect(firstLimit).toBeLessThan(section.indexOf('Repo: private'));
  });

  it('report: high monthly minutes highlighted with basis (S12, Review Focus 5)', () => {
    const r = report(); // 1,240 of 2,000 included minutes: over half
    const t = tflat(r);
    expect(t).toMatch(/⚠ That is more than half of the 2,000 minutes your plan includes each month \(62%\)\./);
    expect(t).toContain('at least 300 pushes'); // the capped activity basis line
    expect(t).toMatch(/about 1,240 minutes a month, or more/); // capped count: a lower bound
    expect(md(r)).toContain('more than half of the 2,000 minutes');
    // at or under half: no highlight, the basis still shown
    const low = { ...r, estimates: { ...r.estimates, monthlyMinutes: 1000 } };
    expect(term(low)).not.toContain('more than half');
    expect(tflat(low)).toContain('at least 300 pushes');
    // no included minutes (a public repo, or plan unknown): never highlighted
    const none = { ...r, estimates: { ...r.estimates, monthlyMinutes: 999_999, includedMinutes: null } };
    expect(term(none)).not.toContain('more than half');
    expect(term(none)).not.toContain('⚠ That is');
    // not capped: no "or more"
    const exact = { ...r, estimates: { ...r.estimates, basis: r.estimates.basis.map((b) => b.replace(/at least /g, '')) } };
    expect(term(exact)).not.toContain('or more');
  });

  it('report: AI cost shown as input + output with cap', () => {
    const t = tflat(report());
    expect(t).toContain('Setup: about 70 GitHub Actions minutes, with a hard limit of 140');
    expect(t).toMatch(/AI: input \$1\.20–\$3\.60, output \$0\.90–\$2\.70 \(total \$2\.10–\$6\.30\)/);
    expect(t).toContain('pipegen stops calling the AI at $12.60');
    expect(t).toContain('Time: about 12–24 minutes');
    expect(t).toContain('How these estimates were made');
    const m = md(report());
    expect(m).toContain('AI: input');
    expect(m).toContain('\\$1.20'); // Markdown: every $ escaped, so GitHub math can't start
    expect(m).not.toMatch(/(?<!\\)\$\d/);
  });

  it('report: sent-to-AI section shows file count and excluded patterns, no contents', () => {
    const r = report();
    const t = term(r);
    const section = t.slice(t.indexOf('What the full setup would send to the AI'), t.indexOf('Permissions the full setup needs'));
    expect(section).toContain('142 files (about 421 KB)');
    expect(section).toContain('Top folders: src, test, scripts');
    // S29: the terminal shows the grouped summary (shared with the consent screen), not ~60 globs
    const unwrapped = flat(section);
    for (const line of excludedSummaryLines()) expect(unwrapped).toContain(line.replace(/^- /, ''));
    for (const g of EXCLUDED_PATTERN_GROUPS) expect(section).toContain(g.label);
    expect(section).toContain(`kept: ${EXCLUDED_KEPT.join(', ')}`);
    expect(section).not.toContain('**/*.tfvars.json');
    expect(section).toMatch(/never file contents/);
    // Markdown and JSON list every pattern
    const m = md(r);
    for (const p of EXCLUDED_PATTERNS) expect(m).toContain(safeMarkdown(p));
    expect(JSON.parse(json(r)).aiBundle.excludedPatterns).toEqual([...EXCLUDED_PATTERNS]);
    // truncated bundle says so
    expect(term({ ...r, aiBundle: { ...r.aiBundle, truncated: true } })).toMatch(/size limit/);
  });

  it('report: warnings shown first, right after the verdict (secrets in the files first)', () => {
    const r = { ...report(), warnings: [SWAP, ANON] };
    const t = term(r);
    const lines = t.split('\n');
    const verdictLine = lines.findIndex((l) => l.startsWith('Verdict:'));
    const next = lines.slice(verdictLine + 1).find((l) => l.trim() !== '');
    expect(next).toBe('⚠ Warnings');
    const found = t.indexOf('Secret-like text');
    expect(found).toBeGreaterThan(t.indexOf('⚠ Warnings'));
    expect(found).toBeLessThan(t.indexOf('This repo could change'));
    expect(t.indexOf('This repo could change')).toBeLessThan(t.indexOf('Without a GitHub token'));
    expect(t).toContain('config/dev.json: aws-access-key, private-key'); // grouped by file, values never shown
    expect(t).toContain(".env: generic-api-key (never sent to the AI; check it isn't committed)");
    const m = md(r);
    expect(m.indexOf('## ⚠ Warnings')).toBeGreaterThan(m.indexOf('Verdict'));
    expect(m.indexOf('## ⚠ Warnings')).toBeLessThan(m.indexOf('## What your GitHub plan allows'));
    // no warnings and nothing found in the files: no warnings section at all
    const quiet = { ...report(), [TREE]: [] };
    expect(term(quiet)).not.toContain('Warnings');
  });

  it('report: --ai suggestions labelled mention-only, not reviewed, never run', () => {
    const r = { ...report(), ai: aiPart() };
    for (const text of [term(r), md(r)]) {
      expect(text).toContain('not reviewed, never run by pipegen');
      expect(text).toContain('zizmor');
      expect(text).toContain('woodruffw/zizmor');
      expect(text).toContain('Finds risky settings in GitHub Actions workflows.');
      expect(text).toContain('the AI also suggests checking type check for shop-api');
      expect(text).toContain('In this version only GitHub Actions and npm packages can become suggestions.');
      // never a step or a command
      const line = text.split('\n').find((l) => l.includes('woodruffw/zizmor')) as string;
      expect(line).not.toMatch(/\b(run|uses|npx|install)\b/i);
    }
    expect(term(r)).toContain('about $0.42');
    expect(md(r)).toContain('about \u200b\\$0.42');
    // no AI part without --ai
    expect(term(report())).not.toContain('not reviewed, never run');
  });

  it('report: hostile-names fixture cleaned in terminal, json and markdown (Review Focus 7)', () => {
    const r = hostileReport();
    const t = term(r);
    const m = md(r);
    const j = json(r);
    for (const text of [t, m]) {
      expect(text).not.toContain(ESC);
      expect(text).not.toMatch(C1);
      expect(text).not.toMatch(BIDI);
      expect(text).not.toMatch(CONTROL);
      expect(text).not.toContain('a'.repeat(2001)); // every value capped (long prose at 2,000)
      expect(text).not.toContain('evil.example/x'); // OSC 8 link target dropped
    }
    // Markdown: no link, image, HTML or @mention survives
    expect(m).not.toMatch(/(?<!\\)\[click\]/);
    expect(m).not.toContain('<script>');
    expect(m).not.toContain('<img');
    expect(m).not.toMatch(/(?<!\u200b)@octocat/);
    expect(m).not.toMatch(/(?<!\u200b)@someone/);
    expect(m).toContain('&lt;script&gt;');
    // JSON: every string (keys too) cleaned
    const all = strings(JSON.parse(j));
    for (const s of all) {
      expect(s).not.toContain(ESC);
      expect(s).not.toMatch(C1);
      expect(s).not.toMatch(BIDI);
      expect(s).not.toMatch(/[\u0000-\u001f\u007f]/);
      expect(s.length).toBeLessThanOrEqual(2000);
    }
    expect(j).not.toContain('a'.repeat(2001));
    // a long service name is cut to 200 in every output (a 4 KB one is hidden whole by redact, as a line too long)
    const name = 'a'.repeat(400);
    const long = { ...report(), profile: { ...report().profile, services: [service({ name })] },
      coverage: report().coverage.map((c) => (c.need.service === undefined ? c : { ...c, need: { ...c.need, service: name } })) };
    for (const text of [term(long).replace(/\n +/g, ''), md(long), json(long)]) {
      expect(text).toContain('a'.repeat(150));
      expect(text).not.toContain('a'.repeat(201));
    }
    // names are capped at 200, paths at 500
    expect(JSON.parse(j).profile.services[0].name.length).toBeLessThanOrEqual(200);
    expect(JSON.parse(j).profile.services[0].path.length).toBeLessThanOrEqual(500);
    expect(JSON.parse(j).profile.services[0].path.length).toBeGreaterThan(200);
  });
});

describe('snapshots', () => {
  it('report: markdown snapshot (realistic free private report with --ai)', async () => {
    const r = { ...report(), ai: aiPart(), warnings: [SWAP] };
    await expect(visible(md(r))).toMatchFileSnapshot('./__snapshots__/audit-render.free-private.md');
  });

  it('report: terminal snapshot (realistic free private report with --ai)', async () => {
    const r = { ...report(), ai: aiPart(), warnings: [SWAP] };
    const t = term(r);
    expect(t).not.toContain(ESC); // no colours
    await expect(visible(t)).toMatchFileSnapshot('./__snapshots__/audit-render.free-private.txt');
  });

  it('report: terminal lines stay within 100 characters', () => {
    const r = { ...report(), ai: aiPart(), warnings: [SWAP, ANON] };
    // pipegen's own commands are never wrapped (U17); everything else fits
    for (const line of term(r).split('\n')) if (!isOwnCommand(line.trim())) expect([...line].length, line).toBeLessThanOrEqual(100);
  });
});

describe('rulings', () => {
  it('S14: serious = a blocking need missing or partial; a layer with no needs is "not needed" and not counted', () => {
    const r = report();
    // pre-commit: blocking secrets missing (serious); push: deps partial (serious); merge: gate missing (serious);
    // deploy: sbom missing (serious)
    expect(term(r)).toContain('Verdict: 4 of 4 layers have gaps; 4 are serious.');
    // a layer whose only gap is a non-blocking need (format-lint) has a gap that isn't serious
    const onlyFormat = { ...r, coverage: r.coverage.filter((c) => c.need.layer !== 'pre-commit' || c.need.id !== 'secrets') };
    expect(term(onlyFormat)).toContain('4 of 4 layers have gaps; 3 are serious.');
    // no deploy needs: "not needed", and the count is of 3 layers
    const noDeploy = { ...r, coverage: r.coverage.filter((c) => c.need.layer !== 'deploy') };
    const t = term(noDeploy);
    expect(t).toContain('not needed: nothing here runs or deploys');
    expect(t).toContain('Verdict: 3 of 3 layers have gaps; 3 are serious.');
    expect(md(noDeploy)).toContain('not needed: nothing here runs or deploys');
    // an unknown row is not a gap and not serious, but the verdict says pipegen couldn't check it
    const unknownOnly = {
      ...r,
      coverage: r.coverage.map((c) => (c.need.layer === 'merge' ? (c.need.id === 'dast' ? c : { ...c, status: 'covered' as const }) : { ...c, status: 'covered' as const })),
    };
    expect(term(unknownOnly)).toContain("Verdict: 0 of 4 layers have gaps. pipegen couldn't check everything in 1 layer.");
    // everything covered
    const allCovered = { ...r, coverage: r.coverage.map((c) => ({ ...c, status: 'covered' as const })) };
    expect(term(allCovered)).toContain('Verdict: all 4 layers are covered.');
    // one serious layer: singular
    const one = { ...r, coverage: r.coverage.map((c) => (c.need.layer === 'push' ? c : { ...c, status: 'covered' as const })) };
    expect(term(one)).toContain('Verdict: 1 of 4 layers has gaps; 1 is serious.');
  });

  it('S8: the next step comes from the model; no command that does not exist in v0.1', () => {
    const r = report();
    for (const text of [term(r), md(r)]) {
      expect(text).toContain('arrives in v0.2 for single-package Node/TypeScript repos.');
      expect(text).not.toMatch(/\brun `?npx pipegen\b/i);
      expect(text).not.toMatch(/\bnpx pipegen init\b/);
    }
    const other = {
      ...r,
      support: { level: 'audit-only' as const, reasons: ['Python support arrives in v0.4.'], nextStep: 'The full setup arrives in v0.4 for Python and monorepos.', nextCommand: null },
    };
    const t = term(other);
    expect(t).toContain('Python support arrives in v0.4.');
    expect(t).toContain('arrives in v0.4 for Python and monorepos.');
    expect(t.indexOf('Python support arrives')).toBeGreaterThan(t.indexOf('Next step'));
  });

  it('S27: the starter-tests text and the 0-services text are shown as the model gives them', () => {
    const r = report();
    const starter = 'No tests found for shop-api: pipegen would create starter tests.';
    const withStarter = {
      ...r,
      wouldAdd: [...r.wouldAdd, { need: need('push', 'unit-tests', 'shop-api'), status: 'missing' as const, tool: null, also: [], note: starter }],
      wouldCreate: [...r.wouldCreate, { what: 'tests' as const, why: starter }],
    };
    expect(term(withStarter)).toContain(starter);
    expect(md(withStarter)).toContain(starter);
    const none = { ...r, profile: { ...r.profile, services: [] }, testsNote: 'No service found to test.' };
    expect(term(none)).toContain('No service found to test.');
    expect(md(none)).toContain('No service found to test.');
  });

  it('S29: the terminal summary is the consent screen\'s (one shared builder)', () => {
    const lines = excludedSummaryLines();
    expect(lines).toEqual([
      ...EXCLUDED_PATTERN_GROUPS.map((g) => `- ${g.label}: ${g.summary}`),
      '- binary files (images, archives, compiled programs), found by their content',
      `kept: ${EXCLUDED_KEPT.join(', ')}`,
    ]);
  });

  it('S13: renderJson cleans every string, slims wouldAdd tools, and keeps the shape', () => {
    const r = { ...report(), ai: aiPart() };
    const j = JSON.parse(json(r));
    expect(j.profile.owner).toBe('acme');
    expect(j.coverage).toHaveLength(r.coverage.length);
    expect(j.estimates.monthlyMinutes).toBe(1240);
    expect(j.ai.costUsd).toBeCloseTo(0.4235);
    const tools = j.wouldAdd.map((w: { tool: unknown }) => w.tool);
    expect(tools).toContainEqual({ kind: 'reviewed', id: 'gitleaks', name: 'gitleaks', repo: 'gitleaks/gitleaks-action', version: 'v2.3.9' });
    expect(tools).toContainEqual({ kind: 'built-in' });
    expect(tools).toContainEqual(null);
    for (const t of tools) if (t !== null) for (const k of Object.keys(t)) expect(['kind', 'id', 'name', 'repo', 'version']).toContain(k);
    // a project script slims too
    const script = { ...r, wouldAdd: [{ need: need('push', 'unit-tests', 'shop-api'), status: 'missing' as const, tool: { kind: 'project-script' as const, needId: 'unit-tests', service: 'shop-api', script: 'test' as const }, also: [], note: 'your own `test` script would run here' }] };
    expect(JSON.parse(json(script)).wouldAdd[0].tool).toEqual({ kind: 'project-script', id: 'unit-tests', name: 'test' });
    // the permission table is pipegen's own: not masked by redact (the row is built from parts, so this committed
    // file stays clear of the secret-literal check)
    const permRow = ['Secrets', 'read and write'].join(': ');
    const withPerm = { ...r, permissions: [...r.permissions, { permission: permRow, why: 'Stores the signing key the pipeline uses.' }] };
    expect(JSON.parse(json(withPerm)).permissions.map((p: { permission: string }) => p.permission)).toContain(permRow);
    expect(term(withPerm)).toContain(`${permRow} — Stores the signing key`);
    expect(md(withPerm)).toContain(`${permRow} — Stores the signing key`);
    // pretty-printed
    expect(json(r)).toContain('\n  "profile": {');
  });

  it('U10: one helper (known values, then redact, then safeText / safeMarkdown) on every output', () => {
    const cred = fake.awsKey();
    const known = `kv${'Q7'.repeat(12)}z`;
    expect(redact(known)).toBe(known); // only the known-value scrub can catch it
    const r = report();
    const planted: AuditReport = {
      ...r,
      profile: {
        ...r.profile,
        services: [service({ name: `svc-${cred}`, path: `apps/${known}` }), service({ name: `${known}-api`, path: `apps/${cred}` })],
        terraformDirs: [`infra/${known}`],
      },
      coverage: r.coverage.map((c, i) => (i === 0 ? { ...c, where: `.github/workflows/${known}.yml (job ${cred})`, by: known } : c)),
      wouldAdd: r.wouldAdd.map((w, i) => (i === 0 ? { ...w, note: `No tests found for ${known}: pipegen would create starter tests.` } : w)),
      wouldCreate: [{ what: 'docker', why: `${cred} runs but has no Dockerfile: pipegen would create one.` }, { what: 'tests', why: `No tests found for ${known}.` }],
      aiBundle: { ...r.aiBundle, topFolders: [known, cred, 'src'] },
      [TREE]: [{ file: `${known}/x.txt`, rule: 'generic-api-' + 'key' }],
      notes: [`Skipped ${known}/package.json: not valid JSON.`],
      warnings: [{ text: `Planted ${known}.`, command: `npx ${known}` }],
      ai: aiPart({ suggestions: [{ name: known, repo: `acme/${known}`, why: `Found ${cred}.` }], notes: [`AI saw ${known}.`] }),
    };
    const o: RenderOptions = { knownValues: [known], now: () => NOW };
    for (const text of [term(planted, o), md(planted, o), json(planted, o)]) {
      expect(text).not.toContain(cred);
      expect(text).not.toContain(known);
      expect(text).not.toContain(known.slice(0, 16));
      expect(text).toContain('REDACTED');
    }
    // the planting is real: without the known value, the scrub doesn't happen
    expect(term(planted, { knownValues: [], now: () => NOW })).toContain(known);
  });

  it('U10: a known value split by an invisible or control character is still caught', () => {
    const known = `kv${'Q7'.repeat(12)}z`;
    const split = `${known.slice(0, 10)}\u200b${known.slice(10, 20)}\u001b[0m${known.slice(20)}`;
    const r = { ...report(), notes: [`Saw ${split} here.`] };
    for (const text of [term(r, { knownValues: [known] }), md(r, { knownValues: [known] }), json(r, { knownValues: [known] })]) {
      expect(text.replace(/[\u200b\\]/g, '')).not.toContain(known);
    }
  });

  it('T0: a value empty after cleaning shows a placeholder; repo values are never in backticks', () => {
    const r = report();
    const empty = { ...r, profile: { ...r.profile, services: [service({ name: '\u001b[0m\u200b' })] }, aiBundle: { ...r.aiBundle, topFolders: ['\u202e'] },
      coverage: r.coverage.map((c, i) => (i === 0 ? { ...c, by: '\u001b[2J', where: '\u2066\u2069' } : c)) };
    for (const text of [term(empty), md(empty)]) expect(text).toContain(EMPTY_PLACEHOLDER);
    expect(safeOutput('\u001b[0m', { target: 'markdown' })).toBe(EMPTY_PLACEHOLDER);
    expect(safeOutput('   ', { target: 'terminal' })).toBe(EMPTY_PLACEHOLDER);
    // a repo value is never wrapped in backticks by the renderer
    const named = { ...r, profile: { ...r.profile, services: [service({ name: 'zz-unique-name' })] },
      coverage: r.coverage.map((c) => (c.need.service === undefined ? c : { ...c, need: { ...c.need, service: 'zz-unique-name' } })) };
    for (const text of [term(named), md(named)]) {
      expect(text).toContain('zz-unique-name');
      expect(text).not.toMatch(/`[^`\n]*zz-unique-name[^`\n]*`/);
    }
  });

  it('T0: a hostile value is escaped exactly once in Markdown (no double escaping, no backslash growth)', () => {
    const value = 'a\\b*c_[d]&e<f>`g`|h';
    const once = safeMarkdown(value);
    const r = { ...report(), notes: [value], aiBundle: { ...report().aiBundle, topFolders: [value] } };
    const m = md(r);
    expect(m).toContain(once);
    expect(m).not.toContain(safeMarkdown(once));
    expect(m).not.toContain('\\\\\\\\'); // never four backslashes in a row
    expect(m).not.toContain('&amp;amp;');
    // a note that was already through safeText (bundle notes) is not escaped twice either
    expect(md({ ...report(), notes: ['x\\y'] })).toContain('x\\\\y');
    expect(md({ ...report(), notes: ['x\\y'] })).not.toContain('x\\\\\\\\y');
  });

  it('notes are shown deduplicated, and the fixed "what this audit can\'t see" list comes just before the next step', () => {
    const r = { ...report(), notes: ['Same note.', 'Same note.', 'Same\u200b note.', 'Other note.'] };
    const t = tflat(r);
    expect(t.split('Same note.').length - 1).toBe(1);
    expect(t).toContain('Other note.');
    for (const line of CANT_SEE) expect(t).toContain(line);
    expect(CANT_SEE.length).toBeGreaterThanOrEqual(7);
    expect(CANT_SEE.join(' ')).toMatch(/doesn't check the tool's other settings/);
    expect(CANT_SEE.join(' ')).toContain('{ tool; [[ … ]] } || true');
    expect(CANT_SEE.join(' ')).toContain("bash -c '…'");
    expect(CANT_SEE.join(' ')).toContain('runs-on');
    expect(CANT_SEE.join(' ')).toMatch(/Windows/);
    expect(CANT_SEE.join(' ')).toMatch(/unknown/);
    expect(CANT_SEE.join(' ')).toMatch(/reusable workflows/i);
    // Task 5 fix round 2 (M4)
    for (const part of ["doesn't read tox's env_list", 'SKIP for pre-commit', 'pinned to a commit SHA', 'up to v1.14.3', 'trusted by its name']) {
      expect(CANT_SEE.join(' '), part).toContain(part);
    }
    const cantSee = t.indexOf("What this audit can't see");
    expect(cantSee).toBeGreaterThan(t.indexOf('\nNotes'));
    expect(cantSee).toBeLessThan(t.indexOf('Next step'));
  });

  it('M3 (Plan U final review): the "can\'t see" list names every case the code reads as unknown or partial', () => {
    const all = CANT_SEE.join(' ');
    // a local action or reusable workflow that calls another local one: unknown (U24, N9)
    expect(all).toContain('A local action or reusable workflow that calls another local one');
    // the per-run budgets, with the numbers the coverage code uses
    for (const part of ['200 workflow files', '100 jobs in a workflow', '200 steps in a job or action', '100 local workflows and actions',
      '16 MB of run text', '50,000 steps', '10,000 folders with runs', '5,000 services']) expect(all, part).toContain(part);
    // a visible TOX… or NOX… variable: partial (final review I2)
    expect(all).toContain('A tox or nox run whose environments a TOX… or NOX… variable in the job picks (like TOXENV from a matrix) shows as partial');
    // paths filters and if: conditions: partial
    expect(all).toContain('`paths:` or `paths-ignore:`');
    expect(all).toContain('`if:` condition');
  });

  it('permissions: every row of the full run\'s table, permission and why', () => {
    const r = report();
    for (const text of [term(r), md(r)]) {
      for (const p of r.permissions) {
        expect(text).toContain(p.permission);
        expect(text).toContain(p.why);
      }
    }
  });

  it('what pipegen would add: reviewed tools, your own scripts, built-in checks and suggestion-only rows', () => {
    const r = report();
    const script = { need: need('push', 'unit-tests', 'shop-api'), status: 'partial' as const, tool: { kind: 'project-script' as const, needId: 'unit-tests', service: 'shop-api', script: 'test' as const }, also: [], note: 'your own `test` script would run here' };
    const t = tflat({ ...r, wouldAdd: [...r.wouldAdd, script] });
    expect(t).toContain('gitleaks v2.3.9 (gitleaks/gitleaks-action), reviewed tool');
    expect(t).toContain("pipegen's own check");
    expect(t).toContain(SUGGESTION_NOTE);
    expect(t).toContain('your own `test` script would run here');
    expect(t).toContain('Dockerfile');
    const unavailable = { ...r, wouldAdd: r.wouldAdd.map((w) => (w.tool === null ? { ...w, note: 'reviewed list unavailable' } : w)) };
    expect(term(unavailable)).toContain('reviewed list unavailable');
  });

  it('the AI cost is "about" the meter\'s per-attempt list cost; a tiny or zero cost reads plainly', () => {
    expect(tflat({ ...report(), ai: aiPart() })).toMatch(/AI cost of this audit: about \$0\.42 at list price \(2 AI calls; 41,200 input and 3,100 output tokens\)/);
    expect(term({ ...report(), ai: aiPart({ costUsd: 0.004 }) })).toContain('less than $0.01');
    expect(term({ ...report(), ai: aiPart({ costUsd: 0, attempts: [], usage: usageOf(0, 0) }) }))
      .toContain('No AI usage was recorded');
  });

  it('a public repo read without a GitHub token says so, and no limits are invented', () => {
    const r = report();
    const pub: AuditReport = {
      ...r,
      profile: { ...r.profile, private: false, plan: 'unknown' },
      capabilities: { ...r.capabilities, branchProtection: true, envRequiredReviewers: true, attestations: true, codeScanning: true, keylessSigningAllowed: true },
      limits: [],
      estimates: { ...r.estimates, includedMinutes: null },
    };
    const t = term(pub);
    expect(t).toContain('Repo: public');
    expect(t).toContain('Nothing here limits');
    expect(t).not.toContain('more than half');
  });

  it('reviewed tool with hostile fields is cleaned in every output', () => {
    const evil = reviewedTool(`x${hostileNames.ansiColour}`, `acme/${hostileNames.bidiOverride}`, hostileNames.osc8Link, ['secrets']);
    const r = { ...report(), wouldAdd: [{ need: need('push', 'secrets'), status: 'missing' as const, tool: evil, also: [], note: 'reviewed tool' }] };
    for (const text of [term(r), md(r), json(r)]) {
      expect(text).not.toContain(ESC);
      expect(text).not.toMatch(BIDI);
    }
  });
});

describe('fix round 1', () => {
  it('I1: about 5,000 services render in the terminal, Markdown and JSON without a stack overflow', () => {
    const r = report();
    const names = Array.from({ length: 5000 }, (_, i) => `svc-${i}`);
    const big: AuditReport = {
      ...r,
      profile: { ...r.profile, services: names.map((name) => service({ name, path: `apps/${name}` })) },
      // every realistic row for every service: 80,000 rows, about 200,000 terminal lines (the review's crash case)
      coverage: names.flatMap((n) => r.coverage.map((c) => ({ ...c, need: { ...c.need, service: n } }))),
      wouldAdd: names.map((n) => ({ need: need('push', 'sast', n), status: 'missing' as const, tool: null, also: [], note: SUGGESTION_NOTE })),
      wouldCreate: names.map((n) => ({ what: 'tests' as const, why: `No tests found for ${n}: pipegen would create starter tests.` })),
      aiBundle: { ...r.aiBundle, topFolders: names },
      notes: names.map((n) => `Skipped ${n}/package.json: not valid JSON.`),
    };
    const t = term(big);
    const m = md(big);
    const j = json(big);
    expect(t).toContain('svc-4999');
    expect(m).toContain('svc-4999');
    expect(JSON.parse(j).coverage).toHaveLength(names.length * r.coverage.length);
  }, 120_000);

  it('I2 (U16): pipegen\'s own checks are gaps pipegen fills, never serious', () => {
    expect(isBuiltInNeed({ category: 'gate' })).toBe(true);
    expect(isBuiltInNeed({ category: 'deploy-verify' })).toBe(true);
    expect(isBuiltInNeed({ category: 'secrets' })).toBe(false);
    const r = report();
    // a well-covered repo: everything covered except the merge gate and the deploy check
    const builtInsOnly = { ...r, coverage: r.coverage.map((c) => (isBuiltInNeed(c.need) ? { ...c, status: 'missing' as const } : { ...c, status: 'covered' as const })) };
    const t = term(builtInsOnly);
    expect(t).toContain('Verdict: 2 of 4 layers have gaps; none is serious.');
    expect(t).not.toContain('serious gaps');
    expect(t).not.toMatch(/⚠ missing/); // no row marker on pipegen's own checks
    expect(t).toMatch(/ {6}missing {2}Merge gate \(pipegen\)/);
    expect(flat(t)).toContain("Merge gate (pipegen), on every pull request (now missing): pipegen's own check"); // still a gap pipegen fills
    expect(md(builtInsOnly)).toContain('2 of 4 layers have gaps; none is serious.');
    // the realistic report still has a third-party gap in every layer
    expect(term(r)).toContain('Verdict: 4 of 4 layers have gaps; 4 are serious.');
  });

  it('I3 (U17): pipegen\'s own commands appear byte for byte, unwrapped in the terminal and unescaped in Markdown', () => {
    const cmd = safeRunCommand('0.1.0')!;
    expect(cmd).toBe('npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./repo');
    // no exact version → no command at all: an unpinned npx pipegen would run whatever owns the npm name (U18)
    expect(safeRunCommand('1.2.3-evil; rm -rf /')).toBeNull();
    expect(safeRunCommand('0.1.0-rc.1')).toBeNull();
    expect(safeRunCommand(null)).toBeNull();
    expect(isOwnCommand('npx --registry=https://registry.npmjs.org pipegen audit --dir ./repo')).toBe(false);
    const r = { ...report(), warnings: [SWAP] };
    const tLines = term(r).split('\n');
    expect(tLines).toContain(`    ${cmd}`); // on its own line, whole
    const mLines = md(r).split('\n');
    const at = mLines.indexOf(`  ${cmd}`);
    expect(at).toBeGreaterThan(0);
    expect(mLines[at - 1]).toBe('  ```sh');
    expect(mLines[at + 1]).toBe('  ```');
    expect(md(r)).not.toContain('\\`npx');
    // a long version is still one line in the terminal
    const long = safeRunCommand('123456789.123456789.123456789')!;
    expect(long.length).toBeGreaterThan(90);
    const longLines = term({ ...r, warnings: [{ ...SWAP, command: long }] }).split('\n');
    expect(longLines).toContain(`    ${long}`);
    // JSON keeps the commands as they are
    const j = JSON.parse(json(r));
    expect(j.warnings[0].command).toBe(cmd);
    expect(j.support.nextCommand).toBeNull(); // ruling U18: none in v0.1
    // a next-step command, once there is one, is a block under the next-step text in every output
    const withNext = { ...r, support: { ...r.support, nextCommand: cmd } };
    expect(term(withNext).split('\n').slice(-1)[0]).toBe(`    ${cmd}`);
    expect(md(withNext).trimEnd().split('\n').slice(-3)).toEqual(['```sh', cmd, '```']);
    // anything that isn't exactly a command pipegen builds is cleaned like any other value
    expect(isOwnCommand('npx --registry=https://registry.npmjs.org pipegen@0.1.0 audit --dir ./repo`; x')).toBe(false);
    const odd = { ...r, warnings: [{ text: 'x', command: '`npx evil` @someone' }] };
    expect(md(odd)).not.toContain('`npx evil`');
    expect(md(odd)).not.toContain('```sh\n`npx');
  });

  it('U18: no output contains a runnable `npx pipegen` (the npm name is not pipegen\'s yet), only the exact-version audit command', () => {
    const r = { ...report(), warnings: [SWAP], ai: aiPart() };
    for (const text of [term(r), md(r), json(r)]) {
      expect(text).not.toMatch(/npx\s+pipegen/);
      expect(text).toContain(safeRunCommand('0.1.0')!); // `npx --registry=… pipegen@0.1.0 audit …` stays
      expect(text).toContain('The full setup arrives in v0.2 for single-package Node/TypeScript repos.');
    }
    expect(isOwnCommand('npx pipegen')).toBe(false);
  });

  it('M1: only the report\'s own top-level permission table skips redact in JSON', () => {
    const cred = fake.awsKey();
    const r = report();
    const nested = { ...r, profile: { ...r.profile, permissions: `uses ${cred}` } } as unknown as AuditReport;
    expect(json(nested)).not.toContain(cred);
  });

  it('M2: a value over 4 KB reads "(value too long to show)", not as a secret', () => {
    const r = { ...report(), notes: [`${'word '.repeat(1000)}end`] };
    for (const text of [term(r), md(r), json(r)]) {
      expect(text).toContain(TOO_LONG);
      expect(text).not.toContain('line too long');
    }
  });

  it('M3: a local model reads "no cost counted", never "$0.00"', () => {
    const t = tflat({ ...report(), ai: aiPart({ local: true, costUsd: 0, attempts: [{ model: 'llama3', input: 9, output: 9, cacheRead: 0, cacheWrite: 0, listUsd: 0 }] }) });
    expect(t).toContain('AI cost of this audit: no cost counted: Ollama runs the model itself, not a paid API (1 AI call).');
    expect(t).not.toContain('$0.00');
  });

  it('M4: plain-English check names, suggestion wording, no "proof", and the gate\'s limit on a plan without a merge lock', () => {
    expect(needLabel('sast')).toBe('Code scan (SAST)');
    expect(needLabel('sbom')).toBe('Software bill of materials (SBOM)');
    expect(needLabel('nope')).toBeNull();
    const t = tflat(report());
    expect(t).toContain('Code scan (SAST) for shop-api');
    expect(t).toContain('Software bill of materials (SBOM) for shop-api');
    expect(t).not.toMatch(/\bsast\b/);
    expect(t).toContain(SUGGESTION_NOTE);
    expect(t).not.toContain('the proof stops');
    expect(t).toContain("On this plan GitHub can't make it a required check");
    const locked = { ...report(), capabilities: { ...report().capabilities, branchProtection: true } };
    expect(tflat(locked)).not.toContain("can't make it a required check");
    // an id pipegen doesn't know is shown cleaned
    expect(tflat({ ...report(), ai: aiPart({ extraNeeds: [{ ...need('push', 'odd-check'), why: 'x' }] }) })).toContain('checking odd-check');
  });

  it('M6: JSON keys that clean to the same text both stay; a __proto__ key is a plain key', () => {
    const r = report();
    const odd = { ...r, profile: { ...r.profile, extra: JSON.parse('{"__proto__": "p", "a\\u001b": 1, "a": 2}') } } as unknown as AuditReport;
    const j = JSON.parse(json(odd));
    expect(Object.keys(j.profile.extra).sort()).toEqual(['__proto__', 'a', 'a (2)']);
  });

  it('M8: JSON keeps a real empty string; human output shows the placeholder', () => {
    const r = { ...report(), profile: { ...report().profile, defaultBranch: '' }, notes: [''] };
    expect(JSON.parse(json(r)).profile.defaultBranch).toBe('');
    expect(JSON.parse(json(r)).notes).toEqual(['']);
    expect(term(r)).toContain(EMPTY_PLACEHOLDER);
  });
});

/** Every hostile name in every field a renderer prints: names, paths, workflow ids, why texts, notes, AI text. */
function hostileReport(): AuditReport {
  const r = freePrivateReport(EXCLUDED_PATTERNS);
  const all = Object.values(hostileNames);
  const joined = all.join(' ');
  return {
    ...r,
    profile: {
      ...r.profile,
      owner: hostileNames.ansiColour, repo: hostileNames.bidiOverride, defaultBranch: hostileNames.osc8Link,
      services: [service({ name: `${'a'.repeat(400)}${hostileNames.mention}`, path: `${'b'.repeat(700)}/${hostileNames.htmlTag}` }),
        ...all.map((h) => service({ name: h, path: h, runtimeVersion: h, dockerfile: h }))],
      terraformDirs: all,
    },
    coverage: r.coverage.map((c, i) => ({
      ...c, need: { ...c.need, ...(c.need.service === undefined ? {} : { service: all[i % all.length] as string }) },
      by: all[(i + 1) % all.length] as string, where: all[(i + 2) % all.length] as string, why: `${c.why} ${all[(i + 3) % all.length]}`,
    })),
    wouldAdd: r.wouldAdd.map((w, i) => ({ ...w, note: `${w.note} ${all[i % all.length]}` })),
    wouldCreate: all.map((h) => ({ what: 'tests' as const, why: `No tests found for ${h}: pipegen would create starter tests.` })),
    testsNote: hostileNames.markdownLink,
    limits: [...r.limits, hostileNames.htmlTag],
    [TREE]: all.map((h) => ({ file: h, rule: h, note: h })),
    aiBundle: { ...r.aiBundle, topFolders: all },
    warnings: [{ text: joined, command: joined }],
    notes: all,
    estimates: { ...r.estimates, basis: [...r.estimates.basis, joined] },
    support: { level: 'audit-only', reasons: all, nextStep: hostileNames.mention, nextCommand: joined },
    ai: aiPart({
      extraNeeds: all.map((h) => ({ ...need('push', h, h), why: h })),
      suggestions: all.map((h) => ({ name: h, repo: h, why: h })),
      notes: all,
    }),
  };
}
