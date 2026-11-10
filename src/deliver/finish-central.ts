// PL-E1: split out of finish.ts (a pure move, by step); see finish.ts for the whole story.
import { gitBlobSha } from '../create/guard.js';
import { CENTRAL_RULESET } from '../layers/locks.js';
import { pathClash } from './deliver.js';
import { type RecordedEdit } from './record.js';
import { show, type Ctx, step, noteAbout, ownersOf } from './finish-base.js';
import { type Target, listRulesets, type Upserted, upsertRuleset, printRuleset } from './finish-rulesets.js';

// ---------- 7. the central ruleset and CODEOWNERS ----------

export async function centralRuleset(x: Ctx): Promise<void> {
  if (x.planned.centralRuleset === undefined) return;
  const what = `the central merge rule (ruleset ${CENTRAL_RULESET} on ${show(`${x.central.owner}/${x.central.repo}`)})`;
  const F = x.fresh.centralRuleset;
  if (F === undefined) { x.skipped.push({ what, why: noteAbout(x.fresh, /lock merges on the private/) ?? 'GitHub no longer offers branch rules on the central repo.' }); return; }
  const t: Target = { kind: 'repo', repo: x.central };
  await step(x, what, async () => {
    const existing = await listRulesets(x, t);
    if (x.print) { await printRuleset(x, t, CENTRAL_RULESET, F, existing); return; }
    if (existing.some((r) => r.name === CENTRAL_RULESET)) {
      // reused (another project's, or this one's from an earlier finish): never a second one
      const r = await upsertRuleset(x, t, CENTRAL_RULESET, F.body, existing);
      recordCentral(x, r);
      x.applied.push(`${what} (${r.wrote === 'none' ? 'reused: already in place' : 'updated'})`);
      return;
    }
    // new: made switched off now, switched on last (after the record commit, which it would otherwise refuse)
    const off = { ...F.body, enforcement: 'disabled' };
    const r = await upsertRuleset(x, t, CENTRAL_RULESET, off, existing);
    recordCentral(x, r);
    x.activate = { id: r.id, body: F.body, what };
  });
}

/** The central ruleset's id goes in the record either way (plan); its created_at only when GitHub gave one (m6: uninstall then asks). */
export function recordCentral(x: Ctx, r: Upserted): void {
  x.centralRec.rulesetId = r.id;
  if (r.createdAt !== null) x.centralRec.rulesetCreatedAt = r.createdAt;
  else x.notes.push(`GitHub didn't say when it made the central ruleset ${CENTRAL_RULESET} (id ${r.id}), so the install record lists it without a date (uninstall asks before it removes it).`);
}

/** The central CODEOWNERS: an existing pipegen block is reused; else the planned file goes with the record commit (before the rule is on). */
export function centralCodeowners(x: Ctx): void {
  const F = x.fresh.centralCodeowners;
  if (F === undefined || x.planned.centralRuleset === undefined) return;
  const c = x.centralCo;
  if (c.block !== null && c.path !== null) {
    const was = x.rec.central?.codeowners;
    x.centralRec.codeowners = { path: c.path, created: was?.path === c.path ? was.created : false };
    // G-FINREC-R3 m1: a block another project wrote with other owners stays in force; say so and what to do (verify reports it as drift)
    const norm = (l: readonly string[]): string => [...new Set(l.map((o) => o.replace(/^@/, '').toLowerCase()))].sort().join(' ');
    const got = ownersOf(c.block);
    const differs = x.planned.owners.central.length > 0 && norm(got) !== norm(x.planned.owners.central);
    x.applied.push(differs
      ? `the central CODEOWNERS (${show(c.path)}, reused: another project's block is in force with other owners; give every project sharing this central repo the same code owners, then run \`npx pipegen finish\` in each. It names ${got.join(' ')}; this project planned ${x.planned.owners.central.join(' ')})`
      : `the central CODEOWNERS (${show(c.path)}, reused)`);
    return;
  }
  if (x.print) {
    x.commands.push(`# Add ${F.file.path} to ${x.central.owner}/${x.central.repo} with this text, before you switch its ruleset on:`);
    for (const line of F.file.content.replace(/\n$/, '').split('\n')) x.commands.push(`#   ${line}`);
    return;
  }
  // m5: the record entry is decided first; a file pipegen can't record is never written
  // G-FINREC (V6b-R1, Plan G carry): the file is recorded as ONE edit whose write chains from the blob finish read (editWritesChained):
  // the record commit is made on x.centralHead, the head that blob was read from (writeRecord refuses a moved head). Any other record entry
  // at that path (a deliver edit, an older finish's `files` entry) describes a file that is no longer there as it was: it is replaced, so
  // the record never names the path twice (sec i2: the record refused itself).
  const what = `the central CODEOWNERS (${show(F.file.path)})`;
  // G-FINREC-R1 (sec M2), deliver's checkBase for this one file: the text must be the blob read (a file that isn't UTF-8 is read lossily,
  // and writing it back would drop the owner's bytes), and a new file must not clash with what is there
  if (c.path !== null && (c.sha === undefined || gitBlobSha(c.text) !== c.sha)) {
    x.skipped.push({ what, why: 'it is not UTF-8 text, so pipegen can\'t add its lines without changing the owner\'s bytes; pipegen leaves the file as it is (save it as UTF-8, then run `npx pipegen finish` again).' });
    return;
  }
  if (c.path === null && pathClash(F.file.path, x.centralTree)) {
    x.skipped.push({ what, why: `${show(F.file.path)} clashes with a file of another letter case, a file where its folder would be, or a folder of that name in the central repo; pipegen writes nothing there (move that file, then run \`npx pipegen finish\` again).` });
    return;
  }
  const sha = gitBlobSha(F.file.content);
  const base = c.path === null ? null : gitBlobSha(c.text);
  const original = c.text;
  // the planned file is the one finish read (locks.ts codeownersPlan names the path it found); any other path proves nothing about its base
  const inserted = c.path === null ? F.file.content : c.path === F.file.path && F.file.content.startsWith(original) ? F.file.content.slice(original.length) : null;
  if (inserted === null || inserted === '') {
    x.skipped.push({ what, why: 'pipegen\'s lines would not simply follow the file\'s own text, so the install record couldn\'t say what to take out on uninstall; pipegen leaves the file as it is.' });
    return;
  }
  const here = (e: { repo: string; path: string }): boolean => e.repo === 'central' && e.path === F.file.path;
  const edit: RecordedEdit = { repo: 'central', path: F.file.path, kind: 'codeowners', inserted, originalSha: base, writtenShas: [sha], baseShas: [base] };
  x.files = x.files.filter((f) => !here(f));
  x.edits = [...x.edits.filter((e) => !here(e)), edit];
  x.centralFiles.push({ path: F.file.path, content: F.file.content });
  x.centralRec.codeowners = { path: F.file.path, created: c.path === null };
}
