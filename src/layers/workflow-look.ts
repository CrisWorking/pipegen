// Plan P Task PL-D1: how a pipegen workflow looks. A comment block at the top (what the file does, when it runs, how to change it, where to read
// more, the pipegen version), the jobs in the order of the six report parts (PL-A1) with one `# --- <part title> ---` banner per part, and a blank
// line between jobs. Comments and order only: no key, value, job id, `needs` or name changes, so the referee and the gate read the same file.
// Pure: the version comes from the caller (never a date, never the clock).
import { isMap, type Document, type Scalar } from 'yaml';
import { PART_TITLE, type PartId } from '../audit/parts.js';
import { PLAIN_VERSION_RE } from '../util/package-data.js';

// PL-D1 Fold R2 (security M1): C0, DEL, C1 (NEL U+0085 included) and the Unicode line/paragraph separators; any of them could end a comment line.
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

/**
 * The comment block (YAML comment text, one line per `\n`; a lone space is an empty `#` line). `runs` completes "When it runs:" (it does not
 * start with "It runs") and `comment` does not say "written by pipegen": the tail line says it once, with the version.
 */
export function workflowHeader(w: { comment: string; runs: string; version: string | null }): string {
  // PL-D1 Fold R2 (security M1): the header is the one check point; a caller can't forget it
  if (w.version !== null && (typeof w.version !== 'string' || !PLAIN_VERSION_RE.test(w.version))) throw new Error('The workflow header\'s version is not a plain pipegen version (like 1.2.3).');
  if (CONTROL_RE.test(w.comment) || CONTROL_RE.test(w.runs)) throw new Error('A workflow header line holds a control or line-break character.');
  return [
    ` ${w.comment}`,
    ' ',
    ` When it runs: ${w.runs}.`,
    ' How to change it: through `npx pipegen update`. Edit it through pipegen; pipegen\'s locks protect it once they are on (see PIPEGEN.md).',
    ' See PIPEGEN.md for what each check does and what is not covered.',
    ` Written by pipegen${w.version === null ? '' : ` ${w.version}`}.`,
  ].join('\n');
}

/**
 * The jobs in part order (a stable sort: inside a part, the order the jobs were given). A job no part is known for (a helper written after its
 * check: the DAST scrub, the code-scanning upload) stays with the job before it; with none before it, it is part 2. PL-D1-R1 (accepted): a job
 * stays in its own part even when it needs a job of a later part (the gate, part 3, needs the pin check of part 6 in the merge file): a banner says
 * what the job is for, and `needs` already says the order it runs in.
 */
export function byPart(ids: readonly string[], partOfJob: (id: string) => PartId | undefined): { id: string; part: PartId }[] {
  let last: PartId = 2;
  const tagged = ids.map((id, index) => { last = partOfJob(id) ?? last; return { id, part: last, index }; });
  return tagged.sort((a, b) => a.part - b.part || a.index - b.index).map(({ id, part }) => ({ id, part }));
}

/** Banners and blank lines on the `jobs` map of a document whose jobs were written in `order` (the result of byPart), then the header. */
export function lookOf(doc: Document, order: readonly { id: string; part: PartId }[], header: string): void {
  const jobs = doc.getIn(['jobs'], true);
  if (isMap(jobs)) {
    for (const [i, pair] of jobs.items.entries()) {
      const key = pair.key as Scalar;
      const part = (order[i] as { part: PartId }).part;
      if (i > 0) key.spaceBefore = true;
      if (i === 0 || part !== (order[i - 1] as { part: PartId }).part) key.commentBefore = ` --- ${PART_TITLE[part]} ---`;
    }
  }
  doc.commentBefore = header;
}
