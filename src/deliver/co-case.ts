// G-COCASE-R1/R2: a CODEOWNERS case variant (a path whose coKey is a CO_PLACES entry's, not that entry exactly) stops finish and setup.
// A small module (the leaf co-places and safe-text only) so deliver, finish and run share it without an import cycle; finish re-exports it.
import { CO_PLACES, coKey } from '../layers/co-places.js';
import { safeText } from '../util/safe-text.js';

const show = (s: string, n = 140): string => safeText(s, n);
type Repos = readonly { label: string; paths: Iterable<string> }[];

/** "<label> has <path> (rename it to <exact> (or remove it))" per repo with a variant. */
function variantParts(repos: Repos): string[] {
  const parts: string[] = [];
  for (const r of repos) {
    const found: string[] = [];
    for (const x of r.paths) {
      const exact = CO_PLACES.find((p) => coKey(p) === coKey(x));
      if (exact !== undefined && exact !== x) found.push(`${show(x)} (rename it to ${exact} (or remove it))`);
    }
    if (found.length > 0) parts.push(`${show(r.label)} has ${found.join(', ')}`);
  }
  return parts;
}
const WHY = 'A CODEOWNERS whose name differs from the path GitHub reads only in letter case (or by a look-alike letter) may be read instead of the file pipegen writes, and the gate reads only the exact path.';

/**
 * The stop message of a check that runs before any write (finish; setup's early read-only stage), or null. GitHub may read such a file
 * instead of the one pipegen writes, and the gate reads only the exact path, so pipegen refuses (fail closed) rather than write a second
 * file. `command` is the one to run again.
 */
export function coCaseProblem(repos: Repos, command: string): string | null {
  const parts = variantParts(repos);
  if (parts.length === 0) return null;
  return `pipegen stopped before changing anything: ${parts.join('; ')}. ${WHY} Rename it as shown (or remove it), then run \`${command}\` again. exit code 2.`;
}

/**
 * G-COCASE-R2 M2: the same refusal for a late check (readBuildFacts, deliver's second tree reads), which may run after the proof or the
 * central commit: it claims nothing about what was changed and names no exit code (the caller prefixes "pipegen stopped: ").
 */
export function coCaseLate(repos: Repos, command: string): string | null {
  const parts = variantParts(repos);
  if (parts.length === 0) return null;
  return `a CODEOWNERS case variant is there now: ${parts.join('; ')}. ${WHY} pipegen opens no setup pull request. Rename it as shown (or remove it), then run \`${command}\` again.`;
}
