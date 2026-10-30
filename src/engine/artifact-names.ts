// Result artifact names (Plan B ruling B4), in a leaf module: it imports only src/types.ts, which imports nothing.
// Plan C's gate and Plan G's job list read the same helper, so the spelling exists once. Per-service needs share an
// id (`sast` for every service), so a name that is only RESULT_ARTIFACT_PREFIX + needId would collide in one run.
import { RESULT_ARTIFACT_PREFIX } from '../types.js';

export class ArtifactNameError extends Error {}

// no `--` (the service separator) and no leading `base-` (the baseline marker), so two different calls never give one name
const NEED_ID_RE = /^(?!base-)(?!.*--)[a-z0-9][a-z0-9-]{0,63}$/;
const MAX_SLUG = 40;

/**
 * A repo-derived name made safe for an artifact name, a folder name and a job id: lower case a-z, 0-9 and single
 * dashes, at most 40 characters, no dash at either end. `--` is the separator in the full name, so it never occurs
 * inside a slug. Throws when nothing is left (a name of only symbols).
 */
export function slug(s: string): string {
  const out = s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+/, '').slice(0, MAX_SLUG).replace(/-+$/, '');
  if (out === '') throw new ArtifactNameError('A name has no letters or digits left after cleaning, so it can not name an artifact.');
  return out;
}

/**
 * `pipegen-out-[base-]<needId>[--<slug(service)>]`. `base` marks the target-branch run of the same check (the
 * baseline scan). The need id must already be a plain id (the floor ids are), without `--` or a leading `base-`.
 */
export function resultArtifactName(needId: string, service?: string, opts?: { base?: true }): string {
  if (!NEED_ID_RE.test(needId)) throw new ArtifactNameError('A need id for an artifact name must be lower case letters, digits and dashes.');
  return `${RESULT_ARTIFACT_PREFIX}${opts?.base === true ? 'base-' : ''}${needId}${service === undefined ? '' : `--${slug(service)}`}`;
}

/** The names of many results at once; two different (need, service) pairs that give one name (slugging, the 40-character cut) throw. */
export function resultArtifactNames(items: readonly { needId: string; service?: string; base?: true }[]): string[] {
  const seen = new Map<string, number>();
  return items.map((it, i) => {
    const name = resultArtifactName(it.needId, it.service, it.base === true ? { base: true } : undefined);
    const first = seen.get(name);
    if (first !== undefined) throw new ArtifactNameError(`Results ${first + 1} and ${i + 1} would collide on one artifact name (${name}).`);
    seen.set(name, i);
    return name;
  });
}

// ---------- artifacts that are not a check's result (ruling S3) ----------
// The gate's own artifacts. None starts with RESULT_ARTIFACT_PREFIX and resultArtifactName always does, so no result name can
// equal one of them. A download step takes result names only (RENDERER_INPUTS); an upload step takes these three only from their own
// file in ${{ runner.temp }}/pipegen-gate, in the gate job, after the gate step (C5b ruling 2: RENDERER_INPUTS and checkJobOrder).
/**
 * The gate's decision and summary data (a JSON file, no SARIF text), uploaded by an `if: always()` step right after the gate step (C5b
 * ruling 2). A report, never authority (review-C5b minor 7): a job that ran earlier could upload a fake under this name first (the gate's
 * own upload then fails, so the gate job fails); consumers decide from the gate job's conclusion, and read this file only beside it.
 */
export const GATE_RESULT_ARTIFACT = 'pipegen-gate-result';
/** The trusted run's baseline counts, written only by the gate action (carries a MAC). */
export const BASELINE_ARTIFACT = 'pipegen-baseline';
/** The marker of a trusted clean run, written only by the gate action (carries a MAC). */
export const CLEAN_RUN_ARTIFACT = 'pipegen-clean-run';
