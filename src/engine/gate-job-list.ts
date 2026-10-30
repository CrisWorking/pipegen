// The gate's job list (Plan C rulings B4 and S4), in a leaf module: it imports only types.ts, artifact-names.ts and need-ids.ts.
// The list is what the gate trusts: one entry per rendered result and per blocking job-status need, with the artifact names
// the gate downloads (computed here, from resultArtifactName; the gate never builds a name) and `needsSecrets`, which Plan C's
// decision uses on a fork PR (decision 110: a required check that needs a secret and did not run blocks).
// The gate step's `job-list` literal is jobListLiteral(gateJobList(draft)), written by gateStepInputs (gate-inputs.ts); the referee checks it equals
// gateJobList(draft) and that the gate job's `needs` include every entry's job (else `not-gate-readable`).
import { FLOOR_NEEDS, type NeedCategory, type OutputFormat, type PipelineDraft, type StepSpec } from '../types.js';
import { ArtifactNameError, resultArtifactName, SECRETS_RANGE_ARTIFACT, SECRETS_RANGE_TOOL, slug } from './artifact-names.js';
import { NEED_ID_CATEGORY, SCHEDULED_CATEGORIES } from './need-ids.js';

/** Ruling B7 of Plan B: the checks the gate judges by their findings; their tool must write SARIF (DAST: ZAP's JSON too). Every other category is judged by job status. */
export const FINDINGS_CATEGORIES: ReadonlySet<string> = new Set(['secrets', 'sast', 'deps', 'iac', 'image-scan', 'dast', 'licences', 'dockerfile-lint']);
/** Needs pipegen's own jobs implement (Plan G), not a tool step: they never need one, and the gate does not wait for them as checks. */
export const PIPEGEN_JOB_CATEGORIES: ReadonlySet<string> = new Set(['gate', 'signing', 'attestation', 'deploy-verify']);

/** Whether a tool's output format is one the gate reads for a need of this category (B7): SARIF, and ZAP's JSON for DAST. */
export const readableFormat = (category: string, format: OutputFormat): boolean => format === 'sarif' || (category === 'dast' && format === 'zap-json');
/** Formats that are findings files (they go through the scrub and are compared with the base); `none` and `junit` are judged by job status (ruling B2). */
export const isResultFormat = (format: OutputFormat): boolean => format === 'sarif' || format === 'zap-json';

/**
 * One entry of the gate's job list. `service` is the service's slug, `job` the id of the job that runs the check (its
 * `needs` entry and its key in `toJSON(needs)`), `artifact` / `baseArtifact` the result artifact of the PR run and of
 * the target-branch run (only for a findings result). `format` is the output format of the tool: `sarif` / `zap-json`
 * entries are findings (compared with the base), `none` / `junit` entries are judged by job status.
 */
export interface JobListEntry {
  needId: string; service?: string; job: string; category: NeedCategory; tool?: string; format: OutputFormat;
  artifact?: string; baseArtifact?: string; blocking: boolean; needsSecrets: boolean; warnFirst?: { since: string };
  /**
   * C9: the secrets job's scan of the pull request's own commits (SECRETS_RANGE_ARTIFACT, betterleaks `git` mode, no base twin). It follows
   * the secrets entry, in the same job; the gate reads it as the commit range (any finding blocks), never as a check of its own.
   */
  range?: true;
}

export class GateJobListError extends Error {}
const FLOOR: ReadonlySet<string> = new Set(FLOOR_NEEDS);

/** The job id of a need's check: the need id, then `--` and the service slug for a per-service need (the same key as its result artifact). */
export function jobIdFor(needId: string, service?: string): string {
  try {
    return `${needId}${service === undefined ? '' : `--${slug(service)}`}`;
  } catch (e) {
    if (e instanceof ArtifactNameError) throw new GateJobListError(e.message);
    throw e;
  }
}

export interface GateJobListOptions {
  /**
   * The output format of a step spec's tool, or undefined when the spec does not count (it did not render). The default reads
   * `spec.output.format`, the copy that validateSpec holds equal to the reviewed template; the referee passes the reviewed
   * entry's own format, and only for specs that rendered and that a parsed file holds a step of.
   */
  formatOf?: (spec: StepSpec, index: number) => OutputFormat | undefined;
}

/**
 * The gate's job list for a draft, in the order of `draft.needs`. Only the needs the merge gate waits for are listed: the
 * `merge` layer, not scheduled, not pipegen's own jobs (gate, signing, attestation, deploy-verify). A need with a rendered
 * findings result gets an entry with its artifact names (blocking or not: a non-blocking result is still read, ruling S19). Any
 * other blocking need gets a job-status entry. A findings category whose tool writes nothing the gate reads is demoted by the
 * referee's blocking rule, so it is no blocking entry; a non-blocking job-status need is not listed. Throws GateJobListError
 * when two tools of one need and service would write one result (one artifact name per need and service).
 */
export function gateJobList(draft: PipelineDraft, opts: GateJobListOptions = {}): JobListEntry[] {
  const formatOf = opts.formatOf ?? ((s: StepSpec): OutputFormat | undefined => s.output.format);
  const out: JobListEntry[] = [];
  // warn-first (#96, S12; final review fix round A, ruling 3): on every entry of a need in draft.warnFirst, never on a floor need (#13)
  const warnFirst = draft.warnFirst ?? {};
  const warnFirstOf = (needId: string, category: string): { warnFirst?: { since: string } } => {
    if (!Object.hasOwn(warnFirst, needId)) return {};
    if (FLOOR.has(needId) || FLOOR.has(category)) throw new GateJobListError(`The floor check ${needId} can not be warn-first: a floor check always blocks (decision 13).`);
    const w = (warnFirst as Readonly<Record<string, { since: string }>>)[needId] as { since: string };
    return { warnFirst: { since: w.since } };
  };
  const seen = new Map<string, string>();   // job id → the (need id, service) that owns it
  for (const need of draft.needs) {
    if (need.layer !== 'merge') continue;
    const category = Object.hasOwn(NEED_ID_CATEGORY, need.id) ? (NEED_ID_CATEGORY as Readonly<Record<string, NeedCategory>>)[need.id] : undefined;
    if (category === undefined || SCHEDULED_CATEGORIES.has(category) || PIPEGEN_JOB_CATEGORIES.has(category)) continue;
    const key = jobIdFor(need.id, need.service);
    // an exact duplicate (the same need on another layer) is one entry; two different pairs with one job id would drop a check silently (slugging, the 40-character cut)
    const owner = `${need.id}\0${need.service ?? ''}`;
    const known = seen.get(key);
    if (known !== undefined) {
      if (known !== owner) throw new GateJobListError(`The checks ${JSON.stringify(known.replace('\0', ' / ').slice(0, 80))} and ${JSON.stringify(owner.replace('\0', ' / ').slice(0, 80))} would be the same job (${key}) and the same result, so one of them would drop out of the gate's list; rename a service.`);
      continue;
    }
    seen.set(key, owner);
    const specs = draft.steps
      .map((spec, i) => ({ spec, format: formatOf(spec, i) }))
      .filter((x): x is { spec: StepSpec; format: OutputFormat } => x.format !== undefined && x.spec.needId === need.id && x.spec.service === need.service);
    const needsSecrets = specs.some((x) => (x.spec.secrets ?? []).length > 0);
    const results = specs.filter((x) => isResultFormat(x.format));
    const service = need.service === undefined ? {} : { service: key.slice(need.id.length + 2) };
    if (results.length > 1) throw new GateJobListError(`The check ${need.id} has ${results.length} tools that each write a result, but one need and service has one result (one artifact name).`);
    const result = results[0];
    if (result !== undefined) {
      out.push({
        needId: need.id, ...service, job: key, category, tool: result.spec.tool.id, format: result.format,
        artifact: nameOf(need.id, need.service), baseArtifact: nameOf(need.id, need.service, true), blocking: need.blocking, needsSecrets, ...warnFirstOf(need.id, category),
      });
      // C9: the secrets job also scans the pull request's own commits (the range block, render-step.ts renderRangeBlock); a repo-wide check only
      if (need.id === 'secrets' && category === 'secrets' && need.service === undefined) {
        out.push({ needId: need.id, job: key, category, tool: SECRETS_RANGE_TOOL, format: 'sarif', artifact: SECRETS_RANGE_ARTIFACT, blocking: true, needsSecrets, range: true });
      }
      continue;
    }
    // job status: only a blocking need, and not a findings category that nothing readable backs (the referee demotes it)
    const demoted = FINDINGS_CATEGORIES.has(category) && !specs.some((x) => readableFormat(category, x.format));
    if (!need.blocking || demoted) continue;
    const tools = [...new Set(specs.map((x) => x.spec.tool.id))];
    out.push({
      needId: need.id, ...service, job: key, category, ...(tools.length === 1 ? { tool: tools[0] as string } : {}), format: specs[0]?.format ?? 'none', blocking: true, needsSecrets, ...warnFirstOf(need.id, category),
    });
  }
  return out;
}

function nameOf(needId: string, service: string | undefined, base = false): string {
  try {
    return resultArtifactName(needId, service, base ? { base: true } : undefined);
  } catch (e) {
    if (e instanceof ArtifactNameError) throw new GateJobListError(e.message);
    throw e;
  }
}

/** The text of the gate step's `job-list` input for a list: JSON, in the order of the list and the keys of the entries. */
export const jobListLiteral = (list: readonly JobListEntry[]): string => JSON.stringify(list);
