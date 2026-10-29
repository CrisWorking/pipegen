// What GitHub itself says about checks the repo's files can't show (hand checks 2026-10-29, ruling P55). Pure: the
// GitHub reads are in src/github/; this file only turns their answers into coverage rows and plain notes.
//
// - CodeQL default setup (fix 2): a code-scan row that the files leave missing becomes partial when GitHub's default
//   setup is on and scans the service's language. Never covered: like a CodeQL workflow (ruling U5), it reports
//   findings and blocks only through code scanning merge protection, which pipegen doesn't read; and it scans pushes to
//   the default branch only (and pull requests to it, and once a week), not every push. When pipegen couldn't check the
//   setup, a missing row is unknown with the reason, never missing.
// - The last run of a covering workflow (fix 3): a row covered by a workflow step becomes partial when the latest
//   completed run of that workflow on the default branch failed: the step exists and can fail the build, but a
//   workflow that fails every run may never reach it. When the runs can't be read (rate limit, no access, no completed
//   run yet) the row keeps its status and a note says what pipegen couldn't see.
import type { DefaultSetup } from '../github/code-scanning-setup.js';
import type { LastRun } from '../github/workflow-runs.js';
import type { Language, RepoProfile } from '../types.js';
import type { Coverage } from './coverage.js';

/** The `by` of a row default setup answers. */
export const DEFAULT_SETUP_BY = 'codeql-default-setup';
const DEFAULT_SETUP_WHERE = "GitHub's code scanning settings (default setup)";

/** CodeQL's language names (default setup's `languages`) for each language pipegen names. PHP has none. */
const CODEQL_LANGUAGES: Readonly<Record<Language, readonly string[]>> = {
  node: ['javascript-typescript', 'javascript', 'typescript'], python: ['python'], go: ['go'], java: ['java-kotlin', 'java'],
  dotnet: ['csharp'], ruby: ['ruby'], php: [], other: [],
};
const LANGUAGE_NAME: Readonly<Record<Language, string>> = {
  node: 'JavaScript/TypeScript', python: 'Python', go: 'Go', java: 'Java', dotnet: 'C#', ruby: 'Ruby', php: 'PHP', other: "this service's",
};

/** Code-scan rows after GitHub's CodeQL default setup (see the header). Rows other than a missing code scan are kept. */
export function applyDefaultSetup(rows: readonly Coverage[], setup: DefaultSetup, p: Pick<RepoProfile, 'services' | 'defaultBranch'>): Coverage[] {
  if (setup.state === 'off') return [...rows];
  return rows.map((r) => {
    if (r.need.category !== 'sast' || r.status !== 'missing') return r;
    if (setup.state === 'unknown') return { need: r.need, status: 'unknown', why: setup.why };
    const service = r.need.service === undefined ? undefined : p.services.find((s) => s.name === r.need.service);
    const scanned = setup.languages === null ? null : setup.languages.join(', ');
    if (service !== undefined && setup.languages !== null && !CODEQL_LANGUAGES[service.language].some((l) => setup.languages?.includes(l))) {
      return { ...r, why: `GitHub's CodeQL default setup is on here, but it doesn't scan ${LANGUAGE_NAME[service.language]} code (it scans ${scanned}).` };
    }
    const langs = scanned === null ? " pipegen couldn't read which languages it scans." : ` It scans ${scanned}.`;
    const why = r.need.layer === 'push'
      ? `GitHub's CodeQL default setup scans pushes to ${p.defaultBranch} only (and pull requests to it, and once a week), not every push; it reports findings but doesn't fail a build.${langs}`
      : `GitHub's CodeQL default setup scans each pull request to ${p.defaultBranch}; it reports findings and blocks a merge only if code scanning merge protection is on, which pipegen doesn't read.${langs}`;
    return { need: r.need, status: 'partial', by: DEFAULT_SETUP_BY, where: DEFAULT_SETUP_WHERE, why };
  });
}

/** Conclusions that mean the run didn't pass (GitHub's check-run conclusions). */
const FAILED: ReadonlySet<string> = new Set(['failure', 'timed_out', 'startup_failure']);
const WORKFLOW_AT = /^(\.github\/workflows\/[A-Za-z0-9._-]{1,200}\.ya?ml) \(job /;

/**
 * The workflow file a covered row was found in (the start of its `where`, the top-level workflow even when the step is
 * in a local action or called workflow), when it is one of the repo's listed workflows; else null (a hook, a config file).
 */
export function coveringWorkflow(row: Coverage, listed: ReadonlySet<string>): string | null {
  if (row.status !== 'covered' || row.where === undefined) return null;
  const path = WORKFLOW_AT.exec(row.where)?.[1];
  return path !== undefined && listed.has(path) ? path : null;
}

export type RunAnswer = LastRun | { state: 'unread'; why: 'rate' | 'cap' };
const UNREAD_WHY: Readonly<Record<string, string>> = {
  access: 'no access to its runs', network: "GitHub didn't answer", answer: "GitHub's answer couldn't be read",
  rate: "GitHub's rate limit", cap: 'more workflows than pipegen asks about',
};

/** Covered rows after the last runs of their workflows, plus the notes for runs pipegen couldn't see (see the header). */
export function applyLastRuns(rows: readonly Coverage[], runs: ReadonlyMap<string, RunAnswer>, listed: ReadonlySet<string>, branch: string): { rows: Coverage[]; notes: string[] } {
  const out = rows.map((r) => {
    const wf = coveringWorkflow(r, listed);
    const run = wf === null ? undefined : runs.get(wf);
    if (wf === null || run === undefined || run.state !== 'read' || !FAILED.has(run.conclusion)) return r;
    const day = run.createdAt === null ? null : run.createdAt.slice(0, 10);
    return {
      ...r, status: 'partial' as const, why: `The last run of ${wf} on ${branch} failed${day === null ? '' : ` (${day})`}, so this check may not be running.`,
      lastRun: { workflow: wf, branch, conclusion: run.conclusion, date: day },
    };
  });
  const unseen = new Map<string, string[]>();
  for (const [wf, run] of runs) {
    const why = run.state === 'none' ? 'no completed run there yet' : run.state === 'unread' ? UNREAD_WHY[run.why] ?? 'unknown' : null;
    if (why !== null) unseen.set(why, [...(unseen.get(why) ?? []), wf]);
  }
  const notes = [...unseen].map(([why, wfs]) => `pipegen couldn't see the last run of ${wfs.sort().join(', ')} on ${branch} (${why}), so the checks ${wfs.length === 1 ? 'it covers' : 'they cover'} show as found in the files, but ${wfs.length === 1 ? 'that workflow' : 'those workflows'} may still fail on every run.`);
  return { rows: out, notes };
}
