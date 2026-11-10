// Plan P Task PL-D2: the display name of a job pipegen writes, "<What> · <service>" ("Secret scan · web"). The name is a label only: the job id
// (the key under `jobs:`, the gate's `needs` entry and `toJSON(needs)` key) is never touched, and the caller jobs and the gate job keep the names
// the required check and the rulesets rely on (those are set where the jobs are built, and are not given here).
// Pure and total: every id gets a name, a table entry for the ids pipegen knows and a readable fallback for any other, so no job is left to show
// its raw id.

/** The "what" of each job id (the part before `--<service>`), in plain words. */
const WHAT: Readonly<Record<string, string>> = Object.freeze({
  // checks of a need (the need id is the job id)
  secrets: 'Secret scan', sast: 'Code scan', deps: 'Dependency scan', 'unit-tests': 'Unit tests', 'full-tests': 'Full tests', 'migration-check': 'Migration check',
  lint: 'Lint', 'format-lint': 'Format and lint', format: 'Format check', 'type-check': 'Type check', coverage: 'Coverage', 'dead-code': 'Dead code check',
  duplication: 'Duplication check', 'dockerfile-lint': 'Dockerfile lint', 'workflow-lint': 'Workflow lint', 'workflow-pin-check': 'Workflow pin check',
  'dependency-review': 'Dependency review', licences: 'Licence check', iac: 'Infrastructure scan', 'hooks-ci': 'Commit hooks check',
  'image-build': 'Image build', 'image-scan': 'Image scan', sbom: 'Software bill of materials', dast: 'DAST scan', 'api-dast': 'API scan', 'update-config': 'Update config check',
  // helper jobs of those checks
  'workflow-lint-online': 'Workflow lint (online)', 'dast-run': 'DAST run', 'zap-active-run': 'ZAP active scan run', 'zap-active': 'ZAP active scan', 'starter-tests': 'Starter tests',
  'code-scanning-dast': 'Upload the DAST results',
  // jobs of pipegen's own
  'pr-check': 'Open pull request check', 'base-scan': 'Base branch scan', 'baseline-check': 'Baseline check', scorecard: 'Scorecard', 'code-scanning': 'Upload the Scorecard result',
  'secrets-history': 'Full-history secret scan', 'code-scanning-history': 'Upload the full-history secrets result', nightly: 'Nightly issues',
  'image-publish': 'Publish the images', sign: 'Sign the images', 'pipegen-verify': 'Verify before deploy',
});

/** Capitalised words of an id nobody listed ("some-new-check" → "Some new check"). */
const spelled = (base: string): string => { const t = base.replace(/-+/g, ' ').trim(); return t === '' ? 'Check' : t.charAt(0).toUpperCase() + t.slice(1); };

/**
 * The display name of the job with this id: "<What>" for a repo-wide job, "<What> · <service>" for the job of one service (the id's `--<service slug>`
 * suffix). Never empty, never an expression, never the id's own text unless the id is all there is.
 */
export function jobName(id: string): string {
  const at = id.indexOf('--');
  const base = at < 0 ? id : id.slice(0, at);
  const svc = at < 0 ? '' : id.slice(at + 2);
  const what = Object.hasOwn(WHAT, base) ? (WHAT as Record<string, string>)[base] as string : spelled(base);
  return svc === '' ? what : `${what} · ${svc}`;
}

/** The jobs of a record with a `name` each: a name already there (the caller jobs, the gate) is kept. */
export function withJobNames<J extends { name?: string }>(jobs: Readonly<Record<string, J>>): Record<string, J> {
  return Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, j.name === undefined ? { ...j, name: jobName(id) } : j]));
}
