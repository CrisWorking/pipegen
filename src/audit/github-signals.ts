// What GitHub itself says about checks the repo's files can't show (hand checks 2026-10-29, ruling P55). Pure: the
// GitHub reads are in src/github/; this file only turns their answers into coverage rows and plain notes.
//
// - CodeQL default setup (fix 2): a code-scan row that the files leave missing becomes partial when GitHub's default
//   setup is on and scans the service's language. Never covered: like a CodeQL workflow (ruling U5), it reports
//   findings and blocks only through code scanning merge protection, which pipegen doesn't read; and it scans pushes to
//   the default branch only (and pull requests to it, and once a week), not every push. When pipegen couldn't check the
//   setup, a missing row is unknown with the reason, never missing.
import type { DefaultSetup } from '../github/code-scanning-setup.js';
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
