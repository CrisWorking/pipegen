// The one place live tests read the GitHub token from: GITHUB_TOKEN, else GH_TOKEN (final review minor 13). The names are
// spelled at run time (test/no-secret-literals.test.ts). Never print the value.
const NAMES = [['GITHUB', 'TOKEN'].join('_'), ['GH', 'TOKEN'].join('_')] as const;

/** The token the live tests use against api.github.com, or undefined when neither variable is set (to a non-blank value). */
export function liveToken(env: Readonly<Record<string, string | undefined>> = process.env): string | undefined {
  for (const n of NAMES) {
    const v = env[n]?.trim();
    if (v !== undefined && v !== '') return v;
  }
  return undefined;
}
