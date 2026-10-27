// A real consent token for tests of the AI step: the real consentScreen() and askConsent() with a prompter that says
// yes, for a counted bundle of `dir`. Only askConsent can make a ConsentToken (Plan U T4b), so tests get one this way.
import { bundleCode, countingSummary } from '../../src/ai/redact.js';
import { askConsent, consentScreen } from '../../src/cli/consent.js';
import type { Prompter } from '../../src/cli/io.js';
import { estimateAuditAi } from '../../src/estimate/estimate.js';
import { permissionsTable } from '../../src/github/client.js';
import type { AiProvider, RepoProfile } from '../../src/types.js';

export const sayYes: Prompter = { confirm: async () => true, select: async (_m, _o, def) => def, text: async () => '' };

/** The token a user gives by saying yes to the audit --ai screen for `provider` with this cap and `dir`'s counted files. */
export async function grantAuditAi(p: RepoProfile, dir: string, provider: AiProvider, capUsd: number | null, knownValues: string[] = []) {
  const counted = countingSummary(await bundleCode(dir, { knownValues }));
  // the estimate's cap is replaced by the one under test (and an unpriced model's refusal is lifted: the AI step's own refusal is what such tests check)
  const est = { ...estimateAuditAi(provider, 1, 1_000), capUsd, unpriced: null };
  const screen = consentScreen(p, provider, est, counted, permissionsTable('read'), [], 'audit-ai', { gitleaksVersion: 'test' });
  const granted = await askConsent(sayYes, screen, (s) => { throw new Error(s); });
  if (granted === null) throw new Error('expected a yes');
  return granted;
}
