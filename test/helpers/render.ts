// Builders for the step renderer tests: a service, a profile and a PlatformActions made from the real reviewed list.
import { emptyRepoFiles, emptyServiceQuality } from '../../src/read/quality.js';
import { PLATFORM_ACTION_IDS, type PlatformActions } from '../../src/engine/pin.js';
import { loadReviewed } from '../../src/engine/reviewed.js';
import { NEED_ID_CATEGORY, NEED_IDS } from '../../src/engine/need-ids.js';
import type { ScanFact } from '../../src/engine/job-rules.js';
import type { RenderContext } from '../../src/engine/render-step.js';
import { SCRUB_STEP_ID_RE, sha16 } from '../../src/engine/tool-flags.js';
import type { RepoProfile, ReviewedTool, Service, StepSpec } from '../../src/types.js';

export const service = (over: Partial<Service> = {}): Service => ({
  name: 'app', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: [], frameworks: [], quality: emptyServiceQuality(), ...over,
});

export const profile = (services: Service[] = [service()]): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none', services,
  terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
});

export const ctxFor = (services: Service[] = [service()], targets?: RenderContext['targets']): RenderContext => ({ profile: profile(services), ...(targets === undefined ? {} : { targets }) });

let cached: ReviewedTool[] | undefined;
/** The real reviewed list (a fresh deep copy each call, so a test can edit an entry). */
export const reviewedList = (): ReviewedTool[] => structuredClone(cached ??= loadReviewed());
export const entry = (id: string): ReviewedTool => {
  const t = reviewedList().find((e) => e.id === id);
  if (t === undefined) throw new Error(`no reviewed entry ${id}`);
  return t;
};

/** PlatformActions from the real list, without the network (platformActions() re-verifies the tags; renderers only read the entries). */
export const platform = (list: ReviewedTool[] = reviewedList()): PlatformActions =>
  Object.fromEntries(Object.entries(PLATFORM_ACTION_IDS).map(([k, id]) => [k, list.find((e) => e.id === id) as ReviewedTool])) as PlatformActions;

/** A spec for a reviewed entry: the entry's own candidate, no choices, no copies of the template. */
export const specFor = (tool: ReviewedTool, over: Partial<StepSpec> = {}): StepSpec => ({
  needId: (NEED_IDS as readonly string[]).find((n) => tool.categories.includes(n) && NEED_ID_CATEGORY[n as keyof typeof NEED_ID_CATEGORY] === n) ?? 'sast', tool: tool.candidate, choices: {}, output: tool.step.output, ...over,
});

/** The commit the fixture gate entry is pinned to. */
export const GATE_SHA = '1'.repeat(40);
/**
 * A fixture for pipegen's own gate action (Plan C C0a): the real entry comes with C6. Like the real one it has no fixed
 * inputs and no choices; `mode` and everything else are inputs the renderer sets (RENDERER_INPUTS).
 */
export const gateEntry = (sha: string = GATE_SHA): ReviewedTool => ({
  id: 'pipegen-gate', categories: ['gate'], languages: ['any'],
  candidate: { id: 'pipegen-gate', name: 'pipegen-gate', kind: 'action', repo: 'crisworking/pipegen', version: 'v0.2.0', pin: { sha }, source: 'reviewed', reviewed: true, categories: ['gate'] },
  step: { action: { uses: `crisworking/pipegen/gate@${sha}`, with: {} }, output: { path: '', format: 'none' } },
  fixedInputs: { with: {} }, choices: {}, configFiles: [], reviewedBy: 'fixture', reviewedAt: '2026-10-29', proofs: 0,
});

/**
 * Scan facts for the scrub steps of a list of steps, taken from the scrub steps themselves (each scrub's tool and format at the scan
 * step id of its artifact). For tests where the scan-to-scrub equality is not the point: the facts agree with the steps by construction.
 */
export function scansFor(steps: readonly { id?: string; with?: Record<string, string> }[]): Map<string, ScanFact> {
  const out = new Map<string, ScanFact>();
  for (const s of steps) {
    const w = s.with;
    if (s.id === undefined || !SCRUB_STEP_ID_RE.test(s.id) || w === undefined || w.artifact === undefined) continue;
    out.set(`tool-run-${sha16(w.artifact)}`, { tool: w.tool as string, format: w.format as 'sarif' | 'zap-json' });
    out.set(`checker-run-${sha16(w.artifact)}`, { tool: w.tool as string, format: w.format as 'sarif' | 'zap-json' });
  }
  return out;
}
