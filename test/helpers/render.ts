// Builders for the step renderer tests: a service, a profile and a PlatformActions made from the real reviewed list.
import { emptyRepoFiles, emptyServiceQuality } from '../../src/read/quality.js';
import { PLATFORM_ACTION_IDS, type PlatformActions } from '../../src/engine/pin.js';
import { loadReviewed } from '../../src/engine/reviewed.js';
import type { RenderContext } from '../../src/engine/render-step.js';
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
  needId: 'sast', tool: tool.candidate, choices: {}, output: tool.step.output, ...over,
});
