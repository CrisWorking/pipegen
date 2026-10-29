// Run-time slots (Plan B Task 6c, ruling B6): values a reviewed tool needs that only the render knows (the image just
// built, the app's local URL, the Dockerfile path, the base git ref). They come from the render context or the profile,
// never from the AI or from memory, and every one is checked here before it travels to the step in an env variable. The
// validators are strict on purpose: a slot value is the only free text that reaches a tool's argv besides the AI's choices.
import { parseImageRef, TAG_RE } from './names.js';
import { PLAIN_REL_RE } from './tool-flags.js';

export const SLOT_KINDS = ['image-digest', 'local-url', 'repo-path', 'git-ref'] as const;
export type SlotKind = (typeof SLOT_KINDS)[number];

const IMAGE_DIGEST_RE = /^([^@]{1,255})@(sha256:[0-9a-f]{64})$/;
const LOCAL_URL_RE = /^http:\/\/(?:localhost|127\.0\.0\.1):([1-9][0-9]{0,4})(\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*\/?)?)?$/;
const GIT_REF_RE = /^origin\/(.+)$/;

/** Facts a validator may need that are not in the value: for git-ref, the profile's default branch. */
export interface SlotFacts { defaultBranch?: string }

/** Why a value can not fill a slot of this kind, or null when it can. */
export function slotProblem(kind: SlotKind, value: unknown, facts: SlotFacts = {}): string | null {
  if (typeof value !== 'string' || value === '') return 'the value is empty';
  switch (kind) {
    case 'image-digest': {
      const m = IMAGE_DIGEST_RE.exec(value);
      if (m === null || parseImageRef(m[1]) === null) return 'an image must be <registry>/<path>@sha256:<64 hex>, with no tag and no second digest';
      return null;
    }
    case 'local-url': {
      const m = LOCAL_URL_RE.exec(value);
      if (m === null) return 'a URL must be http://localhost or http://127.0.0.1 with a port (and an optional plain path)';
      if (Number(m[1]) > 65535) return 'the port is above 65535';
      if (/\.\.|\/\//.test(m[2] ?? '')) return 'the path has an empty or .. segment';
      return null;
    }
    case 'repo-path':
      return PLAIN_REL_RE.test(value) && !value.includes('//') && !value.startsWith('~') ? null : 'a path must be a plain folder or file inside the repository (no .., no leading / or -, no *, no spaces)';
    case 'git-ref': {
      const m = GIT_REF_RE.exec(value);
      const branch = m?.[1];
      if (branch === undefined || facts.defaultBranch === undefined || branch !== facts.defaultBranch) return 'a base ref must be origin/ followed by the repository\'s default branch';
      if (!TAG_RE.test(branch) || branch.includes('..') || branch.endsWith('.') || branch.endsWith('.lock')) return 'the default branch name is not one pipegen can pass to git safely';
      return null;
    }
    default:
      return 'unknown slot kind';
  }
}
