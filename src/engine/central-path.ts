import { createHash } from 'node:crypto';

/**
 * The central workflows of a project. `sign` (v0.2 Plan G G3, ruling S21) is the project's sign workflow: its content is the draft's own
 * signing plan (the image names and the mode are literals of the file, never workflow_call inputs), so it is one file per project, never
 * one file shared by every project of the owner (a second project's install would rewrite the first one's signing file).
 */
export type CentralLayer = 'merge' | 'push' | 'nightly' | 'sign';

/** The longest project name kept as it is: `<name>--nightly.yml` stays inside the 100-character path segment the path rule allows. */
const MAX_PLAIN = 80;
/** A name kept as it is: lower case letters, digits, `.`, `_` and `-`, not starting with `-` or `.`, not ending with `.`. */
const PLAIN_RE = /^[a-z0-9_][a-z0-9._-]*$/;
/** The hash form: never kept as a plain name, so a repository named like it can not take another project's files. */
const HASHED_RE = /^pipegen-[0-9a-f]{20}$/;
/** Windows device names (the path rule refuses a segment whose part before the first dot is one). */
const DEVICE_RE = /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])$/;

/**
 * The name a project's central files carry (ruling S16, Plan D D0a review): one derivation for every caller (the files assemble writes, the
 * caller jobs' `uses`, the find-run step's `central-workflow`, the referee, the sign workflow), so they can never disagree.
 * - The repository name in lower case (GitHub names are case-insensitive, so a rename that only changes the case keeps the files), when it is
 *   a plain name of at most MAX_PLAIN characters. `.`, `_` and `-` are kept apart (never folded into one another), so two repositories of one
 *   owner never share a file.
 * - Otherwise `pipegen-<20 hex of sha256(the lower-case name)>`: a name that is long, starts with `-` or `.`, ends with `.`, is a Windows
 *   device name before its first dot, or already looks like the hash form.
 * Never throws: whatever the text, the result passes the created-path rule.
 */
export function centralProjectName(repo: string): string {
  const lower = String(repo).toLowerCase();
  const plain = lower.length <= MAX_PLAIN && PLAIN_RE.test(lower) && !lower.endsWith('.') && !HASHED_RE.test(lower) && !DEVICE_RE.test(lower.split('.')[0] ?? '');
  return plain ? lower : `pipegen-${createHash('sha256').update(lower, 'utf8').digest('hex').slice(0, 20)}`;
}

/**
 * The path, inside the central repo, of a project's central workflow of one layer (ruling B2): `.github/workflows/<name>--<layer>.yml`, where
 * `<name>` is centralProjectName(project). The one place the file name is spelled: the referee knows the central push file by it (the only
 * central file a pr-check skip may sit in), and centralWorkflowPath builds on it.
 */
export const centralWorkflowFile = (project: string, layer: CentralLayer): string => `.github/workflows/${centralProjectName(project)}--${layer}.yml`;

/**
 * The path of a project's central workflow, `<owner>/pipelines/.github/workflows/<name>--merge.yml`: the one place it is spelled. The renderer
 * writes it into the find-run step (`central-workflow`), the caller job of pipegen.yml calls it (G5), and the referee requires exactly that
 * value, so a path with an `@`, a `..`, another repository or another file is refused. `pinRepo` is `draft.centralPin.repo` and `project` the
 * repository's name.
 */
export const centralWorkflowPath = (pinRepo: string, project: string): string => `${pinRepo}/${centralWorkflowFile(project, 'merge')}`;
