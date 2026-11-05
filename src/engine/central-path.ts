/**
 * The path, inside the central repo, of a project's central workflow of one layer (ruling B2): `.github/workflows/<project>--<layer>.yml`. The one
 * place the file name is spelled: the referee knows the central push file by it (the only central file a pr-check skip may sit in), and
 * centralWorkflowPath builds on it. (S16, G5: the project name gets its slug and hash fallback here, for every caller at once.)
 */
export const centralWorkflowFile = (project: string, layer: 'merge' | 'push' | 'nightly'): string => `.github/workflows/${project}--${layer}.yml`;

/**
 * The path of a project's central workflow, `<owner>/pipelines/.github/workflows/<project>--merge.yml`: the one place it is spelled. The renderer
 * writes it into the find-run step (`central-workflow`) and the referee requires exactly that value, so a path with an `@`, a `..`, another
 * repository or another file is refused. `pinRepo` is `draft.centralPin.repo` and `project` the repository's name.
 */
export const centralWorkflowPath = (pinRepo: string, project: string): string => `${pinRepo}/${centralWorkflowFile(project, 'merge')}`;
