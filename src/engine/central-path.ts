/**
 * The path of a project's central workflow, `<owner>/pipelines/.github/workflows/<project>--merge.yml`: the one place it is spelled. The renderer
 * writes it into the find-run step (`central-workflow`) and the referee requires exactly that value, so a path with an `@`, a `..`, another
 * repository or another file is refused. `pinRepo` is `draft.centralPin.repo` and `project` the repository's name.
 */
export const centralWorkflowPath = (pinRepo: string, project: string): string => `${pinRepo}/.github/workflows/${project}--merge.yml`;
