// PL-F1: the command a "run it again" message names. Every stop says the command that raised it: the setup run is `npx pipegen run`
// (bare `npx pipegen` is the read-only audit, ruling G13-R2 6; "run" and no name are the same), every other command is named
// (`npx pipegen finish`).
export function pipegenCmd(command?: string): string {
  return command === undefined || command === 'run' ? '`npx pipegen run`' : `\`npx pipegen ${command}\``;
}
