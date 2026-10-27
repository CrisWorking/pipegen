## What and why

<!-- One or two sentences. -->

## Checklist

- [ ] Tests added or updated, and `npm test` passes
- [ ] `npx tsc --noEmit` passes
- [ ] Pins changed (reviewed-tools, pinned-binaries, gate/watcher, build devDependencies): yes / no. If yes, listed below
- [ ] Every changed pin points to a release at least 7 days old (cooldown). An urgent security fix instead needs the
      `security-fix` label from a code owner, a `Security-fix-reason:` line below, and a code-owner review on the head
      commit with a `Security-fix-approved` line, renewed after every push (docs/cooldown.md)
- [ ] Threat model updated if behavior changed
- [ ] Build config or lockfile changed on purpose
- [ ] Self-review done (until a second maintainer exists)

## Pins changed

<!-- name, old version, new version, release date -->
