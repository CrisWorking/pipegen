// v0.2 Plan V (V1): the one error uninstall stops with. Its message is plain text for the user (names only, never a secret value or a
// server message), and it always means "nothing more was changed by this step".

/** Uninstall stops: a plain reason and, where there is one, the way on. */
export class UninstallError extends Error {
  constructor(message: string, options?: { cause?: unknown }) { super(message, options); this.name = 'UninstallError'; }
}

/**
 * V6-R3 sec M1: not a failure. The last run sent pipegen's own DELETE of `<owner>/pipelines` and GitHub now answers 404 for it, so the
 * uninstall is finished: the loader removed the local files and says so (V7 maps it to a success).
 */
export class UninstallFinished extends UninstallError {
  constructor(message: string) { super(message); this.name = 'UninstallFinished'; }
}
