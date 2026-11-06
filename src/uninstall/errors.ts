// v0.2 Plan V (V1): the one error uninstall stops with. Its message is plain text for the user (names only, never a secret value or a
// server message), and it always means "nothing more was changed by this step".

/** Uninstall stops: a plain reason and, where there is one, the way on. */
export class UninstallError extends Error {
  constructor(message: string, options?: { cause?: unknown }) { super(message, options); this.name = 'UninstallError'; }
}
