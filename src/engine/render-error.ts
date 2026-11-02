// The renderer's shared leaf: its error type and the few helpers both renderers use (render-step.ts and render-cli.ts).
// It imports only known-values (the cutter that scrubs with the active vault), so neither renderer has to import the other for them.
import { activeSafeText as safeText } from '../util/known-values.js';

export class RenderError extends Error {}

/** A value from outside, shown in a message: one clean line, cut short, quoted when it is a string. */
export const show = (v: unknown): string => (typeof v === 'string' ? JSON.stringify(safeText(v, 60)) : safeText(String(v), 30));

/** An expression opener. Actions evaluates `${{` anywhere in a workflow value, quoted or not, so no rendered text may hold one. */
export const EXPR = '${{';

/** Throws a RenderError (as a function, so it can end an expression). */
export const refuse = (message: string): never => { throw new RenderError(message); };

/** An own property of a table, or undefined: a repo-derived key can not reach the prototype (`toString`, `__proto__`). */
export const own = <T>(o: Readonly<Record<string, T>>, k: string): T | undefined => (Object.hasOwn(o, k) ? o[k] : undefined);
