// The renderer's error type and the one way it quotes a value from outside in a message. A leaf module (it imports only
// safe-text), so render-step.ts and render-cli.ts can share it without importing each other.
import { safeText } from '../util/safe-text.js';

export class RenderError extends Error {}

/** A value from outside, shown in a message: one clean line, cut short, quoted when it is a string. */
export const show = (v: unknown): string => (typeof v === 'string' ? JSON.stringify(safeText(v, 60)) : safeText(String(v), 30));
