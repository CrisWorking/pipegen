// Provider selection, schema-checked completion and the terminal formatter for AI text (spec §19 "AI").
import { z } from 'zod';
import type { AiProvider, AiRequest, AiUsage } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { claudeProvider } from './claude.js';
import { AiError, count } from './errors.js';
import { ollamaProvider } from './ollama.js';
import { openaiProvider } from './openai.js';

export { AiError, type AiErrorKind } from './errors.js';
export { fallbackEnabled } from './claude.js';

export const MISSING_AI_MESSAGE = 'pipegen needs an AI to do the full job. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or run a local model with --ai ollama.';

/** Plain-English line shown at consent when the provider is Claude and fallbackEnabled(provider.model) is true (Task 8). */
export const REFUSAL_FALLBACK_NOTE = 'If Claude declines a request, Anthropic automatically runs it again on another Claude model of its choice (the refusal fallback). Your code still goes only to Anthropic.';

export const OLLAMA_EXPERIMENTAL_NOTE = 'Ollama support is experimental: answers from local models may be weaker, and pipegen checks every one against its schema.';

export interface MakeProviderOptions {
  ai?: string;            // --ai
  model?: string;         // --model
  effort?: string;        // --effort (Claude only)
  ollamaCtx?: number;     // --ollama-ctx
  env: NodeJS.ProcessEnv; // the only place keys and OLLAMA_HOST are read from
  /** Gets one-line notes for the user (the Ollama experimental note), once per logger. Nothing is printed without it. */
  log?: (line: string) => void;
  /** Transport override (tests). Defaults to the global fetch. */
  fetch?: typeof fetch;
}

// One run = one logger, so the experimental note is given once per run even if makeProvider is called again.
const notedLoggers = new WeakSet<(line: string) => void>();

const keyFrom = (env: NodeJS.ProcessEnv, name: string): string | undefined => {
  const v = env[name];
  return typeof v === 'string' && v !== '' ? v : undefined;
};

function makeClaude(opts: MakeProviderOptions, apiKey: string | undefined): AiProvider {
  if (!apiKey) throw new AiError('missing', '--ai claude needs ANTHROPIC_API_KEY to be set.');
  return claudeProvider({ key: apiKey, model: opts.model, effort: opts.effort, fetch: opts.fetch });
}

function makeOpenAi(opts: MakeProviderOptions, apiKey: string | undefined): AiProvider {
  if (!apiKey) throw new AiError('missing', '--ai openai needs OPENAI_API_KEY to be set.');
  if (!opts.model) throw new AiError('missing', 'OpenAI support is experimental and needs a model: pass --model (for example --model gpt-5).');
  return openaiProvider({ key: apiKey, model: opts.model, fetch: opts.fetch });
}

function makeOllama(opts: MakeProviderOptions): AiProvider {
  const p = ollamaProvider({ host: opts.env.OLLAMA_HOST, model: opts.model, numCtx: opts.ollamaCtx, fetch: opts.fetch });
  if (opts.log && !notedLoggers.has(opts.log)) {
    notedLoggers.add(opts.log);
    opts.log(OLLAMA_EXPERIMENTAL_NOTE);
  }
  return p;
}

/** --ai if given; else Claude when ANTHROPIC_API_KEY is set; else OpenAI when OPENAI_API_KEY is set; else AiError('missing'). */
export function makeProvider(opts: MakeProviderOptions): AiProvider {
  const anthropicKey = keyFrom(opts.env, 'ANTHROPIC_API_KEY');
  const openaiKey = keyFrom(opts.env, 'OPENAI_API_KEY');
  switch (opts.ai) {
    case 'claude': return makeClaude(opts, anthropicKey);
    case 'openai': return makeOpenAi(opts, openaiKey);
    case 'ollama': return makeOllama(opts);
    case undefined: break;
    default: throw new AiError('missing', `Unknown --ai value "${safeText(opts.ai, 40)}". Use claude, openai or ollama.`);
  }
  if (anthropicKey) return makeClaude(opts, anthropicKey);
  if (openaiKey) return makeOpenAi(opts, openaiKey);
  throw new AiError('missing', MISSING_AI_MESSAGE);
}

function addUsage(a: AiUsage, b: AiUsage | undefined): AiUsage {
  if (!b) return a;
  return {
    inputTokens: a.inputTokens + count(b.inputTokens),
    outputTokens: a.outputTokens + count(b.outputTokens),
    cacheReadTokens: count(a.cacheReadTokens) + count(b.cacheReadTokens),
    cacheWriteTokens: count(a.cacheWriteTokens) + count(b.cacheWriteTokens),
  };
}

const MAX_FEEDBACK = 4000;

/** The retry request: the original user text unchanged (so a cached code bundle is reused), then what was wrong. */
function withFeedback(req: AiRequest, problem: string): AiRequest {
  const text = problem.length > MAX_FEEDBACK ? `${problem.slice(0, MAX_FEEDBACK)}…` : problem;
  return {
    ...req,
    user: `${req.user}\n\nYour previous answer did not match the required JSON schema "${req.schemaName}":\n${text}\nAnswer again with JSON that matches the schema exactly.`,
  };
}

/**
 * provider.complete, then the answer checked with `schema`. Only an 'invalid' answer (not JSON, or not matching
 * the schema) is retried, up to `retries` times, with the zod error sent back. refusal, truncated, timeout and
 * http errors go straight to the caller. `usage` (and `error.usage` on failure) is the sum over every attempt.
 */
export async function completeValidated<T>(p: AiProvider, req: AiRequest, schema: z.ZodType<T>, retries = 1): Promise<{ data: T; usage: AiUsage }> {
  let usage: AiUsage = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
  let billed = false; // some attempt was answered (and billed), so a final error carries the summed usage
  let current = req;
  for (let attempt = 0; ; attempt++) {
    let problem: string;
    let lastError: AiError;
    try {
      const r = await p.complete(current);
      usage = addUsage(usage, r.usage);
      billed = true;
      const parsed = schema.safeParse(r.data);
      if (parsed.success) return { data: parsed.data, usage };
      problem = z.prettifyError(parsed.error);
      lastError = new AiError('invalid', 'The AI\'s answer did not match the expected format.', usage);
    } catch (e) {
      if (!(e instanceof AiError)) throw e;
      usage = addUsage(usage, e.usage);
      billed ||= e.usage !== undefined;
      if (e.kind !== 'invalid') throw new AiError(e.kind, e.message, billed ? usage : undefined);
      problem = e.message; // pipegen's own text ("…was not valid JSON."), never the answer itself
      lastError = new AiError('invalid', e.message, billed ? usage : undefined);
    }
    if (attempt >= retries) throw lastError;
    current = withFeedback(req, problem);
  }
}

/** Every AI-written string shown in the terminal goes through this first (ANSI, OSC, bidi and control characters removed). */
export function formatAiText(s: string, max?: number): string {
  return safeText(s, max);
}
