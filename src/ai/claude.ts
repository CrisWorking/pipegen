// Claude adapter (spec §19 "AI"). SDK calls follow the claude-api skill's TypeScript guide:
// - client.beta.messages.stream(...).finalMessage() (streaming, as the skill and the SDK ask for a large max_tokens),
//   with `betas` (beta header) and the beta-only `fallbacks: "default"` for models with server-side fallback;
// - structured outputs in `output_config.format`, built and read back with the SDK's betaJSONSchemaOutputFormat helper;
// - `output_config.effort` always set; `max_tokens` always set; no tools, no tool_choice, no temperature;
// - `stop_reason` checked before the answer is parsed; `cache_control` on the code-bundle block;
// - usage summed over `usage.iterations` (the per-attempt source of truth when a fallback model ran).
import Anthropic from '@anthropic-ai/sdk';
import { betaJSONSchemaOutputFormat } from '@anthropic-ai/sdk/helpers/beta/json-schema';
import { DEFAULT_MODEL, type AiProvider, type AiRequest, type AiTokenCounts, type AiUsage, type AiUsageAttempt } from '../types.js';
import { fallbackEnabled } from '../util/claude-fallback.js';
import { safeText } from '../util/safe-text.js';
import { AiError, count, outputLimit, safeCode, withTimeout } from './errors.js';

export { FALLBACK_MODELS, fallbackEnabled } from '../util/claude-fallback.js';

/** Fixed: the key is never sent anywhere else, whatever ANTHROPIC_BASE_URL or the repo says. */
export const CLAUDE_BASE_URL = 'https://api.anthropic.com';
/** Server-side refusal fallback (the `"default"` form needs this exact header). */
export const FALLBACK_BETA = 'server-side-fallback-2026-07-01';
/**
 * Room for adaptive thinking plus the biggest schema answer pipegen asks for. On models whose thinking can't be
 * turned off, thinking counts toward this at effort `high`, and a max_tokens stop is never retried, so the ceiling
 * is the ~64k the claude-api skill recommends for streamed requests (final review batch 2, M6). A request's own
 * `maxOutputTokens` (lower) replaces it, and the cost meter of `audit --ai` (Plan U ruling U13) prices that limit. Requests are streamed
 * (`.stream(...).finalMessage()`), so this size is safe from HTTP timeouts; the total time is still bounded by
 * req.timeoutMs.
 */
export const CLAUDE_MAX_TOKENS = 64_000;
export const CLAUDE_EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'] as const;
export type ClaudeEffort = typeof CLAUDE_EFFORTS[number];
export const DEFAULT_EFFORT: ClaudeEffort = 'high';
/** pipegen's own text for a refusal; the AI's words (and stop_details.explanation) are never shown. */
export const CLAUDE_REFUSAL_MESSAGE = 'Claude declined this request. Nothing was changed.';

const OPEN_TAG = '<code-bundle>';
const CLOSE_TAG = '</code-bundle>';

/** `base` with every request forced to `redirect: 'error'`. */
function noRedirectFetch(base: typeof fetch): typeof fetch {
  return ((input: Parameters<typeof fetch>[0], init?: RequestInit) => base(input, { ...init, redirect: 'error' })) as typeof fetch;
}

export interface ClaudeOptions { key: string; model?: string; effort?: string; fetch?: typeof fetch }

export function isClaudeEffort(e: string): e is ClaudeEffort {
  return (CLAUDE_EFFORTS as readonly string[]).includes(e);
}

/**
 * The user turn. When it starts with bundleText()'s <code-bundle>…</code-bundle> block, that block is sent
 * first with a cache breakpoint at its end, and the rest after it, so retries and later rounds reuse the
 * cached bundle. bundleText neutralizes any closing tag inside repo text, so the first one is the real end.
 */
export function userContent(user: string): string | Anthropic.Beta.BetaTextBlockParam[] {
  if (!user.startsWith(OPEN_TAG)) return user;
  const end = user.indexOf(CLOSE_TAG);
  if (end < 0) return user;
  const cut = end + CLOSE_TAG.length;
  const blocks: Anthropic.Beta.BetaTextBlockParam[] = [{ type: 'text', text: user.slice(0, cut), cache_control: { type: 'ephemeral' } }];
  const rest = user.slice(cut);
  if (rest.trim() !== '') blocks.push({ type: 'text', text: rest }); // the API refuses empty text blocks
  return blocks;
}

interface TokenCounts { input_tokens?: unknown; output_tokens?: unknown; cache_read_input_tokens?: unknown; cache_creation_input_tokens?: unknown }

const toUsage = (u: TokenCounts | null | undefined): AiUsage => ({
  inputTokens: count(u?.input_tokens),
  outputTokens: count(u?.output_tokens),
  cacheReadTokens: count(u?.cache_read_input_tokens),
  cacheWriteTokens: count(u?.cache_creation_input_tokens),
});

/**
 * Billed tokens of the call. Top-level usage covers only the attempt that produced the returned message;
 * `usage.iterations` is the per-attempt source of truth (model-migration.md, refusal section: "Billing"), and
 * cost-optimization.md says to sum the iterations rather than read the top-level counts. So when iterations is a
 * non-empty list, every entry is summed: `message` and `fallback_message` (each model that ran), and also
 * `compaction` and `advisor_message` (pipegen never turns those on, but the SDK types say their tokens are not in
 * the top-level fields, so they are billed on top). Otherwise the top-level fields are used.
 * Plan E S22: with iterations, `attempts` lists each run with the model it names (`model`, the requested one, when it
 * names none), so the report prices a fallback run at its own model; the cost cap keeps pricing the sum at ceiling rates.
 */
export function usageOf(msg: { usage?: (TokenCounts & { iterations?: (TokenCounts & { model?: unknown })[] | null }) | null }, model: string): AiUsage {
  const its = msg.usage?.iterations;
  if (!Array.isArray(its) || its.length === 0) return toUsage(msg.usage);
  const total: AiTokenCounts = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
  const attempts: AiUsageAttempt[] = [];
  for (const it of its) {
    const x = toUsage(it);
    total.inputTokens += x.inputTokens;
    total.outputTokens += x.outputTokens;
    total.cacheReadTokens += x.cacheReadTokens ?? 0;
    total.cacheWriteTokens += x.cacheWriteTokens ?? 0;
    // S22: each run at the model the API names (an entry without one ran on the requested model); for the report only
    const named = typeof it?.model === 'string' && it.model !== '' ? safeText(it.model, 100) : '';
    attempts.push({ model: named === '' ? model : named, input: x.inputTokens, output: x.outputTokens, cacheRead: x.cacheReadTokens ?? 0, cacheWrite: x.cacheWriteTokens ?? 0 });
  }
  return { ...total, attempts };
}

/** The answer text: text blocks after the last fallback block (a declined model's partial output is dropped). */
function answerText(msg: Anthropic.Beta.BetaMessage): string {
  let start = 0;
  msg.content.forEach((b, i) => { if (b.type === 'fallback') start = i + 1; });
  return msg.content.slice(start).flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('');
}

/**
 * An SDK or transport failure as an AiError with pipegen's own text (never the SDK message or response body).
 * With a user-chosen --model, a 400/404 names it, since an unknown or unsupported model is the likely cause.
 */
function httpError(e: unknown, userModel: string | undefined): AiError {
  if (e instanceof AiError) return e;
  if (e instanceof Anthropic.APIConnectionError) return new AiError('http', 'Could not reach the Claude API. Check your network connection.');
  if (e instanceof Anthropic.APIError && typeof e.status === 'number') {
    const body = e.error as { error?: { type?: unknown } } | undefined;
    const type = safeCode(body?.error?.type);
    const hint = userModel !== undefined && (e.status === 400 || e.status === 404) ? `; check --model ("${safeText(userModel, 100)}")` : '';
    return new AiError('http', `The Claude API returned HTTP ${e.status}${type ? ` (${type})` : ''}${hint}.`);
  }
  return new AiError('http', 'The Claude request failed.');
}

/** The SDK's structured-output helper for req.jsonSchema; a schema it can't use is AiError('invalid'). */
function outputFormat(schema: object) {
  try {
    return betaJSONSchemaOutputFormat(schema as Parameters<typeof betaJSONSchemaOutputFormat>[0]);
  } catch {
    throw new AiError('invalid', 'The answer schema must be a JSON object schema ({ "type": "object", ... }).');
  }
}

export function claudeProvider(opts: ClaudeOptions): AiProvider {
  const model = opts.model ?? DEFAULT_MODEL;
  const effort = opts.effort ?? DEFAULT_EFFORT;
  if (!isClaudeEffort(effort)) throw new AiError('invalid', `--effort must be one of: ${CLAUDE_EFFORTS.join(', ')}.`);
  const withFallback = fallbackEnabled(model);
  // Note: the SDK also merges ANTHROPIC_CUSTOM_HEADERS from the user's environment into every request; it has no
  // switch to turn that off (see docs/threat-model.md T46). The key still goes only to CLAUDE_BASE_URL.
  const client = new Anthropic({
    apiKey: opts.key,
    authToken: null, // never pick up ANTHROPIC_AUTH_TOKEN from the environment
    baseURL: CLAUDE_BASE_URL, // never ANTHROPIC_BASE_URL
    logLevel: 'off', // ANTHROPIC_LOG can't make the SDK log requests (prompts hold repo code)
    // No OpenTelemetry: no spans (a global tracer provider, e.g. loaded through NODE_OPTIONS, could export the
    // prompts, which hold repo code, in content mode) and no trace-context headers. Given explicitly, so the
    // ANTHROPIC_OPEN_TELEMETRY* environment variables are not read.
    openTelemetry: { traces: false, propagation: false },
    // A 3xx must never re-send the code bundle (and the x-api-key header, which fetch keeps across origins) to
    // another host, so every request refuses redirects, as the Ollama and OpenAI adapters do.
    fetch: noRedirectFetch(opts.fetch ?? globalThis.fetch),
    // maxRetries stays at the SDK default (2), on purpose (ruling U14, review N4). The claude-api skill (SKILL.md, "Client
    // config") says the SDK retries 408/409/429/5xx answers and connection errors. Those are requests that failed with no
    // message produced; pipegen ASSUMES they are not billed (the skill doesn't say so). A failure after the answer has
    // started streaming is not retried by the SDK. So one metered attempt bills at most one answer.
  });

  return {
    name: 'claude',
    model,
    async complete(req: AiRequest) {
      // The helper adapts the schema for the API (the wire format) and gives the parser. The parser is left out of
      // the request, so the SDK does not parse on its own; it is called only after stop_reason is checked, so
      // half-finished JSON is never parsed.
      const limit = outputLimit(req.maxOutputTokens); // refused up front when it isn't a whole number above 0
      const { parse, ...format } = outputFormat(req.jsonSchema);
      const msg = await withTimeout(req.timeoutMs, 'Claude', async (signal) => {
        try {
          return await client.beta.messages.stream({
            model,
            max_tokens: Math.min(limit ?? CLAUDE_MAX_TOKENS, CLAUDE_MAX_TOKENS),
            ...(withFallback ? { betas: [FALLBACK_BETA], fallbacks: 'default' as const } : {}),
            output_config: { effort, format },
            system: req.system,
            messages: [{ role: 'user', content: userContent(req.user) }],
          }, { signal, timeout: req.timeoutMs }).finalMessage();
        } catch (e) {
          if (signal.aborted) throw e; // withTimeout turns it into AiError('timeout')
          throw httpError(e, opts.model);
        }
      });

      const usage = usageOf(msg, model);
      switch (msg.stop_reason) {
        case 'end_turn':
        case 'stop_sequence':
          break;
        case 'refusal':
          throw new AiError('refusal', CLAUDE_REFUSAL_MESSAGE, usage);
        case 'max_tokens':
        case 'model_context_window_exceeded':
          throw new AiError('truncated', 'Claude\'s answer was cut off before it was complete. Nothing was changed.', usage);
        default:
          throw new AiError('invalid', 'Claude stopped without a complete answer.', usage);
      }
      let data: unknown;
      try {
        data = parse(answerText(msg));
      } catch {
        throw new AiError('invalid', 'Claude\'s answer was not valid JSON.', usage);
      }
      return { data, usage };
    },
  };
}
