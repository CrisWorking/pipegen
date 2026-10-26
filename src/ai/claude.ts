// Claude adapter (spec §19 "AI"). SDK calls follow the claude-api skill's TypeScript guide:
// - client.beta.messages.create with `betas` (beta header) and the beta-only `fallbacks: "default"` parameter;
// - structured outputs in `output_config.format`, built and read back with the SDK's betaJSONSchemaOutputFormat helper;
// - `output_config.effort` always set; `max_tokens` always set; no tools, no tool_choice, no temperature;
// - `stop_reason` checked before the answer is parsed; `cache_control` on the code-bundle block.
import Anthropic from '@anthropic-ai/sdk';
import { betaJSONSchemaOutputFormat } from '@anthropic-ai/sdk/helpers/beta/json-schema';
import { DEFAULT_MODEL, type AiProvider, type AiRequest, type AiUsage } from '../types.js';
import { AiError, count, safeCode, withTimeout } from './errors.js';

/** Fixed: the key is never sent anywhere else, whatever ANTHROPIC_BASE_URL or the repo says. */
export const CLAUDE_BASE_URL = 'https://api.anthropic.com';
/** Server-side refusal fallback, on for every request (the `"default"` form needs this exact header). */
export const FALLBACK_BETA = 'server-side-fallback-2026-07-01';
/**
 * Room for adaptive thinking plus the biggest schema answer pipegen asks for. Non-streaming is fine here:
 * every request passes its own timeout (req.timeoutMs), well under the SDK's 10-minute non-streaming limit.
 */
export const CLAUDE_MAX_TOKENS = 32_000;
export const CLAUDE_EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'] as const;
export type ClaudeEffort = typeof CLAUDE_EFFORTS[number];
export const DEFAULT_EFFORT: ClaudeEffort = 'high';
/** pipegen's own text for a refusal; the AI's words (and stop_details.explanation) are never shown. */
export const CLAUDE_REFUSAL_MESSAGE = 'Claude declined this request. Nothing was changed.';

const OPEN_TAG = '<code-bundle>';
const CLOSE_TAG = '</code-bundle>';

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

function usageOf(msg: Anthropic.Beta.BetaMessage): AiUsage {
  const u = msg.usage;
  return {
    inputTokens: count(u?.input_tokens),
    outputTokens: count(u?.output_tokens),
    cacheReadTokens: count(u?.cache_read_input_tokens),
    cacheWriteTokens: count(u?.cache_creation_input_tokens),
  };
}

/** The answer text: text blocks after the last fallback block (a declined model's partial output is dropped). */
function answerText(msg: Anthropic.Beta.BetaMessage): string {
  let start = 0;
  msg.content.forEach((b, i) => { if (b.type === 'fallback') start = i + 1; });
  return msg.content.slice(start).flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('');
}

/** An SDK or transport failure as an AiError with pipegen's own text (never the SDK message or response body). */
function httpError(e: unknown): AiError {
  if (e instanceof AiError) return e;
  if (e instanceof Anthropic.APIConnectionError) return new AiError('http', 'Could not reach the Claude API. Check your network connection.');
  if (e instanceof Anthropic.APIError && typeof e.status === 'number') {
    const body = e.error as { error?: { type?: unknown } } | undefined;
    const type = safeCode(body?.error?.type);
    return new AiError('http', `The Claude API returned HTTP ${e.status}${type ? ` (${type})` : ''}.`);
  }
  return new AiError('http', 'The Claude request failed.');
}

export function claudeProvider(opts: ClaudeOptions): AiProvider {
  const model = opts.model ?? DEFAULT_MODEL;
  const effort = opts.effort ?? DEFAULT_EFFORT;
  if (!isClaudeEffort(effort)) throw new Error(`--effort must be one of: ${CLAUDE_EFFORTS.join(', ')}.`);
  const client = new Anthropic({
    apiKey: opts.key,
    authToken: null, // never pick up ANTHROPIC_AUTH_TOKEN from the environment
    baseURL: CLAUDE_BASE_URL, // never ANTHROPIC_BASE_URL
    logLevel: 'off', // ANTHROPIC_LOG can't make the SDK log requests (prompts hold repo code)
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });

  return {
    name: 'claude',
    model,
    async complete(req: AiRequest) {
      // The SDK's structured-output helper: it adapts the schema for the API (the wire format) and gives the parser.
      // The parser is called only after stop_reason is checked, so half-finished JSON is never parsed.
      const { parse, ...format } = betaJSONSchemaOutputFormat(req.jsonSchema as Parameters<typeof betaJSONSchemaOutputFormat>[0]);
      const msg = await withTimeout(req.timeoutMs, 'Claude', async (signal) => {
        try {
          return await client.beta.messages.create({
            model,
            max_tokens: CLAUDE_MAX_TOKENS,
            betas: [FALLBACK_BETA],
            fallbacks: 'default',
            output_config: { effort, format },
            system: req.system,
            messages: [{ role: 'user', content: userContent(req.user) }],
          }, { signal, timeout: req.timeoutMs });
        } catch (e) {
          if (signal.aborted) throw e; // withTimeout turns it into AiError('timeout')
          throw httpError(e);
        }
      });

      const usage = usageOf(msg);
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
