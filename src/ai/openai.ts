// OpenAI adapter (experimental). Plain fetch to the fixed Chat Completions URL; no SDK. Redirects are refused.
import type { AiProvider, AiRequest, AiUsage } from '../types.js';
import { AiError, count, safeCode, withTimeout } from './errors.js';

/** Fixed: the key is only ever sent here. */
export const OPENAI_URL = 'https://api.openai.com/v1/chat/completions';
export const OPENAI_REFUSAL_MESSAGE = 'OpenAI declined this request. Nothing was changed.';

export interface OpenAiOptions { key: string; model: string; fetch?: typeof fetch }

interface ChatAnswer {
  choices?: { message?: { content?: unknown; refusal?: unknown }; finish_reason?: unknown }[];
  usage?: { prompt_tokens?: unknown; completion_tokens?: unknown; prompt_tokens_details?: { cached_tokens?: unknown } };
}

function usageOf(a: ChatAnswer): AiUsage {
  return {
    inputTokens: count(a.usage?.prompt_tokens),
    outputTokens: count(a.usage?.completion_tokens),
    cacheReadTokens: count(a.usage?.prompt_tokens_details?.cached_tokens),
  };
}

export function openaiProvider(opts: OpenAiOptions): AiProvider {
  const doFetch = opts.fetch ?? globalThis.fetch;
  return {
    name: 'openai',
    model: opts.model,
    async complete(req: AiRequest) {
      const answer = await withTimeout(req.timeoutMs, 'OpenAI', async (signal) => {
        let res: Response;
        try {
          res = await doFetch(OPENAI_URL, {
            method: 'POST',
            signal,
            redirect: 'error', // a 3xx must never re-send the code bundle (and the key) to another host
            headers: { 'content-type': 'application/json', authorization: `Bearer ${opts.key}` },
            body: JSON.stringify({
              model: opts.model,
              messages: [{ role: 'system', content: req.system }, { role: 'user', content: req.user }],
              response_format: { type: 'json_schema', json_schema: { name: req.schemaName, schema: req.jsonSchema, strict: true } },
            }),
          });
        } catch (e) {
          if (signal.aborted) throw e;
          throw new AiError('http', 'Could not reach the OpenAI API. Check your network connection.');
        }
        if (!res.ok) {
          // The body is not shown: OpenAI echoes part of a wrong key in its message. Only the enumerated code is kept.
          let code = '';
          try { code = safeCode(((await res.json()) as { error?: { code?: unknown } }).error?.code); } catch { /* no usable body */ }
          throw new AiError('http', `The OpenAI API returned HTTP ${res.status}${code ? ` (${code})` : ''}.`);
        }
        try {
          return (await res.json()) as ChatAnswer;
        } catch (e) {
          if (signal.aborted) throw e;
          throw new AiError('http', 'The OpenAI API sent an answer pipegen could not read.');
        }
      });

      const usage = usageOf(answer);
      const choice = answer.choices?.[0];
      const message = choice?.message;
      if ((typeof message?.refusal === 'string' && message.refusal !== '') || choice?.finish_reason === 'content_filter') {
        throw new AiError('refusal', OPENAI_REFUSAL_MESSAGE, usage);
      }
      if (choice?.finish_reason === 'length') throw new AiError('truncated', 'OpenAI\'s answer was cut off before it was complete. Nothing was changed.', usage);
      if (choice?.finish_reason !== 'stop' || typeof message?.content !== 'string') {
        throw new AiError('invalid', 'OpenAI stopped without a complete answer.', usage);
      }
      try {
        return { data: JSON.parse(message.content) as unknown, usage };
      } catch {
        throw new AiError('invalid', 'OpenAI\'s answer was not valid JSON.', usage);
      }
    },
  };
}
