// Ollama adapter (experimental). Plain fetch to {OLLAMA_HOST}/api/chat. No API key is ever sent here.
import type { AiProvider, AiRequest, AiUsage } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { AiError, count, withTimeout } from './errors.js';

export const OLLAMA_DEFAULT_HOST = 'http://127.0.0.1:11434';
export const OLLAMA_DEFAULT_MODEL = 'llama3.1';
/** Always sent: Ollama's own small default silently cuts long prompts. */
export const OLLAMA_DEFAULT_CTX = 32768;

export interface OllamaOptions { host?: string; model?: string; numCtx?: number; fetch?: typeof fetch }

/**
 * The /api/chat URL for an OLLAMA_HOST value. Only http and https are allowed (anything else: AiError 'http').
 * A bare `host:port` (as Ollama itself accepts) is read as http. Any path on the host is kept as a prefix.
 */
export function ollamaChatUrl(host: string = OLLAMA_DEFAULT_HOST): URL {
  const raw = host.trim() === '' ? OLLAMA_DEFAULT_HOST : host.trim();
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`);
  } catch {
    throw new AiError('http', 'OLLAMA_HOST is not a valid URL. Use something like http://127.0.0.1:11434.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new AiError('http', 'OLLAMA_HOST must be an http:// or https:// URL.');
  }
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/api/chat`;
  url.search = '';
  url.hash = '';
  return url;
}

function usageOf(a: { prompt_eval_count?: unknown; eval_count?: unknown }): AiUsage {
  return { inputTokens: count(a.prompt_eval_count), outputTokens: count(a.eval_count) };
}

export function ollamaProvider(opts: OllamaOptions = {}): AiProvider {
  const url = ollamaChatUrl(opts.host);
  const where = url.host; // shown in errors: host and port only, never userinfo or a path
  const model = opts.model ?? OLLAMA_DEFAULT_MODEL;
  const numCtx = opts.numCtx ?? OLLAMA_DEFAULT_CTX;
  if (!Number.isInteger(numCtx) || numCtx < 1) throw new Error('--ollama-ctx must be a whole number above 0.');
  const doFetch = opts.fetch ?? globalThis.fetch;

  return {
    name: 'ollama',
    model,
    async complete(req: AiRequest) {
      const answer = await withTimeout(req.timeoutMs, 'Ollama', async (signal) => {
        let res: Response;
        try {
          res = await doFetch(url, {
            method: 'POST',
            signal,
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              model,
              messages: [{ role: 'system', content: req.system }, { role: 'user', content: req.user }],
              format: req.jsonSchema,
              stream: false,
              options: { num_ctx: numCtx },
            }),
          });
        } catch (e) {
          if (signal.aborted) throw e;
          throw new AiError('http', `Could not reach Ollama at ${where}: is Ollama running?`);
        }
        if (!res.ok) throw new AiError('http', `Ollama at ${where} returned HTTP ${res.status}. Is the model "${safeText(model, 100)}" pulled?`);
        try {
          return (await res.json()) as { message?: { content?: unknown }; done_reason?: unknown; prompt_eval_count?: unknown; eval_count?: unknown };
        } catch (e) {
          if (signal.aborted) throw e;
          throw new AiError('http', `Ollama at ${where} sent an answer pipegen could not read.`);
        }
      });

      const usage = usageOf(answer);
      if (answer.done_reason === 'length') throw new AiError('truncated', 'Ollama\'s answer was cut off before it was complete. Nothing was changed.', usage);
      const content = answer.message?.content;
      if (typeof content !== 'string') throw new AiError('invalid', 'Ollama stopped without a complete answer.', usage);
      try {
        return { data: JSON.parse(content) as unknown, usage };
      } catch {
        throw new AiError('invalid', 'Ollama\'s answer was not valid JSON.', usage);
      }
    },
  };
}
