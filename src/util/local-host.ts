// Whether an Ollama host (host:port, as OllamaProvider.host gives it) is this computer. A leaf module (no imports):
// the consent screen and the estimator both use it, and the estimator must not pull in the AI code (final review
// batch 2, M3/M5).

/** Hosts that are this computer: loopback, and the any-address that Ollama's own client treats as local. */
const LOCAL_HOSTS = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|\[::\])$/i;

/**
 * 'local' when `host` is this computer, 'remote' when it is another machine, 'unknown' when there is no host or it
 * can't be read as an http(s) host (read like ollamaChatUrl: a bare host:port is http). 'unknown' must never be
 * shown as local.
 */
export function hostPlace(host: string | null | undefined): 'local' | 'remote' | 'unknown' {
  if (typeof host !== 'string' || host.trim() === '') return 'unknown';
  const raw = host.trim();
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`);
  } catch {
    return 'unknown';
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'unknown';
  return LOCAL_HOSTS.test(url.hostname) ? 'local' : 'remote';
}
