// A loopback smart-HTTP git server for the git transport tests (E0c): `git http-backend` behind a node:http server on
// 127.0.0.1, serving local bare repos. Nothing leaves the machine. It can ask for Basic auth (x-access-token + a token),
// answer every request with a redirect, or hold receive-pack requests for a while (so a test can look at the client
// while the push is in flight). Every request is recorded with its Authorization header, if any.
import { spawn } from 'node:child_process';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { REAL_GIT } from './git-recorder.js';

/** PATH as it was when the tests started (before a test puts its git recorder first). */
const BASE_PATH = process.env.PATH ?? '/usr/bin:/bin';

/** `header` is the request's Authorization header, if any. */
export interface SeenRequest { method: string; url: string; header?: string }
export interface GitHttpOptions {
  /** Ask for Basic auth with this token (user x-access-token); without it every request is served. */
  token?: string;
  /** Answer every request with a 302 to this port on 127.0.0.1 (same path). */
  redirectTo?: number;
  /** Hold every receive-pack POST this long before serving it. */
  holdPushMs?: number;
}
export interface GitHttpServer {
  port: number;
  requests: SeenRequest[];
  close(): Promise<void>;
}

const readBody = (req: IncomingMessage): Promise<Buffer> =>
  new Promise((ok, fail) => {
    const parts: Buffer[] = [];
    req.on('data', (c: Buffer) => parts.push(c));
    req.on('end', () => ok(Buffer.concat(parts)));
    req.on('error', fail);
  });

async function serveCgi(root: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req);
  const u = new URL(req.url ?? '/', 'http://127.0.0.1');
  const env: Record<string, string> = {
    PATH: BASE_PATH,
    HOME: root,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_PROJECT_ROOT: root,
    GIT_HTTP_EXPORT_ALL: '1',
    PATH_INFO: decodeURIComponent(u.pathname),
    QUERY_STRING: u.search.replace(/^\?/, ''),
    REQUEST_METHOD: req.method ?? 'GET',
    CONTENT_TYPE: req.headers['content-type'] ?? '',
    CONTENT_LENGTH: String(body.length),
    REMOTE_USER: 'x-access-token',
    REMOTE_ADDR: '127.0.0.1',
  };
  const enc = req.headers['content-encoding'];
  if (typeof enc === 'string') env.HTTP_CONTENT_ENCODING = enc;
  const proto = req.headers['git-protocol'];
  if (typeof proto === 'string') env.GIT_PROTOCOL = proto;
  const child = spawn(REAL_GIT, ['http-backend'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const out: Buffer[] = [];
  child.stdout.on('data', (c: Buffer) => out.push(c));
  child.stderr.on('data', () => {});
  // http-backend may exit before reading the whole body (e.g. a rejected push); the reply is on stdout.
  child.stdin.on('error', (e: NodeJS.ErrnoException) => {
    if (e.code !== 'EPIPE') throw e;
  });
  child.stdin.end(body);
  await new Promise<void>((ok) => child.on('close', () => ok()));
  const all = Buffer.concat(out);
  const split = all.indexOf('\r\n\r\n');
  const head = all.subarray(0, split).toString('latin1').split('\r\n');
  let status = 200;
  for (const line of head) {
    const i = line.indexOf(':');
    const name = line.slice(0, i).trim();
    const value = line.slice(i + 1).trim();
    if (name.toLowerCase() === 'status') status = Number(value.split(' ')[0]);
    else if (name !== '') res.setHeader(name, value);
  }
  res.statusCode = status;
  res.end(all.subarray(split + 4));
}

export async function startGitHttp(root: string, opts: GitHttpOptions = {}): Promise<GitHttpServer> {
  const requests: SeenRequest[] = [];
  const server = createServer((req, res) => {
    const seen: SeenRequest = { method: req.method ?? '', url: req.url ?? '' };
    if (req.headers.authorization !== undefined) seen.header = req.headers.authorization;
    requests.push(seen);
    if (opts.redirectTo !== undefined) {
      res.writeHead(302, { Location: `http://127.0.0.1:${opts.redirectTo}${req.url ?? '/'}` });
      res.end();
      return;
    }
    if (opts.token !== undefined) {
      const want = ['Basic', Buffer.from(['x-access-token', opts.token].join(':')).toString('base64')].join(' ');
      if (req.headers.authorization !== want) {
        res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="test"' });
        res.end();
        return;
      }
    }
    const hold = opts.holdPushMs !== undefined && req.method === 'POST' && (req.url ?? '').endsWith('/git-receive-pack') ? opts.holdPushMs : 0;
    setTimeout(() => {
      serveCgi(root, req, res).catch(() => {
        res.statusCode = 500;
        res.end();
      });
    }, hold);
  });
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', () => ok()));
  return {
    port: (server.address() as AddressInfo).port,
    requests,
    close: () =>
      new Promise<void>((ok) => {
        server.closeAllConnections();
        server.close(() => ok());
      }),
  };
}
