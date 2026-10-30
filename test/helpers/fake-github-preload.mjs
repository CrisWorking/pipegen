// Preloaded into the bundled gate with `node --import`: replaces fetch with a table of answers from PIPEGEN_FAKE_GH (a JSON file), so the
// real bundle runs end to end without a network. Not part of the product. Unknown URLs answer 404.
import { appendFileSync, readFileSync } from 'node:fs';
const table = JSON.parse(readFileSync(process.env.PIPEGEN_FAKE_GH, 'utf8'));
const json = (b) => new Response(JSON.stringify(b), { status: 200, headers: { 'content-type': 'application/json' } });
let issueNumber = 40;
globalThis.fetch = async (url, init) => {
  const u = new URL(String(url));
  // C7: the issue writes are recorded (PIPEGEN_FAKE_GH_LOG, one JSON line each) and answered with a number; the issue list is table.issues
  if (u.hostname === 'api.github.com' && init?.method !== undefined && init.method !== 'GET') {
    if (process.env.PIPEGEN_FAKE_GH_LOG) appendFileSync(process.env.PIPEGEN_FAKE_GH_LOG, `${JSON.stringify({ method: init.method, path: u.pathname, body: JSON.parse(String(init.body ?? 'null')) })}\n`);
    return new Response(JSON.stringify({ number: ++issueNumber }), { status: 201, headers: { 'content-type': 'application/json' } });
  }
  if (u.hostname === 'api.github.com' && /\/issues$/.test(u.pathname)) return json(table.issues ?? []);
  if (u.hostname.endsWith('.blob.core.windows.net')) {
    const z = table.zips[u.pathname.split('/').pop()];
    return z === undefined ? new Response('', { status: 404 }) : new Response(Buffer.from(z, 'base64'), { status: 200 });
  }
  if (u.hostname !== 'api.github.com') return new Response('', { status: 404 });
  const key = u.pathname + u.search;
  const zip = /\/actions\/artifacts\/(\d+)\/zip$/.exec(u.pathname);
  if (zip) return new Response('', { status: 302, headers: { location: `https://pipegen-fake.blob.core.windows.net/z/${zip[1]}` } });
  if (/\/actions\/workflows\/[^/]+\/runs$/.test(u.pathname)) return json(table.runs[u.searchParams.get('page')] ?? { workflow_runs: [] });
  const hit = table.routes[key];
  return hit === undefined ? new Response('{}', { status: 404 }) : json(hit);
};
