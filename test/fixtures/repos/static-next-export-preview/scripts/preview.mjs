// Serves the exported site from ./out for a local look.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
const port = Number(process.env.PORT || 4173);
createServer(async (req, res) => {
  const file = req.url === '/' ? '/index.html' : req.url;
  try { res.end(await readFile('out' + file)); } catch { res.statusCode = 404; res.end('not found'); }
}).listen(port);
