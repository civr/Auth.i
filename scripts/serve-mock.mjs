import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../demo/', import.meta.url));
const port = Number(process.env.AUTHI_MOCK_PORT ?? 4173);
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/theme.css', ['theme.css', 'text/css; charset=utf-8']],
  ['/mock.js', ['mock.js', 'text/javascript; charset=utf-8']],
]);
const headers = {
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
};

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('AUTHI_MOCK_PORT must be a port from 1 to 65535.');
}

const server = createServer(async (request, response) => {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { ...headers, allow: 'GET, HEAD' }).end();
    return;
  }

  let pathname;
  try {
    pathname = decodeURIComponent(new URL(request.url ?? '/', 'http://127.0.0.1').pathname);
  } catch {
    response.writeHead(400, headers).end('Bad request');
    return;
  }

  const asset = assets.get(pathname);
  if (!asset) {
    response.writeHead(404, headers).end('Not found');
    return;
  }

  try {
    const body = await readFile(path.join(root, asset[0]));
    response.writeHead(200, { ...headers, 'content-type': asset[1] });
    response.end(request.method === 'HEAD' ? undefined : body);
  } catch {
    response.writeHead(500, headers).end('Unable to read demo asset');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Auth.i browser mock: http://127.0.0.1:${port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => server.close(() => process.exit(0)));
}
