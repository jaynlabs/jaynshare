import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import {
  parseProxyUrl, proxyToUrl, describeProxy, bypassesProxy,
  resolveUpstreamProxy, setUpstreamProxy, resetUpstreamProxy, proxyForHost,
} from '../src/upstream-proxy.ts';
import { upstreamFetch, proxyFetch } from '../src/upstream-fetch.ts';

test.afterEach(() => resetUpstreamProxy());

// ── Parsing ──────────────────────────────────────────────────

test('parses the forms people actually write', () => {
  assert.deepEqual(parseProxyUrl('http://host:3128'), { host: 'host', port: 3128, username: null, password: null });
  // A bare host:port is what most corporate docs hand out; rejecting it would be pedantry.
  assert.deepEqual(parseProxyUrl('host:3128'), { host: 'host', port: 3128, username: null, password: null });
  assert.deepEqual(parseProxyUrl('http://u:p@host:8080'), { host: 'host', port: 8080, username: 'u', password: 'p' });
  assert.equal(parseProxyUrl('http://host').port, 8080);       // default when unstated
  assert.equal(parseProxyUrl('https://host').port, 443);
  assert.equal(parseProxyUrl(''), null);
  assert.equal(parseProxyUrl(null), null);
});

test('credentials survive a round trip through percent-encoding', () => {
  const parsed = parseProxyUrl('http://user%40corp:p%40ss%3Aword@host:3128');
  assert.equal(parsed.username, 'user@corp');
  assert.equal(parsed.password, 'p@ss:word');
  assert.deepEqual(parseProxyUrl(proxyToUrl(parsed)), parsed);
});

test('a wrong protocol is named rather than failing later inside the tunnel', () => {
  assert.throws(() => parseProxyUrl('socks5://host:1080'), /unsupported proxy protocol "socks5"/);
  assert.throws(() => parseProxyUrl('http://host:99999'), /invalid proxy URL|invalid port/);
});

test('describeProxy masks the password', () => {
  const p = parseProxyUrl('http://u:secret@host:3128');
  assert.equal(describeProxy(p), 'http://u:***@host:3128');
  assert.ok(!describeProxy(p).includes('secret'));
  assert.equal(describeProxy(null), 'none');
});

// ── NO_PROXY ─────────────────────────────────────────────────

test('NO_PROXY matches suffixes, with or without a leading dot', () => {
  assert.equal(bypassesProxy('api.anthropic.com', 'anthropic.com'), true);
  assert.equal(bypassesProxy('api.anthropic.com', '.anthropic.com'), true);
  assert.equal(bypassesProxy('api.anthropic.com', 'example.com,anthropic.com'), true);
  assert.equal(bypassesProxy('api.anthropic.com', 'example.com'), false);
  assert.equal(bypassesProxy('api.anthropic.com', '*'), true);
  assert.equal(bypassesProxy('localhost', 'localhost:8080'), true);   // port-qualified, port ignored
  // A suffix must land on a label boundary: "notanthropic.com" is a different host.
  assert.equal(bypassesProxy('notanthropic.com', 'anthropic.com'), false);
});

// ── Resolution precedence ────────────────────────────────────

test('config wins over the environment', () => {
  const r = resolveUpstreamProxy({ upstreamProxy: 'cfg:1' }, { HTTPS_PROXY: 'http://env:2' });
  assert.equal(r.source, 'config');
  assert.equal(r.proxy.host, 'cfg');
});

test('the environment is honoured when the config says nothing', () => {
  const r = resolveUpstreamProxy({}, { HTTPS_PROXY: 'http://env:3128' });
  assert.equal(r.source, 'env:HTTPS_PROXY');
  assert.equal(r.proxy.port, 3128);
  assert.equal(resolveUpstreamProxy({}, { all_proxy: 'http://e:1' }).source, 'env:all_proxy');
  assert.equal(resolveUpstreamProxy({}, {}).proxy, null);
});

test('upstreamProxy:false opts out of the environment entirely', () => {
  const r = resolveUpstreamProxy({ upstreamProxy: false }, { HTTPS_PROXY: 'http://env:2' });
  assert.equal(r.proxy, null);
  assert.equal(r.source, 'disabled');
});

test('proxyForHost applies NO_PROXY', () => {
  setUpstreamProxy(resolveUpstreamProxy({ upstreamProxy: 'p:3128', noProxy: 'internal.example' }, {}));
  assert.equal(proxyForHost('api.anthropic.com').host, 'p');
  assert.equal(proxyForHost('svc.internal.example'), null);
});

// A short-lived command never loads a config.
test('an unset proxy falls back to the environment on first read', () => {
  resetUpstreamProxy();
  const prev = process.env.HTTPS_PROXY;
  process.env.HTTPS_PROXY = 'http://fallback:3128';
  try {
    assert.equal(proxyForHost('api.anthropic.com').host, 'fallback');
  } finally {
    if (prev === undefined) delete process.env.HTTPS_PROXY;
    else process.env.HTTPS_PROXY = prev;
  }
});

// ── End to end through a real CONNECT proxy ──────────────────

// Records every tunnel target.
function connectProxy() {
  const targets = [];
  let authSeen = null;
  const server = http.createServer((_req, res) => { res.writeHead(405); res.end(); });
  server.on('connect', (req, clientSock, head) => {
    targets.push(req.url);
    authSeen = req.headers['proxy-authorization'] || null;
    const [host, port] = req.url.split(':');
    const upstream = net.connect(Number(port), host, () => {
      clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) upstream.write(head);
      clientSock.pipe(upstream);
      upstream.pipe(clientSock);
    });
    upstream.on('error', () => clientSock.destroy());
    clientSock.on('error', () => upstream.destroy());
  });
  return { server, targets, auth: () => authSeen };
}

function listen(server) {
  return new Promise<any>(resolve => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port)));
}

test('an upstream request is tunneled through the configured proxy', async () => {
  const origin = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, path: req.url }));
  });
  const originPort = await listen(origin);
  const { server: proxy, targets } = connectProxy();
  const proxyPort = await listen(proxy);

  // An explicit empty env: the developer's NO_PROXY=127.0.0.1 would bypass the mock proxy.
  setUpstreamProxy(resolveUpstreamProxy({ upstreamProxy: `127.0.0.1:${proxyPort}` }, {}));

  try {
    const res = await upstreamFetch(`http://127.0.0.1:${originPort}/v1/messages`, { method: 'GET', headersTimeoutMs: 8000 });
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(await res.text()), { ok: true, path: '/v1/messages' });
    assert.deepEqual(targets, [`127.0.0.1:${originPort}`]);   // it really went through the proxy
  } finally {
    proxy.close();
    origin.close();
  }
});

test('proxy credentials are offered as Proxy-Authorization', async () => {
  const origin = http.createServer((_req, res) => { res.writeHead(200); res.end('hi'); });
  const originPort = await listen(origin);
  const { server: proxy, auth } = connectProxy();
  const proxyPort = await listen(proxy);

  setUpstreamProxy(resolveUpstreamProxy({ upstreamProxy: `http://bob:s3cret@127.0.0.1:${proxyPort}` }, {}));

  try {
    await upstreamFetch(`http://127.0.0.1:${originPort}/x`, { method: 'GET', headersTimeoutMs: 8000 });
    assert.equal(auth(), `Basic ${Buffer.from('bob:s3cret').toString('base64')}`);
  } finally {
    proxy.close();
    origin.close();
  }
});

test('control-plane calls (oauth) are tunneled too', async () => {
  const origin = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ access_token: 'a' }));
  });
  const originPort = await listen(origin);
  const { server: proxy, targets } = connectProxy();
  const proxyPort = await listen(proxy);

  setUpstreamProxy(resolveUpstreamProxy({ upstreamProxy: `127.0.0.1:${proxyPort}` }, {}));

  try {
    const res = await proxyFetch(`http://127.0.0.1:${originPort}/oauth/token`, { method: 'POST', body: '{}', headersTimeoutMs: 8000 });
    assert.equal(res.ok, true);
    assert.deepEqual(await res.json(), { access_token: 'a' });
    assert.equal(targets.length, 1);
  } finally {
    proxy.close();
    origin.close();
  }
});

test('a bypassed host goes direct even with a proxy configured', async () => {
  const origin = http.createServer((_req, res) => { res.writeHead(200); res.end('direct'); });
  const originPort = await listen(origin);
  const { server: proxy, targets } = connectProxy();
  const proxyPort = await listen(proxy);

  setUpstreamProxy(resolveUpstreamProxy({ upstreamProxy: `127.0.0.1:${proxyPort}`, noProxy: '127.0.0.1' }, {}));

  try {
    const res = await upstreamFetch(`http://127.0.0.1:${originPort}/x`, { method: 'GET', headersTimeoutMs: 8000 });
    assert.equal(await res.text(), 'direct');
    assert.deepEqual(targets, []);                            // the proxy was never asked
  } finally {
    proxy.close();
    origin.close();
  }
});

// oauth's refresh timeout depends on it.
test('an AbortSignal still cancels a tunneled request', async () => {
  const origin = http.createServer(() => { /* never answers */ });
  const originPort = await listen(origin);
  const { server: proxy } = connectProxy();
  const proxyPort = await listen(proxy);

  setUpstreamProxy(resolveUpstreamProxy({ upstreamProxy: `127.0.0.1:${proxyPort}` }, {}));

  try {
    await assert.rejects(
      proxyFetch(`http://127.0.0.1:${originPort}/hang`, { signal: AbortSignal.timeout(150) }),
    );
  } finally {
    proxy.close();
    origin.close();
    await once(origin, 'close').catch(() => {});
  }
});

test('a refused CONNECT names the upstream proxy', async () => {
  const proxy = http.createServer((_req, res) => { res.writeHead(405); res.end(); });
  proxy.on('connect', (_req, sock) => { sock.write('HTTP/1.1 403 Forbidden\r\n\r\n'); sock.end(); });
  const proxyPort = await listen(proxy);

  setUpstreamProxy(resolveUpstreamProxy({ upstreamProxy: `127.0.0.1:${proxyPort}` }, {}));

  try {
    await assert.rejects(
      upstreamFetch('http://198.51.100.7:443/x', { method: 'GET', headersTimeoutMs: 8000 }),
      /upstream proxy refused CONNECT: HTTP\/1\.1 403/,
    );
  } finally {
    proxy.close();
  }
});
