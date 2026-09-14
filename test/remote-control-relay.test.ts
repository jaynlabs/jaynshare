import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import type { Socket } from 'node:net';
import { once } from 'node:events';
import { createProxyRequestListener, createUpgradeRelay } from '../src/server.ts';

async function listen(handler) {
  const server = http.createServer(handler);
  server.listen(0);
  await once(server, 'listening');
  return { server, port: (server.address() as { port: number }).port };
}

async function requestThrough(listener, { method = 'GET', path, headers = {}, body }: {
  method?: string; path: string; headers?: Record<string, string>; body?: string;
}) {
  const { server: proxy, port } = await listen(listener);
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers, body });
    return { status: res.status, text: await res.text(), headers: res.headers };
  } finally {
    proxy.close();
  }
}

test('a GET to /v1/code/* forwards the client credential and streams the response back untouched', async () => {
  const { server: upstream, port: upstreamPort } = await listen((req, res) => {
    assert.equal(req.headers.authorization, 'Bearer client-own-token');
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('event: ping\n\n');
    res.end();
  });

  // A leaked server would hang the whole `node --test` run.
  try {
    const accountManager = { getActiveAccount() { throw new Error('must not rotate Remote Control'); } };
    const listener = createProxyRequestListener({
      accountManager, upstream: `http://127.0.0.1:${upstreamPort}`,
    });

    const { status, text } = await requestThrough(listener, {
      path: '/v1/code/sessions/abc/worker/events/stream',
      headers: { authorization: 'Bearer client-own-token' },
    });

    assert.equal(status, 200);
    assert.match(text, /event: ping/);
  } finally {
    upstream.close();
  }
});

test('does not wait for the request to end before the response can start streaming', async () => {
  const { server: upstream, port: upstreamPort } = await listen((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('event: hello\n\n');
    // Deliberately never end() — mirrors a held-open worker/events/stream.
  });

  const accountManager = { getActiveAccount() { throw new Error('must not rotate'); } };
  const listener = createProxyRequestListener({
    accountManager, upstream: `http://127.0.0.1:${upstreamPort}`,
  });
  const { server: proxy, port } = await listen(listener);

  const controller = new AbortController();
  try {
    const res = await fetch(`http://127.0.0.1:${port}/v1/code/sessions/abc/worker/events/stream`, {
      signal: controller.signal,
    });
    const reader = res.body.getReader();
    const { value } = await reader.read();
    assert.match(Buffer.from(value).toString(), /event: hello/);
  } finally {
    controller.abort();
    proxy.close();
    upstream.close();
    upstream.closeAllConnections(); // the response is never ended
  }
});

test('relays a WebSocket Upgrade handshake and echoes bytes both ways', async () => {
  const { server: upstream, port: upstreamPort } = await listen(() => {});
  upstream.on('upgrade', (req, socket) => {
    assert.equal(req.headers.authorization, 'Bearer client-own-token');
    assert.equal(req.headers.upgrade, 'websocket');
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
    socket.on('data', (chunk) => socket.write(chunk)); // echo whatever the client sends
  });

  const proxy = http.createServer();
  proxy.on('upgrade', createUpgradeRelay({ upstream: `http://127.0.0.1:${upstreamPort}` }));
  proxy.listen(0);
  await once(proxy, 'listening');
  const port = (proxy.address() as { port: number }).port;

  const client = net.connect(port, '127.0.0.1');
  try {
    await once(client, 'connect');
    client.write(
      'GET /v1/session_ingress/ws/abc HTTP/1.1\r\n' +
      'Host: 127.0.0.1\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'authorization: Bearer client-own-token\r\n' +
      '\r\n',
    );

    const [handshake] = await once(client, 'data');
    assert.match(handshake.toString(), /101 Switching Protocols/);

    client.write('ping');
    const [echoed] = await once(client, 'data');
    assert.equal(echoed.toString(), 'ping');
  } finally {
    client.destroy();
    proxy.close();
    upstream.close();
    upstream.closeAllConnections();
  }
});

// The 101 detaches the socket from upstreamReq; an unhandled 'error' on it would kill the process.
test('an upstream socket that dies mid-relay tears down the pair instead of crashing the proxy', async () => {
  const { server: upstream, port: upstreamPort } = await listen(() => {});
  upstream.on('upgrade', (req, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
    // RST rather than FIN: what a dropped link looks like to the relay.
    setTimeout(() => (socket as Socket).resetAndDestroy(), 10);
  });

  const proxy = http.createServer();
  proxy.on('upgrade', createUpgradeRelay({ upstream: `http://127.0.0.1:${upstreamPort}` }));
  proxy.listen(0);
  await once(proxy, 'listening');
  const port = (proxy.address() as { port: number }).port;

  const client = net.connect(port, '127.0.0.1');
  client.on('error', () => {}); // the client end goes away too; that part is expected
  let writer;
  try {
    await once(client, 'connect');
    client.write(
      'GET /v1/session_ingress/ws/abc HTTP/1.1\r\n' +
      'Host: 127.0.0.1\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      '\r\n',
    );

    const [handshake] = await once(client, 'data');
    assert.match(handshake.toString(), /101 Switching Protocols/);

    // Not events.once: it would reject on the ECONNRESET the dying relay is expected to surface.
    const closed = new Promise<any>(resolve => client.once('close', resolve));
    writer = setInterval(() => client.write('ping'), 5);
    await closed;

    // Still alive and still serving — the proxy survived the upstream's death.
    assert.equal(proxy.listening, true);
  } finally {
    clearInterval(writer);
    client.destroy();
    proxy.close();
    upstream.close();
  }
});
