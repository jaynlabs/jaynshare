import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { IncomingMessage } from 'node:http';
import type { Config } from '../src/types.ts';
import { AccountManager } from '../src/account-manager.ts';
import { createProxyServer, isSameOriginControlRequest } from '../src/server.ts';

// Loopback skips the key, so a web page could POST here cross-origin without preflight.

function listen(server) {
  return new Promise<any>(resolve => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port)));
}

const CONFIG = { proxy: { apiKey: 'tc-test' }, upstream: 'https://api.anthropic.com' } as Config;
const ACCTS = [
  { name: 'alice@example.com', type: 'apikey', apiKey: 'k1' },
  { name: 'bob@example.com', type: 'apikey', apiKey: 'k2' },
];

async function withServer(fn, hooks = {}) {
  const am = new AccountManager(ACCTS, 0.98);
  const proxy = createProxyServer(am, CONFIG, { hooks: hooks });
  const port = await listen(proxy);
  try {
    await fn(am, port);
  } finally {
    proxy.close();
  }
}

const switchTo = (port, account, headers = {}) =>
  fetch(`http://127.0.0.1:${port}/jaynshare/switch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify({ account }),
  });

test('a page cannot switch the account cross-origin', async () => {
  await withServer(async (am, port) => {
    assert.equal(am.currentIndex, 0);

    const res = await switchTo(port, 'bob@example.com', { Origin: 'https://evil.example' });

    assert.equal(res.status, 403);
    assert.match((await res.json() as { error: string }).error, /cross-origin/);
    assert.equal(am.currentIndex, 0, 'a refused request must not have switched the account');
  });
});

test('Sec-Fetch-Site is honoured when the browser sends it', async () => {
  await withServer(async (am, port) => {
    const res = await switchTo(port, 'bob@example.com', { 'Sec-Fetch-Site': 'cross-site' });
    assert.equal(res.status, 403);
    assert.equal(am.currentIndex, 0);
  });
});

test('reload is refused cross-origin as well', async () => {
  let reloads = 0;
  await withServer(async (_am, port) => {
    const res = await fetch(`http://127.0.0.1:${port}/jaynshare/reload`, {
      method: 'POST',
      headers: { Origin: 'https://evil.example' },
    });
    assert.equal(res.status, 403);
    assert.equal(reloads, 0, 'a refused reload must not have run');
  }, { reload: async () => { reloads++; return 0; } });
});

test('a request with no browser headers still works', async () => {
  await withServer(async (am, port) => {
    const res = await switchTo(port, 'bob@example.com');
    assert.equal(res.status, 200);
    assert.equal((await res.json() as { ok: boolean }).ok, true);
    assert.equal(am.currentIndex, 1);
  });
});

test('a same-origin browser request is allowed through', async () => {
  await withServer(async (am, port) => {
    const res = await switchTo(port, 'bob@example.com', {
      'Sec-Fetch-Site': 'same-origin',
      Origin: `http://127.0.0.1:${port}`,
    });
    assert.equal(res.status, 200);
    assert.equal(am.currentIndex, 1);
  });
});

// The same-origin policy already hides a read's answer from the page.
test('the guard applies to mutations, not to reads', async () => {
  await withServer(async (_am, port) => {
    const res = await fetch(`http://127.0.0.1:${port}/jaynshare/status`, {
      headers: { Origin: 'https://evil.example' },
    });
    assert.equal(res.status, 200);
  });
});

test('isSameOriginControlRequest: Sec-Fetch-Site wins, Origin is the fallback', () => {
  const req = (headers) => ({ headers }) as IncomingMessage;
  assert.equal(isSameOriginControlRequest(req({ 'sec-fetch-site': 'same-origin' })), true);
  assert.equal(isSameOriginControlRequest(req({ 'sec-fetch-site': 'none' })), true);       // typed in the URL bar
  assert.equal(isSameOriginControlRequest(req({ 'sec-fetch-site': 'cross-site' })), false);
  assert.equal(isSameOriginControlRequest(req({ 'sec-fetch-site': 'same-site' })), false);
  // Sec-Fetch-Site wins over a stale Origin.
  assert.equal(isSameOriginControlRequest(req({ 'sec-fetch-site': 'same-origin', origin: 'https://evil.example' })), true);
  assert.equal(isSameOriginControlRequest(req({ origin: 'https://evil.example' })), false);
  assert.equal(isSameOriginControlRequest(req({})), true); // curl and the CLI
});
