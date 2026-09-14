import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { AccountManager } from '../src/account-manager.js';
import { hashClientSecret } from '../src/client-auth.js';
import { createProxyServer, publicUsageSnapshot } from '../src/server.js';

const secret = 'jaynshare-client-test-secret';
const otherSecret = 'jaynshare-client-other-secret';
const config = {
  proxy: {
    clients: [
      { id: 'mac-one', name: 'Mac One', keyHash: hashClientSecret(secret) },
      { id: 'mac-two', name: 'Mac Two', keyHash: hashClientSecret(otherSecret) },
    ],
  },
  upstream: 'https://api.anthropic.com',
};

function remoteRequest(server, url, key = null) {
  const req = Readable.from([]);
  req.method = 'GET';
  req.url = url;
  req.headers = key ? { 'x-api-key': key } : {};
  req.socket = { remoteAddress: '203.0.113.9', localAddress: '100.64.0.1' };

  const res = {
    status: null,
    headers: null,
    chunks: '',
    writeHead(status, headers) { this.status = status; this.headers = headers; return this; },
    end(chunk) { if (chunk) this.chunks += chunk; this.done(); },
  };
  const complete = new Promise(resolve => { res.done = resolve; });
  server.emit('request', req, res);
  return complete.then(() => ({
    status: res.status,
    headers: res.headers,
    body: JSON.parse(res.chunks || '{}'),
  }));
}

test('an enrolled desktop client can read fleet usage but not operator status', async () => {
  const am = new AccountManager([
    { name: 'one@example.com', type: 'oauth', accessToken: 'token-one' },
    { name: 'two@example.com', type: 'oauth', accessToken: 'token-two' },
  ], 0.98);
  am.accounts[0].quota.unified5h = 0.25;
  am.accounts[1].quota.unified7d = 0.5;
  const server = createProxyServer(am, config, {
    getStatusExtra: () => ({
      routes: [{ name: 'private-policy' }],
      probe: { enabled: true, intervalSeconds: 300, accounts: [{ error: 'private probe detail' }] },
      server: { startedAt: '2026-09-09T10:00:00Z', uptimeSeconds: 42, upstream: 'private-upstream' },
    }),
  });
  try {
    const usage = await remoteRequest(server, '/jaynshare/usage', secret);
    assert.equal(usage.status, 200);
    assert.equal(usage.headers['Cache-Control'], 'no-store');
    assert.equal(usage.body.accounts.length, 2);
    assert.equal(usage.body.accounts[0].quota.unified5h, 0.25);
    assert.equal(usage.body.accounts[1].quota.unified7d, 0.5);
    assert.equal(usage.body.probe.intervalSeconds, 300);
    assert.equal(usage.body.server.uptimeSeconds, 42);
    assert.deepEqual(usage.body.capabilities, {
      sessionAccountPreference: true,
      sessionAssignment: true,
    });
    const encoded = JSON.stringify(usage.body);
    assert.doesNotMatch(encoded, /private probe detail|private-upstream|private-policy/);

    const operatorStatus = await remoteRequest(server, '/jaynshare/status', secret);
    assert.equal(operatorStatus.status, 403);
    assert.match(operatorStatus.body.error, /operator credential required/);
  } finally {
    server.close();
  }
});

test('fleet usage still requires a valid client credential', async () => {
  const am = new AccountManager([{ name: 'one', type: 'apikey', apiKey: 'key' }], 0.98);
  const server = createProxyServer(am, config);
  try {
    assert.equal((await remoteRequest(server, '/jaynshare/usage')).status, 401);
    assert.equal((await remoteRequest(server, '/jaynshare/usage', `${secret}-wrong`)).status, 401);
  } finally {
    server.close();
  }
});

test('public usage snapshots are allow-listed and tolerate missing optional fields', () => {
  assert.deepEqual(publicUsageSnapshot({ accounts: [] }), {
    capabilities: { sessionAccountPreference: true, sessionAssignment: true },
    currentAccount: null,
    switchThreshold: null,
    sessions: null,
    accounts: [],
    probe: {
      enabled: false,
      intervalSeconds: 0,
      running: false,
      lastRunFinishedAt: null,
      nextRunAt: null,
    },
    server: { startedAt: null, uptimeSeconds: null },
  });
});

test('account selection resolves stable identities and rejects indexes', async () => {
  const am = new AccountManager([
    { name: 'one@example.com', type: 'oauth', accessToken: 'one', accountUuid: 'acct-one', orgUuid: 'org-one' },
  ]);
  const server = createProxyServer(am, config);
  try {
    const resolved = await remoteRequest(server, '/jaynshare/account-selection?account=acct-one%2Forg-one', secret);
    assert.equal(resolved.status, 200);
    assert.equal(resolved.body.account, 'one@example.com');
    assert.equal(resolved.body.available, true);
    assert.equal((await remoteRequest(server, '/jaynshare/account-selection?account=0', secret)).status, 404);
    assert.equal((await remoteRequest(server, '/jaynshare/account-selection?account=missing', secret)).status, 404);
    assert.equal((await remoteRequest(server, '/jaynshare/account-selection?account=acct-one', 'wrong')).status, 401);
  } finally {
    server.close();
  }
});

test('session assignment is scoped to the authenticated client', async () => {
  const am = new AccountManager([
    { name: 'one', type: 'apikey', apiKey: 'one' },
    { name: 'two', type: 'apikey', apiKey: 'two' },
  ]);
  am.recordSession('mac-one\0shared-session', 1);
  am.recordSession('mac-two\0shared-session', 0);
  const server = createProxyServer(am, config);
  try {
    const one = await remoteRequest(server, '/jaynshare/usage?session_id=shared-session', secret);
    const two = await remoteRequest(server, '/jaynshare/usage?session_id=shared-session', otherSecret);
    assert.equal(one.body.session.account, 'two');
    assert.equal(two.body.session.account, 'one');
    assert.equal((await remoteRequest(server, '/jaynshare/usage?session_id=unknown', secret)).body.session, null);
    assert.equal((await remoteRequest(server, `/jaynshare/usage?session_id=${'x'.repeat(257)}`, secret)).status, 400);
  } finally {
    server.close();
  }
});
