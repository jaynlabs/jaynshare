import { test } from 'node:test';
import assert from 'node:assert/strict';
import http2 from 'node:http2';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { generateCertChain } from '../src/x509.js';
import { createConnectHandler, resolveConnectPin, connectPinToken } from '../src/mitm.js';
import { AccountManager } from '../src/account-manager.js';
import { ACCOUNT_PREFERENCE_PREFIX, encodeAccountPreference } from '../src/account-preference.js';

// In MITM mode the pin arrives as the Basic username of Proxy-Authorization on the CONNECT.

function listen(server) { return new Promise(r => server.listen(0, '127.0.0.1', () => r(server.address().port))); }
const T = { timeout: 30000 };

function closeHard(server) {
  if (!server) return;
  server.closeAllConnections?.();
  try { server.close(); } catch { /* already closing */ }
}

const basic = (s) => 'Basic ' + Buffer.from(s).toString('base64');

// Rejects with the proxy's status line when the CONNECT is refused.
function connectThroughProxy(proxyPort, target, caCertPem, alpn, proxyAuth = null) {
  return new Promise((resolve, reject) => {
    const raw = net.connect(proxyPort, '127.0.0.1');
    raw.once('error', reject);
    raw.once('connect', () => raw.write(
      `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n` +
      (proxyAuth ? `Proxy-Authorization: ${proxyAuth}\r\n` : '') + '\r\n',
    ));
    let buf = Buffer.alloc(0);
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (!buf.includes('\r\n\r\n')) return;
      raw.removeListener('data', onData);
      const status = buf.toString('utf8').split('\r\n')[0];
      if (!/ 200 /.test(status)) { raw.destroy(); reject(new Error(status)); return; }
      const sock = tls.connect({ socket: raw, servername: 'localhost', ca: [caCertPem], ALPNProtocols: alpn }, () => resolve(sock));
      sock.once('error', reject);
    };
    raw.on('data', onData);
  });
}

function makeUpstream(handler) {
  return http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const out = handler(req, Buffer.concat(chunks).toString('utf8')) || {};
      res.writeHead(out.status || 200, out.headers || {});
      res.end(out.body ?? '');
    });
  });
}

function makeProxy(am, upPort, { leafCertPem, leafKeyPem }, config = {}) {
  const proxy = http.createServer();
  proxy.on('connect', createConnectHandler({
    config: { upstream: `http://127.0.0.1:${upPort}`, ...config },
    accountManager: am,
    ensureLeaf: async () => ({ key: leafKeyPem, cert: leafCertPem }),
    log: () => {},
  }));
  return proxy;
}

const oauthAccount = (name, token) =>
  ({ name, type: 'oauth', accessToken: token, refreshToken: 'r', expiresAt: Date.now() + 3600_000 });

async function postOverTunnel(tlsSock, headers = {}) {
  const client = http2.connect('https://localhost', { createConnection: () => tlsSock });
  const req = client.request({ ':method': 'POST', ':path': '/v1/messages', 'content-type': 'application/json', ...headers });
  let resp;
  req.on('response', (h) => { resp = h; });
  req.resume(); req.end('{"model":"x"}');
  await once(req, 'close');
  client.close();
  return resp;
}

// ── the resolver ──────────────────────────────────────────────────────────────

test('the Basic username selects the account', () => {
  const am = { accounts: [{ name: 'work' }, { name: 'personal' }] };
  assert.deepEqual(resolveConnectPin({ headers: { 'proxy-authorization': basic('work:k') } }, { accountManager: am, config: { proxy: { apiKey: 'k' } } }), { pin: 'work', error: null });
  // No key configured — username alone still pins.
  assert.deepEqual(resolveConnectPin({ headers: { 'proxy-authorization': basic('personal:') } }, { accountManager: am, config: {} }), { pin: 'personal', error: null });
  // A rotation index is not a pin form — array position moves under deletion.
  assert.deepEqual(resolveConnectPin({ headers: { 'proxy-authorization': basic('1:') } }, { accountManager: am, config: {} }), { pin: null, error: 'Unknown account pin "1"' });
});

// The documented `--proxy http://<key>@host:port` form puts the key in the username slot.
test('a username equal to the proxy key is auth, not a pin', () => {
  const am = { accounts: [{ name: 'work' }] };
  assert.deepEqual(resolveConnectPin({ headers: { 'proxy-authorization': basic('secret:') } }, { accountManager: am, config: { proxy: { apiKey: 'secret' } } }), { pin: null, error: null });
  // Even when an account is (unwisely) named after the key, auth wins.
  const clash = { accounts: [{ name: 'secret' }] };
  assert.deepEqual(resolveConnectPin({ headers: { 'proxy-authorization': basic('secret:') } }, { accountManager: clash, config: { proxy: { apiKey: 'secret' } } }), { pin: null, error: null });
});

test('an unknown username is an error rather than an ignored pin', () => {
  const am = { accounts: [{ name: 'work' }] };
  const { pin, error } = resolveConnectPin({ headers: { 'proxy-authorization': basic('typo:') } }, { accountManager: am, config: { proxy: { apiKey: 'secret' } } });
  assert.equal(pin, null);
  assert.match(error, /Unknown account pin "typo"/);
});

test('no header, or a Bearer key, yields no pin', () => {
  const am = { accounts: [{ name: 'work' }] };
  assert.deepEqual(resolveConnectPin({ headers: {} }, { accountManager: am, config: { proxy: { apiKey: 'secret' } } }), { pin: null, error: null });
  assert.deepEqual(resolveConnectPin({ headers: { 'proxy-authorization': 'Bearer secret' } }, { accountManager: am, config: { proxy: { apiKey: 'secret' } } }), { pin: null, error: null });
  assert.equal(connectPinToken({ headers: {} }), null);
});

test('a namespaced CONNECT username carries a soft preference, not a strict pin', () => {
  const am = { accounts: [{ name: 'friend@example.com', accountUuid: 'account-id', orgUuid: 'org-id' }] };
  assert.deepEqual(resolveConnectPin({
    headers: { 'proxy-authorization': basic(`${encodeAccountPreference('friend@example.com')}:secret`) },
  }, { accountManager: am, config: {} }), { pin: null, preference: 'account-id/org-id', error: null });
  assert.match(resolveConnectPin({
    headers: { 'proxy-authorization': basic(`${encodeAccountPreference('missing')}:secret`) },
  }, { accountManager: am, config: {} }).error, /Unknown account preference/);
  assert.match(resolveConnectPin({
    headers: { 'proxy-authorization': basic(`${ACCOUNT_PREFERENCE_PREFIX}!:secret`) },
  }, { accountManager: am, config: {} }).error, /malformed account preference/);
});

// ── end to end through a real tunnel ──────────────────────────────────────────

test('a pinned CONNECT serves every request in the tunnel from that account', T, async () => {
  const { caCertPem, leafCertPem, leafKeyPem } = generateCertChain('localhost');
  const upstream = makeUpstream((req) => ({
    status: 200,
    headers: { 'x-saw-auth': req.headers['authorization'] || 'none' },
  }));
  const upPort = await listen(upstream);

  // 'first' is what rotation would pick; the pin must override that.
  const am = new AccountManager([oauthAccount('first', 'TOKEN-A'), oauthAccount('second', 'TOKEN-B')], 0.98);
  const proxy = makeProxy(am, upPort, { caCertPem, leafCertPem, leafKeyPem });
  const proxyPort = await listen(proxy);

  const tlsSock = await connectThroughProxy(proxyPort, `127.0.0.1:${upPort}`, caCertPem, ['h2'], basic('second:'));
  try {
    const resp = await postOverTunnel(tlsSock);
    assert.equal(resp['x-saw-auth'], 'Bearer TOKEN-B');   // the pinned account, not the rotation pick
  } finally {
    tlsSock.destroy(); closeHard(proxy); closeHard(upstream);
  }
});

test('an unpinned CONNECT still rotates normally', T, async () => {
  const { caCertPem, leafCertPem, leafKeyPem } = generateCertChain('localhost');
  const upstream = makeUpstream((req) => ({
    status: 200,
    headers: { 'x-saw-auth': req.headers['authorization'] || 'none' },
  }));
  const upPort = await listen(upstream);

  const am = new AccountManager([oauthAccount('first', 'TOKEN-A'), oauthAccount('second', 'TOKEN-B')], 0.98);
  const proxy = makeProxy(am, upPort, { caCertPem, leafCertPem, leafKeyPem });
  const proxyPort = await listen(proxy);

  const tlsSock = await connectThroughProxy(proxyPort, `127.0.0.1:${upPort}`, caCertPem, ['h2']);
  try {
    const resp = await postOverTunnel(tlsSock);
    assert.equal(resp['x-saw-auth'], 'Bearer TOKEN-A');   // ordinary selection
  } finally {
    tlsSock.destroy(); closeHard(proxy); closeHard(upstream);
  }
});

test('a soft-preferred CONNECT tries the requested eligible account first', T, async () => {
  const { caCertPem, leafCertPem, leafKeyPem } = generateCertChain('localhost');
  const upstream = makeUpstream(req => ({
    status: 200,
    headers: { 'x-saw-auth': req.headers.authorization || 'none' },
  }));
  const upPort = await listen(upstream);
  const am = new AccountManager([oauthAccount('first', 'TOKEN-A'), oauthAccount('second', 'TOKEN-B')], 0.98);
  const proxy = makeProxy(am, upPort, { caCertPem, leafCertPem, leafKeyPem });
  const proxyPort = await listen(proxy);

  const username = encodeAccountPreference('second');
  const tlsSock = await connectThroughProxy(proxyPort, `127.0.0.1:${upPort}`, caCertPem, ['h2'], basic(`${username}:secret`));
  try {
    const resp = await postOverTunnel(tlsSock);
    assert.equal(resp['x-saw-auth'], 'Bearer TOKEN-B');
    assert.equal(am.currentIndex, 0, 'session preference must not mutate the global account');
  } finally {
    tlsSock.destroy(); closeHard(proxy); closeHard(upstream);
  }
});

test('a quota-rejected soft preference falls back through normal routing', T, async () => {
  const { caCertPem, leafCertPem, leafKeyPem } = generateCertChain('localhost');
  const seen = [];
  const upstream = makeUpstream(req => {
    seen.push(req.headers.authorization);
    if (req.headers.authorization === 'Bearer TOKEN-B') {
      return {
        status: 429,
        headers: {
          'retry-after': '1',
          'anthropic-ratelimit-unified-5h-status': 'rejected',
          'anthropic-ratelimit-unified-5h-utilization': '1',
        },
      };
    }
    return { status: 200, headers: { 'x-saw-auth': req.headers.authorization } };
  });
  const upPort = await listen(upstream);
  const am = new AccountManager([oauthAccount('first', 'TOKEN-A'), oauthAccount('second', 'TOKEN-B')], 0.98);
  const proxy = makeProxy(am, upPort, { caCertPem, leafCertPem, leafKeyPem });
  const proxyPort = await listen(proxy);

  const username = encodeAccountPreference('second');
  const tlsSock = await connectThroughProxy(proxyPort, `127.0.0.1:${upPort}`, caCertPem, ['h2'], basic(`${username}:secret`));
  try {
    const resp = await postOverTunnel(tlsSock, { 'x-claude-code-session-id': 'preferred-failover' });
    assert.equal(resp['x-saw-auth'], 'Bearer TOKEN-A');
    assert.deepEqual(seen, ['Bearer TOKEN-B', 'Bearer TOKEN-A']);
    assert.equal(am.sessionAssignment('local\0preferred-failover').account, 'first');
  } finally {
    tlsSock.destroy(); closeHard(proxy); closeHard(upstream);
  }
});

test('concurrent tunnels with different pins stay separate', T, async () => {
  const { caCertPem, leafCertPem, leafKeyPem } = generateCertChain('localhost');
  const upstream = makeUpstream((req) => ({
    status: 200,
    headers: { 'x-saw-auth': req.headers['authorization'] || 'none' },
  }));
  const upPort = await listen(upstream);

  const am = new AccountManager([oauthAccount('first', 'TOKEN-A'), oauthAccount('second', 'TOKEN-B')], 0.98);
  const proxy = makeProxy(am, upPort, { caCertPem, leafCertPem, leafKeyPem });
  const proxyPort = await listen(proxy);

  const a = await connectThroughProxy(proxyPort, `127.0.0.1:${upPort}`, caCertPem, ['h2'], basic('first:'));
  const b = await connectThroughProxy(proxyPort, `127.0.0.1:${upPort}`, caCertPem, ['h2'], basic('second:'));
  try {
    const [ra, rb] = await Promise.all([postOverTunnel(a), postOverTunnel(b)]);
    assert.equal(ra['x-saw-auth'], 'Bearer TOKEN-A');
    assert.equal(rb['x-saw-auth'], 'Bearer TOKEN-B');
  } finally {
    a.destroy(); b.destroy(); closeHard(proxy); closeHard(upstream);
  }
});

test('an unknown pin is refused at CONNECT', T, async () => {
  const { caCertPem, leafCertPem, leafKeyPem } = generateCertChain('localhost');
  const upstream = makeUpstream(() => ({ status: 200 }));
  const upPort = await listen(upstream);

  const am = new AccountManager([oauthAccount('first', 'TOKEN-A')], 0.98);
  const proxy = makeProxy(am, upPort, { caCertPem, leafCertPem, leafKeyPem });
  const proxyPort = await listen(proxy);

  try {
    await assert.rejects(
      connectThroughProxy(proxyPort, `127.0.0.1:${upPort}`, caCertPem, ['h2'], basic('nosuch:')),
      /407/,
    );
  } finally {
    closeHard(proxy); closeHard(upstream);
  }
});

// Clients send Proxy-Authorization on every CONNECT, third-party hosts included.
test('a pin on a blind-tunneled host is ignored, not refused', T, async () => {
  const { caCertPem, leafCertPem, leafKeyPem } = generateCertChain('localhost');
  const target = http.createServer((_req, res) => { res.writeHead(200); res.end('ok'); });
  const targetPort = await listen(target);
  const upstream = makeUpstream(() => ({ status: 200 }));
  const upPort = await listen(upstream);

  const am = new AccountManager([oauthAccount('first', 'TOKEN-A')], 0.98);
  const proxy = makeProxy(am, upPort, { caCertPem, leafCertPem, leafKeyPem });
  const proxyPort = await listen(proxy);

  // A pin that would 407 in rewrite mode; `localhost` differs from the 127.0.0.1 upstream by name, so it tunnels.
  const raw = net.connect(proxyPort, '127.0.0.1');
  try {
    await once(raw, 'connect');
    raw.write(`CONNECT localhost:${targetPort} HTTP/1.1\r\nHost: localhost:${targetPort}\r\nProxy-Authorization: ${basic('typo:')}\r\n\r\n`);
    const [chunk] = await once(raw, 'data');
    assert.match(chunk.toString('utf8').split('\r\n')[0], / 200 /);
  } finally {
    raw.destroy(); closeHard(proxy); closeHard(target); closeHard(upstream);
  }
});
