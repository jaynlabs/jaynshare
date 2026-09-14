// MITM forward proxy: CONNECT to the upstream host is terminated with a
// locally-minted leaf; the test host is answered locally; anything else is blind-tunneled.

import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import { dirname, join } from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import http2 from 'node:http2';
import { getConfigPath } from './config.js';
import { generateCertChain } from './x509.js';
import { createProxyRequestListener, safeKeyEqual, isLoopbackAddr, relayUpgrade, resolveAccountPin } from './server.js';
import { resolvePrincipal } from './client-auth.js';
import { decodeAccountPreference } from './account-preference.js';

const CA_CERT = 'jaynshare-ca.pem';
const LEAF_CERT = 'jaynshare-leaf.pem';
const LEAF_KEY = 'jaynshare-leaf.key';

// Answered locally: verifies the proxy + CA end-to-end with no credentials.
export const TEST_HOST = 'www.example.org';

const certDir = () => dirname(getConfigPath());
const fpath = (n) => join(certDir(), n);

export function caCertPath() {
  return fpath(CA_CERT);
}

async function readIf(p) {
  try { return await readFile(p, 'utf8'); } catch { return null; }
}

async function atomicWrite(path, data, mode) {
  const tmp = `${path}.tmp${process.pid}`;
  await writeFile(tmp, data, { mode });
  await rename(tmp, path);
}

function leafCovers(caCertPem, leafCertPem, hosts) {
  try {
    const ca = new X509Certificate(caCertPem);
    const leaf = new X509Certificate(leafCertPem);
    if (!leaf.verify(ca.publicKey)) return false;
    const names = (leaf.subjectAltName || '').split(',').map((s) => s.trim());
    return hosts.every((h) => names.includes(`DNS:${h}`));
  } catch {
    return false;
  }
}

export async function ensureCerts(host) {
  const hosts = host === TEST_HOST ? [TEST_HOST] : [host, TEST_HOST];
  const [caCertPem, leafCertPem, leafKeyPem] = await Promise.all([
    readIf(fpath(CA_CERT)), readIf(fpath(LEAF_CERT)), readIf(fpath(LEAF_KEY)),
  ]);

  if (caCertPem && leafCertPem && leafKeyPem && leafCovers(caCertPem, leafCertPem, hosts)) {
    return { caPath: fpath(CA_CERT), caCertPem, leafCertPem, leafKeyPem };
  }

  const chain = generateCertChain(hosts); // the CA key is never persisted
  await mkdir(certDir(), { recursive: true });
  await atomicWrite(fpath(CA_CERT), chain.caCertPem, 0o644);
  await atomicWrite(fpath(LEAF_CERT), chain.leafCertPem, 0o644);
  await atomicWrite(fpath(LEAF_KEY), chain.leafKeyPem, 0o600);
  return {
    caPath: fpath(CA_CERT),
    caCertPem: chain.caCertPem,
    leafCertPem: chain.leafCertPem,
    leafKeyPem: chain.leafKeyPem,
  };
}

function upstreamHostOf(config) {
  try { return new URL(config?.upstream || 'https://api.anthropic.com').hostname; }
  catch { return 'api.anthropic.com'; }
}

export function hostMode(host, config) {
  if (host === TEST_HOST) return 'test';
  if (host === upstreamHostOf(config)) return 'rewrite';
  return 'tunnel';
}

export function createConnectHandler({ config, accountManager, ensureLeaf, logDir = null, hooks = {}, log = () => {}, sx = null, egress = null }) {
  const upstream = config.upstream || 'https://api.anthropic.com';
  const holdMs = (config.holdSeconds || 0) * 1000;

  // One terminating h2/h1 server per (client, pin, preference), minted lazily: a
  // listener bound to the account is how a CONNECT pin reaches the requests inside.
  const serverPromises = new Map();
  const getServer = (pin = '', principal = null, preference = '') => {
    const serverKey = `${principal?.clientId || 'local'}\0${pin}\0${preference}`;
    let p = serverPromises.get(serverKey);
    if (p) return p;
    p = (async () => {
    const { key, cert } = await ensureLeaf();
    const srv = http2.createSecureServer({ key, cert, allowHTTP1: true });
    srv.on('request', createProxyRequestListener({
      accountManager, upstream, logDir, hooks, sx, holdMs, config,
      forcedPin: pin || null,
      preferredAccount: preference || null,
      forcedPrincipal: principal,
      egress,
    }));
    srv.on('upgrade', (req, socket, head) => relayUpgrade(req, socket, head, upstream, sx));
    srv.on('sessionError', (e) => log(`[Jaynshare] MITM session error: ${e.message}`));
    srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch { /* already gone */ } });
    return srv;
    })().catch((err) => {
      serverPromises.delete(serverKey); // a cached rejection would dead-end the MITM path
      throw err;
    });
    serverPromises.set(serverKey, p);
    return p;
  };

  return (req, clientSocket, head) => {
    clientSocket.on('error', () => {});

    // Same gate as the HTTP path; an unauthenticated remote client would otherwise
    // get an account token injected, or an open relay.
    const principal = connectPrincipal(req, clientSocket, config);
    if (!principal) {
      try {
        clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="jaynshare"\r\nConnection: close\r\n\r\n');
      } catch { /* client already gone */ }
      clientSocket.destroy();
      return;
    }

    const [host, portStr] = (req.url || '').split(':');
    const port = parseInt(portStr, 10) || 443;
    const mode = hostMode(host, config);

    if (mode === 'tunnel') {
      let established = false, closed = false;
      // Tears down both sockets once; before the tunnel is live the client is still owed a status line.
      const teardown = (statusLine) => {
        if (closed) return;
        closed = true;
        if (!established && statusLine) {
          try { clientSocket.write(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\n\r\n`); } catch { /* client already gone */ }
        }
        up.destroy(); clientSocket.destroy();
      };
      const up = net.connect(port, host, () => {
        established = true;
        reply200Raw(clientSocket);
        if (head && head.length) up.write(head);
        up.pipe(clientSocket); clientSocket.pipe(up);
      });
      up.on('error', (err) => {
        if (!established) log(`[Jaynshare] tunnel ${host}:${port} failed: ${err.message}`);
        teardown('502 Bad Gateway');
      });
      up.on('close', () => teardown('502 Bad Gateway')); // a FIN before the tunnel is live is a failed dial
      clientSocket.on('close', () => teardown());
      up.setTimeout(30_000, () => teardown('504 Gateway Timeout'));
      return;
    }

    if (mode === 'test') {
      ensureLeaf().then(({ key, cert }) => {
        reply200Raw(clientSocket);
        serveTest(termClaude(clientSocket, head, key, cert, ['http/1.1']));
      }).catch((err) => { log(`[Jaynshare] MITM ${host}: ${err.message}`); reply502Raw(clientSocket); clientSocket.destroy(); });
      return;
    }

    // rewrite. Pins are resolved only here: clients send Proxy-Authorization on
    // every CONNECT, and a pin is meaningless on a blind tunnel.
    const { pin, preference, error } = resolveConnectPin(req, accountManager, config, principal);
    if (error) {
      log(`[Jaynshare] CONNECT ${host}: ${error}`);
      try {
        clientSocket.write(`HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="jaynshare"\r\nConnection: close\r\n\r\n`);
      } catch { /* client already gone */ }
      clientSocket.destroy();
      return;
    }

    getServer(pin || '', principal, preference || '').then((srv) => {
      reply200Raw(clientSocket);
      if (head && head.length) clientSocket.unshift(head);
      srv.emit('connection', clientSocket);
    }).catch((err) => { log(`[Jaynshare] MITM ${host}: ${err.message}`); reply502Raw(clientSocket); clientSocket.destroy(); });
  };
}

// The Basic username of a CONNECT: the only pin channel an HTTPS_PROXY URL can express.
export function connectPinToken(req) {
  const header = (req?.headers?.['proxy-authorization'] || '').trim();
  if (!header.toLowerCase().startsWith('basic ')) return null;
  const dec = Buffer.from(header.slice('basic '.length).trim(), 'base64').toString('utf8');
  const colon = dec.indexOf(':');
  return (colon >= 0 ? dec.slice(0, colon) : dec) || null;
}

// The proxy key wins over an account of the same name. An unknown username is an
// error, never a silently ignored pin.
export function resolveConnectPin(req, accountManager, configOrKey, principal = null) {
  const token = connectPinToken(req);
  if (!token) return { pin: null, error: null };
  const legacyKey = typeof configOrKey === 'string' ? configOrKey : configOrKey?.proxy?.apiKey;
  if (legacyKey && safeKeyEqual(token, legacyKey)) return { pin: null, error: null };
  if (principal && token === principal.clientId) return { pin: null, error: null };
  let preference;
  try { preference = decodeAccountPreference(token); }
  catch (err) { return { pin: null, preference: null, error: err.message }; }
  if (preference != null) {
    const index = resolveAccountPin(accountManager, preference);
    if (index == null) {
      return { pin: null, preference: null, error: `Unknown account preference "${preference}"` };
    }
    const account = accountManager.accounts[index];
    const canonical = account.accountUuid && account.orgUuid
      ? `${account.accountUuid}/${account.orgUuid}`
      : account.accountUuid || account.name;
    return { pin: null, preference: canonical, error: null };
  }
  if (resolveAccountPin(accountManager, token) == null) {
    return { pin: null, error: `Unknown account pin "${token}"` };
  }
  return { pin: token, error: null };
}

// Bearer <key>, or Basic with the key as username or password (`--proxy http://<key>@host:port`).
export function connectAuthorized(req, socket, proxyApiKey) {
  if (typeof proxyApiKey === 'object') return !!connectPrincipal(req, socket, proxyApiKey);
  if (!proxyApiKey) return true;
  if (isLoopbackAddr(socket?.remoteAddress)) return true;
  const m = /^\s*(basic|bearer)\s+(.+?)\s*$/i.exec(req?.headers?.['proxy-authorization'] || '');
  if (!m) return false;
  let presented = m[2];
  if (m[1].toLowerCase() === 'basic') {
    const dec = Buffer.from(m[2], 'base64').toString('utf8');
    const i = dec.indexOf(':');
    const user = i >= 0 ? dec.slice(0, i) : dec;
    const pass = i >= 0 ? dec.slice(i + 1) : '';
    presented = pass || user;
  }
  return safeKeyEqual(presented, proxyApiKey);
}

export function connectPrincipal(req, socket, config) {
  const local = isLoopbackAddr(socket?.remoteAddress);
  if (local) return resolvePrincipal(config, null, { local: true });
  const m = /^\s*(basic|bearer)\s+(.+?)\s*$/i.exec(req?.headers?.['proxy-authorization'] || '');
  if (!m) return resolvePrincipal(config, null);
  let presented = m[2];
  if (m[1].toLowerCase() === 'basic') {
    const decoded = Buffer.from(m[2], 'base64').toString('utf8');
    const colon = decoded.indexOf(':');
    const user = colon >= 0 ? decoded.slice(0, colon) : decoded;
    const pass = colon >= 0 ? decoded.slice(colon + 1) : '';
    presented = pass || user;
  }
  return resolvePrincipal(config, presented);
}

function reply200Raw(sock) { sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); }
function reply502Raw(sock) { try { sock.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); } catch { /* client already gone */ } }

function termClaude(clientSocket, head, key, cert, alpn) {
  if (head && head.length) clientSocket.unshift(head);
  const t = new tls.TLSSocket(clientSocket, { isServer: true, key, cert, ALPNProtocols: alpn });
  t.on('error', () => t.destroy());
  return t;
}

function serveTest(tlsSock) {
  let buf = Buffer.alloc(0);
  const onData = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const idx = buf.indexOf('\r\n\r\n');
    if (idx < 0) { if (buf.length > 65536) tlsSock.destroy(); return; }
    tlsSock.removeListener('data', onData);
    const reqLine = buf.subarray(0, buf.indexOf('\r\n')).toString('latin1');
    const path = reqLine.split(' ')[1] || '/';
    const body = JSON.stringify({ jaynshare: 'mitm-proxy-ok', host: TEST_HOST, path });
    tlsSock.end(
      `HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`,
    );
  };
  tlsSock.on('data', onData);
  tlsSock.on('error', () => tlsSock.destroy());
}
