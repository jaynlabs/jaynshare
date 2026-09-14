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
import { createProxyRequestListener, createUpgradeRelay, safeKeyEqual, isLoopbackAddr, resolveAccountPin } from './server.js';
import { resolvePrincipal } from './client-auth.js';
import { decodeAccountPreference } from './account-preference.js';

const CA_CERT = 'jaynshare-ca.pem';
const LEAF_CERT = 'jaynshare-leaf.pem';
const LEAF_KEY = 'jaynshare-leaf.key';

// Answered locally: verifies the proxy + CA end-to-end with no credentials.
export const TEST_HOST = 'www.example.org';

const certDir = () => dirname(getConfigPath());
const certFilePath = (filename) => join(certDir(), filename);

export function caCertPath() {
  return certFilePath(CA_CERT);
}

async function readIfPresent(filePath) {
  try { return await readFile(filePath, 'utf8'); } catch { return null; }
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
    readIfPresent(certFilePath(CA_CERT)), readIfPresent(certFilePath(LEAF_CERT)), readIfPresent(certFilePath(LEAF_KEY)),
  ]);

  if (caCertPem && leafCertPem && leafKeyPem && leafCovers(caCertPem, leafCertPem, hosts)) {
    return { caPath: certFilePath(CA_CERT), caCertPem, leafCertPem, leafKeyPem };
  }

  const chain = generateCertChain(hosts); // the CA key is never persisted
  await mkdir(certDir(), { recursive: true });
  await atomicWrite(certFilePath(CA_CERT), chain.caCertPem, 0o644);
  await atomicWrite(certFilePath(LEAF_CERT), chain.leafCertPem, 0o644);
  await atomicWrite(certFilePath(LEAF_KEY), chain.leafKeyPem, 0o600);
  return {
    caPath: certFilePath(CA_CERT),
    caCertPem: chain.caCertPem,
    leafCertPem: chain.leafCertPem,
    leafKeyPem: chain.leafKeyPem,
  };
}

function upstreamHostOf(config) {
  try { return new URL(config?.upstream || 'https://api.anthropic.com').hostname; }
  catch { return 'api.anthropic.com'; }
}

function hostMode(host, config) {
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
  const startTerminatingServer = async ({ pin, preference, principal }) => {
    const { key, cert } = await ensureLeaf();
    const srv = http2.createSecureServer({ key, cert, allowHTTP1: true });
    srv.on('request', createProxyRequestListener({
      accountManager, upstream, logDir, hooks, sx, holdMs, config,
      forcedPin: pin || null,
      preferredAccount: preference || null,
      forcedPrincipal: principal,
      egress,
    }));
    srv.on('upgrade', createUpgradeRelay({ upstream, sx }));
    srv.on('sessionError', (e) => log(`[Jaynshare] MITM session error: ${e.message}`));
    srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch { /* already gone */ } });
    return srv;
  };
  const getServer = ({ pin = null, preference = null, principal = null }) => {
    const serverKey = `${principal?.clientId || 'local'}\0${pin || ''}\0${preference || ''}`;
    const running = serverPromises.get(serverKey);
    if (running) return running;
    const starting = startTerminatingServer({ pin, preference, principal }).catch((err) => {
      serverPromises.delete(serverKey); // a cached rejection would dead-end the MITM path
      throw err;
    });
    serverPromises.set(serverKey, starting);
    return starting;
  };

  return (req, clientSocket, head) => {
    clientSocket.on('error', () => {});

    // An unauthenticated remote client would otherwise get an account token
    // injected, or an open relay.
    const principal = connectPrincipal(req, clientSocket, config);
    if (!principal) { refuseConnect(clientSocket); return; }

    const [host, portStr] = (req.url || '').split(':');
    const port = parseInt(portStr, 10) || 443;

    switch (hostMode(host, config)) {
      case 'tunnel':
        blindTunnel({ clientSocket, head }, { host, port }, log);
        return;
      case 'test':
        serveTestHost({ clientSocket, head }, ensureLeaf, log);
        return;
      default:
        // Pins are resolved only here: clients send Proxy-Authorization on every
        // CONNECT, and a pin is meaningless on a blind tunnel.
        rewriteTunnel({ req, clientSocket, head }, { host, accountManager, config, principal, getServer }, log);
    }
  };
}

function refuseConnect(clientSocket) {
  try {
    clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="jaynshare"\r\nConnection: close\r\n\r\n');
  } catch { /* client already gone */ }
  clientSocket.destroy();
}

/** Bytes in both directions, no TLS termination and no account logic. */
function blindTunnel({ clientSocket, head }, { host, port }, log) {
  let established = false, closed = false;
  // Tears down both sockets once; before the tunnel is live the client is still owed a status line.
  const teardown = (statusLine) => {
    if (closed) return;
    closed = true;
    if (!established && statusLine) {
      try { clientSocket.write(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\n\r\n`); } catch { /* client already gone */ }
    }
    upstreamSocket.destroy(); clientSocket.destroy();
  };
  const upstreamSocket = net.connect(port, host, () => {
    established = true;
    reply200Raw(clientSocket);
    if (head && head.length) upstreamSocket.write(head);
    upstreamSocket.pipe(clientSocket); clientSocket.pipe(upstreamSocket);
  });
  upstreamSocket.on('error', (err) => {
    if (!established) log(`[Jaynshare] tunnel ${host}:${port} failed: ${err.message}`);
    teardown('502 Bad Gateway');
  });
  upstreamSocket.on('close', () => teardown('502 Bad Gateway')); // a FIN before the tunnel is live is a failed dial
  clientSocket.on('close', () => teardown());
  upstreamSocket.setTimeout(30_000, () => teardown('504 Gateway Timeout'));
}

function serveTestHost({ clientSocket, head }, ensureLeaf, log) {
  ensureLeaf().then((leaf) => {
    reply200Raw(clientSocket);
    serveTest(terminateTls({ clientSocket, head }, leaf));
  }).catch((err) => { log(`[Jaynshare] MITM ${TEST_HOST}: ${err.message}`); reply502Raw(clientSocket); clientSocket.destroy(); });
}

/** Hands the socket to a terminating h2/h1 server bound to this client's pin. */
function rewriteTunnel({ req, clientSocket, head }, { host, accountManager, config, principal, getServer }, log) {
  const { pin, preference, error } = resolveConnectPin(req, { accountManager, config, principal });
  if (error) {
    log(`[Jaynshare] CONNECT ${host}: ${error}`);
    refuseConnect(clientSocket);
    return;
  }

  getServer({ pin, preference, principal }).then((srv) => {
    reply200Raw(clientSocket);
    if (head && head.length) clientSocket.unshift(head);
    srv.emit('connection', clientSocket);
  }).catch((err) => { log(`[Jaynshare] MITM ${host}: ${err.message}`); reply502Raw(clientSocket); clientSocket.destroy(); });
}

// The Basic username of a CONNECT: the only pin channel an HTTPS_PROXY URL can express.
export function connectPinToken(req) {
  const header = (req?.headers?.['proxy-authorization'] || '').trim();
  if (!header.toLowerCase().startsWith('basic ')) return null;
  const decoded = Buffer.from(header.slice('basic '.length).trim(), 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  return (colon >= 0 ? decoded.slice(0, colon) : decoded) || null;
}

// The proxy key wins over an account of the same name. An unknown username is an
// error, never a silently ignored pin.
export function resolveConnectPin(req, { accountManager, config, principal = null }) {
  const token = connectPinToken(req);
  if (!token) return { pin: null, error: null };
  const legacyKey = config?.proxy?.apiKey;
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

// The credential a CONNECT presents: Bearer <key>, or Basic with the key as the
// password, else the username (`--proxy http://<key>@host:port`).
function presentedCredential(req) {
  const match = /^\s*(basic|bearer)\s+(.+?)\s*$/i.exec(req?.headers?.['proxy-authorization'] || '');
  if (!match) return null;
  if (match[1].toLowerCase() !== 'basic') return match[2];
  const decoded = Buffer.from(match[2], 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  const user = colon >= 0 ? decoded.slice(0, colon) : decoded;
  const pass = colon >= 0 ? decoded.slice(colon + 1) : '';
  return pass || user;
}

/** The same gate as the HTTP path; loopback is exempt, as it is there. */
export function connectPrincipal(req, socket, config) {
  if (isLoopbackAddr(socket?.remoteAddress)) return resolvePrincipal(config, null, { local: true });
  return resolvePrincipal(config, presentedCredential(req));
}

function reply200Raw(sock) { sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); }
function reply502Raw(sock) { try { sock.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); } catch { /* client already gone */ } }

function terminateTls({ clientSocket, head }, { key, cert }) {
  if (head && head.length) clientSocket.unshift(head);
  const tlsSocket = new tls.TLSSocket(clientSocket, { isServer: true, key, cert, ALPNProtocols: ['http/1.1'] });
  tlsSocket.on('error', () => tlsSocket.destroy());
  return tlsSocket;
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
