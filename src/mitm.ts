// MITM forward proxy: CONNECT to the upstream host is terminated with a
// locally-minted leaf; the test host is answered locally; anything else is blind-tunneled.

import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import { dirname, join } from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import http2 from 'node:http2';
import { getConfigPath } from './config.ts';
import { generateCertChain } from './x509.ts';
import { createProxyRequestListener, createUpgradeRelay, safeKeyEqual, isLoopbackAddr, resolveAccountPin } from './server.ts';
import { resolvePrincipal } from './client-auth.ts';
import { decodeAccountPreference } from './account-preference.ts';
import type { Config, Dict, Principal, ServerHooks } from './types.ts';

const CA_CERT = 'jaynshare-ca.pem';
const LEAF_CERT = 'jaynshare-leaf.pem';
const LEAF_KEY = 'jaynshare-leaf.key';

// Answered locally: verifies the proxy + CA end-to-end with no credentials.
export const TEST_HOST = 'www.example.org';

const certDir = (): string => dirname(getConfigPath());
const certFilePath = (filename: string): string => join(certDir(), filename);

export function caCertPath(): string {
  return certFilePath(CA_CERT);
}

async function readIfPresent(filePath: string): Promise<string | null> {
  try { return await readFile(filePath, 'utf8'); } catch { return null; }
}

async function atomicWrite(path: string, data: string, mode: number): Promise<void> {
  const tmp = `${path}.tmp${process.pid}`;
  await writeFile(tmp, data, { mode });
  await rename(tmp, path);
}

function leafCovers(caCertPem: string, leafCertPem: string, hosts: string[]): boolean {
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

export interface EnsureCertsResult {
  caPath: string;
  caCertPem: string;
  leafCertPem: string;
  leafKeyPem: string;
}

export async function ensureCerts(host: string): Promise<EnsureCertsResult> {
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

function upstreamHostOf(config: Config | null | undefined): string {
  try { return new URL(config?.upstream || 'https://api.anthropic.com').hostname; }
  catch { return 'api.anthropic.com'; }
}

function hostMode(host: string, config: Config | null | undefined): 'test' | 'rewrite' | 'tunnel' {
  if (host === TEST_HOST) return 'test';
  if (host === upstreamHostOf(config)) return 'rewrite';
  return 'tunnel';
}

export interface ConnectHandlerOptions {
  config: Config;
  accountManager: any;
  ensureLeaf: () => Promise<{ key: string; cert: string }>;
  logDir?: string | null;
  hooks?: ServerHooks;
  log?: (msg: string) => void;
  sx?: any | null;
  egress?: any | null;
}

export function createConnectHandler({ config, accountManager, ensureLeaf, logDir = null, hooks = {}, log = () => {}, sx = null, egress = null }: ConnectHandlerOptions) {
  const upstream = config.upstream || 'https://api.anthropic.com';
  const holdMs = (config.holdSeconds || 0) * 1000;

  // One terminating h2/h1 server per (client, pin, preference), minted lazily: a
  // listener bound to the account is how a CONNECT pin reaches the requests inside.
  const serverPromises = new Map<string, Promise<http2.Http2SecureServer>>();
  const startTerminatingServer = async ({ pin, preference, principal }: { pin: string | null; preference: string | null; principal: Principal | null }) => {
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
    srv.on('sessionError', (e: Error) => log(`[Jaynshare] MITM session error: ${e.message}`));
    srv.on('clientError', (e: Error, sock) => { try { sock.destroy(); } catch { /* already gone */ } });
    return srv;
  };
  const getServer = ({ pin = null, preference = null, principal = null }: { pin?: string | null; preference?: string | null; principal?: Principal | null }) => {
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

  return (req: http2.Http2ServerRequest | Dict, clientSocket: net.Socket, head: Buffer) => {
    clientSocket.on('error', () => {});

    // An unauthenticated remote client would otherwise get an account token
    // injected, or an open relay.
    const principal = connectPrincipal(req as any, clientSocket, config);
    if (!principal) { refuseConnect(clientSocket); return; }

    const [host = '', portStr = ''] = ((req as Dict).url || '').split(':');
    const port = parseInt(portStr, 10) || 443;

    switch (hostMode(host as string, config)) {
      case 'tunnel':
        blindTunnel({ clientSocket, head }, { host: host as string, port }, log);
        return;
      case 'test':
        serveTestHost({ clientSocket, head }, ensureLeaf, log);
        return;
      default:
        // Pins are resolved only here: clients send Proxy-Authorization on every
        // CONNECT, and a pin is meaningless on a blind tunnel.
        rewriteTunnel({ req: req as any, clientSocket, head }, { host: host as string, accountManager, config, principal, getServer }, log);
    }
  };
}

function refuseConnect(clientSocket: net.Socket): void {
  try {
    clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="jaynshare"\r\nConnection: close\r\n\r\n');
  } catch { /* client already gone */ }
  clientSocket.destroy();
}

/** Bytes in both directions, no TLS termination and no account logic. */
function blindTunnel({ clientSocket, head }: { clientSocket: net.Socket; head: Buffer }, { host, port }: { host: string; port: number }, log: (msg: string) => void): void {
  let established = false, closed = false;
  const upstreamSocket = net.connect(port, host, () => {
    established = true;
    reply200Raw(clientSocket);
    if (head && head.length) upstreamSocket.write(head);
    upstreamSocket.pipe(clientSocket); clientSocket.pipe(upstreamSocket);
  });
  // Tears down both sockets once; before the tunnel is live the client is still owed a status line.
  const teardown = (statusLine?: string) => {
    if (closed) return;
    closed = true;
    if (!established && statusLine) {
      try { clientSocket.write(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\n\r\n`); } catch { /* client already gone */ }
    }
    upstreamSocket.destroy(); clientSocket.destroy();
  };
  upstreamSocket.on('error', (err: Error) => {
    if (!established) log(`[Jaynshare] tunnel ${host}:${port} failed: ${err.message}`);
    teardown('502 Bad Gateway');
  });
  upstreamSocket.on('close', () => teardown('502 Bad Gateway')); // a FIN before the tunnel is live is a failed dial
  clientSocket.on('close', () => teardown());
  upstreamSocket.setTimeout(30_000, () => teardown('504 Gateway Timeout'));
}

function serveTestHost({ clientSocket, head }: { clientSocket: net.Socket; head: Buffer }, ensureLeaf: () => Promise<{ key: string; cert: string }>, log: (msg: string) => void): void {
  ensureLeaf().then((leaf) => {
    reply200Raw(clientSocket);
    serveTest(terminateTls({ clientSocket, head }, leaf));
  }).catch((err) => { log(`[Jaynshare] MITM ${TEST_HOST}: ${err.message}`); reply502Raw(clientSocket); clientSocket.destroy(); });
}

/** Hands the socket to a terminating h2/h1 server bound to this client's pin. */
function rewriteTunnel({ req, clientSocket, head }: { req: Dict; clientSocket: net.Socket; head: Buffer },
  { host, accountManager, config, principal, getServer }: {
    host: string; accountManager: any; config: Config; principal: Principal | null;
    getServer: (opts: { pin?: string | null; preference?: string | null; principal?: Principal | null }) => Promise<http2.Http2SecureServer>;
  }, log: (msg: string) => void): void {
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
export function connectPinToken(req: Dict): string | null {
  const header = String(req?.headers?.['proxy-authorization'] || '').trim();
  if (!header.toLowerCase().startsWith('basic ')) return null;
  const decoded = Buffer.from(header.slice('basic '.length).trim(), 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  return (colon >= 0 ? decoded.slice(0, colon) : decoded) || null;
}

// The proxy key wins over an account of the same name. An unknown username is an
// error, never a silently ignored pin.
export function resolveConnectPin(req: Dict, { accountManager, config, principal = null }:
  { accountManager: any; config: Partial<Config>; principal?: Principal | null }): { pin: string | null; preference?: string | null; error: string | null } {
  const token = connectPinToken(req);
  if (!token) return { pin: null, error: null };
  const legacyKey = config?.proxy?.apiKey;
  if (legacyKey && safeKeyEqual(token, legacyKey)) return { pin: null, error: null };
  if (principal && token === principal.clientId) return { pin: null, error: null };
  let preference: string | null;
  try { preference = decodeAccountPreference(token); }
  catch (err) { return { pin: null, preference: null, error: (err as Error).message }; }
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
function presentedCredential(req: Dict): string | null {
  const match = /^\s*(basic|bearer)\s+(.+?)\s*$/i.exec(String(req?.headers?.['proxy-authorization'] || ''));
  if (!match) return null;
  if (match[1]!.toLowerCase() !== 'basic') return match[2]!;
  const decoded = Buffer.from(match[2]!, 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  const user = colon >= 0 ? decoded.slice(0, colon) : decoded;
  const pass = colon >= 0 ? decoded.slice(colon + 1) : '';
  return pass || user;
}

/** The same gate as the HTTP path; loopback is exempt, as it is there. */
export function connectPrincipal(req: Dict, socket: net.Socket, config: Config): Principal | null {
  if (isLoopbackAddr(socket?.remoteAddress)) return resolvePrincipal(config, undefined, { local: true });
  return resolvePrincipal(config, presentedCredential(req) || undefined);
}

function reply200Raw(sock: net.Socket): void { sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); }
function reply502Raw(sock: net.Socket): void { try { sock.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); } catch { /* client already gone */ } }

function terminateTls({ clientSocket, head }: { clientSocket: net.Socket; head: Buffer }, { key, cert }: { key: string; cert: string }): tls.TLSSocket {
  if (head && head.length) clientSocket.unshift(head);
  const tlsSocket = new tls.TLSSocket(clientSocket, { isServer: true, key, cert, ALPNProtocols: ['http/1.1'] });
  tlsSocket.on('error', () => tlsSocket.destroy());
  return tlsSocket;
}

function serveTest(tlsSock: tls.TLSSocket): void {
  let buf = Buffer.alloc(0);
  const onData = (chunk: Buffer) => {
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
