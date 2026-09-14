// sx.org residential egress: transient 429s key on the outbound IP, so a fresh
// exit IP clears them. TLS stays end-to-end; the proxy relays ciphertext only.

import net from 'node:net';
import tls from 'node:tls';
import https from 'node:https';

const CONNECT_TIMEOUT_MS = 30000; // residential exits can be slow to establish

const sxBase = () => process.env.SX_API_BASE || 'https://api.sx.org';

async function sxGet(path, apiKey, params = {}) {
  const url = new URL(sxBase() + path);
  url.searchParams.set('apiKey', apiKey);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  return res.json();
}

async function sxPost(path, apiKey, body) {
  const url = new URL(sxBase() + path);
  url.searchParams.set('apiKey', apiKey);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

const SX_MODES = ['off', '429', 'always'];
const normalizeMode = (m) => (SX_MODES.includes(m) ? m : 'always');

// ports-list: { proxy: "host:port", login, password, id }; create-port: { server, port, login, password, id }
function parsePort(p) {
  let host, port;
  if (typeof p.proxy === 'string' && p.proxy.includes(':')) {
    const i = p.proxy.lastIndexOf(':');
    host = p.proxy.slice(0, i); port = p.proxy.slice(i + 1);
  } else {
    host = p.server; port = p.port;
  }
  return { host, port: parseInt(port, 10), username: p.login, password: p.password, portId: p.id };
}

// Resolves with the raw socket, paused, once the proxy answers 200.
export function connectThroughProxy({ proxyHost, proxyPort, auth, targetHost, targetPort, timeout = CONNECT_TIMEOUT_MS, label = 'sx.org proxy' }) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ port: proxyPort, host: proxyHost });
    let buf = '';
    const timer = setTimeout(() => fail(new Error(`${label} CONNECT timed out after ${timeout}ms`)), timeout);
    const cleanup = () => {
      clearTimeout(timer);
      sock.removeListener('data', onData);
      sock.removeListener('error', fail);
    };
    const fail = (err) => { cleanup(); sock.destroy(); reject(err); };
    const onData = (chunk) => {
      buf += chunk.toString('latin1');
      const idx = buf.indexOf('\r\n\r\n');
      if (idx < 0) { if (buf.length > 65536) fail(new Error(`${label} CONNECT response too large`)); return; }
      const statusLine = buf.slice(0, buf.indexOf('\r\n'));
      const m = statusLine.match(/^HTTP\/\d\.\d\s+(\d{3})/);
      if (!m || m[1] !== '200') { fail(new Error(`${label} refused CONNECT: ${statusLine}`)); return; }
      cleanup();
      sock.pause(); // the TLS layer must see every byte
      const rest = Buffer.from(buf.slice(idx + 4), 'latin1');
      if (rest.length) sock.unshift(rest);
      resolve(sock);
    };
    sock.once('connect', () => {
      const lines = [`CONNECT ${targetHost}:${targetPort} HTTP/1.1`, `Host: ${targetHost}:${targetPort}`];
      if (auth) lines.push(`Proxy-Authorization: Basic ${Buffer.from(auth).toString('base64')}`);
      lines.push('Proxy-Connection: keep-alive', '', '');
      sock.write(lines.join('\r\n'));
    });
    sock.on('data', onData);
    sock.once('error', fail);
  });
}

export async function tunnelTls({ proxy, targetHost, targetPort = 443, tlsOptions = {}, label = 'sx.org proxy' }) {
  const sock = await connectThroughProxy({
    proxyHost: proxy.host,
    proxyPort: proxy.port,
    auth: proxy.username ? `${proxy.username}:${proxy.password}` : null,
    targetHost,
    targetPort,
    label,
  });
  return new Promise((resolve, reject) => {
    const tlsSock = tls.connect({ socket: sock, servername: targetHost, ...tlsOptions });
    const onErr = (err) => { tlsSock.removeListener('secureConnect', onOk); sock.destroy(); reject(err); };
    const onOk = () => { tlsSock.removeListener('error', onErr); resolve(tlsSock); };
    tlsSock.once('secureConnect', onOk);
    tlsSock.once('error', onErr);
  });
}

/** One-shot agent whose sockets tunnel TLS through the sx proxy; pooling would leak across targets. */
export function sxTunnelAgent(sx, targetHost, targetPort = 443) {
  const proxy = sx.getProxy();
  const agent = new https.Agent({ keepAlive: false });
  agent.createConnection = (_options, cb) => {
    tunnelTls({ proxy, targetHost, targetPort, tlsOptions: sx.tlsOptions || {} })
      .then((sock) => cb(null, sock))
      .catch((err) => cb(err));
    return undefined;
  };
  return agent;
}

export class SxManager {
  constructor({ log = () => {} } = {}) {
    this.log = log;
    this.apiKey = null;
    this.proxy = null;   // { host, port, username, password, portId }
    this.mode = 'always'; // off | 429 | always
    this._rlUntil = 0;    // '429' mode routes via sx until this time
  }

  isProvisioned() { return !!(this.apiKey && this.proxy); }
  getProxy() { return this.proxy; }
  getMode() { return this.mode; }

  useByDefault() { return this.isProvisioned() && this.mode === 'always'; }
  useOn429() { return this.isProvisioned() && this.mode !== 'off'; }
  // A tunnel serves many requests, so '429' mode routes only inside the sticky window.
  useForConnect() {
    if (!this.isProvisioned() || this.mode === 'off') return false;
    return this.mode === 'always' || this.isRecentlyRateLimited();
  }

  noteRateLimited(seconds = 60) { this._rlUntil = Date.now() + Math.min(Math.max(seconds, 1), 300) * 1000; }
  isRecentlyRateLimited() { return Date.now() < this._rlUntil; }

  async configure(apiKey, mode = this.mode) {
    this.mode = normalizeMode(mode);
    if (!apiKey) { this.disable(); return { ok: false, error: 'no API key' }; }
    this.apiKey = apiKey;
    if (this.mode === 'off') { this.proxy = null; return { ok: true, mode: this.mode, proxy: null }; }
    return this._ensureProxy();
  }

  async setMode(mode) {
    this.mode = normalizeMode(mode);
    if (this.mode === 'off') { this.proxy = null; return { ok: true, mode: this.mode }; }
    if (this.apiKey && !this.proxy) return this._ensureProxy();
    return { ok: true, mode: this.mode, proxy: this.proxy };
  }

  disable() { this.apiKey = null; this.proxy = null; }

  async _ensureProxy() {
    try {
      this.proxy = await this.provision();
      this.log(`[Jaynshare] sx.org proxy ready: ${this.proxy.host}:${this.proxy.port}`);
      return { ok: true, mode: this.mode, proxy: this.proxy };
    } catch (err) {
      this.proxy = null;
      this.log(`[Jaynshare] sx.org provisioning failed: ${err.message}`);
      return { ok: false, error: err.message };
    }
  }

  async getBalance() {
    if (!this.apiKey) return null;
    try {
      const r = await sxGet('/v2/user/balance', this.apiKey);
      return r?.success ? r : null;
    } catch { return null; }
  }

  async provision() {
    if (!this.apiKey) throw new Error('sx.org API key not set');
    const list = await sxGet('/v2/proxy/ports', this.apiKey, { per_page: 50 });
    const proxies = list?.message?.proxies || [];
    const active = proxies.find((p) => p.status === 1 && p.login && p.password && p.proxy);
    if (active) return parsePort(active);

    const created = await sxPost('/v2/proxy/create-port', this.apiKey, {
      country_code: 'US', proxy_type_id: 1, type_id: 1, // type_id 1 = residential
    });
    if (!created?.success || !created.data) {
      const detail = created?.errors ? JSON.stringify(created.errors) : (created?.message || JSON.stringify(created));
      throw new Error(`sx.org create-port failed: ${detail}`);
    }
    return parsePort(created.data);
  }
}
