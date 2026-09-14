// `fetch` for upstream: HTTP/1.1 over a pooled agent, tunneled through sx.org or
// a corporate proxy when configured. Returns the fetch-Response subset server.js uses.

import http from 'node:http';
import https from 'node:https';
import { ReadableStream } from 'node:stream/web';
import { sxTunnelAgent } from './sx.js';
import { proxyForHost, proxyAgent } from './upstream-proxy.js';

// Global fetch multiplexes an origin over one h2 connection, whose 64KB flow-control
// window serializes concurrent ~1MB uploads; independent HTTP/1.1 sockets do not.
const MAX_SOCKETS = Number(process.env.JAYNSHARE_UPSTREAM_MAX_SOCKETS) || 256;
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: MAX_SOCKETS });
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: MAX_SOCKETS });
const USE_GLOBAL_FETCH = /^(1|true|yes|on)$/i.test(process.env.JAYNSHARE_UPSTREAM_GLOBAL_FETCH || '');

// Time-to-first-byte only, cleared once headers arrive so a long stream is never
// cut; turns a hang on a dead pooled socket into a fast, retryable failure.
const DEFAULT_HEADERS_TIMEOUT_MS = 120_000;

function resolveHeadersTimeout(perCall) {
  if (perCall != null) return perCall;
  const env = Number(process.env.JAYNSHARE_UPSTREAM_HEADERS_TIMEOUT_MS);
  return env > 0 ? env : DEFAULT_HEADERS_TIMEOUT_MS;
}

function headersTimeoutError(ms) {
  const err = new Error(`upstream response headers timed out after ${ms}ms`);
  err.code = 'JAYNSHARE_HEADERS_TIMEOUT'; // server.js treats it as transient
  return err;
}

/** `via`: an SxManager to dial through, or null for the direct/corporate-proxy path. */
export function upstreamFetch(url, opts = {}, via = null) {
  const fetchOpts = { ...opts, headersTimeoutMs: resolveHeadersTimeout(opts.headersTimeoutMs) };
  if (via?.isProvisioned()) return proxiedFetch(url, fetchOpts, via);
  const useGlobal = USE_GLOBAL_FETCH && !proxyForHost(new URL(url).hostname);
  return useGlobal ? directFetch(url, fetchOpts) : pooledFetch(url, fetchOpts);
}

// For jaynshare's own calls (OAuth, profile, usage); honours the upstream proxy.
export function proxyFetch(url, opts = {}) {
  const { headersTimeoutMs, ...rest } = opts;
  if (!proxyForHost(new URL(url).hostname)) return fetch(url, rest);
  return pooledFetch(url, { ...rest, headersTimeoutMs: resolveHeadersTimeout(headersTimeoutMs) });
}

function pooledFetch(url, opts) {
  const parsedUrl = new URL(url);
  const isHttp = parsedUrl.protocol === 'http:';
  const port = Number(parsedUrl.port) || (isHttp ? 80 : 443);
  const proxy = proxyForHost(parsedUrl.hostname);
  if (proxy) {
    const agent = proxyAgent(proxy, { targetHost: parsedUrl.hostname, targetPort: port, tls: !isHttp, tlsOptions: opts.tlsOptions || {} });
    return nodeRequest(parsedUrl, opts, { transport: isHttp ? http : https, agent });
  }
  return nodeRequest(parsedUrl, opts, { transport: isHttp ? http : https, agent: isHttp ? httpAgent : httpsAgent });
}

// JAYNSHARE_UPSTREAM_GLOBAL_FETCH=1: Node's global fetch with a headers-only
// deadline (AbortSignal.timeout would also kill the body).
function directFetch(url, { headersTimeoutMs, ...opts }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(headersTimeoutError(headersTimeoutMs)), headersTimeoutMs);
  timer.unref?.();
  return fetch(url, { ...opts, signal: ctrl.signal }).then(
    (res) => { clearTimeout(timer); return res; },
    (err) => { clearTimeout(timer); throw err; },
  );
}

function proxiedFetch(url, opts, sx) {
  const parsedUrl = new URL(url);
  const agent = sxTunnelAgent(sx, parsedUrl.hostname, Number(parsedUrl.port) || 443);
  return nodeRequest(parsedUrl, opts, { transport: https, agent });
}

// `req` is created before the timer so a synchronous throw leaves no armed timer.
function nodeRequest(parsedUrl, opts, { transport, agent }) {
  const timeoutMs = opts.headersTimeoutMs;
  return new Promise((resolve, reject) => {
    const req = transport.request(
      parsedUrl,
      { method: opts.method || 'GET', headers: opts.headers || {}, agent },
      (res) => { clearTimeout(timer); cleanupAbort(); resolve(makeResponse(res)); },
    );
    const timer = setTimeout(() => req.destroy(headersTimeoutError(timeoutMs)), timeoutMs);
    timer.unref?.();

    const signal = opts.signal;
    const onAbort = () => req.destroy(signal?.reason ?? new Error('aborted'));
    const cleanupAbort = () => signal?.removeEventListener?.('abort', onAbort);
    if (signal) {
      if (signal.aborted) { clearTimeout(timer); req.destroy(); reject(signal.reason ?? new Error('aborted')); return; }
      signal.addEventListener?.('abort', onAbort, { once: true });
    }

    req.once('error', (err) => { clearTimeout(timer); cleanupAbort(); reject(err); });

    const body = opts.body;
    const method = (opts.method || 'GET').toUpperCase();
    if (body == null || method === 'GET' || method === 'HEAD') req.end();
    else if (typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array) req.end(Buffer.from(body));
    else req.end(String(body));
  });
}

// Not Readable.toWeb: it double-closes the controller when 'close' follows 'end'.
function nodeToWeb(res) {
  let closed = false;
  const close = (controller) => {
    if (closed) return;
    closed = true;
    try { controller.close(); } catch { /* already closed / consumer gone */ }
  };
  return new ReadableStream({
    start(controller) {
      res.on('data', (chunk) => {
        try { controller.enqueue(chunk); } catch { return; }
        if (controller.desiredSize != null && controller.desiredSize <= 0) res.pause();
      });
      res.on('end', () => close(controller));
      res.on('close', () => close(controller));
      res.on('error', (err) => {
        if (closed) return;
        closed = true;
        try { controller.error(err); } catch { /* consumer gone */ }
      });
    },
    pull() { res.resume(); },
    cancel() { res.destroy(); },
  });
}

function makeResponse(res) {
  const web = nodeToWeb(res);
  const collect = async () => {
    const chunks = [];
    const reader = web.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks);
  };
  return {
    status: res.statusCode,
    ok: res.statusCode >= 200 && res.statusCode < 300,
    headers: makeHeaders(res.headers),
    body: web,
    async json() { return JSON.parse((await collect()).toString('utf8')); },
    async text() { return (await collect()).toString('utf8'); },
    async arrayBuffer() { const b = await collect(); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); },
  };
}

function makeHeaders(h) {
  const flat = (v) => (Array.isArray(v) ? v.join(', ') : v);
  const entries = function* () { for (const [k, v] of Object.entries(h)) yield [k, flat(v)]; };
  return {
    get: (name) => { const v = h[name.toLowerCase()]; return v == null ? null : flat(v); },
    entries,
    [Symbol.iterator]: entries,
  };
}
