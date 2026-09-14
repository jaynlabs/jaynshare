import http from 'node:http';
import https from 'node:https';
import { timingSafeEqual } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { ensureCerts, createConnectHandler } from './mitm.js';
import { patchAccountUuid } from './account-uuid-rewrite.js';
import { sanitizeToolPairs } from './tool-pair-sanitize.js';
import { TopLevelFieldFinder, modelGlobMatches, parseRequestModel, parseAdvisorModel } from './model.js';
import { BodyWriter } from './request-log.js';
import { upstreamFetch } from './upstream-fetch.js';
import { sxTunnelAgent } from './sx.js';
import { createEgressGuard } from './egress-guard.js';
import { principalStillAuthorized, resolvePrincipal } from './client-auth.js';


const HOP_BY_HOP_HEADERS = new Set([
  'host', 'connection', 'keep-alive', 'transfer-encoding',
  'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate',
]);
const PIN_PREFIX = '/jaynshare-account/'; // deprecated URL pin, superseded by JAYNSHARE_ACCOUNT
const INLINE_RETRY_AFTER_MAX_SECONDS = 15;
// A rate-limit 429 pauses the account and retries it; past this, the client gets the 429.
const RATE_LIMIT_ABSORB_MAX_SECONDS =
  Number(process.env.JAYNSHARE_RATE_LIMIT_ABSORB_MAX_SECONDS) || 60;
let requestCounter = 0; // process-wide: every MITM listener shares the hooks

// Illegal on an HTTP/2 response; hop-by-hop on h1.
const CONNECTION_SPECIFIC_HEADERS = new Set([
  'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
  'proxy-connection', 'te', 'trailer',
]);

const LOCAL_OPERATOR = { role: 'operator', clientId: 'local', clientName: 'Local operator', local: true };

// Responses the client body was decoded from must not claim an encoding or length.
const STALE_BODY_HEADERS = new Set(['content-encoding', 'content-length']);

/** Methods whose request carries no body, so upstream gets `end()` instead of a pipe. */
const BODYLESS_METHODS = new Set(['GET', 'HEAD']);
const isBodyless = (method) => BODYLESS_METHODS.has(method);

// Reach upstream with the client's own credential, never a rotated account token.
const CLIENT_CREDENTIAL_PATHS = ['/v1/code/', '/api/oauth/files/', '/api/oauth/file_upload'];

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function sendNoStoreJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

function apiError(type, message) {
  return { type: 'error', error: { type, message } };
}

function sendRateLimited(res, retryAfterSeconds, message) {
  res.writeHead(429, { 'Content-Type': 'application/json', 'retry-after': String(retryAfterSeconds) });
  res.end(JSON.stringify(apiError('rate_limit_error', message)));
}

export function safeKeyEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export function isLoopbackAddr(addr) {
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

// A local process reaching a Tailscale-only bind; a remote peer cannot forge the server's own source address.
export function isSelfConnection(remoteAddress, localAddress) {
  return typeof remoteAddress === 'string' && remoteAddress.length > 0
    && remoteAddress === localAddress;
}

export function createProxyServer(accountManager, config, { hooks = {}, sx = null } = {}) {
  const upstream = config.upstream || 'https://api.anthropic.com';
  const logDir = config.logDir || null;
  const holdMs = (config.holdSeconds || 0) * 1000;

  if (logDir) {
    mkdir(logDir, { recursive: true }).catch(() => {});
  }

  const egress = createEgressGuard(config, console.error);
  const forward = createProxyRequestListener({ accountManager, upstream, logDir, hooks, sx, holdMs, config, egress });

  const requestHandler = async (req, res) => {
    try {
      const isLocal = isLoopbackAddr(req.socket.remoteAddress)
        || isSelfConnection(req.socket.remoteAddress, req.socket.localAddress);
      const principal = resolvePrincipal(config, req.headers['x-api-key'], { local: isLocal });
      if (!principal) {
        sendJson(res, 401, apiError('authentication_error', 'Invalid proxy API key'));
        return;
      }
      req.jaynsharePrincipal = principal;
      const control = { accountManager, hooks, principal };

      // Loopback skips the key, so a web page could otherwise POST here cross-origin without preflight.
      if (req.method === 'POST' && (req.url || '').startsWith('/jaynshare/')
          && !isSameOriginControlRequest(req)) {
        sendJson(res, 403, {
          ok: false,
          error: 'cross-origin request refused: the control plane is not reachable from a web page',
        });
        return;
      }

      // The two read-only views open to client credentials.
      const requestUrl = new URL(req.url || '/', 'http://jaynshare.local');
      if (req.method === 'GET' && requestUrl.pathname === '/jaynshare/usage') {
        serveUsage(requestUrl, res, control);
        return;
      }
      if (req.method === 'GET' && requestUrl.pathname === '/jaynshare/account-selection') {
        serveAccountSelection(requestUrl, res, control);
        return;
      }

      if ((req.url || '').startsWith('/jaynshare/') && principal.role !== 'operator') {
        sendJson(res, 403, { ok: false, error: 'operator credential required' });
        return;
      }

      if (/^https?:\/\//i.test(req.url || '')) { relayHttpForward(req, res); return; } // absolute-form: HTTP_PROXY use

      if (req.method === 'GET' && req.url === '/jaynshare/status') { serveStatus(res, control); return; }
      if (req.method === 'POST' && req.url === '/jaynshare/reload') { await serveReload(res, control); return; }
      if (req.method === 'POST' && req.url === '/jaynshare/switch') { await serveSwitch(req, res, control); return; }

      return forward(req, res);
    } catch (err) {
      console.error('[Jaynshare] Unhandled error:', err);
    }
  };

  const server = http.createServer(requestHandler);

  // CONNECT to the upstream host is MITM-relayed; anything else is blind-tunneled.
  const mitmHost = (() => { try { return new URL(upstream).hostname; } catch { return 'api.anthropic.com'; } })();
  let certsPromise = null;
  const ensureLeaf = async () => {
    certsPromise ||= ensureCerts(mitmHost).catch((err) => { certsPromise = null; throw err; }); // never memoize a rejection
    const c = await certsPromise;
    return { key: c.leafKeyPem, cert: c.leafCertPem };
  };
  server.on('connect', createConnectHandler({ config, accountManager, ensureLeaf, logDir, hooks, log: console.error, sx, egress }));
  server.on('upgrade', createUpgradeRelay({ upstream, sx }));

  return server;
}

// ── control plane ───────────────────────────────────────────

function serveUsage(requestUrl, res, { accountManager, hooks, principal }) {
  const suppliedSessionIds = requestUrl.searchParams.getAll('session_id');
  let session;
  if (suppliedSessionIds.length) {
    const sessionId = suppliedSessionIds.length === 1
      ? validateSessionId(suppliedSessionIds[0]) : null;
    if (!sessionId) {
      sendNoStoreJson(res, 400, { ok: false, error: 'invalid session_id' });
      return;
    }
    session = accountManager.sessionAssignment(`${principal.clientId}\0${sessionId}`);
  }
  const status = accountManager.getStatus();
  const extra = hooks.getStatusExtra?.() || {};
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(publicUsageSnapshot(status, extra, session), null, 2));
}

function serveAccountSelection(requestUrl, res, { accountManager }) {
  const selectors = requestUrl.searchParams.getAll('account');
  const selector = selectors.length === 1 ? selectors[0] : '';
  const index = /^\d+$/.test(selector.trim()) ? null : resolveAccountPin(accountManager, selector); // no indexes
  if (index == null) {
    sendNoStoreJson(res, 404, { ok: false, error: 'unknown account selector' });
    return;
  }
  const account = accountManager.accounts[index];
  const { eligible, reason } = accountManager.preferenceEligibility(index);
  sendNoStoreJson(res, 200, {
    account: account.name,
    disabled: !!account.disabled,
    available: eligible,
    ...(reason ? { reason } : {}),
  });
}

function serveStatus(res, { accountManager, hooks }) {
  const status = accountManager.getStatus();
  const extra = hooks.getStatusExtra?.() || {};
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ...extra, ...status }, null, 2));
}

async function serveReload(res, { hooks }) {
  if (!hooks.reload) {
    sendJson(res, 501, { ok: false, error: 'reload not supported' });
    return;
  }
  try {
    const added = await hooks.reload();
    sendJson(res, 200, { ok: true, added: added || 0 });
  } catch (err) {
    sendJson(res, 500, { ok: false, error: err.message });
  }
}

// Body: {"account": "<name|email|accountUuid|accountUuid/orgUuid|orgUuid>"}
async function serveSwitch(req, res, { accountManager }) {
  const names = () => (accountManager.accounts || []).map(a => a.name);
  let target;
  try {
    const raw = await readControlBody(req);
    target = JSON.parse(raw || '{}')?.account;
  } catch (err) {
    const tooLarge = err.message === 'body too large';
    sendJson(res, tooLarge ? 413 : 400, { ok: false, error: tooLarge ? 'request body too large' : 'invalid request body' });
    return;
  }
  if (typeof target !== 'string' || !target.trim()) {
    sendJson(res, 400, { ok: false, error: 'missing "account"', accounts: names() });
    return;
  }
  const index = resolveAccountPin(accountManager, target);
  if (index == null) {
    sendJson(res, 404, { ok: false, error: `no such account "${target}"`, accounts: names() });
    return;
  }
  accountManager.currentIndex = index;
  const name = accountManager.accounts[index].name;
  const { eligible, reason } = accountManager.eligibility(index); // the switch happens; traffic may not follow
  console.log(`[Jaynshare] Switched to account "${name}" (manual)`
    + (eligible ? '' : ` — ${reason}, so rotation will not use it`));
  sendJson(res, 200, { ok: true, account: name, eligible, ...(reason ? { reason } : {}) });
}

/** An allow-list, so a new operator status field is never published to clients by accident. */
export function publicUsageSnapshot(status = {}, extra = {}, session = undefined) {
  const probe = extra.probe || {};
  const server = extra.server || {};
  return {
    capabilities: {
      sessionAccountPreference: true,
      sessionAssignment: true,
    },
    currentAccount: status.currentAccount || null,
    switchThreshold: status.switchThreshold ?? null,
    sessions: status.sessions ? {
      active: status.sessions.active || 0,
      known: status.sessions.known || 0,
      distribute: !!status.sessions.distribute,
    } : null,
    accounts: (status.accounts || []).map(account => ({
      name: account.name,
      type: account.type,
      orgName: account.orgName || null,
      priority: account.priority || 0,
      disabled: !!account.disabled,
      status: account.status || 'unknown',
      sessions: account.sessions || 0,
      quota: { ...(account.quota || {}) },
      usage: { ...(account.usage || {}) },
      rateLimitedUntil: account.rateLimitedUntil || null,
      pausedUntil: account.pausedUntil || null,
    })),
    probe: {
      enabled: !!probe.enabled,
      intervalSeconds: probe.intervalSeconds || 0,
      running: !!probe.running,
      lastRunFinishedAt: probe.lastRunFinishedAt || null,
      nextRunAt: probe.nextRunAt || null,
    },
    server: {
      startedAt: server.startedAt || null,
      uptimeSeconds: server.uptimeSeconds ?? null,
    },
    ...(session !== undefined ? { session: session || null } : {}),
  };
}

function validateSessionId(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256
    && /^[A-Za-z0-9._:-]+$/.test(value) ? value : null;
}

/** Both headers are browser-set and unforgeable from page JavaScript; curl and the CLI send neither. */
export function isSameOriginControlRequest(req) {
  const site = req.headers['sec-fetch-site'];
  if (site) return site === 'same-origin' || site === 'none';
  return !req.headers.origin; // any Origin on a local control POST means a page issued it
}

async function readControlBody(req, limit = 64 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error('body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

// First match wins: `accountUuid/orgUuid`, `accountUuid`, `orgUuid`, display
// name, bare email. Never the rotation index: it shifts on delete.
export function resolveAccountPin(accountManager, token) {
  const accounts = accountManager.accounts || [];
  const norm = (s) => (s || '').trim().toLowerCase();
  const normalizedToken = norm(token);
  if (!normalizedToken) return null;

  const matchingIndex = (pick) => accounts.findIndex(a => norm(pick(a)) === normalizedToken);
  const qualified = accounts.findIndex(a => a.accountUuid && a.orgUuid
    && `${norm(a.accountUuid)}/${norm(a.orgUuid)}` === normalizedToken);

  for (const index of [
    qualified,
    matchingIndex(a => a.accountUuid),
    matchingIndex(a => a.orgUuid),
    matchingIndex(a => a.name),
    matchingIndex(a => (a.name || '').split(' (')[0]),
  ]) if (index >= 0) return index;

  return null;
}

// ── credential-free relays ──────────────────────────────────

// Plain-HTTP counterpart of the blind CONNECT tunnel: a transparent forward proxy, no account logic.
function relayHttpForward(req, res) {
  let target;
  try { target = new URL(req.url); } catch {
    sendJson(res, 400, apiError('invalid_request_error', 'Malformed forward-proxy URL'));
    return;
  }
  const transport = target.protocol === 'http:' ? http : https;
  const headers = copyClientHeaders(req.headers, lk => HOP_BY_HOP_HEADERS.has(lk) || lk === 'proxy-connection');

  const upstreamReq = transport.request(target, { method: req.method, headers }, (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode, copyResponseHeaders(upstreamRes.headers, { decompressed: false }));
    upstreamRes.pipe(res);
  });
  upstreamReq.on('error', (err) => {
    console.error(`[Jaynshare] HTTP forward to ${target.host} failed:`, err.message);
    if (!res.headersSent) sendJson(res, 502, apiError('proxy_error', 'Upstream unreachable'));
  });
  res.on('close', () => upstreamReq.destroy());
  if (isBodyless(req.method)) upstreamReq.end();
  else req.pipe(upstreamReq);
}

// One-shot: the tunnel closes over one target, so the agent must not pool.
function sxAgent(sx, targetHost) {
  return sxTunnelAgent(sx, targetHost);
}

function sxAgentFor({ sx }, targetHost) {
  const useProxy = !!(sx?.useByDefault() && sx.isProvisioned());
  return useProxy ? sxAgent(sx, targetHost) : undefined;
}

/** Client request headers minus h2 pseudo-headers and whatever `skip` names. */
function copyClientHeaders(headers, skip) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    const lk = key.toLowerCase();
    if (lk.startsWith(':') || skip(lk)) continue;
    out[key] = value;
  }
  return out;
}

/** Upstream response headers minus the hop-by-hop set; `decompressed` also drops stale body headers. */
function copyResponseHeaders(headers, { decompressed = true } = {}) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    if (CONNECTION_SPECIFIC_HEADERS.has(key)) continue;
    if (decompressed && STALE_BODY_HEADERS.has(key)) continue;
    out[key] = value;
  }
  return out;
}

// `fetch` auto-decompressed the body, so the encoding and length headers are stale.
function clientResponseHeaders(entries) {
  return copyResponseHeaders(Object.fromEntries(entries));
}

/** Pipes bytes both ways with the client's own headers; a long-poll may withhold headers for minutes. */
function relayStream(req, res, target) {
  const url = new URL(`${target.upstream}${req.url}`);
  const headers = copyClientHeaders(req.headers, lk => HOP_BY_HOP_HEADERS.has(lk) || lk === 'accept-encoding');

  const agent = sxAgentFor(target, url.hostname);
  const transport = url.protocol === 'http:' ? http : https;

  const upstreamReq = transport.request(url, { method: req.method, headers, agent }, (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode, clientResponseHeaders(Object.entries(upstreamRes.headers)));
    upstreamRes.pipe(res);
  });

  upstreamReq.on('error', (err) => {
    console.error('[Jaynshare] Remote Control relay error:', err.message);
    if (!res.headersSent) sendJson(res, 502, apiError('proxy_error', 'Upstream unreachable'));
  });
  res.on('close', () => upstreamReq.destroy());

  if (isBodyless(req.method)) upstreamReq.end();
  else req.pipe(upstreamReq);
}

/** An 'upgrade' listener: relays the WebSocket handshake with the client's own headers, then splices the two sockets. */
export function createUpgradeRelay(target) {
  return (req, socket, head) => {
    const url = new URL(`${target.upstream}${req.url}`);
    // 'upgrade'/'connection' ARE the handshake, so hop-by-hop headers are kept here.
    const headers = copyClientHeaders(req.headers, lk => lk === 'host');

    const agent = sxAgentFor(target, url.hostname);
    const transport = url.protocol === 'http:' ? http : https;

    const upstreamReq = transport.request(url, { method: req.method, headers, agent });

    upstreamReq.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
      const headerLines = Object.entries(upstreamRes.headers)
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join('\r\n');
      socket.write(`HTTP/1.1 ${upstreamRes.statusCode} ${upstreamRes.statusMessage}\r\n${headerLines}\r\n\r\n`);
      if (upstreamHead?.length) socket.write(upstreamHead);
      if (head?.length) upstreamSocket.write(head);
      socket.pipe(upstreamSocket);
      upstreamSocket.pipe(socket);
      // Upgraded sockets are half-open: a FIN ends only the readable side.
      socket.on('end', () => upstreamSocket.destroy());
      upstreamSocket.on('end', () => socket.destroy());
      socket.on('close', () => upstreamSocket.destroy());
      upstreamSocket.on('close', () => socket.destroy());
      upstreamSocket.on('error', () => socket.destroy()); // detached from upstreamReq by the 101
    });

    upstreamReq.on('error', (err) => {
      console.error('[Jaynshare] Remote Control WebSocket relay error:', err.message);
      socket.destroy();
    });
    socket.on('error', () => upstreamReq.destroy());

    upstreamReq.end();
  };
}

async function relayRaw(req, res, { upstream, sx }) {
  const bodyChunks = [];
  for await (const chunk of req) bodyChunks.push(chunk);
  const body = Buffer.concat(bodyChunks);

  try {
    const upstreamRes = await upstreamFetch(`${upstream}${req.url}`, {
      method: req.method,
      headers: {
        'content-type': req.headers['content-type'] || 'application/json',
        'accept': req.headers['accept'] || 'application/json',
        'user-agent': req.headers['user-agent'] || 'node',
      },
      body: body.length > 0 ? body : undefined,
    }, sx?.useByDefault() ? sx : null);

    const responseBody = await upstreamRes.text();
    res.writeHead(upstreamRes.status, copyResponseHeaders(upstreamRes.headers));
    res.end(responseBody);
  } catch (err) {
    console.error('[Jaynshare] Raw relay error:', err.message);
    if (!res.headersSent) sendJson(res, 502, apiError('proxy_error', 'Upstream unreachable'));
  }
}

// ── data plane ──────────────────────────────────────────────

/** The data-plane listener shared by the base server and the MITM's terminating server. */
export function createProxyRequestListener({ accountManager, upstream, logDir = null, hooks = {}, sx = null, holdMs = 0, config = {}, forcedPin = null, preferredAccount = null, forcedPrincipal = null, egress = null }) {
  const listenerContext = { accountManager, upstream, hooks, logDir, sx, holdMs, config };
  return async (req, res) => {
    try {
      const principal = forcedPrincipal || req.jaynsharePrincipal || LOCAL_OPERATOR;
      if (!principalStillAuthorized(config, principal)) {
        sendJson(res, 401, apiError('authentication_error', 'Proxy credential was revoked or rotated'));
        return;
      }
      if (eventLogBlocked(req, config)) { sendJson(res, 200, {}); return; }
      if (egress?.enabled() && !await egressPinned(egress, res)) return;
      if (await relayedVerbatim(req, res, { upstream, sx })) return;

      // Event logs the operator chose to hide stay off the TUI but still reach upstream.
      const clientExchange = { req, res, activity: eventLogHidden(req, config) ? {} : hooks };
      const pins = resolvePins(clientExchange, { accountManager, forcedPin, preferredAccount });
      if (!pins) return;

      await serveExchange(clientExchange, { listenerContext, principal, pins });
    } catch (err) {
      console.error('[Jaynshare] Unhandled error:', err);
    }
  };
}

function eventLogPolicy(req, config) {
  if (!(req.url || '').startsWith('/api/event_logging')) return 'show';
  return config?.eventLogging || 'hide'; // show | hide | block; read live for the TUI toggle
}

const eventLogBlocked = (req, config) => eventLogPolicy(req, config) === 'block';
const eventLogHidden = (req, config) => eventLogPolicy(req, config) !== 'show';

/** The client's own OAuth refresh and credential calls carry their own auth: no account is spent. */
async function relayedVerbatim(req, res, { upstream, sx }) {
  if (req.method === 'POST' && req.url === '/v1/oauth/token') {
    await relayRaw(req, res, { upstream, sx });
    return true;
  }
  if (CLIENT_CREDENTIAL_PATHS.some((p) => (req.url || '').startsWith(p))) {
    relayStream(req, res, { upstream, sx });
    return true;
  }
  return false;
}

/**
 * Resolves the account a pin or preference names, answering the client itself when
 * it names none. Returns null once that answer is sent.
 */
function resolvePins(clientExchange, { accountManager, forcedPin, preferredAccount }) {
  const { req } = clientExchange;

  // `/jaynshare-account/<token>/...` pins one account and never rotates. The prefix is stripped.
  let pinnedIndex = null;
  const urlPin = urlPinToken(req.url || '');
  if (urlPin) {
    pinnedIndex = resolveAccountPin(accountManager, urlPin.token);
    if (pinnedIndex == null) {
      rejectUnknownAccount(clientExchange, `(unknown pin: "${urlPin.token}")`, `Unknown account pin "${urlPin.token}"`);
      return null;
    }
    req.url = urlPin.rest;
  } else if (forcedPin != null) {
    // The MITM pin arrives bound to the listener; resolved per request since a reload can renumber accounts.
    pinnedIndex = resolveAccountPin(accountManager, forcedPin);
    if (pinnedIndex == null) {
      rejectUnknownAccount(clientExchange, `(unknown pin: "${forcedPin}")`, `Unknown account pin "${forcedPin}" (from JAYNSHARE_ACCOUNT)`);
      return null;
    }
  }

  let preferredIndex = null;
  if (pinnedIndex == null && preferredAccount != null) {
    preferredIndex = resolveAccountPin(accountManager, preferredAccount);
    if (preferredIndex == null) {
      rejectUnknownAccount(clientExchange, '(unknown preference)', 'Preferred account no longer exists; choose another account.');
      return null;
    }
  }

  return { pinnedIndex, preferredIndex };
}

/** Reads the request, then relays it through the pool and reports what happened. */
async function serveExchange({ req, res, activity }, { listenerContext, principal, pins }) {
  const { accountManager, upstream, hooks, logDir, sx, holdMs, config } = listenerContext;
  const reqId = ++requestCounter;
  const sessionId = req.headers['x-claude-code-session-id'] || null;
  const sessionKey = sessionId ? `${principal.clientId}\0${sessionId}` : null;
  const client = { clientId: principal.clientId, clientName: principal.clientName };
  activity.onRequestStart?.(reqId, { method: req.method, path: req.url, sessionId, ...client, pinned: pins.pinnedIndex != null });

  const { body, model } = await readBody(req, found => activity.onRequestModel?.(reqId, { model: found }));
  const advisorModel = parseAdvisorModel(body);

  const blockedBy = model ? (config?.blockedModels || []).find((p) => modelGlobMatches(p, model)) : null;
  if (blockedBy) {
    // A fast, non-retryable 400 instead of an upstream rate limit that hangs the pipeline.
    if (!res.headersSent) sendJson(res, 400, apiError('invalid_request_error', `Model "${model}" is blocked by jaynshare (matched "${blockedBy}").`));
    hooks.onRequestEnd?.(reqId, { method: req.method, path: req.url, account: '(blocked)', status: 400, model, sessionId });
    return;
  }

  const ctx = { account: null, status: null, tried: new Set(), reauthed: new Set(), model, advisorModel, ...pins, holdBudgetMs: holdMs, sessionId: sessionKey, publicSessionId: sessionId, ...client, retryCount: 0, rotated: false };
  const exchange = { req, res, body, ctx, accountManager, upstream, hooks, reqId, logDir, sx };
  accountManager.beginSession(sessionKey);
  try {
    await forwardRequest(exchange, 0);
  } catch (err) {
    ctx.status = ctx.status || 502;
    console.error('[Jaynshare] Unhandled error:', err);
    if (!res.headersSent) sendJson(res, 502, apiError('proxy_error', 'Internal proxy error'));
  } finally {
    accountManager.endSession(sessionKey);
    activity.onRequestEnd?.(reqId, { method: req.method, path: req.url, account: ctx.account, accountId: ctx.accountId, status: ctx.status, model: ctx.model, sessionId, ...client, retryCount: ctx.retryCount, rotated: ctx.rotated, errorClass: ctx.errorClass || errorClassForStatus(ctx.status), pinned: ctx.pinnedIndex != null });
  }
}

// Off the pinned exit IP, upstream's 403 costs a re-login; waiting costs latency.
async function egressPinned(egress, res) {
  const state = await egress.waitUntilPinned({ isAborted: () => res.destroyed });
  if (res.destroyed) return false;
  if (state.ok) return true;
  res.writeHead(503, { 'Content-Type': 'application/json', 'retry-after': '30' });
  res.end(JSON.stringify(apiError('proxy_error',
    `Egress is ${state.ip || 'unknown'}, not the pinned ${state.expected.join(', ')} — not sending this request. Check the VPN.`)));
  return false;
}

function urlPinToken(url) {
  if (!url.startsWith(PIN_PREFIX)) return null;
  const afterPrefix = url.slice(PIN_PREFIX.length);
  const tokenEnd = afterPrefix.indexOf('/');
  if (tokenEnd <= 0) return null;
  return { token: decodeURIComponent(afterPrefix.slice(0, tokenEnd)), rest: afterPrefix.slice(tokenEnd) };
}

// A pin or preference naming no account never reaches upstream.
function rejectUnknownAccount({ req, res, activity }, label, message) {
  const reqId = ++requestCounter;
  const sessionId = req.headers['x-claude-code-session-id'] || null;
  activity.onRequestEnd?.(reqId, { method: req.method, path: req.url, account: label, status: 404, model: null, sessionId, pinned: false });
  sendJson(res, 404, apiError('not_found_error', message));
}

// Buffered whole so a 429 can resend it; `model` is peeked as chunks arrive for the TUI.
async function readBody(req, onModel) {
  const bodyChunks = [];
  const modelFinder = new TopLevelFieldFinder('model');
  for await (const chunk of req) {
    bodyChunks.push(chunk);
    if (!modelFinder.done) {
      const found = modelFinder.push(chunk);
      if (found) onModel(found);
    }
  }
  const body = Buffer.concat(bodyChunks);
  return { body, model: modelFinder.done ? modelFinder.value : parseRequestModel(body) };
}

function logTimestamp() {
  const d = new Date();
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

// Streams to disk as bytes flow, so a huge response costs only the current chunk.
function openRequestLog(logDir, reqId) {
  const filename = `${logTimestamp()}_${String(reqId).padStart(5, '0')}.log`;
  const ws = createWriteStream(join(logDir, filename), { flags: 'a' });
  ws.on('error', (err) => console.error(`[Jaynshare] Failed to write log: ${err.message}`));
  let ended = false;
  const write = (s) => { if (!ended && s) ws.write(Buffer.from(String(s), 'latin1')); };
  return {
    write,
    body(label, buf, contentType) {
      if (!buf || !buf.length) { write(`\n\n=== ${label} ===\n(empty)`); return; }
      new BodyWriter(write, label, contentType || '').chunk(buf);
    },
    bodyWriter(label, contentType) { return new BodyWriter(write, label, contentType || ''); },
    end() { if (!ended) { ended = true; ws.end('\n'); } },
  };
}

function formatHeaders(headers) {
  if (headers.entries) {
    return [...headers.entries()].map(([k, v]) => `  ${k}: ${v}`).join('\n');
  }
  return Object.entries(headers).map(([k, v]) => `  ${k}: ${v}`).join('\n');
}

function errorClassForStatus(status) {
  if (status == null || status < 400) return null;
  if (status === 401 || status === 403) return 'authentication';
  if (status === 429) return 'rate_limit';
  if (status >= 500) return 'upstream';
  return 'request';
}

// ── forwarding ──────────────────────────────────────────────

/**
 * One attempt at relaying the exchange through the pool; recurses to fail over,
 * hold, or retry. `useSx` is whether this attempt dials via sx.org.
 */
async function forwardRequest(exchange, retryCount, useSx) {
  const { req, accountManager, hooks, reqId, ctx, sx } = exchange;
  ctx.reauthed ??= new Set();
  ctx.retryCount = Math.max(ctx.retryCount || 0, retryCount || 0);
  const route = useSx === undefined ? !!(sx?.useByDefault()) : useSx;

  const account = pickAccount(exchange);
  if (!account) {
    await respondNoAccount(exchange, retryCount, route);
    return;
  }

  if (ctx.account && ctx.account !== account.name && !ctx.account.startsWith('(')) ctx.rotated = true;
  ctx.account = account.name;
  ctx.accountId = [account.accountUuid, account.orgUuid].filter(Boolean).join('/') || account.name;
  accountManager.recordSession(ctx.sessionId, account.index);
  hooks.onRequestRouted?.(reqId, { account: account.name });

  await accountManager.ensureTokenFresh(account.index);
  if (account.status === 'error' && retryCount < accountManager.accounts.length) {
    ctx.tried.add(account.index);
    return forwardRequest(exchange, retryCount + 1, route);
  }

  const attempt = { account, retryCount, route };
  attempt.headers = upstreamHeaders(req.headers, account);
  attempt.url = `${account.upstream || exchange.upstream}${req.url}`;
  attempt.body = outboundBody(exchange.body, req, account);
  if (attempt.body !== exchange.body) attempt.headers['content-length'] = String(attempt.body.length);
  attempt.log = lazyRequestLog(exchange, attempt);

  try {
    const upstreamRes = await sendUpstream(exchange, attempt);
    if (!upstreamRes) return;

    attempt.rateLimitHeaders = rateLimitHeadersOf(upstreamRes);
    accountManager.updateQuota(account.index, attempt.rateLimitHeaders);
    if (upstreamRes.status !== 429) accountManager.clearRateLimited(account.index);

    if (upstreamRes.status === 429) { await handle429(exchange, attempt, upstreamRes); return; }
    if (upstreamRes.status === 403 && !exchange.res.headersSent) { await handle403(exchange, attempt, upstreamRes); return; }
    if (upstreamRes.status === 401 && canForceRefresh(exchange, attempt)) { await handle401(exchange, attempt, upstreamRes); return; }
    await relayResponse(exchange, attempt, upstreamRes);
  } catch (err) {
    await handleUpstreamError(exchange, attempt, err);
  }
}

// A pinned request never fails over: once tried, there is no account.
function pickAccount({ accountManager, ctx }) {
  if (ctx.pinnedIndex != null) {
    return ctx.tried.has(ctx.pinnedIndex) ? null : accountManager.accounts[ctx.pinnedIndex];
  }
  return accountManager.getActiveAccount({
    exclude: ctx.tried, model: ctx.model, advisorModel: ctx.advisorModel,
    sessionId: ctx.sessionId, preferredIndex: ctx.preferredIndex,
  });
}

async function respondNoAccount(exchange, retryCount, route) {
  const { res, accountManager, ctx } = exchange;
  // Every candidate refused (403): a 502, since neither waiting nor the client's login is at fault.
  const rejected = ctx.credentialRejected;
  const allRefused = rejected?.size > 0 && (ctx.pinnedIndex != null
    ? rejected.has(accountManager.accounts[ctx.pinnedIndex]?.name)
    : rejected.size === accountManager.accounts.length);
  if (allRefused) {
    const names = [...rejected].map(n => `"${n}"`).join(', ');
    ctx.status = 502;
    ctx.account = `(${[...rejected].join(', ')} refused)`;
    if (!res.headersSent) {
      sendJson(res, 502, apiError('proxy_error', `Upstream refused the credential for account ${names} (403). Check the account, then re-add it with: jaynshare login`));
    }
    return;
  }
  if (ctx.pinnedIndex != null) {
    ctx.status = 429;
    ctx.account = '(pinned account unavailable)';
    if (!res.headersSent) {
      sendRateLimited(res, 5, 'Pinned account is unavailable (rate-limited, errored, or already tried). Retry shortly.');
    }
    return;
  }
  ctx.status = 429;
  ctx.account = '(none available)';
  const status = accountManager.getStatus();
  const retryAfter = computeRetryAfter(status.accounts);

  // Hold the connection and poll until an account recovers or the budget runs out.
  if (ctx.holdBudgetMs > 0) {
    const waitMs = Math.min(retryAfter * 1000, ctx.holdBudgetMs, 60_000);
    ctx.holdBudgetMs -= waitMs;
    console.log(`[Jaynshare] All accounts exhausted — holding connection, retry in ${Math.ceil(waitMs / 1000)}s (${Math.ceil(ctx.holdBudgetMs / 1000)}s budget left)`);
    await sleep(waitMs);
    if (res.destroyed) return;
    return forwardRequest(exchange, retryCount, route);
  }

  const exhaustedRetries = ctx.exhaustedRetries || 0;
  if (exhaustedRetries < 1 && retryAfter <= INLINE_RETRY_AFTER_MAX_SECONDS) {
    ctx.exhaustedRetries = exhaustedRetries + 1;
    console.log(`[Jaynshare] All accounts exhausted — waiting ${retryAfter}s before retry`);
    await sleep(retryAfter * 1000);
    if (res.destroyed) return;
    return forwardRequest(exchange, retryCount, route);
  }
  sendRateLimited(res, retryAfter, `All ${accountManager.accounts.length} accounts exhausted. Retry in ${retryAfter}s.`);
}

function upstreamHeaders(reqHeaders, account) {
  const headers = {};
  for (const [key, value] of Object.entries(reqHeaders)) {
    const lk = key.toLowerCase();
    if (lk.startsWith(':')) continue; // h2 pseudo-headers
    if (HOP_BY_HOP_HEADERS.has(lk)) continue;
    if (lk === 'x-api-key') continue;
    if (lk === 'accept-encoding') continue; // fetch auto-decompresses
    headers[key] = value;
  }
  if (account.type === 'oauth') {
    headers['authorization'] = `Bearer ${account.credential}`;
  } else {
    headers['x-api-key'] = account.credential;
  }
  return headers;
}

function outboundBody(body, req, account) {
  let sendBody = sanitizeToolPairs(body, req.url, req.headers['content-type']);
  if (account.accountUuid) sendBody = patchAccountUuid(sendBody, account.accountUuid);
  if (account.modelMap) sendBody = rewriteModel(sendBody, account.modelMap);
  return sendBody;
}

// Opened lazily on the first terminal outcome; a 429-then-retry attempt writes no file.
function lazyRequestLog({ req, body, reqId, logDir }, attempt) {
  let log = null;
  let headWritten = false;
  const get = () => (logDir ? (log ||= openRequestLog(logDir, reqId)) : null);
  return {
    get,
    head() {
      const requestLog = get();
      if (!requestLog || headWritten) return;
      headWritten = true;
      const safeHeaders = { ...attempt.headers };
      if (safeHeaders['x-api-key']) safeHeaders['x-api-key'] = safeHeaders['x-api-key'].slice(0, 15) + '...';
      if (safeHeaders['authorization']) safeHeaders['authorization'] = safeHeaders['authorization'].slice(0, 20) + '...';
      requestLog.write(`=== REQUEST (account: ${attempt.account.name}, retry: ${attempt.retryCount}) ===\n${req.method} ${attempt.url}\n${formatHeaders(safeHeaders)}`);
      if (body.length > 0) requestLog.body('REQUEST BODY', body, req.headers['content-type']);
    },
  };
}

// The concurrency slot is held only until the response headers arrive; null when the client left while waiting.
async function sendUpstream({ req, res, accountManager, sx }, { account, headers, url, body, route }) {
  if (!await accountManager.admit(account.index, () => res.destroyed)) return null;
  try {
    return await upstreamFetch(url, {
      method: req.method,
      headers,
      body: isBodyless(req.method) ? undefined : body,
      redirect: 'manual',
    }, route ? sx : null);
  } finally {
    accountManager.release(account.index);
  }
}

function rateLimitHeadersOf(upstreamRes) {
  const rateLimitHeaders = {};
  for (const [key, value] of upstreamRes.headers.entries()) {
    if (key.startsWith('anthropic-ratelimit-')) rateLimitHeaders[key] = value;
  }
  return rateLimitHeaders;
}

// A quota rejection rotates; a rate-limit throttle pauses and retries the same account.
async function handle429(exchange, attempt, upstreamRes) {
  let retryAfter = parseInt(upstreamRes.headers.get('retry-after'), 10);
  if (Number.isNaN(retryAfter)) retryAfter = 60;
  await upstreamRes.body?.cancel();

  const rejected = rejectedBucket(attempt.rateLimitHeaders);
  const canSwitch = attempt.retryCount < exchange.accountManager.accounts.length;
  if (rejected && canSwitch) return switchAfterQuotaRejection(exchange, attempt, { bucket: rejected, retryAfter });

  return absorbRateLimit(exchange, attempt, Math.min(Math.max(retryAfter, 1), 300)); // a negative value would arm a pause in the past
}

/** The unified bucket upstream rejected on, if any. */
function rejectedBucket(rateLimitHeaders) {
  if (rateLimitHeaders['anthropic-ratelimit-unified-5h-status'] === 'rejected'
      || rateLimitHeaders['anthropic-ratelimit-unified-7d-status'] === 'rejected') return 'general';
  if (rateLimitHeaders['anthropic-ratelimit-unified-7d_oi-status'] === 'rejected') return 'fable';
  return null;
}

/** Quota is spent on this account, so waiting would not help: move to the next one. */
function switchAfterQuotaRejection(exchange, attempt, { bucket, retryAfter }) {
  const { res, accountManager, ctx } = exchange;
  const { account, retryCount, route } = attempt;

  if (bucket === 'fable') {
    // A Fable-only rejection leaves the account usable for other models: no global hold.
    console.log(`[Jaynshare] Fable weekly exhausted on "${account.name}" — switching account for this Fable request`);
  } else {
    const hold = Math.min(Math.max(retryAfter, 1), 3600);
    console.log(`[Jaynshare] Quota rejection (429) on "${account.name}" — throttling ${hold}s and switching account`);
    accountManager.markRateLimited(account.index, hold);
  }

  ctx.tried.add(account.index);
  if (res.destroyed) return;
  return forwardRequest(exchange, retryCount + 1, route);
}

/** A burst, not exhaustion: a fresh egress IP or a short wait beats rotating off a warm cache. */
async function absorbRateLimit(exchange, attempt, retryAfter) {
  const { res, accountManager, ctx, sx } = exchange;
  const { account, retryCount, route } = attempt;
  const maxRetries = accountManager.accounts.length;

  const nextUseSx = !!(sx?.useOn429()); // 429s are IP-based; a fresh egress IP is not throttled
  const switchingToSx = nextUseSx && !route;
  sx?.noteRateLimited(retryAfter);

  // Rotating would move the burst onto the next account and discard this one's cache.
  accountManager.pauseAccount(account.index, Math.min(retryAfter, RATE_LIMIT_ABSORB_MAX_SECONDS));

  if (switchingToSx && retryCount < maxRetries) {
    console.log(`[Jaynshare] 429 on "${account.name}" — retrying via sx.org (fresh egress IP)`);
    if (res.destroyed) return;
    return forwardRequest(exchange, retryCount + 1, nextUseSx);
  }

  if (retryAfter <= RATE_LIMIT_ABSORB_MAX_SECONDS && retryCount < maxRetries) {
    console.log(`[Jaynshare] Rate-limit 429 on "${account.name}" — waiting ${retryAfter}s, retrying same account (no switch)`);
    await sleep(retryAfter * 1000);
    if (res.destroyed) return;
    return forwardRequest(exchange, retryCount + 1, nextUseSx);
  }

  console.log(`[Jaynshare] Rate-limit 429 on "${account.name}" — retry-after ${retryAfter}s over inline cap; returning 429 to client (no switch)`);
  ctx.status = 429;
  if (!res.headersSent && !res.destroyed) sendRateLimited(res, retryAfter, `Rate limited; retry in ${retryAfter}s.`);
}

// A 403 refuses the injected account outright; the client must never see it (it would drop its login).
async function handle403(exchange, { account, retryCount, route }, upstreamRes) {
  await upstreamRes.body?.cancel();
  (exchange.ctx.credentialRejected ??= new Set()).add(account.name);
  exchange.ctx.tried.add(account.index);
  console.error(`[Jaynshare] 403 on "${account.name}" — upstream refused the account credential`);
  return forwardRequest(exchange, retryCount + 1, route);
}

// A 401 before clock expiry means the token was revoked; one forced refresh per account per request.
function canForceRefresh({ accountManager, ctx }, { account, retryCount }) {
  return account.type === 'oauth' && !!account.refreshToken
    && retryCount < accountManager.accounts.length && !ctx.reauthed.has(account.index);
}

async function handle401(exchange, { account, retryCount, route }, upstreamRes) {
  exchange.ctx.reauthed.add(account.index);
  await upstreamRes.body?.cancel();
  console.log(`[Jaynshare] 401 on "${account.name}" — token rejected; forcing refresh and retrying`);
  await exchange.accountManager.refreshTokenAfterRejection(account.index);
  if (exchange.res.destroyed) return;
  return forwardRequest(exchange, retryCount + 1, route);
}

async function relayResponse({ res, accountManager, ctx }, { account, log }, upstreamRes) {
  log.head();
  log.get()?.write(`\n\n=== RESPONSE ${upstreamRes.status} ===\n${formatHeaders(upstreamRes.headers)}`);

  ctx.status = upstreamRes.status;
  res.writeHead(upstreamRes.status, clientResponseHeaders(upstreamRes.headers.entries()));

  if (!upstreamRes.body) {
    const requestLog = log.get();
    if (requestLog) { requestLog.write('\n\n=== RESPONSE BODY ===\n(empty)'); requestLog.end(); }
    res.end();
    return;
  }

  const contentType = upstreamRes.headers.get('content-type') || '';
  const isStreaming = contentType.includes('text/event-stream');

  if (isStreaming) {
    const requestLog = log.get();
    const bodyWriter = requestLog ? requestLog.bodyWriter('RESPONSE BODY (streamed)', contentType) : null;
    await streamResponse(upstreamRes.body, res, { accountManager, accountIndex: account.index, bodyWriter });
    requestLog?.end();
  } else {
    const buf = Buffer.from(await upstreamRes.arrayBuffer());
    extractUsageFromBody(buf, account.index, accountManager);
    const requestLog = log.get();
    if (requestLog) { requestLog.body('RESPONSE BODY', buf, contentType); requestLog.end(); }
    res.end(buf);
  }
}

function isTransientUpstreamError(err) {
  return err instanceof Error &&
    (err.code === 'JAYNSHARE_HEADERS_TIMEOUT' || err.code === 'JAYNSHARE_BODY_TIMEOUT' ||
      err.name === 'TimeoutError' || err.name === 'AbortError' ||
      err.message.includes('fetch failed') ||
      err.code === 'ECONNRESET' || err.code === 'ECONNREFUSED' ||
      err.code === 'ETIMEDOUT' || err.code === 'UND_ERR_CONNECT_TIMEOUT' ||
      err.code === 'UND_ERR_HEADERS_TIMEOUT' || err.code === 'UND_ERR_BODY_TIMEOUT');
}

async function handleUpstreamError(exchange, { account, retryCount, route, log }, err) {
  const { res, accountManager, ctx } = exchange;
  console.error(`[Jaynshare] Upstream error (account "${account.name}"):`, err.message);

  log.head();
  const requestLog = log.get();
  if (requestLog) { requestLog.write(`\n\n=== ERROR ===\n${err.stack || err.message}`); requestLog.end(); }

  // The fetch pool is process-wide, so failing over would not help; a fast failure evicts the dead socket.
  if (isTransientUpstreamError(err)) {
    res.destroy();
    return;
  }

  // A throw is never proof of a bad credential (that is a 401 response), so the account is only skipped this request.
  if (retryCount < accountManager.accounts.length && !res.headersSent) {
    ctx.tried.add(account.index);
    return forwardRequest(exchange, retryCount + 1, route);
  }
  ctx.status = 502;

  if (!res.headersSent) {
    sendJson(res, 502, apiError('proxy_error', `Upstream error: ${err.message}`));
  } else if (!res.writableEnded) {
    res.destroy(); // a broken response makes the client retry; a clean end would not
  }
}

// Resets on every chunk; the headers timeout in upstream-fetch.js covers only time-to-first-byte.
const DEFAULT_BODY_IDLE_TIMEOUT_MS = 120_000;

function resolveBodyIdleTimeout() {
  const env = Number(process.env.JAYNSHARE_UPSTREAM_BODY_TIMEOUT_MS);
  return env > 0 ? env : DEFAULT_BODY_IDLE_TIMEOUT_MS;
}

// Rejects with JAYNSHARE_BODY_TIMEOUT when no chunk arrives within `ms`.
export function readWithIdleTimeout(reader, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error(`upstream stream idle for ${ms}ms`);
      err.code = 'JAYNSHARE_BODY_TIMEOUT';
      reject(err);
    }, ms);
    timer.unref?.();
  });
  const read = reader.read();
  read.catch(() => {}); // abandoned when the timeout wins
  return Promise.race([read, timeout]).finally(() => clearTimeout(timer));
}

async function streamResponse(webStream, res, { accountManager, accountIndex, bodyWriter }) {
  const reader = webStream.getReader();
  const idleMs = resolveBodyIdleTimeout();
  const decoder = new TextDecoder();
  let sseBuffer = '';
  let errored = false;

  try {
    while (true) {
      const { done, value } = await readWithIdleTimeout(reader, idleMs);
      if (done) break;
      if (res.destroyed) break;

      const ok = res.write(value);
      if (bodyWriter) bodyWriter.chunk(Buffer.from(value));

      sseBuffer += decoder.decode(value, { stream: true });
      const events = sseBuffer.split('\n\n');
      sseBuffer = events.pop(); // incomplete event
      for (const event of events) {
        parseSSEUsage(event, accountIndex, accountManager);
      }

      if (!ok) { // backpressure; 'drain' never fires on a destroyed socket
        await new Promise(resolve => {
          const done = () => { res.off('drain', done); res.off('close', done); resolve(); };
          res.once('drain', done);
          res.once('close', done);
        });
        if (res.destroyed) break;
      }
    }

    if (sseBuffer.trim()) {
      parseSSEUsage(sseBuffer, accountIndex, accountManager);
    }
  } catch (err) {
    errored = true; // the caller destroys the response; a clean end would suppress the client's retry
    throw err;
  } finally {
    reader.cancel().catch(() => {}); // evicts a dead socket from the pool
    if (!errored && !res.writableEnded) res.end();
  }
}

function parseSSEUsage(event, accountIndex, accountManager) {
  const dataLine = event.split('\n').find(l => l.startsWith('data: '));
  if (!dataLine) return;

  try {
    const data = JSON.parse(dataLine.slice(6));
    if (data.type === 'message_start' && data.message?.usage) {
      accountManager.updateUsage(accountIndex, data.message.usage.input_tokens, 0);
    } else if (data.type === 'message_delta' && data.usage) {
      accountManager.updateUsage(accountIndex, 0, data.usage.output_tokens);
    }
  } catch {
    // not JSON
  }
}

function extractUsageFromBody(buffer, accountIndex, accountManager) {
  try {
    const json = JSON.parse(buffer.toString());
    if (json.usage) {
      accountManager.updateUsage(accountIndex, json.usage.input_tokens, json.usage.output_tokens);
    }
  } catch {
    // not JSON
  }
}

export function rewriteModel(body, modelMap) {
  try {
    const obj = JSON.parse(body.toString('utf8'));
    if (obj.model && modelMap[obj.model]) {
      obj.model = modelMap[obj.model];
      return Buffer.from(JSON.stringify(obj), 'utf8');
    }
  } catch { /* not JSON */ }
  return body;
}

function computeRetryAfter(accounts) {
  let soonest = Infinity;
  for (const acct of accounts) {
    const reset = acct.rateLimitedUntil || acct.quota.resetsAt;
    if (reset) {
      const ms = new Date(reset).getTime() - Date.now();
      if (ms < soonest) soonest = ms;
    }
  }
  return soonest === Infinity ? 60 : Math.max(1, Math.ceil(soonest / 1000));
}
