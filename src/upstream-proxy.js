// Outbound (egress) proxy for everything jaynshare sends to Anthropic.
//
// Distinct from two other things that also say "proxy" in this codebase:
//   - `config.proxy` is the LOCAL server Claude Code talks to (inbound).
//   - `config.sx` is the sx.org residential-egress integration, a specific
//     paid provider with its own provisioning API and its own routing policy
//     (always / on-429 / off).
// This one is the plain corporate case: the machine cannot open a socket to
// api.anthropic.com at all, and every outbound connection has to go through an
// HTTP CONNECT proxy. It is not a routing policy — when set, it is
// simply how this host reaches the internet.
//
// Node's global fetch cannot use a CONNECT proxy without undici, and "zero
// dependencies" is a project feature, so the tunnel is built by hand on top of
// the same connectThroughProxy() the sx path uses.
//
// Precedence: an explicit request to route via sx wins (sx IS an egress proxy;
// chaining one through the other would be two hops to solve one problem). With
// sx off or not selected for this attempt, the upstream proxy applies.

import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { connectThroughProxy } from './sx.js';

/**
 * Parse a proxy URL into the shape connectThroughProxy wants.
 *
 * Accepts `http://host:port`, `http://user:pass@host:port`, and a bare
 * `host:port` (people write proxies that way constantly, and rejecting it would
 * be pedantry). Returns null for empty input; throws on input that looks like a
 * URL but isn't usable, so a typo in the config surfaces at startup rather than
 * as a mystery connection failure on the first request.
 */
export function parseProxyUrl(value) {
  if (!value || typeof value !== 'string') return null;
  const raw = value.trim();
  if (!raw) return null;

  // A bare host:port has no scheme; give it one so URL can do the parsing.
  const withScheme = /^[a-z0-9+.-]+:\/\//i.test(raw) ? raw : `http://${raw}`;
  let u;
  try {
    u = new URL(withScheme);
  } catch {
    throw new Error(`invalid proxy URL: ${value}`);
  }
  if (!/^https?:$/.test(u.protocol)) {
    // socks5:// is a different wire protocol, not a CONNECT proxy — say so
    // plainly instead of failing later inside the tunnel.
    throw new Error(`unsupported proxy protocol "${u.protocol.replace(/:$/, '')}" (only http/https): ${value}`);
  }
  if (!u.hostname) throw new Error(`proxy URL has no host: ${value}`);

  const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`proxy URL has an invalid port: ${value}`);
  }
  return {
    host: u.hostname,
    port,
    // decodeURIComponent so a password containing e.g. %40 survives the round trip.
    username: u.username ? decodeURIComponent(u.username) : null,
    password: u.password ? decodeURIComponent(u.password) : null,
  };
}

/**
 * Render a proxy back to a storable URL, credentials intact. For writing the
 * config — never for logs or the screen, which must use describeProxy().
 */
export function proxyToUrl(proxy) {
  if (!proxy) return null;
  const auth = proxy.username
    ? `${encodeURIComponent(proxy.username)}${proxy.password ? `:${encodeURIComponent(proxy.password)}` : ''}@`
    : '';
  return `http://${auth}${proxy.host}:${proxy.port}`;
}

/** Render a proxy back to a string, with the password masked. For logs and the TUI. */
export function describeProxy(proxy) {
  if (!proxy) return 'none';
  const auth = proxy.username ? `${proxy.username}:***@` : '';
  return `http://${auth}${proxy.host}:${proxy.port}`;
}

/**
 * NO_PROXY matching, in the form everyone else implements it: a comma-separated
 * list of suffixes, where a leading dot is optional and `*` disables the proxy
 * entirely. Matching is on the hostname only — the port-qualified form
 * (`host:443`) is accepted and its port ignored, which is what curl does.
 */
export function bypassesProxy(hostname, noProxy) {
  if (!noProxy || !hostname) return false;
  const host = hostname.toLowerCase().replace(/\.$/, '');
  for (const raw of String(noProxy).split(',')) {
    const entry = raw.trim().toLowerCase().replace(/:\d+$/, '').replace(/^\./, '').replace(/\.$/, '');
    if (!entry) continue;
    if (entry === '*') return true;
    if (host === entry || host.endsWith(`.${entry}`)) return true;
  }
  return false;
}

/**
 * Where the proxy setting comes from, in precedence order: the config file
 * first (explicit and persistent), then the conventional environment variables.
 *
 * Honouring the environment matters: an operator who has already set
 * HTTPS_PROXY reasonably expects it to be used, and it is what every other CLI
 * on that machine does. `config.upstreamProxy: false`
 * opts out entirely, for a host where the variables are set for other tools but
 * must not apply here.
 */
export function resolveUpstreamProxy(config = {}, env = process.env) {
  if (config.upstreamProxy === false) return { proxy: null, source: 'disabled', noProxy: null };

  const noProxy = config.noProxy ?? env.NO_PROXY ?? env.no_proxy ?? null;

  if (config.upstreamProxy) {
    return { proxy: parseProxyUrl(config.upstreamProxy), source: 'config', noProxy };
  }
  const candidates = [
    ['HTTPS_PROXY', env.HTTPS_PROXY], ['https_proxy', env.https_proxy],
    ['ALL_PROXY', env.ALL_PROXY], ['all_proxy', env.all_proxy],
  ];
  for (const [name, value] of candidates) {
    if (value) return { proxy: parseProxyUrl(value), source: `env:${name}`, noProxy };
  }
  return { proxy: null, source: 'none', noProxy };
}

// ── Process-wide state ───────────────────────────────────────
//
// A single setting for the whole process rather than a value threaded through
// every call: it describes how this HOST reaches the network, so every outbound
// path (request forwarding, token refresh, profile and usage lookups) must agree
// on it. Threading it would mean passing config into oauth.js, which has no
// business knowing about config.

// Undefined until something resolves it. Reading it falls back to the
// environment alone, so short-lived commands that never load a config (and any
// code path that runs before startup wiring) still honour HTTPS_PROXY instead of
// silently going direct. A bad value in the environment must not take a command
// down, so a parse failure degrades to "no proxy" here and is reported loudly at
// startup, where the config value is validated eagerly.
let current = null;

export function setUpstreamProxy(resolved) {
  current = resolved || { proxy: null, source: 'none', noProxy: null };
  return current;
}

export function getUpstreamProxy() {
  if (!current) {
    try { current = resolveUpstreamProxy({}, process.env); } catch { current = { proxy: null, source: 'none', noProxy: null }; }
  }
  return current;
}

/** Reset the memo. Tests only. */
export function resetUpstreamProxy() { current = null; }

/** The proxy to use for `hostname`, or null when going direct. */
export function proxyForHost(hostname) {
  const { proxy, noProxy } = getUpstreamProxy();
  if (!proxy) return null;
  if (bypassesProxy(hostname, noProxy)) return null;
  return proxy;
}

/**
 * An http(s).Agent whose sockets are CONNECT tunnels through `proxy`.
 *
 * keepAlive is off: createConnection closes over one target, so a pooled socket
 * could not be reused for a different host anyway, and parking it would leak an
 * open proxy connection per request. The upstream path's reason for pooling
 * (avoiding a single multiplexed h2 connection) still holds, because each
 * tunnel is its own TCP connection carrying its own HTTP/1.1 exchange.
 */
export function proxyAgent(proxy, { targetHost, targetPort, tls: useTls = true, tlsOptions = {} }) {
  const agent = new (useTls ? https : http).Agent({ keepAlive: false });
  agent.createConnection = (_options, cb) => {
    connectThroughProxy({
      proxyHost: proxy.host,
      proxyPort: proxy.port,
      auth: proxy.username ? `${proxy.username}:${proxy.password ?? ''}` : null,
      targetHost,
      targetPort,
      label: 'upstream proxy',
    })
      .then((sock) => {
        if (!useTls) {
          // connectThroughProxy pauses the socket so a TLS layer sees every
          // byte. Nothing resumes it on the plaintext path, so the HTTP parser
          // would attach to a socket that never flows and the request would sit
          // until the headers deadline. Resume after the caller has it.
          cb(null, sock);
          sock.resume();
          return;
        }
        // TLS is established end-to-end over the tunnel, so the proxy sees only
        // ciphertext and cert verification stays at its secure default.
        const tlsSock = tls.connect({ socket: sock, servername: targetHost, ...tlsOptions });
        const onErr = (err) => { tlsSock.removeListener('secureConnect', onOk); sock.destroy(); cb(err); };
        const onOk = () => { tlsSock.removeListener('error', onErr); cb(null, tlsSock); };
        tlsSock.once('secureConnect', onOk);
        tlsSock.once('error', onErr);
      })
      .catch((err) => cb(err));
    return undefined; // socket is delivered asynchronously through cb
  };
  return agent;
}
