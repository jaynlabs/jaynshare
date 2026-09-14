// Corporate HTTP CONNECT proxy for outbound traffic (config `upstreamProxy` or
// HTTPS_PROXY); when sx routes an attempt, sx wins.

import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { connectThroughProxy } from './sx.js';

export function parseProxyUrl(value) {
  if (!value || typeof value !== 'string') return null;
  const raw = value.trim();
  if (!raw) return null;

  const withScheme = /^[a-z0-9+.-]+:\/\//i.test(raw) ? raw : `http://${raw}`;
  let u;
  try {
    u = new URL(withScheme);
  } catch {
    throw new Error(`invalid proxy URL: ${value}`);
  }
  if (!/^https?:$/.test(u.protocol)) {
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
    username: u.username ? decodeURIComponent(u.username) : null,
    password: u.password ? decodeURIComponent(u.password) : null,
  };
}

// Credentials intact: for the config file only. Logs and the TUI use describeProxy().
export function proxyToUrl(proxy) {
  if (!proxy) return null;
  const auth = proxy.username
    ? `${encodeURIComponent(proxy.username)}${proxy.password ? `:${encodeURIComponent(proxy.password)}` : ''}@`
    : '';
  return `http://${auth}${proxy.host}:${proxy.port}`;
}

export function describeProxy(proxy) {
  if (!proxy) return 'none';
  const auth = proxy.username ? `${proxy.username}:***@` : '';
  return `http://${auth}${proxy.host}:${proxy.port}`;
}

// NO_PROXY as curl reads it: comma-separated suffixes, optional leading dot,
// port ignored, `*` bypasses everything.
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

// Process-wide: how this host reaches the network, shared by every outbound path.
let current = null;

export function setUpstreamProxy(resolved) {
  current = resolved || { proxy: null, source: 'none', noProxy: null };
  return current;
}

export function getUpstreamProxy() {
  if (!current) {
    // Commands that never load a config still honour the environment; loadConfig validates loudly.
    try { current = resolveUpstreamProxy({}, process.env); } catch { current = { proxy: null, source: 'none', noProxy: null }; }
  }
  return current;
}

export function resetUpstreamProxy() { current = null; }

export function proxyForHost(hostname) {
  const { proxy, noProxy } = getUpstreamProxy();
  if (!proxy) return null;
  if (bypassesProxy(hostname, noProxy)) return null;
  return proxy;
}

// An http(s).Agent whose sockets are CONNECT tunnels through `proxy`.
export function proxyAgent(proxy, { targetHost, targetPort, tls: useTls = true, tlsOptions = {} }) {
  const agent = new (useTls ? https : http).Agent({ keepAlive: false }); // one target per socket; pooling would leak
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
          cb(null, sock);
          sock.resume(); // connectThroughProxy leaves the socket paused
          return;
        }
        const tlsSock = tls.connect({ socket: sock, servername: targetHost, ...tlsOptions });
        const onErr = (err) => { tlsSock.removeListener('secureConnect', onOk); sock.destroy(); cb(err); };
        const onOk = () => { tlsSock.removeListener('error', onErr); cb(null, tlsSock); };
        tlsSock.once('secureConnect', onOk);
        tlsSock.once('error', onErr);
      })
      .catch((err) => cb(err));
    return undefined;
  };
  return agent;
}
