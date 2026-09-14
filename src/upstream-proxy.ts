// Corporate HTTP CONNECT proxy for outbound traffic (config `upstreamProxy` or
// HTTPS_PROXY); when sx routes an attempt, sx wins.

import http from 'node:http';
import https from 'node:https';
import { connectThroughProxy, tunnelTls } from './sx.ts';
import type { SxProxy } from './sx.ts';
import type { Config } from './types.ts';

export interface ParsedProxy {
  host: string;
  port: number;
  username: string | null;
  password: string | null;
}

export function parseProxyUrl(value: unknown): ParsedProxy | null {
  if (!value || typeof value !== 'string') return null;
  const raw = value.trim();
  if (!raw) return null;

  const withScheme = /^[a-z0-9+.-]+:\/\//i.test(raw) ? raw : `http://${raw}`;
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(withScheme);
  } catch {
    throw new Error(`invalid proxy URL: ${value}`);
  }
  if (!/^https?:$/.test(parsedUrl.protocol)) {
    throw new Error(`unsupported proxy protocol "${parsedUrl.protocol.replace(/:$/, '')}" (only http/https): ${value}`);
  }
  if (!parsedUrl.hostname) throw new Error(`proxy URL has no host: ${value}`);

  const port = parsedUrl.port ? Number(parsedUrl.port) : (parsedUrl.protocol === 'https:' ? 443 : 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`proxy URL has an invalid port: ${value}`);
  }
  return {
    host: parsedUrl.hostname,
    port,
    username: parsedUrl.username ? decodeURIComponent(parsedUrl.username) : null,
    password: parsedUrl.password ? decodeURIComponent(parsedUrl.password) : null,
  };
}

// Credentials intact: for the config file only. Logs and the TUI use describeProxy().
export function proxyToUrl(proxy: ParsedProxy | null | undefined): string | null {
  if (!proxy) return null;
  const auth = proxy.username
    ? `${encodeURIComponent(proxy.username)}${proxy.password ? `:${encodeURIComponent(proxy.password)}` : ''}@`
    : '';
  return `http://${auth}${proxy.host}:${proxy.port}`;
}

export function describeProxy(proxy: ParsedProxy | null | undefined): string {
  if (!proxy) return 'none';
  const auth = proxy.username ? `${proxy.username}:***@` : '';
  return `http://${auth}${proxy.host}:${proxy.port}`;
}

// NO_PROXY as curl reads it: comma-separated suffixes, optional leading dot,
// port ignored, `*` bypasses everything.
export function bypassesProxy(hostname: string, noProxy: string | null | undefined): boolean {
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

export interface ResolvedUpstreamProxy {
  proxy: ParsedProxy | null;
  source: string;
  noProxy: string | null;
}

export function resolveUpstreamProxy(config: Partial<Config> = {}, env: NodeJS.ProcessEnv = process.env): ResolvedUpstreamProxy {
  if (config.upstreamProxy === false) return { proxy: null, source: 'disabled', noProxy: null };

  const noProxy = config.noProxy ?? env.NO_PROXY ?? env.no_proxy ?? null;

  if (config.upstreamProxy) {
    return { proxy: parseProxyUrl(config.upstreamProxy), source: 'config', noProxy };
  }
  const candidates: [string, string | undefined][] = [
    ['HTTPS_PROXY', env.HTTPS_PROXY], ['https_proxy', env.https_proxy],
    ['ALL_PROXY', env.ALL_PROXY], ['all_proxy', env.all_proxy],
  ];
  for (const [name, value] of candidates) {
    if (value) return { proxy: parseProxyUrl(value), source: `env:${name}`, noProxy };
  }
  return { proxy: null, source: 'none', noProxy };
}

// Process-wide: how this host reaches the network, shared by every outbound path.
let current: ResolvedUpstreamProxy | null = null;

export function setUpstreamProxy(resolved?: ResolvedUpstreamProxy | null): ResolvedUpstreamProxy {
  current = resolved || { proxy: null, source: 'none', noProxy: null };
  return current;
}

export function getUpstreamProxy(): ResolvedUpstreamProxy {
  if (!current) {
    // Commands that never load a config still honour the environment; loadConfig validates loudly.
    try { current = resolveUpstreamProxy({}, process.env); } catch { current = { proxy: null, source: 'none', noProxy: null }; }
  }
  return current;
}

export function resetUpstreamProxy(): void { current = null; }

export function proxyForHost(hostname: string): ParsedProxy | null {
  const { proxy, noProxy } = getUpstreamProxy();
  if (!proxy) return null;
  if (bypassesProxy(hostname, noProxy)) return null;
  return proxy;
}

export interface ProxyAgentOptions {
  targetHost: string;
  targetPort: number;
  tls?: boolean;
  tlsOptions?: Record<string, any>;
}

// An http(s).Agent whose sockets are CONNECT tunnels through `proxy`.
export function proxyAgent(proxy: ParsedProxy, { targetHost, targetPort, tls: useTls = true, tlsOptions = {} }: ProxyAgentOptions): http.Agent {
  const agent = new (useTls ? https : http).Agent({ keepAlive: false }); // one target per socket; pooling would leak
  agent.createConnection = (function (this: http.Agent, _options: unknown, callback?: (err: Error | null, stream?: import('node:stream').Duplex) => void) {
    const sxProxy: import('./sx.ts').SxProxy = { ...proxy, portId: undefined };
    const tlsOverProxy = (): Promise<import('node:tls').TLSSocket> => tunnelTls({
      proxy: sxProxy,
      targetHost,
      targetPort,
      tlsOptions,
      label: 'upstream proxy',
    });
    const connectPlain = (): Promise<import('node:net').Socket> => connectThroughProxy({
      proxyHost: proxy.host,
      proxyPort: proxy.port,
      auth: proxy.username ? `${proxy.username}:${proxy.password ?? ''}` : null,
      targetHost,
      targetPort,
      label: 'upstream proxy',
    }).then((sock) => { sock.resume(); return sock; }); // the CONNECT helper leaves the socket paused

    (useTls ? tlsOverProxy : connectPlain)().then((sock) => callback?.(null, sock)).catch((err) => callback?.(err as Error));
    return undefined;
  }) as http.Agent['createConnection'];
  return agent;
}
