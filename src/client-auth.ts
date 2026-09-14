import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Config, Principal, ProxyClientConfig } from './types.ts';

const HASH_PREFIX = 'sha256:';
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const CLIENT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;

export function generateClientSecret(): string {
  return `jaynshare-client-${randomBytes(24).toString('base64url')}`;
}

export function hashClientSecret(secret: string): string {
  if (typeof secret !== 'string' || !secret) throw new Error('client secret must not be empty');
  return HASH_PREFIX + createHash('sha256').update(secret, 'utf8').digest('hex');
}

export function validClientId(id: unknown): id is string {
  return typeof id === 'string' && CLIENT_ID_RE.test(id);
}

export function validateClientConfig(proxy: Partial<ProxyConfigShape> = {}): ProxyConfigShape {
  const seen = new Set<string>();
  for (const client of proxy.clients || []) {
    if (!validClientId(client?.id)) {
      throw new Error(`invalid proxy client id "${client?.id ?? ''}" (use lowercase letters, numbers, _ or -)`);
    }
    if (seen.has(client.id)) throw new Error(`duplicate proxy client id "${client.id}"`);
    seen.add(client.id);
    if (typeof client.keyHash !== 'string' || !HASH_RE.test(client.keyHash)) {
      throw new Error(`proxy client "${client.id}" has an invalid keyHash`);
    }
  }
  if (proxy.adminKeyHash != null
      && (typeof proxy.adminKeyHash !== 'string' || !HASH_RE.test(proxy.adminKeyHash))) {
    throw new Error('proxy.adminKeyHash is invalid');
  }
  return proxy as ProxyConfigShape;
}

interface ProxyConfigShape {
  clients?: ProxyClientConfig[];
  adminKeyHash?: string;
  apiKey?: string;
  [key: string]: any;
}

function safeEqual(a: unknown, b: unknown): boolean {
  const ba = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

function matchesHash(secret: string, expected: string | undefined): boolean {
  if (!secret || !expected) return false;
  return safeEqual(hashClientSecret(secret), expected);
}

export function resolvePrincipal(config: Config | null | undefined, secret: string | undefined,
  { local = false }: { local?: boolean } = {}): Principal | null {
  if (local) return { role: 'operator', clientId: 'local', clientName: 'Local operator', local: true };
  const proxy: ProxyConfigShape = config?.proxy || {};
  if (!Object.hasOwn(proxy, 'clients') && !proxy.adminKeyHash && !proxy.apiKey) { // a config predating the client registry is open
    return { role: 'operator', clientId: 'anonymous-legacy', clientName: 'Anonymous legacy client', local: false, legacy: true };
  }
  if (matchesHash(secret ?? '', proxy.adminKeyHash ?? '')) {
    return { role: 'operator', clientId: 'operator', clientName: 'Remote operator', local: false, credentialHash: proxy.adminKeyHash };
  }
  for (const client of proxy.clients || []) {
    if (!client.disabled && matchesHash(secret ?? '', client.keyHash ?? '')) {
      return { role: 'client', clientId: client.id, clientName: client.name || client.id, local: false, credentialHash: client.keyHash };
    }
  }
  if (proxy.apiKey && safeEqual(secret, proxy.apiKey)) { // plaintext key; `client migrate` replaces it
    return { role: 'operator', clientId: 'legacy', clientName: 'Legacy client', local: false, legacy: true, credentialHash: hashClientSecret(secret ?? '') };
  }
  return null;
}

export function principalStillAuthorized(config: Config | null | undefined, principal: Principal | null): boolean {
  if (!principal) return false;
  if (principal.local) return true;
  const proxy: ProxyConfigShape = config?.proxy || {};
  if (principal.clientId === 'anonymous-legacy') {
    return !Object.hasOwn(proxy, 'clients') && !proxy.adminKeyHash && !proxy.apiKey;
  }
  if (principal.clientId === 'operator') {
    return !!principal.credentialHash && safeEqual(principal.credentialHash, proxy.adminKeyHash);
  }
  if (principal.clientId === 'legacy') {
    return !!proxy.apiKey && !!principal.credentialHash
      && safeEqual(principal.credentialHash, hashClientSecret(proxy.apiKey));
  }
  const client = (proxy.clients || []).find(candidate => candidate.id === principal.clientId);
  return !!client && !client.disabled && !!principal.credentialHash
    && safeEqual(principal.credentialHash, client.keyHash ?? '');
}

export function clientById(config: Config | null | undefined, id: string): ProxyClientConfig | null {
  return (config?.proxy?.clients || []).find(client => client.id === id) || null;
}
