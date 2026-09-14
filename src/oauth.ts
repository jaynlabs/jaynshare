import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { randomBytes, createHash } from 'node:crypto';
import { exec, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';
import http from 'node:http';
import { proxyFetch } from './upstream-fetch.ts';
import type { FakeResponse } from './upstream-fetch.ts';

const execFileAsync = promisify(execFile);

const DEFAULT_CREDENTIALS_PATH = '~/.claude/.credentials.json';
const KEYCHAIN_SERVICE = 'Claude Code-credentials';

interface RawCredentials {
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: number;
  subscriptionType?: string;
  rateLimitTier?: string;
  claudeAiOauth?: RawCredentials;
  [key: string]: any;
}

export interface ImportedCredentials {
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: number;
  subscriptionType?: string;
  rateLimitTier?: string;
}

export interface RefreshedTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

async function readKeychainCredentials(): Promise<RawCredentials> {
  const { stdout } = await execFileAsync('security', ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-w']);
  return JSON.parse(stdout.trim());
}

export async function importCredentials(filePath: string, {
  home = homedir(), platform = process.platform, readKeychain = readKeychainCredentials }:
  { home?: string; platform?: string; readKeychain?: () => Promise<RawCredentials> } = {}): Promise<ImportedCredentials> {
  const resolvedPath = filePath.replace(/^~/, home);
  let raw: RawCredentials;
  try {
    raw = JSON.parse(await readFile(resolvedPath, 'utf-8'));
  } catch (err) {
    const isDefaultPath = resolvedPath === DEFAULT_CREDENTIALS_PATH.replace(/^~/, home);
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT' || platform !== 'darwin' || !isDefaultPath) throw err;
    try {
      raw = await readKeychain();
    } catch (keychainError) {
      throw new Error(`${(err as Error).message}; macOS Keychain lookup for "${KEYCHAIN_SERVICE}" also failed: ${(keychainError as Error).message}`);
    }
  }

  const data = raw.claudeAiOauth || raw;
  return {
    accessToken: data.accessToken,
    refreshToken: data.refreshToken,
    expiresAt: data.expiresAt,
    subscriptionType: data.subscriptionType,
    rateLimitTier: data.rateLimitTier,
  };
}

const PROFILE_URL = 'https://api.anthropic.com/api/oauth/profile';
const USAGE_URL = 'https://api.anthropic.com/api/oauth/usage';
const OAUTH_USAGE_BETA = 'oauth-2025-04-20';
const DEFAULT_TOKEN_ENDPOINT = 'https://platform.claude.com/v1/oauth/token';
const DEFAULT_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';

const REFRESH_MAX_RETRIES = 2;
const REFRESH_BASE_DELAY_MS = 500;

export async function refreshAccessToken(refreshToken: string, endpoint: string = DEFAULT_TOKEN_ENDPOINT): Promise<RefreshedTokens> {
  for (let attempt = 0; attempt <= REFRESH_MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      await new Promise(resolve => setTimeout(resolve, REFRESH_BASE_DELAY_MS * 2 ** (attempt - 1)));
    }
    try {
      return await requestTokenRefresh(refreshToken, endpoint);
    } catch (err) {
      if (attempt === REFRESH_MAX_RETRIES || !isRetriableRefreshError(err)) throw err;
    }
  }
  throw new Error('unreachable');
}

async function requestTokenRefresh(refreshToken: string, endpoint: string): Promise<RefreshedTokens> {
  const timeoutMs = Number(process.env.JAYNSHARE_REFRESH_TIMEOUT_MS) || 30_000;
  const res = await proxyFetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/plain, */*',
      'User-Agent': 'axios/1.13.6',
    },
    body: JSON.stringify({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: DEFAULT_CLIENT_ID,
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!res.ok) {
    const text = await res.text();
    const err = new Error(`Token refresh failed (${res.status}): ${text}`) as Error & { status?: number };
    err.status = res.status; // lets callers tell an auth rejection from a transient error
    throw err;
  }

  const data = await res.json();
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || refreshToken,
    expiresAt: tokenExpiry(data),
  };
}

/** A server fault or a dropped connection; an auth rejection is final. */
function isRetriableRefreshError(err: unknown): boolean {
  const e = err as (Error & { status?: number; code?: string });
  if ((e?.status ?? 0) >= 500) return true;
  if (!(err instanceof Error)) return false;
  return e.name === 'TimeoutError' || e.name === 'AbortError'
    || e.message.includes('fetch failed')
    || ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT'].includes(e.code ?? '');
}

function normalizeExpiresAt(expiresAt: number | undefined | null): number | undefined | null {
  if (!expiresAt) return expiresAt;
  return expiresAt < 1e12 ? expiresAt * 1000 : expiresAt; // OAuth returns seconds, Claude Code stores milliseconds
}

export function isTokenExpiringSoon(expiresAt: number | null | undefined, thresholdMs = 5 * 60 * 1000): boolean {
  if (!expiresAt) return false;
  return Date.now() + thresholdMs >= normalizeExpiresAt(expiresAt)!;
}

export function isTokenExpired(expiresAt: number | null | undefined): boolean {
  if (!expiresAt) return false;
  return Date.now() >= normalizeExpiresAt(expiresAt)!;
}

/** The human-readable part of an upstream error reply; empty when there is none. */
async function upstreamErrorDetail(res: FakeResponse): Promise<string> {
  try {
    const body = await res.json();
    return body?.error?.message || JSON.stringify(body).slice(0, 200);
  } catch {
    return await res.text().catch(() => '');
  }
}

/** `HTTP 429: rate limited` — status always, detail when the body carries one. */
async function httpErrorMessage(res: FakeResponse): Promise<string> {
  const detail = await upstreamErrorDetail(res);
  return `HTTP ${res.status}${detail ? ': ' + detail : ''}`;
}

/** The token's absolute expiry, or one `expires_in` from now when upstream omits it. */
function tokenExpiry({ expires_at, expires_in }: { expires_at?: number; expires_in?: number }): number {
  return normalizeExpiresAt(expires_at) || (Date.now() + (expires_in || 3600) * 1000);
}

export interface ProfileResult {
  accountUuid?: string;
  email?: string;
  name?: string;
  orgUuid?: string;
  orgName?: string;
  orgType?: string;
  hasClaudeMax?: boolean;
  hasClaudePro?: boolean;
  error?: string;
}

export async function fetchProfile(accessToken: string): Promise<ProfileResult> {
  try {
    const res = await proxyFetch(PROFILE_URL, {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    if (!res.ok) return { error: await httpErrorMessage(res) };
    const data = await res.json();
    return {
      accountUuid: data.account?.uuid,
      email: data.account?.email,
      name: data.account?.display_name,
      orgUuid: data.organization?.uuid,
      orgName: data.organization?.name,
      orgType: data.organization?.organization_type,
      hasClaudeMax: data.account?.has_claude_max,
      hasClaudePro: data.account?.has_claude_pro,
    };
  } catch (err) {
    return { error: (err as Error).message || String(err) };
  }
}

interface ScopedLimit {
  utilization: number | null;
  resets_at: unknown;
}

// Model-scoped weekly quota lives in `limits[]`, not in a top-level `seven_day_<model>` key.
export function findScopedWeeklyLimit(data: any, modelNamePattern: RegExp): ScopedLimit | null {
  const limits: any[] = Array.isArray(data?.limits) ? data.limits : [];
  const entry = limits.find((limit) =>
    limit && limit.group === 'weekly' && limit.scope?.model?.display_name
    && modelNamePattern.test(limit.scope.model.display_name));
  if (!entry) return null;
  return { utilization: entry.percent, resets_at: entry.resets_at };
}

export interface UsageBucket {
  utilization: number | null;
  resetAt: number | null;
}

export function normalizeUsageBucket(bucket: any): UsageBucket | null {
  if (!bucket || typeof bucket !== 'object') return null;

  const rawPct: unknown = bucket.used_percentage ?? bucket.utilization ?? bucket.usedPercentage;
  const parsedPct = typeof rawPct === 'number' ? rawPct : parseFloat(String(rawPct));
  const utilization = Number.isFinite(parsedPct) ? parsedPct / 100 : null; // the endpoint reports 0–100

  const rawReset: unknown = bucket.resets_at ?? bucket.resetsAt ?? bucket.reset_at ?? bucket.resetAt;
  let resetAt: number | null = null;
  if (typeof rawReset === 'number') {
    resetAt = rawReset < 1e12 ? rawReset * 1000 : rawReset;
  } else if (typeof rawReset === 'string') {
    const asNum = Number(rawReset);
    if (Number.isFinite(asNum) && rawReset.trim() !== '') {
      resetAt = asNum < 1e12 ? asNum * 1000 : asNum;
    } else {
      const parsed = Date.parse(rawReset);
      if (Number.isFinite(parsed)) resetAt = parsed;
    }
  }

  return { utilization, resetAt };
}

export interface UsageResult {
  fiveHour?: UsageBucket | null;
  sevenDay?: UsageBucket | null;
  sevenDaySonnet?: UsageBucket | null;
  sevenDayFable?: UsageBucket | null;
  error?: string;
  status?: number | null;
}

// Zero-spend, so safe to poll.
export async function fetchUsage(accessToken: string): Promise<UsageResult> {
  try {
    const res = await proxyFetch(USAGE_URL, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'anthropic-beta': OAUTH_USAGE_BETA,
        'Accept': 'application/json',
      },
    });

    if (!res.ok) {
      return { error: await httpErrorMessage(res), status: res.status };
    }

    const data = await res.json();
    return {
      fiveHour: normalizeUsageBucket(data?.five_hour),
      sevenDay: normalizeUsageBucket(data?.seven_day),
      sevenDaySonnet: normalizeUsageBucket(data?.seven_day_sonnet),
      sevenDayFable: normalizeUsageBucket(findScopedWeeklyLimit(data, /fable/i)),
    };
  } catch (err) {
    return { error: (err as Error).message || String(err), status: null };
  }
}

const OAUTH_AUTHORIZE = 'https://claude.ai/oauth/authorize';
const OAUTH_SCOPES = 'org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload';

export async function loginOAuth(): Promise<RefreshedTokens> {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  const state = randomBytes(32).toString('base64url');

  const { port, codePromise, server } = await startCallbackServer(state);
  const redirectUri = `http://localhost:${port}/callback`;
  const authUrl = buildAuthorizeUrl({ redirectUri, codeChallenge, state });

  console.log('Opening browser for authentication...');
  console.log(`If it doesn't open, visit:\n  ${authUrl}\n`);
  openBrowser(authUrl);

  let code: string;
  try {
    code = await raceWithStdinCode(codePromise, state);
  } finally {
    server.close();
  }

  console.log('Exchanging authorization code for tokens...');
  return exchangeCodeForTokens({ code, state, redirectUri, codeVerifier });
}

function buildAuthorizeUrl({ redirectUri, codeChallenge, state }:
  { redirectUri: string; codeChallenge: string; state: string }): string {
  const authUrl = new URL(OAUTH_AUTHORIZE);
  authUrl.searchParams.set('code', 'true');
  authUrl.searchParams.set('client_id', DEFAULT_CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', OAUTH_SCOPES);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);
  return authUrl.toString();
}

async function exchangeCodeForTokens({ code, state, redirectUri, codeVerifier }:
  { code: string; state: string; redirectUri: string; codeVerifier: string }): Promise<RefreshedTokens> {
  const tokenRes = await proxyFetch(DEFAULT_TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      state,
      grant_type: 'authorization_code',
      client_id: DEFAULT_CLIENT_ID,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    throw new Error(`Token exchange failed (${tokenRes.status}): ${text}`);
  }

  const tokens = await tokenRes.json();
  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt: tokenExpiry(tokens),
  };
}

// The user can paste the full callback URL or just the code.
function raceWithStdinCode(callbackPromise: Promise<string>, expectedState: string): Promise<string> {
  if (!process.stdin.isTTY) return callbackPromise;

  return new Promise((resolve, reject) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    let settled = false;

    const settle = (fn: (v: any) => void, val: any) => {
      if (settled) return;
      settled = true;
      rl.close();
      fn(val);
    };

    rl.question('Paste authorization code here (or wait for browser callback): ', answer => {
      const trimmed = (answer || '').trim();
      if (!trimmed) return; // keep waiting for the callback

      try {
        const url = new URL(trimmed);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        if (code) {
          if (expectedState && state && state !== expectedState) {
            settle(reject, new Error('OAuth state mismatch'));
          } else {
            settle(resolve, code);
          }
          return;
        }
      } catch {}

      settle(resolve, trimmed);
    });

    callbackPromise.then(
      code => settle(resolve, code),
      err => settle(reject, err),
    );
  });
}

function startCallbackServer(expectedState: string): Promise<{ port: number; codePromise: Promise<string>; server: http.Server }> {
  return new Promise((resolve, reject) => {
    let resolveCode!: (code: string) => void;
    let rejectCode!: (err: Error) => void;
    const codePromise = new Promise<string>((res, rej) => { resolveCode = res; rejectCode = rej; });

    const server = http.createServer((req, res) => {
      const url = new URL(req.url || '/', `http://localhost`);

      if (url.pathname === '/callback') {
        const code = url.searchParams.get('code');
        const error = url.searchParams.get('error');
        const state = url.searchParams.get('state');

        if (error) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h2>Authentication failed</h2><p>You can close this tab.</p></body></html>');
          rejectCode(new Error(`OAuth error: ${error} - ${url.searchParams.get('error_description') || ''}`));
          return;
        }

        if (expectedState && state !== expectedState) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h2>Authentication failed</h2><p>State mismatch. You can close this tab.</p></body></html>');
          rejectCode(new Error('OAuth state mismatch'));
          return;
        }

        if (code) {
          res.writeHead(302, { 'Location': 'https://platform.claude.com/oauth/code/success?app=claude-code' });
          res.end();
          resolveCode(code);
          return;
        }
      }

      res.writeHead(404);
      res.end('Not found');
    });

    server.listen(0, () => {
      resolve({ port: (server.address() as any).port, codePromise, server });
    });
    server.on('error', reject);

    const timer = setTimeout(() => {
      rejectCode(new Error('Login timed out after 2 minutes'));
      server.close();
    }, 120_000);
    timer.unref();
  });
}

function openBrowser(url: string): void {
  const platform = process.platform;
  const cmd = platform === 'darwin' ? 'open'
    : platform === 'win32' ? 'start'
    : 'xdg-open';
  exec(`${cmd} ${JSON.stringify(url)}`, () => {});
}
