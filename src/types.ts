// Shared shapes: config files, runtime accounts, hook payloads, and the loose
// JSON records that flow between the server, the TUI, and the wire.

export interface ProxyClientConfig {
  id: string;
  name?: string;
  keyHash?: string;
  disabled?: boolean;
  [key: string]: any;
}

export interface ProxyConfig {
  port?: number;
  host?: string;
  clients?: ProxyClientConfig[];
  apiKey?: string;
  adminKeyHash?: string;
  [key: string]: any;
}

export interface AccountConfig {
  name: string;
  type: string;
  accountUuid?: string | null;
  orgUuid?: string | null;
  orgName?: string | null;
  priority?: number;
  disabled?: boolean;
  upstream?: string | null;
  modelMap?: Record<string, string> | null;
  models?: string[] | null;
  accessToken?: string | null;
  refreshToken?: string | null;
  expiresAt?: number | null;
  apiKey?: string | null;
  importFrom?: string;
  source?: string;
  [key: string]: any;
}

export interface RouteConfig {
  name?: string;
  match: string | string[];
  accounts?: (string | number)[];
  bucket?: string;
  color?: string;
  [key: string]: any;
}

export interface Config {
  proxy: ProxyConfig;
  upstream?: string;
  switchThreshold?: number;
  holdSeconds?: number;
  distributeSessions?: boolean;
  eventLogging?: string;
  blockedModels?: string[];
  routes?: RouteConfig[];
  accounts: AccountConfig[];
  quotaProbeSeconds?: number;
  warmupSeconds?: number;
  sx?: { apiKey?: string; mode?: string } | null;
  logDir?: string;
  auditLog?: { path?: string; maxBytes?: number; keepFiles?: number } | null;
  egress?: {
    pin?: string | string[];
    checkUrl?: string;
    ttlSeconds?: number;
    holdSeconds?: number;
  } | null;
  upstreamProxy?: string | false | null;
  noProxy?: string | null;
  autoUpdate?: boolean;
  [key: string]: any;
}

export interface Quota {
  tokensLimit: number | null;
  tokensRemaining: number | null;
  requestsLimit: number | null;
  requestsRemaining: number | null;
  unified5h: number | null;
  unified7d: number | null;
  unified7dSonnet: number | null;
  unified7dFable: number | null;
  unified5hReset: number | null;
  unified7dReset: number | null;
  unified7dSonnetReset: number | null;
  unified7dFableReset: number | null;
  unifiedStatus: string | null;
  resetsAt: number | string | null;
  [key: string]: any;
}

export interface AccountUsage {
  totalInputTokens: number;
  totalOutputTokens: number;
  totalRequests: number;
  lastUsed: string | null;
  [key: string]: any;
}

/** A live account inside the AccountManager (never a raw config entry). */
export interface Account {
  index: number;
  name: string;
  type: string;
  accountUuid: string | null;
  orgUuid: string | null;
  orgName: string | null;
  priority: number;
  disabled: boolean;
  upstream: string | null;
  modelMap: Record<string, string> | null;
  models: string[] | null;
  credential: string | null;
  refreshToken: string | null;
  expiresAt: number | null;
  status: string;
  probing: boolean;
  requalify?: boolean;
  quota: Quota;
  usage: AccountUsage;
  rateLimitedUntil: number | null;
  throttledAt: number | null;
  inFlight: number;
  rampStartedAt: number | null;
  pausedUntil: number | null;
  _lastRefreshAt: number | null;
  _refreshPromise?: Promise<void> | null;
  [key: string]: any;
}

export interface RouteAccountView {
  name: string;
  eligible: boolean;
}

export interface RouteView {
  name: string;
  match: string[];
  bucket: string | null;
  color: string | null;
  autocreated: boolean;
  pinned: string | null;
  accounts: RouteAccountView[];
  target?: string | null;
  [key: string]: any;
}

/** Info payloads for the request hooks; hooks add their own fields. */
export type RequestInfo = Record<string, any>;

export interface ServerHooks {
  onRequestStart?(id: number, info: RequestInfo): void;
  onRequestModel?(id: number, info: RequestInfo): void;
  onRequestRouted?(id: number, info: RequestInfo): void;
  onRequestEnd?(id: number, info: RequestInfo): void;
  reload?(): Promise<number>;
  getStatusExtra?(): Record<string, any> | undefined;
  [key: string]: any;
}

export interface Principal {
  role: string;
  clientId: string;
  clientName: string;
  local?: boolean;
  legacy?: boolean;
  credentialHash?: string;
  [key: string]: any;
}

/** What the TUI needs from either AccountManager (server mode) or RemoteAccountManager (attach mode). */
export interface TuiAccountManagerLike {
  accounts: Account[];
  currentIndex: number;
  switchThreshold: number;
  distributeSessions?: boolean;
  connected?: boolean;
  refreshExpiredQuotas(): void;
  sessionStats(): { active?: number; known?: number; perAccount?: Record<string | number, number> };
  getRoutes(): RouteView[];
  previewRouteIndex(model: string): number | null;
  setRoutePin?(routeName: string, accountIndex: number): { ok: boolean; reason?: string };
  getRoutePin?(routeName: string): Account | null;
  clearRoutePin?(routeName: string): void;
  setDisabled?(index: number, disabled: boolean): void;
  removeAccount?(index: number): void;
  addAccount?(acct: AccountConfig): number;
  setRoutes?(routes: RouteConfig[]): void;
}

/** Loosely-typed object from a parsed JSON body or status payload. */
export type Dict = Record<string, any>;
