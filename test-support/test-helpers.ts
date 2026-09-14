// Shared helpers for tests that build partial runtime values.

import type { Account, Config, Dict, Quota, TuiAccountManagerLike } from '../src/types.ts';

/** Fills in the required-but-unused fields so a partial config literal satisfies Config. */
export function asConfig(config: Dict = {}): Config {
  return { proxy: {}, accounts: [], ...config };
}

/** Fills in the fields a live account always has so a partial literal satisfies Account. */
const baseQuota = (): Quota => ({
  tokensLimit: null,
  tokensRemaining: null,
  requestsLimit: null,
  requestsRemaining: null,
  unified5h: null,
  unified7d: null,
  unified7dSonnet: null,
  unified7dFable: null,
  unified5hReset: null,
  unified7dReset: null,
  unified7dSonnetReset: null,
  unified7dFableReset: null,
  unifiedStatus: null,
  resetsAt: null,
});

export function asAccount(account: Dict = {}): Account {
  return {
    index: 0,
    name: '',
    type: 'oauth',
    accountUuid: null,
    orgUuid: null,
    orgName: null,
    priority: 0,
    disabled: false,
    upstream: null,
    modelMap: null,
    models: null,
    credential: null,
    refreshToken: null,
    expiresAt: null,
    status: 'active',
    probing: false,
    quota: baseQuota(),
    usage: { totalInputTokens: 0, totalOutputTokens: 0, totalRequests: 0, lastUsed: null },
    rateLimitedUntil: null,
    throttledAt: null,
    inFlight: 0,
    rampStartedAt: null,
    pausedUntil: null,
    _lastRefreshAt: null,
    ...account,
  };
}

/** A minimal AccountManager stand-in for TUI tests. */
export function fakeAccountManager(accounts: Dict[] = [], over: Dict = {}): TuiAccountManagerLike {
  return {
    accounts: accounts.map(asAccount),
    currentIndex: 0,
    switchThreshold: 0.98,
    refreshExpiredQuotas() {},
    sessionStats: () => ({}),
    getRoutes: () => [],
    previewRouteIndex: () => null,
    ...over,
  } as TuiAccountManagerLike;
}
