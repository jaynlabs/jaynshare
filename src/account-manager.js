import { refreshAccessToken, isTokenExpiringSoon, isTokenExpired } from './oauth.js';
import { sameIdentity } from './identity.js';
import { weeklyBucketForModel, modelGlobMatches } from './model.js';
import { SessionTracker } from './session-tracker.js';

export { isFableModel, parseRequestModel, parseAdvisorModel } from './model.js';

// A post-401 forced refresh is suppressed this soon after a successful one.
const FORCED_REFRESH_FLOOR_MS = 10_000;

// Survive a restart; transient state (probing, rateLimitedUntil) does not.
const PERSISTED_QUOTA_FIELDS = [
  'unified5h', 'unified7d', 'unified7dSonnet', 'unified7dFable',
  'unified5hReset', 'unified7dReset', 'unified7dSonnetReset', 'unified7dFableReset', 'unifiedStatus',
  'tokensLimit', 'tokensRemaining', 'requestsLimit', 'requestsRemaining', 'resetsAt',
];

function emptyQuota() {
  return {
    // API-key accounts
    tokensLimit: null,
    tokensRemaining: null,
    requestsLimit: null,
    requestsRemaining: null,
    // Subscription accounts: utilization 0-1, resets in ms
    unified5h: null,
    unified7d: null,
    unified7dSonnet: null,
    unified7dFable: null,
    unified5hReset: null,
    unified7dReset: null,
    unified7dSonnetReset: null,
    unified7dFableReset: null,
    unifiedStatus: null,        // allowed | allowed_warning | rejected
    resetsAt: null,
  };
}

function makeAccount(acct, index) {
  return {
    index,
    name: acct.name,
    type: acct.type,
    accountUuid: acct.accountUuid || null,
    orgUuid: acct.orgUuid || null,
    orgName: acct.orgName || null,
    priority: acct.priority || 0,
    disabled: acct.disabled || false,
    upstream: acct.upstream || null,
    modelMap: acct.modelMap || null,
    models: acct.models || null,
    credential: acct.accessToken || acct.apiKey,
    refreshToken: acct.refreshToken || null,
    expiresAt: acct.expiresAt || null,
    status: 'active',
    probing: true, // no quota known yet; the first response reveals it
    quota: emptyQuota(),
    usage: {
      totalInputTokens: 0,
      totalOutputTokens: 0,
      totalRequests: 0,
      lastUsed: null,
    },
    rateLimitedUntil: null,
    throttledAt: null,
    inFlight: 0,
    rampStartedAt: null,
    pausedUntil: null, // admit() waits; unlike rateLimitedUntil, selection never rotates away
    _lastRefreshAt: null, // gates forced refreshes (FORCED_REFRESH_FLOOR_MS)
  };
}

// A declared model may carry a [Nm] context-length suffix.
/** The unified buckets the headers carry, as a patch for an account's quota. */
function unifiedLimits(headers) {
  const patch = {};
  const utilization = {
    unified5h: parseFloat(headers['anthropic-ratelimit-unified-5h-utilization']),
    unified7d: parseFloat(headers['anthropic-ratelimit-unified-7d-utilization']),
    // `7d_oi` (7-day, overage included) is the Fable weekly bucket; utilization may exceed 1.
    unified7dFable: parseFloat(headers['anthropic-ratelimit-unified-7d_oi-utilization']),
  };
  for (const [field, value] of Object.entries(utilization)) {
    if (!isNaN(value)) patch[field] = value;
  }

  const resets = {
    unified5hReset: headers['anthropic-ratelimit-unified-5h-reset'],
    unified7dReset: headers['anthropic-ratelimit-unified-7d-reset'],
    unified7dFableReset: headers['anthropic-ratelimit-unified-7d_oi-reset'],
  };
  for (const [field, seconds] of Object.entries(resets)) {
    if (seconds) patch[field] = parseInt(seconds, 10) * 1000;
  }

  const status = headers['anthropic-ratelimit-unified-status'];
  if (status) patch.unifiedStatus = status;
  return patch;
}

/** The per-key token and request counters that predate the unified buckets. */
function legacyLimits(headers) {
  const patch = {};
  const counters = {
    tokensLimit: parseInt(headers['anthropic-ratelimit-tokens-limit'], 10),
    tokensRemaining: parseInt(headers['anthropic-ratelimit-tokens-remaining'], 10),
    requestsLimit: parseInt(headers['anthropic-ratelimit-requests-limit'], 10),
    requestsRemaining: parseInt(headers['anthropic-ratelimit-requests-remaining'], 10),
  };
  for (const [field, value] of Object.entries(counters)) {
    if (!isNaN(value)) patch[field] = value;
  }

  const resetsAt = headers['anthropic-ratelimit-tokens-reset'] || headers['anthropic-ratelimit-requests-reset'];
  if (resetsAt) patch.resetsAt = resetsAt;
  return patch;
}

function usagePercent(quota) {
  if (quota.unified7d != null) return (quota.unified7d * 100).toFixed(1);
  if (quota.tokensLimit) return ((1 - quota.tokensRemaining / quota.tokensLimit) * 100).toFixed(1);
  return '?';
}

function modelMatches(declared, model) {
  return declared === model || declared.replace(/\[\d+m\]$/, '') === model;
}

function sampleModelFor(route) {
  return route.match[0].replace(/\*/g, '') || 'model';
}

export class AccountManager {
  constructor(accounts, switchThreshold = 0.98, { refreshFn = refreshAccessToken, throttleProbeFloorMs, forcedRefreshFloorMs = FORCED_REFRESH_FLOOR_MS, routes, ramp, distributeSessions = false, sessionTracker } = {}) {
    this._forcedRefreshFloorMs = forcedRefreshFloorMs;
    this._refreshFn = refreshFn;
    this.accounts = accounts.map((acct, index) => makeAccount(acct, index));
    this.currentIndex = 0;
    this.sessionTracker = sessionTracker || new SessionTracker(); // always observes
    this.distributeSessions = !!distributeSessions; // spread new sessions by load instead of funnelling
    this.routePins = new Map(); // routeName → account index; runtime only
    this.switchThreshold = switchThreshold;
    this.setRoutes(routes);
    // Storm control: a just-switched account takes a failover burst through a ramp.
    this.ramp = {
      enabled: true,
      startConc: 1,       // concurrent requests at the instant of a switch
      stepConc: 1,        // cap increase per stepMs
      stepMs: 250,
      windowMs: 30_000,   // then the cap is Infinity
      pollMs: 50,         // how often a waiting request re-checks the cap
      ...ramp,
    };
    // An exhausted fleet gets one real probe this often, so a stale cache cannot pin it (_selectProbe).
    this.probeIntervalMs = 60_000;
    this._nextProbeAt = 0;
    // A 429 hold is respected verbatim this long before the account becomes probe-eligible.
    this.throttleProbeFloorMs = throttleProbeFloorMs
      ?? (Number(process.env.JAYNSHARE_THROTTLE_PROBE_FLOOR_MS) || 60_000);
  }

  _beginRamp(account) {
    if (account && this.ramp.enabled) account.rampStartedAt = Date.now();
  }

  _rampCap(account, now = Date.now()) {
    if (!this.ramp.enabled || account.rampStartedAt == null) return Infinity;
    const elapsed = Math.max(0, now - account.rampStartedAt); // pauseAccount arms a future start
    if (elapsed >= this.ramp.windowMs) { account.rampStartedAt = null; return Infinity; }
    return this.ramp.startConc + Math.floor(elapsed / this.ramp.stepMs) * this.ramp.stepConc;
  }

  /** Waits for a concurrency slot; false when the client went away meanwhile. Pair `true` with release(). */
  async admit(index, isAborted) {
    const account = this.accounts[index];
    if (!account) return true;
    while (true) {
      if (isAborted?.()) return false;
      const now = Date.now();
      if (account.pausedUntil && now < account.pausedUntil) {
        await new Promise(r => setTimeout(r, Math.min(account.pausedUntil - now, this.ramp.pollMs * 4)));
        continue;
      }
      const cap = this.ramp.enabled ? this._rampCap(account, now) : Infinity;
      if (account.inFlight < cap) { account.inFlight++; return true; }
      await new Promise(r => setTimeout(r, this.ramp.pollMs));
    }
  }

  release(index) {
    const account = this.accounts[index];
    if (account && account.inFlight > 0) account.inFlight--;
  }

  /** Holds new requests in admit() for a 429's retry-after; unlike markRateLimited, selection never rotates away. */
  pauseAccount(index, seconds) {
    const account = this.accounts[index];
    if (!account) return;
    const until = Date.now() + Math.max(0, seconds) * 1000;
    account.pausedUntil = Math.max(account.pausedUntil || 0, until);
    if (this.ramp.enabled) account.rampStartedAt = account.pausedUntil; // release the backlog through a ramp
  }

  /**
   * The account to serve one request, or null when every account is exhausted.
   * @param {{exclude?: Set<number>, model?: string, advisorModel?: string,
   *          sessionId?: string, preferredIndex?: number}} query
   */
  getActiveAccount(query = {}) {
    this.refreshExpiredQuotas();
    const preferred = this._preferredAccount(query);
    if (preferred) return preferred;

    if (this.distributeSessions && query.sessionId
        && !this._pinnedAccountForModel(query.model, query.advisorModel)) {
      const spread = this._selectForSession(query);
      if (spread) return spread;
    }

    // The advisor runs on the same account, so its model must be eligible too;
    // failing that, the request model alone decides.
    if (query.advisorModel) {
      const account = this._select(query);
      if (account) return account;
      this._logAdvisorDegraded(query.advisorModel);
    }
    return this._select({ ...query, advisorModel: null });
  }

  /** A per-session preference beats current/priority order, but not availability or route rules. */
  _preferredAccount({ exclude, model, advisorModel, preferredIndex }) {
    if (preferredIndex == null) return null;
    const preferred = this.accounts[preferredIndex];
    return preferred && !exclude?.has(preferredIndex) && this._isAvailable(preferred, model, advisorModel)
      ? preferred : null;
  }

  _logAdvisorDegraded(advisorModel) {
    if (Date.now() < (this._advisorDegradeLogAt || 0)) return;
    this._advisorDegradeLogAt = Date.now() + 60_000;
    console.log(`[Jaynshare] No account eligible for advisor model "${advisorModel}" — routing by request model only`);
  }

  /**
   * Route pin → current account → best available → exhausted-fleet probe. A pass
   * carrying an advisor model is a trial the caller can fall back from, so it
   * neither probes nor spends the current account's pending requalification.
   */
  _select({ exclude, model, advisorModel }) {
    const trial = !!advisorModel;
    const pinned = this._pinnedAccountForModel(model, advisorModel);
    if (pinned && this._isAvailable(pinned, model, advisorModel) && !exclude?.has(pinned.index)) return pinned;
    const current = this.accounts[this.currentIndex];
    if (current && current.requalify) {
      if (!trial) current.requalify = false;
      const next = this._selectNext(exclude, model, advisorModel);
      if (next) { current.requalify = false; return next; }
    }
    if (this._isAvailable(current, model, advisorModel) && !exclude?.has(current.index)) {
      const betterExists = this._preemptedBy(current, { model, advisorModel, exclude });
      return betterExists ? this._selectNext(exclude, model, advisorModel) : current;
    }
    const next = this._selectNext(exclude, model, advisorModel);
    if (next) return next;
    return trial ? null : this._selectProbe(exclude, model);
  }

  /** The session's pinned account unless a higher-priority one is available, else the least loaded. */
  _selectForSession({ sessionId, exclude, model, advisorModel }) {
    const pinIdx = this.sessionTracker.pinnedAccount(sessionId);
    if (pinIdx != null) {
      const pinned = this.accounts[pinIdx];
      if (pinned && this._isAvailable(pinned, model, advisorModel) && !exclude?.has(pinIdx)) {
        const betterExists = this.accounts.some(a =>
          this._isAvailable(a, model, advisorModel) && !exclude?.has(a.index) && (a.priority || 0) < (pinned.priority || 0));
        if (!betterExists) return pinned;
      }
    }
    return this._pickLeastLoaded(exclude, model, advisorModel);
  }

  /** priority → fewest active sessions → fewest in flight → soonest weekly reset */
  _pickLeastLoaded(exclude = null, model = null, advisorModel = null) {
    const now = Date.now();
    let best = null;
    let bestPriority = Infinity;
    let bestSessions = Infinity;
    let bestInFlight = Infinity;
    let bestReset = Infinity;
    for (const account of this.accounts) {
      if (exclude?.has(account.index)) continue;
      if (!this._isAvailable(account, model, advisorModel)) continue;
      const priority = account.priority || 0;
      const sessions = this.sessionTracker.activeCountFor(account.index, now);
      const inFlight = account.inFlight || 0;
      const reset = this._governingWeeklyReset(account, model) || -Infinity;
      if (priority < bestPriority
        || (priority === bestPriority && sessions < bestSessions)
        || (priority === bestPriority && sessions === bestSessions && inFlight < bestInFlight)
        || (priority === bestPriority && sessions === bestSessions && inFlight === bestInFlight && reset < bestReset)) {
        best = account;
        bestPriority = priority;
        bestSessions = sessions;
        bestInFlight = inFlight;
        bestReset = reset;
      }
    }
    return best;
  }

  recordSession(sessionId, accountIndex) {
    if (sessionId) this.sessionTracker.touch(sessionId, accountIndex);
  }

  /** Paired around the whole client request, retries included. */
  beginSession(sessionId) {
    if (sessionId) this.sessionTracker.beginRequest(sessionId);
  }

  endSession(sessionId) {
    if (sessionId) this.sessionTracker.endRequest(sessionId);
  }

  sessionStats() {
    return this.sessionTracker.stats();
  }

  /** Reads without extending the session's expiry. */
  sessionAssignment(sessionId) {
    const view = this.sessionTracker.lookup(sessionId);
    if (!view || view.accountIndex == null) return null;
    const account = this.accounts[view.accountIndex];
    if (!account) return null;
    return { account: account.name, lastRoutedAt: new Date(view.lastSeen).toISOString() };
  }

  /** Eligibility for a per-session preference; global priority is irrelevant. */
  preferenceEligibility(accountIndex, model = null, advisorModel = null) {
    const account = this.accounts[accountIndex];
    if (!account) return { eligible: false, reason: 'no such account' };
    if (this._isAvailable(account, model, advisorModel)) return { eligible: true };
    if (account.disabled) return { eligible: false, reason: 'disabled' };
    if (account.status === 'error') return { eligible: false, reason: 'in an error state and needs a re-login' };
    if (account.status === 'exhausted') return { eligible: false, reason: 'out of quota' };
    if (account.status === 'throttled') return { eligible: false, reason: 'rate-limited' };
    return { eligible: false, reason: 'at or above the switch threshold' };
  }

  /** getActiveAccount, blocking on a refresh when the token has already expired. */
  async getActiveAccountFresh(query = {}) {
    const account = this.getActiveAccount(query);
    if (account && account.type === 'oauth' && account.refreshToken
        && isTokenExpired(account.expiresAt)) {
      await this.ensureTokenFresh(account.index);
    }
    return account;
  }

  /** _select's answer for `model` without mutating currentIndex or probing. */
  previewRouteIndex(model) {
    const pinned = this._pinnedAccountForModel(model);
    if (pinned && this._isAvailable(pinned, model)) return pinned.index;
    const current = this.accounts[this.currentIndex];
    if (current && this._isAvailable(current, model)) {
      const better = this.accounts.some(a =>
        this._isAvailable(a, model) && (a.priority || 0) < (current.priority || 0));
      if (!better) return current.index;
    }
    const best = this._pickBestAvailable(null, model);
    return best ? best.index : null;
  }

  _isProbeable(account) {
    if (!account) return false;
    if (account.disabled) return false;
    if (account.status === 'error' || account.status === 'exhausted') return false;
    if (account.status === 'throttled' && account.rateLimitedUntil
        && Date.now() < account.rateLimitedUntil) {
      return Date.now() >= (account.throttledAt || 0) + this.throttleProbeFloorMs;
    }
    return true;
  }

  /** Highest utilization (0-1) across the buckets that govern `model`. */
  _maxUtilization(account, model = null) {
    const q = account.quota;
    let max = 0;
    if (q.unified5h != null) max = Math.max(max, q.unified5h);
    const weeklyVal = this._governingWeekly(account, model);
    if (weeklyVal != null) max = Math.max(max, weeklyVal);
    if (q.tokensLimit != null && q.tokensRemaining != null) {
      max = Math.max(max, 1 - q.tokensRemaining / q.tokensLimit);
    }
    if (q.requestsLimit != null && q.requestsRemaining != null) {
      max = Math.max(max, 1 - q.requestsRemaining / q.requestsLimit);
    }
    return max;
  }

  /** Utilization of the weekly bucket governing `model`, falling back to the shared one. */
  _governingWeekly(account, model) {
    const q = account.quota;
    const key = this._weeklyBucketFor(model);
    if (q[key] != null) return q[key];
    return key !== 'unified7d' ? q.unified7d : null;
  }

  _governingWeeklyReset(account, model) {
    const q = account.quota;
    const key = this._weeklyBucketFor(model);
    return q[`${key}Reset`] || q.unified7dReset || null;
  }

  /** Only the family-specific bucket; the shared caps are _isNearQuota's job. */
  _modelWeeklyExhausted(account, model) {
    const q = account.quota;
    const key = this._weeklyBucketFor(model);
    if (key === 'unified7d') return false;
    return q[key] != null && q[key] >= this.switchThreshold;
  }

  /** The least-utilized probeable account, at most once per probeIntervalMs; null between probes. */
  _selectProbe(exclude = null, model = null) {
    const now = Date.now();
    if (now < this._nextProbeAt) return null;

    let best = null;
    let bestPriority = Infinity;
    let bestUsage = Infinity;
    for (const account of this.accounts) {
      if (exclude?.has(account.index)) continue;
      if (!this._isProbeable(account)) continue;
      if (model && this._modelWeeklyExhausted(account, model)) continue;
      if (model && !this._routeAllows(account, model)) continue;
      const priority = account.priority || 0;
      const usage = this._maxUtilization(account, model);
      if (priority < bestPriority ||
          (priority === bestPriority && usage < bestUsage)) {
        bestPriority = priority;
        bestUsage = usage;
        best = account;
      }
    }
    if (!best) return null;

    this._nextProbeAt = now + this.probeIntervalMs;
    this.currentIndex = best.index;
    this._beginRamp(best);
    if (best.status === 'throttled') {
      console.log(`[Jaynshare] All accounts unavailable — revalidating throttled "${best.name}" with a live request`);
    } else {
      console.log(`[Jaynshare] All accounts over threshold — probing "${best.name}" to refresh quota`);
    }
    return best;
  }

  _isAvailable(account, model = null, advisorModel = null) {
    if (!account) return false;
    if (account.disabled) return false;

    if (account.status === 'throttled' && account.rateLimitedUntil) {
      if (Date.now() < account.rateLimitedUntil) return false;
      account.status = 'active';
      account.rateLimitedUntil = null;
      account.throttledAt = null;
      console.log(`[Jaynshare] Account "${account.name}" rate limit expired, marking active`);
    }

    if (account.status === 'exhausted' || account.status === 'error') return false;
    if (this._isNearQuota(account, model)) return false;
    if (model && !this._routeAllows(account, model)) return false;
    if (advisorModel) {
      if (this._modelWeeklyExhausted(account, advisorModel)) return false;
      if (!this._routeAllows(account, advisorModel)) return false;
    }

    return true;
  }

  /** The available account that outranks `account`, or null; same tier never preempts. */
  _preemptedBy(account, { model = null, advisorModel = null, exclude = null } = {}) {
    return this.accounts.find(a => this._isAvailable(a, model, advisorModel)
      && !exclude?.has(a.index)
      && (a.priority || 0) < (account.priority || 0)) || null;
  }

  /** Whether a manual switch to this account would take effect on the next request, with a reason when not. */
  eligibility(accountIndex) {
    const account = this.accounts[accountIndex];
    if (!account) return { eligible: false, reason: 'no such account' };
    if (!this._isAvailable(account)) {
      if (account.disabled) return { eligible: false, reason: 'disabled' };
      if (account.status === 'error') return { eligible: false, reason: 'in an error state and needs a re-login' };
      if (account.status === 'exhausted') return { eligible: false, reason: 'out of quota' };
      if (account.status === 'throttled') return { eligible: false, reason: 'rate-limited' };
      return { eligible: false, reason: 'at or above the switch threshold' };
    }
    const preemptor = this._preemptedBy(account);
    if (preemptor) {
      return { eligible: false, reason: `outranked by higher-priority account "${preemptor.name}"` };
    }
    return { eligible: true };
  }

  /** Route: { name, match: glob|glob[], accounts?: (name|index)[], bucket?, color? } */
  setRoutes(routes) {
    this.routes = (Array.isArray(routes) ? routes : []).map((r, i) => ({
      name: r.name || `route-${i + 1}`,
      match: (Array.isArray(r.match) ? r.match : [r.match]).filter(g => typeof g === 'string' && g),
      accounts: Array.isArray(r.accounts) ? r.accounts.map(String) : [],
      bucket: r.bucket || null,
      color: r.color || null,
    })).filter(r => r.match.length);
    if (this.routePins?.size) {
      const names = new Set(this.routes.map(r => r.name));
      for (const name of [...this.routePins.keys()]) {
        if (name !== 'fable' && name !== 'sonnet' && !names.has(name)) this.routePins.delete(name);
      }
    }
  }

  _routeForModel(model) {
    if (!model || !this.routes?.length) return null;
    return this.routes.find(r => r.match.some(g => modelGlobMatches(g, model))) || null;
  }

  _weeklyBucketFor(model) {
    const route = this._routeForModel(model);
    return route?.bucket || weeklyBucketForModel(model);
  }

  /** A route listing accounts is exclusive; otherwise the deprecated per-account `models` claim applies. */
  _routeAllows(account, model) {
    const route = this._routeForModel(model);
    if (route && route.accounts.length) {
      return route.accounts.includes(account.name) || route.accounts.includes(String(account.index));
    }
    return this._accountOwnsModel(account, model);
  }

  /** @deprecated Use `routes` with an `accounts` list instead. */
  _accountOwnsModel(account, model) {
    const owns = a => !!a.models?.some(m => modelMatches(m, model));
    return owns(account) || !this.accounts.some(owns);
  }

  /** For display: configured routes plus an `autocreated` one per metered family no route covers. */
  getRoutes() {
    const out = this.routes.map(r => ({
      name: r.name, match: r.match, bucket: r.bucket, color: r.color || null, autocreated: false,
      pinned: this._pinnedName(r.name),
      accounts: this._routeAccountsView(r),
      target: this._routeTarget(sampleModelFor(r)),
    }));

    const detected = [];
    if (this.accounts.some(a => a.quota.unified7dFable != null)) {
      detected.push({ name: 'fable', match: ['*fable*'], sample: 'claude-fable-5' });
    }
    if (this.accounts.some(a => a.quota.unified7dSonnet != null)) {
      detected.push({ name: 'sonnet', match: ['*sonnet*'], sample: 'claude-sonnet-4-6' });
    }
    for (const d of detected) {
      if (this._routeForModel(d.sample)) continue;
      out.push({
        name: d.name, match: d.match, bucket: null, color: null, autocreated: true,
        pinned: this._pinnedName(d.name),
        accounts: this.accounts.map(a => ({ name: a.name, eligible: this._isAvailable(a, d.sample) })),
        target: this._routeTarget(d.sample),
      });
    }
    return out;
  }

  _routeTarget(model) {
    const idx = this.previewRouteIndex(model);
    return idx == null ? null : (this.accounts[idx]?.name ?? null);
  }

  _pinnedName(routeName) {
    const idx = this.routePins.get(routeName);
    return idx == null ? null : (this.accounts[idx]?.name ?? null);
  }

  _routeAccountsView(route) {
    const sample = sampleModelFor(route);
    const inRoute = a => !route.accounts.length
      || route.accounts.includes(a.name) || route.accounts.includes(String(a.index));
    return this.accounts.filter(inRoute).map(a => ({ name: a.name, eligible: this._isAvailable(a, sample) }));
  }

  _routeSample(routeName) {
    const r = this.routes.find(x => x.name === routeName);
    if (r) return r.match[0]?.replace(/\*/g, '') || 'model';
    if (routeName === 'fable') return 'claude-fable-5';
    if (routeName === 'sonnet') return 'claude-sonnet-4-6';
    return null;
  }

  /** Rejects only an account the route disallows; a near-quota one is a preference. */
  setRoutePin(routeName, accountIndex) {
    const account = this.accounts[accountIndex];
    if (!account) return { ok: false, reason: 'no such account' };
    const sample = this._routeSample(routeName);
    if (sample && !this._routeAllows(account, sample)) {
      return { ok: false, reason: `route "${routeName}" does not allow "${account.name}"` };
    }
    this.routePins.set(routeName, accountIndex);
    return { ok: true };
  }

  clearRoutePin(routeName) { this.routePins.delete(routeName); }

  getRoutePin(routeName) {
    const idx = this.routePins.get(routeName);
    return idx == null ? null : (this.accounts[idx] || null);
  }

  /** The executor's pin wins; the advisor's applies only when nothing pins the executor. */
  _pinnedAccountForModel(model, advisorModel = null) {
    return this._pinnedFor(model)
      || (advisorModel ? this._pinnedFor(advisorModel) : null);
  }

  _pinnedFor(model) {
    if (!model || !this.routePins.size) return null;
    const route = this._routeForModel(model);
    if (route) {
      const idx = this.routePins.get(route.name);
      return idx == null ? null : (this.accounts[idx] || null);
    }
    for (const name of ['fable', 'sonnet']) {
      if (this.routePins.has(name) && modelGlobMatches(`*${name}*`, model)) {
        return this.accounts[this.routePins.get(name)] || null;
      }
    }
    return null;
  }

  /** @returns {{changed: boolean, session: boolean}} */
  _clearExpiredQuotas(account) {
    const q = account.quota;
    const now = Date.now();
    let changed = false;
    let session = false;

    if (q.unified5h != null && q.unified5hReset && now >= q.unified5hReset) {
      console.log(`[Jaynshare] Account "${account.name}" session quota reset`);
      q.unified5h = null;
      q.unified5hReset = null;
      changed = true;
      session = true;
    }
    if (q.unified7d != null && q.unified7dReset && now >= q.unified7dReset) {
      console.log(`[Jaynshare] Account "${account.name}" weekly quota reset`);
      q.unified7d = null;
      q.unified7dReset = null;
      q.unifiedStatus = null;
      changed = true;
    }
    if (q.unified7dSonnet != null && q.unified7dSonnetReset && now >= q.unified7dSonnetReset) {
      q.unified7dSonnet = null;
      q.unified7dSonnetReset = null;
      changed = true;
    }
    if (q.unified7dFable != null && q.unified7dFableReset && now >= q.unified7dFableReset) {
      q.unified7dFable = null;
      q.unified7dFableReset = null;
      changed = true;
    }

    if (q.resetsAt && now >= new Date(q.resetsAt).getTime()) {
      q.tokensRemaining = null;
      q.tokensLimit = null;
      q.requestsRemaining = null;
      q.requestsLimit = null;
      q.resetsAt = null;
      changed = true;
    }

    return { changed, session };
  }

  refreshExpiredQuotas() {
    let changed = false;
    const sessionReset = [];
    for (const account of this.accounts) {
      const r = this._clearExpiredQuotas(account);
      if (r.changed) changed = true;
      if (r.session) sessionReset.push(account);
    }
    if (sessionReset.length) this._switchOnSessionReset(sessionReset);
    return changed;
  }

  /** Switches to the candidate whose weekly limit expires soonest, if sooner than the current account's. */
  _switchOnSessionReset(candidates) {
    const current = this.accounts[this.currentIndex];
    if (!current || current.quota.unified7dReset == null) return; // still probing it

    let best = null;
    let bestWeekly = current.quota.unified7dReset;
    for (const acc of candidates) {
      if (acc.index === this.currentIndex) continue;
      if (!this._isAvailable(acc)) continue;
      if ((acc.priority || 0) > (current.priority || 0)) continue;
      const weekly = acc.quota.unified7dReset;
      if (weekly == null) continue;
      if (weekly < bestWeekly) {
        bestWeekly = weekly;
        best = acc;
      }
    }

    if (best) {
      this.currentIndex = best.index;
      this._beginRamp(best);
      console.log(`[Jaynshare] Account "${best.name}" session quota reset and weekly expires sooner — switching to it`);
    }
  }

  _isNearQuota(account, model = null) {
    const q = account.quota;
    this._clearExpiredQuotas(account);

    if (q.unified5h != null && q.unified5h >= this.switchThreshold) return true;
    const weeklyVal = this._governingWeekly(account, model); // only the bucket governing `model`
    if (weeklyVal != null && weeklyVal >= this.switchThreshold) return true;

    if (q.tokensLimit != null && q.tokensRemaining != null) {
      const used = 1 - (q.tokensRemaining / q.tokensLimit);
      if (used >= this.switchThreshold) return true;
    }

    if (q.requestsLimit != null && q.requestsRemaining != null) {
      const used = 1 - (q.requestsRemaining / q.requestsLimit);
      if (used >= this.switchThreshold) return true;
    }

    return false;
  }

  /** lowest priority → unknown weekly reset (probe it) → soonest weekly reset. Does not mutate. */
  _pickBestAvailable(exclude = null, model = null, advisorModel = null) {
    let best = null;
    let bestPriority = Infinity;
    let bestReset = Infinity;

    for (let i = 0; i < this.accounts.length; i++) {
      const account = this.accounts[i];
      if (exclude?.has(account.index)) continue;
      if (!this._isAvailable(account, model, advisorModel)) continue;

      const priority = account.priority || 0;
      const weeklyReset = this._governingWeeklyReset(account, model) || -Infinity;
      if (priority < bestPriority ||
          (priority === bestPriority && weeklyReset < bestReset)) {
        bestPriority = priority;
        bestReset = weeklyReset;
        best = account;
      }
    }
    return best;
  }

  /** Picks the starting account after persisted quota is restored; falls back to the current one. */
  selectActiveAccount() {
    this.refreshExpiredQuotas();
    const best = this._pickBestAvailable();
    if (!best) return this.accounts[this.currentIndex] || null;
    this.currentIndex = best.index;
    this._beginRamp(best);
    best.probing = best.quota.unified7dReset == null;
    const wk = best.quota.unified7d != null
      ? `${(best.quota.unified7d * 100).toFixed(1)}% weekly used`
      : 'weekly quota unknown';
    console.log(`[Jaynshare] Starting on account "${best.name}" (priority ${best.priority || 0}, ${wk})`);
    return best;
  }

  _selectNext(exclude = null, model = null, advisorModel = null) {
    const best = this._pickBestAvailable(exclude, model, advisorModel);
    if (best) {
      const switched = best.index !== this.currentIndex;
      this.currentIndex = best.index;
      best.probing = best.quota.unified7dReset == null;
      if (switched) {
        this._beginRamp(best);
        console.log(`[Jaynshare] Switched to account "${best.name}"`);
      }
      return best;
    }

    // Every account is unavailable: take the one that resets soonest, if it already has.
    let soonestAccount = null;
    let soonestTime = Infinity;

    for (const account of this.accounts) {
      if (exclude?.has(account.index)) continue;
      if (account.disabled || account.status === 'error') continue;
      if (model && !this._routeAllows(account, model)) continue;
      if (advisorModel && !this._routeAllows(account, advisorModel)) continue;
      const resetTime = account.rateLimitedUntil
        || account.quota.unified5hReset
        || account.quota.unified7dReset
        || (account.quota.resetsAt ? new Date(account.quota.resetsAt).getTime() : null);

      if (resetTime && resetTime < soonestTime) {
        soonestTime = resetTime;
        soonestAccount = account;
      }
    }

    if (soonestAccount && soonestTime <= Date.now()) {
      soonestAccount.status = 'active';
      soonestAccount.rateLimitedUntil = null;
      this.currentIndex = soonestAccount.index;
      this._beginRamp(soonestAccount);
      console.log(`[Jaynshare] Account "${soonestAccount.name}" reset, switching to it`);
      return soonestAccount;
    }

    return null;
  }

  updateQuota(accountIndex, headers) {
    const account = this.accounts[accountIndex];
    if (!account) return;

    Object.assign(account.quota, unifiedLimits(headers), legacyLimits(headers));
    this._resolveProbe(account);

    account.usage.totalRequests++;
    account.usage.lastUsed = new Date().toISOString();

    if (this._isNearQuota(account)) {
      console.log(`[Jaynshare] Account "${account.name}" at ${usagePercent(account.quota)}% usage — will switch on next request`);
    }
  }

  /** A probing account learns its weekly window from the first answer that carries one. */
  _resolveProbe(account) {
    if (!account.probing || account.quota.unified7dReset == null) return;
    account.probing = false;
    account.requalify = true;
    console.log(`[Jaynshare] Learned weekly quota for "${account.name}", re-evaluating selection`);
  }

  updateUsage(accountIndex, inputTokens, outputTokens) {
    const account = this.accounts[accountIndex];
    if (!account) return;
    if (inputTokens) account.usage.totalInputTokens += inputTokens;
    if (outputTokens) account.usage.totalOutputTokens += outputTokens;
  }

  /** Re-enabling also clears an error state so the account is retried at once. */
  setDisabled(accountIndex, disabled) {
    const account = this.accounts[accountIndex];
    if (!account) return;
    account.disabled = disabled;
    if (!disabled && account.status === 'error') {
      account.status = 'active';
      account.rateLimitedUntil = null;
      console.log(`[Jaynshare] Account "${account.name}" re-enabled — clearing error state`);
    }
  }

  /** Quota from the usage endpoint; usage counters are untouched since a probe is not traffic. */
  applyUsageData(accountIndex, usage) {
    const account = this.accounts[accountIndex];
    if (!account || !usage) return;
    const q = account.quota;

    if (usage.fiveHour) {
      if (usage.fiveHour.utilization != null) q.unified5h = usage.fiveHour.utilization;
      if (usage.fiveHour.resetAt != null) q.unified5hReset = usage.fiveHour.resetAt;
    }
    if (usage.sevenDay) {
      if (usage.sevenDay.utilization != null) q.unified7d = usage.sevenDay.utilization;
      if (usage.sevenDay.resetAt != null) q.unified7dReset = usage.sevenDay.resetAt;
    }
    if (usage.sevenDaySonnet) {
      if (usage.sevenDaySonnet.utilization != null) q.unified7dSonnet = usage.sevenDaySonnet.utilization;
      if (usage.sevenDaySonnet.resetAt != null) q.unified7dSonnetReset = usage.sevenDaySonnet.resetAt;
    }
    if (usage.sevenDayFable) {
      if (usage.sevenDayFable.utilization != null) q.unified7dFable = usage.sevenDayFable.utilization;
      if (usage.sevenDayFable.resetAt != null) q.unified7dFableReset = usage.sevenDayFable.resetAt;
    }

    if (account.probing && q.unified7dReset != null) {
      account.probing = false;
      account.requalify = true;
    }
  }

  markRateLimited(accountIndex, retryAfterSeconds) {
    const account = this.accounts[accountIndex];
    if (!account) return;
    account.status = 'throttled';
    account.rateLimitedUntil = Date.now() + (retryAfterSeconds * 1000);
    account.throttledAt = Date.now();
    console.log(`[Jaynshare] Account "${account.name}" rate limited for ${retryAfterSeconds}s`);
  }

  /** Called on any non-429 response from a throttled account. */
  clearRateLimited(accountIndex) {
    const account = this.accounts[accountIndex];
    if (!account || account.status !== 'throttled') return;
    account.status = 'active';
    account.rateLimitedUntil = null;
    account.throttledAt = null;
    console.log(`[Jaynshare] Account "${account.name}" revalidated — rate limit no longer applies, back in rotation`);
  }

  /** Refreshes only a token that is about to expire. Concurrent calls coalesce. */
  async ensureTokenFresh(accountIndex) {
    const account = this.accounts[accountIndex];
    if (!this._refreshable(account)) return;
    if (!isTokenExpiringSoon(account.expiresAt)) return;
    return this._refreshToken(accountIndex, account);
  }

  /** Refreshes regardless of expiry, after upstream rejected the token with a 401. */
  async refreshTokenAfterRejection(accountIndex) {
    const account = this.accounts[accountIndex];
    if (!this._refreshable(account)) return;

    // A burst of 401s from requests sent before the refresh landed must not rotate the token once each.
    if (account._lastRefreshAt !== null
        && Date.now() - account._lastRefreshAt < this._forcedRefreshFloorMs) {
      return;
    }
    return this._refreshToken(accountIndex, account);
  }

  _refreshable(account) {
    return !!(account && account.type === 'oauth' && account.refreshToken);
  }

  _refreshToken(accountIndex, account) {
    if (account._refreshPromise) return account._refreshPromise;

    account._refreshPromise = (async () => {
      console.log(`[Jaynshare] Refreshing token for account "${account.name}"...`);
      try {
        const newTokens = await this._refreshFn(account.refreshToken);
        account.credential = newTokens.accessToken;
        account.refreshToken = newTokens.refreshToken;
        account.expiresAt = newTokens.expiresAt;
        account._lastRefreshAt = Date.now();
        console.log(`[Jaynshare] Token refreshed for account "${account.name}"`);
        this._onTokenRefresh?.(accountIndex, newTokens);
      } catch (err) {
        console.error(`[Jaynshare] Token refresh failed for "${account.name}": ${err.message}`);
        // Only a rejected refresh token sidelines the account; a transient failure retries next request.
        const isAuthRejection = err.status === 400 || err.status === 401 || err.status === 403;
        if (isAuthRejection) {
          account.status = 'error';
          console.error(`[Jaynshare] Account "${account.name}" needs re-login (refresh token rejected) — run: jaynshare login`);
        }
      } finally {
        account._refreshPromise = null;
      }
    })();

    return account._refreshPromise;
  }

  onTokenRefresh(callback) {
    this._onTokenRefresh = callback;
  }

  updateAccountTokens(accountIndex, { accessToken, refreshToken, expiresAt }) {
    const account = this.accounts[accountIndex];
    if (!account || account.type !== 'oauth') return;

    account.credential = accessToken;
    if (refreshToken) account.refreshToken = refreshToken;
    account.expiresAt = expiresAt;
    if (account.status === 'error') account.status = 'active';
    console.log(`[Jaynshare] Updated tokens for account "${account.name}"`);
    this._onTokenRefresh?.(accountIndex, {
      accessToken,
      refreshToken: account.refreshToken,
      expiresAt: account.expiresAt,
    });
  }

  addAccount(acctData) {
    const index = this.accounts.length;
    this.accounts.push(makeAccount(acctData, index));
    return index;
  }

  removeAccount(index) {
    if (index < 0 || index >= this.accounts.length) return;
    this.accounts.splice(index, 1);
    this.accounts.forEach((a, i) => a.index = i);
    if (this.currentIndex >= this.accounts.length) {
      this.currentIndex = Math.max(0, this.accounts.length - 1);
    } else if (this.currentIndex > index) {
      this.currentIndex--;
    }
    for (const [name, idx] of [...this.routePins.entries()]) {
      if (idx === index) this.routePins.delete(name);
      else if (idx > index) this.routePins.set(name, idx - 1);
    }
  }

  exportQuotaState() {
    return this.accounts.map(a => {
      const quota = {};
      for (const f of PERSISTED_QUOTA_FIELDS) quota[f] = a.quota[f];
      return { accountUuid: a.accountUuid, orgUuid: a.orgUuid, orgName: a.orgName, name: a.name, quota };
    });
  }

  /** Expired windows are restored as-is; _clearExpiredQuotas wipes them on first use. */
  restoreQuotaState(saved) {
    if (!Array.isArray(saved)) return;
    for (const account of this.accounts) {
      const match = saved.find(s => sameIdentity(s, account));
      if (!match || !match.quota) continue;
      for (const f of PERSISTED_QUOTA_FIELDS) {
        if (match.quota[f] != null) account.quota[f] = match.quota[f];
      }
      if (account.quota.unified7dReset != null) account.probing = false;
    }
  }

  /** No credentials. */
  getStatus() {
    const sessions = this.sessionTracker.stats();
    return {
      currentAccount: this.accounts[this.currentIndex]?.name,
      switchThreshold: this.switchThreshold,
      routes: this.getRoutes(),
      sessions: { ...sessions, distribute: this.distributeSessions },
      accounts: this.accounts.map(a => ({
        name: a.name,
        type: a.type,
        orgName: a.orgName || null,
        priority: a.priority || 0,
        disabled: a.disabled || false,
        status: a.status,
        sessions: sessions.perAccount[a.index] || 0,
        quota: { ...a.quota },
        usage: { ...a.usage },
        rateLimitedUntil: a.rateLimitedUntil
          ? new Date(a.rateLimitedUntil).toISOString()
          : null,
        pausedUntil: a.pausedUntil && a.pausedUntil > Date.now()
          ? new Date(a.pausedUntil).toISOString()
          : null,
      })),
    };
  }
}
