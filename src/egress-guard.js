// Opt-in egress pinning: hold requests while the exit IP is not the pinned one,
// so a dropped VPN never sends from the wrong address.

const DEFAULT_CHECK_URL = 'https://api.ipify.org';
const DEFAULT_TTL_MS = 30_000;
const DEFAULT_HOLD_MS = 120_000;
const POLL_MS = 3_000;

export class EgressGuard {
  constructor({ pin, checkUrl = DEFAULT_CHECK_URL, ttlMs = DEFAULT_TTL_MS, holdMs = DEFAULT_HOLD_MS,
    fetchImpl = fetch, pollMs = POLL_MS, log = () => {} } = {}) {
    this.pin = pin || null; // 'auto' | ip | ip[]
    this.checkUrl = checkUrl;
    this.ttlMs = ttlMs;
    this.holdMs = holdMs;
    this.pollMs = pollMs;
    this._fetch = fetchImpl;
    this.log = log;
    this._ip = null;
    this._checkedAt = 0;
    this._auto = null;       // the address 'auto' latched onto
    this._inFlight = null;   // coalesces concurrent probes
  }

  enabled() { return !!this.pin; }

  allowed() {
    if (this.pin === 'auto') return this._auto ? [this._auto] : [];
    return Array.isArray(this.pin) ? this.pin : [this.pin];
  }

  async currentIp({ force = false } = {}) {
    if (!force && this._ip && Date.now() - this._checkedAt < this.ttlMs) return this._ip;
    if (this._inFlight) return this._inFlight;

    this._inFlight = (async () => {
      try {
        const res = await this._fetch(this.checkUrl, { signal: AbortSignal.timeout(5_000) });
        const ip = (await res.text()).trim();
        if (!ip) return null;
        this._ip = ip;
        this._checkedAt = Date.now();
        if (this.pin === 'auto' && !this._auto) {
          this._auto = ip;
          this.log(`[Jaynshare] Egress pinned to ${ip}`);
        }
        return ip;
      } catch {
        return null;
      } finally {
        this._inFlight = null;
      }
    })();

    return this._inFlight;
  }

  matches(ip) {
    if (!ip) return true; // unknown is never "wrong": a failed probe must not block
    const allowed = this.allowed();
    return allowed.length === 0 || allowed.includes(ip);
  }

  async check(opts) {
    const ip = await this.currentIp(opts);
    return { ok: this.matches(ip), ip, expected: this.allowed() };
  }

  async waitUntilPinned({ isAborted = () => false } = {}) {
    const started = Date.now();
    let state = await this.check();
    if (state.ok) return { ...state, waitedMs: 0 };

    this.log(`[Jaynshare] Egress is ${state.ip}, not the pinned ${state.expected.join(', ')} — holding requests`);
    while (Date.now() - started < this.holdMs) {
      if (isAborted()) return { ...state, waitedMs: Date.now() - started };
      await new Promise(resolve => setTimeout(resolve, this.pollMs));
      state = await this.check({ force: true });
      if (state.ok) {
        const waitedMs = Date.now() - started;
        this.log(`[Jaynshare] Egress back on ${state.ip} after ${Math.round(waitedMs / 1000)}s`);
        return { ...state, waitedMs };
      }
    }
    return { ...state, waitedMs: Date.now() - started };
  }
}

export function createEgressGuard(config, log) {
  const cfg = config?.egress;
  if (!cfg?.pin) return null;
  return new EgressGuard({
    pin: cfg.pin,
    checkUrl: cfg.checkUrl,
    ttlMs: cfg.ttlSeconds != null ? cfg.ttlSeconds * 1000 : undefined,
    holdMs: cfg.holdSeconds != null ? cfg.holdSeconds * 1000 : undefined,
    log,
  });
}
