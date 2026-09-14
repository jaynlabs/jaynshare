// Opt-in egress pinning: hold requests while the exit IP is not the pinned one,
// so a dropped VPN never sends from the wrong address.

const DEFAULT_CHECK_URL = 'https://api.ipify.org';
const DEFAULT_TTL_MS = 30_000;
const DEFAULT_HOLD_MS = 120_000;
const POLL_MS = 3_000;

export class EgressGuard {
  pin: string | string[] | null; // 'auto' | ip | ip[]
  checkUrl: string;
  ttlMs: number;
  holdMs: number;
  pollMs: number;
  _fetch: typeof fetch;
  log: (msg: string) => void;
  _ip: string | null = null;
  _checkedAt = 0;
  _auto: string | null = null;      // the address 'auto' latched onto
  _inFlight: Promise<string | null> | null = null; // coalesces concurrent probes

  constructor({ pin, checkUrl = DEFAULT_CHECK_URL, ttlMs = DEFAULT_TTL_MS, holdMs = DEFAULT_HOLD_MS,
    fetchImpl = fetch, pollMs = POLL_MS, log = () => {} }:
    { pin?: string | string[]; checkUrl?: string; ttlMs?: number; holdMs?: number; fetchImpl?: typeof fetch; pollMs?: number; log?: (msg: string) => void } = {}) {
    this.pin = pin || null;
    this.checkUrl = checkUrl;
    this.ttlMs = ttlMs;
    this.holdMs = holdMs;
    this.pollMs = pollMs;
    this._fetch = fetchImpl;
    this.log = log;
  }

  enabled(): boolean { return !!this.pin; }

  allowed(): string[] {
    if (this.pin === 'auto') return this._auto ? [this._auto] : [];
    return Array.isArray(this.pin) ? this.pin : [this.pin as string];
  }

  async currentIp({ force = false }: { force?: boolean } = {}): Promise<string | null> {
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

  matches(ip: string | null): boolean {
    if (!ip) return true; // unknown is never "wrong": a failed probe must not block
    const allowed = this.allowed();
    return allowed.length === 0 || allowed.includes(ip);
  }

  async check(opts?: { force?: boolean }): Promise<{ ok: boolean; ip: string | null; expected: string[] }> {
    const ip = await this.currentIp(opts);
    return { ok: this.matches(ip), ip, expected: this.allowed() };
  }

  async waitUntilPinned({ isAborted = () => false }: { isAborted?: () => boolean } = {}): Promise<{ ok: boolean; ip: string | null; expected: string[]; waitedMs: number }> {
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

export function createEgressGuard(config: any, log: (msg: string) => void): EgressGuard | null {
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
