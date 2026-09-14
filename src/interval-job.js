// Lifecycle, run bookkeeping, and the status head shared by the opt-in periodic
// jobs (quota probe, keep-warm). Subclasses set `label` and implement run logic.

function iso(ts) {
  return ts ? new Date(ts).toISOString() : null;
}

export class IntervalJob {
  constructor({ intervalMs = 0, log = () => {} } = {}) {
    this.intervalMs = intervalMs;
    this.log = log;
    this.timer = null;
    this._running = false;
    this.lastRunStartedAt = null;
    this.lastRunFinishedAt = null;
    this.nextRunAt = intervalMs > 0 ? Date.now() + intervalMs : null;
    this.accountStatus = new Map();
  }

  start() {
    if (this.intervalMs > 0) this.reschedule(this.intervalMs);
  }

  /** Changing the interval never fires a burst; only off→on runs once, immediately. */
  reschedule(intervalMs) {
    const wasOn = this.intervalMs > 0 && this.timer;
    this.intervalMs = intervalMs;
    if (this.timer) { clearInterval(this.timer); this.timer = null; }

    if (intervalMs > 0) {
      this.nextRunAt = Date.now() + intervalMs;
      if (!wasOn) this.run().catch(() => {});
      this.timer = setInterval(() => this.run().catch(() => {}), intervalMs);
      this.timer.unref?.();
      this.log(`[Jaynshare] ${this.label} enabled (every ${Math.round(intervalMs / 1000)}s)`);
    } else if (wasOn) {
      this.nextRunAt = null;
      this.log(`[Jaynshare] ${this.label} disabled`);
    }
  }

  stop() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this.nextRunAt = null;
  }

  /** Guards against overlap and stamps the run's timestamps around `task`. */
  async run(task) {
    if (this._running) return;
    this._running = true;
    this.lastRunStartedAt = Date.now();
    this.nextRunAt = this.intervalMs > 0 ? this.lastRunStartedAt + this.intervalMs : null;
    try {
      await task();
    } finally {
      this.lastRunFinishedAt = Date.now();
      this._running = false;
    }
  }

  /** The head every job reports; the subclass appends its per-account rows. */
  statusHead() {
    return {
      enabled: this.intervalMs > 0,
      intervalSeconds: Math.round(this.intervalMs / 1000),
      running: this._running,
      lastRunStartedAt: iso(this.lastRunStartedAt),
      lastRunFinishedAt: iso(this.lastRunFinishedAt),
      nextRunAt: iso(this.nextRunAt),
    };
  }

  _record(account, status) {
    this.accountStatus.set(account.name, {
      ...(this.accountStatus.get(account.name) || {}),
      ...status,
    });
  }

  /** One row per account; inapplicable ones report `not-applicable` instead of their state. */
  _accountStatusRows(applicable, finishedAtKey) {
    return this.am.accounts.map(account => {
      const status = this.accountStatus.get(account.name);
      return {
        name: account.name,
        status: applicable(account) ? (status?.status || 'never') : 'not-applicable',
        [finishedAtKey]: iso(status?.finishedAt),
        startedAt: iso(status?.startedAt),
        durationMs: status?.durationMs ?? null,
        error: status?.error || null,
      };
    });
  }
}
