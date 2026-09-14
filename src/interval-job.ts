// Lifecycle, run bookkeeping, and the status head shared by the opt-in periodic
// jobs (quota probe, keep-warm). Subclasses set `label` and implement run logic.

import type { Account } from './types.ts';

function iso(ts: number | null): string | null {
  return ts ? new Date(ts).toISOString() : null;
}

export interface JobRunStatus {
  status?: string;
  error?: string | null;
  startedAt?: number;
  finishedAt?: number;
  durationMs?: number;
  [key: string]: any;
}

export abstract class IntervalJob {
  abstract readonly label: string;
  intervalMs: number;
  log: (msg: string) => void;
  timer: NodeJS.Timeout | null = null;
  _running = false;
  lastRunStartedAt: number | null = null;
  lastRunFinishedAt: number | null = null;
  nextRunAt: number | null;
  accountStatus = new Map<string, JobRunStatus>();
  accountManager!: { accounts: Account[] };

  constructor({ intervalMs = 0, log = () => {} }: { intervalMs?: number; log?: (msg: string) => void } = {}) {
    this.intervalMs = intervalMs;
    this.log = log;
    this.nextRunAt = intervalMs > 0 ? Date.now() + intervalMs : null;
  }

  start(): void {
    if (this.intervalMs > 0) this.reschedule(this.intervalMs);
  }

  /** Changing the interval never fires a burst; only off→on runs once, immediately. */
  reschedule(intervalMs: number): void {
    const wasOn = this.intervalMs > 0 && this.timer;
    this.intervalMs = intervalMs;
    if (this.timer) { clearInterval(this.timer); this.timer = null; }

    if (intervalMs > 0) {
      this.nextRunAt = Date.now() + intervalMs;
      if (!wasOn) this._tick();
      this.timer = setInterval(() => this._tick(), intervalMs);
      this.timer.unref?.();
      this.log(`[Jaynshare] ${this.label} enabled (every ${Math.round(intervalMs / 1000)}s)`);
    } else if (wasOn) {
      this.nextRunAt = null;
      this.log(`[Jaynshare] ${this.label} disabled`);
    }
  }

  /** The scheduled entry point: subclasses implement `sweep()` (the actual work). */
  _tick(): void {
    this.run(() => this.sweep()).catch(() => {});
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this.nextRunAt = null;
  }

  /** Guards against overlap and stamps the run's timestamps around `task`. */
  async run(task: () => void | Promise<void>): Promise<void> {
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

  /** The actual work; subclasses implement. */
  abstract sweep(): Promise<void>;

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

  _record(account: Account, status: JobRunStatus): void {
    this.accountStatus.set(account.name, {
      ...(this.accountStatus.get(account.name) || {}),
      ...status,
    });
  }

  /** One row per account; inapplicable ones report `not-applicable` instead of their state. */
  _accountStatusRows(applicable: (account: Account) => boolean, finishedAtKey: string) {
    return this.accountManager.accounts.map(account => {
      const status = this.accountStatus.get(account.name);
      return {
        name: account.name,
        status: applicable(account) ? (status?.status || 'never') : 'not-applicable',
        [finishedAtKey]: iso(status?.finishedAt ?? null),
        startedAt: iso(status?.startedAt ?? null),
        durationMs: status?.durationMs ?? null,
        error: status?.error || null,
      };
    });
  }
}
