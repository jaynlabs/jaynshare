// Opt-in (config.quotaProbeSeconds) background probe of the zero-spend usage
// endpoint, so idle accounts' quota stays fresh.

import { fetchUsage } from './oauth.ts';
import type { UsageResult } from './oauth.ts';
import { IntervalJob } from './interval-job.ts';
import type { Account } from './types.ts';

export class Prober extends IntervalJob {
  readonly label = 'Quota probe';
  declare accountManager: { accounts: Account[]; ensureTokenFresh(i: number): Promise<void>; refreshTokenAfterRejection(i: number): Promise<void>; applyUsageData(i: number, usage: UsageResult): void };
  probeFn: (accessToken: string) => Promise<UsageResult>;
  timeoutMs: number;

  constructor(accountManager: any, { intervalMs = 0, probeFn = fetchUsage, timeoutMs = 10_000, log = console.log }:
    { intervalMs?: number; probeFn?: (accessToken: string) => Promise<UsageResult>; timeoutMs?: number; log?: (msg: string) => void } = {}) {
    super({ intervalMs, log });
    this.accountManager = accountManager;
    this.probeFn = probeFn;
    this.timeoutMs = timeoutMs;
  }

  async probeAll(): Promise<void> {
    return this.run(() => this.sweep());
  }

  async sweep(): Promise<void> {
    const accounts = this.accountManager.accounts.filter((account: Account) => account.type === 'oauth' && account.credential);
    await Promise.all(accounts.map((account: Account) => this.probeAccount(account)));
  }

  async probeAccount(account: Account): Promise<void> {
    const startedAt = Date.now();
    this._record(account, { status: 'running', startedAt });
    try {
      await this.accountManager.ensureTokenFresh(account.index);
      let usage = await this._withTimeout(this.probeFn(account.credential!));
      if ((usage as any)?.status === 401) {
        await this.accountManager.refreshTokenAfterRejection(account.index);
        usage = await this._withTimeout(this.probeFn(account.credential!));
      }

      if (!usage || (usage as any).error) {
        this._record(account, this._outcome((usage as any).error ? 'error' : 'timeout', (usage as any).error || 'probe timed out', startedAt));
        return;
      }

      this.accountManager.applyUsageData(account.index, usage);
      this._record(account, this._outcome('ok', null, startedAt));
    } catch (err) {
      this._record(account, this._outcome('error', (err as Error)?.message || String(err), startedAt));
    }
  }

  _outcome(status: string, error: string | null, startedAt: number) {
    const finishedAt = Date.now();
    return { status, error, startedAt, finishedAt, durationMs: finishedAt - startedAt };
  }

  getStatus() {
    return {
      ...this.statusHead(),
      accounts: this._accountStatusRows(account => account.type === 'oauth', 'lastProbedAt'),
    };
  }

  _withTimeout(promise: Promise<UsageResult>): Promise<UsageResult | null> {
    return Promise.race([
      promise,
      new Promise<null>(resolve => {
        const t = setTimeout(() => resolve(null), this.timeoutMs);
        t.unref?.();
      }),
    ]);
  }
}
