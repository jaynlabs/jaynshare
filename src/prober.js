// Opt-in (config.quotaProbeSeconds) background probe of the zero-spend usage
// endpoint, so idle accounts' quota stays fresh.

import { fetchUsage } from './oauth.js';
import { IntervalJob } from './interval-job.js';

export class Prober extends IntervalJob {
  label = 'Quota probe';

  constructor(accountManager, { intervalMs = 0, probeFn = fetchUsage, timeoutMs = 10_000, log = console.log } = {}) {
    super({ intervalMs, log });
    this.accountManager = accountManager;
    this.probeFn = probeFn;
    this.timeoutMs = timeoutMs;
  }

  async probeAll() {
    return this.run(async () => {
      const accounts = this.accountManager.accounts.filter(account => account.type === 'oauth' && account.credential);
      await Promise.all(accounts.map(account => this.probeAccount(account)));
    });
  }

  async probeAccount(account) {
    const startedAt = Date.now();
    this._record(account, { status: 'running', startedAt });
    try {
      await this.accountManager.ensureTokenFresh(account.index);
      let usage = await this._withTimeout(this.probeFn(account.credential));
      if (usage?.status === 401) {
        await this.accountManager.refreshTokenAfterRejection(account.index);
        usage = await this._withTimeout(this.probeFn(account.credential));
      }

      if (!usage || usage.error) {
        this._record(account, this._outcome(usage?.error ? 'error' : 'timeout', usage?.error || 'probe timed out', startedAt));
        return;
      }

      this.accountManager.applyUsageData(account.index, usage);
      this._record(account, this._outcome('ok', null, startedAt));
    } catch (err) {
      this._record(account, this._outcome('error', err?.message || String(err), startedAt));
    }
  }

  _outcome(status, error, startedAt) {
    const finishedAt = Date.now();
    return { status, error, startedAt, finishedAt, durationMs: finishedAt - startedAt };
  }

  getStatus() {
    return {
      ...this.statusHead(),
      accounts: this._accountStatusRows(account => account.type === 'oauth', 'lastProbedAt'),
    };
  }

  _withTimeout(promise) {
    return Promise.race([
      promise,
      new Promise(resolve => {
        const t = setTimeout(() => resolve(null), this.timeoutMs);
        t.unref?.();
      }),
    ]);
  }
}
