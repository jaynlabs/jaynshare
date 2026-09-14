// Opt-in (config.warmupSeconds): spawns a minimal `claude` pinned to each idle
// account so its 5-hour window is already running when rotation reaches it.

import { spawn } from 'node:child_process';
import { encodePinComponent } from './claude-env.js';

export class Warmer {
  constructor(accountManager, {
    intervalMs = 0,
    port,
    apiKey = null,
    model = 'haiku',
    prompt = 'hi',
    spawnFn = defaultSpawn,
    timeoutMs = 120_000,
    log = console.log,
  } = {}) {
    this.am = accountManager;
    this.intervalMs = intervalMs;
    this.port = port;
    this.apiKey = apiKey;
    this.model = model;
    this.prompt = prompt;
    this.spawnFn = spawnFn;
    this.timeoutMs = timeoutMs;
    this.log = log;
    this.timer = null;
    this._running = false;
    this._abort = null; // AbortController of the in-flight sweep
    this.lastRunStartedAt = null;
    this.lastRunFinishedAt = null;
    this.nextRunAt = intervalMs > 0 ? Date.now() + intervalMs : null;
    this.accountStatus = new Map();
  }

  start() {
    if (this.intervalMs > 0) this.reschedule(this.intervalMs);
  }

  reschedule(intervalMs) {
    const wasOn = this.intervalMs > 0 && this.timer;
    this.intervalMs = intervalMs;
    if (this.timer) { clearInterval(this.timer); this.timer = null; }

    if (intervalMs > 0) {
      this.nextRunAt = Date.now() + intervalMs;
      if (!wasOn) this.warmAll().catch(() => {}); // off→on only; an interval edit must not spend quota
      this.timer = setInterval(() => this.warmAll().catch(() => {}), intervalMs);
      this.timer.unref?.();
      this.log(`[Jaynshare] Keep-warm enabled (every ${Math.round(intervalMs / 1000)}s)`);
    } else if (wasOn) {
      this.nextRunAt = null;
      this.log('[Jaynshare] Keep-warm disabled');
    }
  }

  stop() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this.nextRunAt = null;
    this._abort?.abort();
  }

  _isWarmTarget(account) {
    if (account.type !== 'oauth' || !account.credential) return false;
    if (account.upstream) return false; // the 5h window is Anthropic-specific
    if (account.disabled) return false;
    if (account.status === 'error' || account.status === 'exhausted' || account.status === 'throttled') return false;
    const reset = account.quota?.unified5hReset;
    return !(reset && Date.now() < reset); // a future reset means the window is already running
  }

  async warmAll() {
    if (this._running) return;
    this._running = true;
    const abort = this._abort = new AbortController();
    this.lastRunStartedAt = Date.now();
    this.nextRunAt = this.intervalMs > 0 ? this.lastRunStartedAt + this.intervalMs : null;
    try {
      const targets = this.am.accounts.filter(account => this._isWarmTarget(account));
      for (const account of targets) { // sequential: one subprocess at a time
        if (abort.signal.aborted) break;
        await this.warmAccount(account, abort.signal);
      }
    } finally {
      this.lastRunFinishedAt = Date.now();
      this._running = false;
      if (this._abort === abort) this._abort = null;
    }
  }

  async warmAccount(account, signal) {
    const startedAt = Date.now();
    this._record(account, { status: 'running', startedAt });
    try {
      await this.am.ensureTokenFresh(account.index);
      const code = await this.spawnFn(this._spawnSpec(account, signal));
      const finishedAt = Date.now();
      this._record(account, {
        status: code === 0 ? 'ok' : 'error',
        error: code === 0 ? null : `claude exited ${code}`,
        startedAt, finishedAt, durationMs: finishedAt - startedAt,
      });
    } catch (err) {
      const finishedAt = Date.now();
      this._record(account, {
        status: 'error',
        error: err?.message || String(err),
        startedAt, finishedAt, durationMs: finishedAt - startedAt,
      });
    }
  }

  _spawnSpec(account, signal) {
    const pin = encodePinComponent(account.accountUuid || account.name); // never the index: it shifts on removal
    const baseUrl = `http://127.0.0.1:${this.port}/jaynshare-account/${pin}`;
    return {
      command: 'claude',
      args: ['-p', '--bare', '--model', this.model, '--output-format', 'text', this.prompt],
      env: {
        ...process.env,
        ANTHROPIC_BASE_URL: baseUrl,
        ANTHROPIC_API_KEY: this.apiKey || 'jaynshare-warm',
      },
      timeoutMs: this.timeoutMs,
      signal,
    };
  }

  getStatus() {
    return {
      enabled: this.intervalMs > 0,
      intervalSeconds: Math.round(this.intervalMs / 1000),
      running: this._running,
      lastRunStartedAt: iso(this.lastRunStartedAt),
      lastRunFinishedAt: iso(this.lastRunFinishedAt),
      nextRunAt: iso(this.nextRunAt),
      accounts: this.am.accounts.map(account => {
        const status = this.accountStatus.get(account.name);
        const applicable = account.type === 'oauth' && !account.upstream;
        return {
          name: account.name,
          status: applicable ? (status?.status || 'never') : 'not-applicable',
          lastWarmedAt: iso(status?.finishedAt),
          startedAt: iso(status?.startedAt),
          durationMs: status?.durationMs ?? null,
          error: status?.error || null,
        };
      }),
    };
  }

  _record(account, status) {
    this.accountStatus.set(account.name, {
      ...(this.accountStatus.get(account.name) || {}),
      ...status,
    });
  }
}

function defaultSpawn({ command, args, env, timeoutMs, signal }) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new Error('warm-up aborted')); return; }
    let child;
    try {
      child = spawn(command, args, { env, stdio: 'ignore' });
    } catch (err) {
      reject(err);
      return;
    }
    const onAbort = () => child.kill('SIGKILL');
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`warm-up timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref?.();
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', onAbort); };
    child.once('error', (err) => { cleanup(); reject(err); });
    child.once('exit', (code, sigName) => {
      cleanup();
      if (sigName) { reject(new Error(`claude terminated by ${sigName}`)); return; }
      resolve(code ?? 0);
    });
  });
}

function iso(ts) {
  return ts ? new Date(ts).toISOString() : null;
}
