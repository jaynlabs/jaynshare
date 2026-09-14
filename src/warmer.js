// Opt-in (config.warmupSeconds): spawns a minimal `claude` pinned to each idle
// account so its 5-hour window is already running when rotation reaches it.

import { spawn } from 'node:child_process';
import { encodePinComponent } from './claude-env.js';
import { IntervalJob } from './interval-job.js';

export class Warmer extends IntervalJob {
  label = 'Keep-warm';

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
    super({ intervalMs, log });
    this.am = accountManager;
    this.port = port;
    this.apiKey = apiKey;
    this.model = model;
    this.prompt = prompt;
    this.spawnFn = spawnFn;
    this.timeoutMs = timeoutMs;
    this._abort = null; // AbortController of the in-flight sweep
  }

  stop() {
    super.stop();
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
    return this.run(async () => {
      const abort = this._abort = new AbortController();
      try {
        const targets = this.am.accounts.filter(account => this._isWarmTarget(account));
        for (const account of targets) { // sequential: one subprocess at a time
          if (abort.signal.aborted) break;
          await this.warmAccount(account, abort.signal);
        }
      } finally {
        if (this._abort === abort) this._abort = null;
      }
    });
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
      ...this.statusHead(),
      accounts: this._accountStatusRows(
        account => account.type === 'oauth' && !account.upstream,
        'lastWarmedAt',
      ),
    };
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
