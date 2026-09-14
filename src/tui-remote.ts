import { TUI } from './tui.ts';
import { modelGlobMatches } from './model.ts';
import type { Account, Config, Dict, RouteView } from './types.ts';

// Attach mode: the same TUI, fed by status polled from a server in another process.

const DEFAULT_POLL_MS = 1000;
const DEFAULT_TIMEOUT_MS = 5000;

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

export class RemoteControl {
  port: number;
  apiKey: string | null;
  host: string;
  timeoutMs: number | null; // null: the attach poller derives one from its cadence
  _fetch: typeof fetch;

  constructor({ port, apiKey = null, host = '127.0.0.1', fetchImpl = fetch, timeoutMs = null }:
    { port: number; apiKey?: string | null; host?: string; fetchImpl?: typeof fetch; timeoutMs?: number | null }) {
    this.port = port;
    this.apiKey = apiKey;
    this.host = host;
    this.timeoutMs = timeoutMs;
    this._fetch = fetchImpl;
  }

  async status(): Promise<Dict> {
    const payload = await this._call('GET', '/jaynshare/status');
    if (!Array.isArray(payload?.accounts)) { // anything else on this port is not this control plane
      throw new Error('unexpected reply — this is not a jaynshare status endpoint');
    }
    return payload;
  }

  reload(): Promise<Dict> {
    return this._action('POST', '/jaynshare/reload');
  }

  async switchAccount(name: string): Promise<Dict> {
    try {
      return await this._action('POST', '/jaynshare/switch', { account: name });
    } catch (err) {
      const e = err as (Error & { answered?: boolean; status?: number });
      if (!e.answered && (e.status === 404 || e.status === 501)) { // a 404 in our error shape is an unknown account instead
        throw new Error('this server does not support switching accounts');
      }
      throw err;
    }
  }

  // A foreign service will happily 200 an unknown POST; only `ok: true` means applied.
  async _action(method: string, path: string, body?: Dict): Promise<Dict> {
    const payload = await this._call(method, path, body);
    if (payload?.ok !== true) throw new Error('unexpected reply — this is not a jaynshare control endpoint');
    return payload;
  }

  async _call(method: string, path: string, body?: Dict): Promise<Dict | null> {
    const deadline = this.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const headers: Record<string, string> = {};
    if (this.apiKey) headers['x-api-key'] = this.apiKey;
    if (body !== undefined) headers['content-type'] = 'application/json';

    let res: Response;
    try {
      res = await this._fetch(`http://${this.host}:${this.port}${path}`, {
        method, headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(deadline),
      });
    } catch (err) {
      const e = err as Error;
      if (e?.name === 'TimeoutError' || e?.name === 'AbortError') {
        throw new Error(`no reply within ${deadline}ms`);
      }
      throw err;
    }
    const text = await res.text();
    let payload: Dict | null = null;
    try { payload = text ? JSON.parse(text) : null; } catch { /* not JSON — the status carries the meaning */ }

    if (!res.ok) {
      const answered = payload?.ok === false && typeof payload.error === 'string'; // our own error shape
      // A loopback server exempts clients from the key gate, so a 401 there is not about the key.
      const auth = !answered && (res.status === 401 || res.status === 403);
      const err = new Error(auth
        ? (LOOPBACK_HOSTS.has(this.host)
          ? `something other than jaynshare is answering on port ${this.port} (HTTP ${res.status})`
          : `the server rejected the proxy API key (HTTP ${res.status})`)
        : answered ? payload!.error : `HTTP ${res.status}`) as Error & { status?: number; answered?: boolean };
      err.status = res.status;
      err.answered = answered;
      throw err;
    }
    // A 200 body can still report failure (the reload endpoint does this).
    if (payload && payload.ok === false) throw new Error(payload.error || 'request rejected');
    return payload;
  }
}

function emptyAccount(): Account {
  return {
    index: -1, name: '(unnamed)', type: '?', accountUuid: null, orgUuid: null, orgName: null,
    priority: 0, disabled: false, upstream: null, modelMap: null, models: null, credential: null,
    refreshToken: null, expiresAt: null, status: 'unknown', probing: false, quota: {} as any,
    usage: { totalInputTokens: 0, totalOutputTokens: 0, totalRequests: 0, lastUsed: null },
    rateLimitedUntil: null, throttledAt: null, inFlight: 0, rampStartedAt: null, pausedUntil: null,
    _lastRefreshAt: null,
  };
}

// The dashboard's read surface in attach mode; nothing is guessed beyond the payload.
export class RemoteAccountManager {
  accounts: Account[] = [];
  currentIndex = -1;
  switchThreshold = 0.98;
  distributeSessions = false;
  routes: RouteView[] = [];
  sessions: { active: number; known: number; perAccount: Dict } = { active: 0, known: 0, perAccount: {} };
  connected: boolean | null = false;        // false ⇒ the view is a stale snapshot
  lastError: string | null = null;
  status: Dict | null = null;

  applyStatus(status: Dict): void {
    const accounts = Array.isArray(status?.accounts) ? status.accounts : [];
    // A malformed reply must read as unknown, not crash the renderer.
    this.accounts = accounts.map((a: Dict, index: number): Account => ({
      ...emptyAccount(),
      ...a,
      index,
      name: a.name || '(unnamed)',
      type: a.type || '?',
      quota: { ...(a.quota || {}) },
    }));
    this.currentIndex = this.accounts.findIndex(a => a.name === status?.currentAccount);
    if (status?.switchThreshold != null) this.switchThreshold = status.switchThreshold;

    const sessions = status?.sessions || {};
    this.sessions = {
      active: sessions.active || 0,
      known: sessions.known || 0,
      perAccount: sessions.perAccount || {},
    };
    this.distributeSessions = !!sessions.distribute;
    this.routes = (Array.isArray(status?.routes) ? status.routes : []).map((r: Dict): RouteView => ({
      name: r?.name || '',
      autocreated: false,
      bucket: null,
      color: null,
      pinned: null,
      target: null,
      ...r,
      match: Array.isArray(r?.match) ? r.match : [],
      accounts: Array.isArray(r?.accounts) ? r.accounts : [],
    }));
    this.status = status;
    this.connected = true;
    this.lastError = null;
  }

  markDisconnected(err: unknown): void {
    this.connected = false;
    this.lastError = (err as Error)?.message || String(err);
  }

  sessionStats(): { active?: number; known?: number; perAccount?: Dict } {
    return { ...this.sessions };
  }

  getRoutes(): RouteView[] {
    return this.routes;
  }

  previewRouteIndex(model: string): number | null {
    const route = this.routes.find(r => (r.match || []).some(g => modelGlobMatches(g, model)));
    if (!route?.target) return null;
    const idx = this.accounts.findIndex(a => a.name === route.target);
    return idx >= 0 ? idx : null;
  }

  refreshExpiredQuotas(): void {} // the server re-reports expired windows
}

export interface AttachSession {
  tui: TUI;
  accountManager: RemoteAccountManager;
  poll: () => Promise<void>;
  start: () => void;
  stop: () => void;
}

export function createAttachSession({ control, config, onQuit, pollMs = DEFAULT_POLL_MS }:
  { control: RemoteControl; config: Config; onQuit?: () => void; pollMs?: number }): AttachSession {
  const accountManager = new RemoteAccountManager();
  let timer: NodeJS.Timeout | null = null;
  let polling = false;
  control.timeoutMs ??= Math.max(2000, pollMs * 3); // a poll this late hides an outage

  const stop = () => {
    if (timer) { clearInterval(timer); timer = null; }
  };

  const tui = new TUI({
    accountManager: accountManager as any,
    config,
    remote: true,
    saveConfig: async () => { throw new Error('attach mode cannot write config'); },
    syncAccounts: async () => Number((await control.reload())?.added || 0),
    applySwitch: (name: string) => control.switchAccount(name) as Promise<any>,
    onQuit: () => { stop(); onQuit?.(); },
  });

  const poll = async () => {
    if (polling) return;
    polling = true;
    try {
      const status = await control.status();
      const recovered = !accountManager.connected && accountManager.lastError != null;
      accountManager.applyStatus(status);
      if (recovered) tui._addLog('Reconnected to the server');
    } catch (err) {
      if (accountManager.connected || accountManager.lastError == null) { // one line per outage, not one per tick
        tui._addLog(`Lost contact with the server: ${(err as Error).message}`);
      }
      accountManager.markDisconnected(err);
    } finally {
      polling = false;
    }
    tui.render();
  };

  const start = () => {
    tui.start();
    void poll();
    timer = setInterval(poll, pollMs);
  };

  return { tui, accountManager, poll, start, stop };
}
