import { TUI } from './tui.js';
import { modelGlobMatches } from './model.js';

// Attach mode: the same TUI, fed by status polled from a server in another process.

const DEFAULT_POLL_MS = 1000;
const DEFAULT_TIMEOUT_MS = 5000;

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

export class RemoteControl {
  constructor({ port, apiKey = null, host = '127.0.0.1', fetchImpl = fetch, timeoutMs = null }) {
    this.port = port;
    this.apiKey = apiKey;
    this.host = host;
    this.timeoutMs = timeoutMs; // null: the attach poller derives one from its cadence
    this._fetch = fetchImpl;
  }

  async status() {
    const payload = await this._call('GET', '/jaynshare/status');
    if (!Array.isArray(payload?.accounts)) { // anything else on this port is not this control plane
      throw new Error('unexpected reply — this is not a jaynshare status endpoint');
    }
    return payload;
  }

  reload() {
    return this._action('POST', '/jaynshare/reload');
  }

  async switchAccount(name) {
    try {
      return await this._action('POST', '/jaynshare/switch', { account: name });
    } catch (err) {
      if (!err.answered && (err.status === 404 || err.status === 501)) { // a 404 in our error shape is an unknown account instead
        throw new Error('this server does not support switching accounts');
      }
      throw err;
    }
  }

  // A foreign service will happily 200 an unknown POST; only `ok: true` means applied.
  async _action(method, path, body) {
    const payload = await this._call(method, path, body);
    if (payload?.ok !== true) throw new Error('unexpected reply — this is not a jaynshare control endpoint');
    return payload;
  }

  async _call(method, path, body) {
    const deadline = this.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const headers = {};
    if (this.apiKey) headers['x-api-key'] = this.apiKey;
    if (body !== undefined) headers['content-type'] = 'application/json';

    let res;
    try {
      res = await this._fetch(`http://${this.host}:${this.port}${path}`, {
        method, headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(deadline),
      });
    } catch (err) {
      if (err?.name === 'TimeoutError' || err?.name === 'AbortError') {
        throw new Error(`no reply within ${deadline}ms`);
      }
      throw err;
    }
    const text = await res.text();
    let payload = null;
    try { payload = text ? JSON.parse(text) : null; } catch { /* not JSON — the status carries the meaning */ }

    if (!res.ok) {
      const answered = payload?.ok === false && typeof payload.error === 'string'; // our own error shape
      // A loopback server exempts clients from the key gate, so a 401 there is not about the key.
      const auth = !answered && (res.status === 401 || res.status === 403);
      const err = new Error(auth
        ? (LOOPBACK_HOSTS.has(this.host)
          ? `something other than jaynshare is answering on port ${this.port} (HTTP ${res.status})`
          : `the server rejected the proxy API key (HTTP ${res.status})`)
        : answered ? payload.error : `HTTP ${res.status}`);
      err.status = res.status;
      err.answered = answered;
      throw err;
    }
    // A 200 body can still report failure (the reload endpoint does this).
    if (payload && payload.ok === false) throw new Error(payload.error || 'request rejected');
    return payload;
  }
}

// The dashboard's read surface in attach mode; nothing is guessed beyond the payload.
class RemoteAccountManager {
  constructor() {
    this.accounts = [];
    this.currentIndex = -1;
    this.switchThreshold = 0.98;
    this.distributeSessions = false;
    this.routes = [];
    this.sessions = { active: 0, known: 0, perAccount: {} };
    this.connected = false;   // false ⇒ the view is a stale snapshot
    this.lastError = null;
    this.status = null;
  }

  applyStatus(status) {
    const accounts = Array.isArray(status?.accounts) ? status.accounts : [];
    // A malformed reply must read as unknown, not crash the renderer.
    this.accounts = accounts.map((a, index) => ({
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
    this.routes = (Array.isArray(status?.routes) ? status.routes : []).map(r => ({
      ...r,
      match: Array.isArray(r?.match) ? r.match : [],
      accounts: Array.isArray(r?.accounts) ? r.accounts : [],
    }));
    this.status = status;
    this.connected = true;
    this.lastError = null;
  }

  markDisconnected(err) {
    this.connected = false;
    this.lastError = err?.message || String(err);
  }

  sessionStats() {
    return { ...this.sessions };
  }

  getRoutes() {
    return this.routes;
  }

  previewRouteIndex(model) {
    const route = this.routes.find(r => (r.match || []).some(g => modelGlobMatches(g, model)));
    if (!route?.target) return null;
    const idx = this.accounts.findIndex(a => a.name === route.target);
    return idx >= 0 ? idx : null;
  }

  refreshExpiredQuotas() {} // the server re-reports expired windows
}

export function createAttachSession({ control, config, onQuit, pollMs = DEFAULT_POLL_MS }) {
  const am = new RemoteAccountManager();
  let timer = null;
  let polling = false;
  control.timeoutMs ??= Math.max(2000, pollMs * 3); // a poll this late hides an outage

  const stop = () => {
    if (timer) { clearInterval(timer); timer = null; }
  };

  const tui = new TUI({
    accountManager: am,
    config,
    remote: true,
    saveConfig: async () => { throw new Error('attach mode cannot write config'); },
    syncAccounts: async () => (await control.reload())?.added || 0,
    applySwitch: name => control.switchAccount(name),
    onQuit: () => { stop(); onQuit?.(); },
  });

  const poll = async () => {
    if (polling) return;
    polling = true;
    try {
      const status = await control.status();
      const recovered = !am.connected && am.lastError != null;
      am.applyStatus(status);
      if (recovered) tui._addLog('Reconnected to the server');
    } catch (err) {
      if (am.connected || am.lastError == null) { // one line per outage, not one per tick
        tui._addLog(`Lost contact with the server: ${err.message}`);
      }
      am.markDisconnected(err);
    } finally {
      polling = false;
    }
    tui.render();
  };

  const start = () => {
    tui.start();
    poll();
    timer = setInterval(poll, pollMs);
  };

  return { tui, am, poll, start, stop };
}
