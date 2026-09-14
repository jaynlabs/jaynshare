// Tracks Claude Code sessions (`x-claude-code-session-id`) for the status
// readout and for session → account affinity.
export const SESSION_KNOWN_TTL_MS = 60 * 60 * 1000; // idle this long → forgotten; matches the prompt-cache window
export const SESSION_ACTIVE_TTL_MS = 2 * 60 * 1000; // idle this long → no longer counts toward account load

const SWEEP_INTERVAL_MS = 60 * 1000; // touch() sweeps opportunistically; no external timer

export class SessionTracker {
  constructor({ knownTtlMs, activeTtlMs, now } = {}) {
    this.sessions = new Map();
    this.knownTtlMs = knownTtlMs ?? SESSION_KNOWN_TTL_MS;
    this.activeTtlMs = activeTtlMs ?? SESSION_ACTIVE_TTL_MS;
    this._now = now || (() => Date.now());
    this._lastSweep = 0;
  }

  touch(sessionId, accountIndex = null, now = this._now()) {
    if (!sessionId) return null;
    const s = this._ensure(sessionId, now);
    s.lastSeen = now;
    s.count += 1;
    if (accountIndex != null) s.accountIndex = accountIndex;
    if (now - this._lastSweep > SWEEP_INTERVAL_MS) this.sweep(now);
    return s;
  }

  beginRequest(sessionId, now = this._now()) {
    if (!sessionId) return null;
    const s = this._ensure(sessionId, now);
    s.inFlight += 1;
    s.lastSeen = now;
    return s;
  }

  endRequest(sessionId, now = this._now()) {
    const s = sessionId && this.sessions.get(sessionId);
    if (!s) return;
    s.inFlight = Math.max(0, s.inFlight - 1);
    s.lastSeen = now;
  }

  _ensure(sessionId, now) {
    let s = this.sessions.get(sessionId);
    if (!s) {
      s = { accountIndex: null, firstSeen: now, lastSeen: now, count: 0, inFlight: 0 };
      this.sessions.set(sessionId, s);
    }
    return s;
  }

  _isActive(s, now) {
    return s.inFlight > 0 || now - s.lastSeen <= this.activeTtlMs;
  }

  _isExpired(s, now) {
    return s.inFlight === 0 && now - s.lastSeen > this.knownTtlMs;
  }

  pinnedAccount(sessionId, now = this._now()) {
    const s = sessionId && this.sessions.get(sessionId);
    if (!s) return null;
    if (this._isExpired(s, now)) {
      this.sessions.delete(sessionId);
      return null;
    }
    return s.accountIndex ?? null;
  }

  lookup(sessionId, now = this._now()) {
    const s = sessionId && this.sessions.get(sessionId);
    if (!s) return null;
    if (this._isExpired(s, now)) {
      this.sessions.delete(sessionId);
      return null;
    }
    return { accountIndex: s.accountIndex ?? null, lastSeen: s.lastSeen };
  }

  activeCountFor(accountIndex, now = this._now()) {
    let n = 0;
    for (const s of this.sessions.values()) {
      if (s.accountIndex === accountIndex && this._isActive(s, now)) n += 1;
    }
    return n;
  }

  sweep(now = this._now()) {
    this._lastSweep = now;
    for (const [id, s] of this.sessions) {
      if (this._isExpired(s, now)) this.sessions.delete(id);
    }
  }

  stats(now = this._now()) {
    this._lastSweep = now;
    let known = 0;
    let active = 0;
    const perAccount = {};
    for (const [id, s] of this.sessions) {
      if (this._isExpired(s, now)) {
        this.sessions.delete(id);
        continue;
      }
      known += 1;
      if (this._isActive(s, now)) {
        active += 1;
        if (s.accountIndex != null) perAccount[s.accountIndex] = (perAccount[s.accountIndex] || 0) + 1;
      }
    }
    return { known, active, perAccount };
  }
}
