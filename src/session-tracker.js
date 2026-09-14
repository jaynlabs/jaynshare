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
    const session = this._ensure(sessionId, now);
    session.lastSeen = now;
    session.count += 1;
    if (accountIndex != null) session.accountIndex = accountIndex;
    if (now - this._lastSweep > SWEEP_INTERVAL_MS) this.sweep(now);
    return session;
  }

  beginRequest(sessionId, now = this._now()) {
    if (!sessionId) return null;
    const session = this._ensure(sessionId, now);
    session.inFlight += 1;
    session.lastSeen = now;
    return session;
  }

  endRequest(sessionId, now = this._now()) {
    const session = sessionId && this.sessions.get(sessionId);
    if (!session) return;
    session.inFlight = Math.max(0, session.inFlight - 1);
    session.lastSeen = now;
  }

  _ensure(sessionId, now) {
    let session = this.sessions.get(sessionId);
    if (!session) {
      session = { accountIndex: null, firstSeen: now, lastSeen: now, count: 0, inFlight: 0 };
      this.sessions.set(sessionId, session);
    }
    return session;
  }

  _isActive(session, now) {
    return session.inFlight > 0 || now - session.lastSeen <= this.activeTtlMs;
  }

  _isExpired(session, now) {
    return session.inFlight === 0 && now - session.lastSeen > this.knownTtlMs;
  }

  pinnedAccount(sessionId, now = this._now()) {
    const session = sessionId && this.sessions.get(sessionId);
    if (!session) return null;
    if (this._isExpired(session, now)) {
      this.sessions.delete(sessionId);
      return null;
    }
    return session.accountIndex ?? null;
  }

  lookup(sessionId, now = this._now()) {
    const session = sessionId && this.sessions.get(sessionId);
    if (!session) return null;
    if (this._isExpired(session, now)) {
      this.sessions.delete(sessionId);
      return null;
    }
    return { accountIndex: session.accountIndex ?? null, lastSeen: session.lastSeen };
  }

  activeCountFor(accountIndex, now = this._now()) {
    let n = 0;
    for (const session of this.sessions.values()) {
      if (session.accountIndex === accountIndex && this._isActive(session, now)) n += 1;
    }
    return n;
  }

  sweep(now = this._now()) {
    this._lastSweep = now;
    for (const [id, session] of this.sessions) {
      if (this._isExpired(session, now)) this.sessions.delete(id);
    }
  }

  stats(now = this._now()) {
    this._lastSweep = now;
    let known = 0;
    let active = 0;
    const perAccount = {};
    for (const [id, session] of this.sessions) {
      if (this._isExpired(session, now)) {
        this.sessions.delete(id);
        continue;
      }
      known += 1;
      if (this._isActive(session, now)) {
        active += 1;
        if (session.accountIndex != null) perAccount[session.accountIndex] = (perAccount[session.accountIndex] || 0) + 1;
      }
    }
    return { known, active, perAccount };
  }
}
