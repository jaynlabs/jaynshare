// Tracks Claude Code sessions (`x-claude-code-session-id`) for the status
// readout and for session → account affinity.
export const SESSION_KNOWN_TTL_MS = 60 * 60 * 1000; // idle this long → forgotten; matches the prompt-cache window
export const SESSION_ACTIVE_TTL_MS = 2 * 60 * 1000; // idle this long → no longer counts toward account load

const SWEEP_INTERVAL_MS = 60 * 1000; // touch() sweeps opportunistically; no external timer

interface Session {
  accountIndex: number | null;
  firstSeen: number;
  lastSeen: number;
  count: number;
  inFlight: number;
}

export class SessionTracker {
  sessions = new Map<string, Session>();
  knownTtlMs: number;
  activeTtlMs: number;
  _now: () => number;
  _lastSweep = 0;

  constructor({ knownTtlMs, activeTtlMs, now }: { knownTtlMs?: number; activeTtlMs?: number; now?: () => number } = {}) {
    this.knownTtlMs = knownTtlMs ?? SESSION_KNOWN_TTL_MS;
    this.activeTtlMs = activeTtlMs ?? SESSION_ACTIVE_TTL_MS;
    this._now = now || (() => Date.now());
  }

  touch(sessionId: string, accountIndex: number | null = null, now: number = this._now()): Session | null {
    if (!sessionId) return null;
    const session = this._ensure(sessionId, now);
    session.lastSeen = now;
    session.count += 1;
    if (accountIndex != null) session.accountIndex = accountIndex;
    if (now - this._lastSweep > SWEEP_INTERVAL_MS) this.sweep(now);
    return session;
  }

  beginRequest(sessionId: string, now: number = this._now()): Session | null {
    if (!sessionId) return null;
    const session = this._ensure(sessionId, now);
    session.inFlight += 1;
    session.lastSeen = now;
    return session;
  }

  endRequest(sessionId: string, now: number = this._now()): void {
    const session = sessionId && this.sessions.get(sessionId);
    if (!session) return;
    session.inFlight = Math.max(0, session.inFlight - 1);
    session.lastSeen = now;
  }

  _ensure(sessionId: string, now: number): Session {
    let session = this.sessions.get(sessionId);
    if (!session) {
      session = { accountIndex: null, firstSeen: now, lastSeen: now, count: 0, inFlight: 0 };
      this.sessions.set(sessionId, session);
    }
    return session;
  }

  _isActive(session: Session, now: number): boolean {
    return session.inFlight > 0 || now - session.lastSeen <= this.activeTtlMs;
  }

  _isExpired(session: Session, now: number): boolean {
    return session.inFlight === 0 && now - session.lastSeen > this.knownTtlMs;
  }

  pinnedAccount(sessionId: string | null | undefined, now: number = this._now()): number | null {
    const session = sessionId && this.sessions.get(sessionId);
    if (!session) return null;
    if (this._isExpired(session, now)) {
      this.sessions.delete(sessionId);
      return null;
    }
    return session.accountIndex ?? null;
  }

  lookup(sessionId: string | null, now: number = this._now()): { accountIndex: number | null; lastSeen: number } | null {
    const session = sessionId && this.sessions.get(sessionId);
    if (!session) return null;
    if (this._isExpired(session, now)) {
      this.sessions.delete(sessionId);
      return null;
    }
    return { accountIndex: session.accountIndex ?? null, lastSeen: session.lastSeen };
  }

  activeCountFor(accountIndex: number, now: number = this._now()): number {
    let n = 0;
    for (const session of this.sessions.values()) {
      if (session.accountIndex === accountIndex && this._isActive(session, now)) n += 1;
    }
    return n;
  }

  sweep(now: number = this._now()): void {
    this._lastSweep = now;
    for (const [id, session] of this.sessions) {
      if (this._isExpired(session, now)) this.sessions.delete(id);
    }
  }

  stats(now: number = this._now()): { known: number; active: number; perAccount: Record<number, number> } {
    this._lastSweep = now;
    let known = 0;
    let active = 0;
    const perAccount: Record<number, number> = {};
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
