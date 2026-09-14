import { appendFile, chmod, mkdir, rename, stat, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
const DEFAULT_KEEP_FILES = 7;

export function auditPath(path) {
  try { return new URL(path, 'http://local').pathname; } catch { return String(path || '').split('?')[0]; }
}

export class AuditLog {
  constructor({ path, maxBytes = DEFAULT_MAX_BYTES, keepFiles = DEFAULT_KEEP_FILES, log = console.error }) {
    this.path = path;
    this.maxBytes = Math.max(1024, Number(maxBytes) || DEFAULT_MAX_BYTES);
    this.keepFiles = Math.max(1, Number(keepFiles) || DEFAULT_KEEP_FILES);
    this.log = log;
    this.chain = Promise.resolve();
  }

  write(record) {
    const line = JSON.stringify(record) + '\n';
    const operation = async () => {
      await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
      const size = (await stat(this.path).catch(err => err.code === 'ENOENT' ? null : Promise.reject(err)))?.size || 0;
      if (size && size + Buffer.byteLength(line) > this.maxBytes) await this.rotate();
      await appendFile(this.path, line, { encoding: 'utf8', mode: 0o600 });
      await chmod(this.path, 0o600).catch(() => {});
    };
    const result = this.chain.then(operation, operation);
    this.chain = result.catch(err => this.log(`[Jaynshare] audit log error: ${err.message}`));
    return this.chain;
  }

  async rotate() {
    await unlink(`${this.path}.${this.keepFiles}`).catch(err => { if (err.code !== 'ENOENT') throw err; });
    for (let i = this.keepFiles - 1; i >= 1; i--) {
      await rename(`${this.path}.${i}`, `${this.path}.${i + 1}`).catch(err => { if (err.code !== 'ENOENT') throw err; });
    }
    await rename(this.path, `${this.path}.1`).catch(err => { if (err.code !== 'ENOENT') throw err; });
  }
}

export function auditHooks(audit, downstream = {}) {
  const active = new Map();
  return {
    ...downstream,
    onRequestStart(id, info) {
      active.set(id, { ...info, startedAt: Date.now(), ts: new Date().toISOString() });
      downstream.onRequestStart?.(id, info);
    },
    onRequestModel(id, info) {
      Object.assign(active.get(id) || {}, info);
      downstream.onRequestModel?.(id, info);
    },
    onRequestRouted(id, info) {
      Object.assign(active.get(id) || {}, info);
      downstream.onRequestRouted?.(id, info);
    },
    onRequestEnd(id, info) {
      const start = active.get(id) || {};
      active.delete(id);
      const merged = { ...start, ...info };
      void audit.write({
        ts: start.ts || new Date().toISOString(),
        durationMs: start.startedAt ? Date.now() - start.startedAt : null,
        clientId: merged.clientId || 'unknown',
        sessionId: merged.sessionId || null,
        method: merged.method || null,
        path: auditPath(merged.path),
        model: merged.model || null,
        accountId: merged.accountId || merged.account || null,
        status: merged.status ?? null,
        retryCount: merged.retryCount || 0,
        rotated: !!merged.rotated,
        errorClass: merged.errorClass || null,
      });
      downstream.onRequestEnd?.(id, info);
    },
  };
}
