import { appendFileSync } from 'node:fs';

// The TUI repaints over stderr, so a fatal error must outlive the process on disk.
export function installCrashHandlers(path: string, { exit = process.exit, log = process.stderr }:
  { exit?: (code: number) => void; log?: { write: (s: string) => void } } = {}): void {
  const report = (kind: string) => (err: unknown) => {
    const stack = (err as Error)?.stack || String(err);
    const entry = `\n=== ${new Date().toISOString()} ${kind} ===\n${stack}\n`;
    try { appendFileSync(path, entry, { mode: 0o600 }); } catch { /* stderr still gets it */ }
    log.write(entry);
    exit(1);
  };
  process.on('uncaughtException', report('uncaughtException'));
  process.on('unhandledRejection', report('unhandledRejection'));
}
