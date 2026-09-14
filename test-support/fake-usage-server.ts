// The two endpoints the desktop client calls, for installer and launcher tests.

import { createServer } from 'node:http';
import { realpathSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import type { Dict } from '../src/types.ts';

interface FakeUsageServer {
  port: number;
  host: string;
  requests: Dict[];
  close(): Promise<void>;
}

export const DEFAULT_SNAPSHOT = {
  currentAccount: 'first@example.com',
  switchThreshold: 0.98,
  capabilities: { sessionAccountPreference: true },
  sessions: { active: 1, known: 2 },
  server: { uptimeSeconds: 120 },
  probe: { enabled: true, intervalSeconds: 300 },
  accounts: [
    {
      name: 'first@example.com', status: 'active', sessions: 1,
      quota: { unified5h: 0.2, unified7d: 0.3 },
      usage: { totalRequests: 2, totalInputTokens: 10, totalOutputTokens: 5 },
    },
    {
      name: 'second@example.com', status: 'active', sessions: 0,
      quota: { unified5h: 0.4, unified7d: 0.5 },
    },
    {
      name: 'paused@example.com', status: 'active', disabled: true,
      quota: { unified5h: 0.1, unified7d: 0.1 },
    },
  ],
};

export function startFakeUsageServer({
  secret = 'jaynshare-client-test',
  snapshot = DEFAULT_SNAPSHOT as Dict,
  host = '127.0.0.1',
} = {}): Promise<FakeUsageServer> {
  const requests: Dict[] = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://localhost');
    requests.push({ path: url.pathname, search: url.search, key: req.headers['x-api-key'] || null });
    const send = (status: number, body: Dict): void => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.headers['x-api-key'] !== secret) return send(401, { error: 'unauthorized' });
    if (url.pathname === '/jaynshare/usage') {
      const sessionId = url.searchParams.get('session_id');
      return send(200, sessionId ? { ...snapshot, session: { account: snapshot.currentAccount } } : snapshot);
    }
    if (url.pathname === '/jaynshare/account-selection') {
      const selector = url.searchParams.get('account');
      const account = snapshot.accounts.find((entry: Dict) => entry.name === selector);
      if (!account) return send(404, { error: 'unknown account' });
      return send(200, { account: account.name, available: !account.disabled });
    }
    return send(404, { error: 'not found' });
  });
  return new Promise(resolve => {
    server.listen(0, host, () => resolve({
      port: (server.address() as { port: number }).port,
      host,
      requests,
      close: () => new Promise<void>(done => server.close(() => done())),
    }));
  });
}

let invoked = false;
try {
  invoked = !!process.argv[1]
    && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
} catch { /* a non-existent argv[1] is not this module */ }

if (invoked) {
  const value = (name: string) => {
    const index = process.argv.indexOf(`--${name}`);
    return index === -1 ? undefined : process.argv[index + 1];
  };
  const fake = await startFakeUsageServer({ secret: value('secret') });
  const portFile = value('port-file');
  if (portFile) await writeFile(portFile, String(fake!.port));
  process.stdout.write(`${fake!.port}\n`);
}
