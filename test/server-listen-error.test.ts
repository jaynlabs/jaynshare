import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cliPath = fileURLToPath(new URL('../src/index.ts', import.meta.url));

// On the exact address the child binds: macOS lets a specific bind coexist with a wildcard.
function listen(server) {
  return new Promise<any>(resolve => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port)));
}

function close(server) {
  return new Promise<any>(resolve => server.close(resolve));
}

function runServer(configPath) {
  const child = spawn(process.execPath, [cliPath, 'server'], {
    env: { ...process.env, JAYNSHARE_CONFIG: configPath },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });

  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('server did not exit after listen error'));
    }, 5000);

    child.on('error', err => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('exit', code => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

test('server exits cleanly when configured port is already in use', async () => {
  const occupied = http.createServer((_req, res) => res.end('ok'));
  const port = await listen(occupied);
  const dir = await mkdtemp(join(tmpdir(), 'jaynshare-'));
  const configPath = join(dir, 'config.json');
  await writeFile(configPath, JSON.stringify({
    proxy: { port, apiKey: 'tc-test' },
    upstream: 'https://api.anthropic.com',
    switchThreshold: 0.98,
    accounts: [{ name: 'api-test', type: 'apikey', apiKey: 'sk-ant-test' }],
  }));

  try {
    const result = await runServer(configPath);
    assert.equal(result.code, 1);
    assert.match(result.stderr, new RegExp(`Port ${port} is already in use`));
    assert.match(result.stderr, /jaynshare status/);
    assert.doesNotMatch(result.stderr, /Unhandled 'error' event/);
  } finally {
    await close(occupied);
  }
});
