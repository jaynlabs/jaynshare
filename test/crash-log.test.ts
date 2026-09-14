import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getCrashLogPath } from '../src/config.ts';

const CRASH_LOG = fileURLToPath(new URL('../src/crash-log.ts', import.meta.url));

// The handlers end the process, so a child runs them. Returns { code, stderr, logged }.
function crashIn(dir, source): Promise<{ code: number; stderr: string; logged: string }> {
  const path = join(dir, 'crash.log');
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ['--input-type=module', '--eval',
        `import { installCrashHandlers } from ${JSON.stringify(CRASH_LOG)};
         installCrashHandlers(${JSON.stringify(path)});
         ${source}`],
      async (err, _stdout, stderr) => {
        const logged = await readFile(path, 'utf-8').catch(() => '');
        resolve({ code: Number(err?.code ?? 0), stderr, logged });
      },
    );
  });
}

test('an uncaught exception is recorded before the process dies', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-crash-'));
  try {
    const { code, stderr, logged } = await crashIn(dir, 'setTimeout(() => { throw new Error("boom"); }, 0);');
    assert.equal(code, 1);                       // still exits like Node would
    assert.match(logged, /uncaughtException/);
    assert.match(logged, /Error: boom/);
    assert.match(logged, /at /);                 // the stack, not just the message
    assert.match(stderr, /Error: boom/);         // and stderr keeps working
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('an unhandled rejection is recorded too', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-crash-'));
  try {
    const { code, logged } = await crashIn(dir, 'Promise.reject(new Error("nope"));');
    assert.equal(code, 1);
    assert.match(logged, /unhandledRejection/);
    assert.match(logged, /Error: nope/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('crashes append rather than overwrite', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-crash-'));
  try {
    await crashIn(dir, 'throw new Error("first");');
    const { logged } = await crashIn(dir, 'throw new Error("second");');
    assert.match(logged, /Error: first/);
    assert.match(logged, /Error: second/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the crash log sits next to the config', () => {
  const prev = process.env.JAYNSHARE_CONFIG;
  process.env.JAYNSHARE_CONFIG = '/tmp/somewhere/jaynshare.json';
  try {
    assert.equal(getCrashLogPath(), '/tmp/somewhere/jaynshare-crash.log');
  } finally {
    if (prev === undefined) delete process.env.JAYNSHARE_CONFIG;
    else process.env.JAYNSHARE_CONFIG = prev;
  }
});
