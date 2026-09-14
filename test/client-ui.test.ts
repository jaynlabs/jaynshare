import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassThrough } from 'node:stream';
import {
  accountChoiceState,
  encodeAccountPreference,
  parseClientEnv,
  parseStatusLineInput,
  pickAccount,
  pickerAction,
  renderAccountPicker,
  renderStatus,
  renderStatusLine,
  titleHook,
} from '../deploy/client/jaynshare-client.mjs';
import { startFakeUsageServer } from '../test-support/fake-usage-server.ts';

// Must not block the loop: the fake server answering the installer runs in this process.
function runScript(command, args, options) {
  return new Promise<{ status: number; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(command, args, { ...options, encoding: 'utf8' });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', status => resolve({ status, stdout, stderr }));
  });
}

const snapshot = {
  currentAccount: 'alice@example.com',
  sessions: { active: 2, known: 3 },
  server: { uptimeSeconds: 3600 },
  probe: { enabled: true, intervalSeconds: 300 },
  accounts: [
    {
      name: 'alice@example.com', status: 'active', sessions: 1,
      quota: { unified5h: 0.25, unified5hReset: '2026-09-09T13:00:00Z', unified7d: 0.5 },
      usage: { totalRequests: 4, totalInputTokens: 1000, totalOutputTokens: 500 },
    },
    {
      name: 'cofounder@example.com', status: 'active', sessions: 1,
      quota: { unified5h: 0.75, unified7d: 0.9, unified7dSonnet: 0.4 },
    },
  ],
};

test('desktop client environment parsing does not execute shell syntax', () => {
  assert.deepEqual(parseClientEnv(
    "JAYNSHARE_CLIENT_ID='alice'\nJAYNSHARE_HOST='host.ts.net'\nJAYNSHARE_PORT='3456'\nEVIL=$(touch /tmp/no)\n",
  ), {
    JAYNSHARE_CLIENT_ID: 'alice',
    JAYNSHARE_HOST: 'host.ts.net',
    JAYNSHARE_PORT: '3456',
  });
});

test('fleet status renders every account and both primary quota windows', () => {
  const output = renderStatus(snapshot, { ansi: false, now: Date.parse('2026-09-09T12:00:00Z') });
  assert.match(output, /◆ JAYNSHARE/);
  assert.match(output, /alice\s+active.*25%.*1h.*50%/);
  assert.match(output, /cofounder\s+active.*75%.*90%/);
  assert.match(output, /Sonnet 40%/);
  assert.match(output, /4 routed requests · 1.5k observed tokens/);
});

test('compact status line is yellow and includes every account', () => {
  const output = renderStatusLine(snapshot, { ansi: true });
  assert.match(output, /\x1b\[38;2;247;198;0m◆ JAYNSHARE/);
  assert.match(output, /alice 25%\/50%/);
  assert.match(output, /cofounder 75%\/90%/);
  assert.match(output, /2 active/);
});

test('status line displays the actual session account first', () => {
  const output = renderStatusLine({ ...snapshot, session: { account: 'cofounder@example.com' } }, { ansi: false });
  assert.match(output, /^◆ JAYNSHARE → cofounder 75%\/90%/);
  assert.match(output, /alice 25%\/50%/);
  assert.match(renderStatusLine({ ...snapshot, session: null }, { ansi: false }), /→ pending/);
  assert.match(renderStatusLine({ ...snapshot, session: { account: null } }, { ansi: false }), /→ unknown/);
});

test('status-line input accepts safe session IDs and ignores malformed payloads', () => {
  assert.deepEqual(parseStatusLineInput('{"session_id":"abc-123"}'), { sessionId: 'abc-123' });
  assert.deepEqual(parseStatusLineInput('{}'), { sessionId: null });
  assert.deepEqual(parseStatusLineInput('invalid'), { sessionId: null });
  assert.deepEqual(parseStatusLineInput(JSON.stringify({ session_id: 'x'.repeat(257) })), { sessionId: null });
  assert.deepEqual(parseStatusLineInput(JSON.stringify({ session_id: 'bad value' })), { sessionId: null });
});

test('status-line input matches the redacted supported Claude Code payload', async () => {
  const fixture = await readFile(new URL('./fixtures/claude-status-line-redacted.json', import.meta.url), 'utf8');
  assert.deepEqual(parseStatusLineInput(fixture), {
    sessionId: '00000000-0000-4000-8000-000000000000',
  });
});

test('preference encoding is URL-userinfo-safe for unusual account names', () => {
  assert.match(encodeAccountPreference('Zoë @ work (R&D) / org'), /^JAYNSHARE-PREF-v1-[A-Za-z0-9_-]+$/);
});

test('picker navigation wraps, cancellation works, and disabled rows cannot be selected', () => {
  const status = {
    switchThreshold: 0.98,
    accounts: [
      { name: 'available', status: 'active', quota: {} },
      { name: 'disabled', disabled: true, status: 'active', quota: {} },
    ],
  };
  assert.deepEqual(pickerAction('k', 0, status), { type: 'move', index: 2 });
  assert.deepEqual(pickerAction('j', 2, status), { type: 'move', index: 0 });
  assert.equal(pickerAction('\r', 1, status).account, 'available');
  assert.equal(pickerAction('\r', 2, status).type, 'none');
  assert.equal(pickerAction('\x1b', 1, status).type, 'cancel');
  assert.equal(accountChoiceState(status.accounts[1]).selectable, false);
  assert.match(renderAccountPicker(status, 2, { ansi: false }), /disabled.*disabled/);
});

test('picker restores raw mode, cursor, and alternate screen after selection', async () => {
  const input = new PassThrough() as PassThrough & { isRaw?: boolean; setRawMode(value: boolean): void };
  const output = new PassThrough();
  const rawModes = [];
  let rendered = '';
  input.isRaw = false;
  input.setRawMode = value => { input.isRaw = value; rawModes.push(value); };
  output.on('data', chunk => { rendered += chunk; });
  const selected = pickAccount({ accounts: [{ name: 'friend', status: 'active', quota: {} }] }, {
    terminal: { input, output },
  });
  input.write('\x1b[B');
  input.write('\r');
  assert.equal(await selected, 'friend');
  assert.deepEqual(rawModes, [true, false]);
  assert.match(rendered, /\x1b\[\?1049h/);
  assert.match(rendered, /\x1b\[\?25h\x1b\[\?1049l/);
});

test('title hook brands a useful prompt preview and ignores controls', () => {
  const output = titleHook(JSON.stringify({ prompt: 'Implement the billing settings screen' }));
  assert.equal(output.hookSpecificOutput.hookEventName, 'UserPromptSubmit');
  assert.equal(output.hookSpecificOutput.sessionTitle, '◆ Jaynshare · Implement the billing settings screen');
  assert.equal(titleHook(JSON.stringify({ prompt: '/usage' })), null);
  assert.equal(titleHook('not json'), null);
});

test('Claude configuration preserves user settings and keeps the original backup', async () => {
  const tempHome = await mkdtemp(join(tmpdir(), 'jaynshare-client-ui-'));
  try {
    const claudeDir = join(tempHome, '.claude');
    await mkdir(claudeDir);
    const original = {
      model: 'opus',
      hooks: { PostToolUse: [{ matcher: 'Edit', hooks: [{ type: 'command', command: 'true' }] }] },
    };
    await writeFile(join(claudeDir, 'settings.json'), JSON.stringify(original));
    const script = fileURLToPath(new URL('../deploy/client/configure-claude.mjs', import.meta.url));

    for (let i = 0; i < 2; i++) {
      const result = spawnSync(process.execPath, [script], {
        env: { ...process.env, HOME: tempHome },
        encoding: 'utf8',
      });
      assert.equal(result.status, 0, result.stderr);
    }

    const settings = JSON.parse(await readFile(join(claudeDir, 'settings.json'), 'utf8'));
    assert.equal(settings.model, 'opus');
    assert.equal(settings.theme, 'custom:jaynshare');
    assert.equal(settings.statusLine.command, '~/.local/bin/jaynshare status --line');
    assert.equal(settings.hooks.PostToolUse.length, 1);
    assert.equal(settings.hooks.UserPromptSubmit.length, 1, 'reinstall must not duplicate the title hook');

    const backup = JSON.parse(await readFile(join(claudeDir, 'settings.json.before-jaynshare'), 'utf8'));
    assert.deepEqual(backup, original, 'the first pre-Jaynshare settings survive reinstalls');
    const theme = JSON.parse(await readFile(join(claudeDir, 'themes/jaynshare.json'), 'utf8'));
    assert.equal(theme.overrides.claude, '#f7c600');
  } finally {
    await rm(tempHome, { recursive: true, force: true });
  }
});

test('desktop client upgrade reuses enrollment and installs status without asking for a secret', async () => {
  const tempHome = await mkdtemp(join(tmpdir(), 'jaynshare-client-upgrade-'));
  let fake = null;
  try {
    const fakeBin = join(tempHome, 'bin');
    const xattrLog = join(tempHome, 'xattr.log');
    const configDir = join(tempHome, '.config/jaynshare');
    await mkdir(configDir, { recursive: true });
    await mkdir(fakeBin);
    // Stands in for the real xattr so the assertion below can see exactly which
    // files the installer de-quarantined, on any platform the suite runs on.
    const fakeXattr = join(fakeBin, 'xattr');
    await writeFile(fakeXattr, '#!/bin/sh\ncase "$1" in -p) exit 0 ;; -d) printf \'%s\\n\' "$3" >> "$XATTR_LOG" ;; esac\n');
    await chmod(fakeXattr, 0o755);
    fake = await startFakeUsageServer({ secret: 'existing-secret' });
    await writeFile(join(configDir, 'client.env'),
      `JAYNSHARE_CLIENT_ID='alice'\nJAYNSHARE_HOST='127.0.0.1'\nJAYNSHARE_PORT='${fake.port}'\n`);
    await writeFile(join(configDir, 'client.secret'), 'existing-secret\n');
    await writeFile(join(configDir, 'jaynshare-ca.pem'),
      '-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n');
    const installer = fileURLToPath(new URL('../deploy/client/install.sh', import.meta.url));

    const result = await runScript('/bin/sh', [installer, '--upgrade'], {
      env: {
        ...process.env,
        HOME: tempHome,
        XDG_CONFIG_HOME: join(tempHome, '.config'),
        JAYNSHARE_PLATFORM: 'darwin',
        PATH: `${fakeBin}:${process.env.PATH}`,
        XATTR_LOG: xattrLog,
      },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Updated the Jaynshare desktop client/);
    assert.match(await readFile(join(tempHome, '.local/bin/jaynshare'), 'utf8'), /JAYNSHARE/);
    const clearedQuarantine = (await readFile(xattrLog, 'utf8')).trim().split('\n').sort();
    assert.deepEqual(clearedQuarantine, [
      join(tempHome, '.local/bin/jaynshare'),
      join(tempHome, '.local/bin/jaynshare-claude'),
    ]);
    const settings = JSON.parse(await readFile(join(tempHome, '.claude/settings.json'), 'utf8'));
    assert.equal(settings.statusLine.refreshInterval, 15);
  } finally {
    await fake?.close();
    await rm(tempHome, { recursive: true, force: true });
  }
});

test('launcher direct mode preserves everything after the option boundary', async () => {
  const tempHome = await mkdtemp(join(tmpdir(), 'jaynshare-client-args-'));
  try {
    const bin = join(tempHome, 'bin');
    await mkdir(bin);
    const fakeClaude = join(bin, 'claude');
    await writeFile(fakeClaude, '#!/bin/sh\nprintf \'<%s>\\n\' "$@"\n');
    await chmod(fakeClaude, 0o755);
    const launcher = fileURLToPath(new URL('../deploy/client/jaynshare-claude', import.meta.url));
    const result = spawnSync('/bin/sh', [launcher, '--direct', '--', '--account', 'literal', 'two words'], {
      env: { ...process.env, HOME: tempHome, PATH: `${bin}:${process.env.PATH}` },
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '<--account>\n<literal>\n<two words>\n');
  } finally {
    await rm(tempHome, { recursive: true, force: true });
  }
});
