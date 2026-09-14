// Runs everywhere: JAYNSHARE_PLATFORM=win32 plus stub cygpath/icacls/whoami executables.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassThrough } from 'node:stream';
import {
  clientPlatform,
  linePickerAction,
  openPickerTerminal,
  pickAccount,
  pickerMode,
  renderAccountPicker,
  renderLinePicker,
} from '../deploy/client/jaynshare-client.mjs';
import { startFakeUsageServer } from '../test-support/fake-usage-server.ts';

const installer = fileURLToPath(new URL('../deploy/client/install.sh', import.meta.url));
const launcher = fileURLToPath(new URL('../deploy/client/jaynshare-claude', import.meta.url));
const configureClaude = fileURLToPath(new URL('../deploy/client/configure-claude.mjs', import.meta.url));

const SID = 'S-1-5-21-1111111111-2222222222-3333333333-1001';
const SECRET = 'jaynshare-client-SYNTHETIC0000000000000000000000';

const pickerStatus = {
  switchThreshold: 0.98,
  accounts: [
    { name: 'first@example.com', status: 'active', quota: { unified5h: 0.2, unified7d: 0.3 } },
    { name: 'paused@example.com', status: 'active', disabled: true, quota: {} },
  ],
};

function runScript(command, args, options: any = {}) {
  return new Promise<any>((resolve, reject) => {
    const child = spawn(command, args, options);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', status => resolve({ status, stdout, stderr }));
    if (options.stdin !== undefined) child.stdin.end(options.stdin);
  });
}

async function windowsFixture(name, { roamingProfile = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), `jaynshare-win-${name}-`));
  const home = join(root, 'home');
  const bin = join(root, 'stubs');
  await mkdir(home, { recursive: true });
  await mkdir(bin, { recursive: true });

  // Git Bash puts its own /usr/bin ahead of System32.
  const system32 = join(root, 'windows/System32');
  await mkdir(system32, { recursive: true });
  const writeIn = async (dir, file, body) => {
    await writeFile(join(dir, file), body);
    await chmod(join(dir, file), 0o755);
  };
  const write = (file, body) => writeIn(bin, file, body);
  // Returns a path this host can open; records what it was asked to convert.
  await write('cygpath', '#!/bin/sh\n'
    + 'while [ "$#" -gt 0 ]; do case "$1" in -w|-u|--) shift ;; *) break ;; esac; done\n'
    + 'printf \'%s\\n\' "$1" >> "$CYGPATH_LOG"\nprintf \'%s\\n\' "$1"\n');
  // Git Bash rewrites /switch arguments into paths unless MSYS_NO_PATHCONV is set.
  const noPathConv = '[ "${MSYS_NO_PATHCONV:-}" = 1 ] || '
    + '{ printf \'ERROR: Invalid argument/option - %s\\n\' "$1" >&2; exit 1; }\n';
  await writeIn(system32, 'icacls.exe', '#!/bin/sh\n' + noPathConv
    + 'printf \'%s\\n\' "$*" >> "$ICACLS_LOG"\n'
    + '[ -z "${ICACLS_FAIL:-}" ] || { printf \'access denied\\n\'; exit 1; }\n'
    + 'case "$*" in *grant:r*) printf \'Successfully processed 1 files.\\n\'; exit 0 ;; esac\n'
    + `printf '%s NT AUTHORITY\\\\SYSTEM:(F)\\n' "$1"\n`
    + 'printf \'          MACHINE\\\\tester:(F)\\n\'\n'
    + '[ -z "${ICACLS_EXTRA_ACE:-}" ] || printf \'          BUILTIN\\\\Users:(RX)\\n\'\n');
  await writeIn(system32, 'whoami.exe', '#!/bin/sh\n' + noPathConv
    + `printf '"machine\\\\tester","${SID}"\\n'\n`);
  // Git Bash finds coreutils' whoami first, which knows nothing about /user.
  await write('whoami.exe', '#!/bin/sh\n'
    + '[ "$#" -eq 0 ] || { printf "whoami: extra operand \'%s\'\\n" "$1" >&2; exit 1; }\n'
    + 'printf \'machine\\\\tester\\n\'\n');
  await write('claude', '#!/bin/sh\nprintf \'claude %s\\n\' "$*"\n');

  // A roaming profile: the shell's HOME is not the profile os.homedir() reports.
  let shellHome = home;
  if (roamingProfile) {
    shellHome = join(root, 'git-bash-home');
    await mkdir(shellHome, { recursive: true });
    const shim = join(root, 'profile.cjs');
    await writeFile(shim, `process.env.HOME = ${JSON.stringify(home)};\n`);
    await write('node', '#!/bin/sh\n'
      + `exec ${JSON.stringify(process.execPath)} --require ${JSON.stringify(shim)} "$@"\n`);
  }

  const env: any = {
    ...process.env,
    HOME: shellHome,
    USERPROFILE: home,
    PATH: `${bin}:${system32}:${process.env.PATH}`,
    SYSTEMROOT: join(root, 'windows'),
    JAYNSHARE_PLATFORM: 'win32',
    CYGPATH_LOG: join(root, 'cygpath.log'),
    ICACLS_LOG: join(root, 'icacls.log'),
  };
  delete env.XDG_CONFIG_HOME;
  delete env.WINDIR; // would point at the real System32

  const ca = join(root, 'ca.pem');
  await writeFile(ca, '-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n');

  return {
    root,
    home,
    shellHome,
    system32,
    ca,
    env,
    configDir: join(home, '.config/jaynshare'),
    binDir: join(home, '.local/bin'),
    icaclsLog: () => readFile(join(root, 'icacls.log'), 'utf8').catch(() => ''),
    cygpathLog: () => readFile(join(root, 'cygpath.log'), 'utf8').catch(() => ''),
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

async function install(fixture, { port, env = {}, stdin = `${SECRET}\n`, id = 'windows-tester' }: any = {}) {
  return runScript('/bin/sh', [installer, id, '127.0.0.1', fixture.ca, String(port)], {
    env: { ...fixture.env, ...env },
    stdin,
  });
}

test('platform detection prefers the explicit override over the host platform', () => {
  assert.equal(clientPlatform({ JAYNSHARE_PLATFORM: 'win32' }), 'win32');
  assert.equal(clientPlatform({}), process.platform);
});

test('Windows uses the inherited console because /dev/tty cannot be opened there', () => {
  const windows = openPickerTerminal({ platform: 'win32' });
  assert.equal(windows.ownsInput, false, 'stdin and stderr belong to the caller on Windows');
  assert.equal(windows.input, process.stdin);
  assert.equal(pickerMode(process.stdin, { override: undefined }),
    typeof process.stdin.setRawMode === 'function' ? 'raw' : 'line');
  assert.equal(pickerMode({}, { override: undefined }), 'line');
  assert.equal(pickerMode({ setRawMode() {} }, { override: 'line' }), 'line');
  assert.equal(windows.ascii, true, 'the Windows picker terminal asks for ASCII');
});

test('the Windows picker draws with characters every console codepage agrees on', () => {
  const now = Date.parse('2026-09-09T12:00:00Z');
  // A name past the column width, so the truncation marker is rendered too.
  const wide = {
    ...pickerStatus,
    accounts: [...pickerStatus.accounts,
      { name: 'a-really-long-account-name-that-overruns', status: 'active', quota: {} }],
  };
  for (const [mode, rendered] of [
    ['arrow-key', renderAccountPicker(wide, 1, { now, ansi: false, ascii: true })],
    ['numbered', renderLinePicker(wide, { now, ascii: true })],
    ['retry message', linePickerAction('3', wide, { ascii: true }).message],
  ]) {
    const offending = rendered.match(/[^\x09\x0a\x20-\x7e]/g);
    assert.equal(offending, null,
      `the ${mode} picker sent ${JSON.stringify(offending?.join(''))} to a console that cannot decode it`);
  }
  // The ASCII stand-ins still say what the originals said.
  assert.match(renderAccountPicker(pickerStatus, 0, { now, ansi: false, ascii: true }),
    /^ +> Automatic/m, 'the selected row is still marked');
  assert.match(renderAccountPicker(pickerStatus, 0, { now, ansi: false, ascii: true }),
    /Up\/Dn move {2}- {2}Enter choose {2}- {2}Esc cancel/, 'the key hints survive in ASCII');
  // macOS writes to a descriptor that takes UTF-8, and keeps the real glyphs.
  assert.match(renderAccountPicker(pickerStatus, 0, { now, ansi: false }), /↑\/↓ move/);
});

test('the numbered picker lists every account and marks the unselectable ones', () => {
  const rendered = renderLinePicker(pickerStatus, { now: Date.parse('2026-09-09T12:00:00Z') });
  assert.match(rendered, /1\) Automatic/);
  assert.match(rendered, /2\) first  /, 'long account names are shortened for the narrow list');
  assert.match(rendered, /3\) paused .*disabled.*\[unavailable\]/);
  assert.match(rendered, /Type a number and press Enter, or type q to cancel\./);
});

test('numbered input selects, cancels, and refuses anything else', () => {
  assert.deepEqual(linePickerAction('1', pickerStatus), { type: 'select', account: null });
  assert.deepEqual(linePickerAction(' 2 ', pickerStatus), { type: 'select', account: 'first@example.com' });
  assert.equal(linePickerAction('3', pickerStatus).type, 'retry', 'a disabled account cannot be chosen');
  assert.equal(linePickerAction('4', pickerStatus).type, 'retry');
  assert.equal(linePickerAction('0', pickerStatus).type, 'retry');
  assert.equal(linePickerAction('two', pickerStatus).type, 'retry');
  assert.equal(linePickerAction('', pickerStatus).type, 'none');
  for (const word of ['q', 'Q', 'quit', 'cancel']) {
    assert.equal(linePickerAction(word, pickerStatus).type, 'cancel');
  }
  // A secret pasted into the wrong prompt arrives with a trailing CR in Git Bash.
  assert.deepEqual(linePickerAction('2\r', pickerStatus), { type: 'select', account: 'first@example.com' });
});

test('the numbered picker draws on stderr and keeps retrying until a valid choice', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let rendered = '';
  output.on('data', chunk => { rendered += chunk; });
  const selected = pickAccount(pickerStatus, { terminal: { input, output }, mode: 'line' });
  input.write('3\n');
  input.write('2\n');
  assert.equal(await selected, 'first@example.com');
  assert.match(rendered, /paused cannot be selected right now\./);
  assert.equal(input.isPaused(), true, 'the picker releases the caller\'s stdin');
});

test('a closed input is never an implicit account choice', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const selected = pickAccount(pickerStatus, { terminal: { input, output }, mode: 'line' });
  input.end();
  await assert.rejects(selected, /explicit choice; use --account ACCOUNT or --auto/);
});

test('Claude settings run the Windows client through node by native path', async () => {
  const home = await mkdtemp(join(tmpdir(), 'jaynshare-win-settings-'));
  try {
    const result = spawnSync(process.execPath, [configureClaude,
      '--platform', 'win32', '--client-path', 'C:\\Users\\tester\\.local\\bin\\jaynshare'], {
      env: { ...process.env, HOME: home, USERPROFILE: home },
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    const settings = JSON.parse(await readFile(join(home, '.claude/settings.json'), 'utf8'));
    assert.equal(settings.statusLine.command,
      'node "C:\\Users\\tester\\.local\\bin\\jaynshare" status --line');
    assert.equal(settings.hooks.UserPromptSubmit[0].hooks[0].command,
      'node "C:\\Users\\tester\\.local\\bin\\jaynshare" title-hook');

    const noPath = spawnSync(process.execPath, [configureClaude, '--platform', 'win32'], {
      env: { ...process.env, HOME: home, USERPROFILE: home }, encoding: 'utf8',
    });
    assert.notEqual(noPath.status, 0);
    assert.match(noPath.stderr, /--client-path is required/);

    const quoted = spawnSync(process.execPath, [configureClaude,
      '--platform', 'win32', '--client-path', 'C:\\a"b\\jaynshare'], {
      env: { ...process.env, HOME: home, USERPROFILE: home }, encoding: 'utf8',
    });
    assert.notEqual(quoted.status, 0, 'a quote in the path must not be able to escape the command');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('macOS settings are unchanged by the Windows support', async () => {
  const home = await mkdtemp(join(tmpdir(), 'jaynshare-mac-settings-'));
  try {
    const result = spawnSync(process.execPath, [configureClaude, '--platform', 'darwin'], {
      env: { ...process.env, HOME: home }, encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    const settings = JSON.parse(await readFile(join(home, '.claude/settings.json'), 'utf8'));
    assert.equal(settings.statusLine.command, '~/.local/bin/jaynshare status --line');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('a Windows install locks the enrollment by SID and verifies it afterwards', async () => {
  const fixture = await windowsFixture('install');
  const fake = await startFakeUsageServer({ secret: SECRET });
  try {
    const result = await install(fixture, { port: fake.port });
    assert.equal(result.status, 0, result.stderr);

    const acl = await fixture.icaclsLog();
    assert.match(acl, /\/inheritance:r/, 'inherited entries have to be removed');
    // /inheritance:r cannot remove an explicit entry left by an earlier install.
    assert.equal((acl.match(/\/reset/g) || []).length, 4,
      'every locked path is reset before access is granted');
    assert.match(acl, new RegExp(`grant:r \\*${SID}:\\(OI\\)\\(CI\\)F`), 'the directory grant is inheritable');
    assert.match(acl, new RegExp(`grant:r \\*${SID}:F`), 'each file is granted to this user by SID');
    assert.match(acl, /\*S-1-5-18:/, 'SYSTEM keeps access');
    assert.equal(acl.includes(SECRET), false, 'no icacls command line may carry the secret');
    for (const name of ['client.env', 'client.secret', 'jaynshare-ca.pem']) {
      assert.match(acl, new RegExp(name.replace('.', '\\.')), `${name} must be locked`);
    }

    const stored = await readFile(join(fixture.configDir, 'client.secret'), 'utf8');
    assert.equal(stored.trim(), SECRET);
    assert.equal(result.stdout.includes(SECRET), false, 'the installer never echoes the secret');
    assert.equal(result.stderr.includes(SECRET), false);

    const elsewhere = await runScript(process.execPath, [join(fixture.binDir, 'jaynshare'), 'status', '--json'], {
      env: { ...fixture.env, XDG_CONFIG_HOME: '/c/Users/tester/.config' },
    });
    assert.equal(elsewhere.status, 0, elsewhere.stderr);
  } finally {
    await fake.close();
    await fixture.cleanup();
  }
});

test('enrollment follows the Windows profile even when Git Bash exports another HOME', async () => {
  const fixture = await windowsFixture('roaming', { roamingProfile: true });
  const fake = await startFakeUsageServer({ secret: SECRET });
  try {
    const result = await install(fixture, { port: fake.port });
    assert.equal(result.status, 0, result.stderr);
    assert.equal((await readFile(join(fixture.configDir, 'client.secret'), 'utf8')).trim(), SECRET);
    assert.match(await readFile(join(fixture.home, '.claude/settings.json'), 'utf8'), /jaynshare/);

    await assert.rejects(readFile(join(fixture.shellHome, '.config/jaynshare/client.secret')), /ENOENT/,
      'nothing may be enrolled under the HOME Git Bash exported');
    await assert.rejects(readFile(join(fixture.shellHome, '.claude/settings.json')), /ENOENT/);

    // The launcher has to make the same choice or it reads an empty profile.
    const recorder = join(fixture.root, 'stubs/claude');
    await writeFile(recorder, '#!/bin/sh\nprintf \'proxy=%s\\n\' "${HTTPS_PROXY:-}"\n');
    await chmod(recorder, 0o755);
    const auto = await runScript('/bin/sh', [launcher, '--auto', '--', '--version'], { env: fixture.env });
    assert.equal(auto.status, 0, auto.stderr);
    assert.match(auto.stdout,
      new RegExp(`proxy=http://windows-tester:${SECRET}@127\\.0\\.0\\.1:${fake.port}/`));
  } finally {
    await fake.close();
    await fixture.cleanup();
  }
});

test('an install that cannot lock the secret keeps nothing', async () => {
  const fixture = await windowsFixture('acl-failure');
  const fake = await startFakeUsageServer({ secret: SECRET });
  try {
    const result = await install(fixture, { port: fake.port, env: { ICACLS_FAIL: '1' } });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /icacls could not protect/);
    await assert.rejects(readFile(join(fixture.configDir, 'client.secret')), /ENOENT/,
      'a failed install must not leave a secret behind');
  } finally {
    await fake.close();
    await fixture.cleanup();
  }
});

test('an extra principal on the secret fails the install closed', async () => {
  const fixture = await windowsFixture('acl-extra');
  const fake = await startFakeUsageServer({ secret: SECRET });
  try {
    const result = await install(fixture, { port: fake.port, env: { ICACLS_EXTRA_ACE: '1' } });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /not restricted to your account/);
    assert.match(result.stderr, /expected exactly 2 access entries, found 3/);
    await assert.rejects(readFile(join(fixture.configDir, 'client.secret')), /ENOENT/);
  } finally {
    await fake.close();
    await fixture.cleanup();
  }
});

test('an install that cannot authenticate is rolled back to the previous client', async () => {
  const fixture = await windowsFixture('rollback');
  const fake = await startFakeUsageServer({ secret: SECRET });
  try {
    assert.equal((await install(fixture, { port: fake.port })).status, 0);
    const before = await readFile(join(fixture.configDir, 'client.env'), 'utf8');

    // Port 9 is the discard port: closed on every supported runner.
    const failed = await install(fixture, { port: 9, id: 'other-tester' });
    assert.notEqual(failed.status, 0);
    assert.match(failed.stderr, /could not reach the server; nothing was kept/);
    assert.match(failed.stderr, /rolled back/);
    assert.equal(await readFile(join(fixture.configDir, 'client.env'), 'utf8'), before,
      'the working enrollment survives a failed reinstall');

    const still = await runScript(process.execPath,
      [join(fixture.binDir, 'jaynshare'), 'status', '--json'], { env: fixture.env });
    assert.equal(still.status, 0, still.stderr);
  } finally {
    await fake.close();
    await fixture.cleanup();
  }
});

test('a malformed secret is rejected before anything is written', async () => {
  const fixture = await windowsFixture('bad-secret');
  try {
    const result = await install(fixture, { port: 9, stdin: 'secret with spaces\n' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unexpected characters/);
    assert.equal(result.stderr.includes('secret with spaces'), false,
      'a rejected secret must not be echoed back');
    await assert.rejects(readFile(join(fixture.configDir, 'client.env')), /ENOENT/);
  } finally {
    await fixture.cleanup();
  }
});

test('a Windows shell with a non-Windows Node is refused with an actionable message', async () => {
  const fixture = await windowsFixture('mismatch');
  try {
    const uname = join(fixture.root, 'stubs/uname');
    await writeFile(uname, '#!/bin/sh\nprintf \'MINGW64_NT-10.0\\n\'\n');
    await chmod(uname, 0o755);
    const result = await install(fixture, { port: 9, env: { JAYNSHARE_PLATFORM: 'linux' } });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /this shell runs on Windows but node reports "linux"/);
    assert.match(result.stderr, /install the Windows build of Node\.js 26\+/);
  } finally {
    await fixture.cleanup();
  }
});

test('the launcher builds an authenticated proxy URL without putting the secret in argv', async () => {
  const fixture = await windowsFixture('launcher');
  const fake = await startFakeUsageServer({ secret: SECRET });
  try {
    assert.equal((await install(fixture, { port: fake.port })).status, 0);

    const recorder = join(fixture.root, 'stubs/claude');
    await writeFile(recorder, '#!/bin/sh\n'
      + 'printf \'proxy=%s\\n\' "${HTTPS_PROXY:-}"\n'
      + 'printf \'ca=%s\\n\' "${NODE_EXTRA_CA_CERTS:-}"\n'
      + 'printf \'ps=%s\\n\' "$(ps -o args= -p $$ 2>/dev/null)"\n'
      + 'printf \'arg=%s\\n\' "$@"\n');
    await chmod(recorder, 0o755);

    const auto = await runScript('/bin/sh', [launcher, '--auto', '--', '--model', 'opus', 'two words'],
      { env: fixture.env });
    assert.equal(auto.status, 0, auto.stderr);
    assert.match(auto.stdout, new RegExp(`proxy=http://windows-tester:${SECRET}@127\\.0\\.0\\.1:${fake.port}/`));
    assert.match(auto.stdout, /arg=--model\narg=opus\narg=two words/);
    assert.equal(auto.stdout.includes(`ps=${SECRET}`), false,
      'the secret must not be visible in the process command line');

    const ca = auto.stdout.match(/^ca=(.*)$/m)[1];
    assert.equal(await readFile(ca, 'utf8').then(text => text.includes('BEGIN CERTIFICATE')), true,
      'NODE_EXTRA_CA_CERTS has to point at a file this Node can read');
    assert.match(await fixture.cygpathLog(), /jaynshare-ca\.pem/,
      'the CA path is converted for native Node rather than passed as an MSYS spelling');

    const account = await runScript('/bin/sh', [launcher, '--account', 'second@example.com', '--', '--print'],
      { env: fixture.env });
    assert.equal(account.status, 0, account.stderr);
    assert.match(account.stdout, /proxy=http:\/\/JAYNSHARE-PREF-v1-[A-Za-z0-9_-]+:/);

    const direct = await runScript('/bin/sh', [launcher, '--direct', '--', '--version'], { env: fixture.env });
    assert.equal(direct.status, 0, direct.stderr);
    assert.match(direct.stdout, /proxy=\n/, '--direct is the only escape hatch and it clears the proxy');
    assert.equal(direct.stdout.includes(SECRET), false);
  } finally {
    await fake.close();
    await fixture.cleanup();
  }
});

test('the launcher refuses to fall back to the local Claude account', async () => {
  const fixture = await windowsFixture('no-fallback');
  const fake = await startFakeUsageServer({ secret: SECRET });
  try {
    assert.equal((await install(fixture, { port: fake.port })).status, 0);
    await fake.close();

    const marker = join(fixture.root, 'claude-ran');
    const recorder = join(fixture.root, 'stubs/claude');
    await writeFile(recorder, `#!/bin/sh\n: > ${JSON.stringify(marker)}\n`);
    await chmod(recorder, 0o755);

    const result = await runScript('/bin/sh', [launcher, '--auto', '--', '--version'], { env: fixture.env });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Jaynshare proxy is unreachable; refusing direct fallback/);
    await assert.rejects(readFile(marker), /ENOENT/, 'Claude must not start on the local account');
  } finally {
    await fake.close().catch(() => {});
    await fixture.cleanup();
  }
});

test('an upgrade reuses the existing enrollment and never prompts', async () => {
  const fixture = await windowsFixture('upgrade');
  const fake = await startFakeUsageServer({ secret: SECRET });
  try {
    assert.equal((await install(fixture, { port: fake.port })).status, 0);
    const before = await readFile(join(fixture.configDir, 'client.secret'), 'utf8');

    const upgrade = await runScript('/bin/sh', [installer, '--upgrade'], { env: fixture.env, stdin: '' });
    assert.equal(upgrade.status, 0, upgrade.stderr);
    assert.match(upgrade.stdout, /Updated the Jaynshare desktop client/);
    assert.equal(upgrade.stderr.includes('Client secret:'), false);
    assert.equal(await readFile(join(fixture.configDir, 'client.secret'), 'utf8'), before);
  } finally {
    await fake.close();
    await fixture.cleanup();
  }
});
