#!/usr/bin/env node

import { chmod, copyFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

const home = homedir();
const claudeDir = join(home, '.claude');
const settingsPath = join(claudeDir, 'settings.json');
const backupPath = join(claudeDir, 'settings.json.before-jaynshare');
const themeDir = join(claudeDir, 'themes');
const themePath = join(themeDir, 'jaynshare.json');

function option(argv, name) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) return null;
  const value = argv[index + 1];
  if (typeof value !== 'string' || value.startsWith('--')) {
    throw new Error(`--${name} requires a value`);
  }
  return value;
}

// install.sh passes the platform it detected with `node -p process.platform`
// plus, on Windows, the native path it produced with `cygpath -w`. Keeping both
// decisions in one place means the settings file can never disagree with where
// the client was actually installed.
function clientCommandFor(platform, clientPath) {
  if (platform !== 'win32') return '~/.local/bin/jaynshare';
  if (!clientPath) throw new Error('--client-path is required when --platform is win32');
  if (/["\r\n]/.test(clientPath)) throw new Error('client path contains unsupported characters');
  // The extensionless helper is not directly executable on Windows, and Claude
  // Code may run this through either Git Bash or cmd.exe. `node "<path>"` is
  // parsed identically by both, and JSON.stringify escapes the backslashes.
  return `node "${clientPath}"`;
}

const argv = process.argv.slice(2);
const platform = option(argv, 'platform') || process.platform;
const clientCommand = clientCommandFor(platform, option(argv, 'client-path'));

async function readSettings() {
  try {
    return JSON.parse(await readFile(settingsPath, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    if (err instanceof SyntaxError) {
      throw new Error(`${settingsPath} is not valid JSON; fix it before installing Jaynshare UI settings`);
    }
    throw err;
  }
}

async function atomicJson(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.jaynshare-tmp-${process.pid}`;
  await writeFile(temp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  await rename(temp, path);
  await chmod(path, 0o600).catch(() => {});
}

const settings = await readSettings();
await mkdir(claudeDir, { recursive: true, mode: 0o700 });
await copyFile(settingsPath, backupPath, constants.COPYFILE_EXCL).catch(err => {
  if (err.code !== 'ENOENT' && err.code !== 'EEXIST') throw err;
});

settings.theme = 'custom:jaynshare';
settings.statusLine = {
  type: 'command',
  command: `${clientCommand} status --line`,
  refreshInterval: 15,
  padding: 1,
};

settings.hooks ||= {};
settings.hooks.UserPromptSubmit ||= [];
const titleCommand = `${clientCommand} title-hook`;
const hasTitleHook = settings.hooks.UserPromptSubmit.some(group =>
  Array.isArray(group?.hooks) && group.hooks.some(hook => hook?.command === titleCommand));
if (!hasTitleHook) {
  settings.hooks.UserPromptSubmit.push({
    hooks: [{ type: 'command', command: titleCommand, timeout: 2 }],
  });
}

await atomicJson(settingsPath, settings);
await mkdir(themeDir, { recursive: true, mode: 0o700 });
await atomicJson(themePath, {
  name: 'Jaynshare',
  base: 'dark',
  overrides: {
    claude: '#f7c600',
    claudeShimmer: '#ffe680',
    promptBorder: '#f7c600',
    promptBorderShimmer: '#ffe680',
    rate_limit_fill: '#f7c600',
  },
});

process.stdout.write(`Configured yellow Jaynshare theme, status line and session titles in ${settingsPath}\n`);
if (await readFile(backupPath, 'utf8').then(() => true, () => false)) {
  process.stdout.write(`Previous Claude settings copied to ${backupPath}\n`);
}
