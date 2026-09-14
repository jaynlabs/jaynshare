// The `claude` shell alias that routes through `jaynshare run`: one line in the
// rc file, interactive shells only.

import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync, realpathSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

const MARKER = '# jaynshare alias';

function detectShell() {
  return (process.env.SHELL || '').split('/').pop() || 'bash';
}

function commandOnPath(cmd) {
  for (const dir of (process.env.PATH || '').split(':')) {
    if (dir && existsSync(join(dir, cmd))) return true;
  }
  return false;
}

export function jaynshareRef() {
  if (commandOnPath('jaynshare')) return 'jaynshare';
  const entry = process.argv[1]; // not installed on PATH (a clone): embed this CLI's path
  if (!entry) return 'jaynshare';
  let abs;
  try { abs = realpathSync(entry); } catch { abs = entry; }
  return `"${abs}"`;
}

export function aliasLine(shell = detectShell(), ref = jaynshareRef()) {
  const body = `${ref} run --`;
  if (shell === 'fish') return `alias claude '${body}'`;
  return `alias claude='${body}'`;
}

export function rcPathForShell(shell = detectShell()) {
  const home = homedir();
  switch (shell) {
    case 'zsh':  return join(home, '.zshrc');
    case 'sh':   return join(home, '.profile');
    case 'fish': {
      const cfg = process.env.XDG_CONFIG_HOME || join(home, '.config');
      return join(cfg, 'fish', 'conf.d', 'jaynshare.fish');
    }
    case 'bash':
    default:     return join(home, '.bashrc');
  }
}

export function printAlias({ shell = detectShell() } = {}) {
  const line = aliasLine(shell);
  console.log('# Route plain `claude` through the proxy (errors if the proxy is down;');
  console.log('# append --auto-fallback before `--` to launch claude directly instead).');
  console.log('# Add this to your shell config:');
  console.log('');
  console.log(`  ${line}`);
  console.log('');
  console.log(`# Or install it automatically: jaynshare alias --install`);
  console.log(`#   → writes to ${rcPathForShell(shell)} (override with --shell <bash|zsh|fish|sh>)`);
}

export function installAlias({ shell = detectShell(), rcPath = rcPathForShell(shell) } = {}) {
  const line = aliasLine(shell);
  mkdirSync(dirname(rcPath), { recursive: true });
  let text = existsSync(rcPath) ? readFileSync(rcPath, 'utf8') : '';

  if (text.includes(line)) {
    console.log(`Alias already present in ${rcPath}`);
    return;
  }
  if (text && !text.endsWith('\n')) text += '\n';
  text += `${MARKER}\n${line}\n`;
  writeFileSync(rcPath, text);
  console.log(`Installed alias in ${rcPath}`);
  console.log('Reload your shell (or open a new terminal) to use it.');
}

export function uninstallAlias({ shell = detectShell(), rcPath = rcPathForShell(shell) } = {}) {
  if (!existsSync(rcPath)) {
    console.log(`Nothing to remove (${rcPath} does not exist)`);
    return;
  }
  const text = readFileSync(rcPath, 'utf8');
  // Match on the marker, not the alias text: the embedded path may have changed.
  const blockRe = new RegExp(`\\n?${escapeRe(MARKER)}\\n[^\\n]*\\n?`, 'g');
  let cleaned = text.replace(blockRe, '\n');
  cleaned = cleaned.replace(/\n{3,}/g, '\n\n');

  if (cleaned === text) {
    console.log(`Alias not found in ${rcPath}`);
    return;
  }

  if (rcPath.endsWith('jaynshare.fish') && cleaned.trim() === '') {
    rmSync(rcPath);
    console.log(`Removed ${rcPath}`);
    return;
  }
  writeFileSync(rcPath, cleaned);
  console.log(`Removed alias from ${rcPath}`);
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
