// Self-update for global npm installs, checked at most once a day. A git
// checkout is never touched; a local copy only gets a notice.

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { getConfigPath } from './config.js';

export const PKG_NAME = '@jaynlabs/jaynshare';
const REGISTRY = 'https://registry.npmjs.org';
const DAY_MS = 24 * 60 * 60 * 1000;

function packageRoot() {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..');
}

export function currentVersion(root = packageRoot()) {
  try {
    return JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version || null;
  } catch {
    return null;
  }
}

export function compareVersions(a, b) {
  const numericParts = (v) => String(v).split('+')[0].split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
  const versionAParts = numericParts(a), versionBParts = numericParts(b);
  for (let i = 0; i < 3; i++) {
    const diff = (versionAParts[i] || 0) - (versionBParts[i] || 0);
    if (diff) return diff;
  }
  return 0;
}

function npmGlobalRoot() {
  try {
    const result = spawnSync('npm', ['root', '-g'], { encoding: 'utf8', timeout: 5000 });
    if (result.status === 0 && result.stdout) return result.stdout.trim();
  } catch { /* npm missing */ }
  return null;
}

export function installKind({ root = packageRoot(), globalRoot = npmGlobalRoot } = {}) {
  if (existsSync(join(root, '.git'))) return 'git';
  const normalizedRoot = root.split('\\').join('/');
  if (!normalizedRoot.includes('/node_modules/')) return 'unknown';
  const globalRootPath = typeof globalRoot === 'function' ? globalRoot() : globalRoot;
  if (globalRootPath && normalizedRoot.startsWith(globalRootPath.split('\\').join('/'))) return 'global';
  return 'local';
}

export async function fetchLatestVersion({ fetchImpl = fetch, timeoutMs = 5000 } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(`${REGISTRY}/${PKG_NAME}`, {
      signal: ctrl.signal,
      headers: { accept: 'application/vnd.npm.install-v1+json' }, // abbreviated packument
    });
    if (!res.ok) return null;
    const json = await res.json();
    return json['dist-tags']?.latest || null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function defaultCacheFile() {
  return join(dirname(getConfigPath()), 'update-check.json');
}
async function readCache(path) {
  try { return JSON.parse(await readFile(path, 'utf8')); } catch { return {}; }
}
async function writeCache(path, cache) {
  try { await writeFile(path, JSON.stringify(cache)); } catch { /* best effort */ }
}

export async function checkForUpdate({
  current = currentVersion(),
  cachePath = defaultCacheFile(),
  fetchImpl = fetch,
  now = Date.now(),
  intervalMs = DAY_MS,
  force = false,
} = {}) {
  if (!current) return null;
  const cache = await readCache(cachePath);
  let latest = cache.latest || null;
  const fresh = cache.checkedAt && (now - cache.checkedAt) < intervalMs;
  if (force || !fresh) {
    const fetched = await fetchLatestVersion({ fetchImpl });
    if (fetched) latest = fetched;
    await writeCache(cachePath, { checkedAt: now, latest });
  }
  if (!latest) return null;
  return { current, latest, updateAvailable: compareVersions(latest, current) > 0 };
}

export function runUpdate(version = 'latest', { spawnImpl = spawnSync } = {}) {
  const result = spawnImpl('npm', ['install', '-g', `${PKG_NAME}@${version}`], {
    stdio: 'inherit',
    timeout: 180000,
  });
  return !!result && !result.error && result.status === 0;
}

export async function autoUpdate({ config = {}, force = false, log = console.error } = {}) {
  const root = packageRoot();
  if (existsSync(join(root, '.git'))) return { skipped: 'git' };
  if (process.env.JAYNSHARE_DISABLE_AUTOUPDATE || config.autoUpdate === false) {
    return { skipped: 'disabled' };
  }
  const info = await checkForUpdate({ force });
  if (!info) return { skipped: 'check-failed' };
  if (!info.updateAvailable) return { ...info, upToDate: true };

  if (installKind({ root }) !== 'global') {
    log(`[Jaynshare] Update available: ${info.current} → ${info.latest}. Run: jaynshare update`);
    return { ...info, notified: true };
  }
  log(`[Jaynshare] Updating ${info.current} → ${info.latest}…`);
  const ok = runUpdate(info.latest);
  log(ok
    ? `[Jaynshare] Updated to ${info.latest}. Restart jaynshare to use the new version.`
    : `[Jaynshare] Auto-update failed. Run manually: npm install -g ${PKG_NAME}@latest`);
  return { ...info, updated: ok };
}
