import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { resolveUpstreamProxy, setUpstreamProxy } from './upstream-proxy.js';
import { validateClientConfig } from './client-auth.js';

export function getConfigPath() {
  if (process.env.JAYNSHARE_CONFIG) return process.env.JAYNSHARE_CONFIG;
  const configDir = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(configDir, 'jaynshare.json');
}

export function getStatePath() {
  const cfg = getConfigPath();
  return cfg.endsWith('.json') ? cfg.replace(/\.json$/, '.state.json') : cfg + '.state';
}

export function getCrashLogPath() {
  const cfg = getConfigPath();
  return cfg.endsWith('.json') ? cfg.replace(/\.json$/, '-crash.log') : cfg + '-crash.log';
}

export async function loadState() {
  try {
    return JSON.parse(await readFile(getStatePath(), 'utf-8'));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

export async function saveState(state) {
  await writePrivateJson(getStatePath(), state);
}

async function writePrivateJson(path, data) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  await chmod(path, 0o600).catch(() => {}); // `mode` applies only on create
}

function createDefaultConfig() {
  return {
    proxy: {
      port: 3456,
      clients: [],
    },
    upstream: 'https://api.anthropic.com',
    switchThreshold: 0.98,
    holdSeconds: 0,
    distributeSessions: false,
    eventLogging: 'hide',
    blockedModels: [],
    accounts: [],
  };
}

export async function loadConfig() {
  const path = getConfigPath();
  try {
    const config = JSON.parse(await readFile(path, 'utf-8'));
    validateClientConfig(config.proxy || {});
    applyUpstreamProxy(config);
    return config;
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

function applyUpstreamProxy(config) {
  try {
    setUpstreamProxy(resolveUpstreamProxy(config));
  } catch (err) {
    console.error(`[Jaynshare] Bad proxy setting in ${getConfigPath()}: ${err.message}`);
    process.exit(1);
  }
}

export async function loadOrCreateConfig() {
  let config = await loadConfig();
  if (!config) {
    config = createDefaultConfig();
    await saveConfig(config);
    console.log(`Created config at ${getConfigPath()}`);
  }
  return config;
}

export async function saveConfig(config) {
  await writePrivateJson(getConfigPath(), config);
}

// Read-modify-write updates are chained so concurrent callers never clobber each other.
let configUpdateChain = Promise.resolve();

export function atomicConfigUpdate(updater) {
  const run = async () => {
    const config = await loadConfig() || createDefaultConfig();
    await updater(config);
    await saveConfig(config);
    return config;
  };
  const result = configUpdateChain.then(run, run);
  configUpdateChain = result.then(() => {}, () => {});
  return result;
}
