import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { resolveUpstreamProxy, setUpstreamProxy } from './upstream-proxy.ts';
import { validateClientConfig } from './client-auth.ts';
import type { Config } from './types.ts';

export function getConfigPath(): string {
  if (process.env.JAYNSHARE_CONFIG) return process.env.JAYNSHARE_CONFIG;
  const configDir = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(configDir, 'jaynshare.json');
}

export function getStatePath(): string {
  const cfg = getConfigPath();
  return cfg.endsWith('.json') ? cfg.replace(/\.json$/, '.state.json') : cfg + '.state';
}

export function getCrashLogPath(): string {
  const cfg = getConfigPath();
  return cfg.endsWith('.json') ? cfg.replace(/\.json$/, '-crash.log') : cfg + '-crash.log';
}

export async function loadState(): Promise<any> {
  try {
    return JSON.parse(await readFile(getStatePath(), 'utf-8'));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function saveState(state: any): Promise<void> {
  await writePrivateJson(getStatePath(), state);
}

async function writePrivateJson(path: string, data: any): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  await chmod(path, 0o600).catch(() => {}); // `mode` applies only on create
}

function createDefaultConfig(): Config {
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

export async function loadConfig(): Promise<Config | null> {
  const path = getConfigPath();
  try {
    const config = JSON.parse(await readFile(path, 'utf-8')) as Config;
    validateClientConfig(config.proxy || {});
    applyUpstreamProxy(config);
    return config;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

function applyUpstreamProxy(config: Config): void {
  try {
    setUpstreamProxy(resolveUpstreamProxy(config));
  } catch (err) {
    console.error(`[Jaynshare] Bad proxy setting in ${getConfigPath()}: ${(err as Error).message}`);
    process.exit(1);
  }
}

export async function loadOrCreateConfig(): Promise<Config> {
  let config = await loadConfig();
  if (!config) {
    config = createDefaultConfig();
    await saveConfig(config);
    console.log(`Created config at ${getConfigPath()}`);
  }
  return config;
}

export async function saveConfig(config: Config): Promise<void> {
  await writePrivateJson(getConfigPath(), config);
}

// Read-modify-write updates are chained so concurrent callers never clobber each other.
let configUpdateChain = Promise.resolve();

export function atomicConfigUpdate<T>(updater: (config: Config) => T | Promise<T>): Promise<T> {
  const run = async (): Promise<T> => {
    const config = await loadConfig() || createDefaultConfig();
    await updater(config);
    await saveConfig(config);
    return config as T;
  };
  const result = configUpdateChain.then(run, run);
  configUpdateChain = result.then(() => {}, () => {});
  return result;
}
