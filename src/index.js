#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createWriteStream, readFileSync } from 'node:fs';
import net from 'node:net';
import { loadOrCreateConfig, loadConfig, saveConfig, atomicConfigUpdate, getConfigPath, getCrashLogPath, loadState, saveState } from './config.js';
import { installCrashHandlers } from './crash-log.js';
import { AccountManager } from './account-manager.js';
import { createProxyServer } from './server.js';
import { importCredentials, loginOAuth, fetchProfile, refreshAccessToken, isTokenExpiringSoon } from './oauth.js';
import { sameIdentity, orgKey, matchAccounts, findUpsertTarget, orgLabel, withOrgSuffixes } from './identity.js';
import { resolveAccounts } from './resolve-accounts.js';
import * as alias from './alias.js';
import { ensureCerts } from './mitm.js';
import { Prober } from './prober.js';
import { Warmer } from './warmer.js';
import { TUI } from './tui.js';
import { RemoteControl, createAttachSession } from './tui-remote.js';
import { SxManager } from './sx.js';
import { autoUpdate, checkForUpdate, currentVersion, runUpdate, installKind, PKG_NAME } from './updater.js';
import { renderStatus } from './status-renderer.js';
import { buildClaudeEnvLines, encodePinComponent } from './claude-env.js';
import { serviceKind, installService, uninstallService, serviceStatus, renderService, logPath } from './service.js';
import { formatTerminalTitle, titleSequence, TITLE_STACK_PUSH, TITLE_STACK_POP } from './terminal-title.js';
import { getUpstreamProxy, describeProxy } from './upstream-proxy.js';
import { clientById, generateClientSecret, hashClientSecret, resolvePrincipal, validClientId } from './client-auth.js';
import { AuditLog, auditHooks } from './audit-log.js';

const args = process.argv.slice(2);
const command = args[0];

const COMMANDS = {
  server: serverCommand,
  run: runCommand,
  import: importCommand,
  login: loginCommand,
  env: envCommand,
  status: statusCommand,
  attach: attachCommand,
  accounts: accountsCommand,
  client: clientCommand,
  clients: clientCommand,
  switch: switchCommand,
  remove: removeCommand,
  priority: priorityCommand,
  disable: () => setAccountRotation(DISABLE),
  enable: () => setAccountRotation(ENABLE),
  api: apiCommand,
  alias: aliasCommand,
  service: serviceCommand,
  probe: probeCommand,
  warmup: warmupCommand,
  route: routeCommand,
  routes: routeCommand,
  update: updateCommand,
  version: printVersion,
  '--version': printVersion,
  '-V': printVersion,
  help: showHelp,
  '--help': showHelp,
  '-h': showHelp,
};

// `server` and `run` return while still owning the process; help lets a piped stdout drain.
const NO_EXIT = new Set(['server', 'run', 'help', '--help', '-h']);

function resolveCommand(name) {
  if (Object.hasOwn(COMMANDS, name)) return [COMMANDS[name], !NO_EXIT.has(name)];
  if (!name || name.startsWith('-')) return [serverCommand, false]; // bare flags start the server
  console.error(`Unknown command: ${name}\n`);
  showHelp();
  process.exit(1);
}

function printVersion() {
  console.log(currentVersion() || 'unknown');
}

// ── server ──────────────────────────────────────────────────

async function serverCommand() {
  const config = await loadServerConfig();
  const accounts = await resolveServerAccounts(config);

  const threshold = config.switchThreshold || 0.98;
  const accountManager = new AccountManager(accounts, threshold, { routes: config.routes, ramp: config.stormRamp, distributeSessions: config.distributeSessions });
  await restoreQuota(accountManager);
  persistRefreshedTokens(accountManager, config);

  const port = config.proxy.port;
  // A wider bind needs proxy.apiKey: the proxy injects tokens and relays CONNECT.
  const bindHost = process.env.JAYNSHARE_HOST || config.proxy.host || '127.0.0.1';
  const headless = args.includes('--headless') || args.includes('--no-tui');
  const useTUI = !headless && process.stdout.isTTY && process.stdin.isTTY;
  const activityLogPath = argValue('--activity-log') || null;

  const sx = await createSxManager(config);
  const prober = new Prober(accountManager, { intervalMs: (config.quotaProbeSeconds || 0) * 1000 });
  const warmer = new Warmer(accountManager, {
    intervalMs: (config.warmupSeconds || 0) * 1000,
    port,
    apiKey: config.proxy?.apiKey,
  });
  const background = { prober, warmer };
  const reloadAccounts = makeReloadAccounts({ config, accountManager, sx, prober, warmer });

  const tui = useTUI ? new TUI({
    accountManager, config, sx, activityLogPath,
    saveConfig: () => atomicConfigUpdate(diskConfig => writeRuntimeConfig(diskConfig, config, accountManager)),
    syncAccounts: reloadAccounts,
    probeQuota: () => prober.probeAll(),
    onQuit: () => shutdown(), // raw mode: ctrl-c never reaches the OS as a signal
  }) : null;

  const hooks = serverHooks({ tui, activityLogPath }, { config, background, reloadAccounts });
  const server = createProxyServer(accountManager, config, { hooks, sx });
  const onListenError = err => handleServerListenError(err, port);
  server.once('error', onListenError);

  server.listen(port, bindHost, () => {
    server.removeListener('error', onListenError); // a runtime error is not a listen failure
    server.on('error', err => console.error(`[Jaynshare] Server error: ${err.message}`));
    announceUpstreamProxy();
    if (tui) {
      tui.start();
      console.log(`Listening on port ${port} with ${accounts.length} account(s)`);
    } else {
      printStartupBanner({ bindHost, port, accounts, threshold, config });
    }
  });

  const stopTitle = startTerminalTitleUpdater(accountManager);
  const stopQuotaPersistence = persistQuotaPeriodically(accountManager);

  prober.start();
  warmer.start();

  if (!tui) autoUpdate({ config }).catch(() => {}); // npm output would corrupt the TUI

  const shutdown = makeShutdown({ server, tui, background, stop: [stopTitle, stopQuotaPersistence] });
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

function saveQuotaState(accountManager) {
  return saveState({ quota: accountManager.exportQuotaState() })
    .catch(err => console.error(`[Jaynshare] Failed to save quota state: ${err.message}`));
}

/** Returns a stop() that also flushes the state one last time. */
function persistQuotaPeriodically(accountManager, everyMs = 60_000) {
  const timer = setInterval(() => saveQuotaState(accountManager), everyMs);
  timer.unref?.();
  return () => {
    clearInterval(timer);
    return saveQuotaState(accountManager);
  };
}

/** Request hooks: the TUI's activity pane, a headless log, or neither — plus the audit log and control-plane extras. */
function serverHooks({ tui, activityLogPath }, { config, background, reloadAccounts }) {
  const startedAt = Date.now();
  let hooks = {};
  if (tui) {
    hooks = {
      onRequestStart: (id, info) => tui.onRequestStart(id, info),
      onRequestModel: (id, info) => tui.onRequestModel(id, info),
      onRequestRouted: (id, info) => tui.onRequestRouted(id, info),
      onRequestEnd: (id, info) => tui.onRequestEnd(id, info),
    };
  } else if (activityLogPath) {
    hooks = activityLogHooks(activityLogPath);
  }

  if (config.auditLog?.path) hooks = auditHooks(new AuditLog(config.auditLog), hooks);

  hooks.reload = reloadAccounts;
  hooks.getStatusExtra = () => ({
    blockedModels: [...(config.blockedModels || [])],
    server: {
      startedAt: new Date(startedAt).toISOString(),
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      port: config.proxy.port,
      upstream: config.upstream || 'https://api.anthropic.com',
    },
    probe: background.prober.getStatus(),
    warm: background.warmer.getStatus(),
  });
  return hooks;
}

/** Idempotent; a second signal exits at once rather than waiting for the drain. */
function makeShutdown({ server, tui, background, stop }) {
  let shuttingDown = false;
  return async () => {
    if (shuttingDown) process.exit(0); // second ctrl-c
    shuttingDown = true;
    try { tui?.stop(); } catch { /* terminal already restored */ }
    if (!tui) console.log('\n[Jaynshare] Shutting down...');
    background.prober.stop();
    background.warmer.stop();
    await Promise.all(stop.map(fn => fn()));
    setTimeout(() => process.exit(0), 2000).unref?.();
    server.closeAllConnections?.();
    server.close(() => process.exit(0));
  };
}

// ── server startup phases ───────────────────────────────────

/** Exits the process when a startup guard fails. */
async function loadServerConfig() {
  installCrashHandlers(getCrashLogPath()); // the TUI repaints over anything Node prints on the way out

  const config = await loadOrCreateConfig();

  const logTo = argValue('--log-to');
  if (logTo) config.logDir = logTo;
  if (config.logDir && config.auditLog?.path) {
    console.error('Refusing to combine full request-body logging with privacy audit logging. Remove logDir/--log-to.');
    process.exit(1);
  }

  if (config.accounts.length === 0) {
    console.error('No accounts configured.\n');
    console.error('Add an account first:');
    console.error('  jaynshare import           Import from Claude Code');
    console.error('  jaynshare login            OAuth login via browser');
    console.error('  jaynshare login --api      Add an API key');
    process.exit(1);
  }

  return config;
}

/** Exits if no account survives resolution. */
async function resolveServerAccounts(config) {
  const accounts = await resolveAccounts(config);
  if (accounts.length === 0) {
    console.error('No valid accounts after initialization');
    process.exit(1);
  }

  for (const acct of config.accounts) {
    if (!acct.models?.length) continue;
    const route = { name: acct.name, match: acct.models, accounts: [acct.name] };
    console.error(`[Jaynshare] Deprecated: account "${acct.name}" uses "models" — replace it with a routes entry: ${JSON.stringify(route)}`);
  }

  return accounts;
}

async function restoreQuota(accountManager) {
  const savedState = await loadState().catch(err => {
    console.error(`[Jaynshare] Could not read saved state: ${err.message}`);
    return null;
  });
  if (savedState?.quota) accountManager.restoreQuotaState(savedState.quota);
  accountManager.selectActiveAccount();
}

function persistRefreshedTokens(accountManager, config) {
  accountManager.onTokenRefresh((idx, newTokens) => {
    const account = accountManager.accounts[idx];
    if (!account) return;
    if (config.accounts[idx]) { // a TUI save would otherwise clobber the fresh tokens
      config.accounts[idx].accessToken = newTokens.accessToken;
      config.accounts[idx].refreshToken = newTokens.refreshToken;
      config.accounts[idx].expiresAt = newTokens.expiresAt;
    }
    atomicConfigUpdate(diskConfig => {
      for (const diskAcct of diskConfig.accounts) { // accounts added externally while running
        const known = config.accounts.some(a => sameIdentity(a, diskAcct));
        if (!known) {
          config.accounts.push(diskAcct);
          accountManager.addAccount(diskAcct);
        }
      }
      const cfgIdx = findConfigAccount(diskConfig, account);
      if (cfgIdx >= 0) {
        diskConfig.accounts[cfgIdx].accessToken = newTokens.accessToken;
        diskConfig.accounts[cfgIdx].refreshToken = newTokens.refreshToken;
        diskConfig.accounts[cfgIdx].expiresAt = newTokens.expiresAt;
      }
    }).catch(err => console.error(`[Jaynshare] Failed to save refreshed token: ${err.message}`));
  });
}

async function createSxManager(config) {
  const sx = new SxManager({ log: console.error });
  if (config.sx?.apiKey) {
    const r = await sx.configure(config.sx.apiKey, config.sx.mode);
    if (!r.ok) console.error(`[Jaynshare] sx.org disabled: ${r.error}`);
  } else if (config.sx?.mode) {
    await sx.setMode(config.sx.mode);
  }
  return sx;
}

/** Applies disk config changes to the running server; returns the number of accounts added. */
function makeReloadAccounts({ config, accountManager, sx, prober, warmer }) {
  return async () => {
    const diskConfig = await loadConfig();
    if (!diskConfig) return 0;
    const added = await syncAccountsFromDisk(diskConfig, config, accountManager);
    config.proxy = diskConfig.proxy || { port: config.proxy?.port || 3456, clients: [] }; // client auth reads it live
    config.routes = diskConfig.routes || [];
    accountManager.setRoutes(config.routes);
    const diskSxKey = diskConfig.sx?.apiKey || null;
    const diskSxMode = diskConfig.sx?.mode || 'always';
    if (diskSxKey !== sx.apiKey || diskSxMode !== sx.mode) {
      config.sx = diskConfig.sx;
      if (diskSxKey) await sx.configure(diskSxKey, diskSxMode);
      else { sx.disable(); await sx.setMode(diskSxMode); }
    }
    const probeMs = (diskConfig.quotaProbeSeconds || 0) * 1000;
    if (probeMs !== prober.intervalMs) {
      config.quotaProbeSeconds = diskConfig.quotaProbeSeconds || 0;
      prober.reschedule(probeMs);
    }
    const warmMs = (diskConfig.warmupSeconds || 0) * 1000;
    if (warmMs !== warmer.intervalMs) {
      config.warmupSeconds = diskConfig.warmupSeconds || 0;
      warmer.reschedule(warmMs);
    }
    return added;
  };
}

/** Projects the server's live state onto the config being written. */
function writeRuntimeConfig(diskConfig, config, accountManager) {
  // Live tokens win; disk-only fields (importFrom) survive.
  diskConfig.accounts = config.accounts.map((a, i) => {
    const am = accountManager.accounts[i];
    const live = am ? {
      ...a,
      accessToken: am.credential,
      refreshToken: am.refreshToken,
      expiresAt: am.expiresAt,
    } : a;
    const diskAcct = diskConfig.accounts.find(d => sameIdentity(d, a));
    return diskAcct ? { ...diskAcct, ...live } : live;
  });
  if (config.sx) diskConfig.sx = config.sx; else delete diskConfig.sx;
  if (config.switchThreshold != null) diskConfig.switchThreshold = config.switchThreshold;
  if (config.quotaProbeSeconds != null) diskConfig.quotaProbeSeconds = config.quotaProbeSeconds;
  if (config.warmupSeconds != null) diskConfig.warmupSeconds = config.warmupSeconds;
  if (config.routes != null) diskConfig.routes = config.routes;
}

/** The headless equivalent of the TUI's activity pane. */
function activityLogHooks(activityLogPath) {
  const aStream = createWriteStream(activityLogPath, { flags: 'a' });
  aStream.on('error', err => process.stderr.write(`[Jaynshare] activity log error: ${err.message}\n`));
  const ts = () => new Date().toLocaleTimeString('en-US', { hour12: false });
  const writeActivity = msg => {
    aStream.write(`${ts()}  ${msg.replace(/^\[Jaynshare\]\s*/, '')}\n`);
  };

  const inFlight = new Map();
  const hooks = {
    onRequestStart: (id, info) => inFlight.set(id, { ...info, started: Date.now() }),
    onRequestModel: (id, info) => {
      const r = inFlight.get(id);
      if (r && info.model) r.model = info.model;
    },
    onRequestRouted: (id, info) => {
      const r = inFlight.get(id);
      if (r) r.account = info.account;
    },
    onRequestEnd: (id, info) => {
      const r = inFlight.get(id);
      inFlight.delete(id);
      const dur = r ? ((Date.now() - r.started) / 1000).toFixed(1) : '?';
      const acct = info.account || r?.account || '?';
      const model = info.model ? ` (${info.model})` : '';
      const sid = info.sessionId ? `${info.sessionId.slice(0, 6)} ` : '';
      const pin = (info.pinned || r?.pinned) ? ' [pin]' : '';
      writeActivity(`${sid}${info.method} ${info.path}${model} → ${acct}${pin} (${info.status}, ${dur}s)`);
    },
  };

  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a) => { const m = a.join(' '); origLog(m); writeActivity(m); };
  console.error = (...a) => { const m = a.join(' '); origErr(m); writeActivity(m); };
  process.on('exit', () => aStream.end());

  return hooks;
}

function announceUpstreamProxy() {
  const egressProxy = getUpstreamProxy();
  if (!egressProxy.proxy) return;
  const via = egressProxy.source.startsWith('env:') ? ` (from ${egressProxy.source.slice(4)})` : '';
  console.log(`[Jaynshare] Upstream proxy: ${describeProxy(egressProxy.proxy)}${via}`);
}

function printStartupBanner({ bindHost, port, accounts, threshold, config }) {
  const sep = '='.repeat(60);
  console.log('');
  console.log(sep);
  console.log('  Jaynshare Proxy');
  console.log(sep);
  console.log(`  Bind:       ${bindHost}:${port}${bindHost === '127.0.0.1' ? ' (localhost only)' : ' (reachable off-box — ensure proxy.apiKey is set)'}`);
  console.log(`  Accounts:   ${accounts.length}`);
  console.log(`  Threshold:  ${(threshold * 100).toFixed(0)}%`);
  console.log(`  Upstream:   ${config.upstream || 'https://api.anthropic.com'}`);
  console.log('');
  accounts.forEach((a, i) => {
    console.log(`  [${i + 1}] ${a.name} (${a.type})`);
  });
  console.log('');
  console.log('  Run Claude through proxy:  jaynshare run');
  console.log('  Show env vars:             jaynshare env');
  console.log(sep);
  console.log('');
}

// ── import ──────────────────────────────────────────────────

async function importCommand() {
  const config = await loadOrCreateConfig();

  let name = argValue('--name');
  const jsonStr = argValue('--json');

  let creds;
  if (jsonStr) { // the credentials file's shape, or its claudeAiOauth object alone
    try {
      const raw = JSON.parse(jsonStr);
      const data = raw.claudeAiOauth || raw;
      if (!data.accessToken) {
        console.error('JSON must contain "accessToken" (directly or under "claudeAiOauth")');
        process.exit(1);
      }
      creds = {
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expiresAt: data.expiresAt,
      };
    } catch (err) {
      console.error(`Failed to parse --json: ${err.message}`);
      process.exit(1);
    }
  } else {
    const fromPath = argValue('--from') || '~/.claude/.credentials.json';
    try {
      creds = await importCredentials(fromPath);
    } catch (err) {
      console.error(`Failed to import from ${fromPath}: ${err.message}`);
      process.exit(1);
    }
  }

  await upsertOAuthAccount(config, { name, creds, source: 'import' });
}

// ── login ───────────────────────────────────────────────────

async function loginCommand() {
  if (args.includes('--api')) {
    await loginApiCommand();
    return;
  }
  if (args.includes('--oauth')) {
    await loginOAuthCommand();
    return;
  }

  if (!process.stdout.isTTY) {
    await loginOAuthCommand();
    return;
  }

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  console.log('Select login method:\n');
  console.log('  1. Claude subscription  (Pro, Max, Team, Enterprise)');
  console.log('  2. Anthropic API key    (Console API billing)');
  console.log('');
  const choice = await new Promise(resolve => rl.question('Choice [1]: ', resolve));
  rl.close();

  switch (choice.trim() || '1') {
    case '1': await loginOAuthCommand(); break;
    case '2': await loginApiCommand(); break;
    default:
      console.error(`Invalid choice: ${choice.trim()}`);
      process.exit(1);
  }
}

async function loginApiCommand() {
  const config = await loadOrCreateConfig();
  let name = argValue('--name');

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const apiKey = await new Promise(resolve => rl.question('Anthropic API key: ', resolve));
  rl.close();

  if (!apiKey.trim()) {
    console.error('No API key provided');
    process.exit(1);
  }

  if (!name) {
    const n = config.accounts.filter(a => a.name.startsWith('api-')).length + 1;
    name = `api-${n}`;
  }

  config.accounts.push({ name, type: 'apikey', apiKey: apiKey.trim() });
  await saveConfig(config);
  console.log(`Added API key account "${name}"`);
  console.log(`Saved to ${getConfigPath()}`);
}

async function loginOAuthCommand() {
  const config = await loadOrCreateConfig();
  let name = argValue('--name');

  console.log('Starting OAuth login...');
  let creds;
  try {
    creds = await loginOAuth();
  } catch (err) {
    console.error(`OAuth login failed: ${err.message}`);
    console.error('');
    console.error('Alternatives:');
    console.error('  jaynshare import        Import from existing Claude Code credentials');
    console.error('  jaynshare login --api   Add an API key instead');
    process.exit(1);
  }

  await upsertOAuthAccount(config, { name, creds, source: 'login' });
}

// ── env ─────────────────────────────────────────────────────

// For `eval "$(jaynshare env)"`: only the export lines go to stdout.
async function envCommand() {
  const config = await loadConfig(); // creating one would print to stdout
  if (!config) {
    process.stderr.write(`No config found at ${getConfigPath()}. Add an account first: jaynshare login\n`);
    process.exit(1);
  }
  const port = config.proxy.port;
  const useMitm = !args.slice(1).includes('--no-mitm');
  const caPath = useMitm ? (await ensureCerts(upstreamHost(config))).caPath : null;
  const account = (process.env.JAYNSHARE_ACCOUNT || '').trim();

  const lines = buildClaudeEnvLines({
    port, useMitm, caPath, holdSeconds: config.holdSeconds,
    account, proxyApiKey: config.proxy?.apiKey || '',
  });
  process.stdout.write(`${lines.join('\n')}\n`);

  await printEnvNotes(config, { port, useMitm, account });
}

/** Everything the operator reads rather than evals, so stdout stays pure shell. */
async function printEnvNotes(config, { port, useMitm, account }) {
  const mode = useMitm ? 'MITM forward-proxy' : 'base-URL';
  process.stderr.write(`# Jaynshare env: ${mode} mode, localhost:${port}\n`);
  if (account) {
    process.stderr.write(`# pinned to account "${account}" (JAYNSHARE_ACCOUNT)\n`);
    if (!(config.accounts || []).some((a, i) => a.name === account || String(i) === account)) {
      process.stderr.write(`# warning: no account named "${account}" in the config — the proxy will refuse this pin\n`);
    }
  }
  process.stderr.write(`# apply to this shell:  eval "$(jaynshare env${useMitm ? '' : ' --no-mitm'})"\n`);
  if (!(await isProxyUp(port))) {
    process.stderr.write(`# note: proxy not running on port ${port} — start it with: jaynshare server\n`);
  }
  if (config.proxy?.apiKey) {
    process.stderr.write(`# remote (non-loopback) clients must also present the proxy key: ANTHROPIC_API_KEY=<proxy.apiKey> (base-URL), or http://<key>@host:${port} (MITM)\n`);
  }
}

// ── run ─────────────────────────────────────────────────────

async function runCommand() {
  const config = await loadOrCreateConfig();
  const { flags, claudeArgs } = splitRunArgs(args.slice(1));
  const port = config.proxy.port;

  const account = (process.env.JAYNSHARE_ACCOUNT || '').trim();
  let env = { ...process.env };
  delete env.JAYNSHARE_ACCOUNT; // never seen by claude's tools and MCP servers

  if (await isProxyUp(port)) {
    env = await withProxyEnv(env, { config, account, useMitm: !flags.includes('--no-mitm') });
  } else {
    refuseOrFallBack(port, flags.includes('--auto-fallback'));
  }
  env = withHoldTimeout(env, config.holdSeconds);

  const result = spawnSync('claude', claudeArgs, {
    stdio: 'inherit',
    shell: process.platform === 'win32',
    env,
  });

  if (result.error) {
    if (result.error.code === 'ENOENT') {
      console.error('Claude Code not found in PATH. Install it first.');
    } else {
      console.error(`Failed to start claude: ${result.error.message}`);
    }
    process.exit(1);
  }

  await autoUpdate({ config }).catch(() => {});

  process.exit(result.status ?? 1);
}

// jaynshare flags come before an optional `--`; everything after it goes to claude verbatim.
function splitRunArgs(rest) {
  const sep = rest.indexOf('--');
  if (sep >= 0) return { flags: rest.slice(0, sep), claudeArgs: rest.slice(sep + 1) };
  const ours = new Set(['--mitm', '--no-mitm', '--auto-fallback']); // --mitm is a no-op
  return { flags: rest, claudeArgs: rest.filter(a => !ours.has(a)) };
}

/** The child's environment, pointed at the proxy in forward-proxy or base-URL mode. */
async function withProxyEnv(env, { config, account, useMitm }) {
  const port = config.proxy.port;
  const pinnedBase = isLocalAccountPin(env.ANTHROPIC_BASE_URL, port); // legacy pin form

  if (!useMitm) {
    // No ANTHROPIC_API_KEY: Claude Code stays in subscription mode.
    if (account) {
      console.error(`[Jaynshare] Pinned to account "${account}" (JAYNSHARE_ACCOUNT)`);
      return { ...env, ANTHROPIC_BASE_URL: `http://localhost:${port}/jaynshare-account/${encodePinComponent(account)}` };
    }
    return pinnedBase ? env : { ...env, ANTHROPIC_BASE_URL: `http://localhost:${port}` };
  }

  const { caPath } = await ensureCerts(upstreamHost(config));
  // The pin travels as `Proxy-Authorization: Basic <acct>:<key>` on each CONNECT.
  const userinfo = account
    ? `${encodePinComponent(account)}:${encodePinComponent(config.proxy?.apiKey || '')}@`
    : '';
  const proxyUrl = `http://${userinfo}127.0.0.1:${port}`;

  if (account) console.error(`[Jaynshare] Pinned to account "${account}" (JAYNSHARE_ACCOUNT)`);
  else if (pinnedBase) {
    console.error('[Jaynshare] Account pin in ANTHROPIC_BASE_URL ignored: MITM mode does not use a base URL.');
    console.error('[Jaynshare] Use JAYNSHARE_ACCOUNT=<account> instead — it pins in both modes.');
  }

  const rest = { ...env };
  delete rest.ANTHROPIC_BASE_URL; // the two modes must not stack
  return {
    ...rest,
    HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, https_proxy: proxyUrl, http_proxy: proxyUrl,
    NO_PROXY: 'localhost,127.0.0.1,::1', no_proxy: 'localhost,127.0.0.1,::1',
    NODE_EXTRA_CA_CERTS: caPath,
  };
}

/** Exits unless the caller opted into launching claude without the proxy. */
function refuseOrFallBack(port, autoFallback) {
  if (autoFallback) {
    console.error(`[Jaynshare] Proxy not running on port ${port} — launching claude directly (--auto-fallback; start it with: jaynshare server)`);
    return;
  }
  console.error(`[Jaynshare] Proxy not running on port ${port}.`);
  console.error('Start it with: jaynshare server');
  console.error('Or pass --auto-fallback to launch claude directly (bypassing the proxy) when it is down.');
  process.exit(1);
}

// Claude Code must not time out while the proxy holds a request.
function withHoldTimeout(env, holdSeconds) {
  const holdMs = (holdSeconds || 0) * 1000;
  if (holdMs <= 0) return env;
  const needed = holdMs + 60_000; // one extra poll cycle
  const API_TIMEOUT_DEFAULT_MS = 600_000;
  const current = parseInt(env.API_TIMEOUT_MS || '0', 10) || API_TIMEOUT_DEFAULT_MS;
  return current < needed ? { ...env, API_TIMEOUT_MS: String(needed) } : env;
}

// ── status ──────────────────────────────────────────────────

async function statusCommand() {
  const config = await loadOrCreateConfig();
  const url = `http://localhost:${config.proxy.port}/jaynshare/status`;
  const json = args.includes('--json');
  const colorArg = argValue('--color') || args.find(arg => arg.startsWith('--color='))?.slice('--color='.length);
  const color = colorArg === 'always'
    || (colorArg !== 'never' && process.stdout.isTTY);

  try {
    const res = await fetch(url, { headers: { 'x-api-key': config.proxy.apiKey } });
    const data = await res.json();
    if (json) {
      console.log(JSON.stringify(data, null, 2));
      return;
    }
    console.log(renderStatus(data, { color }));
  } catch (err) {
    console.error('Cannot connect to proxy at localhost:' + config.proxy.port);
    console.error('Is the server running? Start with: jaynshare server');
    if (err?.message) console.error(`Details: ${err.message}`);
    process.exit(1);
  }
}

// ── attach ──────────────────────────────────────────────────

// The dashboard against an already running server, from polled status.
async function attachCommand() {
  const config = await loadOrCreateConfig();
  const port = config.proxy.port;
  const bound = process.env.JAYNSHARE_HOST || config.proxy.host || '127.0.0.1';
  const host = (bound === '0.0.0.0' || bound === '::') ? '127.0.0.1' : bound;

  if (!process.stdin.isTTY) {
    console.error('jaynshare attach needs a terminal. For a one-shot readout use: jaynshare status');
    process.exit(1);
  }

  const control = new RemoteControl({ port, host, apiKey: config.proxy.apiKey });
  let first;
  try {
    first = await control.status(); // fail here, not inside the TUI
  } catch (err) {
    console.error(`Cannot connect to proxy at ${host}:${port}`);
    console.error('Is the server running? Start with: jaynshare server');
    if (err?.message) console.error(`Details: ${err.message}`);
    process.exit(1);
  }

  await new Promise(resolve => {
    const session = createAttachSession({ control, config, onQuit: resolve });
    session.am.applyStatus(first);
    session.start();
  });
}

// ── switch ──────────────────────────────────────────────────

// A runtime preference held by the server; nothing is written to the config.
async function switchCommand() {
  const config = await loadOrCreateConfig();
  const port = config.proxy.port;
  const headers = { 'x-api-key': config.proxy.apiKey };
  const name = args[1] && !args[1].startsWith('-') ? args[1] : null;

  try {
    if (name) await requestSwitch({ port, headers, name });
    else await listServerAccounts({ port, headers });
  } catch (err) {
    console.error('Cannot connect to proxy at localhost:' + port);
    console.error('Is the server running? Start with: jaynshare server');
    if (err?.message) console.error(`Details: ${err.message}`);
    process.exit(1);
  }
}

async function listServerAccounts({ port, headers }) {
  const res = await fetch(`http://localhost:${port}/jaynshare/status`, { headers });
  const data = res.ok ? await res.json().catch(() => null) : null;
  if (!data || !Array.isArray(data.accounts)) {
    console.error(`Unexpected reply from localhost:${port} (HTTP ${res.status}) — no account list in it.`);
    console.error('Something is listening there, but it does not answer like this jaynshare version.');
    process.exit(1);
  }
  if (!data.accounts.length) {
    console.log('No accounts configured.');
    return;
  }
  for (const a of data.accounts) {
    const state = a.disabled ? 'disabled' : (a.status && a.status !== 'active' ? a.status : null);
    console.log(`${a.name === data.currentAccount ? '*' : ' '} ${a.name}${state ? `  (${state})` : ''}`);
  }
  console.log('\nSwitch with: jaynshare switch <name>');
}

async function requestSwitch({ port, headers, name }) {
  const res = await fetch(`http://localhost:${port}/jaynshare/switch`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ account: name }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // An older server forwards the request upstream, whose error is an object.
    const detail = typeof data.error === 'string' ? data.error : null;
    console.error(detail || `Switch failed: unexpected reply from localhost:${port} (HTTP ${res.status}).`);
    if (!detail) console.error('An older server without this endpoint answers this way; restart it to pick up the new version.');
    if (data.accounts?.length) {
      console.error('Known accounts:');
      for (const n of data.accounts) console.error(`  ${n}`);
    }
    process.exit(1);
  }
  console.log(`Switched to "${data.account}"`);
  if (data.eligible === false) {
    console.error(`Warning: "${data.account}" is ${data.reason || 'not currently eligible'}, so requests will not route to it until that changes.`);
  }
}

// ── accounts ────────────────────────────────────────────────

async function accountsCommand() {
  const config = await loadOrCreateConfig();
  const verbose = args.includes('-v') || args.includes('--verbose');

  if (config.accounts.length === 0) {
    console.log('No accounts configured.');
    console.log('Add one with: jaynshare import, jaynshare login, or jaynshare login --api');
    return;
  }

  if (await refreshExpiringTokens(config.accounts)) await saveConfig(config);

  const profiled = await withProfiles(config.accounts);
  const identityTouched = backfillIdentity(profiled);
  const unique = withoutDuplicateIdentities(profiled);
  const removed = profiled.length - unique.length;
  if (removed > 0) config.accounts = unique.map(entry => entry.account);
  const renamed = nameFromEmail(unique);
  if (identityTouched || removed > 0 || renamed) await saveConfig(config);
  if (removed > 0) console.log(`Removed ${removed} duplicate account(s)\n`);

  unique.forEach((entry, i) => printAccount(entry, { position: i + 1, verbose }));
}

/** Returns whether any token changed. A failed refresh is left for fetchProfile to report. */
async function refreshExpiringTokens(accounts) {
  let changed = false;
  await Promise.all(accounts.map(async (a) => {
    if (a.type !== 'oauth' || !a.refreshToken) return;
    if (!isTokenExpiringSoon(a.expiresAt)) return;
    try {
      const newTokens = await refreshAccessToken(a.refreshToken);
      a.accessToken = newTokens.accessToken;
      a.refreshToken = newTokens.refreshToken;
      a.expiresAt = newTokens.expiresAt;
      changed = true;
    } catch {
      // reported by fetchProfile
    }
  }));
  return changed;
}

/** Pairs each account with its live profile, so the two never drift out of step. */
async function withProfiles(accounts) {
  const profiles = await Promise.all(accounts.map(a =>
    a.type === 'oauth' && a.accessToken ? fetchProfile(a.accessToken) : null
  ));
  return accounts.map((account, i) => ({ account, profile: profiles[i] }));
}

/** Copies identity the profile knows onto the config entry; returns whether anything changed. */
function backfillIdentity(entries) {
  let touched = false;
  for (const { account, profile } of entries) {
    if (!profile || profile.error) continue;
    if (profile.accountUuid && account.accountUuid !== profile.accountUuid) { account.accountUuid = profile.accountUuid; touched = true; }
    if (profile.orgUuid && account.orgUuid !== profile.orgUuid) { account.orgUuid = profile.orgUuid; touched = true; }
    if (profile.orgName && account.orgName !== profile.orgName) { account.orgName = profile.orgName; touched = true; }
  }
  return touched;
}

/** Same person, different org is a distinct account. The most recently added entry survives. */
function withoutDuplicateIdentities(entries) {
  const seen = new Set();
  const kept = [];
  for (let i = entries.length - 1; i >= 0; i--) {
    const { account } = entries[i];
    const key = account.accountUuid ? `${account.accountUuid}::${orgKey(account) || ''}` : null;
    if (key && seen.has(key)) continue;
    if (key) seen.add(key);
    kept.unshift(entries[i]);
  }
  return kept;
}

/** "email", or "email (Org)" when the person spans several orgs; names are the user-facing key. */
function nameFromEmail(entries) {
  const orgCount = new Map();
  for (const { account } of entries) {
    if (account.accountUuid) orgCount.set(account.accountUuid, (orgCount.get(account.accountUuid) || 0) + 1);
  }
  let touched = false;
  for (const { account, profile } of entries) {
    const email = (profile && !profile.error && profile.email) ? profile.email : null;
    if (!email) continue;
    const newName = orgCount.get(account.accountUuid) > 1 ? `${email} (${orgLabel(account)})` : email;
    if (account.name !== newName) { account.name = newName; touched = true; }
  }
  return touched;
}

function printAccount({ account, profile }, { position, verbose }) {
  if (account.type === 'apikey') {
    console.log(`  [${position}] ${account.name} (apikey)  ${account.apiKey?.slice(0, 15)}...`);
    return;
  }

  const hasProfile = profile && !profile.error;
  const tier = hasProfile ? (profile.hasClaudeMax ? 'Max' : profile.hasClaudePro ? 'Pro' : 'subscription') : null;
  const status = hasProfile ? `Claude ${tier}` : `unknown (${profile?.error || 'no token'})`;
  const src = account.source ? `, ${account.source}` : '';
  console.log(`  [${position}] ${account.name} (${status}${src})`);
  if (hasProfile && profile.email && profile.email !== account.name) console.log(`       Email: ${profile.email}`);
  if (hasProfile && profile.orgName) console.log(`       Org:   ${profile.orgName}`);
  if (account.accountUuid) console.log(`       ID:    ${account.accountUuid}`);
  if (verbose && account.expiresAt) console.log(`       Token: ${formatExpiry(account.expiresAt)}`);
}

function formatExpiry(expiresAt) {
  const remaining = expiresAt - Date.now();
  if (remaining <= 0) return 'expired';
  const mins = Math.floor(remaining / 60000);
  const hrs = Math.floor(mins / 60);
  return `expires in ${hrs > 0 ? `${hrs}h ${mins % 60}m` : `${mins}m`}`;
}

// ── api ─────────────────────────────────────────────────────

async function apiCommand() {
  const config = await loadOrCreateConfig();
  const path = args[1];

  if (!path) {
    console.error('Usage: jaynshare api <path> [--account NAME] [--method POST] [--data JSON]');
    console.error('Example: jaynshare api /api/oauth/claude_cli/roles');
    process.exit(1);
  }

  const upstream = config.upstream || 'https://api.anthropic.com';
  const url = path.startsWith('http') ? path : `${upstream}${path}`;
  const res = await fetch(url, apiRequestInit(await apiAccount(config)));
  await printApiResponse(res);
}

/** The account named on the command line, else the first OAuth one. */
async function apiAccount(config) {
  const accounts = await resolveAccounts(config);
  const named = argValue('--account');
  if (named) {
    const account = resolveAccount(accounts, named, argValue('--org'));
    if (!account) { console.error(`Account "${named}" not found`); process.exit(1); }
    return account;
  }
  const account = accounts.find(a => a.type === 'oauth') || accounts[0];
  if (!account) { console.error('No accounts configured'); process.exit(1); }
  return account;
}

function apiRequestInit(account) {
  const credential = account.accessToken || account.apiKey;
  const headers = account.type === 'oauth'
    ? { 'Authorization': `Bearer ${credential}` }
    : { 'x-api-key': credential };
  const init = { method: (argValue('--method') || 'GET').toUpperCase(), headers };

  const data = argValue('--data');
  if (data) return { ...init, headers: { ...headers, 'Content-Type': 'application/json' }, body: data };
  return init;
}

/** Headers go to stderr so the body alone can be piped into a JSON tool. */
async function printApiResponse(res) {
  console.error(`${res.status} ${res.statusText}`);
  for (const [k, v] of res.headers.entries()) {
    console.error(`  ${k}: ${v}`);
  }
  console.error('');

  const body = await res.text();
  try {
    console.log(JSON.stringify(JSON.parse(body), null, 2));
  } catch {
    console.log(body);
  }
}

// ── alias ───────────────────────────────────────────────────

function aliasCommand() {
  const shell = argValue('--shell') || undefined;
  if (args.includes('--uninstall')) {
    alias.uninstallAlias({ shell });
  } else if (args.includes('--install')) {
    alias.installAlias({ shell });
  } else {
    alias.printAlias({ shell });
  }
}

// ── service ─────────────────────────────────────────────────

async function serviceCommand() {
  const sub = args[1] || 'status';
  const kind = serviceKind();
  if (!kind) {
    console.error(`jaynshare service: no service integration for ${process.platform}`);
    console.error('Run the proxy yourself with: jaynshare server --headless');
    process.exit(1);
  }
  const configPath = process.env.JAYNSHARE_CONFIG || null; // the unit does not inherit the shell's

  switch (sub) {
    case 'install': {
      const res = await installService({ configPath });
      if (!res.ok) { console.error(`jaynshare service install failed: ${res.error}`); process.exit(1); }
      break;
    }
    case 'uninstall': {
      const res = await uninstallService();
      if (!res.ok) { console.error(`jaynshare service uninstall failed: ${res.error}`); process.exit(1); }
      break;
    }
    case 'print':
      process.stdout.write(renderService({ configPath }));
      break;
    case 'status': {
      const s = await serviceStatus();
      console.log(`Service:   ${s.installed ? s.file : 'not installed'}`);
      console.log(`State:     ${s.running ? `running${s.pid ? ` (pid ${s.pid})` : ''}` : s.detail}`);
      if (kind === 'launchd') console.log(`Logs:      ${logPath()}`);
      else console.log('Logs:      journalctl --user --unit jaynshare.service');
      break;
    }
    default:
      console.error('Usage: jaynshare service <install|uninstall|status|print>');
      process.exit(1);
  }
}

// ── probe ───────────────────────────────────────────────────

async function probeCommand() {
  const config = await loadOrCreateConfig();
  const arg = args[1];

  if (arg === undefined) {
    const cur = config.quotaProbeSeconds || 0;
    console.log(cur > 0 ? `Quota probe: every ${cur}s` : 'Quota probe: off (passive only)');
    console.log('Set with: jaynshare probe <off|seconds>   e.g. jaynshare probe 300');
    return;
  }

  const seconds = readIntervalArg(arg, {
    usage: 'Usage: jaynshare probe <off|seconds>',
    minSeconds: 30,
    tooShort: 'Minimum probe interval is 30s (to avoid hammering the usage endpoint).',
  });
  config.quotaProbeSeconds = seconds;
  await saveConfig(config);
  console.log(seconds > 0
    ? `Quota probe set to every ${seconds}s (reads /api/oauth/usage; does not spend quota).`
    : 'Quota probe disabled (passive only).');
  await notifyRunningServer(config);
}

// ── warmup ──────────────────────────────────────────────────

async function warmupCommand() {
  const config = await loadOrCreateConfig();
  const arg = args[1];

  if (arg === undefined) {
    const cur = config.warmupSeconds || 0;
    console.log(cur > 0 ? `Keep-warm: every ${cur}s` : 'Keep-warm: off');
    console.log('Set with: jaynshare warmup <off|seconds>   e.g. jaynshare warmup 600');
    console.log('Note: warming spawns a minimal `claude` per idle account and DOES spend a little quota');
    console.log('(unlike the passive quota probe). It only warms accounts whose 5h window is idle.');
    return;
  }

  const seconds = readIntervalArg(arg, {
    usage: 'Usage: jaynshare warmup <off|seconds>',
    minSeconds: 60,
    tooShort: 'Minimum keep-warm interval is 60s.',
  });
  config.warmupSeconds = seconds;
  await saveConfig(config);
  console.log(seconds > 0
    ? `Keep-warm set to every ${seconds}s (spawns a minimal \`claude\` per idle account; spends a little quota).`
    : 'Keep-warm disabled.');
  await notifyRunningServer(config);
}

/** Seconds, or 0 for off. Exits on anything else. */
function readIntervalArg(arg, { usage, minSeconds, tooShort }) {
  if (arg === 'off' || arg === '0') return 0;
  const seconds = parseInt(arg, 10);
  if (Number.isNaN(seconds) || seconds < 0) {
    console.error(usage);
    process.exit(1);
  }
  if (seconds > 0 && seconds < minSeconds) {
    console.error(tooShort);
    process.exit(1);
  }
  return seconds;
}

// ── update ──────────────────────────────────────────────────

async function updateCommand() {
  const cur = currentVersion();
  console.log(`Current version: ${cur || 'unknown'}`);

  const kind = installKind();
  if (kind === 'git') {
    console.log('This is a git checkout — update it with `git pull`, not npm.');
    return;
  }

  const info = await checkForUpdate({ force: true });
  if (!info) {
    console.error('Could not reach the npm registry to check for updates.');
    process.exitCode = 1;
    return;
  }
  if (!info.updateAvailable) {
    console.log(`Already up to date (latest is ${info.latest}).`);
    return;
  }

  console.log(`Updating ${info.current} → ${info.latest} …`);
  const ok = runUpdate(info.latest);
  if (ok) {
    console.log(`Updated to ${info.latest}. Restart jaynshare to use the new version.`);
  } else {
    console.error(`Update failed. Try manually: npm install -g ${PKG_NAME}@latest`);
    process.exitCode = 1;
  }
}

// ── remove ──────────────────────────────────────────────────

/** Exits when the query is ambiguous across orgs. */
function resolveAccount(accounts, query, orgFilter) {
  const matches = matchAccounts(accounts, query, orgFilter);
  if (matches.length === 1) return matches[0];
  if (matches.length === 0) return null;
  console.error(`"${query}" matches ${matches.length} accounts — disambiguate with --org <name|uuid>:`);
  for (const a of matches) {
    console.error(`  - ${a.name}${a.orgName ? `  (org: ${a.orgName})` : ''}`);
  }
  process.exit(1);
}

async function removeCommand() {
  const config = await loadOrCreateConfig();
  const name = args[1];

  if (!name) {
    console.error('Usage: jaynshare remove <account-name|email> [--org <name|uuid>]');
    process.exit(1);
  }

  const account = resolveAccount(config.accounts, name, argValue('--org'));
  if (!account) {
    console.error(`Account "${name}" not found`);
    process.exit(1);
  }

  config.accounts.splice(config.accounts.indexOf(account), 1);
  await saveConfig(config);
  console.log(`Removed account "${account.name}"`);
}

// ── route ───────────────────────────────────────────────────

const ROUTE_USAGE = [
  'Usage: jaynshare route [list]',
  '       jaynshare route add <name> --match "<glob>[,<glob>]" [--accounts "<name-or-index>[,...]"] [--bucket <quota-bucket>] [--color <name>]',
  '       jaynshare route rm <name>',
  '',
  'A route pins model ids matching its globs to an exclusive set of accounts.',
  'Omit --accounts to route to all accounts (e.g. just to override --bucket).',
  '--color (red/green/yellow/blue/magenta/cyan) tints the route\'s inline marker in the TUI.',
  'First matching route wins. Changes apply to a running server immediately.',
].join('\n');

const ROUTE_COLORS = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan'];

function splitList(value) {
  return (value || '').split(',').map(s => s.trim()).filter(Boolean);
}

const ROUTE_SUBCOMMANDS = {
  list: listRoutes,
  add: addRoute,
  rm: removeRoute,
  remove: removeRoute,
  delete: removeRoute,
};

async function routeCommand() {
  const sub = ROUTE_SUBCOMMANDS[args[1] || 'list'];
  if (!sub) {
    console.error(ROUTE_USAGE);
    process.exit(1);
  }
  const config = await loadOrCreateConfig();
  config.routes = Array.isArray(config.routes) ? config.routes : [];
  await sub(config);
}

function listRoutes(config) {
  if (!config.routes.length) { console.log('No routes configured.'); return; }
  for (const r of config.routes) {
    const match = (Array.isArray(r.match) ? r.match : [r.match]).join(', ');
    const accts = (r.accounts && r.accounts.length) ? r.accounts.join(', ') : '(all accounts)';
    const bucket = r.bucket ? `  bucket=${r.bucket}` : '';
    const color = r.color ? `  color=${r.color}` : '';
    console.log(`${r.name || '(unnamed)'}: ${match} → ${accts}${bucket}${color}`);
  }
}

async function addRoute(config) {
  const route = readRouteFlags(config);
  const at = config.routes.findIndex(r => r.name === route.name);
  if (at >= 0) { config.routes[at] = route; console.log(`Updated route "${route.name}"`); }
  else { config.routes.push(route); console.log(`Added route "${route.name}"`); }
  await saveConfig(config);
  await notifyRunningServer(config);
}

/** Exits on a malformed route; warns (but accepts) an account that does not exist yet. */
function readRouteFlags(config) {
  const name = args[2] && !args[2].startsWith('--') ? args[2] : null;
  const match = splitList(argValue('--match'));
  const accounts = splitList(argValue('--accounts'));
  const bucket = argValue('--bucket');
  const color = argValue('--color');

  if (!name || !match.length) {
    console.error(ROUTE_USAGE);
    process.exit(1);
  }
  if (color && !ROUTE_COLORS.includes(color.toLowerCase())) {
    console.error(`Unknown color "${color}" — expected one of: ${ROUTE_COLORS.join(', ')}`);
    process.exit(1);
  }
  const known = new Set(config.accounts.map(a => a.name));
  for (const a of accounts) {
    if (!known.has(a) && !/^\d+$/.test(a)) console.error(`Warning: no account named "${a}" (yet)`);
  }

  const route = { name, match };
  if (accounts.length) route.accounts = accounts;
  if (bucket) route.bucket = bucket;
  if (color) route.color = color.toLowerCase();
  return route;
}

async function removeRoute(config) {
  const name = args[2];
  const before = config.routes.length;
  config.routes = config.routes.filter(r => r.name !== name);
  if (config.routes.length === before) { console.error(`Route "${name}" not found`); process.exit(1); }
  await saveConfig(config);
  await notifyRunningServer(config);
  console.log(`Removed route "${name}"`);
}

// ── priority ────────────────────────────────────────────────

async function priorityCommand() {
  const config = await loadOrCreateConfig();
  const name = args[1];

  if (!name) {
    console.error('Usage: jaynshare priority <account-name|email> <n> [--org <name|uuid>]');
    console.error('       jaynshare priority <account-name|email> --first | --last');
    console.error('Lower priority is preferred for rotation (default 0).');
    process.exit(1);
  }

  const account = resolveAccount(config.accounts, name, argValue('--org'));
  if (!account) {
    console.error(`Account "${name}" not found`);
    process.exit(1);
  }

  const priorities = config.accounts.map(a => a.priority || 0);
  let priority;
  if (args.includes('--first')) {
    priority = Math.min(0, ...priorities) - 1;
  } else if (args.includes('--last')) {
    priority = Math.max(0, ...priorities) + 1;
  } else {
    const numTok = args.slice(2).find(t => /^-?\d+$/.test(t));
    priority = numTok != null ? parseInt(numTok, 10) : NaN;
    if (Number.isNaN(priority)) {
      console.error('Provide an integer priority, or --first / --last.');
      process.exit(1);
    }
  }

  account.priority = priority;
  await saveConfig(config);
  console.log(`Set priority of "${account.name}" to ${priority} (lower = preferred)`);
  await notifyRunningServer(config);
}

// ── enable / disable ────────────────────────────────────────

const DISABLE = { verb: 'disable', done: 'Disabled', apply: (a) => { a.disabled = true; } };
const ENABLE = { verb: 'enable', done: 'Enabled', apply: (a) => { delete a.disabled; } };

async function setAccountRotation({ verb, done, apply }) {
  const config = await loadOrCreateConfig();
  const name = args[1];

  if (!name) {
    console.error(`Usage: jaynshare ${verb} <account-name|email> [--org <name|uuid>]`);
    process.exit(1);
  }

  const account = resolveAccount(config.accounts, name, argValue('--org'));
  if (!account) {
    console.error(`Account "${name}" not found`);
    process.exit(1);
  }

  apply(account);
  await saveConfig(config);
  console.log(`${done} account "${account.name}"`);
  await notifyRunningServer(config);
}

// ── proxy clients ──────────────────────────────────────────

const CLIENT_STATE_CHANGES = {
  disable: { done: 'Disabled', apply: (client) => { client.disabled = true; } },
  enable: { done: 'Enabled', apply: (client) => { client.disabled = false; } },
  revoke: { done: 'Revoked', apply: (client, config) => { config.proxy.clients = config.proxy.clients.filter(c => c.id !== client.id); } },
};

async function clientCommand() {
  const sub = args[1] || 'list';
  if (sub === 'list') return listClients();
  if (sub === 'env') return printClientEnv();
  if (sub === 'add') return addClient();
  if (sub === 'rotate') return rotateClientSecret();
  if (CLIENT_STATE_CHANGES[sub]) return changeClientState(sub);
  if (sub === 'migrate') return migrateLegacyKey();
  if (sub === 'admin' && args[2] === 'rotate') return rotateAdminCredential();
  clientUsage();
}

async function listClients() {
  const config = await loadOrCreateConfig();
  const clients = config.proxy?.clients || [];
  if (!clients.length) { console.log('No proxy clients configured.'); return; }
  for (const client of clients) {
    console.log(`${client.id}\t${client.disabled ? 'disabled' : 'enabled'}\t${client.name || client.id}`);
  }
}

// The client's own secret arrives on stdin, so it is never re-read from disk (only its hash is stored).
async function printClientEnv() {
  const id = args[2];
  const host = argValue('--host');
  const ca = argValue('--ca');
  const config = await loadOrCreateConfig();
  const port = Number(argValue('--port') || config.proxy?.port || 3456);
  if (!clientById(config, id) || !host || !/^[A-Za-z0-9.-]+$/.test(host) || !ca
      || !Number.isInteger(port) || port < 1 || port > 65535) {
    clientUsage('Usage: jaynshare client env <id> --host <tailscale-host> --ca <path> [--port 3456]');
  }
  const secret = readFileSync(0, 'utf8').trim();
  const principal = resolvePrincipal(config, secret);
  if (!principal || principal.clientId !== id) clientUsage('The secret on stdin does not match that client.');

  const quote = value => `'${String(value).replace(/'/g, `'"'"'`)}'`;
  const proxyUrl = `http://${id}:${secret}@${host}:${port}`;
  console.log(`export HTTPS_PROXY=${quote(proxyUrl)}`);
  console.log(`export HTTP_PROXY=${quote(proxyUrl)}`);
  console.log(`export https_proxy=${quote(proxyUrl)}`);
  console.log(`export http_proxy=${quote(proxyUrl)}`);
  console.log("export NO_PROXY='localhost,127.0.0.1,::1'");
  console.log("export no_proxy='localhost,127.0.0.1,::1'");
  console.log(`export NODE_EXTRA_CA_CERTS=${quote(ca)}`);
  console.log('unset ANTHROPIC_BASE_URL ANTHROPIC_API_KEY');
}

async function addClient() {
  const id = args[2];
  if (!validClientId(id)) clientUsage('Client ID must use lowercase letters, numbers, _ or -.');
  const name = argValue('--name') || id;
  const secret = generateClientSecret();
  const config = await atomicConfigUpdate(config => {
    config.proxy ||= { port: 3456 };
    config.proxy.clients ||= [];
    if (clientById(config, id)) throw new Error(`proxy client "${id}" already exists`);
    config.proxy.clients.push({ id, name, keyHash: hashClientSecret(secret), disabled: false });
  }).catch(clientCommandError);
  await notifyRunningServer(config);
  announceSecret(secret, `Added proxy client "${id}".`);
}

async function changeClientState(sub) {
  const { done, apply } = CLIENT_STATE_CHANGES[sub];
  const id = args[2];
  if (!id) clientUsage(`Usage: jaynshare client ${sub} <id>`);
  const config = await atomicConfigUpdate(config => {
    apply(requireClient(config, id), config);
  }).catch(clientCommandError);
  await notifyRunningServer(config);
  console.log(`${done} proxy client "${id}"`);
}

async function rotateClientSecret() {
  const id = args[2];
  if (!id) clientUsage('Usage: jaynshare client rotate <id>');
  const secret = generateClientSecret();
  const config = await atomicConfigUpdate(config => {
    requireClient(config, id).keyHash = hashClientSecret(secret);
  }).catch(clientCommandError);
  await notifyRunningServer(config);
  announceSecret(secret, `Rotated proxy client "${id}".`);
}

async function migrateLegacyKey() {
  let migrated = false;
  const config = await atomicConfigUpdate(config => {
    const legacy = config.proxy?.apiKey;
    if (!legacy) return;
    config.proxy.clients ||= [];
    if (clientById(config, 'legacy')) throw new Error('proxy client "legacy" already exists');
    config.proxy.clients.push({ id: 'legacy', name: 'Migrated legacy client', keyHash: hashClientSecret(legacy), disabled: false });
    delete config.proxy.apiKey;
    migrated = true;
  }).catch(clientCommandError);
  await notifyRunningServer(config);
  console.log(migrated ? 'Migrated proxy.apiKey to hashed client "legacy".' : 'No proxy.apiKey to migrate.');
}

async function rotateAdminCredential() {
  const secret = generateClientSecret().replace('jaynshare-client-', 'jaynshare-admin-');
  const config = await atomicConfigUpdate(config => {
    config.proxy ||= { port: 3456, clients: [] };
    config.proxy.adminKeyHash = hashClientSecret(secret);
  }).catch(clientCommandError);
  await notifyRunningServer(config);
  announceSecret(secret, 'Rotated the operator credential.');
}

function requireClient(config, id) {
  const client = clientById(config, id);
  if (!client) throw new Error(`proxy client "${id}" not found`);
  return client;
}

// stdout carries the secret alone, so a caller can capture it; the notice goes to stderr.
function announceSecret(secret, notice) {
  process.stdout.write(`${secret}\n`);
  process.stderr.write(`[Jaynshare] ${notice} This secret will not be shown again.\n`);
}

function clientCommandError(err) {
  console.error(`[Jaynshare] ${err.message}`);
  process.exit(1);
}

function clientUsage(message = null) {
  if (message) console.error(message);
  console.error('Usage: jaynshare client list | add <id> [--name NAME] | disable|enable|revoke|rotate <id> | env <id> --host HOST --ca PATH | migrate | admin rotate');
  process.exit(1);
}

// ── help ────────────────────────────────────────────────────

function showHelp() {
  console.log(`Jaynshare - Multi-account Claude proxy

Usage: jaynshare [command] [options]

Commands:
  server              Start the proxy server (default; --headless to skip the TUI)
  import              Import credentials from Claude Code
  login               OAuth login via browser
  login --api         Add an API key account
  env [--no-mitm]     Print export lines to point Claude Code at the proxy, for
                      'eval "$(jaynshare env)"' (MITM forward-proxy by default;
                      --no-mitm for base-URL only). Handy for agent multiplexers
                      that spawn claude themselves instead of via 'jaynshare run'
  run [--no-mitm] [--auto-fallback] [-- args...]
                      Run Claude Code through the proxy (errors if it's down,
                      unless --auto-fallback launches claude directly instead).
                      Routes via an HTTPS forward proxy + local CA by default, so
                      even hardcoded api.anthropic.com endpoints are intercepted;
                      --no-mitm uses base-URL routing only. Set JAYNSHARE_ACCOUNT to pin
                      the session to one account (see Environment below)
  alias               Print a shell alias so plain 'claude' routes via the proxy
                      (--install to write it to your shell rc; --uninstall to remove)
  service <sub>       Run the proxy as a user service that starts at login and
                      restarts on its own: install | uninstall | status | print
                      (LaunchAgent on macOS, systemd --user unit on Linux;
                      'print' writes the unit to stdout without touching anything)
  status [--json]     Show rich proxy/account/probe status (live)
                      Use --color=always|never to control ANSI colors
  attach              Open the live dashboard against a running server; s
                      switches account, R reloads config, q leaves it running
  accounts            List configured accounts
  client <subcommand> Manage distinct proxy clients: list, add, disable, enable,
                      revoke, rotate, migrate, or admin rotate
  switch [NAME]       Make the running server prefer one account (as 's' in the
                      TUI does); with no NAME, list accounts and mark the current
  remove <name>       Remove an account (by name or email; --org to disambiguate)
  disable <name>      Temporarily exclude an account from rotation
  enable <name>       Re-enable a disabled account (also clears a stuck error)
  priority <name> <n> Set rotation priority (lower = preferred; --first/--last)
  route [list|add|rm] Per-model routing: pin model globs to specific accounts
                      (add <name> --match "<glob>" [--accounts "<name>"] [--bucket <b>])
  probe [off|secs]    Opt-in background quota refresh for idle accounts
                      (off by default; reads usage endpoint, spends no quota)
  warmup [off|secs]   Opt-in: keep idle accounts' 5h timers running by sending
                      a minimal claude request to each (off by default; spends
                      a little quota, unlike probe)
  api <path>          Call an API endpoint with account credentials
  update              Check npm for a newer jaynshare and install it
  version             Print the installed version
  help                Show this help

Options:
  --name NAME         Set account name (import/login)
  --org NAME|UUID     Disambiguate when an email spans multiple orgs (remove/priority/api)
  --from PATH         Credentials path (import, default: ~/.claude/.credentials.json;
                      on macOS the default falls back to the Keychain)
  --json JSON         Import from inline JSON (import), e.g.:
                      --json '{"accessToken":"...","refreshToken":"...","expiresAt":1234}'
  --log-to DIR        Log full requests/responses to DIR (server, one file per request)
  --activity-log FILE Append TUI activity lines to FILE (server; works in headless mode too)
  --headless          Run the server without the interactive TUI (for backgrounding)
  --no-mitm           (run) skip the forward proxy; route via ANTHROPIC_BASE_URL only
  --auto-fallback     (run) if the proxy is down, launch claude directly instead
                      of erroring out (bypasses the proxy: no rotation)

Environment:
  JAYNSHARE_ACCOUNT             Pin a session to ONE account, bypassing rotation. Works in
                      both modes. Accepts accountUuid, orgUuid,
                      accountUuid/orgUuid, or a display name/email:
                        JAYNSHARE_ACCOUNT=me@example.com jaynshare run
                      Prefer a UUID for anything scripted: display names are
                      rewritten when an email gains a second org. Read by 'run'
                      and 'env', then removed from the environment so it never
                      reaches claude or the tools it spawns. An unknown account
                      is refused rather than silently rotated.
  JAYNSHARE_CONFIG   Path to the config file (default below)
  JAYNSHARE_DISABLE_AUTOUPDATE=1
                      Skip the background self-update check

The server always accepts both base-URL and proxy/CONNECT clients, so instances
launched with and without --no-mitm can share one server.

A running server re-syncs accounts from config on POST /jaynshare/reload
(local only). add/login/enable/disable/priority trigger it automatically.
POST /jaynshare/switch {"account": "<name>"} makes one account the preferred
one, which is what 'jaynshare switch' calls.

Upstream proxy. On a host with no direct route to the internet, set
"upstreamProxy": "http://user:pass@host:3128" (or just "host:3128") and every
outbound connection — request forwarding, OAuth login, token refresh, profile
and usage — is CONNECT-tunneled through it, TLS end to end. HTTPS_PROXY /
ALL_PROXY are honored when the config says nothing, NO_PROXY exempts hosts, and
"upstreamProxy": false ignores the environment entirely. Settable live in the
TUI settings screen. Distinct from "proxy" (the local port Claude Code talks to)
and from sx.org (a specific residential-egress provider with its own policy).

Egress pin (opt-in, off unless configured). Set "egress": { "pin": "auto" } to
hold requests whenever the exit IP is not the pinned one — a VPN that dropped
mid-session otherwise sends the request from an unexpected region, and upstream
answers 403, which Claude Code reports as a dead session and demands a re-login.
"auto" pins whatever address the server sees first; an explicit IP (or a list of
them) pins those. Held requests wait up to holdSeconds (default 120), then get a
503. See config.example.json.

A global npm install self-updates in the background (checked once/day, applied
on the next launch). Disable with JAYNSHARE_DISABLE_AUTOUPDATE=1 or
"autoUpdate": false in the config.

Config: ${getConfigPath()}
Crash log: ${getCrashLogPath()} (server; written when the process dies unexpectedly)
`);
}

// ── shared account upsert ────────────────────────────────────

async function upsertOAuthAccount(config, { name, creds, source = 'unknown' }) {
  const profile = await fetchProfile(creds.accessToken);
  if (!profile || profile.error) {
    console.error(`Warning: could not fetch account profile — ${profile?.error || 'no token'}`);
  }
  const account = oauthEntry({ name: name || derivedAccountName(config.accounts, profile), creds, source, profile });

  const at = findUpsertTarget(config.accounts, account);
  if (at >= 0) {
    const prev = config.accounts[at];
    config.accounts[at] = { ...prev, ...account, name: prev.name }; // keeps disk-only fields
    console.log(`Updated account "${prev.name}"`);
  } else {
    // A name the user chose stands as typed; only a derived one gains an org suffix.
    const named = name ? { accounts: config.accounts, incoming: account } : withOrgSuffixes(config.accounts, account);
    config.accounts = [...named.accounts, named.incoming];
    console.log(`Added account "${named.incoming.name}"`);
  }

  await saveConfig(config);
  console.log(`Saved to ${getConfigPath()}`);
  await notifyRunningServer(config);
}

function derivedAccountName(accounts, profile) {
  if (profile?.email) {
    const tier = profile.hasClaudeMax ? 'Max' : profile.hasClaudePro ? 'Pro' : null;
    if (tier) console.log(`Detected Claude ${tier} account: ${profile.email}`);
    return profile.email;
  }
  return `account-${accounts.filter(a => a.name.startsWith('account-')).length + 1}`;
}

function oauthEntry({ name, creds, source, profile }) {
  return {
    name,
    type: 'oauth',
    source,
    accountUuid: profile?.accountUuid || null,
    orgUuid: profile?.orgUuid || null,
    orgName: profile?.orgName || null,
    accessToken: creds.accessToken,
    refreshToken: creds.refreshToken,
    expiresAt: creds.expiresAt,
  };
}

// ── config sync helpers ─────────────────────────────────────

function findConfigAccount(diskConfig, account) {
  return diskConfig.accounts.findIndex(a => sameIdentity(a, account));
}

/** Returns the number of accounts added. */
async function syncAccountsFromDisk(diskConfig, memConfig, accountManager) {
  let added = 0;
  const claim = oneToOneClaim(accountManager);

  for (const diskAcct of diskConfig.accounts) {
    const mgrIdx = claim(diskAcct);

    if (mgrIdx < 0) {
      memConfig.accounts.push(diskAcct);
      accountManager.addAccount(diskAcct);
      added++;
      console.log(`[Jaynshare] Picked up new account "${diskAcct.name}" from config`);
      continue;
    }

    const mgr = accountManager.accounts[mgrIdx];
    applyDiskFields(mgr, diskAcct, accountManager);
    const freshCred = await readDiskCredential(diskAcct);
    if (freshCred) applyCredential(mgr, freshCred, accountManager);
  }
  return added;
}

/** Each disk entry claims one manager account, so same-person/different-org entries pair 1:1. */
function oneToOneClaim(accountManager) {
  const claimed = new Set();
  return (diskAcct) => {
    for (let i = 0; i < accountManager.accounts.length; i++) {
      if (!claimed.has(i) && sameIdentity(accountManager.accounts[i], diskAcct)) {
        claimed.add(i);
        return i;
      }
    }
    claimed.add(accountManager.accounts.length); // the entry about to be added
    return -1;
  };
}

function applyDiskFields(mgr, diskAcct, accountManager) {
  if (diskAcct.orgUuid && !mgr.orgUuid) mgr.orgUuid = diskAcct.orgUuid;
  if (diskAcct.orgName && !mgr.orgName) mgr.orgName = diskAcct.orgName;
  if (diskAcct.name && mgr.name !== diskAcct.name) mgr.name = diskAcct.name;
  if (diskAcct.priority != null && mgr.priority !== diskAcct.priority) mgr.priority = diskAcct.priority;
  const wantDisabled = !!diskAcct.disabled;
  if (mgr.disabled !== wantDisabled) accountManager.setDisabled(mgr.index, wantDisabled);
}

/** The credential the disk entry now carries, re-imported when it names a source file. */
async function readDiskCredential(diskAcct) {
  if (diskAcct.type === 'apikey') return diskAcct.apiKey ? { apiKey: diskAcct.apiKey } : null;
  if (diskAcct.type !== 'oauth') return null;
  if (diskAcct.importFrom) {
    try {
      const creds = await importCredentials(diskAcct.importFrom);
      return { accessToken: creds.accessToken, refreshToken: creds.refreshToken, expiresAt: creds.expiresAt };
    } catch (err) {
      console.error(`[Jaynshare] Re-import failed for "${diskAcct.name}": ${err.message}`);
      return null;
    }
  }
  if (!diskAcct.accessToken) return null;
  return { accessToken: diskAcct.accessToken, refreshToken: diskAcct.refreshToken, expiresAt: diskAcct.expiresAt };
}

function applyCredential(mgr, freshCred, accountManager) {
  if (freshCred.accessToken) {
    const changed = mgr.credential !== freshCred.accessToken
      || mgr.refreshToken !== freshCred.refreshToken;
    const diskIsStaler = freshCred.expiresAt && mgr.expiresAt
      && freshCred.expiresAt < mgr.expiresAt;
    if (changed && !diskIsStaler) {
      accountManager.updateAccountTokens(mgr.index, freshCred);
      console.log(`[Jaynshare] Refreshed credentials for "${mgr.name}"`);
    }
    return;
  }
  if (freshCred.apiKey && mgr.credential !== freshCred.apiKey) {
    mgr.credential = freshCred.apiKey;
    if (mgr.status === 'error') mgr.status = 'active';
    console.log(`[Jaynshare] Updated API key for "${mgr.name}"`);
  }
}

// ── helpers ─────────────────────────────────────────────────

// Whether `url` is a /jaynshare-account/ pin aimed at this proxy, under any local spelling.
function isLocalAccountPin(url, port) {
  if (!url) return false;
  let u;
  try { u = new URL(url); } catch { return false; }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  const urlPort = u.port || (u.protocol === 'https:' ? '443' : '80');
  return isLocal && urlPort === String(port) && u.pathname.startsWith('/jaynshare-account/');
}

function argValue(flag) {
  const i = args.indexOf(flag);
  return (i >= 0 && args[i + 1]) ? args[i + 1] : null;
}

function upstreamHost(config) {
  try { return new URL(config.upstream || 'https://api.anthropic.com').hostname; }
  catch { return 'api.anthropic.com'; }
}

/** Returns an idempotent stop() that restores the shell's title. */
function startTerminalTitleUpdater(accountManager) {
  const out = process.stdout;
  if (!out.isTTY || process.env.JAYNSHARE_NO_TITLE) return () => {};

  let last = null;
  const render = () => {
    const total = accountManager.accounts.length;
    const index = Math.min(accountManager.currentIndex || 0, Math.max(0, total - 1));
    const name = accountManager.accounts[index]?.name || null;
    const title = formatTerminalTitle({ index, total, name });
    if (title !== last) { last = title; out.write(titleSequence(title)); }
  };

  out.write(TITLE_STACK_PUSH);
  render();
  const timer = setInterval(render, 2000);
  timer.unref?.();

  let stopped = false;
  const stop = () => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    try { out.write(TITLE_STACK_POP); } catch { /* terminal gone */ }
  };
  process.on('exit', stop);
  return stop;
}

// Best effort; account removals still need a restart.
async function notifyRunningServer(config) {
  const port = config?.proxy?.port;
  if (!port) return;
  const host = config.proxy?.host || 'localhost';
  const urlHost = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  try {
    const res = await fetch(`http://${urlHost}:${port}/jaynshare/reload`, {
      method: 'POST',
      headers: { 'x-api-key': config.proxy?.apiKey || '' },
    });
    if (res.ok) {
      const data = await res.json().catch(() => ({}));
      // stderr: `client add` writes its one-time secret to stdout.
      console.error(`Reloaded running server${data.added ? ` (+${data.added} new account)` : ''}.`);
    }
  } catch { /* no server running */ }
}

function isProxyUp(port, timeout = 600) {
  return new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const done = up => { socket.destroy(); resolve(up); };
    socket.setTimeout(timeout);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => resolve(false));
  });
}

function handleServerListenError(err, port) {
  if (err.code === 'EADDRINUSE') {
    console.error(`[Jaynshare] Port ${port} is already in use.`);
    console.error('Another Jaynshare proxy may already be running.');
    console.error('Check the existing server with: jaynshare status');
    console.error(`Find the listener with: lsof -nP -iTCP:${port} -sTCP:LISTEN`);
  } else if (err.code === 'EACCES') {
    console.error(`[Jaynshare] Permission denied while listening on port ${port}.`);
    console.error('Choose a non-privileged port in the Jaynshare config.');
  } else {
    console.error(`[Jaynshare] Failed to listen on port ${port}: ${err.message}`);
  }
  process.exit(1);
}

// Runs last: a command body reaches every const in this module only once the
// module has finished evaluating.
const [handler, exitWhenDone] = resolveCommand(command);
await handler();
if (exitWhenDone) process.exit(0);
