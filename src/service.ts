// `jaynshare service`: a per-user LaunchAgent on macOS, a systemd --user unit on Linux.

import { writeFile, mkdir, rm } from 'node:fs/promises';
import { existsSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

export const LABEL = 'com.jaynlabs.jaynshare';
const UNIT_NAME = 'jaynshare.service';

export function serviceKind(platform: string = process.platform): 'launchd' | 'systemd' | null {
  if (platform === 'darwin') return 'launchd';
  if (platform === 'linux') return 'systemd';
  return null;
}

export function launchAgentPath(home: string = homedir()): string {
  return join(home, 'Library', 'LaunchAgents', `${LABEL}.plist`);
}

export function systemdUnitPath(home: string = homedir(), xdgConfig: string | undefined = process.env.XDG_CONFIG_HOME): string {
  return join(xdgConfig || join(home, '.config'), 'systemd', 'user', UNIT_NAME);
}

export function logPath(home: string = homedir(), platform: string = process.platform): string {
  return platform === 'darwin'
    ? join(home, 'Library', 'Logs', 'jaynshare.log')
    : join(home, '.local', 'state', 'jaynshare.log');
}

interface ResolveExecOptions {
  execPath?: string;
  argv1?: string;
  pathEnv?: string;
  realpath?: (p: string) => string;
  exists?: (p: string) => boolean;
}

// Prefers the `node` on PATH over process.execPath, and argv[1] unresolved: the
// versioned paths behind them (Homebrew Cellar, node_modules) die on upgrade.
export function resolveExec({
  execPath = process.execPath,
  argv1 = process.argv[1],
  pathEnv = process.env.PATH || '',
  realpath = realpathSync,
  exists = existsSync,
}: ResolveExecOptions = {}): { node: string; entry: string | undefined } {
  const same = (candidate: string): boolean => {
    try { return realpath(candidate) === realpath(execPath); } catch { return false; }
  };
  let node = execPath;
  for (const dir of pathEnv.split(':')) {
    if (!dir) continue;
    const candidate = join(dir, 'node');
    if (exists(candidate) && same(candidate)) { node = candidate; break; }
  }
  return { node, entry: argv1 };
}

// launchd starts with an empty environment; the self-update needs npm on PATH.
export function servicePath({ node, entry }: { node: string; entry?: string }): string {
  const dirs = [dirname(node), entry ? dirname(entry) : '', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'];
  return [...new Set(dirs.filter(Boolean))].join(':');
}

const xmlEscape = (s: unknown) => String(s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export interface ServiceExec {
  node: string;
  entry?: string;
  path: string;
  configPath?: string | null;
}

export function renderLaunchAgent({ node, entry, log, path, configPath = null }: { node: string; entry?: string; log: string; path: string; configPath?: string | null }): string {
  const args = [node, entry || '', 'server', '--headless'];
  const env = [`    <key>PATH</key>\n    <string>${xmlEscape(path)}</string>`];
  if (configPath) env.push(`    <key>JAYNSHARE_CONFIG</key>\n    <string>${xmlEscape(configPath)}</string>`);
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args.map(a => `    <string>${xmlEscape(a)}</string>`).join('\n')}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>${xmlEscape(log)}</string>
  <key>StandardErrorPath</key>
  <string>${xmlEscape(log)}</string>
  <key>EnvironmentVariables</key>
  <dict>
${env.join('\n')}
  </dict>
</dict>
</plist>
`;
}

export function renderSystemdUnit({ node, entry, path, configPath = null }: { node: string; entry?: string; path: string; configPath?: string | null }): string {
  const environment = [`Environment=PATH=${path}`, 'Environment=JAYNSHARE_DISABLE_AUTOUPDATE=1'];
  if (configPath) environment.push(`Environment=JAYNSHARE_CONFIG=${configPath}`);
  return `[Unit]
Description=Jaynshare multi-account Claude proxy
Documentation=file://${dirname(entry || '')}/../../README.md
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${node} ${entry} server --headless
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
${environment.join('\n')}

[Install]
WantedBy=default.target
`;
}

interface RunResult { code: number; stdout: string; stderr: string; }
type RunFn = (cmd: string, args: string[]) => RunResult;

function runCommand(cmd: string, args: string[]): RunResult {
  const result = spawnSync(cmd, args, { encoding: 'utf8' });
  return { code: result.status ?? 1, stdout: result.stdout || '', stderr: result.stderr || '' };
}

const guiDomain = (uid: number = process.getuid?.() ?? 0): string => `gui/${uid}`;

export interface ServiceOptions {
  kind?: ReturnType<typeof serviceKind>;
  home?: string;
  platform?: string;
  exec?: { node: string; entry?: string };
  run?: RunFn;
  configPath?: string | null;
  log?: (msg: string) => void;
  xdgConfig?: string;
}

type InstallResult = { ok: true; file: string; logFile?: string | null } | { ok: false; error: string; file?: string };

export async function installService({
  kind = serviceKind(), home = homedir(), platform = process.platform,
  exec = resolveExec(), run = runCommand, configPath = null, log = console.log,
  xdgConfig = process.env.XDG_CONFIG_HOME,
}: ServiceOptions = {}): Promise<InstallResult> {
  if (!kind) return { ok: false, error: `No service integration for ${platform}` };
  const where = { home, platform, xdgConfig };
  const unit: ServiceExec = { ...exec, path: servicePath(exec), configPath };
  return kind === 'launchd'
    ? installLaunchAgent(unit, where, { run, log })
    : installSystemdUnit(unit, where, { run, log });
}

interface Where { home: string; platform: string; xdgConfig: string | undefined; }

async function installLaunchAgent(unit: ServiceExec, { home, platform }: Where, { run, log }: { run: RunFn; log: (msg: string) => void }): Promise<InstallResult> {
  const logFile = logPath(home, platform);
  const plist = launchAgentPath(home);
  await mkdir(dirname(plist), { recursive: true });
  await mkdir(dirname(logFile), { recursive: true });
  await writeFile(plist, renderLaunchAgent({ ...unit, log: logFile }), { mode: 0o644 });
  run('launchctl', ['bootout', `${guiDomain()}/${LABEL}`]); // bootstrap fails if the label is already loaded
  const boot = run('launchctl', ['bootstrap', guiDomain(), plist]);
  if (boot.code !== 0) return { ok: false, error: boot.stderr.trim() || `launchctl bootstrap exited ${boot.code}`, file: plist };
  log(`[Jaynshare] Service installed: ${plist}`);
  log(`[Jaynshare] Logs: ${logFile}`);
  return { ok: true, file: plist, logFile };
}

async function installSystemdUnit(unit: ServiceExec, { home, xdgConfig }: Where, { run, log }: { run: RunFn; log: (msg: string) => void }): Promise<InstallResult> {
  const file = systemdUnitPath(home, xdgConfig);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, renderSystemdUnit(unit), { mode: 0o644 });
  run('systemctl', ['--user', 'daemon-reload']);
  const enable = run('systemctl', ['--user', 'enable', '--now', UNIT_NAME]);
  if (enable.code !== 0) return { ok: false, error: enable.stderr.trim() || `systemctl exited ${enable.code}`, file };
  log(`[Jaynshare] Service installed: ${file}`);
  log('[Jaynshare] Logs: journalctl --user --unit jaynshare.service --follow');
  log('[Jaynshare] To keep it running with no session open: loginctl enable-linger $USER');
  return { ok: true, file, logFile: null };
}

export async function uninstallService({
  kind = serviceKind(), home = homedir(), run = runCommand, log = console.log,
  xdgConfig = process.env.XDG_CONFIG_HOME,
}: ServiceOptions = {}): Promise<InstallResult> {
  if (!kind) return { ok: false, error: 'No service integration for this platform' };
  if (kind === 'launchd') {
    const plist = launchAgentPath(home);
    run('launchctl', ['bootout', `${guiDomain()}/${LABEL}`]);
    await rm(plist, { force: true });
    log(`[Jaynshare] Service removed: ${plist}`);
    return { ok: true, file: plist };
  }
  const unit = systemdUnitPath(home, xdgConfig);
  run('systemctl', ['--user', 'disable', '--now', UNIT_NAME]);
  await rm(unit, { force: true });
  run('systemctl', ['--user', 'daemon-reload']);
  log(`[Jaynshare] Service removed: ${unit}`);
  return { ok: true, file: unit };
}

export interface ServiceStatusResult {
  installed: boolean;
  running: boolean;
  detail: string;
  pid?: string | null;
  file?: string;
}

export async function serviceStatus({
  kind = serviceKind(), home = homedir(), run = runCommand,
  xdgConfig = process.env.XDG_CONFIG_HOME,
}: ServiceOptions = {}): Promise<ServiceStatusResult> {
  if (!kind) return { installed: false, running: false, detail: 'unsupported platform' };
  if (kind === 'launchd') {
    const plist = launchAgentPath(home);
    const result = run('launchctl', ['print', `${guiDomain()}/${LABEL}`]);
    const pid = /\bpid = (\d+)/.exec(result.stdout)?.[1] || null;
    return { installed: existsSync(plist), running: result.code === 0 && !!pid, pid, file: plist, detail: result.code === 0 ? 'loaded' : 'not loaded' };
  }
  const unit = systemdUnitPath(home, xdgConfig);
  const result = run('systemctl', ['--user', 'is-active', UNIT_NAME]);
  return { installed: existsSync(unit), running: result.stdout.trim() === 'active', file: unit, detail: result.stdout.trim() || result.stderr.trim() };
}

export function renderService({ kind = serviceKind(), home = homedir(), platform = process.platform, exec = resolveExec(), configPath = null }: ServiceOptions = {}): string | null {
  if (!kind) return null;
  const path = servicePath(exec);
  return kind === 'launchd'
    ? renderLaunchAgent({ ...exec, log: logPath(home, platform), path, configPath })
    : renderSystemdUnit({ ...exec, path, configPath });
}
