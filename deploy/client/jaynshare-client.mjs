#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { closeSync, openSync, realpathSync, writeSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ReadStream } from 'node:tty';

const ESC = '\x1b[';
const YELLOW = `${ESC}38;2;247;198;0m`;
const RESET = `${ESC}0m`;
const DIM = `${ESC}2m`;
const PREFERENCE_PREFIX = 'JAYNSHARE-PREF-v1-';

// JAYNSHARE_PLATFORM lets the tests drive the Windows paths from any machine.
export function clientPlatform(env = process.env) {
  return env.JAYNSHARE_PLATFORM || process.platform;
}

function clientDir() {
  // Native Windows Node cannot open the MSYS spellings Git Bash exports in XDG_CONFIG_HOME.
  if (clientPlatform() === 'win32') return join(homedir(), '.config', 'jaynshare');
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'jaynshare');
}

export function parseClientEnv(text) {
  const result = {};
  for (const line of String(text).split(/\r?\n/)) {
    const match = line.match(/^([A-Z][A-Z0-9_]*)='([^']*)'$/);
    if (match) result[match[1]] = match[2];
  }
  return result;
}

export async function loadClientConfig(dir = clientDir()) {
  let envText;
  let secret;
  try {
    [envText, secret] = await Promise.all([
      readFile(join(dir, 'client.env'), 'utf8'),
      readFile(join(dir, 'client.secret'), 'utf8'),
    ]);
  } catch (err) {
    throw new Error(`client is not enrolled (${err.path || dir} is missing)`);
  }
  const env = parseClientEnv(envText);
  const config = {
    id: env.JAYNSHARE_CLIENT_ID,
    host: env.JAYNSHARE_HOST,
    port: Number(env.JAYNSHARE_PORT),
    secret: secret.split(/\r?\n/, 1)[0],
  };
  if (!config.id || !config.host || !Number.isInteger(config.port) || !config.secret) {
    throw new Error('client enrollment is incomplete; rerun the Jaynshare installer');
  }
  return config;
}

async function fetchJson(config, path, { timeoutMs = 2500, fetchImpl = fetch } = {}) {
  let response;
  try {
    response = await fetchImpl(`http://${config.host}:${config.port}${path}`, {
      headers: { 'x-api-key': config.secret },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    if (err?.name === 'TimeoutError' || err?.name === 'AbortError') {
      throw new Error(`server did not reply within ${timeoutMs}ms`);
    }
    throw new Error(`server is unreachable: ${err.message}`);
  }
  const text = await response.text();
  let payload;
  try { payload = JSON.parse(text); } catch { payload = null; }
  if (!response.ok) {
    const message = response.status === 401
      ? 'client credential was rejected; rotate or reinstall it'
      : response.status === 403
        ? 'server needs the Jaynshare client-dashboard update'
        : payload?.error || `server returned HTTP ${response.status}`;
    const err = new Error(message);
    err.status = response.status;
    throw err;
  }
  return payload;
}

export async function fetchUsage(config, { sessionId = null, ...options } = {}) {
  const query = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : '';
  let payload;
  try { payload = await fetchJson(config, `/jaynshare/usage${query}`, options); }
  catch (err) {
    // An older server treats the query-bearing URL as an operator endpoint.
    if (!sessionId || (err.status !== 403 && err.status !== 404)) throw err;
    payload = await fetchJson(config, '/jaynshare/usage', options);
  }
  if (!Array.isArray(payload?.accounts)) throw new Error('server returned an invalid usage snapshot');
  return payload;
}

export async function resolveAccountSelection(config, selector, { usage = null, ...options } = {}) {
  const snapshot = usage || await fetchUsage(config, options);
  if (!snapshot.capabilities?.sessionAccountPreference) {
    throw new Error('server upgrade required for per-session account selection');
  }
  let payload;
  try {
    payload = await fetchJson(config,
      `/jaynshare/account-selection?account=${encodeURIComponent(selector)}`, options);
  } catch (err) {
    if (err.status === 404) throw new Error(`unknown account "${selector}"; run "jaynshare status" to list accounts`);
    throw err;
  }
  if (typeof payload?.account !== 'string' || !payload.account) {
    throw new Error('server returned an invalid account selection');
  }
  return payload;
}

export function encodeAccountPreference(identity) {
  if (typeof identity !== 'string' || !identity.trim() || /[\0\r\n]/.test(identity)) {
    throw new Error('account preference must be a safe non-empty string');
  }
  const bytes = Buffer.from(identity, 'utf8');
  if (bytes.length > 1024) throw new Error('account preference is too long');
  return PREFERENCE_PREFIX + bytes.toString('base64url');
}

const color = (enabled, code, value) => enabled ? `${ESC}${code}m${value}${RESET}` : String(value);
const yellow = (enabled, value) => enabled ? `${YELLOW}${value}${RESET}` : String(value);

// The Windows console decodes raw byte writes with its OEM codepage; each ASCII stand-in keeps its width.
const GLYPHS = {
  unicode: { marker: '›', keys: '↑/↓', separator: '·', ellipsis: '…' },
  ascii: { marker: '>', keys: 'Up/Dn', separator: '-', ellipsis: '~' },
};

export const glyphs = ascii => ascii ? GLYPHS.ascii : GLYPHS.unicode;

function pct(value) {
  if (value == null || !Number.isFinite(Number(value))) return '  ?';
  return `${Math.round(Number(value) * 100)}`.padStart(3);
}

function shortName(value, width = 20, ellipsis = GLYPHS.unicode.ellipsis) {
  const raw = String(value || '?').replace(/\p{C}/gu, ' ').replace(/\s+/g, ' ').trim() || '?';
  const local = raw.includes('@') ? raw.slice(0, raw.indexOf('@')) : raw;
  return local.length <= width ? local : `${local.slice(0, width - 1)}${ellipsis}`;
}

function duration(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return 'now';
  const mins = Math.ceil(ms / 60_000);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h${mins % 60 ? `${mins % 60}m` : ''}`;
  const days = Math.floor(hours / 24);
  return `${days}d${hours % 24 ? `${hours % 24}h` : ''}`;
}

function compactNumber(value) {
  const number = Number(value) || 0;
  if (number >= 1_000_000) return `${(number / 1_000_000).toFixed(number >= 10_000_000 ? 0 : 1)}m`;
  if (number >= 1_000) return `${(number / 1_000).toFixed(number >= 100_000 ? 0 : 1)}k`;
  return String(number);
}

function resetIn(value, now) {
  const at = Date.parse(value);
  return Number.isFinite(at) ? duration(at - now) : '-';
}

function bar(value, enabled, width = 12) {
  if (value == null || !Number.isFinite(Number(value))) return color(enabled, 90, '?'.repeat(width));
  const used = Math.max(0, Math.min(1, Number(value)));
  const filled = Math.round(used * width);
  const code = used >= 0.98 ? 31 : used >= 0.8 ? 33 : 32;
  return color(enabled, code, '█'.repeat(filled)) + color(enabled, 90, '░'.repeat(width - filled));
}

export function accountChoiceState(account, threshold = 0.98) {
  if (account.disabled) return { selectable: false, reason: 'disabled' };
  if (account.status === 'error') return { selectable: false, reason: 'error' };
  if (account.status === 'exhausted') return { selectable: false, reason: 'exhausted' };
  if (account.status === 'throttled') return { selectable: false, reason: 'rate-limited' };
  const q = account.quota || {};
  if ([q.unified5h, q.unified7d].some(value => Number.isFinite(Number(value)) && Number(value) >= threshold)) {
    return { selectable: false, reason: 'over quota' };
  }
  return { selectable: true };
}

export function pickerAction(key, index, status) {
  const count = (status.accounts || []).length + 1;
  if (key === '\x1b[A' || key === 'k') return { type: 'move', index: (index - 1 + count) % count };
  if (key === '\x1b[B' || key === 'j') return { type: 'move', index: (index + 1) % count };
  if (key === '\x1b' || key === 'q' || key === '\x03') return { type: 'cancel', index };
  if (key === '\r' || key === '\n') {
    if (index === 0) return { type: 'select', index, account: null };
    const account = status.accounts[index - 1];
    if (accountChoiceState(account, status.switchThreshold ?? 0.98).selectable) {
      return { type: 'select', index, account: account.name };
    }
  }
  return { type: 'none', index };
}

function pickerRows(status, now, g) {
  const rows = [{ name: 'Automatic', description: 'server decides', selectable: true }];
  for (const account of status.accounts || []) {
    const choice = accountChoiceState(account, status.switchThreshold ?? 0.98);
    const q = account.quota || {};
    const dot = `  ${g.separator}  `;
    const quotas = `${pct(q.unified5h).trim()}% 5h${dot}${pct(q.unified7d).trim()}% 7d`;
    const resets = [q.unified5hReset, q.unified7dReset]
      .map(value => resetIn(value, now)).filter(value => value !== '-');
    rows.push({
      name: shortName(account.name, 28, g.ellipsis),
      description: `${quotas}${resets.length ? `${dot}resets ${resets.join('/')}` : ''}${choice.reason ? `${dot}${choice.reason}` : ''}`,
      selectable: choice.selectable,
    });
  }
  return rows;
}

export function renderAccountPicker(status, index, { now = Date.now(), ansi = true, ascii = false } = {}) {
  const g = glyphs(ascii);
  const rows = pickerRows(status, now, g);
  const lines = ['Choose an account for this Claude session', ''];
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const marker = i === index ? g.marker : ' ';
    const text = `  ${marker} ${row.name.padEnd(30)} ${row.description}`;
    lines.push(ansi && !row.selectable ? `${DIM}${text}${RESET}` : text);
  }
  lines.push('', `${g.keys} move  ${g.separator}  Enter choose  ${g.separator}  Esc cancel`);
  return lines.join('\n');
}

export function renderLinePicker(status, { now = Date.now(), ascii = false } = {}) {
  const rows = pickerRows(status, now, glyphs(ascii));
  const lines = ['Choose an account for this Claude session', ''];
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    lines.push(`  ${String(i + 1).padStart(2)}) ${row.name.padEnd(30)} ${row.description}`
      + (row.selectable ? '' : '  [unavailable]'));
  }
  lines.push('', 'Type a number and press Enter, or type q to cancel.');
  return lines.join('\n');
}

export function linePickerAction(line, status, { ascii = false } = {}) {
  const value = String(line).replace(/\p{C}/gu, '').trim();
  const count = (status.accounts || []).length + 1;
  if (!value) return { type: 'none' };
  if (/^(q|quit|cancel)$/i.test(value)) return { type: 'cancel' };
  if (!/^[0-9]+$/.test(value)) {
    return { type: 'retry', message: `Enter a number between 1 and ${count}, or q to cancel.` };
  }
  const index = Number(value) - 1;
  if (index < 0 || index >= count) {
    return { type: 'retry', message: `Enter a number between 1 and ${count}, or q to cancel.` };
  }
  if (index === 0) return { type: 'select', account: null };
  const account = status.accounts[index - 1];
  if (!accountChoiceState(account, status.switchThreshold ?? 0.98).selectable) {
    return { type: 'retry', message: `${shortName(account.name, 28, glyphs(ascii).ellipsis)} cannot be selected right now.` };
  }
  return { type: 'select', account: account.name };
}

function openTtyTerminal() {
  const readFd = openSync('/dev/tty', 'r');
  let writeFd;
  try { writeFd = openSync('/dev/tty', 'w'); }
  catch (err) { closeSync(readFd); throw err; }
  return {
    input: new ReadStream(readFd),
    output: { write(value) { writeSync(writeFd, value); } }, // reaches the terminal before a signal exit closes it
    ascii: false,
    ownsInput: true,
    close() {
      try { closeSync(readFd); } catch { /* already closed */ }
      try { closeSync(writeFd); } catch { /* already closed */ }
    },
  };
}

function openInheritedTerminal({ input = process.stdin, errorFd = 2 } = {}) {
  return {
    input,
    output: { write(value) { writeSync(errorFd, value); } }, // stdout carries the chosen account
    ascii: true,
    ownsInput: false,
    close() { /* stdin and stderr belong to the caller */ },
  };
}

export function openPickerTerminal({ platform = clientPlatform() } = {}) {
  // Native Windows Node cannot open /dev/tty.
  return platform === 'win32' ? openInheritedTerminal() : openTtyTerminal();
}

// Asks the descriptor, not the platform: a Git for Windows build may hand Node a pipe or a console.
export function pickerMode(input, { override = process.env.JAYNSHARE_PICKER } = {}) {
  if (override === 'raw' || override === 'line') return override;
  return typeof input?.setRawMode === 'function' ? 'raw' : 'line';
}

export class PickerCancelled extends Error {
  constructor(message = 'account selection cancelled') {
    super(message);
    this.name = 'PickerCancelled';
  }
}

function pickerSession(tty, restore) {
  let cleaned = false;
  let rejectSelection;
  const onSignal = () => rejectSelection?.(new PickerCancelled());
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  return {
    arm(reject) { rejectSelection = reject; },
    cleanup() {
      if (cleaned) return;
      cleaned = true;
      process.removeListener('SIGINT', onSignal);
      process.removeListener('SIGTERM', onSignal);
      try { restore(); } catch { /* terminal disappeared */ }
      try { tty.input.pause?.(); } catch { /* terminal disappeared */ }
      if (tty.ownsInput) {
        try { tty.input.destroy?.(); } catch { /* already closed */ }
        tty.close?.();
      }
    },
  };
}

async function runRawPicker(status, tty, now) {
  const { input, output } = tty;
  let index = 0;
  let previousRaw = !!input.isRaw;
  const draw = () => output.write(`${ESC}H${ESC}2J${renderAccountPicker(status, index, { now, ascii: !!tty.ascii })}`);
  const session = pickerSession(tty, () => {
    input.setRawMode?.(previousRaw);
    output.write(`${ESC}?25h${ESC}?1049l`);
  });
  try {
    input.setRawMode?.(true);
    input.resume?.();
    output.write(`${ESC}?1049h${ESC}?25l`);
    draw();
    return await new Promise((resolve, reject) => {
      const detach = () => {
        input.removeListener('data', onData);
        input.removeListener('error', onError);
      };
      const finish = (callback, value) => { detach(); callback(value); };
      session.arm(err => finish(reject, err));
      const onError = err => finish(reject, err);
      const onData = chunk => {
        const action = pickerAction(Buffer.from(chunk).toString('utf8'), index, status);
        index = action.index;
        if (action.type === 'select') finish(resolve, action.account);
        else if (action.type === 'cancel') finish(reject, new PickerCancelled());
        else if (action.type === 'move') draw();
      };
      input.on('data', onData);
      input.once('error', onError);
    });
  } finally {
    session.cleanup();
  }
}

async function runLinePicker(status, tty, now) {
  const { input, output } = tty;
  const session = pickerSession(tty, () => output.write(`${ESC}?25h`));
  let buffer = '';
  try {
    input.resume?.();
    input.setEncoding?.('utf8');
    output.write(`${renderLinePicker(status, { now, ascii: !!tty.ascii })}\n> `);
    return await new Promise((resolve, reject) => {
      const detach = () => {
        input.removeListener('data', onData);
        input.removeListener('error', onError);
        input.removeListener('end', onEnd);
      };
      const finish = (callback, value) => { detach(); callback(value); };
      session.arm(err => finish(reject, err));
      const onError = err => finish(reject, err);
      const onEnd = () => finish(reject,
        new PickerCancelled('account selection needs an explicit choice; use --account ACCOUNT or --auto'));
      const onData = chunk => {
        buffer += Buffer.from(chunk).toString('utf8');
        let newline;
        while ((newline = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, newline);
          buffer = buffer.slice(newline + 1);
          const action = linePickerAction(line, status, { ascii: !!tty.ascii });
          if (action.type === 'select') return finish(resolve, action.account);
          if (action.type === 'cancel') return finish(reject, new PickerCancelled());
          output.write(action.type === 'retry' ? `${action.message}\n> ` : '> ');
        }
      };
      input.on('data', onData);
      input.once('error', onError);
      input.once('end', onEnd);
    });
  } finally {
    session.cleanup();
  }
}

export async function pickAccount(status, {
  terminal = null, now = Date.now(), platform = clientPlatform(), mode = null,
} = {}) {
  const tty = terminal || openPickerTerminal({ platform });
  const resolved = mode || pickerMode(tty.input);
  return resolved === 'line' ? runLinePicker(status, tty, now) : runRawPicker(status, tty, now);
}

export function renderStatus(status, { ansi = process.stdout.isTTY, now = Date.now() } = {}) {
  const accounts = status.accounts || [];
  const lines = [];
  const sessions = status.sessions || {};
  const server = status.server || {};
  const probe = status.probe || {};

  lines.push(yellow(ansi, '◆ JAYNSHARE') + color(ansi, 2, '  pooled account status'));
  lines.push(
    `${accounts.length} account${accounts.length === 1 ? '' : 's'} · `
    + `${sessions.active || 0} active / ${sessions.known || 0} known sessions · `
    + (server.uptimeSeconds == null ? 'server online' : `server up ${duration(server.uptimeSeconds * 1000)}`),
  );
  lines.push(probe.enabled
    ? `quota probe every ${duration((probe.intervalSeconds || 0) * 1000)}${probe.running ? ' (refreshing)' : ''}`
    : 'quota probe off; idle-account values may be unknown');
  lines.push('');
  lines.push(`${'ACCOUNT'.padEnd(22)} ${'STATE'.padEnd(11)} ${'SESS'.padStart(4)}  ${'5 HOUR'.padEnd(19)} RESET  ${'7 DAY'.padEnd(19)} RESET`);
  lines.push(color(ansi, 2, '─'.repeat(93)));

  for (const account of accounts) {
    const q = account.quota || {};
    const current = account.name === status.currentAccount;
    const marker = current ? yellow(ansi, '◆') : ' ';
    const state = account.disabled ? 'disabled' : account.status || 'unknown';
    const stateCode = state === 'active' ? 32 : state === 'throttled' ? 33 : state === 'unknown' ? 90 : 31;
    const identity = `${marker} ${shortName(account.name, 20)}`.padEnd(22 + (ansi && current ? YELLOW.length + RESET.length : 0));
    lines.push(
      `${identity} ${color(ansi, stateCode, state.padEnd(11))} ${String(account.sessions || 0).padStart(4)}  `
      + `${bar(q.unified5h, ansi)} ${pct(q.unified5h)}% ${resetIn(q.unified5hReset, now).padStart(6)}  `
      + `${bar(q.unified7d, ansi)} ${pct(q.unified7d)}% ${resetIn(q.unified7dReset, now).padStart(6)}`,
    );
    const scoped = [];
    if (q.unified7dSonnet != null) scoped.push(`Sonnet ${pct(q.unified7dSonnet).trim()}% (${resetIn(q.unified7dSonnetReset, now)})`);
    if (q.unified7dFable != null) scoped.push(`Fable ${pct(q.unified7dFable).trim()}% (${resetIn(q.unified7dFableReset, now)})`);
    if (scoped.length) lines.push(color(ansi, 2, `${''.padEnd(41)}${scoped.join(' · ')}`));
    const usage = account.usage || {};
    const tokens = (usage.totalInputTokens || 0) + (usage.totalOutputTokens || 0);
    lines.push(color(ansi, 2,
      `${''.padEnd(24)}${usage.totalRequests || 0} routed requests · ${compactNumber(tokens)} observed tokens`));
  }
  if (accounts.length) lines.push('', color(ansi, 2, '◆ marks the server global default, not this viewer\'s session'));
  return lines.join('\n');
}

export function renderStatusLine(status, { ansi = true, sessionState = null } = {}) {
  const accountCell = account => {
    const q = account.quota || {};
    return `${shortName(account.name, 10)} ${pct(q.unified5h).trim()}%/${pct(q.unified7d).trim()}%`;
  };
  const accounts = status.accounts || [];
  const assignedName = status.session?.account || null;
  const assigned = assignedName && accounts.find(account => account.name === assignedName);
  const cells = accounts.filter(account => account !== assigned).map(accountCell);
  let assignment = '';
  if (assignedName) assignment = ` → ${assigned ? accountCell(assigned) : shortName(assignedName, 10)}`;
  else if (sessionState === 'unknown' || status.session?.account === null) assignment = ' → unknown';
  else if (Object.hasOwn(status, 'session')) assignment = ' → pending';
  const sessions = status.sessions?.active || 0;
  return `${yellow(ansi, '◆ JAYNSHARE')}${assignment}${cells.length ? `  ·  ${cells.join('  ')}` : ''}  ·  ${sessions} active`;
}

export function titleHook(input) {
  let payload;
  try { payload = JSON.parse(input); } catch { return null; }
  const prompt = String(payload?.prompt || '').replace(/\p{C}/gu, ' ').replace(/\s+/g, ' ').trim();
  if (!prompt || /^[\/#]/.test(prompt) || prompt.startsWith('!')) return null;
  const preview = prompt.length > 58 ? `${prompt.slice(0, 57)}…` : prompt;
  return {
    hookSpecificOutput: {
      hookEventName: 'UserPromptSubmit',
      sessionTitle: `◆ Jaynshare · ${preview}`,
    },
  };
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

export function parseStatusLineInput(input) {
  if (typeof input !== 'string' || input.length > 64 * 1024) return { sessionId: null };
  let payload;
  try { payload = JSON.parse(input); } catch { return { sessionId: null }; }
  const sessionId = payload?.session_id;
  if (typeof sessionId !== 'string' || !sessionId || sessionId.length > 256
      || !/^[A-Za-z0-9._:-]+$/.test(sessionId)) return { sessionId: null };
  return { sessionId };
}

async function readOptionalStdin(input = process.stdin, timeoutMs = 150) {
  if (input.isTTY) return '';
  return new Promise(resolve => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      input.removeListener('data', onData);
      input.removeListener('end', finish);
      input.removeListener('error', finish);
      input.pause?.();
      resolve(Buffer.concat(chunks).toString('utf8'));
    };
    const onData = chunk => {
      const value = Buffer.from(chunk);
      size += value.length;
      if (size <= 64 * 1024) chunks.push(value);
      else finish();
    };
    const timer = setTimeout(finish, timeoutMs);
    timer.unref?.();
    input.on('data', onData);
    input.once('end', finish);
    input.once('error', finish);
    input.resume?.();
  });
}

async function showDashboard(config) {
  if (!process.stdout.isTTY) {
    process.stdout.write(renderStatus(await fetchUsage(config), { ansi: false }) + '\n');
    return;
  }
  let stopped = false;
  const restore = () => {
    if (stopped) return;
    stopped = true;
    process.stdout.write(`${ESC}?25h${ESC}?1049l`);
  };
  process.once('SIGINT', () => { restore(); process.exit(0); });
  process.once('SIGTERM', () => { restore(); process.exit(0); });
  process.stdout.write(`${ESC}?1049h${ESC}?25l`);
  while (!stopped) {
    let frame;
    try { frame = renderStatus(await fetchUsage(config), { ansi: true }); }
    catch (err) { frame = `${yellow(true, '◆ JAYNSHARE')}\n\n${color(true, 31, err.message)}`; }
    process.stdout.write(`${ESC}H${ESC}2J${frame}\n\n${color(true, 2, 'Live read-only dashboard · Ctrl-C to close')}`);
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
}

const USAGE = 'Jaynshare desktop client\n\n  jaynshare status [--json|--line]\n  jaynshare dashboard\n';

async function main(argv = process.argv.slice(2)) {
  const command = argv[0] || 'help';
  if (command === 'title-hook') return runTitleHook();
  if (command === 'pick-account' || command === 'resolve-account') return runAccountCommand(command, argv);
  if (command !== 'status' && command !== 'dashboard') {
    process.stdout.write(USAGE);
    return;
  }

  const config = await loadClientConfig();
  if (command === 'dashboard') return showDashboard(config);
  return runStatus(config, argv);
}

async function runTitleHook() {
  const output = titleHook(await readStdin());
  if (output) process.stdout.write(JSON.stringify(output));
}

/** Prints the account a launcher should pin to: either the operator's pick or the named one. */
async function runAccountCommand(command, argv) {
  const config = await loadClientConfig();
  const usage = await fetchUsage(config);
  const selected = command === 'pick-account' ? await pickAccount(usage) : argv[1];
  if (command === 'resolve-account' && (typeof selected !== 'string' || !selected)) {
    throw new Error('missing account selector');
  }
  if (selected == null) {
    process.stdout.write(config.id);
    return;
  }
  const resolved = await resolveAccountSelection(config, selected, { usage });
  if (!resolved.available) {
    process.stderr.write(`jaynshare: ${resolved.account} is currently ${resolved.reason || 'unavailable'}; normal failover will apply\n`);
  }
  process.stdout.write(encodeAccountPreference(resolved.account));
}

async function runStatus(config, argv) {
  try {
    const lineInput = argv.includes('--line') ? parseStatusLineInput(await readOptionalStdin()) : { sessionId: null };
    const status = await fetchUsage(config, { sessionId: lineInput.sessionId });
    if (argv.includes('--json')) process.stdout.write(JSON.stringify(status, null, 2) + '\n');
    else if (argv.includes('--line')) process.stdout.write(renderStatusLine(status, { ansi: true }) + '\n'); // Claude renders the pipe in the terminal
    else process.stdout.write(renderStatus(status) + '\n');
  } catch (err) {
    if (!argv.includes('--line')) throw err;
    process.stdout.write(`${yellow(true, '◆ JAYNSHARE')} ${color(true, 31, 'offline')}\n`);
  }
}

// argv[1] may be a symlinked spelling of import.meta.url.
let invoked = false;
try {
  invoked = !!process.argv[1]
    && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
} catch { /* a non-existent argv[1] is not this module */ }
if (invoked) {
  main().catch(err => {
    process.stderr.write(`jaynshare: ${err.message}\n`);
    process.exitCode = 1;
  });
}
