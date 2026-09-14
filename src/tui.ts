import { createWriteStream } from 'node:fs';
import { importCredentials, fetchProfile } from './oauth.ts';
import type { ImportedCredentials, ProfileResult } from './oauth.ts';
import { sameIdentity, findUpsertTarget, withOrgSuffixes } from './identity.ts';
import { parseProxyUrl, proxyToUrl, describeProxy, resolveUpstreamProxy, setUpstreamProxy, getUpstreamProxy } from './upstream-proxy.ts';
import type { Account, AccountConfig, Config, Dict, RouteAccountView, RouteConfig, RouteView, TuiAccountManagerLike } from './types.ts';

const SPINNER = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'.split('');

const SPIN_MS = 500;          // only while something animates; an idle tick would keep a laptop awake
const IDLE_TICK_MS = 5_000;
const FORCE_REPAINT_MS = 60_000; // recovers from anything else writing over the terminal
const ESC = '\x1b[';
const RESET = `${ESC}0m`;
const BOLD = `${ESC}1m`;
const DIM = `${ESC}2m`;
const REV = `${ESC}7m`;   // reverse video

const bold = (s: string): string => `${BOLD}${s}${RESET}`;
const dim = (s: string): string => `${DIM}${s}${RESET}`;
const fg = (c: number, s: string): string => `${ESC}${c}m${s}${RESET}`;
const green = (s: string): string => fg(32, s);
const yellow = (s: string): string => fg(33, s);
const red = (s: string): string => fg(31, s);
const cyan = (s: string): string => fg(36, s);
const gray = (s: string): string => fg(90, s);

// Route colors (config `color`).
const NAMED_FG = {
  red: 31, green: 32, yellow: 33, blue: 34, magenta: 35, cyan: 36, white: 37,
  brightred: 91, brightgreen: 92, brightyellow: 93, brightblue: 94,
  brightmagenta: 95, brightcyan: 96,
};
const ROUTE_COLOR_NAMES = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan'];
const isRouteColor = (name: unknown): boolean => Object.prototype.hasOwnProperty.call(NAMED_FG, String(name || '').toLowerCase());
const routeColorFn = (name: unknown): ((s: string) => string) => {
  const code = (NAMED_FG as Record<string, number | undefined>)[String(name || '').toLowerCase()];
  return code ? (s => fg(code, s)) : cyan;
};

// Session colors avoid red (errors) and gray (timestamps).
const SESSION_FG = [36, 35, 34, 33, 94, 95, 96, 93, 92];
const SESSION_ID_LEN = 6;
function sessionColorCode(sid: string): number {
  let hash = 0;
  for (let i = 0; i < sid.length; i++) hash = (hash * 31 + sid.charCodeAt(i)) >>> 0;
  return SESSION_FG[hash % SESSION_FG.length];
}
const sessionTag = (sid: string | null): string =>
  sid ? fg(sessionColorCode(sid), sid.slice(0, SESSION_ID_LEN)) : ' '.repeat(SESSION_ID_LEN);

// Which quota-family bar (F7/S7) a route sits next to.
const routeFamily = (route: RouteView): string | null => {
  const hay = `${route.name} ${(route.match || []).join(' ')}`.toLowerCase();
  if (/fable/.test(hay)) return 'fable';
  if (/sonnet/.test(hay)) return 'sonnet';
  return null;
};

// bold: the route's pin; plain: eligible; dim: ineligible
const routeGlyph = (paint: (s: string) => string, eligible: boolean, pinned: boolean): string =>
  pinned ? bold(paint('►')) : eligible ? paint('►') : dim(paint('►'));

const ANSI_RE = /\x1b\[[0-9;]*m/g;
const strip = (s: string): string => s.replace(ANSI_RE, '');
const visibleWidth = (s: string): number => strip(s).length;

function rpad(s: string, w: number): string {
  const gap = w - visibleWidth(s);
  return gap > 0 ? s + ' '.repeat(gap) : s;
}

function splitCsv(value?: string): string[] {
  return (value || '').split(',').map(s => s.trim()).filter(Boolean);
}

/** Counts visible characters only; ANSI codes pass through. */
function truncate(s: string, w: number): string {
  let visible = 0;
  let out = '';
  let i = 0;
  while (i < s.length && visible < w) {
    if (s[i] === '\x1b') {
      const end = s.indexOf('m', i);
      if (end >= 0) { out += s.slice(i, end + 1); i = end + 1; continue; }
    }
    out += s[i];
    visible++;
    i++;
  }
  return out + RESET;
}

function fitLine(s: string, w: number): string {
  const v = visibleWidth(s);
  if (v > w) return truncate(s, w);
  if (v < w) return s + ' '.repeat(w - v);
  return s;
}

function formatReset(resetTs: number | string | null | undefined): string {
  const ts = typeof resetTs === 'string' ? new Date(resetTs).getTime() : resetTs;
  if (!ts) return '';
  const ms = ts - Date.now();
  if (ms <= 0) return '';
  const mins = Math.ceil(ms / 60000);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  const remainingMinutes = mins % 60;
  if (hrs < 24) return remainingMinutes > 0 ? `${hrs}h${remainingMinutes}m` : `${hrs}h`;
  const days = Math.floor(hrs / 24);
  const remainingHours = hrs % 24;
  return remainingHours > 0 ? `${days}d${remainingHours}h` : `${days}d`;
}

/** A background-colored bar with the reset time (or the percentage) overlaid. */
export function bar(ratio: number | null | undefined, w = 10, resetTs?: number | string | null): string {
  const resetLabel = formatReset(typeof resetTs === 'string' ? new Date(resetTs).getTime() : resetTs);

  if (ratio == null || isNaN(ratio)) {
    const label = resetLabel || '-';
    const text = label.slice(0, w);
    const pad = w - text.length;
    const leftPad = Math.floor(pad / 2);
    const rightPad = pad - leftPad;
    return `${ESC}100m${' '.repeat(leftPad)}${text}${' '.repeat(rightPad)}${RESET}`;
  }

  ratio = Math.max(0, Math.min(1, ratio));
  const filledWidth = Math.round(ratio * w);
  const backgroundColor = ratio < 0.7 ? 42 : ratio < 0.9 ? 43 : 41; // green | yellow | red

  const pct = (ratio * 100).toFixed(0) + '%';
  const label = resetLabel || pct;
  const text = label.slice(0, w);
  const pad = w - text.length;
  const leftPad = Math.floor(pad / 2);
  const rightPad = pad - leftPad;
  const chars = (' '.repeat(leftPad) + text + ' '.repeat(rightPad));

  const filled = chars.slice(0, filledWidth);
  const empty = chars.slice(filledWidth);
  const labelColor = backgroundColor === 41 ? 97 : 30; // themes render green/yellow light, so the label is black there

  let out = '';
  if (filled) out += `${ESC}${backgroundColor};${labelColor}m${filled}`;
  if (empty) out += `${ESC}100;37m${empty}`;
  out += RESET;
  return out;
}

function timestamp() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function accountStatusLabel(account: Account, isCurrent: boolean): string {
  if (account.disabled) return gray('disabled');
  switch (account.status) {
    case 'active':    return isCurrent ? green('active') : 'active';
    case 'throttled': return yellow('throttled');
    case 'exhausted': return red('exhausted');
    case 'error':     return red('error');
    default:          return account.status || 'ready';
  }
}

/** The two bars every row shows: subscription windows when known, else the API-key counters. */
function quotaBars(quota: Dict): { label: string; ratio: number | null; reset: number | string | null }[] {
  if (quota.unified5h != null || quota.unified7d != null || quota.unified7dSonnet != null || quota.unified7dFable != null) {
    return [
      { label: 'Ses', ratio: quota.unified5h, reset: quota.unified5hReset },
      { label: 'Wk ', ratio: quota.unified7d, reset: quota.unified7dReset },
    ];
  }
  const reset = quota.resetsAt ? new Date(quota.resetsAt).getTime() : null;
  const used = (remaining: number | null, limit: number | null) => (limit != null && remaining != null ? 1 - remaining / limit : null);
  return [
    { label: 'Tok', ratio: used(quota.tokensRemaining, quota.tokensLimit), reset },
    { label: 'Req', ratio: used(quota.requestsRemaining, quota.requestsLimit), reset },
  ];
}

/** Families whose own weekly bucket is at or over the switch threshold. */
function spentFamilies(quota: Dict, threshold: number): string[] {
  const spent = [];
  if (quota.unified7dSonnet != null && quota.unified7dSonnet >= threshold) spent.push('Sonnet');
  if (quota.unified7dFable != null && quota.unified7dFable >= threshold) spent.push('Fable');
  return spent;
}

export type TuiMode = 'normal' | 'select' | 'add' | 'input' | 'settings' | 'pick' | 'routes' | 'blocklist';

interface SettingsField {
  id: string;
  label: string;
  hint?: string;
  value: () => string;
  left?: () => void;
  right?: () => void;
  enter?: () => void;
}

interface Picker {
  title: string;
  hint?: string;
  items: { label: string; value: string; paint?: (s: string) => string }[];
  multi: boolean;
  cb: ((values: string[]) => void) | ((value: string) => void);
  idx: number;
  sel: Set<string>;
}

export interface TuiOptions {
  accountManager: TuiAccountManagerLike;
  config: Config;
  saveConfig: (config: Config) => Promise<void>;
  syncAccounts: () => Promise<number>;
  onQuit?: () => void;
  sx?: any | null;
  probeQuota?: (() => Promise<void>) | null;
  activityLogPath?: string | null;
  remote?: boolean;
  applySwitch?: ((name: string) => Promise<Dict>) | null;
  readCredentials?: typeof importCredentials;
  readProfile?: typeof fetchProfile;
}

export class TUI {
  accountManager!: TuiAccountManagerLike;
  remote: boolean;
  applySwitch: ((name: string) => Promise<Dict>) | null;
  config: Config;
  saveConfig: (config: Config) => Promise<void>;
  syncAccounts: () => Promise<number>;
  onQuit?: () => void;
  sx: any | null;
  sxBalance: any | null = null;
  probeQuota: (() => Promise<void>) | null;
  activityLogPath: string | null;
  _readCredentials: typeof importCredentials;
  _readProfile: typeof fetchProfile;
  _activityStream: import('node:fs').WriteStream | null;

  log: { t: string; msg: string }[] = [];           // completed
  active = new Map<number, Dict>(); // in flight
  mode: TuiMode = 'normal';    // normal | select | add | input | settings | pick
  pick: Picker | null = null;
  pickReturn: TuiMode = 'routes'; // mode to fall back to when the picker closes
  selAction: string | null = null;   // switch | remove | toggle
  selIdx = 0;
  selRoute: RouteView | null = null;    // in switch mode: null = global default, else a getRoutes() entry to pin
  selReturn: TuiMode = 'normal'; // mode to fall back to when select mode closes
  setIdx = 0;         // cursor row on the settings screen (BIOS-style nav)
  blockIdx = 0;       // cursor row on the blocked-models editor
  routeIdx = 0;
  inputPrompt = '';
  inputBuf = '';
  inputCb: ((v: string) => void) | null = null;
  inputReturn: TuiMode = 'normal'; // mode after a cancelled input
  frame = 0;
  running = false;
  timer: NodeJS.Timeout | null = null;
  _setTimeout = setTimeout;
  _origLog: ((...args: any[]) => void) | null = null;
  _origErr: ((...args: any[]) => void) | null = null;
  _probing = false;
  _rendering = false;
  _lastFrame: string | null = null;
  _lastPaintAt = 0;
  _dataHandler?: (d: string) => void;
  _resizeHandler?: () => void;

  constructor({ accountManager, config, saveConfig, syncAccounts, onQuit, sx = null, probeQuota = null, activityLogPath = null,
    remote = false, applySwitch = null, // attach mode: mutations are off, a switch becomes a request
    readCredentials = importCredentials, readProfile = fetchProfile }: TuiOptions) {
    this.accountManager = accountManager;
    this.remote = remote;
    this.applySwitch = applySwitch;
    this.config = config;
    this.saveConfig = saveConfig;
    this.syncAccounts = syncAccounts;
    this.onQuit = onQuit;
    this.sx = sx;
    this.sxBalance = null;
    this.probeQuota = probeQuota;
    this.activityLogPath = activityLogPath;
    this._readCredentials = readCredentials;
    this._readProfile = readProfile;
    this._activityStream = null;

    this.log = [];           // completed
    this.active = new Map(); // in flight
    this.mode = 'normal';    // normal | select | add | input | settings | pick
    this.pick = null;
    this.pickReturn = 'routes'; // mode to fall back to when the picker closes
    this.selAction = null;   // switch | remove | toggle
    this.selIdx = 0;
    this.selRoute = null;    // in switch mode: null = global default, else a getRoutes() entry to pin
    this.selReturn = 'normal'; // mode to fall back to when select mode closes
    this.setIdx = 0;         // cursor row on the settings screen (BIOS-style nav)
    this.blockIdx = 0;       // cursor row on the blocked-models editor
    this.inputPrompt = '';
    this.inputBuf = '';
    this.inputCb = null;
    this.inputReturn = 'normal'; // mode after a cancelled input
    this.frame = 0;
    this.running = false;
    this.timer = null;
    this._setTimeout = setTimeout;
    this._origLog = null;
    this._origErr = null;
  }

  // ── lifecycle ──────────────────────────────────────

  start(): void {
    this.running = true;
    if (this.activityLogPath) {
      this._activityStream = createWriteStream(this.activityLogPath, { flags: 'a' });
      this._activityStream.on('error', err => {
        this._activityStream = null; // logging it to the TUI would recurse
        process.stderr.write(`[Jaynshare] activity log error: ${err.message}\n`);
      });
    }
    process.stdout.write(`${ESC}?1049h${ESC}?25l`);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    this._dataHandler = d => this._onData(d);
    this._resizeHandler = () => this.render({ force: true });
    process.stdin.on('data', this._dataHandler);
    process.stdout.on('resize', this._resizeHandler);

    this._origLog = console.log;
    this._origErr = console.error;
    console.log = ((...a: unknown[]) => this._addLog(a.join(' '))) as typeof console.log;
    console.error = ((...a: unknown[]) => this._addLog(a.join(' '))) as typeof console.error;

    this._lastFrame = null;
    this.render();
    this._scheduleTick();
  }

  _tickDelay(): number { return this.active.size > 0 ? SPIN_MS : IDLE_TICK_MS; }

  _scheduleTick(): void {
    if (!this.running) return;
    this.timer = this._setTimeout(() => {
      if (!this.running) return;
      if (this.active.size > 0) this.frame = (this.frame + 1) % SPINNER.length;
      this.render();
      this._scheduleTick();
    }, this._tickDelay());
    this.timer.unref?.();
  }

  _retick(): void {
    if (!this.running) return;
    if (this.timer) clearTimeout(this.timer);
    this._scheduleTick();
  }

  stop(): void {
    this.running = false;
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    if (this._origLog && this._origErr) { console.log = this._origLog; console.error = this._origErr; }
    if (this._activityStream) { this._activityStream.end(); this._activityStream = null; }
    if (this._dataHandler) process.stdin.removeListener('data', this._dataHandler);
    if (this._resizeHandler) process.stdout.removeListener('resize', this._resizeHandler);
    process.stdout.write(`${ESC}?25h${ESC}?1049l`);
    try { process.stdin.setRawMode(false); } catch {}
    process.stdin.pause();
  }

  // ── server hooks ───────────────────────────────────

  onRequestStart(id: number, info: Dict): void {
    this.active.set(id, { ...info, t: timestamp(), started: Date.now(), account: null });
    this.render();
    if (this.active.size === 1) this._retick();
  }

  onRequestModel(id: number, info: Dict): void {
    const r = this.active.get(id);
    if (r && info.model) { r.model = info.model; this.render(); }
  }

  onRequestRouted(id: number, info: Dict): void {
    const r = this.active.get(id);
    if (r) r.account = info.account;
  }

  onRequestEnd(id: number, info: Dict): void {
    const r = this.active.get(id);
    this.active.delete(id);
    const dur = r ? ((Date.now() - r.started) / 1000).toFixed(1) : '?';
    const acct = info.account || r?.account || '?';
    const model = info.model ? ` (${info.model})` : '';
    const sid = info.sessionId || r?.sessionId || null;
    const pin = (info.pinned || r?.pinned) ? dim(' [pin]') : '';
    this._addLog(`${sessionTag(sid)} ${info.method} ${info.path}${model} → ${acct}${pin} (${info.status}, ${dur}s)`);
    if (this.active.size === 0) this._retick();
  }

  _addLog(msg: string): void {
    msg = msg.replace(/^\[Jaynshare\]\s*/, '');
    const t = timestamp();
    this.log.unshift({ t, msg });
    if (this.log.length > 200) this.log.length = 200;
    if (this._activityStream) this._activityStream.write(`${t}  ${strip(msg)}\n`);
    if (this.running) this.render();
  }

  // ── input handling ─────────────────────────────────

  _onData(d: string): void {
    if (d === '\x1b[A') return this._key('up');
    if (d === '\x1b[B') return this._key('down');
    if (d === '\x1b[C') return this._key('right');
    if (d === '\x1b[D') return this._key('left');
    if (d === '\x1b') return this._key('esc');
    if (d === '\r' || d === '\n') return this._key('enter');
    if (d === '\t') return this._key('tab');
    if (d === '\x03') return this._key('ctrl-c');
    if (d === '\x7f' || d === '\x08') return this._key('bs');
    if (d.length === 1 && d >= ' ') return this._key(d);
  }

  _key(k: string): void {
    if (k === 'ctrl-c') { this.stop(); this.onQuit?.(); return; }

    switch (this.mode) {
      case 'normal': this._keyNormal(k); break;
      case 'select': this._keySelect(k); break;
      case 'add':    this._keyAdd(k); break;
      case 'input':  this._keyInput(k); break;
      case 'settings': this._keySettings(k); break;
      case 'routes': this._keyRoutes(k); break;
      case 'pick': this._keyPick(k); break;
      case 'blocklist': this._keyBlocklist(k); break;
    }
    this.render();
  }

  _keyNormal(k: string): void {
    if (k === 'q') { this.stop(); this.onQuit?.(); }
    else if (k === 's' && this.accountManager.accounts.length > 0) {
      this.mode = 'select'; this.selAction = 'switch'; this.selIdx = Math.max(0, this.accountManager.currentIndex); this.selRoute = null; this.selReturn = 'normal';
    }
    else if (k === 'R') { this._doSync(); }
    else if (this.remote) { /* the server owns everything below */ }
    else if (k === 'd' && this.accountManager.accounts.length > 0) {
      this.mode = 'select'; this.selAction = 'toggle'; this.selIdx = this.accountManager.currentIndex; this.selReturn = 'normal';
    }
    else if (k === 'p' && this.accountManager.accounts.length > 0) { this._doProbe(); }
    else if (k === 'g') { this.mode = 'settings'; this.setIdx = 0; this._loadSxBalance(); }
  }

  // Rows are conditional: always index through this array.
  _settingsFields(): SettingsField[] {
    const fields: SettingsField[] = [];

    fields.push({
      id: 'threshold',
      label: 'Switch threshold',
      hint: '←→ ±1%',
      value: () => {
        const thr = this.accountManager.switchThreshold ?? this.config.switchThreshold ?? 0.98;
        return green(`${Math.round(thr * 100)}%`);
      },
      left: () => this._nudgeThreshold(-1),
      right: () => this._nudgeThreshold(+1),
      enter: () => this._promptInput('Switch threshold % (1-100)', v => this._doSetThreshold(v.trim())),
    });

    fields.push({
      id: 'probe',
      label: 'Quota probe',
      hint: '←→ ±30s',
      value: () => {
        const probe = this.config.quotaProbeSeconds || 0;
        return probe > 0 ? green(`${probe}s`) : gray('off (passive)');
      },
      left: () => this._nudgeProbe(-30),
      right: () => this._nudgeProbe(+30),
      enter: () => this._promptInput('Quota probe seconds (0=off, min 30)', v => this._doSetProbe(v.trim())),
    });

    fields.push({
      id: 'eventlog',
      label: 'Event logging',
      hint: '←→ cycle',
      value: () => {
        const mode = this.config.eventLogging || 'hide';
        return mode === 'show' ? green('show')
          : mode === 'block' ? red('block')
          : gray('hide');
      },
      left: () => this._cycleEventLogging(-1),
      right: () => this._cycleEventLogging(+1),
      enter: () => this._cycleEventLogging(+1),
    });

    fields.push({
      id: 'routes',
      label: 'Manage routing',
      hint: 'Enter to open',
      value: () => {
        const n = (this.config.routes || []).length;
        return n ? green(`${n} route${n === 1 ? '' : 's'}`) : gray('none');
      },
      enter: () => { this.mode = 'routes'; this.routeIdx = 0; },
    });

    fields.push({
      id: 'blocklist',
      label: 'Blocked models',
      hint: 'Enter to edit',
      value: () => {
        const n = (this.config.blockedModels || []).length;
        return n ? red(`${n} blocked`) : gray('none');
      },
      enter: () => { this.mode = 'blocklist'; this.blockIdx = 0; },
    });

    fields.push({
      id: 'addAccount',
      label: 'Add account',
      hint: 'Enter to open',
      value: () => {
        const n = this.accountManager.accounts.length;
        return n ? green(`${n} account${n === 1 ? '' : 's'}`) : gray('none');
      },
      enter: () => { this.mode = 'add'; },
    });

    if (this.accountManager.accounts.length > 0) {
      fields.push({
        id: 'removeAccount',
        label: 'Remove account',
        hint: 'Enter to pick',
        value: () => dim('—'),
        enter: () => { this.mode = 'select'; this.selAction = 'remove'; this.selIdx = 0; this.selReturn = 'settings'; },
      });
    }

    fields.push({
      id: 'upstreamProxy',
      label: 'Upstream proxy',
      hint: 'Enter to set',
      value: () => {
        const { proxy, source } = getUpstreamProxy();
        if (!proxy) return dim('(direct)');
        const via = source.startsWith('env:') ? gray(` (${source.slice(4)})`) : '';
        return green(describeProxy(proxy)) + via;
      },
      enter: () => this._promptInput('Upstream proxy (host:port, or blank for direct)', v => this._doSetUpstreamProxy(v.trim())),
    });

    if (this.sx) {
      fields.push({
        id: 'sxmode',
        label: 'sx.org mode',
        hint: '←→ cycle',
        value: () => {
          const mode = this.sx.getMode();
          return mode === 'always' ? green('always')
            : mode === '429' ? cyan('on 429 only')
            : gray('off');
        },
        left: () => this._cycleSxMode(-1),
        right: () => this._cycleSxMode(+1),
        enter: () => this._cycleSxMode(+1),
      });

      fields.push({
        id: 'sxkey',
        label: 'sx.org API key',
        hint: 'Enter to set',
        value: () => {
          const key = this.config.sx?.apiKey;
          return key ? key.slice(0, 4) + '…' + key.slice(-4) : dim('(not set)');
        },
        enter: () => this._promptInput('sx.org API key', v => this._doSetSxKey(v.trim())),
      });

      if (this.config.sx?.apiKey) {
        fields.push({
          id: 'sxclear',
          label: 'Clear sx.org key',
          hint: 'Enter to clear',
          value: () => dim('—'),
          enter: () => this._doClearSxKey(),
        });
      }
    }

    return fields;
  }

  _keySettings(k: string): void {
    const fields = this._settingsFields();
    const n = fields.length;
    if (n > 0 && this.setIdx >= n) this.setIdx = n - 1;
    const field = fields[this.setIdx];

    if (k === 'up' || k === 'k') this.setIdx = (this.setIdx - 1 + n) % n;
    else if (k === 'down' || k === 'j') this.setIdx = (this.setIdx + 1) % n;
    else if (k === 'left') field?.left?.();
    else if (k === 'right') field?.right?.();
    else if (k === 'enter') field?.enter?.();
    else if (k === 'esc' || k === 'q') { this.mode = 'normal'; }
  }

  _promptInput(prompt: string, cb: (v: string) => void): void {
    this.mode = 'input';
    this.inputReturn = 'settings';
    this.inputPrompt = prompt;
    this.inputBuf = '';
    this.inputCb = v => { if (v) cb(v); };
  }

  _nudgeThreshold(deltaPct: number): void {
    const cur = Math.round((this.accountManager.switchThreshold ?? this.config.switchThreshold ?? 0.98) * 100);
    const next = Math.max(1, Math.min(100, cur + deltaPct));
    if (next !== cur) this._doSetThreshold(String(next));
  }

  _nudgeProbe(deltaSec: number): void {
    const cur = this.config.quotaProbeSeconds || 0;
    const next = Math.max(0, cur + deltaSec);
    if (next !== cur) this._doSetProbe(String(next));
  }

  async _doSetThreshold(input: string): Promise<void> {
    const pct = Number(input);
    if (!Number.isFinite(pct) || pct < 1 || pct > 100) {
      this._addLog('Invalid threshold — enter 1–100'); this.mode = 'settings'; if (this.running) this.render(); return;
    }
    const v = Math.round(pct) / 100;
    this.config.switchThreshold = v;
    this.accountManager.switchThreshold = v;
    try { await this.saveConfig(this.config); }
    catch (e: any) { this._addLog(`Failed to save: ${e.message}`); }
    this._addLog(`Switch threshold set to ${Math.round(v * 100)}%`);
    this.mode = 'settings';
    if (this.running) this.render();
  }

  async _doSetProbe(input: string): Promise<void> {
    let secs = parseInt(input, 10);
    if (Number.isNaN(secs) || secs < 0) {
      this._addLog('Invalid interval — enter 0 (off) or seconds'); this.mode = 'settings'; if (this.running) this.render(); return;
    }
    if (secs > 0 && secs < 30) secs = 30; // the CLI minimum
    this.config.quotaProbeSeconds = secs;
    try { await this.saveConfig(this.config); }
    catch (e: any) { this._addLog(`Failed to save: ${e.message}`); }
    try { await this.syncAccounts(); } // reschedules the prober
    catch (e: any) { this._addLog(`Reload failed: ${e.message}`); }
    this._addLog(secs > 0 ? `Quota probe every ${secs}s` : 'Quota probe disabled');
    this.mode = 'settings';
    if (this.running) this.render();
  }

  _keySelect(k: string): void {
    const len = this.accountManager.accounts.length;
    if (k === 'up' || k === 'k') this.selIdx = Math.max(0, this.selIdx - 1);
    else if (k === 'down' || k === 'j') this.selIdx = Math.min(len - 1, this.selIdx + 1);
    // ←→ cycle the pin target: the default account, then each route. Attach mode has no pins.
    else if ((k === 'tab' || k === 'right') && this.selAction === 'switch' && !this.remote) this._cycleSelRoute(+1);
    else if (k === 'left' && this.selAction === 'switch' && !this.remote) this._cycleSelRoute(-1);
    else if (k === 'enter') {
      if (this.selAction === 'switch') {
        this._doSwitchSelection();
      } else if (this.selAction === 'toggle') {
        this._doToggleDisabled(this.selIdx);
      } else {
        this._doRemove(this.selIdx);
      }
      if (this.mode === 'select') this.mode = this.selReturn;
    }
    else if (k === 'esc' || k === 'q') { this.mode = this.selReturn; }
  }

  _cycleSelRoute(dir: number): void {
    const routes = this.accountManager.getRoutes();
    const cycle = [null, ...routes];
    const selName = this.selRoute?.name;
    const at = selName ? routes.findIndex(r => r.name === selName) + 1 : 0;
    const from = at < 1 ? 0 : at; // a vanished route lands on the default
    this.selRoute = cycle[(from + dir + cycle.length) % cycle.length];
  }

  _doSwitchSelection(): void {
    const acct = this.accountManager.accounts[this.selIdx];
    if (!acct) { this.mode = 'normal'; this._addLog('That account is no longer listed'); return; } // attach mode polls
    if (this.applySwitch) { this.mode = 'normal'; this._doSwitchRemote(acct); return; }
    if (this.selRoute === null) {
      this.accountManager.currentIndex = this.selIdx;
      this._addLog(`Switched to "${acct.name}"`);
      this.mode = 'normal';
      return;
    }
    const name = this.selRoute.name;
    if (this.accountManager.getRoutePin?.(name) === acct) {
      this.accountManager.clearRoutePin?.(name);
      this._addLog(`Unpinned route "${name}"`);
      this.mode = 'normal';
      return;
    }
    const res = this.accountManager.setRoutePin?.(name, this.selIdx);
    if (res?.ok) {
      this._addLog(`Pinned "${acct.name}" for route "${name}"`);
      this.mode = 'normal';
    } else {
      this._addLog(`Can't pin: ${res?.reason}`); // stays in select mode
    }
  }

  async _doSwitchRemote(acct: Account): Promise<void> {
    if (!this.applySwitch) return;
    try {
      const res = await this.applySwitch(acct.name);
      const name = res?.account || acct.name;
      if (res?.eligible === false) {
        // The reason arrives over the wire and is drawn into a fixed-width frame.
        const given = typeof res.reason === 'string' ? res.reason.replace(/\p{C}/gu, ' ').trim().slice(0, 60) : '';
        this._addLog(`Switched to "${name}" — ${given ? `it is ${given}` : 'it cannot serve requests right now'}`);
      } else {
        this._addLog(`Switched to "${name}"`);
      }
    } catch (e: any) {
      this._addLog(`Switch failed: ${e.message}`);
    }
    if (this.running) this.render();
  }

  _keyAdd(k: string): void {
    if (k === 'i') { this._doImport(); this.mode = 'settings'; }
    else if (k === 'k') {
      this.mode = 'input';
      this.inputReturn = 'settings';
      this.inputPrompt = 'API key';
      this.inputBuf = '';
      this.inputCb = v => { if (v) this._doAddKey(v); };
    }
    else if (k === 'esc' || k === 'q') { this.mode = 'settings'; }
  }

  _keyInput(k: string): void {
    if (k === 'enter') {
      const cb = this.inputCb;
      const v = this.inputBuf;
      this.mode = this.inputReturn; this.inputCb = null; this.inputBuf = '';
      cb?.(v);
    }
    else if (k === 'esc') { this.mode = this.inputReturn; this.inputCb = null; this.inputBuf = ''; }
    else if (k === 'bs') { this.inputBuf = this.inputBuf.slice(0, -1); }
    else if (k.length === 1) { this.inputBuf += k; }
  }

  // ── account operations ─────────────────────────────

  async _doProbe(): Promise<void> {
    if (!this.probeQuota) { this._addLog('Quota probe unavailable'); return; }
    if (this._probing) return;
    const oauthCount = this.accountManager.accounts.filter(a => a.type === 'oauth' && a.credential).length;
    if (oauthCount === 0) { this._addLog('No OAuth accounts to probe'); return; }
    this._probing = true;
    this._addLog(`Refreshing quota on ${oauthCount} account${oauthCount === 1 ? '' : 's'}...`);
    try {
      await this.probeQuota();
      this._addLog('Quota refresh complete');
    } catch (e: any) {
      this._addLog(`Quota refresh failed: ${e.message}`);
    } finally {
      this._probing = false;
    }
  }

  async _doSync(): Promise<void> {
    try {
      const count = await this.syncAccounts();
      if (count > 0) {
        this._addLog(`Synced ${count} new account(s) from config`);
      } else {
        this._addLog('Config reloaded, credentials refreshed');
      }
    } catch (e: any) {
      this._addLog(`Sync failed: ${e.message}`);
    }
  }

  // ── Network settings ───────────────────────────────

  /** Applied live as well as saved. Blank clears it. */
  async _doSetUpstreamProxy(value: string): Promise<void> {
    let parsed;
    try {
      parsed = parseProxyUrl(value);
    } catch (e: any) {
      this._addLog(`Invalid proxy: ${e.message}`);
      this.mode = 'settings';
      return;
    }

    if (parsed) this.config.upstreamProxy = proxyToUrl(parsed);
    else delete this.config.upstreamProxy;

    try { await this.saveConfig(this.config); }
    catch (e: any) { this._addLog(`Failed to save proxy setting: ${e.message}`); }

    const resolved = setUpstreamProxy(resolveUpstreamProxy(this.config));
    if (resolved.proxy) this._addLog(`Upstream proxy set to ${describeProxy(resolved.proxy)}`);
    else this._addLog('Upstream proxy cleared — connecting directly');
    this.mode = 'settings';
  }

  // ── sx.org settings ────────────────────────────────

  _loadSxBalance(): void {
    this.sxBalance = null;
    if (!this.sx?.apiKey) return;
    this.sx.getBalance()
      .then((b: Dict) => { this.sxBalance = b; if (this.running) this.render(); })
      .catch(() => {});
  }

  _sxModeLabel(mode: string): string { return mode === 'always' ? 'always' : mode === '429' ? 'on 429 only' : 'off'; }

  async _doSetSxKey(key: string): Promise<void> {
    const mode = this.config.sx?.mode || 'always';
    this.config.sx = { apiKey: key, mode };
    try { await this.saveConfig(this.config); }
    catch (e: any) { this._addLog(`Failed to save sx.org key: ${e.message}`); }
    this._addLog('sx.org: configuring...');
    const result = await this.sx.configure(key, mode);
    if (result.ok && result.proxy) this._addLog(`sx.org key saved — proxy ${result.proxy.host}:${result.proxy.port} (mode: ${this._sxModeLabel(mode)})`);
    else if (result.ok) this._addLog(`sx.org key saved (mode: ${this._sxModeLabel(mode)})`);
    else this._addLog(`sx.org error: ${result.error}`);
    this._loadSxBalance();
    this.mode = 'settings';
    if (this.running) this.render();
  }

  async _cycleSxMode(dir = 1): Promise<void> {
    const order = ['off', '429', 'always'];
    const next = order[(order.indexOf(this.sx.getMode()) + dir + order.length) % order.length];
    this.config.sx = { ...(this.config.sx || {}), mode: next };
    try { await this.saveConfig(this.config); }
    catch (e: any) { this._addLog(`Failed to save: ${e.message}`); }
    const result = await this.sx.setMode(next);
    this._addLog(`sx.org mode: ${this._sxModeLabel(next)}${result.ok ? '' : ` — ${result.error}`}`);
    if (next !== 'off') this._loadSxBalance();
    if (this.running) this.render();
  }

  async _cycleEventLogging(dir = 1): Promise<void> {
    const order = ['show', 'hide', 'block'];
    const cur = this.config.eventLogging || 'hide';
    const next = order[(order.indexOf(cur) + dir + order.length) % order.length];
    this.config.eventLogging = next; // the server reads the shared object live
    try { await this.saveConfig(this.config); }
    catch (e: any) { this._addLog(`Failed to save: ${e.message}`); }
    this._addLog(`Event logging: ${next}`);
    if (this.running) this.render();
  }

  async _doClearSxKey(): Promise<void> {
    this.config.sx = null;
    try { await this.saveConfig(this.config); }
    catch (e: any) { this._addLog(`Failed to save: ${e.message}`); }
    this.sx.disable();
    this.sxBalance = null;
    this._addLog('sx.org key cleared');
    if (this.running) this.render();
  }

  async _doImport(): Promise<void> {
    try {
      this._addLog('Importing credentials...');
      const creds = await this._readCredentials('~/.claude/.credentials.json');
      const profile = await this._readProfile(creds.accessToken || '');
      if (!profile || profile.error) {
        this._addLog(`Warning: could not fetch profile — ${profile?.error || 'no token'}`);
      }

      const entry = this._importedEntry(creds, profile);
      const at = findUpsertTarget(this.config.accounts, entry);
      if (at >= 0) this._updateImported(at, entry);
      else this._addImported(entry);

      await this.saveConfig(this.config);
    } catch (e: any) {
      this._addLog(`Import failed: ${e.message}`);
    }
  }

  _importedEntry(creds: ImportedCredentials, profile: ProfileResult | null): AccountConfig {
    let name: string;
    if (profile?.email) {
      const tier = profile.hasClaudeMax ? 'Max' : profile.hasClaudePro ? 'Pro' : null;
      if (tier) this._addLog(`Detected Claude ${tier}: ${profile.email}`);
      name = profile.email;
    } else {
      const n = this.config.accounts.filter(a => a.name.startsWith('account-')).length + 1;
      name = `account-${n}`;
    }
    return {
      name, type: 'oauth', source: 'import',
      accountUuid: profile?.accountUuid || null,
      orgUuid: profile?.orgUuid || null,
      orgName: profile?.orgName || null,
      accessToken: creds.accessToken,
      refreshToken: creds.refreshToken,
      expiresAt: creds.expiresAt,
    };
  }

  /** Refreshes the config entry and, when it is already running, the live account. */
  _updateImported(at: number, entry: AccountConfig): void {
    const prev = this.config.accounts[at];
    this.config.accounts[at] = { ...prev, ...entry, name: prev.name };
    const live = this.accountManager.accounts.find(a => sameIdentity(a, entry)) || this.accountManager.accounts[at];
    if (live) {
      live.credential = entry.accessToken ?? null;
      live.refreshToken = entry.refreshToken ?? null;
      live.expiresAt = entry.expiresAt ?? null;
      live.accountUuid = entry.accountUuid ?? null;
      live.orgUuid = entry.orgUuid ?? null;
      live.orgName = entry.orgName ?? null;
      if (live.status === 'error') live.status = 'active';
    }
    this._addLog(`Updated account "${prev.name}"`);
  }

  _addImported(entry: AccountConfig): void {
    const { accounts, incoming } = withOrgSuffixes(this.config.accounts, entry);
    this.config.accounts = [...accounts, incoming];
    this.accountManager.addAccount?.(incoming);
    this._addLog(`Imported account "${incoming.name}"`);
  }

  async _doAddKey(apiKey: string): Promise<void> {
    const n = this.config.accounts.filter(a => a.name.startsWith('api-')).length + 1;
    const name = `api-${n}`;
    this.config.accounts.push({ name, type: 'apikey', apiKey });
    this.accountManager.addAccount?.({ name, type: 'apikey', apiKey });
    await this.saveConfig(this.config);
    this._addLog(`Added API key account "${name}"`);
  }

  async _doRemove(idx: number): Promise<void> {
    if (idx < 0 || idx >= this.accountManager.accounts.length) return;
    const name = this.accountManager.accounts[idx].name;
    this.accountManager.removeAccount?.(idx);
    this.config.accounts.splice(idx, 1);
    if (this.selIdx >= this.accountManager.accounts.length) this.selIdx = Math.max(0, this.accountManager.accounts.length - 1);
    await this.saveConfig(this.config);
    this._addLog(`Removed account "${name}"`);
  }

  async _doToggleDisabled(idx: number): Promise<void> {
    if (idx < 0 || idx >= this.accountManager.accounts.length) return;
    const acct = this.accountManager.accounts[idx];
    const next = !acct.disabled;
    this.accountManager.setDisabled?.(idx, next);
    if (this.config.accounts[idx]) this.config.accounts[idx].disabled = next; // saveConfig merges; delete would keep the disk value
    await this.saveConfig(this.config);
    this._addLog(`${next ? 'Disabled' : 'Enabled'} account "${acct.name}"`);
  }

  // ── rendering ──────────────────────────────────────

  render({ force = false }: { force?: boolean } = {}): void {
    if (!this.running) return;
    if (this._rendering) return; // _addLog re-enters
    this._rendering = true;
    try {
      const frame = this._frame();
      if (force) this._paint(frame);
      else this._paintIfChanged(frame);
    } finally {
      this._rendering = false;
    }
  }

  _paintIfChanged(buf: string): void {
    const stale = Date.now() - (this._lastPaintAt || 0) >= FORCE_REPAINT_MS;
    if (!stale && buf === this._lastFrame) return;
    this._paint(buf);
  }

  _paint(buf: string): void {
    this._lastFrame = buf;
    this._lastPaintAt = Date.now();
    process.stdout.write(buf);
  }

  /** Builds the whole screen; painting it is the caller's job. */
  _frame(): string {
    this.accountManager.refreshExpiredQuotas();
    const W = process.stdout.columns || 80;
    const H = process.stdout.rows || 24;

    if (W < 40 || H < 8) return `${ESC}H${ESC}2JTerminal too small (need 40x8+)\r\n`;

    const footerH = 2;
    const lines: string[] = [];
    this._renderHeader(lines, W);

    // A prompt keeps the screen it was launched from behind it.
    const view = this.mode === 'input' ? this.inputReturn
      : this.mode === 'add' ? 'settings'
      : this.mode;
    if (view === 'settings') {
      this._renderSettings(lines);
    } else if (view === 'routes') {
      this._renderRoutes(lines);
    } else if (view === 'pick') {
      this._renderPick(lines);
    } else if (view === 'blocklist') {
      this._renderBlocklist(lines);
    } else {
      this._renderAccounts(lines, W);
      this._renderActivity(lines, W, H - footerH);
    }

    while (lines.length < H - footerH) lines.push('');
    lines.push(' ' + dim('─'.repeat(W - 2)));
    lines.push(this._renderFooter());

    let buf = `${ESC}H`;
    for (let i = 0; i < H; i++) {
      buf += fitLine(lines[i] || '', W);
      if (i < H - 1) buf += '\r\n';
    }
    buf += this.mode === 'input' ? `${ESC}?25h` : `${ESC}?25l`;
    return buf;
  }

  _renderHeader(lines: string[], W: number): void {
    const left = bold(yellow(' ◆ JAYNSHARE'));
    const port = this.config.proxy?.port || 3456;
    const sess = this.accountManager.sessionStats();
    const sessStr = (sess.active || sess.known)
      ? `${sess.active} sess${this.accountManager.distributeSessions ? green(' dist') : ''}  `
      : '';
    const live = this.accountManager.connected === false ? red('▼') : green('▲'); // attach mode lost the server
    const right = `${sessStr}Port ${port} ${live} `;
    lines.push(left + ' '.repeat(Math.max(1, W - visibleWidth(left) - visibleWidth(right))) + right);
    lines.push(' ' + dim('─'.repeat(W - 2)));
  }

  _renderAccounts(lines: string[], W: number): void {
    lines.push('');
    if (this.accountManager.accounts.length === 0) {
      lines.push(yellow(this.remote
        ? '  The server reports no accounts.'
        : '  No accounts configured. Press [g] → Add account.'));
      return;
    }
    const showBoth = W >= 70;
    const barWidth = showBoth
      ? Math.max(5, Math.min(20, Math.floor((W - 56) / 2)))
      : Math.max(5, Math.min(20, W - 45));

    const layout = { barWidth, showBoth, ...this._routeLayout() };
    for (let i = 0; i < this.accountManager.accounts.length; i++) {
      lines.push(this._renderAcct(i, layout));
    }
  }

  /** The route markers every account row shares: one column per general route, one ► per family. */
  _routeLayout(): { routes: RouteView[]; genRoutes: RouteView[]; familyTarget: Dict } {
    const routes = this.accountManager.getRoutes();
    const anyFable = this.accountManager.accounts.some(a => a.quota.unified7dFable != null);
    const anySonnet = this.accountManager.accounts.some(a => a.quota.unified7dSonnet != null);
    return {
      routes,
      genRoutes: routes.filter(r => routeFamily(r) === null),
      familyTarget: {
        fable: anyFable ? this.accountManager.previewRouteIndex('claude-fable-5') : null,
        sonnet: anySonnet ? this.accountManager.previewRouteIndex('claude-sonnet-4-6') : null,
      },
    };
  }

  /** In-flight requests, then the completed log down to `maxLines`. Attach mode sees only its own messages. */
  _renderActivity(lines: string[], W: number, maxLines: number): void {
    lines.push('');
    const activeCount = this.active.size;
    const activeTag = activeCount > 0 ? `  ${cyan(activeCount + ' active')}` : '';
    const activityHeader = this.remote ? ' Messages ' : ` Activity${activeTag} `;
    lines.push(activityHeader + dim('─'.repeat(Math.max(1, W - visibleWidth(activityHeader)))));

    const now = Date.now();
    for (const [, r] of this.active) {
      const elapsed = ((now - r.started) / 1000).toFixed(1);
      const spinner = cyan(SPINNER[this.frame]);
      const modelSuffix = r.model ? dim(` (${r.model})`) : '';
      const pin = r.pinned ? dim(' [pin]') : '';
      const routingSuffix = r.account ? ` → ${r.account}${pin}` : '';
      lines.push(` ${spinner} ${gray(r.t)}  ${sessionTag(r.sessionId)} ${r.method} ${r.path}${modelSuffix}${routingSuffix} ${dim(`(${elapsed}s...)`)}`);
    }

    const space = Math.max(0, maxLines - lines.length);
    for (let i = 0; i < space && i < this.log.length; i++) {
      lines.push(`   ${gray(this.log[i].t)}  ${this.log[i].msg}`);
    }
  }

  _renderAcct(idx: number, { barWidth, showBoth, routes = [], genRoutes = [], familyTarget = {} }: { barWidth: number; showBoth: boolean; routes?: RouteView[]; genRoutes?: RouteView[]; familyTarget?: Dict }): string {
    const account = this.accountManager.accounts[idx];
    const isCurrent = idx === this.accountManager.currentIndex;
    const isSel = this.mode === 'select' && idx === this.selIdx;

    const sel = isSel ? cyan('>') : ' ';
    const cur = isCurrent ? green('►') : ' ';

    // One fixed column per general route, so the marker's position identifies the route.
    const memberOf = (route: RouteView) => route.accounts.find((x: RouteAccountView) => x.name === account.name);
    const startCells = genRoutes.map(r => {
      const member = memberOf(r);
      return member ? routeGlyph(routeColorFn(r.color), member.eligible, r.pinned === account.name) : ' ';
    });
    const startSlot = genRoutes.length ? `${startCells.join('')} ` : '';

    // A single ► on the account the family bucket routes to right now.
    const familyMark = (family: string): string => {
      if (familyTarget[family] !== idx) return ' ';
      const r = routes.find(x => routeFamily(x) === family);
      const pinned = r ? r.pinned === account.name : false;
      return routeGlyph(routeColorFn(r?.color), true, pinned);
    };

    const rawName = account.name.slice(0, 12).padEnd(12);
    const name = isSel ? bold(rawName) : rawName;
    const type = gray(account.type.padEnd(7));
    const status = rpad(accountStatusLabel(account, isCurrent), 10);

    const quota = account.quota;
    const [primary, secondary] = quotaBars(quota);

    let line = ` ${sel}${cur} ${startSlot}${name} ${type} ${status} ${primary.label} ${bar(primary.ratio, barWidth, primary.reset)}`;
    if (showBoth) {
      line += `  ${secondary.label} ${bar(secondary.ratio, barWidth, secondary.reset)}`;
      if (quota.unified7dSonnet != null) {
        line += ` ${familyMark('sonnet')}S7  ${bar(quota.unified7dSonnet, barWidth, quota.unified7dSonnetReset)}`;
      }
      if (quota.unified7dFable != null) {
        line += ` ${familyMark('fable')}F7  ${bar(quota.unified7dFable, barWidth, quota.unified7dFableReset)}`;
      }
    }
    const blocked = spentFamilies(quota, this.accountManager.switchThreshold);
    if (blocked.length) line += `  ${red('⊘ ' + blocked.join(' '))}`;
    return line;
  }

  _renderSettings(lines: string[]): void {
    const fields = this._settingsFields();
    if (this.setIdx >= fields.length) this.setIdx = Math.max(0, fields.length - 1);
    const selId = fields[this.setIdx]?.id;
    const byId = (id: string): SettingsField | undefined => fields.find(f => f.id === id);

    const row = (field?: SettingsField): string => {
      const selected = field && field.id === selId;
      const label = (field ? field.label : '').padEnd(16);
      const value = field ? field.value() : '';
      if (selected) {
        const hint = field.hint ? `   ${dim(field.hint)}` : '';
        const inner = rpad(` ${label}  ${strip(value)} `, 34);
        return `  ${cyan('▸')}${REV}${inner}${RESET}${hint}`;
      }
      return `    ${dim(label)}  ${value}`;
    };
    const info = (label: string, value: string): string => `    ${dim(label.padEnd(16))}  ${value}`;

    lines.push('');
    lines.push(bold('  Rotation') + dim('  — switch accounts when quota crosses the threshold'));
    lines.push(row(byId('threshold')));
    lines.push('');
    lines.push(bold('  Quota probe') + dim('  — refresh idle accounts from the usage endpoint'));
    lines.push(row(byId('probe')));
    lines.push('');
    lines.push(bold('  Activity log') + dim('  — what to do with Claude Code\'s telemetry'));
    lines.push(row(byId('eventlog')));
    lines.push('');
    lines.push(bold('  Routing') + dim('  — pin model families to specific accounts, or block them outright'));
    lines.push(row(byId('routes')));
    lines.push(row(byId('blocklist')));
    lines.push('');
    lines.push(bold('  Accounts') + dim('  — add (import / API key) or remove an account'));
    lines.push(row(byId('addAccount')));
    if (byId('removeAccount')) lines.push(row(byId('removeAccount')));
    lines.push('');
    lines.push(bold('  Network') + dim('  — how this machine reaches Anthropic'));
    lines.push(row(byId('upstreamProxy')));
    lines.push(dim('  Set when the machine has no direct route out (HTTPS_PROXY is'));
    lines.push(dim('  picked up automatically). Applies to requests, login and refresh.'));
    lines.push('');
    lines.push(bold('  sx.org proxy') + dim('  — route upstream via a residential IP (429 workaround)'));
    lines.push('');
    if (!this.sx) { lines.push(yellow('  Unavailable in this build.')); return; }
    const key = this.config.sx?.apiKey;
    const mode = this.sx.getMode();
    const proxy = this.sx.getProxy?.();
    const proxyStr = mode === 'off' ? gray('—')
      : this.sx.isProvisioned() ? green(`${proxy.host}:${proxy.port}`)
      : key ? yellow('not provisioned')
      : gray('no key');
    const b = this.sxBalance;
    lines.push(row(byId('sxmode')));
    lines.push(row(byId('sxkey')));
    lines.push(info('Proxy', proxyStr));
    lines.push(info('Balance', b ? green('$' + Number(b.balance).toFixed(4)) : dim('…')));
    if (byId('sxclear')) lines.push(row(byId('sxclear')));
    lines.push('');
    lines.push(dim('  always    tunnel ALL upstream traffic through sx.org'));
    lines.push(dim('  on 429    only retry through sx.org after a 429 (fresh IP)'));
    lines.push(dim('  off       never use sx.org (API key is kept)'));
    lines.push('');
    lines.push(dim('  TLS stays end-to-end; residential traffic is metered by sx.org.'));
  }

  // ── routes editor ──────────────────────────────────

  _keyRoutes(k: string): void {
    const routes = this.config.routes || [];
    const n = routes.length;
    if (this.routeIdx >= n) this.routeIdx = Math.max(0, n - 1);
    if ((k === 'up' || k === 'k') && n) this.routeIdx = (this.routeIdx - 1 + n) % n;
    else if ((k === 'down' || k === 'j') && n) this.routeIdx = (this.routeIdx + 1) % n;
    else if (k === 'a') this._routeEdit(null);
    else if (k === 'e' && n) this._routeEdit(routes[this.routeIdx]);
    else if (k === 'd' && n) this._routeDelete(this.routeIdx);
    else if (k === 'esc' || k === 'q') { this.mode = 'settings'; this.setIdx = 0; }
  }

  // Unlike _promptInput, a blank value reaches the callback.
  _routePrompt(label: string, prefill?: string, cb?: (v: string) => void): void {
    this.mode = 'input';
    this.inputReturn = 'routes';
    this.inputPrompt = label;
    this.inputBuf = prefill || '';
    this.inputCb = v => { if (cb) cb((v || '').trim()); };
  }

  // Esc cancels without calling `cb`, abandoning the whole edit.
  _openPicker({ title, hint, items, multi, selected, cb }: { title: string; hint?: string; items: Picker['items']; multi: boolean; selected?: string | string[]; cb: Picker['cb'] }): void {
    this.mode = 'pick';
    this.pickReturn = 'routes';
    this.pick = {
      title, hint, items, multi, cb,
      idx: multi ? 0 : Math.max(0, items.findIndex(it => it.value === (selected || ''))),
      sel: new Set(multi ? (selected || []) : []),
    };
  }

  _pickAccounts(preselected: string[], cb: (values: string[]) => void): void {
    this._openPicker({
      title: 'Route accounts',
      hint: 'Space toggles — none selected = all accounts',
      multi: true,
      selected: preselected,
      items: this.accountManager.accounts.map(a => ({ label: a.name, value: a.name })),
      cb,
    });
  }

  _pickBucket(current: string, cb: (value: string) => void): void {
    this._openPicker({
      title: 'Quota bucket',
      hint: 'weekly bucket this route is metered against',
      multi: false,
      selected: current,
      items: [
        { label: 'auto (by model family)', value: '' },
        { label: 'unified7d (shared weekly)', value: 'unified7d' },
        { label: 'unified7dFable', value: 'unified7dFable' },
        { label: 'unified7dSonnet', value: 'unified7dSonnet' },
      ],
      cb,
    });
  }

  _pickColor(current: string, cb: (value: string) => void): void {
    this._openPicker({
      title: 'Marker color',
      hint: 'highlights this route on the dashboard',
      multi: false,
      selected: current,
      items: [
        { label: 'default', value: '' },
        ...ROUTE_COLOR_NAMES.map(c => ({ label: c, value: c, paint: routeColorFn(c) })),
      ],
      cb,
    });
  }

  _keyPick(k: string): void {
    const picker = this.pick;
    if (!picker) { this.mode = this.pickReturn; return; }
    const len = picker.items.length;
    if (k === 'up' || k === 'k') picker.idx = Math.max(0, picker.idx - 1);
    else if (k === 'down' || k === 'j') picker.idx = Math.min(len - 1, picker.idx + 1);
    else if (picker.multi && (k === ' ' || k === 'x')) {
      const selected = picker.items[picker.idx]?.value;
      if (selected != null) { picker.sel.has(selected) ? picker.sel.delete(selected) : picker.sel.add(selected); }
    }
    else if (k === 'enter') {
      const cb = picker.cb;
      this.pick = null;
      this.mode = this.pickReturn;
      if (picker.multi) (cb as (values: string[]) => void)?.(picker.items.filter(it => picker.sel.has(it.value)).map(it => it.value));
      else (cb as (value: string) => void)?.(picker.items[picker.idx]?.value ?? '');
    }
    else if (k === 'esc' || k === 'q') { this.pick = null; this.mode = this.pickReturn; }
  }

  _renderPick(lines: string[]): void {
    const picker = this.pick;
    if (!picker) return;
    lines.push('');
    lines.push(bold('  ' + picker.title) + (picker.hint ? dim('  — ' + picker.hint) : ''));
    lines.push('');
    if (!picker.items.length) {
      lines.push(gray('    (no accounts loaded — a route with none set serves all)'));
      return;
    }
    picker.items.forEach((it, i) => {
      const cur = i === picker.idx;
      const cursor = cur ? cyan('▸') : ' ';
      const mark = picker.multi
        ? (picker.sel.has(it.value) ? green('[x]') : dim('[ ]'))
        : (cur ? cyan('◉') : dim('◯'));
      const paint = it.paint || (s => s);
      lines.push(`   ${cursor} ${mark} ${paint(cur ? bold(it.label) : it.label)}`);
    });
  }

  /** `orig` is null when adding. */
  _routeEdit(orig: RouteConfig | null): void {
    const draft: Dict = {
      match: (orig ? (Array.isArray(orig.match) ? orig.match : [orig.match]) : []).join(', '),
      accounts: (orig?.accounts || []).join(', '),
      bucket: orig?.bucket || '',
      color: orig?.color || '',
    };
    this._routePrompt('Route name', orig?.name || '', name => {
      if (!name) { this._addLog('Route name required — cancelled'); this.mode = 'routes'; return; }
      draft.name = name;
      this._routePrompt('Model glob(s), comma-separated (e.g. *fable*)', draft.match, match => {
        if (!match) { this._addLog('At least one glob required — cancelled'); this.mode = 'routes'; return; }
        draft.match = match;
        this._pickAccounts(splitCsv(draft.accounts), accts => {
          draft.accounts = accts.join(', ');
          this._pickBucket(draft.bucket, bucket => {
            draft.bucket = bucket;
            this._pickColor(draft.color, color => {
              draft.color = color;
              this._routeSave(draft, orig);
            });
          });
        });
      });
    });
  }

  async _routeSave(draft: Dict, orig: RouteConfig | null): Promise<void> {
    const route: RouteConfig = { name: draft.name, match: splitCsv(draft.match) };
    const accounts = splitCsv(draft.accounts);
    if (accounts.length) route.accounts = accounts;
    if (draft.bucket) route.bucket = draft.bucket;
    if (draft.color) {
      if (isRouteColor(draft.color)) route.color = draft.color.toLowerCase();
      else this._addLog(`Unknown color "${draft.color}" — using default`);
    }

    this.config.routes = this.config.routes || [];
    const at = orig ? this.config.routes.indexOf(orig)
      : this.config.routes.findIndex((r: RouteConfig) => r.name === route.name);
    if (at >= 0) this.config.routes[at] = route; else this.config.routes.push(route);

    this.accountManager.setRoutes?.(this.config.routes);
    try { await this.saveConfig(this.config); this._addLog(`Route "${route.name}" saved`); }
    catch (e: any) { this._addLog(`Failed to save route: ${e.message}`); }
    this.mode = 'routes';
    this.routeIdx = at >= 0 ? at : this.config.routes.length - 1;
    if (this.running) this.render();
  }

  async _routeDelete(idx: number): Promise<void> {
    const routes = this.config.routes || [];
    const r = routes[idx];
    if (!r) return;
    routes.splice(idx, 1);
    this.accountManager.setRoutes?.(routes);
    try { await this.saveConfig(this.config); this._addLog(`Route "${r.name}" deleted`); }
    catch (e: any) { this._addLog(`Failed to save: ${e.message}`); }
    this.routeIdx = Math.max(0, Math.min(idx, routes.length - 1));
    if (this.running) this.render();
  }

  _keyBlocklist(k: string): void {
    const list = this.config.blockedModels || [];
    const n = list.length;
    if (this.blockIdx >= n) this.blockIdx = Math.max(0, n - 1);
    if ((k === 'up' || k === 'k') && n) this.blockIdx = (this.blockIdx - 1 + n) % n;
    else if ((k === 'down' || k === 'j') && n) this.blockIdx = (this.blockIdx + 1) % n;
    else if (k === 'a') this._blocklistAdd();
    else if (k === 'd' && n) this._blocklistDelete(this.blockIdx);
    else if (k === 'esc' || k === 'q') { this.mode = 'settings'; this.setIdx = 0; }
  }

  _blocklistAdd(): void {
    this.mode = 'input';
    this.inputReturn = 'blocklist';
    this.inputPrompt = 'Block model glob (e.g. *fable*)';
    this.inputBuf = '';
    this.inputCb = v => this._doBlocklistAdd((v || '').trim());
  }

  async _doBlocklistAdd(pat: string): Promise<void> {
    if (!pat) { this._addLog('Blocklist add cancelled'); return; }
    this.config.blockedModels = this.config.blockedModels || [];
    if (this.config.blockedModels.includes(pat)) { this._addLog(`"${pat}" already blocked`); return; }
    this.config.blockedModels.push(pat);
    this.blockIdx = this.config.blockedModels.length - 1;
    try { await this.saveConfig(this.config); this._addLog(`Blocked model "${pat}"`); }
    catch (e: any) { this._addLog(`Failed to save: ${e.message}`); }
    if (this.running) this.render();
  }

  async _blocklistDelete(idx: number): Promise<void> {
    const list = this.config.blockedModels || [];
    const pat = list[idx];
    if (pat == null) return;
    list.splice(idx, 1);
    this.blockIdx = Math.max(0, Math.min(idx, list.length - 1));
    try { await this.saveConfig(this.config); this._addLog(`Unblocked "${pat}"`); }
    catch (e: any) { this._addLog(`Failed to save: ${e.message}`); }
    if (this.running) this.render();
  }

  _renderBlocklist(lines: string[]): void {
    const list = this.config.blockedModels || [];
    lines.push('');
    lines.push(bold('  Blocked models') + dim('  — requests whose model matches a glob are rejected, not forwarded'));
    lines.push('');
    if (!list.length) {
      lines.push(gray('    Nothing blocked. Press [a] to add a glob (e.g. *fable*).'));
    } else {
      list.forEach((pat, i) => {
        const sel = i === this.blockIdx;
        const cursor = sel ? cyan('▸') : ' ';
        lines.push(`   ${cursor} ${red('✗')} ${sel ? bold(pat) : pat}`);
      });
    }
  }

  _renderRoutes(lines: string[]): void {
    const routes = this.config.routes || [];
    lines.push('');
    lines.push(bold('  Routes') + dim('  — pin model globs to specific accounts (first match wins)'));
    lines.push('');
    if (!routes.length) {
      lines.push(gray('    No routes configured. Press [a] to add one.'));
    } else {
      routes.forEach((r, i) => {
        const sel = i === this.routeIdx;
        const cursor = sel ? cyan('▸') : ' ';
        const match = (Array.isArray(r.match) ? r.match : [r.match]).join(', ');
        const accts = (r.accounts && r.accounts.length) ? r.accounts.join(' ') : dim('(all accounts)');
        const bucket = r.bucket ? dim(`  [${r.bucket}]`) : '';
        const name = rpad(r.name || '(unnamed)', 14);
        lines.push(`   ${cursor} ${sel ? bold(name) : name} ${cyan(rpad(match, 22))} ${dim('→')} ${accts}${bucket}`);
      });
    }
    const auto = this.accountManager.getRoutes().filter(r => r.autocreated);
    if (auto.length) {
      lines.push('');
      lines.push(dim('  Auto-detected (not saved):'));
      for (const r of auto) {
        lines.push(dim(`     ${r.match.join(', ')} → ${r.accounts.map(a => a.name).join(' ')}`));
      }
    }
  }

  _renderFooter(): string {
    switch (this.mode) {
      case 'normal':
        return this.remote
          ? ` ${bold('s')}witch  ${bold('R')}eload  ${bold('q')}uit`
          : ` ${bold('s')}witch  ${bold('d')}isable  ${bold('p')}robe quota  ${bold('R')}eload  ${bold('g')} settings  ${bold('q')}uit`;
      case 'settings':
        return ` ${dim('↑↓')} navigate  ${dim('←→')} change  ${bold('Enter')} edit  ${bold('Esc')} back`;
      case 'routes':
        return ` ${dim('↑↓')} select  ${bold('a')}dd  ${bold('e')}dit  ${bold('d')}elete  ${bold('Esc')} back`;
      case 'pick':
        return this.pick?.multi
          ? ` ${dim('↑↓')} move  ${bold('Space')} toggle  ${bold('Enter')} confirm  ${bold('Esc')} cancel`
          : ` ${dim('↑↓')} move  ${bold('Enter')} select  ${bold('Esc')} cancel`;
      case 'blocklist':
        return ` ${dim('↑↓')} select  ${bold('a')}dd  ${bold('d')}elete  ${bold('Esc')} back`;
      case 'select': {
        if (this.selAction === 'switch' && this.remote) {
          return ` ${dim('↑↓')} select  ${bold('Enter')} switch  ${bold('Esc')} cancel`;
        }
        if (this.selAction === 'switch') {
          const target = this.selRoute
            ? routeColorFn(this.selRoute.color)(`route ${this.selRoute.name}`)
            : 'default';
          return ` ${dim('↑↓')} select  ${dim('←→')} target: ${target}  ${bold('Enter')} pin  ${bold('Esc')} cancel`;
        }
        const act = this.selAction === 'toggle' ? 'enable/disable' : 'remove';
        return ` ${dim('↑↓')} select  ${bold('Enter')} ${act}  ${bold('Esc')} cancel`;
      }
      case 'add':
        return ` ${bold('i')}mport Claude Code  ${bold('k')} API key  ${bold('Esc')} cancel`;
      case 'input':
        return ` ${this.inputPrompt}: ${this.inputBuf}█`;
      default:
        return '';
    }
  }
}
