import { findFamilyBlock, modelGlobOverlaps } from './model.ts';
import type { Dict } from './types.ts';

const ESC = '\x1b[';
const RESET = `${ESC}0m`;

export function renderStatus(status: Dict, { color = process.stdout.isTTY, now = Date.now() }: { color?: boolean; now?: number } = {}): string {
  const probe = status.probe || { enabled: false, intervalSeconds: 0, accounts: [] };
  const warm = status.warm || { enabled: false, intervalSeconds: 0, accounts: [] };
  const blocked = (status.blockedModels || []).filter((p: unknown) => typeof p === 'string' && p.length) as string[];
  // One render's ambient state, so a formatter takes only what it formats.
  const view = { paint: colors(color), now, probe, blocked, threshold: status.switchThreshold };
  const { paint } = view;
  const lines: string[] = [];

  lines.push(paint.bold(paint.yellow('◆ JAYNSHARE status')));
  lines.push(`${paint.dim('Active'.padEnd(12))} ${paint.cyan(status.currentAccount || 'none')}`);
  lines.push(`${paint.dim('Switch at'.padEnd(12))} ${formatPercent(status.switchThreshold)}`);
  if (blocked.length) {
    lines.push(`${paint.dim('Blocked'.padEnd(12))} ${paint.red(blocked.join(', '))}`);
  }
  if (status.sessions) {
    lines.push(`${paint.dim('Sessions'.padEnd(12))} ${formatSessions(status.sessions, paint)}`);
  }
  lines.push(`${paint.dim('Probe'.padEnd(12))} ${formatProbeSummary(probe, view)}`);
  if (warm.enabled) {
    lines.push(`${paint.dim('Keep-warm'.padEnd(12))} ${formatProbeSummary(warm, view)}`);
  }
  if (status.server?.startedAt || status.server?.uptimeSeconds != null) {
    lines.push(`${paint.dim('Server'.padEnd(12))} ${formatServerSummary(status.server, now)}`);
  }
  lines.push('');

  for (const line of routingLines(status.routes, view)) lines.push(line);

  for (const account of status.accounts || []) {
    lines.push(renderAccountHeader(account, status.currentAccount, view));
    for (const quotaLine of quotaLines(account, view)) {
      lines.push(`  ${quotaLine}`);
    }
    const routing = modelRoutingLine(account, view);
    if (routing) lines.push(`  ${routing}`);
    lines.push(`  ${paint.dim('Usage'.padEnd(8))} ${formatUsage(account.usage, now)}`);
    lines.push(`  ${paint.dim('Probe'.padEnd(8))} ${formatAccountProbe(account.name, view)}`);
    lines.push('');
  }

  return lines.join('\n').trimEnd();
}

interface Paint {
  rgb(r: number, g: number, b: number, value: string): string;
  bold(value: string): string;
  dim(value: string): string;
  gray(value: string): string;
  green(value: string): string;
  yellow(value: string): string;
  red(value: string): string;
  blue(value: string): string;
  magenta(value: string): string;
  cyan(value: string): string;
}

function colors(enabled: boolean): Paint {
  const wrap = (code: number) => (value: string) => enabled ? `${ESC}${code}m${value}${RESET}` : String(value);
  return {
    rgb: (r, g, b, value) => enabled ? `${ESC}38;2;${r};${g};${b}m${value}${RESET}` : String(value),
    bold: wrap(1),
    dim: wrap(2),
    gray: wrap(90),
    green: wrap(32),
    yellow: wrap(33),
    red: wrap(31),
    blue: wrap(34),
    magenta: wrap(35),
    cyan: wrap(36),
  };
}

const ROUTE_COLORS = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan'];
function paintRoute(paint: Paint, color: unknown, value: string): string {
  const name = String(color || '').toLowerCase();
  const fn = (ROUTE_COLORS.indexOf(name) >= 0)
    ? (paint as any)[name] as (s: string) => string
    : paint.cyan;
  return fn(value);
}

function routingLines(routes: Dict[] | undefined, { paint, blocked }: { paint: Paint; blocked: string[] }): string[] {
  if (!Array.isArray(routes) || routes.length === 0) return [];
  const lines: string[] = [paint.bold('Routing')];
  for (const route of routes) {
    const globs: string[] = route.match || [];
    const match = globs.join(', ');
    const routeBlocked = globs.length > 0
      && globs.every(g => blocked.some(p => modelGlobOverlaps(p, g)));
    const accounts = routeBlocked
      ? paint.red('blocked')
      : (route.accounts || [])
        .map((a: Dict) => (a.eligible ? paint.green(a.name) : paint.red(a.name))).join(' ') || paint.gray('(none)');
    const tag = route.autocreated ? paint.dim(' (auto)') : route.bucket ? paint.dim(` [${route.bucket}]`) : '';
    const pin = route.pinned ? paint.dim(` [pinned: ${route.pinned}]`) : '';
    const label = paintRoute(paint, route.color, match.padEnd(16)); // pad before painting
    lines.push(`  ${label} ${paint.dim('→')} ${accounts}${tag}${pin}`);
  }
  lines.push('');
  return lines;
}

function renderAccountHeader(account: Dict, currentAccount: string, view: { paint: Paint; now: number }): string {
  const { paint } = view;
  const current = account.name === currentAccount;
  const marker = current ? paint.cyan('>') : ' ';
  const name = current ? paint.bold(account.name) : account.name;
  const status = formatAccountStatus(account, view);
  const org = account.orgName ? ` ${paint.dim(account.orgName)}` : '';
  const sess = account.sessions ? ` ${paint.dim(`${account.sessions} sess`)}` : '';
  return `${marker} ${name} ${paint.dim(`(${account.type}, prio ${account.priority || 0})`)} ${status}${org}${sess}`;
}

function formatSessions(sessions: Dict, paint: Paint): string {
  const active = sessions.active || 0;
  const known = sessions.known || 0;
  const mode = sessions.distribute ? paint.green('distributing') : paint.dim('single-account');
  return `${active} active / ${known} known ${paint.dim('·')} ${mode}`;
}

function formatAccountStatus(account: Dict, { paint, now }: { paint: Paint; now: number }): string {
  const parts: string[] = [];
  if (account.disabled) parts.push(paint.gray('disabled'));

  const status = account.status || 'unknown';
  const colored = status === 'active'
    ? paint.green(status)
    : status === 'throttled'
      ? paint.yellow(status)
      : status === 'error' || status === 'exhausted'
        ? paint.red(status)
        : status;
  parts.push(colored);

  const throttleAt = parseTs(account.rateLimitedUntil);
  if (throttleAt && throttleAt > now) {
    parts.push(`throttle ${formatDuration(throttleAt - now)}`);
  }

  return parts.join(' / ');
}

// Per-family eligibility, for accounts whose Sonnet or Fable weekly bucket is metered separately.
function modelRoutingLine(account: Dict, { paint, now, blocked, threshold }: { paint: Paint; now: number; blocked: string[]; threshold: number }): string | null {
  const quota = account.quota || {};
  if (quota.unified7dSonnet == null && quota.unified7dFable == null) return null;
  const t = Number(threshold);
  const fiveOver = quota.unified5h != null && !Number.isNaN(t) && quota.unified5h >= t;

  const cell = (label: string, weekly: number | null, reset: unknown): string => {
    if (findFamilyBlock(blocked, label)) { // the blocklist outranks quota headroom
      return `${label} ${paint.red('⊘')}${paint.dim(' blocked')}`;
    }
    const weeklyOver = weekly != null && !Number.isNaN(t) && weekly >= t;
    const mark = fiveOver || weeklyOver ? paint.red('✗') : paint.green('✓');
    const resetTs = parseTs(reset);
    const when = weeklyOver && resetTs && resetTs > now ? paint.dim(` ${formatDuration(resetTs - now)}`) : '';
    return `${label} ${mark}${when}`;
  };

  const cells = [cell('Opus', quota.unified7d, quota.unified7dReset)];
  if (quota.unified7dSonnet != null) cells.push(cell('Sonnet', quota.unified7dSonnet, quota.unified7dSonnetReset));
  if (quota.unified7dFable != null) cells.push(cell('Fable', quota.unified7dFable, quota.unified7dFableReset));
  return `${paint.dim('Models'.padEnd(8))} ${cells.join('   ')}`;
}

function quotaLines(account: Dict, view: { paint: Paint; now: number }): string[] {
  const quota = account.quota || {};
  const line = (label: string, ratio: unknown, resetAt: unknown) => formatQuotaLine({ label, ratio, resetAt }, view);
  const lines: string[] = [];

  if (quota.unified5h != null || quota.unified7d != null || quota.unified7dSonnet != null || quota.unified7dFable != null) {
    lines.push(line('Session', quota.unified5h, quota.unified5hReset));
    lines.push(line('Weekly', quota.unified7d, quota.unified7dReset));
    if (quota.unified7dSonnet != null) {
      lines.push(line('Sonnet', quota.unified7dSonnet, quota.unified7dSonnetReset));
    }
    if (quota.unified7dFable != null) {
      lines.push(line('Fable', quota.unified7dFable, quota.unified7dFableReset));
    }
    return lines;
  }

  if (quota.tokensLimit != null && quota.tokensRemaining != null) {
    lines.push(line('Tokens', 1 - quota.tokensRemaining / quota.tokensLimit, quota.resetsAt));
  }
  if (quota.requestsLimit != null && quota.requestsRemaining != null) {
    lines.push(line('Requests', 1 - quota.requestsRemaining / quota.requestsLimit, quota.resetsAt));
  }
  if (lines.length === 0) lines.push(`${view.paint.dim('Quota'.padEnd(8))} ${view.paint.gray('unknown')}`);
  return lines;
}

function formatQuotaLine({ label, ratio, resetAt }: { label: string; ratio: unknown; resetAt: unknown }, { paint, now }: { paint: Paint; now: number }): string {
  const resetTs = parseTs(resetAt);
  const reset = resetTs && resetTs > now ? ` reset ${formatDuration(resetTs - now)}` : '';
  return `${paint.dim(label.padEnd(8))} ${usageBar(ratio, paint)} ${formatPercent(ratio)}${reset}`;
}

function usageBar(ratio: unknown, paint: Paint): string {
  if (ratio == null || Number.isNaN(Number(ratio))) return `[${paint.gray('??????????????????')}]`;
  const width = 18;
  const safeRatio = Math.max(0, Math.min(1, Number(ratio)));
  const full = Math.round(safeRatio * width);
  const fill = Array.from({ length: full }, (_, i) => {
    const [r, g, b] = gradientColor(i, width);
    return paint.rgb(r, g, b, '█');
  }).join('');
  return `[${fill}${paint.gray('░'.repeat(width - full))}]`;
}

function gradientColor(index: number, width: number): [number, number, number] {
  const t = width <= 1 ? 1 : index / (width - 1);
  const from = t < 0.5 ? [35, 209, 96] : [245, 185, 40];
  const to = t < 0.5 ? [245, 185, 40] : [239, 68, 68];
  const p = t < 0.5 ? t * 2 : (t - 0.5) * 2;
  return from.map((value, i) => Math.round(value + (to[i]! - value) * p)) as [number, number, number];
}

function formatProbeSummary(probe: Dict, { paint, now }: { paint: Paint; now: number }): string {
  if (!probe.enabled) return paint.gray('off (passive only)');
  const bits: string[] = [`on every ${formatDuration((probe.intervalSeconds || 0) * 1000)}`];
  if (probe.running) bits.push(paint.yellow('running'));
  const last = parseTs(probe.lastRunFinishedAt);
  if (last) bits.push(`last ${formatAgo(last, now)}`);
  const next = parseTs(probe.nextRunAt);
  if (next && next > now) bits.push(`next ${formatDuration(next - now)}`);
  return bits.join(', ');
}

function formatAccountProbe(accountName: string, { paint, now, probe }: { paint: Paint; now: number; probe: Dict }): string {
  const row = (probe.accounts || []).find((account: Dict) => account.name === accountName);
  if (!probe.enabled) return paint.gray('off');
  if (!row) return paint.gray('never');
  if (row.status === 'not-applicable') return paint.gray('not applicable');
  const status = row.status === 'ok'
    ? paint.green('ok')
    : row.status === 'running'
      ? paint.yellow('running')
      : row.status === 'never'
        ? paint.gray('never')
        : paint.red(row.status || 'error');
  const last = parseTs(row.lastProbedAt || row.startedAt);
  const when = last ? ` ${formatAgo(last, now)}` : '';
  const duration = typeof row.durationMs === 'number' ? `, ${Math.round(row.durationMs)}ms` : '';
  const error = row.error ? `, ${safeLine(row.error)}` : '';
  return `${status}${when}${duration}${error}`;
}

function safeLine(value: unknown): string {
  return String(value).replace(/\x1b\[[0-?]*[ -/]*[@-~]|\p{C}/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, 120);
}

function formatUsage(usage: Dict = {}, now: number = Date.now()): string {
  const requests = usage.totalRequests || 0;
  const tokens = (usage.totalInputTokens || 0) + (usage.totalOutputTokens || 0);
  const last = parseTs(usage.lastUsed);
  const lastText = last ? `, last ${formatAgo(last, now)}` : '';
  return `${requests} req, ${formatNumber(tokens)} tok${lastText}`;
}

function formatServerSummary(server: Dict, now: number): string {
  if (server.uptimeSeconds != null) return `up ${formatDuration(server.uptimeSeconds * 1000)}`;
  const started = parseTs(server.startedAt);
  return started ? `up ${formatDuration(now - started)}` : 'unknown';
}

function formatPercent(value: unknown): string {
  if (value == null || Number.isNaN(Number(value))) return '-';
  return `${Math.round(Number(value) * 100)}%`;
}

function formatNumber(value: unknown): string {
  const num = Number(value) || 0;
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}m`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}k`;
  return String(num);
}

function formatAgo(timestamp: number, now: number): string {
  const delta = now - timestamp;
  if (delta < 0) return `in ${formatDuration(-delta)}`;
  return `${formatDuration(delta)} ago`;
}

function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '-';
  const totalSeconds = Math.max(1, Math.round(ms / 1000));
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const totalMinutes = Math.ceil(totalSeconds / 60);
  if (totalMinutes < 60) return `${totalMinutes}m`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours < 24) return minutes ? `${hours}h${minutes}m` : `${hours}h`;
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours ? `${days}d${remHours}h` : `${days}d`;
}

function parseTs(value: unknown): number | null {
  if (value == null) return null;
  if (typeof value === 'number') return value;
  const parsed = Date.parse(String(value));
  return Number.isNaN(parsed) ? null : parsed;
}
