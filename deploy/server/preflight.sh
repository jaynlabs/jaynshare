#!/bin/sh
set -u

failures=0
ok() { printf 'ok   %s\n' "$*"; }
warn() { printf 'warn %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*" >&2; failures=$((failures + 1)); }

config_path=${JAYNSHARE_CONFIG:-"$HOME/.config/jaynshare.json"}
ca_path=${JAYNSHARE_CA_FILE:-"$HOME/.config/jaynshare-ca.pem"}

printf '%s\n' 'Jaynshare beta server preflight'

if [ "$(uname -s 2>/dev/null)" = Linux ]; then ok 'Linux host'; else fail 'server must run on Linux'; fi

if command -v node >/dev/null 2>&1; then
  node_major=$(node -e 'process.stdout.write(process.versions.node.split(".")[0])' 2>/dev/null || printf 0)
  if [ "$node_major" -ge 26 ]; then ok "Node.js $(node --version)"; else fail 'Node.js 26+ is required'; fi
else
  fail 'Node.js is missing'
fi

if [ -r "$config_path" ]; then
  ok "config is readable: $config_path"
  config_summary=$(node -e '
    const fs = require("fs");
    const c = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const host = c.proxy?.host || "";
    const match = /^100\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (!match || Number(match[1]) < 64 || Number(match[1]) > 127
        || Number(match[2]) > 255 || Number(match[3]) > 255) {
      throw new Error("proxy.host must be a Tailscale IPv4 address (100.64.0.0/10)");
    }
    const port = Number(c.proxy?.port || 3456);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("proxy.port is invalid");
    if (!Array.isArray(c.proxy?.clients)) throw new Error("proxy.clients must be an array");
    if (c.proxy.apiKey) throw new Error("migrate the legacy plaintext proxy.apiKey before beta access");
    if (!Array.isArray(c.accounts) || !c.accounts.length) throw new Error("at least one upstream account is required");
    if (c.autoUpdate !== false) throw new Error("autoUpdate must be false on the beta server");
    if (c.eventLogging !== "block") throw new Error("eventLogging must be block on the beta server");
    if (c.logDir) throw new Error("body-level logDir must be disabled");
    if (!c.auditLog?.path) throw new Error("auditLog.path is required");
    process.stdout.write([host, port, c.accounts.length, c.proxy.clients.length, c.auditLog.path].join("\t"));
  ' "$config_path" 2>&1) || {
    fail "invalid server config: $config_summary"
    config_summary=''
  }
else
  fail "cannot read config: $config_path"
  config_summary=''
fi

proxy_host=''
proxy_port=''
account_count=0
client_count=0
audit_path=''
if [ -n "$config_summary" ]; then
  proxy_host=$(printf '%s' "$config_summary" | cut -f1)
  proxy_port=$(printf '%s' "$config_summary" | cut -f2)
  account_count=$(printf '%s' "$config_summary" | cut -f3)
  client_count=$(printf '%s' "$config_summary" | cut -f4)
  audit_path=$(printf '%s' "$config_summary" | cut -f5)
  ok "config: $account_count upstream account(s), $client_count client(s), $proxy_host:$proxy_port"
  [ "$account_count" -ge 2 ] || warn 'only one upstream account is configured; fine for testing, but there is no failover'
fi

if command -v stat >/dev/null 2>&1 && [ -e "$config_path" ]; then
  config_mode=$(stat -c '%a' "$config_path" 2>/dev/null || printf unknown)
  if [ "$config_mode" = 600 ]; then ok 'config permissions are 0600'; else fail "config permissions are $config_mode, expected 600"; fi
fi

if [ -n "$audit_path" ]; then
  audit_dir=$(dirname -- "$audit_path")
  if [ -d "$audit_dir" ] && [ -w "$audit_dir" ]; then ok "audit directory is writable: $audit_dir"; else fail "audit directory is not writable: $audit_dir"; fi
fi

if [ -r "$ca_path" ] && grep -q 'BEGIN CERTIFICATE' "$ca_path"; then
  ok "public CA is ready: $ca_path"
else
  fail "public CA is missing or invalid: $ca_path"
fi

if command -v tailscale >/dev/null 2>&1; then
  tail_ip=$(tailscale ip -4 2>/dev/null | sed -n '1p')
  if [ -n "$proxy_host" ] && [ "$tail_ip" = "$proxy_host" ]; then
    ok "Tailscale is connected as $tail_ip"
  elif [ -n "$tail_ip" ]; then
    fail "config binds $proxy_host but this machine's Tailscale IPv4 is $tail_ip"
  else
    fail 'Tailscale is installed but not connected'
  fi
else
  fail 'Tailscale CLI is missing'
fi

if command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet jaynshare.service 2>/dev/null; then
  ok 'jaynshare.service is active'
else
  fail 'jaynshare.service is not active'
fi

if [ -n "$proxy_host" ] && [ -n "$proxy_port" ] && command -v node >/dev/null 2>&1; then
  live_summary=$(node -e '
    (async () => {
      const [host, port] = process.argv.slice(1);
      const response = await fetch(`http://${host}:${port}/jaynshare/status`, {
        signal: AbortSignal.timeout(2500),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const status = await response.json();
      if (!Array.isArray(status.accounts)) throw new Error("invalid status response");
      process.stdout.write(`${status.accounts.length} account(s) visible`);
    })().catch(error => {
      process.stderr.write(error.message);
      process.exit(1);
    });
  ' "$proxy_host" "$proxy_port" 2>&1) && ok "live proxy answered: $live_summary" || fail "live proxy check failed: $live_summary"
fi

if [ "$failures" -eq 0 ]; then
  printf '%s\n' 'READY — the server can issue tester bundles.'
  exit 0
fi

printf '%s\n' "NOT READY — $failures check(s) failed." >&2
exit 1
