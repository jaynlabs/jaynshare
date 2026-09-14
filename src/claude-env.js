// encodeURIComponent leaves `( ) ' ! *` alone; these lines are eval'd unquoted by a shell.
export function encodePinComponent(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

// The shell `export` lines for `eval "$(jaynshare env)"`: the same environment
// `jaynshare run` gives claude. No ANTHROPIC_API_KEY — it would drop Claude Code
// out of subscription mode.
export function buildClaudeEnvLines({ port, useMitm = true, caPath = null, holdSeconds = 0, account = null, proxyApiKey = '' }) {
  const lines = [];
  const pin = (account || '').trim();

  if (useMitm) {
    const userinfo = pin ? `${encodePinComponent(pin)}:${encodePinComponent(proxyApiKey || '')}@` : '';
    const proxyUrl = `http://${userinfo}127.0.0.1:${port}`;
    lines.push(
      `export HTTPS_PROXY=${proxyUrl}`,
      `export HTTP_PROXY=${proxyUrl}`,
      `export https_proxy=${proxyUrl}`,
      `export http_proxy=${proxyUrl}`,
      'export NO_PROXY=localhost,127.0.0.1,::1',
      'export no_proxy=localhost,127.0.0.1,::1',
    );
    if (caPath) lines.push(`export NODE_EXTRA_CA_CERTS=${caPath}`);
    lines.push('unset ANTHROPIC_BASE_URL'); // the two modes must not stack in one shell
  } else {
    const prefix = pin ? `/jaynshare-account/${encodePinComponent(pin)}` : '';
    lines.push(`export ANTHROPIC_BASE_URL=http://localhost:${port}${prefix}`);
  }

  if (pin) lines.push('unset JAYNSHARE_ACCOUNT'); // carried by the routing now; keep it out of the child

  const holdMs = (holdSeconds || 0) * 1000;
  if (holdMs > 0) lines.push(`export API_TIMEOUT_MS=${holdMs + 60_000}`); // outlive a proxy hold

  return lines;
}
