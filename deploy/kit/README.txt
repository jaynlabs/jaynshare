Jaynshare client kit

This archive is the client half of a Jaynshare release: the client
executable for each supported platform. `jaynshare join` fetches it from
your pool's server and installs the one for this machine; you never use
the kit directly.

Prerequisite: Claude Code must already be installed on this machine; the
pool serves Claude Code; it never installs it or replaces your own login.

To join a pool, run the line your operator sends you:

  jaynshare join jsi1_...

The invite works once and expires. It names the server, the identity that
server must present and the key its client is signed with, so the join
refuses any other server and any other client.

Members:
  release.json, release.json.minisig, SHA256SUMS   the signed release set
  payload/<platform>/jaynshare[.exe]              the client executable

Using the pool

Once enrolled, run `jaynshare claude` wherever you would have run Claude
Code. It starts a picker when the pool cannot choose for you: pick the
account to serve this session and it is remembered for it. Pass
`--account <name>` to name the account yourself, or `--auto` to let the
pool pick without asking. `--direct` runs outside the pool entirely,
under your own login instead of a pool account.

`jaynshare status` shows this machine's enrollment and connection state.
If you want plain `claude` to keep working, `jaynshare alias` makes it
run the pool client.

A private address never provides encryption. If the base URL is
plain HTTP, the client secret and request content travel in clear on the
private network (the CONNECT proxy exposes its proxy credential there);
your operator mitigates this with TLS on the base URL's listener and by
keeping the pool's network segmented.

What does not work through the pool

Claude Code's Remote Control and other account-bound features do not
work through the pool, in either mode. A warning about connectors at
startup is expected: it means the pool's gateway credential is in use,
not that something is broken. Your own Claude login is never used, read
or relayed by the pool; only the enrolled client identity travels.

If a prompt fails with a proxy-tunnel error

Claude Code reports a revoked credential as a proxy-tunnel error. After
a revocation, run `jaynshare status`: it names the enrollment state and
tells you whether this machine is still enrolled.

What the server records

For every request the server writes one audit record, with these fields
by name:

  timestamp, duration_ms, principal (your client id),
  source_address (the address your request came from), session_id,
  method, path (without the query string), model, serving_account,
  no_service_reason, selection_cause, status, attempts, failed_over,
  error_class, pinned, mode, blocked_pattern.

The record never contains a credential, and never a request or response
body. The source address is recorded as described above.

Wire capture

Request and response bodies are recorded only while wire capture is on.
`jaynshare status` and the status line always show whether wire capture
is currently on.
