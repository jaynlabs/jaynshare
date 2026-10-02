# Security and privacy model

Read this before sending source code, secrets, customer data, or other
confidential material through Jaynshare.

## The central trust decision

Jaynshare is a **trusted intermediary**. It is not end-to-end encrypted between
Claude Code and Anthropic:

```text
Claude Code  == TLS under the pool's CA ==>  Jaynshare  == verified TLS ==>  Anthropic
                                                 |
                                     plaintext requests and responses
```

`jaynshare claude` launches Claude Code with the pool's forward proxy and the
pool's CA. Claude Code's TLS session to `api.anthropic.com` ends at the
Jaynshare server, which then opens its own verified TLS connection to
Anthropic. The server must read request bodies to pick an account, inject that
account's credential, and buffer the request so it can retry it on another
account.

Consequently, the server operator — and anyone who compromises the host or the
deployed binary — can read prompts, code context, tool results, attachments,
and model responses. They can also alter a request or a response, including
injecting malicious instructions or code. Client authentication and TLS
protect the service from outsiders; they do not protect a client from the
server operator. No technical control makes an untrusted operator safe while
keeping this routing design.

The operator is whoever can reach the server's loopback listener or control its
systemd unit. See
[the server installation notes](../deploy/README-server.md).

## Who can see or influence what?

| Actor | Access and influence |
| --- | --- |
| Server operator | Can access provider credentials and all traffic the server handles, change the deployed binary or configuration, turn on wire capture, invite and revoke clients, and change routing. Must be fully trusted. |
| Enrolled client A | Sends and receives its own traffic. Can see the pool metadata listed below, can pick an eligible account for its own session, and can log in the Claude accounts it owns. Cannot use its credential to read client B's prompts, responses or sessions, to log in client B's accounts, or to call the operator surface. |
| Other account owners | Do not receive request bodies through Jaynshare, but their provider account may carry another participant's request. That usage falls under that account's provider terms and settings. |
| Anthropic | Receives the content routed to it under the selected account. Its own terms, retention and privacy controls apply. |
| Network peer without a Jaynshare credential | Is refused by the proxy and the control surface. Network exposure should still be restricted with network policy and host firewall rules. |

An enrolled client's status read is an explicit allow-list. It exposes each
account's display name and its five-hour and weekly utilisation, how many
accounts are configured and selectable, how many sessions are known and
active, the server version and identity pin, the CA fingerprint and that of a
staged next CA, the version and digests of the client the server offers,
whether wire capture is on, and, for the client's own session, the account
that last served it. It does
**not** expose provider credentials, per-account identity or routes, the
configuration, other clients, other clients' sessions, or any request or
response body.

Sessions are keyed by the authenticated client together with Claude Code's
session id, so the same session id on two enrolled machines does not share
routing state. A response is returned only on the connection that made the
request; no endpoint lets one client retrieve another client's response.

This isolates content, not resources or risk. All clients consume shared quota;
their activity changes which account stays available and can contribute to
provider rate limits, suspension or termination affecting everyone. An
operator can also move the pool's default account. Do not put people in one
pool who should not share those consequences.

## On the network

Listeners bind only to loopback or private addresses (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7`); installation
refuses anything else. A private address does not encrypt anything:

- The forward proxy authenticates each client with a proxy credential in the
  `CONNECT` request, which crosses the private network in clear. The request
  content inside the tunnel is protected by the TLS session under the pool's
  CA.
- The base-URL listener carries the join, the client's status reads and its
  kit downloads, authenticated by the client secret. It serves TLS on the
  server's identity, which clients pin, or on an operator certificate. Only
  a configuration kept from 2.0 can still leave it on plain HTTP, where the
  secret and everything the listener answers cross the private network in
  clear; no machine can join such a server.

Put the server on a network only its participants can reach, such as a
tailnet, and filter ingress to the listener ports.

## What a client pins

The invite carries two pins, and the join keeps both:

- **The server's identity:** `sha256/` and the digest of the key the server
  generated at its first start, which its base-URL certificate presents. The
  client checks that key on every connection instead of a name or a CA, so
  another host on the network is refused, even with a certificate the system
  trusts. A server on an operator certificate has no pin; its clients check
  that certificate against the system store or the CA file given at the join.
- **The release signing key:** the key the server's client kit is signed
  with, kept as the client's `release.pub`. The join installs a client only
  from a kit signed by it, and so does every later update when the client
  follows its server's version. A compromised server can still read and alter
  traffic, but it cannot make its clients run an executable that key did not
  sign.

The invite is therefore the root of trust: it travels once, through a private
channel, and the join that spends it refuses any server and any kit other than
the ones it names. Before it, `install.sh` and `install.ps1` download the first
executable over HTTPS from the release host and check it only against that
host's `SHA256SUMS`. That executable runs the join, which then installs the
client from the server's signed kit, or keeps the bootstrap's own executable
when the server offers no kit.

## Data handling and storage

- **In memory:** the server buffers each complete request body so it can retry
  it on another account. Responses are streamed. The process handles content
  in plaintext even when nothing is written to disk.
- **Provider credentials:** OAuth tokens and API keys live in the server's state
  file, written with mode `0600` under the dedicated service account. Clients
  receive neither the credentials nor the configuration.
- **Client credentials:** each client receives its own secret when it joins,
  with an invite that works once and expires. The server keeps only a SHA-256
  digest of the secret. Client secrets and the
  optional remote-operator secret are separate and can be rotated or revoked
  independently.
- **Secret files:** a secret read from a file must be its owner's alone: mode
  `0600` on Linux and macOS, and on Windows no access for anyone but you,
  SYSTEM and Administrators. A broader file is refused before it is read, as
  are the server's configuration, state, logs and keys at startup.
- **Audit log:** one record per exchange with metadata only: time, duration,
  client, source address, session id, method, path without its query, model,
  serving account, status, attempts, failover and error class. No body and no
  credential. Files are owner-only and rotate by size. This metadata can still
  be sensitive.
- **Wire capture:** off by default. When the operator turns it on, the server
  writes every exchange, bodies included, to a capture directory, with
  credentials replaced by a placeholder. Those files can contain source code,
  prompts, outputs and any secret present in a message: treat them as highly
  sensitive. Capture cannot run unnoticed: every enrolled client's status shows
  that it is on, and the audit log keeps running.
- **Telemetry:** `data_plane.telemetry_policy = "block"` stops Claude Code's
  event-logging requests at the server; the default, `forward`, relays them.
  This is not a content filter and says nothing about what Anthropic receives
  in ordinary model requests.

Jaynshare provides no per-client retention controls, no encryption of request
bodies from the operator, and no formal security certification. No independent
security audit is claimed.

## MITM scope

The pool's CA reaches clients over the pinned channel, the next one too while
a rotation is staged. It is handed only to the Claude Code process that
`jaynshare claude` launches, through `NODE_EXTRA_CA_CERTS`. It enters the operating
system's trust store only if the engineer runs `jaynshare trust-ca add`, which
always asks first. The server terminates TLS only for `api.anthropic.com` and
its own credential-free probe host; any other `CONNECT` target is relayed as
an opaque tunnel, and a target that points back at the server itself is
refused.

That narrow scope limits the effect of trusting the CA. It does not stop a
malicious server from changing traffic for the intercepted host. Releases and
kits are signed, and clients accept only kits signed by their pinned key;
verify what you install on the server (`jaynshare release verify`), and install
only from a source you trust.

## Safer deployment checklist

1. Run the server under its dedicated, unprivileged service account, on a host
   controlled by an operator every participant trusts.
2. Bind to a private address, restrict which people and devices can reach it,
   and never expose the listeners to the public internet.
3. Keep the base-URL listener on TLS, the server identity's or your own
   certificate, and back up the identity key with the server's state.
4. Give every person and device its own client, and send each invite through
   a private channel; invite with `--no-account` whoever should not add
   accounts. Never share the remote-operator secret; revoke the client and
   remove its network access when someone leaves.
5. Keep wire capture off. Define a retention and access policy for the audit
   log, and tell participants what is kept.
6. Update deliberately, from verified releases; rerun `jaynshare server
   preflight` after each change to the host. `server auto-update` installs
   every signed release unattended: leave it off if you review releases first.
7. Do not route material whose owner has not approved disclosure to the server
   operator, the serving account, and Anthropic. Keep unrelated production
   secrets out of prompts and repositories.
8. Where API-backed or organisation-managed credentials fit the use case,
   prefer them, and review the provider terms that apply.

Report suspected vulnerabilities privately as described in
[the security policy](../SECURITY.md).
