# Claude Desktop details

`jaynshare desktop` and its setup are in the [README](../README.md#claude-desktop-on-macos).
This page covers how the connection works, its limits and recovery.

## How it connects

The integration selects a named **Jaynshare** Gateway in Desktop's separate
`Claude-3p` profile. Desktop receives a fresh local bearer, while the client
uses your enrollment and server identity pin internally. Desktop's native
`egressProxyUrl` points at the same loopback listener; the relay adds the proxy
credential only on its connection to the server. Setup leaves the system proxy
untouched and installs a missing pool CA in your login keychain only after
confirmation; the [MITM scope](security-and-privacy.md#mitm-scope) covers the CA.

Desktop lists the models the pool's accounts offer through `/v1/models`, and
the upstream refuses those an account cannot use. The managed engine's token
counts use the same pool transport as inference; Desktop can issue many
independent counts for its context breakdown. Connection warming is answered
locally. On first startup, Desktop's managed runtime downloads through the
proxy, and the connection test waits until that runtime is verified.

## Compatibility check

The check runs once per launch: before profile setup when the runtime is
already there, otherwise after Desktop provisions it and before any inference
is forwarded. It verifies the engine's protocol, not Desktop's interface: the
native app blocks remote debugging and custom test profiles, so the check
cannot drive it. Desktop 2.31226.0 with Claude Code 2.1.293 is the last
version whose profile and startup contracts were inspected.

## Network

Public catalogs, signatures and runtime downloads at `downloads.claude.ai` use
an anonymous streaming server route that keeps cache and range behavior.
WebFetch domain checks receive the real upstream response without a pool
credential; other page requests use opaque tunnels. The relay has no direct
fallback when the server is unavailable. Not every Desktop process is
guaranteed to use the Gateway or the proxy; a strict guarantee requires an OS
egress policy.

## Request logs

Each request line names its operation: `inference`, `count_tokens` for relayed
token counts and `models` for model listings. Token counts outside the managed
engine and `title_fallback` get a local `501` with `x-should-retry: false`.
`unsupported_direct` marks a request that needs a compatibility update. These
labels contain no prompts, session identifiers or credentials.

## Setup, upgrade and restore

One jaynshare installation at a time sets up Desktop; restore the other one
first, the quickstart's with `bash quickstart.sh down`.

A profile set up by an earlier release is upgraded at the next setup; stop the
command and quit Desktop fully first. An interrupted setup can be retried or
restored. The recorded loopback port is reused: if another process holds it,
stop that process, or restore while Desktop is closed and set up again.

Restore and client uninstall remove the local credential and the Jaynshare
entry, restore the selection fields only while they still match the installed
values, and keep other Gateways, preferences and conversation history.
