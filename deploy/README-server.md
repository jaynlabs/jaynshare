# Jaynshare server installation

Operator trust: every account on this host that can reach
the server process's loopback listener or control the jaynshare systemd
unit is trusted as the operator. That group must hold no untrusted user.

Decision record: pooling an account requires your dated
decision record, kept somewhere you own: the account's kind and plan as its
owner reports it, who decided that pooling it is permitted, and when.

Read these statements before you run `install.sh` or `server install`.
They are operator obligations that no command carries out for you.

## Install

```sh
curl -fsSL https://github.com/jaynlabs/jaynshare/releases/latest/download/install.sh | sudo sh
```

`install.sh` checks the archive for this host against the release's
`SHA256SUMS`, then runs `jaynshare server install`, which:

1. downloads the release set and verifies its signature;
2. creates the `jaynshare` service account;
3. writes `/var/lib/jaynshare/.config/jaynshare/config.toml` when there is
   none: the data plane on this host's Tailscale address, else on its only
   private IPv4 address, else on the one you type, with identity TLS (below);
4. runs preflight against that configuration;
5. installs under `/opt/jaynshare`, links `/usr/local/bin/jaynshare`, starts
   the service and rolls back if it does not answer;
6. on a first install, prints an invite for you, named after `SUDO_USER`:
   `jaynshare join jsi1_…`.

`install.sh --version <version>` installs a given release. To choose the
address yourself, or to install a configuration you wrote (`jaynshare config
new` writes a scaffold), run `jaynshare server install` with `--listen <ip>` or
`--config <path>`. From a clone, `tools/install-server.sh` builds the checkout
as you and installs it with sudo, beside the official client kit of its
version; run it again after `git pull`.

Where preflight cannot inspect the host firewall, Tailscale's own rules
included, install asks you to record the interface and rule you checked by
hand (see Addresses and ingress).

## Clients

Operator commands run as the service account:

```sh
alias js='sudo -u jaynshare -H jaynshare'
js client invite bob --name "Bob"   # → jaynshare join jsi1_…
js client reissue bob               # a lost or expired invite
js client revoke bob
js status
```

An invite names the server's address, the identity it presents and the key
its client kit is signed with, so the join refuses any other server and any
other client. It works once and expires after
`clients.enrollment_lifetime_seconds` (a day by default; `--expires` sets it
per invite). Send it through a private channel.

The join offers to add each of the engineer's accounts, Claude and ChatGPT
alike, to the pool, owned by that client. With `--no-account` it doesn't, and that client can only log in
again the accounts it already owns. `js account login --name <name>` still
adds an account from the server.

## Update

Run `install.sh` again, or `sudo jaynshare server update`: the newest release
from where the install came from (the release host, a mirror, or the clone's
build). `--version <version>` and `--from <release-dir>` pick another one. A
failed update rolls back. Every client follows on its next `jaynshare claude`
or `jaynshare status`: it fetches the server's client kit, checks it against
its pinned signing key and replaces itself. A rollback is followed too.

`sudo jaynshare server auto-update on` updates every night, at 03:00 plus up
to an hour, through a systemd timer that catches up after downtime; `off`
removes it. It follows releases only, so it is refused on a clone's build. An
unattended update keeps the installed configuration, so it passes a firewall
preflight cannot inspect.

Update several servers from this machine, one host at a time; a host whose
update fails rolls itself back and the loop moves on:

```sh
for h in host1 host2 host3; do
  ssh "$h" 'sudo jaynshare server update --version <version> --yes'
done
```

## Identity TLS

The base-URL listener serves TLS on the server's own identity: a key
generated at first start as
`/var/lib/jaynshare/.local/state/jaynshare/server-identity-key.pem`, under a
self-signed certificate. Clients pin the key itself (`server.tls_pin` in
`js status`), received in the invite, so no CA is involved and the address can
change. Back the key up with the state: a new key strands every client until
it joins again.

`data_plane.tls` selects the transport:

- `"identity"`, what install writes;
- `"certificate"`, your own certificate in `data_plane.tls_certificate_file`
  and `data_plane.tls_private_key_file`. Its invites carry no pin; the join
  trusts the system store, or the CA file given with `--tls-ca`;
- `"off"`, plain HTTP. Nothing joins it.

Without the key, the certificate files decide, so a 2.0 configuration keeps
its transport. To move one from HTTP to identity TLS, set `tls = "identity"`
under `[data_plane]` and restart. Clients on 2.1 have already received the
pin from their status reads and move to `https` on their own.

## MITM CA rotation

`js ca rotate` stages the next CA. Clients fetch it on their next `status` or
launch and trust both; the proxy switches to it after seven days, or when the
current CA expires if that comes first. `js ca rotate --now` replaces the CA at
once, and each client picks it up on its next launch. An engineer who added
the CA to the system store with `jaynshare trust-ca add` runs it again after
the switch.

## Who is the operator

Every account able to reach the server process's loopback -- or to control
its systemd unit -- is trusted as the operator. That control group
therefore must have no untrusted user: an account that can connect to the
loopback service or stop the unit can read the pool's state. Do not share
any such account or shell with a user the pool does not fully trust.

Account pooling is a terms decision, not a technical one. Before an
account serves engineers, keep your own dated decision record: the
account's kind and plan as its owner reports it, who decided that pooling
it is permitted, and when. Re-read it before a material upgrade or a
change in who has access. No command asks for either statement; you
carry both obligations by reading this page and installing anyway.

## Addresses and ingress

A listener address must be loopback, IPv4 private (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`), IPv4 shared address space
(`100.64.0.0/10`) or IPv6 unique-local (`fc00::/7`). Preflight refuses
`0.0.0.0`, `::`, link-local, multicast and globally routable addresses,
even where a firewall appears to block them. The list is not
configurable.

For a non-loopback listener, filter ingress on that private interface --
or on its source range only. Preflight verifies that the published
address is assigned to this host and names the interface; check a rule
that admits traffic on it and nothing else. Opening the port globally
violates the private-listener rule and fails preflight. The installer never alters a
firewall: creating, changing or deleting firewall rules is operator work,
before or after the commands, never inside them.

## Clear text on the private network

The CONNECT proxy listener has no TLS of its own: its proxy credential
crosses the private network in clear, while the requests inside the tunnel
travel under the pool's CA. A base URL on plain HTTP also exposes the client
secret and every status read; keep it on TLS. Segment the private network
too: a private address never provides encryption.

## Deployment boundary

Host access is operator access. Whoever is root on the server host
reads the pool's state and enters the server's loopback trust zone, so
they must be the operator. Another tenant needs its own VM, and an
enrolled engineer never receives host access.
