# Jaynshare

Share your claude subscriptions!

Jaynshare is a self-hosted, quota-aware router for Claude Code. It pools
multiple Claude accounts behind one private service, rotates away from
exhausted or unhealthy accounts, and lets enrolled macOS and Windows clients
see fleet availability without receiving the server's credentials.

> [!WARNING]
> Pooling Claude subscriptions conflicts with Anthropic's published terms and can
> lead to suspension or termination of every account involved, without a refund.
> Whether a particular deployment also raises legal issues depends on its facts
> and jurisdiction; this project does not claim that it is legal or authorized.
> Read the [subscription-sharing risk summary](is_this_safe.md),
> [security and privacy model](docs/security-and-privacy.md), and
> [compliance notes](docs/compliance.md) before deploying.

> [!IMPORTANT]
> Jaynshare is a trusted intermediary, not an end-to-end encrypted relay. The
> server receives prompts, code context, tool results, and model responses in
> plaintext so it can route and retry them. A server operator—or anyone who
> compromises the server—can read or alter that traffic. Only use a server whose
> operator and deployed code you trust.

## short demo

<img width="900" height="575" alt="demo-2" src="https://github.com/user-attachments/assets/e68a0565-4ff2-40c0-96ef-2ae2408603aa" />

## Highlights

- OAuth and API-key accounts with quota-aware failover
- Priority, per-model, and session-aware routing
- Interactive terminal UI plus headless operation
- Private client enrollment for macOS and native Windows
- Tailscale-oriented deployment, audit logging, and credential revocation
- Strict TypeScript with no runtime npm dependencies

## Requirements

- Node.js 26+
- Linux with systemd for the hosted server deployment
- Tailscale for remote client access
- Git Bash for Windows clients

## Quick start

For a local development instance:

```sh
git clone https://github.com/jaynlabs/jaynshare.git
cd jaynshare
npm install
node src/index.ts login --oauth --name primary
node src/index.ts server
```

In another terminal:

```sh
node src/index.ts run
```

The first command creates `~/.config/jaynshare.json`. Review it before use. For
a private multi-machine installation, follow the [deployment guide](docs/deployment.md).

## Documentation

- [Deployment and client enrollment](docs/deployment.md)
- [Security and privacy model](docs/security-and-privacy.md)
- [Usage and CLI reference](docs/usage.md)
- [Configuration](docs/configuration.md)
- [Accounts](docs/accounts.md)
- [Routing](docs/routing.md)
- [Quota behavior](docs/quota.md)
- [Proxy modes](docs/proxy-modes.md)
- [Windows client internals](docs/windows-client.md)
- [Nix](nix/README.md)

## Development

```sh
npm install
npm test
npm run lint
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report
security issues privately as described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
