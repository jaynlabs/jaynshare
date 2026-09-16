# Jaynshare

Jaynshare is a self-hosted, quota-aware router for Claude Code. It pools
multiple Claude accounts behind one private service, rotates away from
exhausted or unhealthy accounts, and lets enrolled macOS and Windows clients
see fleet availability without receiving the server's credentials.

> [!WARNING]
> You probably know that this is not accepted by Anthropic's TOS, that DOES NOT mean it's illegal. Please read the
> [subscription-sharing risk summary](is_this_safe.md) and
> [compliance notes](docs/compliance.md), obtain every account owner's consent,
> and never commit credentials, transcripts, or deployment details.

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
