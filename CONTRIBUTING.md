# Contributing

Thanks for taking a look. Jaynshare is a small Node project with no runtime npm
dependencies; contributing to it should be correspondingly simple.

## Before you start

- Read [compliance.md](docs/compliance.md). It covers the terms-of-service
  question that sits underneath this whole project.
- For anything larger than a bug fix, open an issue first. It is cheaper to
  agree on an approach than to review a large change built on the wrong one.
- Vulnerabilities do **not** go in issues or pull requests — see
  [SECURITY.md](SECURITY.md).

## Setting up

Node.js 26 or newer. `npm install` fetches the development toolchain; the
application itself has no runtime npm dependencies.

```sh
npm install
npm test          # the full suite
npm run lint
```

The Windows client has its own end-to-end check, which installs into a throwaway
profile and needs no server or credential:

```sh
bash test-support/client-install-check.sh
```

On native Windows (Git Bash) that script is the only suite that runs — `npm test`
spawns `/bin/sh` and asserts POSIX mode bits.

Nix users can also run `nix flake check` and `nix run .#jaynshare -- help`.

## What CI requires

`.github/workflows/ci.yml` runs the test suite and ESLint on Node 26, the client
install check on `windows-latest`, and the Nix flake check. The
aggregate `test` job is the single required status. Please make sure the suite
and lint pass locally before opening a pull request.

## House style

- Match the surrounding code. The core codebase is strict TypeScript executed
  with Node's native type stripping, with no framework or transpile step.
- Every behavioral change needs a test. The suite is `node --test` with no
  helpers library — look at a neighbouring file in `test/` for the shape.
- Comments explain *why*, not *what*. Several existing comments record a
  constraint that is not obvious from the code (Git Bash path spellings, NTFS
  ACLs, CRLF handling); that is the bar.
- **Never commit a real secret, token, account state, machine address,
  hostname or transcript.** Tests use `example.com` addresses and obviously
  synthetic fixtures; keep it that way. `.gitignore` covers the runtime state
  files and the `onboarding/` bundle directory, but it is not a substitute for
  checking your own diff.

## Commits and pull requests

Write commit messages that say why the change is needed, not just what changed.
Keep unrelated changes in separate commits — a formatting sweep bundled with a
behavior change is hard to review and harder to revert.

## License

By contributing you agree that your contributions are licensed under the MIT
License, the same terms as the rest of the project. See [LICENSE](LICENSE).
