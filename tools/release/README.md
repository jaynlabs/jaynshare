# Release tooling

Builds one release set from given binaries:

- five platform archives (`.tar.gz`, windows `.zip`);
- the client kit;
- the canonical `release.json`, `SHA256SUMS` and `release.json.minisig`.

## In CI

`.github/workflows/release.yml` builds each target natively on its own runner, then packages the set with `build.py`:

- A `v*` tag signs with the `RELEASE_SEED` secret of the `release` environment, so each release waits for that environment's reviewer. The set is checked with `jaynshare release verify` against the embedded key, then published as a GitHub release.
- A manual run, or a pull request that touches the release inputs, is a dry run. It signs with a throwaway key, verifies the set against that key, and uploads it as the `release-set` workflow artifact. Nothing is published.

The tag must match the version in `Cargo.toml`, and a pre-release version makes a GitHub pre-release.

Setup, once per repository (a fork uses its own key):

1. Create the environment `release` (Settings → Environments), with yourself as required reviewer and `v*` tags as its only deployment refs.
2. Add the seed as its secret, base64-encoded: `base64 -i <seed file> | gh secret set RELEASE_SEED --env release`.
3. Commit the matching public key as `deploy/release-key.pub`.

## Locally

| File | Does |
|---|---|
| `build.py` | archives, kits, manifest, sums and signature from `--bin <target>=<path>` inputs |
| `build.py` | key rotation: `--next-key <seed>` adds `next_key_id` to `release.json` and writes `release.json.<id>.minisig` and `release-key-<id>.pub` beside the set; `release verify --key-id <id>` admits the next key |
| `cross.sh` | the five binaries: alpine musl ×2, macOS ×2 natively, `cargo xwin` for msvc (needs `cargo install --locked cargo-xwin`, `rustup component add llvm-tools` and the owner's acceptance of Microsoft's CRT/SDK license) — `tools/release/cross.sh --out <dir> [--target <triple>]... [--commit <40 hex>] [--allow-dirty]` |
| `publish.sh` | an off-CI release: validates the signing key path, builds all five targets, and creates the GitHub release with every release artifact |

The signing seed never enters the repository, the build workspace, an
artifact or a log. The tools read it from a path outside the repository
(`--key <seed>`). The public half is `deploy/release-key.pub`, which the
verifier embeds.
