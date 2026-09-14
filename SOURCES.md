# Source provenance

Jaynshare is derived from [TeamClaude](https://github.com/KarpelesLab/teamclaude)
by KarpelesLab, imported as a squashed subtree and maintained here since. The
repository is self-contained: a fresh clone needs no submodule initialization.

| Imported revision | Upstream | License |
| --- | --- | --- |
| `3ca78adcef705ff90a181fcc637efb718af9758d` (based on upstream `1342e92b7207d5e3bb5af08402909810d7378019`) | `https://github.com/KarpelesLab/teamclaude.git` | MIT; TeamClaude © KarpelesLab, Jaynshare modifications © Jayn Labs (2026) |

The original MIT license and copyright notice are retained in
[LICENSE](LICENSE); attribution is in [NOTICE.md](NOTICE.md).

`cswap` (`https://github.com/dpemmons/cswap.git`, MIT, Dale Emmons 2026, derived
from Onur Cetinkol's `claude-swap`) was briefly vendored as a read-only design
reference. It was never imported into Jaynshare and does not ship here; recover
it from revision `a875d47440df701ade5f4421c2131423ad41da61` upstream.

## Syncing from upstream

A future upstream sync is a separate reviewed subtree-import task and must update
this file. Do not run `git pull` inside imported source or fetch package upgrades
as part of unrelated work.

Upstream's own `.github/workflows/ci.yml` is not carried here: it targeted the
`master` branch and the `teamclaude` flake attribute, neither of which exists in
this repository. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) replaces
it. Re-apply that deletion after any upstream sync.
