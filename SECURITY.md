# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's **Security** tab on
this repository — *Report a vulnerability* — which opens a private advisory
visible only to the maintainers.

Please do not open a public issue, and do not include secrets, tokens, prompts,
audit records or infrastructure addresses in a report. A description of the
weakness and how to reach it is enough; we will ask if we need more.

## Supported versions

Jaynshare is developed on `main`. Fixes land there; there is no long-term
support branch for older releases.

## Installation integrity

The supported installation path is a reviewed commit of this repository, or its
matching release archive and SHA-256 checksum. The inherited npm updater is
disabled in the documented server deployment: production updates are deliberate,
reviewed imports followed by tests and a pinned release. Third-party archives
and automatic updates from unreviewed registry packages are not supported.

## If a credential is exposed

Jaynshare holds long-lived Claude credentials, so exposure has a defined
response:

- **Client secret** — rotate or revoke that client immediately and replace only
  the affected machine's secret. Other clients are unaffected.
- **Operator secret** — rotate the operator credential; it is the only one that
  can mutate server state.
- **OAuth credentials** — revoke the affected Claude session, remove the account
  from service, and enroll it again only once the host is trusted.

## Attribution

Jaynshare is derived from TeamClaude and retains its MIT license and
attribution; see [NOTICE.md](NOTICE.md).
