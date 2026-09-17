# Security and privacy model

Read this before sending source code, secrets, customer data, or other
confidential material through Jaynshare.

## The central trust decision

Jaynshare is a **trusted intermediary**. It is not end-to-end encrypted between
Claude Code and Anthropic:

```text
Claude Code  == private-network transport ==>  Jaynshare  == verified TLS ==>  Anthropic
                                                  |
                                      plaintext requests and responses
```

The server must read request bodies to select a model/account, rewrite account
metadata, buffer a request for retry, and inject the selected account's
credential. In MITM mode it terminates TLS for the configured Anthropic host
with a Jaynshare CA, then opens and verifies a new TLS connection to Anthropic.
In base-URL mode Claude Code sends the request directly to Jaynshare. The
documented remote deployment relies on Tailscale to encrypt the client-to-server
network link.

Consequently, the server operator—and anyone who compromises the host or the
deployed Jaynshare code—can read prompts, code context, tool results,
attachments, and model responses. They can also alter a request or response,
including injecting malicious instructions or code. Client authentication and
TLS protect the service from outsiders; they do not protect a client from the
server operator. There is no technical control that can make an untrusted
Jaynshare operator safe while preserving the current routing design.

## Who can see or influence what?

| Actor | Access and influence |
| --- | --- |
| Server operator | Can access provider credentials and all traffic handled by the server, change the deployed code or configuration, enable body logging, revoke clients, and change routing. Must be fully trusted. |
| Enrolled client A | Sends and receives its own traffic. Can see the fleet metadata listed below and can prefer an eligible account for its own session. Cannot use a client credential to read client B's prompts, responses, or session assignment, or to call operator control endpoints. |
| Other account owners | Do not receive request bodies through Jaynshare, but their provider account may carry another user's request. That usage is subject to that account's provider contract, organization settings, and data controls. |
| Anthropic or another configured backend | Receives the content routed to it under the selected account. Its own terms, retention, and privacy controls apply. |
| Network peer without a Jaynshare credential | Is rejected by the data and control planes. Network exposure should still be restricted with Tailscale grants/ACLs and host firewall rules. |

An enrolled client can call the read-only usage endpoints. These deliberately
expose account display name, account type, organization name, priority,
availability, quota/reset state, aggregate token/request usage, and aggregate
session counts. They do **not** expose provider tokens, client secrets, prompt or
response bodies, other clients' session IDs, or the operator API.

Sessions are namespaced by the authenticated client ID, so reusing a Claude
session ID on two enrolled machines does not join their routing state. Responses
are returned only on the HTTP connection that made the request; Jaynshare has no
endpoint for one client to retrieve another client's response.

This is isolation of content in the current implementation, not isolation of
resources or risk. All clients can consume shared quota. Their activity can
change which account remains available for later requests and can contribute to
provider rate limits, suspension, or termination affecting everyone. An
operator can also switch the fleet's default account. Do not use one pool for
people who should not share those consequences.

## Data handling and storage

- **In memory:** Jaynshare buffers each complete request body so it can retry it
  on another account. Responses are normally streamed. The process therefore
  handles content in plaintext even when no body log is enabled.
- **Provider credentials:** OAuth tokens and API keys are stored in the server
  configuration, which the supported installer restricts to mode `0600` under a
  dedicated unprivileged user. Clients receive neither those credentials nor
  the server configuration.
- **Client credentials:** each enrolled client gets a distinct secret. The
  server stores only its SHA-256 hash. Client and operator credentials are
  separate and can be rotated or revoked independently.
- **Production audit log:** the supplied deployment records metadata—time,
  duration, client ID, session ID, path, model, selected account, status, retry,
  and error class—not prompt or response bodies. Files are created with mode
  `0600` and rotate by size. This metadata can still be sensitive.
- **Full body logging:** `logDir` and `--log-to` record request and response
  bodies. They are off in the supplied deployment, and startup refuses to
  combine them with the privacy audit log. If enabled manually, the files can
  contain source code, prompts, outputs, and secrets present in message bodies;
  treat them as highly sensitive.
- **Activity views:** the TUI, optional activity log, and enrolled-client status
  views contain routing and usage metadata, not message bodies.
- **Telemetry:** the supplied deployment sets `eventLogging` to `block`, which
  stops Claude Code event-logging requests at Jaynshare. This setting is not a
  general content filter and makes no claim about data Anthropic receives in
  ordinary model requests.

Jaynshare does not provide per-client content retention controls, content-level
access logs, encryption of request bodies from the operator, or a formal
security certification. No independent security audit is claimed here.

## MITM scope

The generated CA is added through `NODE_EXTRA_CA_CERTS` only to the Claude Code
process launched by `jaynshare run` or `jaynshare-claude`; the supported setup
does not install it in the operating system trust store. Jaynshare terminates
TLS for the configured upstream host and a built-in, credential-free test host.
Other HTTPS hosts requested through the forward proxy are blind tunnels, and
Jaynshare continues to verify the real upstream certificate on its outbound
connection.

That limited CA scope reduces the effect of accidental certificate trust. It
does not stop a malicious server from changing traffic for the intercepted host
or a malicious installer from changing the client configuration. Review the
exact source revision and installation bundle you deploy.

## Safer deployment checklist

1. Use a dedicated, patched, unprivileged server account controlled by an
   operator every participant trusts.
2. Bind only to the private Tailscale address, restrict which identities can
   reach the host, and never expose the proxy to the public internet.
3. Give every person/device its own client credential. Never share the operator
   credential; revoke both the Jaynshare credential and network access when a
   client leaves.
4. Keep `logDir` disabled. Define a retention and access policy for metadata
   audit logs, and tell users exactly what is retained.
5. Review and pin updates. The supported production setup disables automatic
   updates; rerun the deployment preflight after each change.
6. Do not route material whose owner has not approved disclosure to the server
   operator, the selected provider account, and Anthropic (or the configured
   backend). Keep unrelated production secrets out of prompts and repositories.
7. Use API-backed or organization-managed credentials when those arrangements
   fit the use case, and separately review the applicable provider terms.

Report suspected vulnerabilities privately as described in
[the security policy](../SECURITY.md).
