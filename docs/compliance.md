# Compliance and terms of service

**Read this before you deploy Jaynshare.**

Jaynshare routes Claude Code traffic through multiple Claude identities. Provider
terms of service generally govern whether a subscription may be shared, pooled,
or accessed by anyone other than its owner, and pooling personal subscriptions
may well fall outside them. Jaynshare takes no position that such use is
authorized, and shipping this tool is not a representation that it is.

Deciding whether a given deployment is permitted is the operator's
responsibility, not the tool's. Before you deploy:

- Read the current terms for the accounts you intend to pool. They change, and
  the answer you found last year may not hold.
- Consider whether metered API billing covers your use case. Where it does, it
  is the path with no terms question attached.
- If you are deploying inside an organization, get that decision made by whoever
  is accountable for it rather than assuming it.

Whatever you conclude, these hold:

- Enroll only accounts whose owners have consented and personally authorized the
  enrollment. Never ask for, watch, or store anyone's password; the OAuth flow
  exists so you do not have to.
- Do not point unrelated third-party clients at pooled OAuth credentials.
- Keep the deployment reachable only by the people it is for. The documented
  topology binds to a private network address for this reason.
- Re-check your position before a material upgrade or a change in who has
  access.

This document is not legal advice.
