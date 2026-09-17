# Compliance and terms of service

**Read this before you deploy Jaynshare.**

Jaynshare routes Claude Code traffic through multiple Claude identities.
Anthropic's published Consumer Terms prohibit sharing account credentials or
making an account available to anyone else. Its Claude Code documentation also
says that developers may not route requests through Free, Pro, or Max plan
credentials on behalf of their users. Pooling personal subscriptions therefore
conflicts with the published rules. Account-owner consent is necessary between
participants, but it is not permission from Anthropic.

Do not describe this distinction as "against the terms but not illegal." Terms
and criminal law are different questions, but that slogan is incomplete and can
sound like a safety guarantee. Legality and civil liability depend on the
deployment, representations, data, contracts, and jurisdiction. Jaynshare makes
no legal conclusion about a particular use.

Deciding whether a given deployment is permitted is the operator's
responsibility, not the tool's. Before you deploy:

- Read the current terms for the accounts you intend to pool. They change, and
  the answer you found last year may not hold.
- Consider whether metered API billing covers your use case. Where it does, it
  avoids the subscription-sharing issue, although the API's commercial terms
  and other obligations still apply.
- If you are deploying inside an organization, get that decision made by whoever
  is accountable for it rather than assuming it.
- Complete a security and privacy review using the documented
  [trust model](security-and-privacy.md). Provider compliance does not make an
  untrusted proxy safe.

Whatever you conclude, these hold:

- Enroll only accounts whose owners have consented and personally authorized the
  enrollment. Never ask for, watch, or store anyone's password; the OAuth flow
  exists so you do not have to.
- Do not point unrelated third-party clients at pooled OAuth credentials.
- Keep the deployment reachable only by the people it is for. The documented
  topology binds to a private network address for this reason.
- Tell users that the server operator can inspect or modify their traffic and
  that other participants can consume shared quota. Do not call the service
  private without explaining that trust boundary.
- Re-check your position before a material upgrade or a change in who has
  access.

Sources: [Anthropic Consumer Terms](https://www.anthropic.com/legal/consumer-terms)
and [Claude Code legal and compliance documentation](https://code.claude.com/docs/en/legal-and-compliance),
reviewed 17 September 2026.

This document is not legal advice.
