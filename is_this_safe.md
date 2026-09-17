# Is subscription sharing safe?

**Pooling personal Claude subscriptions conflicts with Anthropic's published
rules.** Its Consumer Terms prohibit sharing account credentials or making an
account available to someone else, and its Claude Code documentation says that
developers may not route requests through Free, Pro, or Max credentials for
their users. A proxy, company ownership, or account-owner consent does not
override those rules.

This page covers subscription and compliance risk. The separate
[security and privacy model](docs/security-and-privacy.md) covers what the proxy
can see and what one participant can learn about another.
Reviewed: **17 September 2026**.

## What can happen?

- **Account suspension or termination:** enrolled accounts can lose access,
  including the owner's personal use outside Jaynshare. Anthropic's terms allow
  suspension or termination without notice for a suspected breach.
- **Financial loss:** subscription value may be lost. Anthropic's terms say a
  subscription terminated for a violation is not refunded, subject to
  applicable law.
- **Shared consequences:** another participant's activity can consume quota or
  trigger enforcement against the account used.
- **Service interruption:** bans, withdrawals, or provider changes can stop the
  service, leading to customer refund demands or claims.
- **Data and security exposure:** the server is able to read and alter routed
  traffic. A malicious participant cannot directly read another participant's
  request through the client API, but can consume shared quota and contribute to
  enforcement against a shared provider account.

Enforcement likelihood is unknown. Neither provider should be presented as a
safe option, and losses are not necessarily limited to the price of a
subscription: an account owner may lose access, a user may expose confidential
code to an untrusted operator, and a paid service may owe refunds or incur other
liability.

## Who bears the risk?

| Model | Main exposure |
| --- | --- |
| Company supplies subscriptions | Company accounts and spend; buyers' payments and service continuity. |
| Customers contribute subscriptions | Contributors' existing accounts, subscription spend, and personal usage. |
| Mixed pool | Both; disclose that unrelated contributors supply capacity. |

A participant who never enrolls a provider account is not putting such an
account at risk, but still accepts the proxy's security and privacy risks and
can affect the shared accounts through their usage.

## What does consent change?

**Consent is not provider permission or a blanket liability waiver.** Account
owners and users should be told, before enrollment, about termination risk,
what the operator can inspect or modify, what metadata other users can see,
retention, withdrawal, refunds, and any contributor compensation. Do not
guarantee account reinstatement, confidentiality from the operator, or
uninterrupted access.

An authorized API-backed service or a written provider agreement is a different
contractual route, with its own obligations.

## Sources

- [Anthropic Consumer Terms](https://www.anthropic.com/legal/consumer-terms)
- [Claude Code: legal, compliance, and credential use](https://code.claude.com/docs/en/legal-and-compliance)
- [Anthropic Transparency Hub: enforcement](https://www.anthropic.com/transparency/system-trust-reporting)

This is a risk summary, not legal advice, a prediction of enforcement, or a
guarantee of compliance.
