// An account's identity is its Anthropic account UUID plus its organization: one
// person can hold a separate account (token, quota) in each org.

interface IdentityLike {
  accountUuid?: string | null;
  orgUuid?: string | null;
  orgName?: string | null;
  name?: string;
  [key: string]: any;
}

export function orgKey(acct: IdentityLike | null | undefined): string | null {
  return acct?.orgUuid || acct?.orgName || null;
}

export function sameIdentity(a: IdentityLike | null | undefined, b: IdentityLike | null | undefined): boolean {
  if (a?.accountUuid && b?.accountUuid) {
    if (a.accountUuid !== b.accountUuid) return false;
    const orgKeyA = orgKey(a);
    const orgKeyB = orgKey(b);
    if (orgKeyA && orgKeyB) return orgKeyA === orgKeyB;
    return true; // an org still unknown on one side never contradicts
  }
  return a?.name === b?.name;
}

// True only when both sides are fully identified and differ; unknown never means "different".
export function distinctAccounts(a: IdentityLike | null | undefined, b: IdentityLike | null | undefined): boolean {
  if (!a?.accountUuid || !b?.accountUuid) return false;
  if (a.accountUuid !== b.accountUuid) return true;
  const orgKeyA = orgKey(a);
  const orgKeyB = orgKey(b);
  return !!(orgKeyA && orgKeyB && orgKeyA !== orgKeyB);
}

// The config entry a login should update, or -1. Two orgs of one person share a
// display name, so a name match counts only when identity does not contradict it.
export function findUpsertTarget(accounts: IdentityLike[], incoming: IdentityLike): number {
  const byIdentity = accounts.findIndex(a => sameIdentity(a, incoming));
  if (byIdentity >= 0) return byIdentity;
  return accounts.findIndex(a => a.name === incoming.name && !distinctAccounts(a, incoming));
}

export function emailOf(acct: IdentityLike | null | undefined): string {
  return (acct?.name || '').replace(/ \(.*\)$/, '');
}

export function matchAccounts<T extends IdentityLike>(accounts: T[], query: string, orgFilter?: string): T[] {
  let matches = accounts.filter(a => a.name === query);
  if (matches.length === 0) {
    matches = accounts.filter(a => emailOf(a) === query);
  }
  if (orgFilter) {
    matches = matches.filter(a =>
      (a.orgName && a.orgName === orgFilter) ||
      (a.orgUuid && (a.orgUuid === orgFilter || a.orgUuid.startsWith(orgFilter)))
    );
  }
  return matches;
}

export function orgLabel(acct: IdentityLike): string {
  return acct.orgName || (acct.orgUuid ? acct.orgUuid.slice(0, 8) : 'org');
}

export function withOrgSuffixes<T extends IdentityLike>(accounts: T[], incoming: T): { accounts: T[]; incoming: T } {
  const clashes = (a: T) => a.accountUuid && a.accountUuid === incoming.accountUuid && !sameIdentity(a, incoming);
  if (!accounts.some(clashes)) return { accounts, incoming };
  return {
    accounts: accounts.map(a =>
      clashes(a) && !a.name!.includes(' (') ? { ...a, name: `${a.name} (${orgLabel(a)})` } : a
    ),
    incoming: { ...incoming, name: `${incoming.name} (${orgLabel(incoming)})` },
  };
}
