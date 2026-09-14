// An account's identity is its Anthropic account UUID plus its organization: one
// person can hold a separate account (token, quota) in each org.

export function orgKey(acct) {
  return acct?.orgUuid || acct?.orgName || null;
}

export function sameIdentity(a, b) {
  if (a?.accountUuid && b?.accountUuid) {
    if (a.accountUuid !== b.accountUuid) return false;
    const ka = orgKey(a);
    const kb = orgKey(b);
    if (ka && kb) return ka === kb;
    return true; // an org still unknown on one side never contradicts
  }
  return a?.name === b?.name;
}

// True only when both sides are fully identified and differ; unknown never means "different".
export function distinctAccounts(a, b) {
  if (!a?.accountUuid || !b?.accountUuid) return false;
  if (a.accountUuid !== b.accountUuid) return true;
  const ka = orgKey(a);
  const kb = orgKey(b);
  return !!(ka && kb && ka !== kb);
}

// The config entry a login should update, or -1. Two orgs of one person share a
// display name, so a name match counts only when identity does not contradict it.
export function findUpsertTarget(accounts, incoming) {
  const byIdentity = accounts.findIndex(a => sameIdentity(a, incoming));
  if (byIdentity >= 0) return byIdentity;
  return accounts.findIndex(a => a.name === incoming.name && !distinctAccounts(a, incoming));
}

export function emailOf(acct) {
  return (acct?.name || '').replace(/ \(.*\)$/, '');
}

export function matchAccounts(accounts, query, orgFilter) {
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
