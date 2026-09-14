import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AccountManager } from '../src/account-manager.js';

function oauth(name, extra = {}) {
  return { name, type: 'oauth', accessToken: 't', refreshToken: 'r', expiresAt: Date.now() + 3600_000, ...extra };
}

// Unavailable without an expired hold, so selection reaches the fallback paths.
function nearQuotaFutureReset(am, i) {
  am.accounts[i].quota.unified7d = 0.999;
  am.accounts[i].quota.unified7dReset = Date.now() + 3600_000;
}

test('the soonest-reset fallback never resurrects a disabled account', () => {
  const am = new AccountManager([oauth('disabled'), oauth('busy')], 0.98);
  am.markRateLimited(0, 1);
  am.accounts[0].rateLimitedUntil = Date.now() - 5000; // hold already expired…
  am.accounts[0].disabled = true;                      // …but operator-disabled
  nearQuotaFutureReset(am, 1);                          // the other account is genuinely busy

  const acct = am.getActiveAccount();
  assert.notEqual(acct?.name, 'disabled');             // never selected
  assert.equal(am.accounts[0].disabled, true);         // still disabled
  assert.equal(am.accounts[0].status, 'throttled');    // NOT flipped to active
  assert.notEqual(am.accounts[0].rateLimitedUntil, null); // hold NOT cleared
});

test('the soonest-reset fallback never resurrects an errored account', () => {
  const am = new AccountManager([oauth('broken'), oauth('busy')], 0.98);
  am.markRateLimited(0, 1);
  am.accounts[0].rateLimitedUntil = Date.now() - 5000;
  am.accounts[0].status = 'error'; // token needs re-login
  nearQuotaFutureReset(am, 1);

  const acct = am.getActiveAccount();
  assert.notEqual(acct?.name, 'broken');
  assert.equal(am.accounts[0].status, 'error'); // not silently reactivated
});

test('an owned-model request never falls back to a non-owner account', () => {
  const am = new AccountManager([
    oauth('claude'),
    oauth('deepseek', { models: ['deepseek-chat'], priority: 100 }),
  ], 0.98);
  am.markRateLimited(1, 3600);        // the sole owner is throttled (future hold)
  nearQuotaFutureReset(am, 0);        // the Claude account is busy too

  const acct = am.getActiveAccount(null, 'deepseek-chat');
  assert.notEqual(acct?.name, 'claude'); // the deepseek model must not hit Claude
});

test('ownership guard is inert when no account claims the model', () => {
  const am = new AccountManager([oauth('a'), oauth('b')], 0.98);
  nearQuotaFutureReset(am, 0);
  nearQuotaFutureReset(am, 1);
  // Every account near quota → a probe is allowed; some account is returned.
  const acct = am.getActiveAccount(null, 'claude-sonnet-4-6');
  assert.ok(acct, 'a probe target should still be selectable');
});
