import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ACCOUNT_PREFERENCE_PREFIX,
  decodeAccountPreference,
  encodeAccountPreference,
} from '../src/account-preference.js';
import { AccountManager } from '../src/account-manager.js';

test('soft account preference protocol round-trips supported identities', () => {
  for (const identity of [
    'friend@example.com',
    'Jane Doe (R&D / Europe)',
    '账户 @ example / org',
    'aaaaaaaa-bbbb/cccc-dddd',
  ]) {
    assert.equal(decodeAccountPreference(encodeAccountPreference(identity)), identity);
  }
});

test('non-reserved usernames remain legacy pins and malformed reserved values fail closed', () => {
  assert.equal(decodeAccountPreference('friend@example.com'), null);
  for (const value of [ACCOUNT_PREFERENCE_PREFIX, `${ACCOUNT_PREFERENCE_PREFIX}!`, `${ACCOUNT_PREFERENCE_PREFIX}wA`]) {
    assert.throws(() => decodeAccountPreference(value), /malformed/);
  }
});

test('a preference is tried first without changing global selection and then falls back', () => {
  const am = new AccountManager([
    { name: 'global', type: 'apikey', apiKey: 'a' },
    { name: 'preferred', type: 'apikey', apiKey: 'b' },
  ]);
  assert.equal(am.getActiveAccount(null, null, null, null, 1).name, 'preferred');
  assert.equal(am.currentIndex, 0);
  assert.equal(am.getActiveAccount(new Set([1]), null, null, null, 1).name, 'global');
  am.accounts[1].disabled = true;
  assert.equal(am.getActiveAccount(null, null, null, null, 1).name, 'global');
});

test('a preference cannot bypass an exclusive model route', () => {
  const am = new AccountManager([
    { name: 'route-owner', type: 'apikey', apiKey: 'a' },
    { name: 'preferred', type: 'apikey', apiKey: 'b' },
  ], 0.98, { routes: [{ name: 'special', match: ['special-*'], accounts: ['route-owner'] }] });
  assert.equal(am.getActiveAccount(null, 'special-model', null, null, 1).name, 'route-owner');
});
