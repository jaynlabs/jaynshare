import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateClientSecret, hashClientSecret, resolvePrincipal, validateClientConfig,
  principalStillAuthorized,
} from '../src/client-auth.js';

test('generated client secrets authenticate by hash without storing plaintext', () => {
  const secret = generateClientSecret();
  const config = { proxy: { clients: [{ id: 'alice', name: 'Alice', keyHash: hashClientSecret(secret) }] } };
  assert.equal(JSON.stringify(config).includes(secret), false);
  assert.deepEqual(resolvePrincipal(config, secret), {
    role: 'client', clientId: 'alice', clientName: 'Alice', local: false,
    credentialHash: config.proxy.clients[0].keyHash,
  });
  assert.equal(resolvePrincipal(config, `${secret}x`), null);
});

test('disabled clients are refused and operator credentials are distinct', () => {
  const clientSecret = generateClientSecret();
  const adminSecret = generateClientSecret();
  const config = { proxy: {
    adminKeyHash: hashClientSecret(adminSecret),
    clients: [{ id: 'cto', keyHash: hashClientSecret(clientSecret), disabled: true }],
  } };
  assert.equal(resolvePrincipal(config, clientSecret), null);
  assert.equal(resolvePrincipal(config, adminSecret).role, 'operator');
});

test('a CONNECT-bound principal is invalidated by disable, rotation, or registry activation', () => {
  const secret = generateClientSecret();
  const config = { proxy: { clients: [{ id: 'alice', keyHash: hashClientSecret(secret) }] } };
  const principal = resolvePrincipal(config, secret);
  assert.equal(principalStillAuthorized(config, principal), true);
  config.proxy.clients[0].disabled = true;
  assert.equal(principalStillAuthorized(config, principal), false);
  config.proxy.clients[0].disabled = false;
  config.proxy.clients[0].keyHash = hashClientSecret(generateClientSecret());
  assert.equal(principalStillAuthorized(config, principal), false);

  const legacyOpen = resolvePrincipal({ proxy: {} }, null);
  assert.equal(principalStillAuthorized({ proxy: { clients: [] } }, legacyOpen), false);
});

test('new empty registries are closed while omitted legacy registries remain compatible', () => {
  assert.equal(resolvePrincipal({ proxy: { clients: [] } }, 'anything'), null);
  assert.equal(resolvePrincipal({ proxy: {} }, null).legacy, true);
});

test('client config rejects duplicate and unsafe ids', () => {
  const keyHash = hashClientSecret('secret');
  assert.throws(() => validateClientConfig({ clients: [{ id: 'Not Safe', keyHash }] }), /invalid/);
  assert.throws(() => validateClientConfig({ clients: [{ id: 'alice', keyHash }, { id: 'alice', keyHash }] }), /duplicate/);
});
