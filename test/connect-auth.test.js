import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connectPrincipal } from '../src/mitm.js';
import { safeKeyEqual, isLoopbackAddr, isSelfConnection } from '../src/server.js';

// Without the CONNECT gate, a remote client gets a token injected or an open relay.

const sock = (remoteAddress) => ({ remoteAddress });
const req = (auth) => ({ headers: auth ? { 'proxy-authorization': auth } : {} });
const keyed = { proxy: { apiKey: 'secret' } };

test('no proxy credential configured → CONNECT is open (matches the HTTP path)', () => {
  assert.ok(connectPrincipal(req(), sock('203.0.113.9'), { proxy: {} }));
});

test('loopback clients are exempt even when a key is set', () => {
  for (const a of ['127.0.0.1', '::1', '::ffff:127.0.0.1']) {
    assert.equal(connectPrincipal(req(), sock(a), keyed)?.local, true, a);
  }
});

test('a remote client with no Proxy-Authorization is denied', () => {
  assert.equal(connectPrincipal(req(), sock('203.0.113.9'), keyed), null);
});

test('a remote client with the correct Bearer key is allowed', () => {
  assert.ok(connectPrincipal(req('Bearer secret'), sock('203.0.113.9'), keyed));
});

test('a remote client with a wrong key is denied', () => {
  assert.equal(connectPrincipal(req('Bearer nope'), sock('203.0.113.9'), keyed), null);
});

test('Basic auth carrying the key as username or password is accepted', () => {
  const asUser = 'Basic ' + Buffer.from('secret:').toString('base64');  // curl http://secret@host
  const asPass = 'Basic ' + Buffer.from('x:secret').toString('base64'); // curl http://x:secret@host
  assert.ok(connectPrincipal(req(asUser), sock('10.0.0.5'), keyed));
  assert.ok(connectPrincipal(req(asPass), sock('10.0.0.5'), keyed));
});

test('safeKeyEqual is value-correct and length/type-safe', () => {
  assert.equal(safeKeyEqual('abc', 'abc'), true);
  assert.equal(safeKeyEqual('abc', 'abd'), false);
  assert.equal(safeKeyEqual('abc', 'abcd'), false); // different length, no throw
  assert.equal(safeKeyEqual(undefined, 'abc'), false);
  assert.equal(safeKeyEqual('abc', null), false);
});

test('isLoopbackAddr recognizes the three loopback forms only', () => {
  assert.equal(isLoopbackAddr('127.0.0.1'), true);
  assert.equal(isLoopbackAddr('::1'), true);
  assert.equal(isLoopbackAddr('::ffff:127.0.0.1'), true);
  assert.equal(isLoopbackAddr('10.0.0.1'), false);
  assert.equal(isLoopbackAddr(undefined), false);
});

test('isSelfConnection accepts only identical non-empty socket addresses', () => {
  assert.equal(isSelfConnection('100.64.0.10', '100.64.0.10'), true);
  assert.equal(isSelfConnection('100.64.0.11', '100.64.0.10'), false);
  assert.equal(isSelfConnection(undefined, undefined), false);
  assert.equal(isSelfConnection('', ''), false);
});
