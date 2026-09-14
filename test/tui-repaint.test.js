import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TUI } from '../src/tui.js';

// An idle TUI must not wake the machine: the tick slows down and an unchanged frame is not written.

function makeTUI() {
  const am = {
    accounts: [{ name: 'a', index: 0, type: 'oauth', credential: 't' }],
    currentIndex: 0,
    switchThreshold: 0.98,
    getRoutes: () => [],
    sessionStats: () => ({ active: 0, total: 0 }),
    getStatus: () => ({ accounts: [] }),
    refreshExpiredQuotas: () => {},
  };
  const config = { proxy: { port: 1 }, accounts: [{ name: 'a', type: 'oauth' }], routes: [], blockedModels: [] };
  return new TUI({
    accountManager: am, config, sx: null,
    saveConfig: async () => {}, syncAccounts: async () => 0, onQuit: () => {},
  });
}

test('the tick is slow while idle and fast only while something is animating', () => {
  const tui = makeTUI();
  assert.equal(tui.active.size, 0);
  const idle = tui._tickDelay();

  tui.active.set('r1', { started: Date.now() });
  const busy = tui._tickDelay();

  assert.ok(busy < idle, `animating tick (${busy}ms) must be faster than idle (${idle}ms)`);
  // The point of the issue: idling must not mean waking twice a second.
  assert.ok(idle >= 5000, `idle tick is ${idle}ms — too chatty to let a laptop sleep`);

  tui.active.delete('r1');
  assert.equal(tui._tickDelay(), idle, 'falls back to the idle cadence once nothing is in flight');
});

function runOneTick(tui) {
  let captured = null;
  tui._setTimeout = (fn) => { captured = fn; return { unref() {} }; };
  tui._scheduleTick();
  assert.ok(captured, '_scheduleTick armed no timer');
  // Stop it re-arming forever when we invoke it.
  const rearm = tui._scheduleTick;
  tui._scheduleTick = () => {};
  try { captured(); } finally { tui._scheduleTick = rearm; }
}

test('the spinner frame only advances when the spinner is on screen', () => {
  const tui = makeTUI();
  tui.running = true;
  tui.render = () => {};

  const before = tui.frame;
  runOneTick(tui);
  assert.equal(tui.frame, before, 'an idle tick must not change what would be drawn');

  tui.active.set('r1', { started: Date.now() });
  runOneTick(tui);
  assert.notEqual(tui.frame, before, 'the spinner still animates while a request is in flight');
});

test('an identical frame is not written to the terminal twice', () => {
  const tui = makeTUI();
  tui.running = true;

  const writes = [];
  const orig = process.stdout.write;
  process.stdout.write = (chunk) => { writes.push(String(chunk)); return true; };
  try {
    tui._paint('SAME', false);
    tui._paint('SAME', false);
    tui._paint('SAME', false);
    assert.equal(writes.length, 1, 'repeated identical frames collapse to one write');

    tui._paint('DIFFERENT', false);
    assert.equal(writes.length, 2, 'a changed frame is written');

    tui._paint('DIFFERENT', true); // a resize
    assert.equal(writes.length, 3, 'a forced repaint is written even when unchanged');
  } finally {
    process.stdout.write = orig;
  }
});

test('an unchanged frame is still repainted eventually', () => {
  const tui = makeTUI();
  tui.running = true;

  const writes = [];
  const orig = process.stdout.write;
  process.stdout.write = (chunk) => { writes.push(String(chunk)); return true; };
  try {
    tui._paint('SAME', false);
    assert.equal(writes.length, 1);
    tui._paint('SAME', false);
    assert.equal(writes.length, 1);

    // Pretend the last paint was long enough ago to be considered stale.
    tui._lastPaintAt = Date.now() - 120_000;
    tui._paint('SAME', false);
    assert.equal(writes.length, 2, 'a stale screen is refreshed even when the frame matches');
  } finally {
    process.stdout.write = orig;
  }
});

test('a request arriving while idle re-arms the tick at once', () => {
  const tui = makeTUI();
  tui.running = true;
  tui.render = () => {};

  let scheduled = 0;
  tui._scheduleTick = () => { scheduled++; };

  tui.onRequestStart('r1', { method: 'POST', path: '/v1/messages' });
  assert.equal(scheduled, 1, 'going from idle to animating re-arms the tick');

  // A second concurrent request is already animating — no need to re-arm again.
  tui.onRequestStart('r2', { method: 'POST', path: '/v1/messages' });
  assert.equal(scheduled, 1);
});
