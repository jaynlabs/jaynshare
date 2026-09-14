import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLog, auditHooks, auditPath } from '../src/audit-log.ts';

test('auditPath removes query strings', () => {
  assert.equal(auditPath('/v1/messages?token=secret'), '/v1/messages');
});

test('audit hooks write metadata without request bodies', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'jaynshare-audit-'));
  try {
    const path = join(dir, 'audit.ndjson');
    const audit = new AuditLog({ path });
    const hooks = auditHooks(audit);
    hooks.onRequestStart(1, { clientId: 'alice', sessionId: 's1', method: 'POST', path: '/v1/messages?secret=yes' });
    hooks.onRequestModel(1, { model: 'claude-test' });
    hooks.onRequestEnd(1, { status: 200, accountId: 'account/org', retryCount: 1, rotated: true });
    await audit.chain;
    const record = JSON.parse((await readFile(path, 'utf8')).trim());
    assert.equal(record.clientId, 'alice');
    assert.equal(record.path, '/v1/messages');
    assert.equal(record.accountId, 'account/org');
    assert.equal(record.retryCount, 1);
    assert.equal(record.rotated, true);
    assert.equal(JSON.stringify(record).includes('secret=yes'), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
