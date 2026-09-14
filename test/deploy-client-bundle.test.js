import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const prepare = fileURLToPath(new URL('../deploy/server/prepare-client.sh', import.meta.url));

test('prepare-client creates a secret-free bundle and a separate one-time secret', async () => {
  const tempHome = await mkdtemp(join(tmpdir(), 'jaynshare-prepare-client-'));
  try {
    const output = join(tempHome, 'output');
    const extract = join(tempHome, 'extract');
    const configPath = join(tempHome, 'jaynshare.json');
    const caPath = join(tempHome, 'jaynshare-ca.pem');
    await mkdir(extract);
    await writeFile(configPath, JSON.stringify({
      proxy: { host: '127.0.0.1', port: 9, clients: [] },
      accounts: [],
    }));
    await writeFile(caPath, '-----BEGIN CERTIFICATE-----\ntest-public-ca\n-----END CERTIFICATE-----\n');

    const env = {
      ...process.env,
      HOME: tempHome,
      JAYNSHARE_CONFIG: configPath,
      JAYNSHARE_CA_FILE: caPath,
    };
    const result = spawnSync('/bin/sh', [prepare, 'friend-one', 'Friend One', 'jaynshare.example.ts.net', output], {
      env,
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);

    const archive = join(output, 'jaynshare-friend-one.tar.gz');
    const secretFile = join(output, 'jaynshare-friend-one.secret');
    const secret = (await readFile(secretFile, 'utf8')).trim();
    assert.match(secret, /^jaynshare-client-/);

    const listing = spawnSync('tar', ['-tzf', archive], { encoding: 'utf8' });
    assert.equal(listing.status, 0, listing.stderr);
    assert.match(listing.stdout, /jaynshare-friend-one\/install\.sh/);
    assert.doesNotMatch(listing.stdout, /secret/i);
    assert.match(listing.stdout, /jaynshare-friend-one\/client\/windows-acl\.sh/,
      'the Windows access-rule helper ships in the same platform-neutral bundle');

    const unpack = spawnSync('tar', ['-xzf', archive, '-C', extract], { encoding: 'utf8' });
    assert.equal(unpack.status, 0, unpack.stderr);
    const installer = await readFile(join(extract, 'jaynshare-friend-one/install.sh'), 'utf8');
    assert.match(installer, /friend-one/);
    assert.match(installer, /jaynshare\.example\.ts\.net/);
    assert.equal(installer.includes(secret), false);

    const readme = await readFile(join(extract, 'jaynshare-friend-one/START-HERE.txt'), 'utf8');
    assert.match(readme, /-- macOS/, 'the bundle has to tell a Mac tester what to run');
    const macInstructions = readme.split('-- Windows')[0];
    assert.match(macInstructions, /bash \.\/install\.sh/,
      'the Mac instructions must survive transfer channels that strip executable bits');
    assert.match(readme, /Git Bash/, 'the same bundle has to tell a Windows tester what to run');

    // Nothing anywhere in the archive may carry the credential, not just the
    // installer: the bundle and the secret travel through different channels.
    const bundled = await readdir(join(extract, 'jaynshare-friend-one'), { recursive: true, withFileTypes: true });
    for (const entry of bundled) {
      if (!entry.isFile()) continue;
      const contents = await readFile(join(entry.parentPath ?? entry.path, entry.name), 'utf8');
      assert.equal(contents.includes(secret), false, `no bundled file may contain the secret: ${entry.name}`);
    }

    const saved = await readFile(configPath, 'utf8');
    assert.match(saved, /"id": "friend-one"/);
    assert.equal(saved.includes(secret), false);

    const again = spawnSync('/bin/sh', [prepare, 'friend-one', 'Friend One', 'jaynshare.example.ts.net', output], {
      env,
      encoding: 'utf8',
    });
    assert.notEqual(again.status, 0);
    assert.match(again.stderr, /refusing to overwrite/);
  } finally {
    await rm(tempHome, { recursive: true, force: true });
  }
});

test('the desktop client runs when invoked through a symlinked path', async () => {
  const tempHome = await mkdtemp(join(tmpdir(), 'jaynshare-client-symlink-'));
  try {
    const realClient = fileURLToPath(new URL('../deploy/client/jaynshare-client.mjs', import.meta.url));
    const linkedClient = join(tempHome, 'jaynshare');
    await symlink(realClient, linkedClient);

    const result = spawnSync('node', [linkedClient], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Jaynshare desktop client/);
  } finally {
    await rm(tempHome, { recursive: true, force: true });
  }
});
