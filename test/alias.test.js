import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { existsSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { aliasLine, rcPathForShell, jaynshareRef, installAlias, uninstallAlias } from '../src/alias.js';

test('aliasLine uses the right syntax per shell (explicit ref)', () => {
  assert.equal(aliasLine('bash', 'jaynshare'), "alias claude='jaynshare run --'");
  assert.equal(aliasLine('zsh', 'jaynshare'), "alias claude='jaynshare run --'");
  assert.equal(aliasLine('fish', 'jaynshare'), "alias claude 'jaynshare run --'");
});

test('aliasLine embeds a quoted absolute path when jaynshare is not on PATH', () => {
  assert.equal(aliasLine('bash', '"/opt/tc/index.js"'), `alias claude='"/opt/tc/index.js" run --'`);
  assert.equal(aliasLine('fish', '"/opt/tc/index.js"'), `alias claude '"/opt/tc/index.js" run --'`);
});

test('jaynshareRef returns the bare command when it is on PATH', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-path-'));
  const prev = process.env.PATH;
  try {
    const bin = join(dir, 'jaynshare');
    writeFileSync(bin, '#!/bin/sh\n', { mode: 0o755 });
    chmodSync(bin, 0o755);
    process.env.PATH = dir;
    assert.equal(jaynshareRef(), 'jaynshare');
  } finally {
    process.env.PATH = prev;
    await rm(dir, { recursive: true, force: true });
  }
});

test('jaynshareRef falls back to a quoted absolute path when not on PATH', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-path-'));
  const prev = process.env.PATH;
  try {
    process.env.PATH = dir; // empty dir → no jaynshare
    const ref = jaynshareRef();
    assert.match(ref, /^".*"$/);          // quoted
    assert.ok(ref.includes('/'));          // an absolute-ish path, not the bare command
    assert.notEqual(ref, 'jaynshare');
  } finally {
    process.env.PATH = prev;
    await rm(dir, { recursive: true, force: true });
  }
});

test('rcPathForShell maps shells to their rc files', () => {
  const prevHome = process.env.HOME;
  const prevXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = '/home/u';
  delete process.env.XDG_CONFIG_HOME;
  try {
    assert.equal(rcPathForShell('bash'), '/home/u/.bashrc');
    assert.equal(rcPathForShell('zsh'), '/home/u/.zshrc');
    assert.equal(rcPathForShell('sh'), '/home/u/.profile');
    assert.equal(rcPathForShell('fish'), '/home/u/.config/fish/conf.d/jaynshare.fish');
  } finally {
    process.env.HOME = prevHome;
    if (prevXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = prevXdg;
  }
});

test('install adds the alias, is idempotent, and uninstall removes it cleanly', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-alias-'));
  const rcPath = join(dir, '.bashrc');
  await writeFile(rcPath, '# existing user content\nexport FOO=1\n');
  try {
    installAlias({ shell: 'bash', rcPath });
    let text = await readFile(rcPath, 'utf8');
    assert.match(text, /alias claude=.*run --/);
    assert.ok(text.includes('# jaynshare alias'));
    assert.ok(text.includes('# existing user content')); // preserved

    // Idempotent: a second install doesn't duplicate the line.
    installAlias({ shell: 'bash', rcPath });
    text = await readFile(rcPath, 'utf8');
    assert.equal(text.match(/alias claude=/g).length, 1);

    // Uninstall removes our block; user content stays intact.
    uninstallAlias({ shell: 'bash', rcPath });
    text = await readFile(rcPath, 'utf8');
    assert.ok(!text.includes('alias claude='));
    assert.ok(!text.includes('# jaynshare alias'));
    assert.ok(text.includes('export FOO=1'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('uninstall removes our block even if the embedded path differs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-alias-'));
  const rcPath = join(dir, '.bashrc');
  // Simulate a previously-installed alias with an absolute path that no longer
  // matches what jaynshareRef() would compute now.
  await writeFile(rcPath, 'export FOO=1\n# jaynshare alias\nalias claude=\'"/old/path/index.js" run --\'\n');
  try {
    uninstallAlias({ shell: 'bash', rcPath });
    const text = await readFile(rcPath, 'utf8');
    assert.ok(!text.includes('alias claude='));
    assert.ok(!text.includes('# jaynshare alias'));
    assert.ok(text.includes('export FOO=1'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('uninstall of a dedicated fish drop-file removes the file when empty', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc-alias-'));
  const rcPath = join(dir, 'jaynshare.fish');
  try {
    installAlias({ shell: 'fish', rcPath });
    assert.ok(existsSync(rcPath));
    uninstallAlias({ shell: 'fish', rcPath });
    assert.ok(!existsSync(rcPath)); // emptied → removed
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
