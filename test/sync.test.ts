import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import type { KpsApi } from '../client/api.ts';
import { credentials, kdbxweb } from '../client/kdbx.ts';
import { LocalVault } from '../client/sync.ts';
import { addEntry, adminApi, createUser, DB_PASSWORD, findEntry, newDatabase, startServer, tempDir, type TestServer, titles } from './helpers.ts';

const creds = () => credentials(DB_PASSWORD);

let server: TestServer;
let admin: KpsApi;

before(async () => {
  server = await startServer();
  admin = await adminApi(server.url);
});

after(() => server.stop());

/** Creates a vault from a new database on "laptop" and clones it onto "phone". */
async function setup(name: string, phoneApi: KpsApi = admin) {
  const info = await admin.createVault(name);
  const laptop = await LocalVault.create(await tempDir('kps-laptop-'), { serverUrl: server.url, vaultId: info.id, vaultName: name });
  const db = newDatabase();
  addEntry(db, 'shared');
  await laptop.save(db);
  assert.equal((await laptop.sync(admin, creds(), db)).status, 'pushed');

  const phone = await LocalVault.create(await tempDir('kps-phone-'), { serverUrl: server.url, vaultId: info.id, vaultName: name });
  assert.equal((await phone.sync(phoneApi, creds())).status, 'pulled');
  return { info, laptop, phone };
}

describe('offline-first sync', () => {
  it('Should_MergeBothSides_When_DevicesEditedDifferentEntriesOffline', async () => {
    const { laptop, phone } = await setup('Offline edits');

    // Both devices work offline and add an entry.
    const laptopDb = await laptop.open(creds());
    addEntry(laptopDb, 'from laptop');
    await laptop.save(laptopDb);
    const phoneDb = await phone.open(creds());
    addEntry(phoneDb, 'from phone');
    await phone.save(phoneDb);

    // Laptop comes online first: plain push.
    assert.equal((await laptop.sync(admin, creds(), laptopDb)).status, 'pushed');
    // Phone comes online: its base revision is stale, so it merges and pushes.
    const result = await phone.sync(admin, creds(), phoneDb);
    assert.equal(result.status, 'merged');
    assert.deepEqual(titles(result.db!), ['from laptop', 'from phone', 'shared']);

    // Laptop pulls the merged result.
    const pulled = await laptop.sync(admin, creds());
    assert.equal(pulled.status, 'pulled');
    assert.deepEqual(titles(pulled.db!), ['from laptop', 'from phone', 'shared']);
  });

  it('Should_KeepNewestAndHistory_When_SameEntryEditedOnBothDevices', async () => {
    const { laptop, phone } = await setup('Same entry');
    const laptopDb = await laptop.open(creds());
    const phoneDb = await phone.open(creds());

    const l = findEntry(laptopDb, 'shared')!;
    l.pushHistory();
    l.fields.set('UserName', 'laptop-user');
    // KDBX stores times with one-second resolution; real edits are seconds apart.
    l.times.lastModTime = new Date(Date.now() + 2000);
    await laptop.save(laptopDb);

    const p = findEntry(phoneDb, 'shared')!; // phone edits later, so its version wins
    p.pushHistory();
    p.fields.set('UserName', 'phone-user');
    p.times.lastModTime = new Date(Date.now() + 4000);
    await phone.save(phoneDb);

    await laptop.sync(admin, creds(), laptopDb);
    const result = await phone.sync(admin, creds(), phoneDb);
    assert.equal(result.status, 'merged');
    const merged = findEntry(result.db!, 'shared')!;
    assert.equal(merged.fields.get('UserName'), 'phone-user');
    // The losing edit is not lost: it is in the entry history.
    assert.ok(merged.history.some((h) => h.fields.get('UserName') === 'laptop-user'));
  });

  it('Should_PropagateDeletion_When_EntryDeletedOnOneDevice', async () => {
    const { laptop, phone } = await setup('Deletion');
    const laptopDb = await laptop.open(creds());
    const victim = addEntry(laptopDb, 'to delete');
    await laptop.save(laptopDb);
    await laptop.sync(admin, creds(), laptopDb);
    const phoneDb = (await phone.sync(admin, creds())).db!;

    laptopDb.move(victim, null); // permanent delete, records a DeletedObject tombstone
    await laptop.save(laptopDb);
    addEntry(phoneDb, 'phone add');
    await phone.save(phoneDb);

    await laptop.sync(admin, creds(), laptopDb);
    const result = await phone.sync(admin, creds(), phoneDb);
    assert.deepEqual(titles(result.db!), ['phone add', 'shared']);
  });

  it('Should_KeepLocalChanges_When_ServerUnreachable', async () => {
    const dataDir = await tempDir();
    let local = await startServer({ dataDir });
    const api = await adminApi(local.url);
    const info = await api.createVault('Unreachable');
    const vault = await LocalVault.create(await tempDir(), { serverUrl: local.url, vaultId: info.id, vaultName: 'Unreachable' });
    const db = newDatabase();
    addEntry(db, 'first');
    await vault.save(db);
    await vault.sync(api, creds(), db);

    const port = new URL(local.url).port;
    await local.stop();
    addEntry(db, 'written offline');
    await vault.save(db);
    const offline = await vault.sync(api, creds(), db);
    assert.equal(offline.status, 'offline');
    assert.equal(vault.state.dirty, true);

    // The cache survives an app restart and still opens without the server.
    const reopened = await (await LocalVault.load(vault.dir)).open(creds());
    assert.deepEqual(titles(reopened), ['first', 'written offline']);

    local = await startServer({ dataDir, port: Number(port) });
    try {
      const online = await vault.sync(api, creds(), db);
      assert.equal(online.status, 'pushed');
      assert.equal(vault.state.dirty, false);
    } finally {
      await local.stop();
    }
  });

  it('Should_NotContactServer_When_WorkOfflineEnabled', async () => {
    const { laptop } = await setup('Work offline');
    await laptop.setWorkOffline(true);
    const db = await laptop.open(creds());
    addEntry(db, 'offline only');
    await laptop.save(db);
    assert.equal((await laptop.sync(admin, creds(), db)).status, 'work-offline');
    assert.equal((await admin.getVault(laptop.state.vaultId)).revision, 1);
    await laptop.setWorkOffline(false);
    assert.equal((await laptop.sync(admin, creds(), db)).status, 'pushed');
  });

  it('Should_SaveConflictCopy_When_MasterKeyChangedOnOtherDevice', async () => {
    const { laptop, phone, info } = await setup('Key change');
    const laptopDb = await laptop.open(creds());
    laptopDb.credentials.setPassword(kdbxweb.ProtectedValue.fromString('a brand new password'));
    await laptop.save(laptopDb);
    await laptop.sync(admin, creds(), laptopDb);

    const phoneDb = await phone.open(creds());
    addEntry(phoneDb, 'unsynced phone entry');
    await phone.save(phoneDb);
    const result = await phone.sync(admin, creds(), phoneDb);
    assert.equal(result.status, 'key-changed');
    assert.ok(result.conflictId);
    assert.equal((await admin.getVault(info.id)).conflicts, 1);
    // Local conflict copy kept, cache now holds the server version (new key).
    const files = await fs.readdir(phone.dir);
    assert.ok(files.some((f) => f.startsWith('conflict-')));
    const reopened = await phone.open(credentials('a brand new password'));
    assert.deepEqual(titles(reopened), ['shared']);
    assert.ok(path.isAbsolute(phone.file));
  });

  it('Should_ReportReadOnly_When_ReaderHasLocalChanges', async () => {
    const reader = await createUser(server.url, admin.token!, 'sync-reader');
    const info = await admin.createVault('Read only');
    await fetch(`${server.url}/api/v1/vaults/${info.id}/members/sync-reader`, {
      method: 'PUT', headers: { Authorization: `Bearer ${admin.token}`, 'Content-Type': 'application/json' }, body: '{"role":"reader"}',
    });
    const owner = await LocalVault.create(await tempDir(), { serverUrl: server.url, vaultId: info.id, vaultName: 'Read only' });
    const db = newDatabase();
    addEntry(db, 'owner');
    await owner.save(db);
    await owner.sync(admin, creds(), db);

    const local = await LocalVault.create(await tempDir(), { serverUrl: server.url, vaultId: info.id, vaultName: 'Read only' });
    const readerDb = (await local.sync(reader, creds())).db!;
    addEntry(readerDb, 'not allowed');
    await local.save(readerDb);
    assert.equal((await local.sync(reader, creds(), readerDb)).status, 'read-only');
  });
});
