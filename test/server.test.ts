import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { ApiError, KpsApi } from '../client/api.ts';
import { ADMIN, adminApi, call, createUser, databaseBytes, newDatabase, startServer, type TestServer, addEntry } from './helpers.ts';

let server: TestServer;
let admin: KpsApi;
let kdbxA: Uint8Array;
let kdbxB: Uint8Array;

before(async () => {
  server = await startServer({ keepRevisions: 3, keepDays: 0 });
  admin = await adminApi(server.url);
  const db = newDatabase();
  addEntry(db, 'one');
  kdbxA = await databaseBytes(db);
  addEntry(db, 'two');
  kdbxB = await databaseBytes(db);
});

after(() => server.stop());

describe('status and authentication', () => {
  it('Should_IdentifyServer_When_StatusRequestedWithoutAuth', async () => {
    const res = await call(server.url, undefined, 'GET', '/api/v1/status');
    assert.equal(res.status, 200);
    assert.equal((await res.json()).server, 'keepass-server');
  });

  it('Should_Return401_When_TokenMissingOrInvalid', async () => {
    assert.equal((await call(server.url, undefined, 'GET', '/api/v1/vaults')).status, 401);
    assert.equal((await call(server.url, 'kps_nope', 'GET', '/api/v1/vaults')).status, 401);
  });

  it('Should_RejectLogin_When_PasswordWrong', async () => {
    await assert.rejects(new KpsApi(server.url).login(ADMIN.username, 'wrong-password', 'x'), (err: ApiError) => err.status === 401);
  });

  it('Should_ThrottleLogin_When_TooManyFailures', async () => {
    const api = new KpsApi(server.url);
    for (let i = 0; i < 5; i++) await api.login('throttled-user', 'bad-password', 'x').catch(() => undefined);
    await assert.rejects(api.login('throttled-user', 'bad-password', 'x'), (err: ApiError) => err.status === 429);
  });

  it('Should_RevokeToken_When_LoggedOut', async () => {
    const api = await adminApi(server.url);
    const token = api.token!;
    await api.logout();
    assert.equal((await call(server.url, token, 'GET', '/api/v1/me')).status, 401);
  });

  it('Should_PassConnectionTest_When_CredentialsValid', async () => {
    const ok = await KpsApi.testConnection(server.url, ADMIN.username, ADMIN.password);
    assert.equal(ok.ok, true);
    const badLogin = await KpsApi.testConnection(server.url, ADMIN.username, 'nope-nope-nope');
    assert.deepEqual([badLogin.ok, badLogin.step], [false, 'login']);
    const unreachable = await KpsApi.testConnection('http://127.0.0.1:1', ADMIN.username, ADMIN.password);
    assert.deepEqual([unreachable.ok, unreachable.step], [false, 'reach']);
  });
});

describe('users', () => {
  it('Should_ForbidUserAdmin_When_NotAdmin', async () => {
    const bob = await createUser(server.url, admin.token!, 'bob-users');
    assert.equal((await call(server.url, bob.token, 'GET', '/api/v1/users')).status, 403);
  });

  it('Should_RefuseRemovingLastAdmin_When_OnlyOneAdmin', async () => {
    const me = await admin.me();
    const helper = await createUser(server.url, admin.token!, 'helper-admin');
    const helperMe = await helper.me();
    // helper is not admin, so demoting the only admin must fail
    const res = await call(server.url, admin.token, 'PATCH', `/api/v1/users/${me.id}`, { isAdmin: false });
    assert.equal(res.status, 409);
    assert.equal((await call(server.url, admin.token, 'DELETE', `/api/v1/users/${helperMe.id}`)).status, 200);
  });

  it('Should_RevokeSessions_When_UserDisabled', async () => {
    const carol = await createUser(server.url, admin.token!, 'carol-disabled');
    const { id } = await carol.me();
    await call(server.url, admin.token, 'PATCH', `/api/v1/users/${id}`, { disabled: true });
    assert.equal((await call(server.url, carol.token, 'GET', '/api/v1/me')).status, 401);
  });
});

describe('vault content and concurrency', () => {
  it('Should_RequireIfMatch_When_Uploading', async () => {
    const vault = await admin.createVault('No precondition');
    const res = await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/content`, kdbxA);
    assert.equal(res.status, 428);
  });

  it('Should_Return404EmptyVault_When_NothingUploaded', async () => {
    const vault = await admin.createVault('Empty');
    await assert.rejects(admin.download(vault.id), (err: ApiError) => err.code === 'empty_vault');
  });

  it('Should_RejectUpload_When_NotKdbx', async () => {
    const vault = await admin.createVault('Garbage');
    await assert.rejects(admin.upload(vault.id, new TextEncoder().encode('<html>not a db</html>'.repeat(20)), 0), (err: ApiError) => err.status === 422);
  });

  it('Should_RejectUpload_When_ChecksumMismatch', async () => {
    const vault = await admin.createVault('Truncated');
    const res = await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/content`, kdbxA, {
      'If-Match': '"0"', 'X-KPS-SHA256': '0'.repeat(64),
    });
    assert.equal(res.status, 400);
  });

  it('Should_Return412_When_BaseRevisionStale', async () => {
    const vault = await admin.createVault('Concurrency');
    const first = await admin.upload(vault.id, kdbxA, 0);
    assert.equal(first.revision, 1);
    // A second device also based its changes on revision 0.
    await assert.rejects(admin.upload(vault.id, kdbxB, 0), (err: ApiError) => {
      assert.equal(err.status, 412);
      assert.equal(err.details.currentRevision, 1);
      return true;
    });
    const second = await admin.upload(vault.id, kdbxB, 1);
    assert.equal(second.revision, 2);
  });

  it('Should_ReturnSameRevision_When_UploadRetriedAfterLostResponse', async () => {
    const vault = await admin.createVault('Retry');
    const first = await admin.upload(vault.id, kdbxA, 0);
    const retry = await admin.upload(vault.id, kdbxA, 0);
    assert.deepEqual([retry.revision, retry.unchanged], [first.revision, true]);
  });

  it('Should_AllowOnlyOneWinner_When_UploadsRace', async () => {
    const vault = await admin.createVault('Race');
    await admin.upload(vault.id, kdbxA, 0);
    const other = newDatabase();
    addEntry(other, 'other');
    const race = await Promise.allSettled([admin.upload(vault.id, kdbxB, 1), admin.upload(vault.id, await databaseBytes(other), 1)]);
    assert.equal(race.filter((r) => r.status === 'fulfilled').length, 1);
    assert.equal(race.filter((r) => r.status === 'rejected' && (r.reason as ApiError).status === 412).length, 1);
  });

  it('Should_Return304_When_RevisionUnchanged', async () => {
    const vault = await admin.createVault('Conditional get');
    const up = await admin.upload(vault.id, kdbxA, 0);
    assert.equal(await admin.download(vault.id, up.revision), null);
    const full = await admin.download(vault.id);
    assert.deepEqual(full?.data, kdbxA);
  });

  it('Should_NotifyWaiters_When_NewRevisionUploaded', async () => {
    const vault = await admin.createVault('Wait');
    const waiting = admin.waitForChange(vault.id, 0, 10);
    await admin.upload(vault.id, kdbxA, 0);
    assert.equal(await waiting, 1);
  });
});

describe('revisions, retention and conflicts', () => {
  it('Should_PruneOldRevisions_When_BeyondRetention', async () => {
    const vault = await admin.createVault('Retention');
    let rev = 0;
    for (let i = 0; i < 6; i++) {
      const db = newDatabase();
      addEntry(db, `v${i}`);
      rev = (await admin.upload(vault.id, await databaseBytes(db), rev)).revision;
    }
    const res = await call(server.url, admin.token, 'GET', `/api/v1/vaults/${vault.id}/revisions`);
    const revisions = (await res.json()) as Array<{ revision: number }>;
    assert.deepEqual(revisions.map((r) => r.revision), [6, 5, 4]);
    const pruned = await call(server.url, admin.token, 'GET', `/api/v1/vaults/${vault.id}/revisions/1/content`);
    assert.equal(pruned.status, 404);
  });

  it('Should_CreateNewRevision_When_OldRevisionRestored', async () => {
    const vault = await admin.createVault('Restore');
    await admin.upload(vault.id, kdbxA, 0);
    await admin.upload(vault.id, kdbxB, 1);
    const res = await call(server.url, admin.token, 'POST', `/api/v1/vaults/${vault.id}/revisions/1/restore`);
    assert.equal(res.status, 201);
    const current = await admin.download(vault.id);
    assert.deepEqual([current?.revision, current?.data], [3, kdbxA]);
  });

  it('Should_StoreAndResolveConflictCopy_When_Uploaded', async () => {
    const vault = await admin.createVault('Conflicts');
    const id = await admin.uploadConflict(vault.id, kdbxB, 0, 'test');
    assert.equal((await admin.getVault(vault.id)).conflicts, 1);
    const get = await call(server.url, admin.token, 'GET', `/api/v1/vaults/${vault.id}/conflicts/${id}/content`);
    assert.deepEqual(new Uint8Array(await get.arrayBuffer()), kdbxB);
    assert.equal((await call(server.url, admin.token, 'DELETE', `/api/v1/vaults/${vault.id}/conflicts/${id}`)).status, 200);
    assert.equal((await admin.getVault(vault.id)).conflicts, 0);
  });
});

describe('sharing', () => {
  it('Should_HideVault_When_UserNotMember', async () => {
    const vault = await admin.createVault('Private');
    const eve = await createUser(server.url, admin.token!, 'eve');
    assert.equal((await eve.listVaults()).length, 0);
    await assert.rejects(eve.download(vault.id), (err: ApiError) => err.status === 404);
  });

  it('Should_EnforceRoles_When_MembersShareVault', async () => {
    const vault = await admin.createVault('Shared');
    await admin.upload(vault.id, kdbxA, 0);
    const reader = await createUser(server.url, admin.token!, 'reader1');
    const editor = await createUser(server.url, admin.token!, 'editor1');
    await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/members/reader1`, { role: 'reader' });
    await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/members/editor1`, { role: 'editor' });

    assert.deepEqual((await reader.download(vault.id))?.data, kdbxA);
    await assert.rejects(reader.upload(vault.id, kdbxB, 1), (err: ApiError) => err.status === 403);
    assert.equal((await editor.upload(vault.id, kdbxB, 1)).revision, 2);
    // editors cannot manage members
    assert.equal((await call(server.url, editor.token, 'PUT', `/api/v1/vaults/${vault.id}/members/reader1`, { role: 'editor' })).status, 403);
    // the last owner cannot be removed
    assert.equal((await call(server.url, admin.token, 'DELETE', `/api/v1/vaults/${vault.id}/members/${ADMIN.username}`)).status, 409);
  });
});
