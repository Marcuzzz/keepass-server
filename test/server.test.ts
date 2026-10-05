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

describe('groups', () => {
  const createGroup = async (name: string, members: string[] = []): Promise<{ id: number; name: string }> => {
    const res = await call(server.url, admin.token, 'POST', '/api/v1/groups', { name, members });
    assert.equal(res.status, 201);
    return res.json();
  };

  it('Should_ForbidGroupAdmin_When_NotAdmin', async () => {
    const mallory = await createUser(server.url, admin.token!, 'mallory-groups');
    const group = await createGroup('admin-only');
    assert.equal((await call(server.url, mallory.token, 'POST', '/api/v1/groups', { name: 'mine' })).status, 403);
    assert.equal((await call(server.url, mallory.token, 'PATCH', `/api/v1/groups/${group.id}`, { name: 'x' })).status, 403);
    assert.equal((await call(server.url, mallory.token, 'PUT', `/api/v1/groups/${group.id}/members/mallory-groups`)).status, 403);
    assert.equal((await call(server.url, mallory.token, 'DELETE', `/api/v1/groups/${group.id}`)).status, 403);
  });

  it('Should_RejectGroup_When_NameTakenOrMemberUnknown', async () => {
    await createGroup('Duplicate');
    assert.equal((await call(server.url, admin.token, 'POST', '/api/v1/groups', { name: 'duplicate' })).status, 409);
    assert.equal((await call(server.url, admin.token, 'POST', '/api/v1/groups', { name: 'ghosts', members: ['nobody-here'] })).status, 404);
  });

  it('Should_ListOnlyOwnGroups_When_NotAdmin', async () => {
    const dave = await createUser(server.url, admin.token!, 'dave-groups');
    await createGroup('dave-team', ['dave-groups']);
    await createGroup('not-dave');
    const res = await call(server.url, dave.token, 'GET', '/api/v1/groups');
    assert.deepEqual(((await res.json()) as Array<{ name: string }>).map((g) => g.name), ['dave-team']);
  });

  it('Should_GrantGroupRole_When_GroupAddedToVault', async () => {
    const vault = await admin.createVault('Group shared');
    await admin.upload(vault.id, kdbxA, 0);
    const frank = await createUser(server.url, admin.token!, 'frank-groups');
    const group = await createGroup('readers', ['frank-groups']);
    assert.equal((await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/groups/readers`, { role: 'reader' })).status, 200);

    assert.deepEqual((await frank.listVaults()).map((v) => [v.name, v.role]), [['Group shared', 'reader']]);
    assert.deepEqual((await frank.download(vault.id))?.data, kdbxA);
    await assert.rejects(frank.upload(vault.id, kdbxB, 1), (err: ApiError) => err.status === 403);

    // removing the user from the group revokes access
    await call(server.url, admin.token, 'DELETE', `/api/v1/groups/${group.id}/members/frank-groups`);
    await assert.rejects(frank.download(vault.id), (err: ApiError) => err.status === 404);
    // adding back, then removing the group from the vault revokes access too
    await call(server.url, admin.token, 'PUT', `/api/v1/groups/${group.id}/members/frank-groups`);
    assert.equal((await frank.listVaults()).length, 1);
    assert.equal((await call(server.url, admin.token, 'DELETE', `/api/v1/vaults/${vault.id}/groups/readers`)).status, 200);
    await assert.rejects(frank.download(vault.id), (err: ApiError) => err.status === 404);
  });

  it('Should_UseHighestRole_When_DirectAndGroupRolesDiffer', async () => {
    const vault = await admin.createVault('Highest role');
    await admin.upload(vault.id, kdbxA, 0);
    const gina = await createUser(server.url, admin.token!, 'gina-groups');
    await createGroup('editors', ['gina-groups']);
    await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/members/gina-groups`, { role: 'reader' });
    await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/groups/editors`, { role: 'editor' });
    assert.equal((await gina.getVault(vault.id)).role, 'editor');
    assert.equal((await gina.upload(vault.id, kdbxB, 1)).revision, 2);
  });

  it('Should_ShareNewVault_When_CreatedWithGroups', async () => {
    const hank = await createUser(server.url, admin.token!, 'hank-groups');
    await createGroup('family', ['hank-groups']);
    const res = await call(server.url, admin.token, 'POST', '/api/v1/vaults', { name: 'Family', groups: [{ name: 'family', role: 'editor' }] });
    assert.equal(res.status, 201);
    const vault = (await res.json()) as { id: string };
    assert.equal((await hank.getVault(vault.id)).role, 'editor');
    const groups = await call(server.url, hank.token, 'GET', `/api/v1/vaults/${vault.id}/groups`);
    assert.deepEqual(((await groups.json()) as Array<{ name: string; role: string }>).map((g) => [g.name, g.role]), [['family', 'editor']]);
  });

  it('Should_NotCreateVault_When_GroupUnknown', async () => {
    const before = (await admin.listVaults()).length;
    const res = await call(server.url, admin.token, 'POST', '/api/v1/vaults', { name: 'Orphan', groups: [{ name: 'no-such-group', role: 'reader' }] });
    assert.equal(res.status, 404);
    assert.equal((await admin.listVaults()).length, before);
  });

  it('Should_RevokeVaultAccess_When_GroupDeleted', async () => {
    const vault = await admin.createVault('Deleted group');
    const ivy = await createUser(server.url, admin.token!, 'ivy-groups');
    const group = await createGroup('temporary', ['ivy-groups']);
    await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/groups/temporary`, { role: 'reader' });
    assert.equal((await ivy.listVaults()).length, 1);
    assert.equal((await call(server.url, admin.token, 'DELETE', `/api/v1/groups/${group.id}`)).status, 200);
    assert.equal((await ivy.listVaults()).length, 0);
  });

  it('Should_ManageGroupsAndSharing_When_UsingClientApi', async () => {
    const kim = await createUser(server.url, admin.token!, 'kim-groups');
    const group = await admin.createGroup('client-api');
    await admin.addGroupMember(group.id, 'kim-groups');
    const vault = await admin.createVault('Client api', [{ name: 'client-api', role: 'reader' }]);
    assert.equal((await kim.getVault(vault.id)).role, 'reader');
    await admin.shareWithGroup(vault.id, 'client-api', 'editor');
    assert.deepEqual((await kim.vaultGroups(vault.id)).map((g) => g.role), ['editor']);
    assert.equal((await admin.renameGroup(group.id, 'client-api-2')).name, 'client-api-2');
    assert.deepEqual((await kim.listGroups()).map((g) => g.name), ['client-api-2']);
    await admin.unshareGroup(vault.id, 'client-api-2');
    await assert.rejects(kim.getVault(vault.id), (err: ApiError) => err.status === 404);
    await admin.removeGroupMember(group.id, 'kim-groups');
    await admin.deleteGroup(group.id);
    assert.equal((await kim.listGroups()).length, 0);
  });

  it('Should_ForbidGroupSharing_When_NotOwner', async () => {
    const vault = await admin.createVault('Owner only sharing');
    const jack = await createUser(server.url, admin.token!, 'jack2-groups');
    await createGroup('jacks', ['jack2-groups']);
    await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/groups/jacks`, { role: 'editor' });
    assert.equal((await call(server.url, jack.token, 'PUT', `/api/v1/vaults/${vault.id}/groups/jacks`, { role: 'owner' })).status, 403);
  });
});

describe('rename and duplicate', () => {
  it('Should_RenameVault_When_Owner', async () => {
    const vault = await admin.createVault('rename-me');
    assert.equal((await admin.renameVault(vault.id, 'renamed')).name, 'renamed');
    const reader = await createUser(server.url, admin.token!, 'rename-reader');
    await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/members/rename-reader`, { role: 'reader' });
    await assert.rejects(reader.renameVault(vault.id, 'nope'), (err: ApiError) => err.status === 403);
  });

  it('Should_DeleteVault_When_Owner', async () => {
    const vault = await admin.createVault('delete-me');
    await admin.upload(vault.id, kdbxA, 0);
    const editor = await createUser(server.url, admin.token!, 'delete-editor');
    await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${vault.id}/members/delete-editor`, { role: 'editor' });
    await assert.rejects(editor.deleteVault(vault.id), (err: ApiError) => err.status === 403);
    await admin.deleteVault(vault.id);
    await assert.rejects(admin.getVault(vault.id), (err: ApiError) => err.status === 404);
  });

  it('Should_TreatAdminAsOwner_When_GroupGivesLowerRole', async () => {
    const owner = await createUser(server.url, admin.token!, 'admin-role-owner');
    const vault = await owner.createVault('admin-role-vault');
    await admin.createGroup('admin-role-group', ['admin']);
    await owner.shareWithGroup(vault.id, 'admin-role-group', 'reader');
    assert.equal((await admin.getVault(vault.id)).role, 'owner');
    assert.equal((await admin.listVaults()).find((v) => v.id === vault.id)?.role, 'owner');
    await admin.renameVault(vault.id, 'admin-role-renamed');
    await admin.deleteVault(vault.id);
  });

  it('Should_CopyCurrentDatabaseOnly_When_Duplicating', async () => {
    const source = await admin.createVault('dup-source');
    await admin.upload(source.id, kdbxA, 0);
    await admin.upload(source.id, kdbxB, 1);
    const copy = await admin.duplicateVault(source.id, 'dup-copy');
    assert.equal(copy.name, 'dup-copy');
    assert.equal(copy.role, 'owner');
    assert.equal(copy.revision, 1);
    assert.deepEqual((await admin.download(copy.id))!.data, kdbxB);
    const revisions = (await (await call(server.url, admin.token, 'GET', `/api/v1/vaults/${copy.id}/revisions`)).json()) as Array<{ note: string }>;
    assert.equal(revisions.length, 1);
    assert.match(revisions[0]!.note, /Copy of "dup-source" revision 2/);

    // The vaults are independent, and deleting the source keeps the copy's (shared) blob.
    await admin.upload(copy.id, kdbxA, 1);
    assert.equal((await admin.getVault(source.id)).revision, 2);
    assert.equal((await call(server.url, admin.token, 'DELETE', `/api/v1/vaults/${source.id}`)).status, 200);
    assert.deepEqual((await admin.download(copy.id))!.data, kdbxA);
    const rev1 = await call(server.url, admin.token, 'GET', `/api/v1/vaults/${copy.id}/revisions/1/content`);
    assert.deepEqual(new Uint8Array(await rev1.arrayBuffer()), kdbxB);
  });

  it('Should_DefaultNameAndStayEmpty_When_DuplicatingEmptyVault', async () => {
    const source = await admin.createVault('empty-source');
    const copy = await admin.duplicateVault(source.id);
    assert.equal(copy.name, 'empty-source (copy)');
    assert.equal(copy.revision, 0);
    await admin.upload(copy.id, kdbxA, 0);
  });

  it('Should_CopySharing_When_OwnerAsksForIt', async () => {
    const source = await admin.createVault('dup-shared');
    await admin.upload(source.id, kdbxA, 0);
    const reader = await createUser(server.url, admin.token!, 'dup-reader');
    await admin.createGroup('dup-group', []);
    await call(server.url, admin.token, 'PUT', `/api/v1/vaults/${source.id}/members/dup-reader`, { role: 'reader' });
    await admin.shareWithGroup(source.id, 'dup-group', 'editor');

    const plain = await admin.duplicateVault(source.id, 'dup-plain');
    assert.deepEqual((await admin.vaultGroups(plain.id)).map((g) => g.name), []);

    const shared = await admin.duplicateVault(source.id, 'dup-with-sharing', true);
    assert.deepEqual((await admin.vaultGroups(shared.id)).map((g) => `${g.name}:${g.role}`), ['dup-group:editor']);
    const members = (await (await call(server.url, admin.token, 'GET', `/api/v1/vaults/${shared.id}/members`)).json()) as Array<{ username: string; role: string }>;
    assert.deepEqual(members.map((m) => `${m.username}:${m.role}`).sort(), ['admin:owner', 'dup-reader:reader']);

    // A reader can make a private copy, but not copy who has access.
    await assert.rejects(reader.duplicateVault(source.id, 'x', true), (err: ApiError) => err.status === 403);
    const own = await reader.duplicateVault(source.id, 'reader copy');
    assert.equal(own.role, 'owner');
    assert.deepEqual((await reader.download(own.id))!.data, kdbxA);
    const stranger = await createUser(server.url, admin.token!, 'dup-stranger');
    await assert.rejects(stranger.duplicateVault(source.id), (err: ApiError) => err.status === 404);
  });
});

describe('API documentation', () => {
  it('Should_DescribeEveryRoute_When_ServingOpenApiSpec', async () => {
    const res = await call(server.url, undefined, 'GET', '/api/openapi.json');
    assert.equal(res.status, 200);
    const spec = (await res.json()) as { openapi: string; servers: Array<{ url: string }>; paths: Record<string, Record<string, unknown>> };
    assert.equal(spec.openapi, '3.1.0');
    const documented = Object.entries(spec.paths)
      .flatMap(([p, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${spec.servers[0]!.url}${p.replace(/\{(\w+)\}/g, ':$1')}`))
      .sort();
    const routed = server.app.router.list()
      .filter((r) => r.path.startsWith('/api/v1/'))
      .map((r) => `${r.method} ${r.path}`)
      .sort();
    assert.deepEqual(documented, routed);
  });

  it('Should_ServeOnlyWhitelistedVendorFiles_When_RequestingFontAwesome', async () => {
    const css = await call(server.url, undefined, 'GET', '/vendor/fontawesome/css/solid.min.css');
    assert.equal(css.status, 200);
    assert.match(await css.text(), /fa-solid-900\.woff2/);
    const font = await call(server.url, undefined, 'GET', '/vendor/fontawesome/webfonts/fa-solid-900.woff2');
    assert.equal(font.headers.get('content-type'), 'font/woff2');
    assert.equal((await call(server.url, undefined, 'GET', '/vendor/fontawesome/css/brands.min.css')).status, 404);
    assert.equal((await call(server.url, undefined, 'GET', '/vendor/fontawesome/../../package.json')).status, 404);
  });

  it('Should_ServeDocsPage_When_RequestingApiDocs', async () => {
    const res = await call(server.url, undefined, 'GET', '/api/docs');
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /text\/html/);
    assert.match(await res.text(), /api-docs\.js/);
    assert.equal((await call(server.url, undefined, 'GET', '/api-docs.js')).status, 200);
  });
});
